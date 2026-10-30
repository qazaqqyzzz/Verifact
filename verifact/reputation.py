"""Opt-in Google Safe Browsing lookup, separate from configuration scoring.

The caller must obtain the user's consent to send full URLs (including query
strings) to Google, supply their own key, and show the provider's protection
notice. This module never reads environment variables or enables itself.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import http.client
import json
import math
import re
import ssl
import threading
import time

from . import __version__
from .network import ScanError, validate_url


PROVIDER = "Google Safe Browsing"
ADVISORY_URL = "https://developers.google.com/safe-browsing/v4/advisory"
TERMS_URL = "https://developers.google.com/safe-browsing/v4/usage-limits"
PROTECTION_NOTICE = ("Google's lists can miss risky pages and can incorrectly flag legitimate pages. "
                     "A lookup is a limited snapshot, not a guarantee of safety.")
PRIVACY_NOTICE = "Full checked URLs, including paths and query strings, are sent to Google when you request a reputation lookup."
MAX_URLS = 12
MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 128 * 1024
MAX_MATCHES = 100
MAX_CACHE_URLS = 256
_CACHE = {}
_CACHE_LOCK = threading.RLock()
THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")
PLATFORM_TYPES = {"WINDOWS", "LINUX", "ANDROID", "OSX", "IOS", "ANY_PLATFORM", "ALL_PLATFORMS", "CHROME"}
THREAT_INFO = {
    "MALWARE": ("Potential malware", "https://developers.google.com/search/docs/monitor-debug/security/malware"),
    "SOCIAL_ENGINEERING": ("Potential phishing or deceptive content", "https://www.antiphishing.org/"),
    "UNWANTED_SOFTWARE": ("Potential unwanted software", "https://www.google.com/about/unwanted-software-policy.html"),
    "POTENTIALLY_HARMFUL_APPLICATION": ("Potentially harmful application", ADVISORY_URL),
}


class ReputationError(ValueError):
    """A user-safe error that never contains provider bodies or credentials."""


def _now():
    return datetime.now(timezone.utc)


def _result(status="not_checked", detail=None, **extra):
    result = {"provider": PROVIDER, "status": status, "checked_at": None,
              "checked_count": 0, "matches": [], "expires_at": None,
              "detail": detail or "No threat-list lookup has been requested. Configuration checks do not establish reputation.",
              "attribution": "Advisory provided by Google" if status == "listed" else "",
              "source_url": ADVISORY_URL, "notice": PROTECTION_NOTICE, "stale": False}
    result.update(extra)
    return result


def _urls(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_URLS:
        raise ReputationError(f"A lookup needs between 1 and {MAX_URLS} public HTTP/HTTPS URLs.")
    urls = []
    for value in values:
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_URL_LENGTH:
            raise ReputationError("A lookup URL is missing or exceeds the length limit.")
        try:
            url = validate_url(value)[0]
        except (ScanError, ValueError, TypeError) as exc:
            raise ReputationError("Only public-domain HTTP/HTTPS links without credentials or custom ports can be looked up.") from exc
        if len(url) > MAX_URL_LENGTH:
            raise ReputationError("A normalized lookup URL exceeds the length limit.")
        if url not in urls:
            urls.append(url)
    return urls


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReputationError("Google Safe Browsing returned ambiguous duplicate fields.")
        value[key] = item
    return value


def _post(payload, api_key, timeout):
    """One fixed HTTPS destination, without proxies, redirects or retries."""
    connection = http.client.HTTPSConnection("safebrowsing.googleapis.com", timeout=timeout,
                                             context=ssl.create_default_context())
    response = None
    deadline = time.monotonic() + timeout
    try:
        connection.request("POST", "/v4/threatMatches:find",
                           body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                           headers={"Content-Type": "application/json; charset=utf-8",
                                    "Accept": "application/json", "Accept-Encoding": "identity",
                                    "X-Goog-Api-Key": api_key,
                                    "User-Agent": f"Verifact/{__version__}", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            hint = {400: "Check that the API key is valid and Safe Browsing is enabled.",
                    401: "Check the API key.", 403: "Check the API key restrictions and enable Safe Browsing in its Google project.",
                    429: "The provider's quota or rate limit was reached. Try again later."}.get(response.status,
                    "The service is temporarily unavailable.")
            raise ReputationError(f"Google Safe Browsing returned HTTP {response.status}. {hint}")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ReputationError("Google Safe Browsing returned an unsupported response type.")
        raw = bytearray()
        while len(raw) <= MAX_RESPONSE_BYTES:
            if response.isclosed() is True:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReputationError("Google Safe Browsing did not finish within the request time limit.")
            if connection.sock:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ReputationError("Google Safe Browsing returned more data than the allowed response limit.")
        if type(response.length) is int and response.length > 0:
            raise ReputationError("Google Safe Browsing returned an incomplete response.")
        return json.loads(raw, object_pairs_hook=_json_object)
    except (OSError, http.client.HTTPException) as exc:
        raise ReputationError("Google Safe Browsing could not be reached. No retry was made.") from exc
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ReputationError):
            raise
        raise ReputationError("Google Safe Browsing returned unreadable data.") from exc
    finally:
        if response:
            response.close()
        connection.close()


def _expiry(value, checked_at):
    # Protobuf Duration permits nine fractional places. Reject malformed,
    # missing and non-positive lifetimes rather than inventing freshness.
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,9})?s", value):
        raise ReputationError("The threat-list response did not include a usable validity period.")
    duration = float(value[:-1])
    if not math.isfinite(duration) or duration <= 0:
        raise ReputationError("The threat-list response did not include a usable validity period.")
    return checked_at + timedelta(seconds=duration)


def _parse(value, urls, checked_at):
    if not isinstance(value, dict) or any(key != "matches" for key in value):
        raise ReputationError("Google Safe Browsing returned an unexpected response; reputation was not established.")
    matches = value.get("matches", [])
    if not isinstance(matches, list) or len(matches) > MAX_MATCHES:
        raise ReputationError("Google Safe Browsing returned an invalid match list.")
    if not matches:
        return _result("no_match", "No known match was returned for these URLs in the requested Google lists at the lookup time. This does not mean the link is safe.",
                       checked_at=checked_at.isoformat(), checked_count=len(urls))
    cleaned = []
    expires = []
    for match in matches:
        if not isinstance(match, dict):
            raise ReputationError("Google Safe Browsing returned an incomplete match.")
        threat = match.get("threat")
        kind = match.get("threatType")
        if (kind not in THREAT_TYPES or match.get("threatEntryType") != "URL"
                or not isinstance(match.get("platformType"), str) or match["platformType"] not in PLATFORM_TYPES
                or not isinstance(threat, dict) or not isinstance(threat.get("url"), str)):
            raise ReputationError("Google Safe Browsing returned an unsupported match.")
        try:
            url = validate_url(threat["url"])[0]
        except (ScanError, ValueError) as exc:
            raise ReputationError("Google Safe Browsing returned an invalid matched URL.") from exc
        if url not in urls:
            raise ReputationError("Google Safe Browsing returned a match that could not be associated with the submitted URLs.")
        expiry = _expiry(match.get("cacheDuration"), checked_at)
        expires.append(expiry)
        item = {"url": url, "threat_type": kind, "label": THREAT_INFO[kind][0],
                "advice_url": THREAT_INFO[kind][1], "expires_at": expiry.isoformat()}
        if item not in cleaned:
            cleaned.append(item)
    return _result("listed", "Google lists one or more checked URLs as potentially risky. Avoid entering information or downloading files until you verify the intended destination.",
                   checked_at=checked_at.isoformat(), checked_count=len(urls), matches=cleaned,
                   expires_at=min(expires).isoformat())


def _lookup(prepared, api_key, timeout):
    """Consult the required positive cache before contacting Google again."""
    with _CACHE_LOCK:
        current = _now()
        for url, entry in list(_CACHE.items()):
            active = [item for item in entry["matches"] if datetime.fromisoformat(item["expires_at"]) > current]
            if active:
                entry["matches"] = active
            else:
                del _CACHE[url]
        cached = [url for url in prepared if url in _CACHE]
        pending = [url for url in prepared if url not in _CACHE]
        if len(_CACHE) + len(pending) > MAX_CACHE_URLS:
            raise ReputationError("The local reputation cache is full. Wait for earlier lookups to expire before checking more links.")
        checked_at = current
        if pending:
            payload = {"client": {"clientId": "verifact", "clientVersion": __version__},
                       "threatInfo": {"threatTypes": list(THREAT_TYPES), "platformTypes": ["ANY_PLATFORM"],
                                      "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in pending]}}
            result = _parse(_post(payload, api_key, timeout), pending, checked_at)
            for item in result["matches"]:
                entry = _CACHE.setdefault(item["url"], {"checked_at": checked_at.isoformat(), "matches": []})
                entry["matches"].append(deepcopy(item))
        else:
            result = _result()
        if cached:
            matches = [item for url in cached for item in _CACHE[url]["matches"]] + result["matches"]
            oldest = min([checked_at.isoformat(), *[_CACHE[url]["checked_at"] for url in cached]])
            result = _result("listed", "Google lists one or more checked URLs as potentially risky. Avoid entering information or downloading files until you verify the intended destination.",
                             checked_at=oldest, checked_count=len(prepared), matches=matches,
                             expires_at=min(item["expires_at"] for item in matches), cached_count=len(cached))
        return public_result(result)


def inspect_urls(urls, api_key=None, timeout=8):
    """Look up URLs only when explicitly called with a personal API key.

    Nothing is fetched from the supplied URLs by this function. Its one request
    sends them to Google's fixed API endpoint. An absent key sends nothing;
    malformed input/provider data and network failures never become no_match.
    """
    if not api_key:
        return _result(detail="Reputation lookup is optional. Add your own Google Safe Browsing key to check known-threat lists.")
    try:
        if (not isinstance(api_key, str) or not 20 <= len(api_key) <= 512
                or not api_key.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in api_key)):
            raise ReputationError("The Google Safe Browsing key is not in the expected format.")
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 1 <= timeout <= 30:
            raise ReputationError("The reputation request time limit must be between 1 and 30 seconds.")
        prepared = _urls(urls)
        # Start cache age before the request, so transit time cannot extend it.
        return _lookup(prepared, api_key, timeout)
    except ReputationError as exc:
        return _result("unavailable", str(exc))


def public_result(result, now=None):
    """Return a display snapshot with stale Google warnings removed.

    Call on report reads and before export; the browser must also expire a
    displayed warning at expires_at. Saved reports describe historic evidence,
    not live protection. This helper never refreshes through the network.
    """
    if (not isinstance(result, dict) or not isinstance(result.get("status"), str)
            or result["status"] not in {"listed", "no_match", "not_checked", "unavailable"}):
        return _result()
    copied = deepcopy(result)
    if copied["status"] != "listed":
        return copied
    try:
        expiry = datetime.fromisoformat(copied["expires_at"])
        current = now or _now()
        if expiry.tzinfo is None or current.tzinfo is None:
            raise ValueError("Timestamp has no timezone")
        expired = current >= expiry
    except (KeyError, ValueError, TypeError):
        expired = True
    if expired:
        return _result("unavailable", "This lookup has expired. Request a new reputation lookup for a current result.",
                       checked_at=copied.get("checked_at"), checked_count=copied.get("checked_count", 0),
                       expires_at=copied.get("expires_at"), stale=True)
    return copied
