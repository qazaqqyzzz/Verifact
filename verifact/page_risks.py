"""Bounded static dependency observations, with no resource fetch or execution."""

import base64
import binascii
import re
from urllib.parse import urljoin, urlsplit

from .checks import _origin, read_page


MAX_DEPENDENCIES = 200
MAX_ORIGINS = 20
COUNT_FIELDS = ("script_count", "cross_origin_scripts", "without_integrity", "iframe_count",
                "cross_origin_iframes", "integrity_present", "integrity_unknown", "crossorigin_present",
                "unresolved_count")
SCOPE = "Static script-src and iframe-src observations from the downloaded HTML. No dependency was requested or executed."
LIMITS = [
    "Different origins do not establish different owners, and a dependency is not evidence of malware or a vulnerability.",
    "Integrity checks recognize SHA-256, SHA-384 or SHA-512 metadata syntax only. Resource bytes and matching hashes were not verified.",
    "Crossorigin attribute presence does not verify CORS response headers, successful loading or browser enforcement.",
    "Inline scripts, srcdoc frames, stylesheets, module imports and JavaScript-created requests are outside this inventory.",
    "At most 200 supported src declarations and 20 origin rows are retained. Partial counts are observed lower bounds.",
]


def _unavailable(reason="This saved report does not contain a page dependency check. Run a new check to collect it."):
    return {"status": "unavailable", **{key: None for key in COUNT_FIELDS}, "origins": [],
            "origins_omitted": 0, "limited": False, "review": None, "scope": SCOPE,
            "limits": list(LIMITS), "reason": reason}


def _url_text(value):
    if not isinstance(value, str):
        raise ValueError("Missing or oversized URL")
    value = value.strip("".join(chr(number) for number in range(33)))
    value = value.replace("\t", "").replace("\n", "").replace("\r", "")
    if not value or "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Unsupported URL")
    return value


def _origin_text(url):
    scheme, hostname, port = _origin(url)
    if not hostname or len(hostname) > 253 or any(char.isspace() or char in '<>"\'\\%/?#@' for char in hostname):
        raise ValueError("Unsupported hostname")
    host = "[" + hostname + "]" if ":" in hostname else hostname
    return scheme + "://" + host + (":" + str(port) if port != (443 if scheme == "https" else 80) else "")


def _dependency_origin(entry, document_url):
    source = _url_text(entry["src"])
    if urlsplit(source).scheme:
        return _origin_text(source)
    base = entry.get("base")
    if base is False:
        raise ValueError("Oversized base URL")
    if base not in {None, ""}:
        base = urljoin(document_url, _url_text(base))
        # Unsupported or ambiguous bases must not quietly become same-origin.
        _origin_text(base)
    else:
        base = document_url
    return _origin_text(urljoin(base, source))


def has_integrity_metadata(value):
    """Recognize usable supported digest syntax; never claim a byte match."""
    if not isinstance(value, str) or len(value) > 4096:
        return False
    for token in re.split(r"[ \t\r\n\f]+", value.strip()):
        matched = re.fullmatch(r"(?i:sha(256|384|512))-([A-Za-z0-9+/_-]+={0,2})(?:\?[!-~]*)?", token)
        if not matched:
            continue
        bits, encoded = matched.groups()
        try:
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(raw) == int(bits) // 8:
            return True
    return False


def dependency_review(data):
    """Authored owner guidance based on counts, never stored review prose."""
    if not isinstance(data, dict) or data.get("status") not in {"assessed", "partial"}:
        return None
    missing, external = data.get("without_integrity"), data.get("cross_origin_scripts")
    if type(missing) is not int or type(external) is not int or not 0 < missing <= external <= MAX_DEPENDENCIES:
        return None
    count = ("At least " if data["status"] == "partial" else "") + str(missing)
    return {"id": "page_dependencies", "title": "Review external script dependencies", "tone": "amber",
            "why": count + " script" + ("s" if missing != 1 else "") + " from another origin lack" + ("" if missing != 1 else "s")
                   + " usable integrity metadata. The script content was not downloaded or checked.",
            "action": "Owner: confirm these sources are needed; pin fixed versions and add integrity checks where practical."}


def assess_page_risks(response):
    """Inspect the already-fetched response only; all persisted URLs are origins."""
    page, available, complete = read_page(response)
    if not available:
        return _unavailable("Supported HTML was not available for a dependency inventory.")
    try:
        document_origin = _origin_text(response.url)
    except (ValueError, TypeError, UnicodeError):
        return _unavailable("The returned page origin could not be established.")
    result = {"status": "assessed", **{key: 0 for key in COUNT_FIELDS}, "origins": [],
              "origins_omitted": 0, "limited": bool(page.dependency_limited), "review": None,
              "scope": SCOPE, "limits": list(LIMITS), "reason": ""}
    result["unresolved_count"] = page.dependency_unsupported
    origins = {}
    for entry in page.dependencies:
        script = entry["kind"] in {"script", "module"}
        result["script_count" if script else "iframe_count"] += 1
        try:
            origin = _dependency_origin(entry, response.url)
        except (ValueError, TypeError, UnicodeError):
            result["unresolved_count"] = min(MAX_DEPENDENCIES, result["unresolved_count"] + 1)
            continue
        if origin == document_origin:
            continue
        row = origins.setdefault(origin, {"origin": origin, "scripts": 0, "iframes": 0, "without_integrity": 0})
        if script:
            result["cross_origin_scripts"] += 1
            row["scripts"] += 1
            result["crossorigin_present"] += int(entry["crossorigin"])
            if entry["integrity"] is None:
                result["integrity_unknown"] += 1
            elif has_integrity_metadata(entry["integrity"]):
                result["integrity_present"] += 1
            else:
                result["without_integrity"] += 1
                row["without_integrity"] += 1
        else:
            result["cross_origin_iframes"] += 1
            row["iframes"] += 1
    result["origins"] = list(origins.values())[:MAX_ORIGINS]
    result["origins_omitted"] = max(0, len(origins) - MAX_ORIGINS)
    result["limited"] |= bool(result["origins_omitted"])
    if not complete or result["limited"] or result["unresolved_count"] or result["integrity_unknown"]:
        result["status"] = "partial"
        reasons = []
        if not complete:
            reasons.append("The returned HTML was incomplete or unsuccessful.")
        if result["limited"]:
            reasons.append("The dependency or origin display limit was reached.")
        if result["unresolved_count"] or result["integrity_unknown"]:
            reasons.append("Some sources or integrity metadata could not be interpreted reliably.")
        result["reason"] = " ".join(reasons) + " Counts describe only the inspected, supported declarations."
    result["review"] = dependency_review(result)
    return result


def page_risks_for_report(report):
    """Read bounded inventory data; absent/invalid old fields stay unavailable."""
    data = report.get("page_risks") if isinstance(report, dict) else None
    if not isinstance(data, dict):
        return _unavailable()
    if data.get("status") == "unavailable":
        return _unavailable("A page dependency inventory was unavailable when this report was recorded.")
    if data.get("status") not in {"assessed", "partial"}:
        return _unavailable("The saved dependency inventory could not be read reliably.")
    if any(type(data.get(key)) is not int or not 0 <= data[key] <= MAX_DEPENDENCIES for key in COUNT_FIELDS):
        return _unavailable("The saved dependency counts could not be read reliably.")
    if (data["script_count"] + data["iframe_count"] > MAX_DEPENDENCIES
            or data["cross_origin_scripts"] > data["script_count"]
            or data["cross_origin_iframes"] > data["iframe_count"]
            or data["without_integrity"] + data["integrity_present"] + data["integrity_unknown"] != data["cross_origin_scripts"]
            or data["crossorigin_present"] > data["cross_origin_scripts"]):
        return _unavailable("The saved dependency counts were inconsistent.")
    rows = data.get("origins")
    if not isinstance(rows, list) or len(rows) > MAX_ORIGINS:
        return _unavailable("The saved origin inventory could not be read reliably.")
    origins, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("origin"), str):
            return _unavailable("The saved origin inventory could not be read reliably.")
        try:
            raw = row["origin"]
            if raw != _origin_text(raw):
                raise ValueError("Expected an origin only")
        except (ValueError, TypeError, UnicodeError):
            return _unavailable("The saved origin inventory contains an unsupported origin.")
        if raw in seen or any(type(row.get(key)) is not int or not 0 <= row[key] <= MAX_DEPENDENCIES for key in ("scripts", "iframes", "without_integrity")):
            return _unavailable("The saved origin inventory was inconsistent.")
        if row["without_integrity"] > row["scripts"] or row["scripts"] + row["iframes"] == 0:
            return _unavailable("The saved integrity count was inconsistent.")
        seen.add(raw)
        origins.append({key: row[key] for key in ("origin", "scripts", "iframes", "without_integrity")})
    for key, total in (("scripts", "cross_origin_scripts"), ("iframes", "cross_origin_iframes"), ("without_integrity", "without_integrity")):
        if sum(row[key] for row in origins) > data[total]:
            return _unavailable("The saved origin totals were inconsistent.")
    omitted = data.get("origins_omitted", 0)
    if type(omitted) is not int or not 0 <= omitted <= MAX_DEPENDENCIES:
        return _unavailable("The saved origin limit metadata was invalid.")
    if not omitted and any(sum(row[key] for row in origins) != data[total]
                           for key, total in (("scripts", "cross_origin_scripts"), ("iframes", "cross_origin_iframes"),
                                              ("without_integrity", "without_integrity"))):
        return _unavailable("The saved origin totals did not match the dependency counts.")
    partial = data["status"] == "partial" or data.get("limited") is True or omitted or data["unresolved_count"] or data["integrity_unknown"]
    result = {"status": "partial" if partial else "assessed", **{key: data[key] for key in COUNT_FIELDS},
              "origins": origins, "origins_omitted": omitted, "limited": data.get("limited") is True or bool(omitted),
              "scope": SCOPE, "limits": list(LIMITS),
              "reason": "Only the inspected, supported declarations could be summarized; some content, sources or details were unavailable." if partial else ""}
    result["review"] = dependency_review(result)
    return result
