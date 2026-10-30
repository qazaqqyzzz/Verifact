"""Free, local domain matching against CERT Polska's active warning list.

Only the fixed public feed is downloaded. Submitted links, hostnames and page
contents are never sent to CERT Polska. A replacement snapshot removes entries
that disappeared from the active list; stale snapshots cannot produce verdicts.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import threading
from urllib.parse import urlsplit

from .network import Client, ScanError, normalize_domain, validate_url


PROVIDER = "CERT Polska"
SOURCE_URL = "https://cert.pl/lista-ostrzezen/"
FEED_URL = "https://hole.cert.pl/domains/v2/domains.txt"
FRESHNESS_SECONDS = 300
RETRY_SECONDS = 60
MAX_FEED_BYTES = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT = 12
MAX_DOMAINS = 500000
MAX_HOSTS = 16
SCOPE = "One community domain-warning list, focused mainly on threats targeting Poland. Other countries and newly created threats may be missing."
PRIVACY_NOTE = "The public list is downloaded and matched on this computer. Your links are not sent to CERT Polska."
NOTICE = "A listed domain is a warning to investigate, not proof about every page. No match does not establish that a website is safe. CERT Polska does not endorse Verifact."


def _now():
    return datetime.now(timezone.utc)


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        result = datetime.fromisoformat(value)
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


@dataclass(frozen=True)
class FeedSnapshot:
    domains: frozenset
    fetched_at: datetime
    expires_at: datetime


def parse_domains(raw):
    """Reject incomplete/ambiguous input instead of treating it as no match."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FEED_BYTES:
        raise ValueError("The community list is empty or exceeds the download limit.")
    text = raw.decode("utf-8-sig", errors="strict")
    domains = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        # The official v2 text representation contains one hostname per line.
        # No URLs, wildcard rules, inline comments or arbitrary suffixes.
        if line != line.strip() or len(line) > 253:
            raise ValueError("The community list contains an unsupported entry.")
        try:
            domain = normalize_domain(line)
        except (ScanError, UnicodeError) as exc:
            raise ValueError("The community list contains an unsupported entry.") from exc
        domains.add(domain)
        if len(domains) > MAX_DOMAINS:
            raise ValueError("The community list exceeds its entry limit.")
    if not domains:
        raise ValueError("The community list is empty.")
    return frozenset(domains)


def _download_bytes():
    """Worker-only I/O; the parent enforces a wall-clock deadline as well."""
    # This separate budget cannot consume the website scan's request allowance.
    client = Client(timeout=8, max_bytes=MAX_FEED_BYTES, max_redirects=0, max_requests=1)
    fetched = client.fetch(FEED_URL)
    response = fetched.response
    if (response is None or response.url != FEED_URL or response.status != 200
            or response.truncated or response.body_error):
        raise ValueError("The community list could not be downloaded completely.")
    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
        raise ValueError("The community list uses an unsupported encoding.")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"", "text/plain", "application/octet-stream"}:
        raise ValueError("The community list returned an unsupported content type.")
    if len(response.body) > MAX_FEED_BYTES:
        raise ValueError("The community list exceeds the download limit.")
    return response.body


def _download(now):
    """Bound DNS, headers and body retrieval with a killable child process."""
    environment = dict(os.environ)
    environment.pop("OPENAI_API_KEY", None)
    environment.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
    command = [sys.executable, "-m", "websignal.threat_feed", "--download-worker"]
    try:
        # The worker accepts no target and writes only the bounded feed body.
        # subprocess.run kills and reaps it on timeout; no background task can
        # later publish an overdue snapshot or retain a stalled resolver.
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=DOWNLOAD_TIMEOUT, check=False,
                                env=environment, cwd=str(Path(__file__).resolve().parent.parent))
    except subprocess.TimeoutExpired as exc:
        raise ValueError("The community list download exceeded its time limit.") from exc
    if result.returncode != 0 or not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_FEED_BYTES:
        raise ValueError("The community list could not be downloaded completely.")
    domains = parse_domains(result.stdout)
    return FeedSnapshot(domains, now, now + timedelta(seconds=FRESHNESS_SECONDS))


class FeedCache:
    """One bounded, atomic snapshot shared by scans in this local session."""
    def __init__(self):
        self.lock = threading.RLock()
        self.snapshot = None
        self.retry_after = None
        self.refreshing = False

    def peek(self, now=None):
        current = now or _now()
        with self.lock:
            value = self.snapshot
            return value if value and value.fetched_at <= current < value.expires_at else None

    def get(self, now=None):
        current = now or _now()
        with self.lock:
            fresh = self.peek(current)
            if fresh:
                return fresh
            if self.refreshing or (self.retry_after and current < self.retry_after):
                return None
            self.refreshing = True
        # Network/DNS work must not hold the lock used by report reads. Other
        # callers get unavailable while this single refresh is in progress.
        try:
            replacement = _download(current)
            with self.lock:
                self.snapshot = replacement  # Replace, never union: removals matter.
                self.retry_after = None
                return replacement if replacement.expires_at > _now() else None
        except (ScanError, ValueError, UnicodeError, OSError):
            with self.lock:
                self.retry_after = _now() + timedelta(seconds=RETRY_SECONDS)
            return None
        finally:
            with self.lock:
                self.refreshing = False


_CACHE = FeedCache()


def _result(status="not_checked", detail=None, **extra):
    result = {"provider": PROVIDER, "status": status, "source_url": SOURCE_URL,
              "checked_at": None, "fetched_at": None, "expires_at": None,
              "checked_hosts": [], "checked_count": 0, "matches": [], "feed_entries": None,
              "stale": False, "detail": detail or "The community warning list was not checked.",
              "scope": SCOPE, "privacy_note": PRIVACY_NOTE, "notice": NOTICE}
    result.update(extra)
    return result


def _hosts(urls):
    if not isinstance(urls, (list, tuple)) or not 1 <= len(urls) <= MAX_HOSTS:
        raise ValueError("Unsupported link list")
    hosts = []
    for url in urls:
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError("Unsupported link")
        host = validate_url(url)[1]
        if host not in hosts:
            hosts.append(host)
    return hosts


def match_hosts(hosts, snapshot, now=None):
    """A listed hostname covers itself and descendants, never its parents."""
    current = now or _now()
    if not isinstance(snapshot, FeedSnapshot) or not snapshot.fetched_at <= current < snapshot.expires_at:
        return _result("unavailable", "The community list is not current. No current result was established.", stale=True)
    matches = []
    for host in hosts:
        labels = host.split(".")
        for offset in range(len(labels) - 1):
            candidate = ".".join(labels[offset:])
            if candidate in snapshot.domains:
                matches.append({"hostname": host, "listed_domain": candidate,
                                "match_type": "exact" if offset == 0 else "subdomain"})
                break
    return _result("listed" if matches else "no_match",
                   "A checked hostname matches CERT Polska's active warning list. Verify the destination independently before visiting."
                   if matches else "No checked hostname matched this current community list. This limited result does not establish safety.",
                   checked_at=current.isoformat(), fetched_at=snapshot.fetched_at.isoformat(),
                   expires_at=snapshot.expires_at.isoformat(), checked_hosts=list(hosts),
                   checked_count=len(hosts), matches=matches, feed_entries=len(snapshot.domains))


def inspect_urls(urls, enabled=True, cache=None):
    if enabled is not True:
        return _result(detail="Community list checking was turned off for this check.")
    try:
        hosts = _hosts(urls)
    except (ScanError, ValueError, TypeError):
        return _result("unavailable", "The checked hostnames could not be established.")
    cache = cache or _CACHE
    try:
        snapshot = cache.get()
    except Exception:
        snapshot = None  # An optional feed failure must not stop the page check.
    if snapshot is None:
        return _result("unavailable", "The community list is unavailable or out of date. Other checks can still run.",
                       checked_at=_now().isoformat(), checked_hosts=hosts,
                       checked_count=len(hosts), stale=getattr(cache, "snapshot", None) is not None)
    return match_hosts(hosts, snapshot)


def public_result(result, now=None):
    """Sanitize saved results and expire both matches and no-match claims."""
    current = now or _now()
    if (not isinstance(result, dict) or not isinstance(result.get("status"), str)
            or result["status"] not in {"listed", "no_match", "unavailable", "not_checked"}):
        return _result()
    status = result["status"]
    if status == "not_checked":
        return _result()
    checked = _timestamp(result.get("checked_at"))
    fetched = _timestamp(result.get("fetched_at"))
    expires = _timestamp(result.get("expires_at"))
    try:
        values = result.get("checked_hosts", [])
        if not isinstance(values, list) or len(values) > MAX_HOSTS:
            raise ValueError("Invalid host list")
        hosts = list(dict.fromkeys(normalize_domain(value) for value in values))
    except (ScanError, TypeError, AttributeError, ValueError):
        return _result("unavailable", "The saved community result is incomplete.")
    common = {"checked_at": checked.isoformat() if checked else None, "checked_hosts": hosts,
              "checked_count": len(hosts), "fetched_at": fetched.isoformat() if fetched else None,
              "expires_at": expires.isoformat() if expires else None}
    if status == "unavailable":
        return _result("unavailable", "The community list could not provide a current result.",
                       stale=result.get("stale") is True, **common)
    if (not checked or not fetched or not expires or not hosts
            or not fetched <= checked <= current or not fetched < expires <= fetched + timedelta(seconds=FRESHNESS_SECONDS)
            or current >= expires):
        return _result("unavailable", "This community result has expired or lacks valid freshness evidence. Run a new check to refresh it.",
                       stale=True, **common)
    count = result.get("feed_entries")
    if type(count) is not int or not 1 <= count <= MAX_DOMAINS:
        return _result("unavailable", "The saved community result is incomplete.", **common)
    values = result.get("matches")
    if not isinstance(values, list) or len(values) > len(hosts) or (status == "listed") != bool(values):
        return _result("unavailable", "The saved community matches are inconsistent.", **common)
    matches = []
    for item in values:
        try:
            host = normalize_domain(item["hostname"])
            listed = normalize_domain(item["listed_domain"])
            if host not in hosts or not (host == listed or host.endswith("." + listed)):
                raise ValueError("Invalid match")
            matches.append({"hostname": host, "listed_domain": listed,
                            "match_type": "exact" if host == listed else "subdomain"})
        except (KeyError, ScanError, TypeError, AttributeError, ValueError):
            return _result("unavailable", "The saved community matches are inconsistent.", **common)
    return _result(status,
                   "A checked hostname matches CERT Polska's active warning list. Verify the destination independently before visiting."
                   if matches else "No checked hostname matched this current community list. This limited result does not establish safety.",
                   matches=matches, feed_entries=count, **common)


def community_for_report(report):
    """Read only: use freshness and a newer cached replacement, never fetch."""
    raw = report.get("community_reputation") if isinstance(report, dict) else None
    result = public_result(raw)
    # A newer full snapshot may remove a previous listing before it is displayed.
    snapshot = _CACHE.peek()
    previous = _timestamp(result.get("fetched_at"))
    if snapshot and previous and snapshot.fetched_at > previous and result["checked_hosts"]:
        return match_hosts(result["checked_hosts"], snapshot)
    return deepcopy(result)


def _download_worker():
    """Private fixed-source entry point; never accept URLs or print errors."""
    try:
        raw = _download_bytes()
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FEED_BYTES:
            return 1
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0
    except (ScanError, ValueError, UnicodeError, OSError):
        return 1


if __name__ == "__main__":
    raise SystemExit(_download_worker() if sys.argv[1:] == ["--download-worker"] else 2)
