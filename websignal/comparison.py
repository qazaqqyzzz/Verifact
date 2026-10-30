"""Compare two observed snapshots of the same target; no network or verdicts."""

import json
import math
import re
import unicodedata
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


CHECKS = {
    "tls": "TLS certificate and connection",
    "certificate_expiry": "Certificate renewal window",
    "https_redirect": "HTTP to HTTPS redirects",
    "hsts": "HTTPS-only browser policy",
    "csp": "Content security policy",
    "framing": "Framing policy",
    "nosniff": "MIME sniffing protection",
    "referrer": "Referrer policy",
    "http_resources": "Explicit HTTP resources",
    "password_forms": "Password form destinations",
    "cookie_flags": "Cookie attributes",
}
STATUSES = {"pass": "Passed", "attention": "Needs review", "info": "Observation", "unknown": "Unknown"}
NOTE = "Changes describe two observations, not proof of an attack or an improvement. Network conditions and returned content can differ."


def _target(report):
    """Normalize only components whose equivalence is unambiguous here."""
    raw = report.get("target_url") if "target_url" in report else "https://" + str(report.get("domain", "")) + "/"
    if not isinstance(raw, str) or not raw or len(raw) > 8192:
        return None
    if "\\" in raw or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        return None
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
        port = parsed.port
        if port is not None and port != (443 if parsed.scheme == "https" else 80):
            host += ":" + str(port)
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def _plain(value, limit=700):
    text = str(value)
    text = "".join(c for c in text if not unicodedata.category(c).startswith("C"))
    return text if len(text) <= limit else text[:limit] + "…"


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    except ValueError:
        return None


def _url_display(value):
    """Snapshot summaries need destinations, never query argument values."""
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            host = parsed.hostname
            if parsed.port is not None:
                host += ":" + str(parsed.port)
            query = urlencode([(name, "[redacted]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)])
            return _plain(urlunsplit((parsed.scheme, host, parsed.path, query, "")), 500)
    except (ValueError, UnicodeError):
        return "URL unavailable"
    return _plain(value, 500)


def _bounded(value, depth=0):
    if depth > 5:
        return "…"
    if isinstance(value, dict):
        # Legacy/imported reports may contain additional fields. Never copy
        # secrets into a diff merely because they appear in its evidence.
        forbidden = {"value", "cookie_value", "cookie", "set_cookie", "set-cookie", "authorization", "password", "token", "secret", "api_key"}
        return {str(key)[:80]: _bounded(item, depth + 1) for key, item in sorted(value.items(), key=lambda item: str(item[0]))[:30]
                if str(key).lower() not in forbidden}
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:20]]
    if isinstance(value, str):
        # CSP nonces rotate for every response. They are not a policy change.
        value = re.sub(r"nonce-[^\s;'\"]+", "nonce-[per-response]", value, flags=re.I)
        return re.sub(r"https?://[^\s<>\"']+", lambda match: _url_display(match.group()), _plain(value))
    if isinstance(value, float) and not math.isfinite(value):
        return "Non-finite value"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _plain(value)


def _referrer_snapshot(finding, legacy_scope=False):
    """Compare declarations, not a newer scanner's interpretation of them.

Older reports retained one header-or-meta string. Across that schema boundary
compare only the declaration they could retain, while preserving any explicit
uncertainty in the newer record. New-to-new comparisons retain both sources.
    """
    raw = finding.get("evidence")
    status = "info" if finding.get("status") in ("pass", "info", "attention") else "unknown"
    coverage = []
    if isinstance(raw, str):
        declaration = None if raw == "No explicit policy observed" else raw
        evidence = {"declaration": declaration}
    elif (isinstance(raw, dict) and isinstance(raw.get("header"), str)
          and isinstance(raw.get("meta_policies"), list)
          and all(isinstance(value, str) for value in raw["meta_policies"])):
        header, meta = raw["header"], raw["meta_policies"]
        if raw.get("complete_html") is not True:
            coverage.append("HTML completeness not established")
        if raw.get("limited") is not False:
            coverage.append("Declaration inventory limited or limit state unknown")
        if legacy_scope:
            # The former check preferred a header and otherwise retained the
            # last meta declaration. Its absence is represented explicitly.
            evidence = {"declaration": header if header else meta[-1] if meta else None}
        else:
            evidence = {"header": header or None, "meta_declarations": meta}
    else:
        return {"status": "unknown", "evidence": {"declaration_evidence": _bounded(raw),
                                                   "coverage": "Unsupported evidence shape"}}
    if status == "unknown":
        coverage.append("Finding was unassessed")
    evidence["coverage"] = coverage or ["No recorded coverage limitation"]
    return {"status": status, "evidence": _bounded(evidence)}


def _finding_snapshot(identifier, finding, legacy_referrer=False):
    if not isinstance(finding, dict):
        return None
    if identifier == "referrer":
        return _referrer_snapshot(finding, legacy_referrer)
    status = finding.get("status", "unknown")
    evidence = finding.get("evidence")
    if identifier == "certificate_expiry" and isinstance(evidence, dict):
        evidence = {"expires": evidence.get("expires")}
    if identifier == "cookie_flags" and isinstance(evidence, dict):
        # Only fields that the cookie check deliberately records are useful.
        evidence = {key: evidence.get(key) for key in (
            "cookies_observed", "missing_secure", "missing_http_only", "missing_same_site",
            "same_site_none_without_secure", "malformed_count", "limited")}
        cookies = finding.get("evidence", {}).get("cookies")
        if isinstance(cookies, list):
            evidence["cookies"] = [{key: cookie.get(key) for key in ("name", "secure", "http_only", "same_site")}
                                   for cookie in cookies[:30] if isinstance(cookie, dict)]
    return {"status": status if status in STATUSES else "unknown", "evidence": _bounded(evidence)}


def _display(value):
    if value is None:
        return "Not recorded"
    if isinstance(value, dict) and set(value) == {"status", "evidence"}:
        return _plain(STATUSES.get(value["status"], "Unknown") + " · " + json.dumps(value["evidence"], ensure_ascii=False, sort_keys=True), 900)
    return _plain(json.dumps(_bounded(value), ensure_ascii=False, sort_keys=True), 900)


def compare_reports(previous, current):
    """Return bounded, neutral differences; never merge two scopes or scores."""
    previous = previous if isinstance(previous, dict) else {}
    current = current if isinstance(current, dict) else {}
    result = {"available": False, "reason": "", "previous_created_at": _plain(previous.get("created_at", ""), 80),
              "current_created_at": _plain(current.get("created_at", ""), 80), "changes": [], "summary": "", "note": NOTE}
    if not previous or not current:
        result.update(reason="Two reports are needed to compare changes.", summary="No previous snapshot available.")
        return result
    target = _target(previous)
    if target is None or target != _target(current):
        result.update(reason="Compare reports for the same exact URL, including its path and query.", summary="These reports cover different targets.")
        return result
    if bool(previous.get("demo")) != bool(current.get("demo")):
        result.update(reason="A sample report cannot be compared with a live check.", summary="These reports use different data sources.")
        return result
    earlier, later = _timestamp(previous.get("created_at")), _timestamp(current.get("created_at"))
    if earlier is None or later is None:
        result.update(reason="Both reports need a valid timestamp with a time zone.", summary="The order of these snapshots could not be established.")
        return result
    if earlier >= later:
        result.update(reason="Choose a saved report created before the current check.", summary="The selected report is not an earlier snapshot.")
        return result

    result["available"] = True

    def add(identifier, title, before, after):
        if before == after:
            return
        kind = "added" if before is None else "removed" if after is None else "changed"
        before_text, after_text = _display(before), _display(after)
        if before_text == after_text:
            after_text = _plain(after_text, 750) + " (Recorded values changed; private or long values are hidden.)"
        result["changes"].append({"id": identifier, "title": title, "before": before_text, "after": after_text, "kind": kind})

    def findings(report):
        values = report.get("findings")
        return {item.get("id"): item for item in values[:1000]
                if isinstance(item, dict) and isinstance(item.get("id"), str)} if isinstance(values, list) else {}

    old, new = findings(previous), findings(current)
    for identifier, title in CHECKS.items():
        legacy_referrer = identifier == "referrer" and any(
            isinstance(item, dict) and isinstance(item.get("evidence"), str)
            for item in (old.get(identifier), new.get(identifier)))
        add(identifier, title, _finding_snapshot(identifier, old.get(identifier), legacy_referrer),
            _finding_snapshot(identifier, new.get(identifier), legacy_referrer))
    for identifier, title in (("status", "Returned HTTP status"), ("url", "Final destination")):
        previous_response, current_response = previous.get("response"), current.get("response")
        before = previous_response.get(identifier) if isinstance(previous_response, dict) else None
        after = current_response.get(identifier) if isinstance(current_response, dict) else None
        add("response_" + identifier, title, before, after)
    old_link, new_link = previous.get("link_analysis"), current.get("link_analysis")
    if isinstance(old_link, dict) and isinstance(new_link, dict):
        add("link_redirects", "Submitted link redirect trail", old_link.get("redirects"), new_link.get("redirects"))
    count = len(result["changes"])
    result["summary"] = f"{count} recorded change{'s' if count != 1 else ''} since the previous check." if count else "No changes in the compared security observations."
    return result
