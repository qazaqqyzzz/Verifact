"""Optional RFC 9116 maintenance check, separate from security/risk scoring.

Exactly one bounded GET uses the scan's existing guarded client. It never
follows redirects, opens published contact links or probes alternate paths.
"""

from datetime import datetime, timedelta, timezone
from email.message import Message
import re
from urllib.parse import urlsplit, urlunsplit

from .network import ScanError, validate_url


MAX_BYTES = 32 * 1024
MAX_LINES = 1000
MAX_LINE = 2048
PATH = "/.well-known/security.txt"
SOURCE_URL = "https://www.rfc-editor.org/rfc/rfc9116.html"
SCOPE = ("Optional maintenance check of the final HTTPS origin's /.well-known/security.txt. "
         "Its presence or absence does not grant or deny permission to test the site and does not change the security score.")
LIMITS = ("Contact delivery, linked resources, organization identity and digital signatures are not verified. "
          "Only Contact, Expires and Canonical receive basic syntax checks; this is not a complete RFC conformance audit.")


def _now(value):
    return value.astimezone(timezone.utc) if value is not None else datetime.now(timezone.utc)


def _evidence(url, now):
    return {"status": "unavailable", "checked_url": url, "checked_at": now.isoformat(), "http_status": None,
            "contact_count": None, "contact_schemes": [], "expires_at": None,
            "canonical_present": False, "canonical_matches": None, "signature": "absent",
            "issues": [], "source_url": SOURCE_URL}


def _finding(evidence, status="info", detail="", recommendation=""):
    return {"id": "security_contact", "category": "Domain", "status": status,
            "title": "Public security contact", "evidence": evidence,
            "explanation": " ".join(part for part in (detail, SCOPE, LIMITS) if part),
            "recommendation": recommendation}


def _issue(evidence, code, detail):
    if code not in {item["code"] for item in evidence["issues"]}:
        evidence["issues"].append({"code": code, "detail": detail})


def _uri(value):
    """Basic absolute URI shape; values are never returned, dereferenced or used as HTML."""
    if (not value or len(value) > MAX_LINE or not value.isascii()
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", value)
            or re.search(r"%(?![0-9A-Fa-f]{2})", value)):
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"}:
            if (scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.port == 0):
                return None
        elif scheme == "mailto":
            # Full mailbox validation/deliverability is intentionally out of scope.
            if not parsed.path or "@" not in parsed.path or parsed.netloc:
                return None
        elif scheme == "tel" and not parsed.path:
            return None
        return scheme
    except ValueError:
        return None


def _canonical(value):
    if _uri(value) != "https":
        return None
    parsed = urlsplit(value)
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    authority = host + (":" + str(parsed.port) if parsed.port not in {None, 443} else "")
    return urlunsplit(("https", authority, parsed.path or "/", parsed.query, parsed.fragment))


def _cleartext(lines, evidence):
    if lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----":
        if any(line.startswith("-----BEGIN PGP") for line in lines):
            raise ValueError("unsupported_signature")
        return lines
    evidence["signature"] = "present_unverified"
    try:
        start = lines.index("")
        signature = lines.index("-----BEGIN PGP SIGNATURE-----", start + 1)
        end = lines.index("-----END PGP SIGNATURE-----", signature + 1)
        if (start < 2 or not all(re.fullmatch(r"Hash: [A-Za-z0-9,-]+", line) for line in lines[1:start])
                or any(line.strip() for line in lines[end + 1:]) or end <= signature + 1):
            raise ValueError("unsupported_signature")
    except ValueError as exc:
        raise ValueError("unsupported_signature") from exc
    return [line[2:] if line.startswith("- ") else line for line in lines[start + 1:signature]]


def parse_security_contact(body, retrieved_url, now=None):
    """Parse bounded already-fetched bytes. Return a redacted finding, never contact values."""
    now = _now(now)
    evidence = _evidence(retrieved_url, now)
    evidence["status"] = "review"
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        _issue(evidence, "body_limit", "The file exceeds the 32 KiB inspection limit or is unavailable.")
        evidence["status"] = "unavailable"
        return _finding(evidence, "unknown", "The complete contact file could not be assessed.")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        _issue(evidence, "encoding", "The file is not valid UTF-8 text.")
        return _finding(evidence, "attention", "The returned file needs an encoding review.", "Publish security.txt as UTF-8 text/plain.")
    if text.startswith("\ufeff"):
        text = text[1:]
        _issue(evidence, "byte_order_mark", "A UTF-8 byte order mark was observed; publish plain UTF-8 without it.")
    if "\r" in text.replace("\r\n", "") or any(ord(c) < 32 and c not in "\r\n\t" for c in text):
        _issue(evidence, "control_characters", "Unsupported control characters or lone carriage returns were observed.")
        return _finding(evidence, "attention", "The returned file needs a format review.", "Use plain text fields separated by LF or CRLF line endings.")
    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) > MAX_LINES + 1 or any(len(line) > MAX_LINE for line in lines):
        _issue(evidence, "line_limit", "The file exceeds the line-count or 2,048-character field limit.")
        evidence["status"] = "unavailable"
        return _finding(evidence, "unknown", "The complete contact file could not be assessed.")
    if text and not text.endswith("\n"):
        _issue(evidence, "final_newline", "The final line has no LF or CRLF terminator.")
    try:
        lines = _cleartext(lines, evidence)
    except ValueError:
        evidence["signature"] = "unsupported"
        evidence["status"] = "unavailable"
        _issue(evidence, "signature_format", "The signature wrapper could not be safely separated from the contact fields.")
        return _finding(evidence, "unknown", "A signed contact file was observed but could not be parsed. No signature was verified.")
    fields = {}
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([!-9;-~]+):[ \t]+(.*?)[ \t]*", line)
        if match is None or not match.group(2):
            _issue(evidence, "field_format", "At least one line is not a nonempty Name: value field.")
            continue
        name, value = match.group(1).lower(), match.group(2)
        if name in {"contact", "expires", "canonical"}:
            fields.setdefault(name, []).append(value)
        # Extension fields must be ignored; do not retain names or values.
    contacts = fields.get("contact", [])
    evidence["contact_count"] = len(contacts)
    if not contacts:
        _issue(evidence, "missing_contact", "No Contact field was found.")
    schemes = []
    for value in contacts:
        scheme = _uri(value)
        if scheme is None:
            _issue(evidence, "contact_uri", "At least one Contact field lacks a supported absolute URI shape; web contacts must use HTTPS.")
        else:
            schemes.append(scheme if scheme in {"https", "mailto", "tel"} else "other")
    evidence["contact_schemes"] = list(dict.fromkeys(schemes))
    expires = fields.get("expires", [])
    if len(expires) != 1:
        _issue(evidence, "expires_count", "Exactly one Expires field is required.")
    else:
        value = expires[0]
        syntax = re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:(\d{2})(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value)
        if syntax and syntax.group(1) == "60":
            evidence["status"] = "unavailable"
            _issue(evidence, "unsupported_expiry", "A leap-second expiry timestamp was observed and was not interpreted.")
        else:
            try:
                if not syntax:
                    raise ValueError("Invalid timestamp")
                expiry = datetime.fromisoformat(value.upper().replace("Z", "+00:00")).astimezone(timezone.utc)
                evidence["expires_at"] = expiry.isoformat()
                if expiry <= now:
                    _issue(evidence, "expired", "The contact file's stated expiry time has passed.")
                elif expiry > now + timedelta(days=366):
                    _issue(evidence, "long_expiry", "The expiry is more than a year away; RFC 9116 recommends a shorter freshness window.")
            except (ValueError, OverflowError):
                _issue(evidence, "expires_format", "Expires is not an interpreted RFC 3339 timestamp with a timezone.")
    canonical = fields.get("canonical", [])
    evidence["canonical_present"] = bool(canonical)
    if canonical:
        normalized = [_canonical(value) for value in canonical]
        if None in normalized:
            _issue(evidence, "canonical_uri", "At least one Canonical field is not a supported HTTPS URI.")
        evidence["canonical_matches"] = _canonical(retrieved_url) in [value for value in normalized if value is not None]
        if not evidence["canonical_matches"]:
            _issue(evidence, "canonical_mismatch", "No Canonical field names the URL from which this file was retrieved; do not rely on these contact details without independent verification.")
    if evidence["status"] == "unavailable":
        return _finding(evidence, "unknown", "The contact file contains an unsupported timestamp; freshness was not established.")
    if evidence["issues"]:
        return _finding(evidence, "attention", "A contact file was returned, but its format or freshness needs maintenance.",
                        "Review the listed issues: publish a usable Contact URI, one future Expires timestamp, and matching Canonical URLs when that field is used.")
    evidence["status"] = "current"
    return _finding(evidence, "info", "Contact and future expiry fields were observed; any Canonical fields matched the retrieval URL. This does not verify that the contacts are genuine or reachable.")


def inspect_security_contact(client, final_response, *, now=None):
    """Use a scan-owned Client; restore its body limit and preserve its request budget."""
    now = _now(now)
    evidence = _evidence(None, now)
    if final_response is None:
        return _finding(evidence, "unknown", "No final page response was available, so no contact-file request was made.")
    try:
        canonical, host, _, _ = validate_url(final_response.url)
        if urlsplit(canonical).scheme != "https":
            evidence["status"] = "not_applicable"
            return _finding(evidence, "unknown", "The final page used HTTP. No different HTTPS destination was invented for this check.")
        url = "https://" + host + PATH
        evidence["checked_url"] = url
    except (ScanError, TypeError, AttributeError, ValueError):
        return _finding(evidence, "unknown", "The final page origin was not suitable for this bounded contact-file check.")
    previous_limit = client.max_bytes
    try:
        client.max_bytes = min(previous_limit, MAX_BYTES)
        response = client.request(url)
    except ScanError:
        return _finding(evidence, "unknown", "The contact-file request was unavailable, blocked, or outside the remaining scan budget.")
    finally:
        client.max_bytes = previous_limit
    evidence["http_status"] = response.status
    if response.status in {404, 410}:
        evidence["status"] = "not_found"
        return _finding(evidence, "info", "No security.txt file was found at the standard public location. Other reporting channels may exist.",
                        "Consider publishing a maintained security.txt to help researchers find the intended reporting channel.")
    if 300 <= response.status < 400:
        evidence["status"] = "redirect"
        return _finding(evidence, "unknown", "The contact-file location returned a redirect. This one-request check does not follow it or inspect the destination.")
    if response.status != 200 or response.truncated or getattr(response, "body_error", None) or len(response.body) > MAX_BYTES:
        return _finding(evidence, "unknown", "The standard location did not return a complete successful contact file within the inspection limits.")
    content_type = response.headers.get("content-type", "")
    message = Message()
    if isinstance(content_type, str) and len(content_type) <= 1024:
        message["content-type"] = content_type
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in {"", "identity"}:
        return _finding(evidence, "unknown", "The contact response used an unsupported content encoding; the file contents were not interpreted.")
    if (message.get_content_type() != "text/plain" or not content_type
            or message.get_content_charset("utf-8").lower() != "utf-8"):
        evidence["status"] = "review"
        _issue(evidence, "content_type", "The response was not supported UTF-8 text/plain with identity content encoding.")
        return _finding(evidence, "attention", "The standard path responded, but a supported plain-text contact file was not established.",
                        "Serve the intended security.txt as UTF-8 text/plain; ensure a generic HTML page is not returned for this path.")
    result = parse_security_contact(response.body, url, now)
    result["evidence"]["http_status"] = response.status
    return result
