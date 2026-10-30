"""Bounded URL observations, without claiming to identify a site's owner.

These rules highlight spelling and destination changes for review. They are
not a phishing classifier or a replacement for threat-intelligence data.
"""

import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

from .network import ScanError, normalize_domain, validate_url


SENSITIVE_KEYS = {
    "token", "accesstoken", "idtoken", "refreshtoken", "authtoken", "auth",
    "authorization", "password", "passwd", "pwd", "secret", "clientsecret",
    "apikey", "key", "session", "sessionid", "sid", "signature", "sig",
    "code", "samlresponse", "samlrequest", "assertion", "ticket",
}


def _reject_sensitive_url(url):
    parsed = urlsplit(url)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128):
        name = re.sub(r"[^a-z0-9]", "", unquote(key).casefold())
        if name in SENSITIVE_KEYS or name.endswith("token"):
            raise ScanError("This link appears to contain a private access value. Use a public page without login, reset, session or API tokens.", "blocked")
    # Do not visit one-time links, even when their token is in the path.
    path = unquote(parsed.path).casefold()
    if re.search(r"/(?:reset(?:[-_]?password)?|password[-_]?reset|magic[-_]?link|verify[-_]?email|confirm[-_]?email|unsubscribe|activate|invitation|invite)/[^/]+", path):
        raise ScanError("This looks like a private or one-time action link. Use a public page without its action token.", "blocked")


def normalize_target(value):
    """Canonical public-link syntax; actual DNS safety is checked on connect.

Paths and non-sensitive query strings are preserved. Fragments never travel
in an HTTP request and are omitted. Secret detection is intentionally
conservative and cannot recognize every private link.
    """
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ScanError("Enter a public HTTP/HTTPS link or domain, up to 2,048 characters.", "blocked")
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    canonical, *_ = validate_url(value)
    if len(canonical) > 2048:
        raise ScanError("The encoded link is too long. Use a public URL up to 2,048 characters.", "blocked")
    try:
        _reject_sensitive_url(canonical)
    except ValueError as exc:
        raise ScanError("This link has too many query parameters. Use a shorter public page link.", "blocked") from exc
    return canonical


def normalize_expected_domain(value):
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise ScanError("Enter the domain you expected, such as example.com.", "blocked")
    return normalize_domain(value)


def domain_matches(host, expected):
    return bool(host and expected and (host == expected or host.endswith("." + expected)))


def _unicode_hostname(host):
    try:
        return ".".join(label.encode("ascii").decode("idna") if label.startswith("xn--") else label for label in host.split("."))
    except UnicodeError:
        # IDNA 2008 names that cannot round-trip through Python's older codec
        # remain visible in their unambiguous ASCII form.
        return host


def _scripts(label):
    scripts = set()
    for char in label:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HANGUL", "HIRAGANA", "KATAKANA", "CJK"):
            if script in name:
                scripts.add(script)
                break
    return scripts


def _skeleton(host):
    # A small, explainable set, used only against the user's expected domain.
    mapping = str.maketrans("аесорхуіјΑΒΕΖΗΙΚΜΝΟΡΤΥΧοр", "aecopxyijabezhikmnoptyxop")
    return unicodedata.normalize("NFKC", _unicode_hostname(host)).translate(mapping).casefold()


def _one_edit_apart(left, right):
    if abs(len(left) - len(right)) > 1 or min(len(left), len(right)) < 5:
        return False
    if len(left) == len(right):
        differences = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        return len(differences) == 1 or (len(differences) == 2 and differences[1] == differences[0] + 1
            and left[differences[0]] == right[differences[1]] and left[differences[1]] == right[differences[0]])
    short, long = (left, right) if len(left) < len(right) else (right, left)
    return any(short == long[:i] + long[i + 1:] for i in range(len(long)))


def analyze_link(input_url, fetched, expected_domain=None):
    """Explain only observed URL structure and destinations, never legitimacy."""
    expected = normalize_expected_domain(expected_domain)
    chain = [{"url": item["url"], "status": item["status"]} for item in fetched.chain]
    final = fetched.response.url if fetched.response else None
    route_hosts = [urlsplit(item["url"]).hostname for item in chain]
    hosts = list(dict.fromkeys(route_hosts))
    input_host = urlsplit(input_url).hostname
    if input_host not in hosts:
        hosts.insert(0, input_host)
    warnings = []

    def add(identifier, title, detail, tone="amber"):
        warnings.append({"id": identifier, "title": title, "detail": detail, "tone": tone})

    for host in hosts:
        if not host:
            continue
        unicode_host = _unicode_hostname(host)
        if any(label.startswith("xn--") for label in host.split(".")):
            mixed = any(len(_scripts(label)) > 1 for label in unicode_host.split("."))
            add("mixed_script" if mixed else "international_domain",
                "Mixed writing systems in a domain" if mixed else "International domain spelling",
                f"The network hostname is {host}; its readable form is {unicode_host}. "
                + ("Some letters come from different writing systems and can look alike. " if mixed else "International domains are legitimate and common. ")
                + "Compare the actual hostname with the site you intended to visit.", "amber" if mixed else "unknown")
        if expected and not domain_matches(host, expected):
            if expected + "." in host or host.startswith(expected + "-"):
                add("misleading_subdomain", "Expected name inside a different domain",
                    f"{host} contains {expected}, but is not that domain or one of its subdomains. Check the complete hostname before entering information.")
            elif _skeleton(host) == _skeleton(expected) or _one_edit_apart(_skeleton(host), _skeleton(expected)):
                add("similar_spelling", "Similar spelling to your expected domain",
                    f"{host} resembles {expected}, but is a different hostname. Similarity is a review signal, not proof of impersonation.")
    if len(hosts) > 1:
        add("host_change", "The link changes hostname",
            "Observed hosts: " + " → ".join(host for host in hosts if host)
            + ". Redirects are common for sign-in, tracking and www aliases; this does not establish whether they share an owner.", "unknown")
    final_host = urlsplit(final).hostname if final else None
    expected_match = domain_matches(final_host, expected) if final_host and expected else None
    if expected and expected_match is False:
        add("expected_domain_mismatch", "Destination differs from the domain you expected",
            f"The final host is {final_host}. You expected {expected} or a subdomain of it. Confirm the destination independently before signing in or paying.")
    if urlsplit(input_url).scheme == "http":
        add("http_start", "The submitted link starts with HTTP",
            "The first request is unencrypted, even if a later redirect uses HTTPS. Use a verified HTTPS address when possible.")
    if final and urlsplit(final).scheme != "https":
        add("unencrypted_destination", "The final page uses unencrypted HTTP",
            "The returned page was not protected by HTTPS. Avoid entering passwords or payment information on this connection.", "red")
    if fetched.error_kind == "downgrade":
        add("downgrade", "An HTTPS-to-HTTP redirect was blocked",
            "The link tried to leave an encrypted connection. Verifact stopped before contacting the unencrypted destination.", "red")
    if fetched.error:
        add("incomplete_route", "The complete destination could not be reached",
            fetched.error + " No conclusion about the final destination can be drawn.", "unknown")
    return {"input_url": input_url, "final_url": final, "redirects": chain,
            "redirect_count": sum(item["status"] in {301, 302, 303, 307, 308} for item in chain),
            "host_changes": sum(before != after for before, after in zip(route_hosts, route_hosts[1:])),
            "completed": fetched.response is not None,
            "warnings": warnings, "expected_domain": expected, "expected_match": expected_match,
            "error": fetched.error, "error_kind": fetched.error_kind,
            "note": "URL structure and redirects are observations, not proof of a scam or a site's identity. Full accepted paths and query strings are included in this report; do not share reports containing private links."}
