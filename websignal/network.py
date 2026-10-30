"""Small, bounded HTTP client that connects only to validated public IPs.

DNS answers are checked before connecting, and the socket is pinned to a
validated address. TLS still verifies the original hostname using SNI.
"""

from dataclasses import dataclass, field
import http.client
import ipaddress
import re
import socket
import ssl
import time
import unicodedata
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from . import __version__


class ScanError(Exception):
    def __init__(self, message, kind="unavailable"):
        super().__init__(message)
        self.kind = kind


def normalize_domain(value):
    value = value.strip().rstrip(".")
    if not value or any(c in value for c in "/:@?#\\%") or any(c.isspace() for c in value):
        raise ScanError("Enter a domain such as example.com, without a URL, port or path.", "blocked")
    try:
        spelling = unicodedata.normalize("NFC", value.lower())
        value = spelling.encode("idna").decode("ascii")
        # The standard-library codec is IDNA 2003. Reject deviation mappings
        # (e.g. ß -> ss) rather than checking a different host from a browser.
        # An explicitly supplied ASCII/punycode hostname is used as written.
        if not spelling.isascii() and value.encode("ascii").decode("idna") != spelling:
            raise ScanError("This international domain has an ambiguous spelling. Use its exact ASCII/punycode hostname.", "blocked")
    except UnicodeError as exc:
        raise ScanError("Invalid international domain name.", "blocked") from exc
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ScanError("IP literals are not accepted; enter a public domain.", "blocked")
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels)
            or labels[-1] in {"localhost", "local", "internal", "test", "invalid", "onion"}):
        raise ScanError("A valid public domain is required.", "blocked")
    return value


def resolve_public(host, port):
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScanError(f"DNS lookup failed for {host}: {exc}") from exc
    result = []
    for family, socktype, protocol, _, sockaddr in answers:
        address = ipaddress.ip_address(sockaddr[0])
        # Reject mixed public/private answers too. Transition addresses are
        # excluded because they can encode destinations outside this policy.
        if (not address.is_global or address.is_multicast
                or (address.version == 6 and (address.ipv4_mapped or address.sixtofour
                    or address.teredo or address in ipaddress.ip_network("64:ff9b::/96")))):
            raise ScanError(f"Blocked non-public or transition address for {host}.", "blocked")
        if sockaddr not in [item[3] for item in result]:
            result.append((family, socktype, protocol, sockaddr))
    if not result:
        raise ScanError("No public DNS addresses returned.")
    return result


def validate_url(url):
    if any(ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ScanError("Blocked malformed redirect URL.", "blocked")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
            raise ValueError("Only HTTP(S) URLs without credentials are supported")
        host = normalize_domain(parsed.hostname or "")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if port != (443 if parsed.scheme == "https" else 80):
            raise ValueError("Only standard HTTP/HTTPS ports are supported")
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="%=&?/:@!$'()*+,;~-._")
        canonical = urlunsplit((parsed.scheme, host, path, query, ""))
        return canonical, host, port, path + ("?" + query if query else "")
    except ValueError as exc:
        raise ScanError(f"Blocked URL: {exc}", "blocked") from exc


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes = b""
    truncated: bool = False
    addresses: list = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    # Set-Cookie is not a comma-separated header. Preserve field boundaries in
    # memory; reports expose only redacted attribute observations.
    set_cookie_headers: list | None = None
    # A complete header block remains useful even when its body was cut short.
    body_error: str | None = None


def response_headers(fields):
    """Keep Set-Cookie fields separate; Expires dates can contain commas."""
    headers, cookies = {}, []
    for key, value in fields:
        key = key.lower()
        if key == "set-cookie":
            cookies.append(value)
        elif key == "strict-transport-security":
            # RFC 6797 §8.1: process only the first STS field, not a joined value.
            headers.setdefault(key, value)
        else:
            headers[key] = headers.get(key, "") + (", " if key in headers else "") + value
    return headers, cookies


@dataclass
class Fetch:
    response: Response | None
    chain: list = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None


class Client:
    def __init__(self, timeout=8.0, max_bytes=2 * 1024 * 1024, max_redirects=3, max_requests=12):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.max_requests = max_requests
        self.requests = 0
        self.cache = {}
        self.last_request = 0.0

    def request(self, url):
        url, host, port, path = validate_url(url)
        if url in self.cache:
            return self.cache[url]
        if self.requests >= self.max_requests:
            raise ScanError("Scan request budget exhausted.")
        answers = resolve_public(host, port)
        time.sleep(max(0, 0.25 - (time.monotonic() - self.last_request)))
        self.requests += 1
        self.last_request = time.monotonic()
        deadline = self.last_request + self.timeout
        sock = None
        connection = None
        response = None
        try:
            last_error = None
            candidates = answers[:8]
            for index, (family, socktype, protocol, sockaddr) in enumerate(candidates):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    last_error = TimeoutError("Connection deadline exceeded")
                    break
                try:
                    sock = socket.socket(family, socktype, protocol)
                    # A stale first DNS address must not consume the entire
                    # deadline. Share the remaining time among bounded fallback
                    # candidates; the overall request deadline never restarts.
                    sock.settimeout(remaining / (len(candidates) - index))
                    sock.connect(sockaddr)
                    break
                except OSError as exc:
                    if sock:
                        sock.close()
                    sock = None
                    last_error = exc
                    if time.monotonic() >= deadline:
                        break
            if sock is None:
                raise ScanError(f"Connection failed: {last_error}")
            tls = {}
            if port == 443:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                cert = sock.getpeercert()
                tls = {"hostname": host, "verified": True, "version": sock.version(),
                       "not_after": cert.get("notAfter"), "not_before": cert.get("notBefore"),
                       "issuer": ", ".join(f"{k}={v}" for part in cert.get("issuer", ()) for k, v in part)}
            # A socket is already connected. HTTPConnection must not resolve
            # the hostname again or consult environment proxy settings.
            connection = http.client.HTTPConnection(host, port, timeout=self.timeout)
            connection.sock = sock
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            # HTTPConnection transports an already verified TLS socket here.
            # Set the standard-port authority explicitly so it does not append
            # :443 as though this were plain HTTP (some virtual hosts differ).
            connection.request("GET", path, headers={"Host": host, "User-Agent": f"Verifact/{__version__} (public configuration check)",
                               "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            headers, cookies = response_headers(response.getheaders())
            body = bytearray()
            body_error = None
            is_redirect = response.status in {301, 302, 303, 307, 308}
            try:
                while not is_redirect and len(body) <= self.max_bytes:
                    # read1 closes a Connection: close socket as soon as its
                    # declared final bytes arrive. Do not settimeout on it again.
                    if response.isclosed() is True:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Response body deadline exceeded")
                    sock.settimeout(remaining)
                    chunk = response.read1(min(16384, self.max_bytes + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                # read1 may silently accept EOF before Content-Length is met.
                if (not is_redirect and len(body) <= self.max_bytes
                        and type(response.length) is int and response.length > 0):
                    body_error = "Response body ended before its declared length."
            except (OSError, http.client.HTTPException):
                # Keep verified TLS and received headers; body-based checks must
                # remain unassessed. Never expose arbitrary server error text.
                body_error = "Response body could not be completely read within the request limit."
            result = Response(url, response.status, headers, bytes(body[:self.max_bytes]),
                              len(body) > self.max_bytes or body_error is not None,
                              sorted({x[3][0] for x in answers}), tls, cookies, body_error)
            self.cache[url] = result
            return result
        except ssl.SSLCertVerificationError as exc:
            raise ScanError(f"TLS certificate could not be verified: {exc.verify_message}", "tls_verification") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ScanError(f"Request unavailable: {exc}") from exc
        finally:
            if response:
                response.close()
            if connection:
                connection.close()
            if sock:
                sock.close()

    def fetch(self, url, url_validator=None):
        chain = []
        visited = set()
        try:
            for hop in range(self.max_redirects + 1):
                url, *_ = validate_url(url)
                if url_validator is not None:
                    url = url_validator(url)
                if url in visited:
                    raise ScanError("Redirect loop detected.")
                visited.add(url)
                response = self.request(url)
                chain.append({"url": response.url, "status": response.status})
                if response.status not in {301, 302, 303, 307, 308}:
                    return Fetch(response, chain)
                location = response.headers.get("location")
                if not location:
                    raise ScanError("Redirect response has no Location header.")
                if hop == self.max_redirects:
                    raise ScanError("Redirect limit reached.")
                target, *_ = validate_url(urljoin(url, location))
                if urlsplit(url).scheme == "https" and urlsplit(target).scheme == "http":
                    raise ScanError("HTTPS-to-HTTP downgrade redirect observed and blocked.", "downgrade")
                url = target
        except ScanError as exc:
            return Fetch(None, chain, str(exc), exc.kind)
