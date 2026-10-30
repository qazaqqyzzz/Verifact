"""Exercise real HTTPResponse framing, without contacting external websites."""

from contextlib import contextmanager
import socket
import unittest
from unittest.mock import Mock, patch

from verifact.checks import page_checks, transport_checks
from verifact.network import Client, Fetch, ScanError, normalize_domain, response_headers, validate_url


PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, 6, ("93.184.215.14", 80))


class ConnectedFixtureSocket:
    """An already connected socketpair; only the production connect is replaced."""

    def __init__(self, connected):
        self.connected = connected

    def connect(self, address):
        if address != PUBLIC[3]:
            raise AssertionError("Unexpected destination in isolated fixture")

    def __getattr__(self, name):
        return getattr(self.connected, name)


@contextmanager
def wire_response(wire):
    client_socket, peer = socket.socketpair()
    adapter = ConnectedFixtureSocket(client_socket)
    try:
        # The request is tiny and fits the socket buffer; no responding thread,
        # server listener, DNS lookup or external network is needed.
        peer.sendall(wire)
        peer.shutdown(socket.SHUT_WR)
        with patch("verifact.network.resolve_public", return_value=[PUBLIC]), \
                patch("verifact.network.socket.socket", return_value=adapter):
            yield adapter
    finally:
        client_socket.close()
        peer.close()


class BodyFramingRegressionTests(unittest.TestCase):
    def test_default_port_host_header_matches_verified_hostname_on_the_wire(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                client_socket, peer = socket.socketpair()
                adapter = ConnectedFixtureSocket(client_socket)
                adapter.getpeercert = lambda: {"notAfter": "Dec 31 23:59:59 2099 GMT"}
                adapter.version = lambda: "TLSv1.3"
                context = Mock()
                context.wrap_socket.return_value = adapter
                try:
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    peer.shutdown(socket.SHUT_WR)
                    with patch("verifact.network.resolve_public", return_value=[PUBLIC]) as resolve, \
                            patch("verifact.network.socket.socket", return_value=adapter), \
                            patch("verifact.network.ssl.create_default_context", return_value=context):
                        response = Client().request(scheme + "://example.com/path")
                    request = peer.recv(4096)
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"\r\nHost: example.com\r\n", request)
                    self.assertEqual(request.count(b"\r\nHost:"), 1)
                    self.assertNotIn(b"Host: example.com:443", request)
                    resolve.assert_called_once_with("example.com", 443 if scheme == "https" else 80)
                    if scheme == "https":
                        context.wrap_socket.assert_called_once_with(adapter, server_hostname="example.com")
                        self.assertTrue(response.tls["verified"])
                    else:
                        context.wrap_socket.assert_not_called()
                finally:
                    client_socket.close()
                    peer.close()

    def test_connection_close_after_exact_body_keeps_successful_response(self):
        body = b"<title>Complete page</title>"
        wire = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                b"Connection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        with wire_response(wire) as sock:
            fetched = Client().fetch("http://example.com/")
            self.assertEqual(sock.fileno(), -1)
        self.assertIsNone(fetched.error)
        self.assertEqual(fetched.response.status, 403)
        self.assertEqual(fetched.response.body, body)
        self.assertFalse(fetched.response.truncated)
        self.assertIsNone(fetched.response.body_error)
        self.assertEqual(transport_checks(fetched, Fetch(None))[0]["status"], "attention")

    def test_short_content_length_is_incomplete_not_a_clean_page(self):
        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 100\r\nConnection: close\r\n"
                b"Strict-Transport-Security: max-age=3600\r\n\r\n<title>Partial</title>")
        with wire_response(wire):
            response = Client().request("http://example.com/")
        self.assertTrue(response.truncated)
        self.assertIn("declared length", response.body_error)
        self.assertEqual(response.headers["strict-transport-security"], "max-age=3600")
        findings = {item["id"]: item for item in page_checks(response)}
        self.assertEqual(findings["http_resources"]["status"], "unknown")
        self.assertEqual(findings["password_forms"]["status"], "unknown")

    def test_malformed_chunked_body_preserves_headers_and_marks_incomplete(self):
        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n"
                b"X-Content-Type-Options: nosniff\r\n\r\n5\r\nhello\r\nINVALID\r\n")
        with wire_response(wire):
            response = Client().request("http://example.com/")
        self.assertTrue(response.truncated)
        self.assertIsNotNone(response.body_error)
        self.assertEqual(response.body, b"hello")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_body_timeout_keeps_verified_tls_and_received_headers(self):
        sock, connection = Mock(), Mock()
        incoming = Mock(status=200, length=None)
        incoming.isclosed.return_value = False
        incoming.getheaders.return_value = [("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=3600")]
        incoming.read1.side_effect = [b"<title>Partial", TimeoutError("timeout")]
        connection.getresponse.return_value = incoming
        context = Mock()
        context.wrap_socket.return_value = sock
        sock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2099 GMT"}
        sock.version.return_value = "TLSv1.3"
        with patch("verifact.network.resolve_public", return_value=[PUBLIC]), \
                patch("verifact.network.socket.socket", return_value=sock), \
                patch("verifact.network.ssl.create_default_context", return_value=context), \
                patch("verifact.network.http.client.HTTPConnection", return_value=connection):
            fetched = Client().fetch("https://example.com/")
        context.wrap_socket.assert_called_once_with(sock, server_hostname="example.com")
        self.assertIsNone(fetched.error)
        self.assertTrue(fetched.response.truncated)
        self.assertIsNotNone(fetched.response.body_error)
        self.assertTrue(fetched.response.tls["verified"])
        findings = {item["id"]: item for item in transport_checks(Fetch(None), fetched)}
        self.assertEqual(findings["tls"]["status"], "pass")
        incoming.close.assert_called_once()

    def test_size_limit_still_bounds_body_without_claiming_early_eof(self):
        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: 30\r\nConnection: close\r\n\r\n" + b"a" * 30)
        with wire_response(wire):
            response = Client(max_bytes=8).request("http://example.com/")
        self.assertEqual(response.body, b"a" * 8)
        self.assertTrue(response.truncated)
        self.assertIsNone(response.body_error)

    def test_no_content_response_needs_no_body(self):
        with wire_response(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"):
            response = Client().request("http://example.com/")
        self.assertEqual(response.status, 204)
        self.assertFalse(response.truncated)
        self.assertEqual(response.body, b"")


class HeaderAndDestinationRegressionTests(unittest.TestCase):
    def test_ambiguous_unicode_spelling_does_not_select_another_host(self):
        for value in ["faß.de", "fa\u200dss.de", "FAẞ.de"]:
            with self.subTest(value=value), self.assertRaisesRegex(ScanError, "ambiguous"):
                normalize_domain(value)
        with self.assertRaisesRegex(ScanError, "ambiguous"):
            validate_url("https://faß.de/login")

    def test_unambiguous_unicode_and_explicit_punycode_are_preserved(self):
        for value in ["BÜCHER.de", "bu\u0308cher.de", "xn--bcher-kva.de"]:
            with self.subTest(value=value):
                self.assertEqual(normalize_domain(value), "xn--bcher-kva.de")
        self.assertEqual(normalize_domain("xn--fa-hia.de"), "xn--fa-hia.de")

    def test_first_hsts_field_controls_observation(self):
        headers, _ = response_headers([("Strict-Transport-Security", "max-age=3600"),
                                       ("strict-transport-security", "max-age=0")])
        self.assertEqual(headers["strict-transport-security"], "max-age=3600")
        headers, _ = response_headers([("Strict-Transport-Security", ""),
                                       ("Strict-Transport-Security", "max-age=3600")])
        self.assertEqual(headers["strict-transport-security"], "")

    def test_explicit_zero_port_is_not_treated_as_default(self):
        for url in ["http://example.com:0/", "https://example.com:0/"]:
            with self.subTest(url=url), self.assertRaises(ScanError):
                validate_url(url)


class AddressFallbackRegressionTests(unittest.TestCase):
    def test_slow_first_address_does_not_exhaust_healthy_fallback(self):
        clock = [1000.0]
        first, second, connection = Mock(), Mock(), Mock()
        incoming = Mock(status=200, length=None)
        incoming.isclosed.return_value = False
        incoming.getheaders.return_value = [("Content-Type", "text/html")]
        incoming.read1.side_effect = [b"<title>Available</title>", b""]
        connection.getresponse.return_value = incoming
        fallback = (socket.AF_INET, socket.SOCK_STREAM, 6, ("93.184.215.15", 80))

        def first_timeout(address):
            clock[0] += first.settimeout.call_args.args[0]
            raise TimeoutError("first address timed out")

        first.connect.side_effect = first_timeout
        with patch("verifact.network.resolve_public", return_value=[PUBLIC, fallback]), \
                patch("verifact.network.socket.socket", side_effect=[first, second]), \
                patch("verifact.network.time.monotonic", side_effect=lambda: clock[0]), \
                patch("verifact.network.time.sleep"), \
                patch("verifact.network.http.client.HTTPConnection", return_value=connection):
            client = Client(timeout=8)
            fetched = client.fetch("http://example.com/")
        self.assertIsNone(fetched.error)
        self.assertEqual(fetched.response.status, 200)
        first.settimeout.assert_called_once_with(4.0)
        self.assertEqual(second.settimeout.call_args_list[0].args, (4.0,))
        second.connect.assert_called_once_with(fallback[3])
        self.assertEqual(client.requests, 1)
        self.assertEqual(clock[0], 1004.0)

    def test_multiple_unreachable_addresses_share_one_deadline_and_bounded_attempts(self):
        clock, created = [1000.0], []
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, ("93.184.215." + str(n), 80))
                   for n in range(1, 11)]

        def socket_factory(*args):
            sock = Mock()

            def timeout(address):
                clock[0] += sock.settimeout.call_args.args[0]
                raise TimeoutError("address timed out")

            sock.connect.side_effect = timeout
            created.append(sock)
            return sock

        with patch("verifact.network.resolve_public", return_value=answers), \
                patch("verifact.network.socket.socket", side_effect=socket_factory), \
                patch("verifact.network.time.monotonic", side_effect=lambda: clock[0]), \
                patch("verifact.network.time.sleep"), \
                patch("verifact.network.http.client.HTTPConnection") as http:
            client = Client(timeout=8)
            fetched = client.fetch("http://example.com/")
        self.assertIsNone(fetched.response)
        self.assertIn("Connection failed", fetched.error)
        self.assertEqual(len(created), 8)
        self.assertAlmostEqual(clock[0], 1008.0)
        self.assertEqual(client.requests, 1)
        http.assert_not_called()
        for sock in created:
            sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
