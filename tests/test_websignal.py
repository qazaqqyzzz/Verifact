import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from websignal.checks import page_checks, transport_checks
from websignal.cli import main
from websignal.network import Client, Fetch, Response, ScanError, normalize_domain, resolve_public, validate_url
from websignal.reports import html_report, text_report
from websignal.scanner import demo_report


PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80))
PRIVATE = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))


class DestinationTests(unittest.TestCase):
    def test_invalid_inputs_are_blocked(self):
        for domain in ["localhost", "127.0.0.1", "::1", "https://example.com", "example.com:8080",
                       "user@example.com", "example.com/path", "a.local", "a..com", "-bad.com", "2130706433"]:
            with self.subTest(domain=domain), self.assertRaises(ScanError):
                normalize_domain(domain)
        self.assertEqual(normalize_domain(" EXAMPLE.COM. "), "example.com")

    def test_redirect_url_validation(self):
        for url in ["file:///etc/passwd", "http://127.0.0.1/", "https://example.com:8443/",
                    "https://user:pass@example.com/", "https://example.com/\r\nInjected: x",
                    "http://example.com\\@localhost/"]:
            with self.subTest(url=url), self.assertRaises(ScanError):
                validate_url(url)

    def test_mixed_dns_answers_are_blocked(self):
        with patch("websignal.network.socket.getaddrinfo", return_value=[PUBLIC, PRIVATE]), self.assertRaises(ScanError):
            resolve_public("example.com", 80)

    def test_ipv6_and_cloud_metadata_addresses_are_blocked(self):
        for ip in ["169.254.169.254", "10.1.2.3", "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::"]:
            answer = (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))
            with self.subTest(ip=ip), patch("websignal.network.socket.getaddrinfo", return_value=[answer]), self.assertRaises(ScanError):
                resolve_public("example.com", 80)

    def test_connection_uses_validated_ip_without_second_dns_lookup(self):
        sock = Mock()
        http = Mock()
        response = Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.read1.side_effect = [b"<html></html>", b""]
        http.getresponse.return_value = response
        with patch("websignal.network.socket.getaddrinfo", side_effect=[[PUBLIC], [PRIVATE]]) as resolver, \
                patch("websignal.network.socket.socket", return_value=sock), \
                patch("websignal.network.http.client.HTTPConnection", return_value=http):
            result = Client().request("http://example.com/")
        resolver.assert_called_once()
        sock.connect.assert_called_once_with(PUBLIC[4])
        self.assertIs(http.sock, sock)
        self.assertEqual(result.status, 200)

    def test_redirect_to_private_host_is_revalidated(self):
        client = Client()
        first = Response("http://example.com/", 302, {"location": "http://internal.example.com/"})
        real_request = client.request
        with patch.object(client, "request", side_effect=lambda url: first if url == first.url else real_request(url)), \
                patch("websignal.network.socket.getaddrinfo", return_value=[PRIVATE]), \
                patch("websignal.network.socket.socket") as connect:
            result = client.fetch(first.url)
        self.assertEqual(result.error_kind, "blocked")
        connect.assert_not_called()

    def test_downgrade_and_redirect_loop_stop(self):
        client = Client()
        with patch.object(client, "request", return_value=Response("https://example.com/", 302, {"location": "http://example.com/"})) as request:
            result = client.fetch("https://example.com/")
        self.assertEqual(result.error_kind, "downgrade")
        request.assert_called_once()
        with patch.object(client, "request", return_value=Response("http://example.com/", 302, {"location": "/"})):
            self.assertIn("loop", client.fetch("http://example.com/").error)

    def test_response_size_is_bounded(self):
        sock, http, response = Mock(), Mock(), Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.read1.return_value = b"12345"
        http.getresponse.return_value = response
        with patch("websignal.network.socket.getaddrinfo", return_value=[PUBLIC]), \
                patch("websignal.network.socket.socket", return_value=sock), \
                patch("websignal.network.http.client.HTTPConnection", return_value=http):
            result = Client(max_bytes=4).request("http://example.com/")
        self.assertTrue(result.truncated)
        self.assertEqual(result.body, b"1234")


class InterpretationTests(unittest.TestCase):
    def test_failed_fetch_is_unknown(self):
        result = transport_checks(Fetch(None, error="timeout"), Fetch(None, error="timeout"))
        self.assertTrue(all(item["status"] == "unknown" for item in result))
        self.assertTrue(all(item["status"] == "unknown" for item in page_checks(None)))

    def test_html_meta_csp_and_empty_decorative_alt(self):
        response = Response("https://example.com/", 200, {"content-type": "text/html"},
                            b'''<meta http-equiv="Content-Security-Policy" content="default-src 'self'"><img alt="">''')
        findings = {item["id"]: item for item in page_checks(response)}
        self.assertEqual(findings["csp"]["status"], "info")
        self.assertEqual(findings["image_alt"]["status"], "pass")
        self.assertEqual(findings["referrer"]["status"], "info")

    def test_truncated_and_error_pages_do_not_produce_quality_verdicts(self):
        for status, truncated in [(200, True), (403, False)]:
            response = Response("https://example.com/", status, {"content-type": "text/html"}, b"", truncated)
            findings = page_checks(response)
            self.assertTrue(all(item["status"] == "unknown" for item in findings if item["category"] == "Quality"))

    def test_report_escapes_site_content(self):
        report = demo_report()
        report["findings"][0]["evidence"] = '<script>alert("x")</script>\x1b[2J'
        self.assertNotIn('<script>alert', html_report(report))
        self.assertIn("&lt;script&gt;", html_report(report))
        self.assertNotIn("\x1b", text_report(report))

    def test_offline_cli_and_demo_exclusion_from_research(self):
        with tempfile.TemporaryDirectory() as tmp, patch("websignal.network.socket.getaddrinfo") as dns:
            output = Path(tmp) / "demo.json"
            self.assertEqual(main(["demo", "--format", "json", "--output", str(output)]), 0)
            self.assertTrue(json.loads(output.read_text())["demo"])
            with patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(main(["summarize", str(output)]), 2)
            dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
