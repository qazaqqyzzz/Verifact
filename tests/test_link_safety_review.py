"""Independent adversarial checks for exact links and their public boundary."""

import json
import unittest
from unittest.mock import patch

from websignal.links import analyze_link, normalize_target
from websignal.network import Client, Fetch, Response, ScanError
from websignal.scanner import scan


def response(url, status=200, location=None):
    headers = {"content-type": "text/html", "strict-transport-security": "max-age=31536000"}
    if location:
        headers["location"] = location
    return Response(url, status, headers, b"<title>Public page</title><p>Page</p>")


class LinkSafetyReviewTests(unittest.TestCase):
    def test_return_to_an_earlier_hostname_counts_both_transitions(self):
        chain = [{"url": "https://first.example/a", "status": 302},
                 {"url": "https://second.example/b", "status": 302},
                 {"url": "https://first.example/c", "status": 200}]
        analysis = analyze_link(chain[0]["url"], Fetch(response(chain[-1]["url"]), chain))
        self.assertEqual(analysis["host_changes"], 2)
        self.assertEqual(analysis["redirect_count"], 2)

    def test_exact_http_page_cannot_earn_hsts_or_a_verified_tls_light(self):
        target = "http://public.example/page"
        with patch.object(Client, "request", side_effect=lambda url: response(url)):
            report = scan(target)
        findings = {item["id"]: item for item in report["findings"]}
        self.assertEqual(findings["tls"]["status"], "attention")
        self.assertEqual(findings["hsts"]["status"], "attention")
        self.assertEqual(report["dashboard"]["rating"]["tone"], "red")
        self.assertEqual(report["response"]["url"], target)

    def test_redirect_to_encoded_token_is_not_requested_or_serialized(self):
        client = Client()
        first = response("https://public.example/page", 302, "/continue?%61ccess_token=one-time-private-value")
        with patch.object(client, "request", return_value=first) as request:
            fetched = client.fetch(first.url, url_validator=normalize_target)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(fetched.error_kind, "blocked")
        analysis = analyze_link(first.url, fetched, "public.example")
        self.assertFalse(analysis["completed"])
        self.assertIsNone(analysis["expected_match"])
        self.assertNotIn("one-time-private-value", json.dumps(analysis))

    def test_dns_private_redirect_still_passes_through_the_transport_gate(self):
        client = Client()
        original = client.request
        first = response("https://public.example/path", 302, "https://rebound.example/secret")

        def request(url):
            return first if url == first.url else original(url)

        with patch.object(client, "request", side_effect=request), \
                patch("websignal.network.resolve_public", side_effect=ScanError("Blocked non-public address.", "blocked")) as resolver, \
                patch("websignal.network.socket.socket") as socket:
            fetched = client.fetch(first.url, url_validator=normalize_target)
        resolver.assert_called_once_with("rebound.example", 443)
        socket.assert_not_called()
        self.assertEqual(fetched.error_kind, "blocked")
        self.assertEqual(fetched.chain, [{"url": first.url, "status": 302}])

    def test_expected_domain_cannot_be_hidden_in_suffix_or_path(self):
        for url in ("https://trusted.example.evil.net/login", "https://evil.net/trusted.example", "https://nottrusted.example/"):
            with self.subTest(url=url):
                analysis = analyze_link(url, Fetch(response(url), [{"url": url, "status": 200}]), "trusted.example")
                self.assertFalse(analysis["expected_match"])
                self.assertIn("expected_domain_mismatch", {item["id"] for item in analysis["warnings"]})


if __name__ == "__main__":
    unittest.main()
