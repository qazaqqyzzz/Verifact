"""Exact-link coverage and conservative URL observations, all offline."""

import io
import json
import unittest
from unittest.mock import patch

from websignal.cli import main
from websignal.links import analyze_link, domain_matches, normalize_target
from websignal.network import Client, Fetch, Response, ScanError
from websignal.scanner import scan


def observed(url, status=200, location=None):
    headers = {"content-type": "text/html"}
    if location is not None:
        headers["location"] = location
    tls = {"verified": True, "hostname": "example.com", "not_after": "Dec 31 23:59:59 2099 GMT"} if url.startswith("https:") else {}
    return Response(url, status, headers, b"<title>Page at exact link</title>", tls=tls)


class ExactURLTests(unittest.TestCase):
    def test_path_and_benign_query_are_preserved_fragment_is_omitted(self):
        self.assertEqual(normalize_target(" EXAMPLE.COM/search?q=one%20two&page=2#section "),
                         "https://example.com/search?q=one%20two&page=2")
        self.assertEqual(normalize_target("https://example.com:443/тест?q=hello world"),
                         "https://example.com/%D1%82%D0%B5%D1%81%D1%82?q=hello%20world")
        self.assertEqual(normalize_target("example.com"), "https://example.com/")

    def test_private_tokens_and_action_links_are_rejected(self):
        for url in ["https://example.com/?access_token=secret", "https://example.com/?%74oken=secret",
                    "https://example.com/?api-key=secret", "https://example.com/oauth?code=secret",
                    "https://example.com/account/reset-password/secret", "https://example.com/unsubscribe/secret"]:
            with self.subTest(url=url), self.assertRaisesRegex(ScanError, "private|one-time"):
                normalize_target(url)
        self.assertEqual(normalize_target("https://example.com/reset-password"), "https://example.com/reset-password")

    def test_unsafe_url_syntax_cannot_become_a_fetch_target(self):
        for value in ["http://127.0.0.1/", "https://user:pass@example.com/path", "https://example.com:444/path",
                      "https://example.com/a\r\nb", "file:///etc/passwd", "example.com/a" * 200]:
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_target(value)

    def test_exact_https_url_is_assessed_separately_from_http_homepage(self):
        target = "https://example.com/catalog?item=12"
        requests = []

        def request(_client, url):
            requests.append(url)
            return observed(url, 301, "https://example.com/") if url == "http://example.com/" else observed(url)

        with patch.object(Client, "request", request):
            report = scan(target, expected_domain="example.com")
        self.assertEqual(requests, [target, "http://example.com/", "https://example.com/"])
        self.assertEqual(report["response"]["url"], target)
        self.assertEqual(report["target_url"], target)
        self.assertEqual(report["link_analysis"]["final_url"], target)
        self.assertTrue(report["link_analysis"]["expected_match"])

    def test_http_input_is_not_silently_replaced_by_https(self):
        target = "http://example.com/item?id=12"
        with patch.object(Client, "request", side_effect=lambda url: observed(url)) as request:
            report = scan(target)
        self.assertEqual([call.args[0] for call in request.call_args_list], [target, "http://example.com/"])
        self.assertEqual(report["response"]["url"], target)
        tls = next(item for item in report["findings"] if item["id"] == "tls")
        self.assertEqual(tls["status"], "attention")
        self.assertIn("unencrypted", tls["explanation"])
        self.assertIn("unencrypted_destination", [item["id"] for item in report["link_analysis"]["warnings"]])
        self.assertEqual(report["dashboard"]["rating"]["tone"], "red")
        priority = next(item for item in report["dashboard"]["priorities"] if item["finding_id"] == "tls")
        self.assertEqual(priority["title"], "Unencrypted destination")
        self.assertIn("unencrypted HTTP page", priority["detail"])
        self.assertEqual(priority["tone"], "red")

    def test_sensitive_redirect_stops_before_any_private_link_request(self):
        client = Client()
        first = observed("https://example.com/", 302, "/reset-password/secret")
        with patch.object(client, "request", return_value=first) as request:
            fetched = client.fetch(first.url, url_validator=normalize_target)
        request.assert_called_once_with(first.url)
        self.assertEqual(fetched.error_kind, "blocked")
        self.assertIsNone(fetched.response)
        self.assertNotIn("secret", json.dumps(analyze_link(first.url, fetched)))

    def test_stdin_target_is_supported_and_not_echoed(self):
        target = "https://example.com/search?q=private-search-term"
        with patch("sys.stdin", io.StringIO(target)), patch("sys.stdout", new_callable=io.StringIO) as stdout, \
                patch("sys.stderr", new_callable=io.StringIO) as stderr, \
                patch.object(Client, "request", side_effect=lambda url: observed(url)):
            code = main(["scan", "--target-stdin", "--expected-domain", "example.com", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["target_url"], target)
        self.assertNotIn("private-search-term", stderr.getvalue())


class LinkObservationTests(unittest.TestCase):
    def test_expected_domain_matches_only_boundary_aligned_subdomains(self):
        self.assertTrue(domain_matches("login.example.com", "example.com"))
        self.assertFalse(domain_matches("example.com.evil.net", "example.com"))
        self.assertFalse(domain_matches("notexample.com", "example.com"))

    def test_misleading_subdomain_and_final_mismatch_have_concrete_evidence(self):
        url = "https://example.com.attacker.net/login"
        result = analyze_link(url, Fetch(observed(url), [{"url": url, "status": 200}]), "example.com")
        identifiers = {item["id"] for item in result["warnings"]}
        self.assertFalse(result["expected_match"])
        self.assertIn("misleading_subdomain", identifiers)
        self.assertIn("expected_domain_mismatch", identifiers)

    def test_legitimate_international_domain_is_not_called_a_scam(self):
        url = normalize_target("https://bücher.de/")
        result = analyze_link(url, Fetch(observed(url), [{"url": url, "status": 200}]))
        self.assertEqual(result["warnings"][0]["id"], "international_domain")
        self.assertEqual(result["warnings"][0]["tone"], "unknown")
        self.assertIn("legitimate", result["warnings"][0]["detail"])

    def test_mixed_script_lookalike_gets_a_limited_warning(self):
        url = normalize_target("https://pаypal.com/")  # Second character is Cyrillic.
        result = analyze_link(url, Fetch(observed(url), [{"url": url, "status": 200}]), "paypal.com")
        identifiers = {item["id"] for item in result["warnings"]}
        self.assertIn("mixed_script", identifiers)
        self.assertIn("similar_spelling", identifiers)

    def test_redirect_chain_preserves_response_order_and_reports_host_change(self):
        chain = [{"url": "https://short.example/abc", "status": 302},
                 {"url": "https://example.com/page", "status": 200}]
        result = analyze_link(chain[0]["url"], Fetch(observed(chain[1]["url"]), chain), "example.com")
        self.assertEqual(result["redirects"], chain)
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["host_changes"], 1)
        self.assertTrue(result["completed"])
        self.assertTrue(result["expected_match"])
        self.assertEqual(result["warnings"][0]["id"], "host_change")

    def test_blocked_downgrade_has_no_fabricated_final_destination(self):
        url = "https://example.com/"
        fetched = Fetch(None, [{"url": url, "status": 302}], "HTTPS-to-HTTP downgrade redirect observed and blocked.", "downgrade")
        result = analyze_link(url, fetched, "example.com")
        self.assertIsNone(result["final_url"])
        self.assertIsNone(result["expected_match"])
        self.assertFalse(result["completed"])
        self.assertIn("downgrade", [item["id"] for item in result["warnings"]])


if __name__ == "__main__":
    unittest.main()
