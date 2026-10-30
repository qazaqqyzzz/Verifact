"""Referrer declaration review: no browser requests or external services."""

import unittest

from websignal.assessment import assess
from websignal.checks import page_checks
from websignal.network import Response, response_headers


def review(header=None, body=b"<html><head><title>Example</title></head><body></body></html>", **options):
    headers = {"content-type": "text/html"}
    if header is not None:
        headers["referrer-policy"] = header
    response = Response("https://example.com/public", 200, headers, body, **options)
    return next(item for item in page_checks(response) if item["id"] == "referrer")


class ReferrerReviewTests(unittest.TestCase):
    def test_only_explicit_unsafe_url_gets_attention(self):
        item = review("unsafe-url")
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["policy"], "unsafe-url")
        self.assertEqual(item["evidence"]["source"], "header")
        self.assertIn("When applied", item["explanation"])
        self.assertIn("not the effective policy", item["explanation"])
        self.assertIn("strict-origin-when-cross-origin", item["recommendation"])
        self.assertIn("if suitable", item["recommendation"])
        for header in (None, "", "unknown-value", "never", "always", '"unsafe-url"',
                       "no-referrer", "strict-origin", "same-origin", "origin",
                       "strict-origin-when-cross-origin", "origin-when-cross-origin", "no-referrer-when-downgrade"):
            with self.subTest(header=header):
                item = review(header)
                self.assertEqual(item["status"], "info")
                self.assertEqual(item["recommendation"], "")

    def test_header_list_uses_last_recognized_token_not_first_or_last_raw_value(self):
        cases = [("unsafe-url, no-referrer", "no-referrer", "info"),
                 ("no-referrer, unsafe-url", "unsafe-url", "attention"),
                 ("no-referrer, future-policy, unsafe-url, future-policy", "unsafe-url", "attention"),
                 ("unsafe-url, nonsense", "unsafe-url", "attention"),
                 ("unsafe-url; no-referrer", None, "info"),
                 (" UNSAFE-URL \t", "unsafe-url", "attention"),
                 ("\u00a0unsafe-url\u00a0", None, "info")]
        for header, policy, status in cases:
            with self.subTest(header=header):
                item = review(header)
                self.assertEqual(item["evidence"]["policy"], policy)
                self.assertEqual(item["status"], status)

    def test_multiple_header_fields_preserve_token_order(self):
        headers, _ = response_headers([("Referrer-Policy", "unsafe-url"), ("Referrer-Policy", "same-origin")])
        self.assertEqual(review(headers["referrer-policy"])["evidence"]["policy"], "same-origin")

    def test_header_is_reviewed_first_without_claiming_to_override_html(self):
        html = b'<meta name="referrer" content="unsafe-url">'
        item = review("strict-origin", html)
        self.assertEqual(item["status"], "info")
        self.assertEqual(item["evidence"]["source"], "header")
        self.assertEqual(item["evidence"]["meta_policies"], ["unsafe-url"])
        self.assertIn("HTML metadata", item["explanation"])
        self.assertIn("may change behavior", item["explanation"])
        opposite = review("unsafe-url", b'<meta name="referrer" content="no-referrer">')
        self.assertEqual(opposite["status"], "attention")
        self.assertEqual(opposite["evidence"]["policy"], "unsafe-url")

    def test_supported_single_meta_policy_is_fallback(self):
        for header in (None, "unknown-policy"):
            item = review(header, b'<head><meta name="ReFeRrEr" content="UNSAFE-URL"></head>')
            self.assertEqual(item["status"], "attention")
            self.assertEqual(item["evidence"]["source"], "meta")
        for value in (b"unsafe-url, no-referrer", b"never", b"always", b" unsafe-url ", b"unsafe-url;", b""):
            with self.subTest(value=value):
                self.assertEqual(review(body=b'<meta name="referrer" content="' + value + b'">')["status"], "info")

    def test_last_supported_static_meta_declaration_selected(self):
        item = review(body=b'<meta name="referrer" content="unsafe-url"><meta name="referrer" content="no-referrer">'
                           b'<meta name="referrer" content="future-policy">')
        self.assertEqual(item["evidence"]["policy"], "no-referrer")
        self.assertEqual(item["status"], "info")

    def test_inert_metadata_and_http_equiv_are_not_active_referrer_declarations(self):
        meta = b'<meta name="referrer" content="unsafe-url">'
        for container in (b"template", b"noscript", b"iframe", b"textarea", b"title", b"xmp", b"noembed", b"noframes", b"svg", b"math"):
            with self.subTest(container=container):
                item = review(body=b"<" + container + b">" + meta + b"</" + container + b">")
                self.assertEqual(item["status"], "info")
                self.assertEqual(item["evidence"]["meta_policies"], [])
        self.assertEqual(review(body=b'<meta http-equiv="referrer" content="unsafe-url">')["status"], "info")

    def test_duplicate_attributes_use_first_browser_attribute(self):
        item = review(body=b'<meta name="referrer" content="no-referrer" content="unsafe-url">')
        self.assertEqual(item["evidence"]["policy"], "no-referrer")
        self.assertEqual(item["status"], "info")

    def test_truncated_html_does_not_establish_meta_policy_but_header_is_observable(self):
        meta = b'<meta name="referrer" content="unsafe-url">'
        item = review(body=meta, truncated=True)
        self.assertEqual(item["status"], "unknown")
        self.assertIsNone(item["evidence"]["policy"])
        self.assertEqual(review("unsafe-url", meta, truncated=True)["status"], "attention")

    def test_metadata_and_header_evidence_are_bounded(self):
        item = review(body=b'<meta name="referrer" content="no-referrer">' * 32 + b'<meta name="referrer" content="unsafe-url">')
        self.assertEqual(item["status"], "unknown")
        self.assertEqual(len(item["evidence"]["meta_policies"]), 32)
        self.assertTrue(item["evidence"]["limited"])
        huge = review("unsafe-url," + "x" * 9000)
        self.assertEqual(huge["status"], "unknown")
        self.assertLessEqual(len(huge["evidence"]["header"]), 8192)

    def test_referrer_has_no_numeric_score_weight(self):
        self.assertEqual(assess({"findings": [review("unsafe-url")]}),
                         assess({"findings": [review("strict-origin")]}))


if __name__ == "__main__":
    unittest.main()
