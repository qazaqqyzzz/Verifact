"""Public contact maintenance: strict bounds, no links opened, no security score."""

from datetime import datetime, timezone
import json
import unittest
from unittest.mock import Mock, patch

from websignal.assessment import assess
from websignal.network import Client, Response, ScanError
from websignal.security_contact import MAX_BYTES, MAX_LINES, PATH, inspect_security_contact, parse_security_contact


NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
URL = "https://site.example" + PATH
VALID = b"Contact: mailto:security@site.example\nExpires: 2027-04-01T12:00:00Z\nCanonical: https://site.example/.well-known/security.txt\n"


def final(url="https://site.example/private/path?token=PRIVATE_TOKEN"):
    return Response(url, 200, {"content-type": "text/html"}, b"<p>site</p>")


def contact(body=VALID, status=200, headers=None, **kwargs):
    return Response(URL, status, headers if headers is not None else {"content-type": "text/plain; charset=utf-8"}, body, **kwargs)


def codes(item):
    return {issue["code"] for issue in item["evidence"]["issues"]}


class SecurityContactParserTests(unittest.TestCase):
    def test_current_contact_is_informational_not_a_safety_pass(self):
        item = parse_security_contact(VALID, URL, NOW)
        self.assertEqual(item["status"], "info")
        self.assertEqual(item["evidence"]["status"], "current")
        self.assertEqual(item["evidence"]["contact_count"], 1)
        self.assertEqual(item["evidence"]["contact_schemes"], ["mailto"])
        self.assertTrue(item["evidence"]["canonical_matches"])
        self.assertIn("does not grant or deny permission", item["explanation"])
        self.assertNotIn("security@", json.dumps(item))

    def test_case_comments_extensions_and_multiple_contacts(self):
        body = (b"# comment\r\nCONTACT: mailto:security%2Bprivate@site.example\r\nContact: tel:+1-555-1234\r\n"
                b"Contact: https://reports.example/PRIVATE_PATH?private=PRIVATE_QUERY\r\n"
                b"X-Unrecognized: SECRET_VALUE\r\nexpires: 2027-04-01t12:00:00z\r\n")
        item = parse_security_contact(body, URL, NOW)
        self.assertEqual(item["evidence"]["status"], "current")
        self.assertEqual(item["evidence"]["contact_count"], 3)
        self.assertEqual(item["evidence"]["contact_schemes"], ["mailto", "tel", "https"])
        self.assertFalse(item["evidence"]["canonical_present"])
        self.assertNotIn("PRIVATE", json.dumps(item))
        self.assertNotIn("SECRET", json.dumps(item))

    def test_missing_and_duplicate_required_fields_never_current(self):
        for body, expected in ((b"Expires: 2027-04-01T12:00:00Z\n", "missing_contact"),
                               (b"Contact: mailto:security@site.example\n", "expires_count"),
                               (VALID + b"Expires: 2027-04-01T12:00:00Z\n", "expires_count")):
            with self.subTest(body=body):
                item = parse_security_contact(body, URL, NOW)
                self.assertEqual(item["status"], "attention")
                self.assertIn(expected, codes(item))

    def test_invalid_contact_uris_do_not_become_usable_contacts(self):
        for value in ("security@site.example", "http://site.example/report", "mailto:", "mailto:missing-address", "https://site.example:99999/", "https://a.example/%XX", "https://a.example/hello world"):
            with self.subTest(value=value):
                body = ("Contact: " + value + "\nExpires: 2027-04-01T12:00:00Z\n").encode()
                item = parse_security_contact(body, URL, NOW)
                self.assertIn("contact_uri", codes(item))
                self.assertEqual(item["status"], "attention")

    def test_expiry_boundaries_and_timezone_are_respected(self):
        for expiry, expected in (("2026-10-31T12:00:00Z", "expired"),
                                 ("2026-10-31T13:00:00+02:00", "expired"),
                                 ("2030-01-01T00:00:00Z", "long_expiry"),
                                 ("2027-02-30T12:00:00Z", "expires_format"),
                                 ("2027-04-01T12:00:00", "expires_format")):
            with self.subTest(expiry=expiry):
                item = parse_security_contact(("Contact: mailto:a@b.example\nExpires: " + expiry + "\n").encode(), URL, NOW)
                self.assertEqual(item["status"], "attention")
                self.assertIn(expected, codes(item))
        item = parse_security_contact(b"Contact: mailto:a@b.example\nExpires: 2026-10-31T14:00:01+02:00\n", URL, NOW)
        self.assertEqual(item["evidence"]["status"], "current")
        item = parse_security_contact(b"Contact: mailto:a@b.example\nExpires: 2026-12-31T23:59:60Z\n", URL, NOW)
        self.assertEqual(item["status"], "unknown")
        self.assertIn("unsupported_expiry", codes(item))

    def test_canonical_matching_is_origin_and_path_specific(self):
        for value in ("https://other.example/.well-known/security.txt", "https://site.example/security.txt", "http://site.example/.well-known/security.txt"):
            with self.subTest(value=value):
                body = VALID.replace(URL.encode(), value.encode())
                item = parse_security_contact(body, URL, NOW)
                self.assertEqual(item["status"], "attention")
                self.assertFalse(item["evidence"]["canonical_matches"])
        body = VALID.replace(URL.encode(), b"https://SITE.EXAMPLE:443/.well-known/security.txt")
        self.assertEqual(parse_security_contact(body, URL, NOW)["evidence"]["status"], "current")

    def test_signature_is_never_claimed_verified_and_trailing_content_is_rejected(self):
        signed = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + VALID + b"-----BEGIN PGP SIGNATURE-----\n\nZmFrZQ==\n-----END PGP SIGNATURE-----\n"
        item = parse_security_contact(signed, URL, NOW)
        self.assertEqual(item["evidence"]["signature"], "present_unverified")
        self.assertEqual(item["evidence"]["status"], "current")
        item = parse_security_contact(signed + b"Contact: mailto:untrusted@other.example\n", URL, NOW)
        self.assertEqual(item["status"], "unknown")
        self.assertEqual(item["evidence"]["signature"], "unsupported")
        self.assertNotIn("untrusted@", json.dumps(item))

    def test_malformed_encoding_lines_and_limits_are_bounded(self):
        for body, status, code in ((b"\xff", "attention", "encoding"),
                                   (VALID + b"Bad field\n", "attention", "field_format"),
                                   (VALID.rstrip(b"\n"), "attention", "final_newline"),
                                   (VALID + b"\x00", "attention", "control_characters"),
                                   (b"#" * (MAX_BYTES + 1), "unknown", "body_limit"),
                                   (b"#" * 2049 + b"\n", "unknown", "line_limit"),
                                   (b"\n" * (MAX_LINES + 1), "unknown", "line_limit")):
            with self.subTest(status=status, code=code):
                item = parse_security_contact(body, URL, NOW)
                self.assertEqual(item["status"], status)
                self.assertIn(code, codes(item))


class SecurityContactRequestTests(unittest.TestCase):
    def test_only_one_standard_path_request_preserves_budget_and_restores_body_limit(self):
        client = Client(max_bytes=100000, max_requests=12)
        def request(url):
            self.assertEqual(url, URL)
            self.assertEqual(client.max_bytes, MAX_BYTES)
            self.assertEqual(client.max_requests, 12)
            return contact()
        with patch.object(client, "request", side_effect=request) as called, patch.object(client, "fetch") as follow:
            item = inspect_security_contact(client, final(), now=NOW)
        called.assert_called_once_with(URL)
        follow.assert_not_called()
        self.assertEqual(client.max_bytes, 100000)
        self.assertEqual(item["evidence"]["status"], "current")
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(item))
        self.assertNotIn("private/path", json.dumps(item))

    def test_no_final_or_http_only_page_makes_no_request(self):
        client = Client()
        for page in (None, final("http://site.example/"), final("https://user:SECRET@site.example/"), final("https://127.0.0.1/")):
            with self.subTest(page=page), patch.object(client, "request") as called:
                item = inspect_security_contact(client, page, now=NOW)
                called.assert_not_called()
                self.assertEqual(item["status"], "unknown")
                self.assertNotIn("SECRET", json.dumps(item))

    def test_redirect_missing_file_and_unavailable_are_distinct(self):
        client = Client()
        for code, status, state in ((301, "unknown", "redirect"), (302, "unknown", "redirect"),
                                    (404, "info", "not_found"), (410, "info", "not_found"), (503, "unknown", "unavailable")):
            with self.subTest(code=code), patch.object(client, "request", return_value=contact(status=code, headers={"location": "https://private.example/TOKEN"})) as called:
                item = inspect_security_contact(client, final(), now=NOW)
                self.assertEqual((item["status"], item["evidence"]["status"]), (status, state))
                called.assert_called_once_with(URL)
                self.assertNotIn("TOKEN", json.dumps(item))

    def test_budget_exhaustion_and_network_errors_are_redacted(self):
        client = Client(max_requests=0)
        item = inspect_security_contact(client, final(), now=NOW)
        self.assertEqual(item["status"], "unknown")
        self.assertEqual(client.requests, 0)
        client = Client(max_bytes=100000)
        with patch.object(client, "request", side_effect=ScanError("SECRET_RAW_ERROR")):
            item = inspect_security_contact(client, final(), now=NOW)
        self.assertEqual(client.max_bytes, 100000)
        self.assertNotIn("SECRET_RAW_ERROR", json.dumps(item))

    def test_html_compression_incomplete_and_oversized_files_never_current(self):
        client = Client()
        responses = [contact(headers={"content-type": "text/html"}), contact(headers={}),
                     contact(headers={"content-type": "text/plain; charset=iso-8859-1"}),
                     contact(headers={"content-type": "text/plain", "content-encoding": "gzip"}),
                     contact(truncated=True), contact(body_error="PRIVATE_ERROR"), contact(b"x" * (MAX_BYTES + 1))]
        for res in responses:
            with self.subTest(res=res.headers), patch.object(client, "request", return_value=res):
                item = inspect_security_contact(client, final(), now=NOW)
                self.assertNotEqual(item["evidence"]["status"], "current")
                self.assertNotIn("PRIVATE_ERROR", json.dumps(item))
        with patch.object(client, "request", return_value=contact(headers={"content-type": "text/plain"})):
            self.assertEqual(inspect_security_contact(client, final(), now=NOW)["evidence"]["status"], "current")

    def test_parser_does_not_resolve_contacts_or_change_score(self):
        with patch("websignal.network.resolve_public") as dns, patch("websignal.network.Client.request") as request:
            item = parse_security_contact(VALID, URL, NOW)
        dns.assert_not_called()
        request.assert_not_called()
        self.assertEqual(assess({"findings": []}), assess({"findings": [item]}))


if __name__ == "__main__":
    unittest.main()
