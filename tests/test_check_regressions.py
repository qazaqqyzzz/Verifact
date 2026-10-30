"""Reproductions of scanner interpretation defects found in the check audit."""

import unittest

from websignal.assessment import assess
from websignal.checks import page_checks
from websignal.network import Response


def findings(body=b"<html><head><title>Example</title></head><body></body></html>", headers=None, **kwargs):
    response = Response("https://example.com/", 200,
                        {"content-type": "text/html", **(headers or {})}, body, **kwargs)
    return {item["id"]: item for item in page_checks(response)}


class HSTSParsingRegressions(unittest.TestCase):
    def test_malformed_or_duplicate_directives_do_not_earn_hsts_credit(self):
        invalid = [
            'max-age="60', 'max-age=60"', 'max-age=no; max-age=60',
            'max-age=60; MAX-AGE=invalid', 'max-age=60; max-age=60',
            'max-age=60; includeSubDomains=invalid',
            'max-age=60; includeSubDomains; includeSubDomains',
            'max-age=60; extension="unterminated', 'max-age=60; invalid value',
            'max-age=60, max-age=90', 'max-age=+60', 'max-age=٦٠',
        ]
        for header in invalid:
            with self.subTest(header=header):
                item = findings(headers={"strict-transport-security": header})["hsts"]
                self.assertEqual(item["status"], "attention")
                score = assess({"findings": [item]})
                self.assertEqual((score["earned"], score["coverage"]), (0, 15))

    def test_quoted_escaped_and_extension_values_are_parsed_as_directives(self):
        valid = [
            'max-age=60', ' ; MAX-AGE = "60" ; includeSubDomains; preload; ',
            'max-age="6\\0"; extension="text; with a semicolon"',
            'max-age=60; extension="an escaped \\" quote"',
        ]
        for header in valid:
            with self.subTest(header=header):
                self.assertEqual(findings(headers={"strict-transport-security": header})["hsts"]["status"], "pass")

    def test_very_long_max_age_cannot_crash_the_scan(self):
        for digits, expected in [("9" * 5000, "pass"), ("0" * 5000, "attention")]:
            with self.subTest(expected=expected):
                result = findings(headers={"strict-transport-security": "max-age=" + digits})
                self.assertEqual(result["hsts"]["status"], expected)
                self.assertEqual(result["title"]["status"], "pass")

    def test_zero_lifetime_and_insecure_response_do_not_pass(self):
        self.assertEqual(findings(headers={"strict-transport-security": 'max-age="000"'})["hsts"]["status"], "attention")
        insecure = Response("http://example.com/", 200, {"strict-transport-security": "max-age=60"})
        item = next(item for item in page_checks(insecure) if item["id"] == "hsts")
        self.assertEqual(item["status"], "attention")


class HTMLParsingRegressions(unittest.TestCase):
    def test_svg_titles_and_later_html_titles_do_not_merge_into_page_title(self):
        body = (b'<html><head><title>GitHub - Example</title></head><body>'
                b'<svg><title>Logo label</title></svg><title>Later title</title>'
                b'<svg><title>Customer logo</title></svg></body></html>')
        self.assertEqual(findings(body)["title"]["evidence"], "GitHub - Example")

    def test_svg_title_alone_is_not_a_document_title(self):
        result = findings(b'<html><body><svg><title>Logo</title></svg></body></html>')
        self.assertEqual(result["title"]["status"], "attention")
        self.assertEqual(result["title"]["evidence"], "")

    def test_duplicate_form_attributes_keep_first_browser_value(self):
        result = findings(b'<form method="get" method="post" action="http://other.example/login" '
                          b'action="https://example.com/login"><input name="pw" type="password"></form>')
        item = result["password_forms"]
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["get_submissions"], 1)
        self.assertEqual(item["evidence"]["http_actions"], 1)
        self.assertEqual(item["evidence"]["cross_origin_actions"], 1)

    def test_http_resource_scheme_whitespace_does_not_create_false_pass(self):
        result = findings(b'<script src="  h&#10;ttp://cdn.example/app.js "></script>'
                          b'<img src="http://cdn.example/image.png" src="https://cdn.example/image.png">')
        self.assertEqual(result["http_resources"]["status"], "attention")
        self.assertEqual(result["http_resources"]["evidence"]["count"], 2)

    def test_html_lookalike_media_types_remain_unknown(self):
        for content_type in ("text/htmlish", "application/x-text/html", "text/plain; note=text/html"):
            with self.subTest(content_type=content_type):
                result = findings(b'<title>Should not be parsed</title>', {"content-type": content_type})
                self.assertEqual(result["title"]["status"], "unknown")
                self.assertEqual(result["http_resources"]["status"], "unknown")

    def test_optional_header_whitespace_is_not_a_configuration_failure(self):
        result = findings(headers={"x-content-type-options": " nosniff \t", "x-frame-options": " SAMEORIGIN \t"})
        self.assertEqual(result["nosniff"]["status"], "pass")
        self.assertEqual(result["framing"]["status"], "info")
        score = assess({"findings": list(result.values())})
        self.assertEqual(next(row["earned"] for row in score["items"] if row["finding_id"] == "framing"), 10)

    def test_only_head_http_equiv_meta_can_earn_csp_presence_credit(self):
        policy = b'<meta http-equiv="content-security-policy" content="default-src &#39;self&#39;">'
        for body in (b'<html><head></head><body>' + policy + b'</body></html>',
                     b'<div>Body content</div>' + policy,
                     b'Visible body text' + policy,
                     b'<meta name="content-security-policy" content="default-src &#39;self&#39;">',
                     b'<head><noscript>' + policy + b'</noscript></head>'):
            with self.subTest(body=body):
                item = findings(body)["csp"]
                self.assertEqual(item["status"], "attention")
                self.assertEqual(assess({"findings": [item]})["earned"], 0)
        for body in (policy + b'<p>Body</p>', b'<head><title>Example</title><style>p {color:red}</style>' + policy + b'</head>'):
            with self.subTest(body=body):
                item = findings(body)["csp"]
                self.assertEqual(item["status"], "info")
                self.assertEqual(assess({"findings": [item]})["earned"], 10)


if __name__ == "__main__":
    unittest.main()
