"""Owner observations must not overstate passive evidence or change scores."""

import json
import unittest
from unittest.mock import patch

from websignal.assessment import assess
from websignal.checks import page_checks, read_page
from websignal.network import Response, response_headers
from websignal.security_hygiene import TITLES, hygiene_checks


def response(body="<p>Public information</p>", headers=None, **kwargs):
    fields = {"content-type": "text/html; charset=utf-8"}
    fields.update(headers or {})
    return Response("https://app.example.com/page", kwargs.pop("status", 200), fields, body.encode(), **kwargs)


def findings(res):
    return {item["id"]: item for item in page_checks(res)}


class SecurityHygieneTests(unittest.TestCase):
    def test_absent_optional_policies_are_informational_and_missing_response_unknown(self):
        result = findings(response())
        for identifier in TITLES:
            with self.subTest(identifier=identifier):
                self.assertEqual(result[identifier]["status"], "info")
        self.assertTrue(all(item["status"] == "unknown" for item in hygiene_checks(None, None)))

    def test_public_cors_wildcard_is_not_called_vulnerable(self):
        item = findings(response(headers={"access-control-allow-origin": "*"}))["cors_policy"]
        self.assertEqual(item["status"], "info")
        self.assertFalse(item["evidence"]["origin_probe_performed"])
        item = findings(response(headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}))["cors_policy"]
        self.assertEqual(item["status"], "attention")
        self.assertIn("wildcard_with_credentials", item["evidence"]["issues"])
        self.assertIn("not evidence of credential leakage", item["explanation"])

    def test_cors_null_invalid_and_explicit_origins_are_distinguished(self):
        for origin in ("null", "https://one.example, https://two.example", "https://one.example/path", "https://one.example:99999"):
            with self.subTest(origin=origin):
                self.assertEqual(findings(response(headers={"access-control-allow-origin": origin}))["cors_policy"]["status"], "attention")
        for origin in ("https://allowed.example", "https://allowed.example:8443", "chrome-extension://abcdef"):
            with self.subTest(origin=origin):
                item = findings(response(headers={"access-control-allow-origin": origin, "access-control-allow-credentials": "true"}))["cors_policy"]
                self.assertEqual(item["status"], "info")
                self.assertEqual(item["evidence"]["allow_origin"], "single_origin")
                self.assertFalse(item["evidence"]["vary_origin"])
        item = findings(response(headers={"access-control-allow-origin": "https://allowed.example", "vary": "Accept-Encoding, Origin"}))["cors_policy"]
        self.assertTrue(item["evidence"]["vary_origin"])

    def test_cors_credentials_true_is_case_sensitive(self):
        for value in ("True", "false", "true, true"):
            with self.subTest(value=value):
                item = findings(response(headers={"access-control-allow-credentials": value}))["cors_policy"]
                self.assertEqual(item["status"], "attention")
                self.assertFalse(item["evidence"]["credentials_allowed"])
        item = findings(response(headers={"access-control-allow-credentials": " true\t"}))["cors_policy"]
        self.assertTrue(item["evidence"]["credentials_allowed"])

    def test_combined_single_value_headers_are_reviewed_without_rejecting_multiple_csp_policies(self):
        headers, _ = response_headers([("X-Frame-Options", "SAMEORIGIN"), ("X-Frame-Options", "DENY"),
                                       ("X-Content-Type-Options", "nosniff"), ("X-Content-Type-Options", "nosniff"),
                                       ("Content-Security-Policy", "default-src 'self'"),
                                       ("Content-Security-Policy", "default-src 'none'")])
        item = findings(response(headers=headers))["header_quality"]
        self.assertEqual(item["status"], "attention")
        self.assertEqual({issue["header"] for issue in item["evidence"]["issues"]}, {"x-frame-options", "x-content-type-options"})
        item = findings(response(headers={"content-security-policy": "default-src 'self'; script-src 'self'; SCRIPT-SRC https:"}))["header_quality"]
        self.assertEqual(item["evidence"]["issues"][0]["issue"], "duplicate_directives")

    def test_public_cache_does_not_fail_without_account_context(self):
        for value in ("public, max-age=3600", "s-maxage=300", "no-cache", "private", "no-store", ""):
            with self.subTest(value=value):
                item = findings(response(headers={"cache-control": value}))["response_caching"]
                self.assertEqual(item["status"], "info")
        item = findings(response('<input type="password">', headers={"cache-control": "public, max-age=3600"}))["response_caching"]
        self.assertEqual(item["status"], "attention")
        self.assertIn("shared_cache_with_account_context", item["evidence"]["issues"])
        self.assertFalse(item["evidence"]["personalized_content_confirmed"])

    def test_cookie_value_never_enters_cache_evidence(self):
        item = findings(response(headers={"cache-control": "public, s-maxage=60"},
                                 set_cookie_headers=["session=VERY_PRIVATE_COOKIE; Secure"]))["response_caching"]
        self.assertEqual(item["status"], "attention")
        self.assertTrue(item["evidence"]["sets_cookie"])
        self.assertNotIn("VERY_PRIVATE", json.dumps(item))
        self.assertNotIn("session", json.dumps(item))

    def test_private_and_no_store_prevent_shared_cache_claim_but_no_cache_does_not(self):
        for value in ("public, private", "s-maxage=300, no-store", "public, max-age=60, NO-STORE"):
            with self.subTest(value=value):
                item = findings(response('<input type="password">', headers={"cache-control": value}))["response_caching"]
                self.assertEqual(item["status"], "info")
                self.assertFalse(item["evidence"]["explicit_shared_cache"])
        item = findings(response('<input type="password">', headers={"cache-control": "public, no-cache"}))["response_caching"]
        self.assertEqual(item["status"], "attention")
        self.assertIn("does not prohibit storage", item["explanation"])

    def test_quoted_cache_fields_do_not_invent_directives(self):
        item = findings(response(headers={"cache-control": 'private="Set-Cookie, no-store", max-age="300", x-secret="HIDDEN_VALUE"'}))["response_caching"]
        self.assertEqual(item["status"], "info")
        self.assertFalse(item["evidence"]["no_store"])
        self.assertFalse(item["evidence"]["private"])
        self.assertNotIn("HIDDEN_VALUE", json.dumps(item))
        self.assertNotIn("x-secret", json.dumps(item))
        for value in ("max-age=20, max-age=30", "s-maxage=-1", 'max-age="12', "max-age=never"):
            with self.subTest(value=value):
                self.assertIn(findings(response(headers={"cache-control": value}))["response_caching"]["status"], {"attention", "unknown"})

    def test_browser_isolation_only_reviews_explicit_unrecognized_values(self):
        headers = {"cross-origin-opener-policy": 'same-origin; report-to="group,a"',
                   "cross-origin-embedder-policy": "credentialless", "cross-origin-resource-policy": "cross-origin",
                   "permissions-policy": 'camera=(), microphone=(self "https://meeting.example")'}
        item = findings(response(headers=headers))["browser_isolation"]
        self.assertEqual(item["status"], "info")
        self.assertEqual(item["evidence"]["policies"]["permissions-policy"], "present")
        self.assertFalse(item["evidence"]["browser_isolation_tested"])
        headers["cross-origin-opener-policy"] = "same-origin, same-origin"
        item = findings(response(headers=headers))["browser_isolation"]
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["unrecognized_headers"], ["cross-origin-opener-policy"])

    def test_large_or_control_character_headers_stay_unknown_without_raw_evidence(self):
        headers = {"content-security-policy": "SECRET" * 1500, "access-control-allow-origin": "PRIVATE\r\nVALUE",
                   "cache-control": "PRIVATE" * 1400, "cross-origin-embedder-policy": "PRIVATE" * 1400,
                   "server": "PRIVATE" * 1400}
        result = findings(response(headers=headers))
        for identifier in ("header_quality", "cors_policy", "response_caching", "browser_isolation", "public_disclosures"):
            with self.subTest(identifier=identifier):
                self.assertEqual(result[identifier]["status"], "unknown")
                self.assertNotIn("PRIVATE", json.dumps(result[identifier]))
                self.assertNotIn("SECRET", json.dumps(result[identifier]))

    def test_software_versions_are_unverified_hints_and_never_copy_arbitrary_headers(self):
        item = findings(response('<meta name="generator" content="WordPress 6.2.1 PRIVATE_KEY">',
                                 headers={"server": "nginx/1.20.1 (PRIVATE_PATH)", "x-powered-by": "PHP/8.2.4 token=PRIVATE_TOKEN"}))["public_disclosures"]
        self.assertEqual(item["status"], "info")
        self.assertEqual(len(item["evidence"]["version_hints"]), 3)
        self.assertFalse(item["evidence"]["version_vulnerabilities_checked"])
        self.assertNotIn("PRIVATE", json.dumps(item))

    def test_debug_finding_requires_error_response_and_multiple_markers(self):
        body = '<title>RuntimeError // Werkzeug Debugger</title><script>var q="__debugger__";</script>PRIVATE_STACK_PATH'
        self.assertEqual(findings(response(body))["public_disclosures"]["status"], "info")
        item = findings(response(body, status=500))["public_disclosures"]
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["error_page_markers"], ["werkzeug_debugger_error"])
        self.assertNotIn("PRIVATE_STACK_PATH", json.dumps(item))
        self.assertEqual(findings(response('<title>Werkzeug Debugger</title>', status=500))["public_disclosures"]["status"], "info")
        item = findings(response('Django Version: 5.2 <code>DEBUG = True</code>', status=500))["public_disclosures"]
        self.assertEqual(item["evidence"]["error_page_markers"], ["django_debug_error"])

    def test_iframe_absence_is_not_failure_and_same_origin_combo_is_reviewed(self):
        body = '<iframe src="https://video.example/embed"></iframe><iframe src="/untrusted?token=PRIVATE" sandbox="allow-scripts allow-same-origin"></iframe>'
        item = findings(response(body))["iframe_sandbox"]
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["iframes_observed"], 2)
        self.assertEqual(item["evidence"]["same_origin_source_with_both"], 1)
        self.assertNotIn("PRIVATE", json.dumps(item))
        self.assertEqual(findings(response('<iframe src="https://video.example/embed"></iframe>'))["iframe_sandbox"]["status"], "info")

    def test_iframe_base_srcdoc_and_inert_markup(self):
        body = ('<template><iframe src="/ignored" sandbox="allow-scripts allow-same-origin"></iframe></template>'
                '<noscript><iframe src="/ignored" sandbox="allow-scripts allow-same-origin"></iframe></noscript>'
                '<base href="https://frames.example/"><iframe src="relative" sandbox="allow-scripts allow-same-origin">'
                '<iframe src="/fallback" sandbox="allow-scripts allow-same-origin"></iframe></iframe>'
                '<iframe src="https://ignored.example/" srcdoc="PRIVATE" sandbox="allow-scripts allow-same-origin"></iframe>')
        item = findings(response(body))["iframe_sandbox"]
        self.assertEqual(item["evidence"]["iframes_observed"], 2)
        self.assertEqual(item["evidence"]["scripts_and_same_origin_allowed"], 2)
        self.assertEqual(item["evidence"]["same_origin_source_with_both"], 1)
        self.assertNotIn("PRIVATE", json.dumps(item))

    def test_iframe_limits_and_first_duplicate_attribute_are_respected(self):
        item = findings(response('<iframe sandbox="" sandbox="allow-scripts allow-same-origin" src="/"></iframe>'))["iframe_sandbox"]
        self.assertEqual(item["status"], "info")
        self.assertEqual(item["evidence"]["sandbox_present"], 1)
        item = findings(response('<iframe sandbox="' + "x" * 1100 + '"></iframe>'))["iframe_sandbox"]
        self.assertEqual(item["status"], "unknown")
        self.assertTrue(item["evidence"]["limited"])
        res = response('<iframe src="/"></iframe>' * 120)
        page, _, _ = read_page(res)
        self.assertEqual(len(page.hygiene_frames), 100)
        self.assertTrue(page.hygiene_frames_limited)
        self.assertEqual(findings(res)["iframe_sandbox"]["status"], "unknown")

    def test_hygiene_never_performs_network_or_changes_the_eight_weighted_checks(self):
        res = response('<input type="password"><iframe sandbox="allow-scripts allow-same-origin" src="/"></iframe>',
                       headers={"cache-control": "public", "access-control-allow-origin": "null"})
        with patch("websignal.network.Client.request") as fetch, patch("websignal.network.resolve_public") as dns:
            all_findings = page_checks(res)
        fetch.assert_not_called()
        dns.assert_not_called()
        before = assess({"findings": [item for item in all_findings if item["id"] not in TITLES]})
        after = assess({"findings": all_findings})
        self.assertEqual(before, after)
        self.assertEqual(after["total_checks"], 8)


if __name__ == "__main__":
    unittest.main()
