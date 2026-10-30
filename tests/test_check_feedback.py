"""Presentation must describe actual evidence without rescoring or leaking data."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch

from verifact.check_feedback import HANDLERS, NO_CHANGE, check_feedback_for_report
from verifact.checks import finding, page_checks
from verifact.network import Fetch, Response
from verifact.scanner import demo_report, finish_report
from verifact.security_contact import parse_security_contact


def response(body='<html lang="en"><head><title>Example</title><meta name="viewport" content="width=device-width"></head><body></body></html>', headers=None, **kwargs):
    fields = {"content-type": "text/html; charset=utf-8"}
    fields.update(headers or {})
    return Response("https://app.example.com/", kwargs.pop("status", 200), fields, body.encode(), **kwargs)


def present(res):
    return check_feedback_for_report({"findings": page_checks(res), "response": {
        "status": res.status, "body_truncated": res.truncated, "body_error": res.body_error}})


def single(identifier, status, evidence, **report):
    return check_feedback_for_report({"findings": [finding(identifier, "Browser", status, "Test", evidence, "")], **report})[identifier]


class CheckFeedbackTests(unittest.TestCase):
    def test_all_current_ids_have_evidence_derived_feedback_without_mutation_or_network(self):
        report = demo_report()
        report["findings"].append(finding("rdap", "Domain", "info", "Registration", {
            "queried_domain": "example.com", "events": [{"action": "registration", "date": "2020-01-01"}],
            "nameservers": ["ns.example.com"]}, ""))
        report["findings"].append(parse_security_contact(
            b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
            "https://app.example.com/.well-known/security.txt", now=datetime(2026, 10, 31, tzinfo=timezone.utc)))
        report["check_feedback"] = {"tls": {"fact": "UNTRUSTED SAVED PRESENTATION"}}
        original = deepcopy(report)
        with patch("socket.socket", side_effect=AssertionError("Presentation must be offline")):
            result = check_feedback_for_report(report)
        self.assertEqual(report, original)
        self.assertEqual(set(result), set(HANDLERS))
        self.assertEqual(len(result), 24)
        self.assertNotIn("UNTRUSTED", json.dumps(result))
        for item in report["findings"]:
            with self.subTest(identifier=item["id"]):
                value = result[item["id"]]
                self.assertEqual(value["state"], item["status"])
                self.assertEqual(set(value), {"result", "fact", "fix", "state"})
                self.assertNotEqual(value["result"], "Observation")
                self.assertTrue(value["fact"] and value["fix"])
                self.assertLessEqual(len(value["result"]), 48)
                self.assertLessEqual(len(value["fact"]), 500)
                self.assertLessEqual(len(value["fix"]), 350)

    def test_connection_counts_protocol_and_snapshot_expiry(self):
        value = single("https_redirect", "pass", {"chain": [{"url": "http://example.com/"}, {"url": "https://example.com/?private=SECRET"}], "error": "SECRET"})
        self.assertEqual(value["state"], "pass")
        self.assertIn("later request", value["fact"])
        self.assertNotIn("SECRET", json.dumps(value))
        self.assertIn("TLSv1.3", single("tls", "pass", {"verified": True, "version": "TLSv1.3"})["fact"])
        self.assertEqual(single("tls", "attention", {"encrypted": False})["result"], "Unencrypted final page")
        self.assertEqual(single("tls", "attention", {"error": "HTTPS-to-HTTP downgrade redirect observed and blocked."})["result"], "HTTPS downgrade blocked")
        certificate = single("tls", "attention", {"error": "TLS certificate could not be verified: SECRET"})
        self.assertEqual(certificate["result"], "Certificate not verified")
        self.assertNotIn("SECRET", json.dumps(certificate))
        for days, status, label in ((-1, "attention", "Expired"), (0, "attention", "Less than 1 day left"), (1, "attention", "1 day left"), (14, "pass", "14 days left")):
            with self.subTest(days=days):
                value = single("certificate_expiry", status, {"days_remaining": days, "expires": "Nov 15 00:00:00 2026 GMT"})
                self.assertEqual(value["result"], label)
                self.assertIn("check", value["fact"])
        self.assertEqual(single("certificate_expiry", "pass", {"days_remaining": 1})["state"], "unknown")

    def test_header_absence_invalid_and_presence_are_distinct(self):
        absent = present(response())
        self.assertEqual(absent["hsts"]["result"], "Not set")
        self.assertEqual(absent["csp"]["result"], "Not set")
        self.assertEqual(absent["nosniff"]["result"], "Not set")
        self.assertIn("No frame-ancestors", absent["framing"]["fact"])
        declared = present(response(headers={"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-frame-options": "DENY"}))
        self.assertEqual(declared["hsts"]["state"], "pass")
        self.assertEqual(declared["csp"]["state"], "info")
        self.assertEqual(declared["framing"]["state"], "info")
        self.assertIn("DENY", declared["framing"]["fact"])
        invalid = present(response(headers={"strict-transport-security": "max-age=0", "x-content-type-options": "foo"}))
        self.assertIn("max-age=0", invalid["hsts"]["fact"])
        self.assertEqual(invalid["nosniff"]["result"], "Unrecognized value")
        self.assertEqual(single("hsts", "pass", "max-age=0")["state"], "unknown")
        self.assertEqual(single("nosniff", "pass", "wrong")["state"], "unknown")

    def test_referrer_policy_is_not_promoted_to_verified_browser_behavior(self):
        unsafe = present(response(headers={"referrer-policy": "no-referrer, unsafe-url"}))["referrer"]
        self.assertEqual(unsafe["state"], "attention")
        self.assertIn("unsafe-url", unsafe["fact"])
        self.assertIn("not tested", unsafe["fact"])
        declared = present(response(headers={"referrer-policy": "unsafe-url, no-referrer"}))["referrer"]
        self.assertEqual(declared["state"], "info")
        self.assertIn("no-referrer", declared["fact"])
        absent = present(response())["referrer"]
        self.assertEqual(absent["result"], "No supported declaration")
        self.assertIn("not a privacy failure", absent["fact"])

    def test_page_counts_and_specific_fixes(self):
        values = present(response('<html><head></head><body><img src="http://example.com/a"><img alt="" src="/b"><script src="http://example.com/b"></script></body></html>'))
        self.assertIn("1 of 2", values["image_alt"]["fact"])
        self.assertIn("2 explicit HTTP", values["http_resources"]["fact"])
        for identifier in ("title", "viewport", "language"):
            self.assertEqual(values[identifier]["result"], "Not set")
            self.assertNotEqual(values[identifier]["fix"], NO_CHANGE)
        empty = present(response())
        self.assertEqual(empty["image_alt"]["result"], "No images found")
        self.assertEqual(empty["http_resources"]["result"], "None found in HTML")
        self.assertEqual(single("image_alt", "pass", {"images": 2, "missing_alt_attributes": 1})["state"], "unknown")

    def test_password_form_evidence_count_and_no_form_cases(self):
        unsafe = present(response('<form action="http://other.example.com/login" method="get"><input name="password" type="password"></form>'))["password_forms"]
        self.assertEqual(unsafe["result"], "Destinations need review")
        self.assertIn("1 HTTP action", unsafe["fact"])
        self.assertIn("1 GET submission", unsafe["fact"])
        self.assertIn("1 cross-origin", unsafe["fact"])
        secure = present(response('<form action="/login" method="post"><input name="password" type="password"></form>'))["password_forms"]
        self.assertEqual(secure["result"], "HTTPS POST observed")
        self.assertEqual(secure["fix"], NO_CHANGE)
        self.assertEqual(present(response())["password_forms"]["result"], "No password form found")
        self.assertEqual(present(response('<form method="dialog"><input name="password" type="password"></form>'))["password_forms"]["result"], "Dialog submission only")
        unknown = present(response('<input type="password" name="password">'))["password_forms"]
        self.assertEqual(unknown["result"], "Could not check")
        self.assertIn("association", unknown["fact"])

    def test_cookie_counts_without_values_or_names(self):
        risky = present(response(set_cookie_headers=["secret_cookie=PRIVATE_VALUE; HttpOnly", "other=PRIVATE2; Secure"]))["cookie_flags"]
        self.assertIn("1 of 2", risky["fact"])
        self.assertNotIn("secret_cookie", json.dumps(risky))
        self.assertNotIn("PRIVATE", json.dumps(risky))
        secure = present(response(set_cookie_headers=["s=value; Secure; HttpOnly; SameSite=Lax"]))["cookie_flags"]
        self.assertEqual(secure["result"], "Attributes present")
        optional = present(response(set_cookie_headers=["script_cookie=value; Secure"]))["cookie_flags"]
        self.assertEqual(optional["state"], "info")
        self.assertIn("1 lack HttpOnly", optional["fact"])
        self.assertIn("purpose", optional["fix"])
        self.assertEqual(present(response())["cookie_flags"]["result"], "No cookies returned")
        malformed = present(response(set_cookie_headers=["malformed"]))["cookie_flags"]
        self.assertEqual(malformed["state"], "unknown")
        self.assertIn("1 Set-Cookie", malformed["fact"])

    def test_header_conflicts_cors_cache_and_isolation_review(self):
        values = present(response('<input type="password">', headers={
            "x-content-type-options": "nosniff, nosniff", "x-frame-options": "INVALID",
            "content-security-policy": "script-src 'self'; script-src 'none'",
            "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
            "cache-control": "public, max-age=60", "cross-origin-opener-policy": "wrong"}))
        self.assertIn("multiple values", values["header_quality"]["fact"])
        self.assertIn("repeated directives", values["header_quality"]["fact"])
        self.assertIn("browsers reject", values["cors_policy"]["fact"])
        self.assertNotIn("leak", values["cors_policy"]["fact"])
        self.assertIn("personalized content was not confirmed", values["response_caching"]["fact"])
        self.assertIn("COOP", values["browser_isolation"]["fact"])

    def test_optional_headers_and_public_caching_are_not_failed(self):
        for policy in ("*", "https://allowed.example.com"):
            with self.subTest(policy=policy):
                value = present(response(headers={"access-control-allow-origin": policy}))["cors_policy"]
                self.assertEqual(value["state"], "info")
                self.assertEqual(value["fix"], NO_CHANGE)
        for policy, label in (("public, max-age=60", "Shared caching declared"), ("no-cache", "Revalidation required"), ("no-store", "Storage prohibited"), ("private", "Private caching declared")):
            with self.subTest(policy=policy):
                value = present(response(headers={"cache-control": policy}))["response_caching"]
                self.assertEqual(value["state"], "info")
                self.assertEqual(value["result"], label)
        self.assertEqual(present(response())["browser_isolation"]["result"], "Not set (optional)")
        optional = present(response(headers={"cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp", "permissions-policy": "camera=()"}))["browser_isolation"]
        self.assertEqual(optional["state"], "info")
        self.assertIn("COOP: same-origin", optional["fact"])
        self.assertIn("COEP: require-corp", optional["fact"])

    def test_disclosure_and_iframe_facts_stay_within_observed_scope(self):
        versions = present(response(headers={"server": "nginx/1.22.1", "x-powered-by": "PHP/8.3.0"}))["public_disclosures"]
        self.assertEqual(versions["state"], "info")
        self.assertIn("2 software-version", versions["fact"])
        self.assertIn("not verified", versions["fact"])
        debug = present(response('<title>Error</title>Django Version: 4.2 DEBUG = True', status=500))["public_disclosures"]
        self.assertEqual(debug["result"], "Debug markers found")
        self.assertIn("Django debug", debug["fact"])
        iframe = present(response('<iframe src="/embed" sandbox="allow-scripts allow-same-origin"></iframe>'))["iframe_sandbox"]
        self.assertIn("1 initially same-origin", iframe["fact"])
        self.assertIn("not loaded", iframe["fact"])
        no_sandbox = present(response('<iframe src="https://other.example.com"></iframe>'))["iframe_sandbox"]
        self.assertEqual(no_sandbox["state"], "info")
        self.assertIn("0 of 1", no_sandbox["fact"])

    def test_contact_file_results_are_maintenance_not_safety_claims(self):
        when = datetime(2026, 10, 31, tzinfo=timezone.utc)
        cases = ((b"Contact: mailto:SECRET@example.com\nExpires: 2026-01-01T00:00:00Z\n", "Contact file expired"),
                 (b"Expires: 2027-01-01T00:00:00Z\n", "Contact field missing"),
                 (b"Contact: mailto:SECRET@example.com\n", "Expiry field needs review"),
                 (b"Contact: mailto:SECRET@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://other.example.com/security.txt\n", "Canonical URL mismatch"))
        for body, label in cases:
            with self.subTest(label=label):
                item = parse_security_contact(body, "https://app.example.com/.well-known/security.txt", now=when)
                value = check_feedback_for_report({"findings": [item]})["security_contact"]
                self.assertEqual(value["result"], label)
                self.assertEqual(value["state"], "attention")
                self.assertNotIn("SECRET", json.dumps(value))
        absent = single("security_contact", "info", {"status": "not_found", "http_status": 404, "issues": []})
        self.assertEqual(absent["result"], "Not found (optional)")
        redirected = single("security_contact", "unknown", {"status": "redirect"})
        self.assertIn("did not follow", redirected["fact"])

    def test_unknown_response_reasons_do_not_promote_partial_html_to_pass(self):
        for res, expected in ((response(truncated=True), "download limit"),
                              (response(truncated=True, body_error="SECRET"), "did not finish"),
                              (response(status=403), "HTTP 403"),
                              (response(headers={"content-type": "application/json"}), "supported HTML")):
            with self.subTest(expected=expected):
                values = present(res)
                for identifier in ("title", "image_alt", "http_resources", "password_forms"):
                    self.assertEqual(values[identifier]["state"], "unknown")
                    self.assertEqual(values[identifier]["result"], "Could not check")
                    self.assertIn(expected, values[identifier]["fact"])
                self.assertNotIn("SECRET", json.dumps(values))
        unavailable = finish_report("example.com", Fetch(None, [], "SECRET"), Fetch(None, [], "SECRET"), 0)
        values = check_feedback_for_report(unavailable)
        self.assertTrue(all(value["state"] == "unknown" for value in values.values()))
        self.assertNotIn("SECRET", json.dumps(values))
        unavailable.update(inspection_skipped=True, skip_reason="community_match")
        self.assertTrue(all("not contacted" in value["fact"] for value in check_feedback_for_report(unavailable).values()))

    def test_header_limits_explain_unknowns(self):
        too_long = "a" * 8193
        values = present(response(headers={"x-frame-options": too_long, "access-control-allow-origin": too_long,
                                          "cache-control": 'max-age="bad', "cross-origin-opener-policy": too_long,
                                          "server": too_long, "referrer-policy": too_long}))
        for identifier in ("header_quality", "cors_policy", "response_caching", "browser_isolation", "public_disclosures", "referrer"):
            with self.subTest(identifier=identifier):
                self.assertEqual(values[identifier]["state"], "unknown")
                self.assertIn("limit", values[identifier]["fact"])
                self.assertNotEqual(values[identifier]["fix"], NO_CHANGE)

    def test_untrusted_values_never_appear_in_copy(self):
        marker = "SECRET<script>alert(1)</script>"
        res = response('<html lang="' + marker + '"><head><title>' + marker + '</title><meta name="viewport" content="' + marker + '"></head><body><script src="http://example.com/?key=SECRET"></script></body></html>', headers={
            "content-security-policy": "default-src https://example.com/?key=SECRET", "x-frame-options": marker,
            "strict-transport-security": marker, "server": marker, "access-control-allow-origin": marker},
            set_cookie_headers=["SECRET=PRIVATE; Secure"])
        values = present(res)
        serialized = json.dumps(values)
        for secret in ("SECRET", "PRIVATE", "<script>", "https://example.com/?"):
            self.assertNotIn(secret, serialized)

    def test_malformed_duplicate_and_oversized_findings_fail_to_unknown(self):
        self.assertEqual(check_feedback_for_report(None), {})
        self.assertEqual(check_feedback_for_report({"findings": None}), {})
        first = finding("tls", "Transport", "pass", "TLS", {"verified": True}, "")
        duplicated = check_feedback_for_report({"findings": [first, deepcopy(first)]})["tls"]
        self.assertEqual(duplicated["state"], "unknown")
        self.assertIn("More than one", duplicated["fact"])
        self.assertEqual(check_feedback_for_report({"findings": [first] * 129})["tls"]["state"], "unknown")
        self.assertEqual(single("new_unsupported_check", "pass", {})["state"], "unknown")
        for identifier in HANDLERS:
            for status in ("pass", "attention", "info", "unknown", "invalid"):
                for evidence in (None, [], True, 1, {"policy": [], "issues": [{}]}):
                    with self.subTest(identifier=identifier, status=status, evidence=evidence):
                        value = single(identifier, status, evidence)
                        self.assertEqual(value["state"], "unknown")
                        self.assertNotEqual(value["fix"], NO_CHANGE)


if __name__ == "__main__":
    unittest.main()
