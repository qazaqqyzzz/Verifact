"""Meaningful snapshot differences and safe optional report exports."""

from copy import deepcopy
from datetime import datetime, timedelta
from html.parser import HTMLParser
import json
import unittest
from unittest.mock import patch

from verifact.comparison import compare_reports
from verifact.reports import html_report, render, text_report
from verifact.scanner import demo_report


def fixture():
    report = demo_report()
    report["target_url"] = "https://demo.example.com/"
    return report


def later_copy(report):
    copied = deepcopy(report)
    copied["created_at"] = (datetime.fromisoformat(report["created_at"]) + timedelta(minutes=1)).isoformat()
    return copied


def finding(report, identifier):
    return next(item for item in report["findings"] if item["id"] == identifier)


class ComparisonTests(unittest.TestCase):
    def test_matches_exact_target_including_path_and_query(self):
        previous, current = fixture(), fixture()
        previous["target_url"] = "https://demo.example.com/login?school=one"
        for target in ("https://demo.example.com/", "https://demo.example.com/login?school=two", "http://demo.example.com/login?school=one"):
            current["target_url"] = target
            result = compare_reports(previous, current)
            self.assertFalse(result["available"])
            self.assertEqual(result["changes"], [])

    def test_ignores_fragment_and_default_port_but_preserves_query_order(self):
        previous, current = fixture(), fixture()
        previous["target_url"] = "https://DEMO.example.com:443/?a=1&b=2#old"
        current["target_url"] = "https://demo.example.com/?a=1&b=2#new"
        self.assertTrue(compare_reports(previous, current)["available"])
        current["target_url"] = "https://demo.example.com/?b=2&a=1"
        self.assertFalse(compare_reports(previous, current)["available"])

    def test_legacy_homepage_snapshot_matches_explicit_root_only(self):
        previous, current = fixture(), fixture()
        del previous["target_url"]
        self.assertTrue(compare_reports(previous, current)["available"])
        current["target_url"] += "account"
        self.assertFalse(compare_reports(previous, current)["available"])

    def test_synthetic_and_live_reports_are_never_compared(self):
        previous, current = fixture(), fixture()
        current["demo"] = False
        result = compare_reports(previous, current)
        self.assertFalse(result["available"])
        self.assertIn("sample report", result["reason"])

    def test_newer_equal_and_undated_imports_are_not_called_previous(self):
        previous, current = fixture(), fixture()
        previous["created_at"] = "2030-01-01T00:00:00+00:00"
        current["created_at"] = "2026-01-01T00:00:00+00:00"
        self.assertFalse(compare_reports(previous, current)["available"])
        previous["created_at"] = current["created_at"]
        self.assertFalse(compare_reports(previous, current)["available"])
        for timestamp in ("yesterday", "2025-01-01T00:00:00", [], None):
            previous["created_at"] = timestamp
            self.assertFalse(compare_reports(previous, current)["available"])
        previous["created_at"] = "2025-12-31T23:59:59Z"
        self.assertTrue(compare_reports(previous, current)["available"])

    def test_unchanged_and_naturally_counting_down_certificate_are_quiet(self):
        previous = fixture()
        current = later_copy(previous)
        current["created_at"] = "2026-10-31T10:00:00+00:00"
        finding(current, "certificate_expiry")["evidence"]["days_remaining"] -= 1
        result = compare_reports(previous, current)
        self.assertTrue(result["available"])
        self.assertEqual(result["changes"], [])
        self.assertIn("No changes", result["summary"])

    def test_header_certificate_form_and_redirect_changes_are_visible(self):
        previous = fixture()
        current = later_copy(previous)
        finding(current, "hsts").update(status="attention", evidence="Header absent")
        finding(current, "tls")["evidence"]["not_after"] = "Dec 31 23:59:59 2100 GMT"
        finding(current, "password_forms")["evidence"]["forms_with_password"] = 1
        current["response"]["status"] = 403
        current["response"]["url"] = "https://elsewhere.example.net/login?token=redact-me"
        previous["link_analysis"] = {"redirects": [{"url": "https://demo.example.com/", "status": 200}]}
        current["link_analysis"] = {"redirects": [{"url": "https://elsewhere.example.net/login?token=redact-me", "status": 403}]}
        result = compare_reports(previous, current)
        identifiers = {item["id"] for item in result["changes"]}
        self.assertTrue({"hsts", "tls", "password_forms", "response_status", "response_url", "link_redirects"} <= identifiers)
        self.assertNotIn("redact-me", json.dumps(result))
        self.assertTrue(all(len(item["before"]) <= 901 and len(item["after"]) <= 901 for item in result["changes"]))
        self.assertIn("not proof of an attack", result["note"])

    def test_query_only_destination_change_is_detected_but_value_is_masked(self):
        previous = fixture()
        current = later_copy(previous)
        previous["response"]["url"] = "https://demo.example.com/end?r=old-private-value"
        current["response"]["url"] = "https://demo.example.com/end?r=new-private-value"
        result = compare_reports(previous, current)
        self.assertEqual([item["id"] for item in result["changes"]], ["response_url"])
        self.assertNotIn("private-value", json.dumps(result))

    def test_per_response_csp_nonces_do_not_create_false_changes(self):
        previous = fixture()
        current = later_copy(previous)
        for report, nonce in ((previous, "abc123"), (current, "def456")):
            finding(report, "csp").update(status="info", evidence={"header": "script-src 'nonce-" + nonce + "'; object-src 'none'"})
        self.assertEqual(compare_reports(previous, current)["changes"], [])
        finding(current, "csp")["evidence"]["header"] += "; frame-ancestors 'none'"
        self.assertEqual(compare_reports(previous, current)["changes"][0]["id"], "csp")

    def test_legacy_absent_referrer_and_new_absent_record_are_the_same_observation(self):
        previous = fixture()
        current = later_copy(previous)
        finding(previous, "referrer").update(status="info", evidence="No explicit policy observed")
        finding(current, "referrer").update(status="info", evidence={"complete_html": True, "header": "",
            "header_policy": None, "limited": False, "meta_policies": [], "policy": None, "source": None})
        self.assertEqual(compare_reports(previous, current)["changes"], [])

    def test_same_legacy_unsafe_referrer_does_not_look_like_a_new_site_change(self):
        for source in ("header", "meta"):
            with self.subTest(source=source):
                previous = fixture()
                current = later_copy(previous)
                finding(previous, "referrer").update(status="info", evidence="unsafe-url")
                finding(current, "referrer").update(status="attention", evidence={"complete_html": True,
                    "header": "unsafe-url" if source == "header" else "", "limited": False,
                    "meta_policies": ["unsafe-url"] if source == "meta" else [], "policy": "unsafe-url", "source": source})
                self.assertEqual(compare_reports(previous, current)["changes"], [])

    def test_actual_referrer_declaration_change_remains_visible_across_schemas(self):
        previous = fixture()
        current = later_copy(previous)
        finding(previous, "referrer").update(status="info", evidence="unsafe-url")
        finding(current, "referrer").update(status="info", evidence={"complete_html": True,
            "header": "strict-origin-when-cross-origin", "limited": False, "meta_policies": [],
            "policy": "strict-origin-when-cross-origin", "source": "header"})
        changes = compare_reports(previous, current)["changes"]
        self.assertEqual([item["id"] for item in changes], ["referrer"])
        self.assertIn("unsafe-url", changes[0]["before"])
        self.assertIn("strict-origin-when-cross-origin", changes[0]["after"])

    def test_referrer_unknown_or_partial_coverage_is_not_normalized_to_known_absence(self):
        for status, complete, limited in (("unknown", True, False), ("info", False, False), ("info", True, True)):
            with self.subTest(status=status, complete=complete, limited=limited):
                previous = fixture()
                current = later_copy(previous)
                finding(previous, "referrer").update(status="info", evidence="No explicit policy observed")
                finding(current, "referrer").update(status=status, evidence={"complete_html": complete,
                    "header": "", "limited": limited, "meta_policies": [], "policy": None, "source": None})
                self.assertEqual([item["id"] for item in compare_reports(previous, current)["changes"]], ["referrer"])
        finding(previous, "referrer").update(status="unknown", evidence="No explicit policy observed")
        finding(current, "referrer").update(status="info", evidence={"complete_html": True,
            "header": "", "limited": False, "meta_policies": [], "policy": None, "source": None})
        self.assertEqual([item["id"] for item in compare_reports(previous, current)["changes"]], ["referrer"])

    def test_new_referrer_snapshots_keep_changes_to_header_and_meta_sources(self):
        previous = fixture()
        current = later_copy(previous)
        evidence = {"complete_html": True, "header": "strict-origin", "limited": False,
                    "meta_policies": [], "policy": "strict-origin", "source": "header"}
        finding(previous, "referrer").update(status="info", evidence=deepcopy(evidence))
        finding(current, "referrer").update(status="info", evidence=deepcopy(evidence))
        finding(current, "referrer")["evidence"]["meta_policies"] = ["unsafe-url"]
        changes = compare_reports(previous, current)["changes"]
        self.assertEqual([item["id"] for item in changes], ["referrer"])
        self.assertIn("unsafe-url", changes[0]["after"])

    def test_imported_cookie_values_never_appear_in_comparison(self):
        previous = fixture()
        current = later_copy(previous)
        finding(current, "cookie_flags")["evidence"].update(cookies_observed=1, cookies=[{
            "name": "session", "value": "TOP-SECRET", "secure": True, "http_only": True, "same_site": "Lax"}])
        result = compare_reports(previous, current)
        self.assertIn("Cookie attributes", json.dumps(result))
        self.assertNotIn("TOP-SECRET", json.dumps(result))

    def test_missing_and_malformed_optional_fields_do_not_crash(self):
        self.assertFalse(compare_reports(None, fixture())["available"])
        for value in ([], {}, 123, "not-a-url", "https://user:secret@example.com", "https://example.com:bad"):
            previous = fixture()
            previous["target_url"] = value
            result = compare_reports(previous, fixture())
            self.assertIsInstance(result, dict)
        previous, current = fixture(), fixture()
        previous.update(findings=None, response="bad", link_analysis=[])
        current.update(response=123, link_analysis={"redirects": float("nan")})
        result = compare_reports(previous, current)
        self.assertTrue(result["available"])
        json.dumps(result, allow_nan=False)

    def test_huge_imported_evidence_is_bounded(self):
        previous, current = fixture(), fixture()
        finding(current, "hsts")["evidence"] = "x" * 50000
        result = compare_reports(previous, current)
        self.assertLess(len(json.dumps(result)), 5000)
        self.assertEqual(len(result["changes"]), 1)


class Markup(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ExtendedExportTests(unittest.TestCase):
    def test_link_trace_and_comparison_are_in_both_exports_and_escaped(self):
        report = fixture()
        payload = '<script>alert("x")</script>\x1b[2J'
        report["link_analysis"] = {"input_url": "https://demo.example.com/" + payload,
                                   "final_url": "https://demo.example.com/login", "completed": True,
                                   "redirects": [{"url": payload, "status": 302}],
                                   "warnings": [{"title": "Look closer", "detail": payload}], "note": "A trail is context."}
        report["comparison"] = {"available": True, "summary": "One recorded change", "previous_created_at": "Yesterday",
                                "changes": [{"title": payload, "before": payload, "after": "After"}]}
        markup, plain = html_report(report), text_report(report)
        self.assertIn("Link details &amp; redirect trail", markup)
        self.assertIn("Changes since the previous check", markup)
        self.assertIn("&lt;script&gt;", markup)
        self.assertIn("Report privacy", markup)
        self.assertNotIn("\x1b", plain)
        self.assertFalse(any(tag in {"script", "iframe", "img"} for tag, attrs in Markup(markup).tags))
        self.assertIn("SNAPSHOT COMPARISON", plain)
        self.assertIn("https://demo.example.com/login", plain)
        saved = json.loads(render(report, "json"))
        self.assertEqual(saved["link_analysis"]["final_url"], "https://demo.example.com/login")

    def test_reputation_export_is_historical_and_separate_not_a_current_warning(self):
        report = fixture()
        report["reputation"] = {"provider": "Google Safe Browsing", "status": "listed",
                                "checked_at": "2026-10-30T12:00:00+00:00", "expires_at": "2026-10-30T12:05:00+00:00",
                                "matches": [{"url": "https://example.com/listed", "threat_type": "MALWARE"}],
                                "attribution": "Advisory provided by Google"}
        with patch("verifact.reputation.public_result", return_value=report["reputation"]):
            markup, plain = html_report(report), text_report(report)
        self.assertIn("Snapshot only", markup)
        self.assertIn("does not display a current threat warning or clearance", plain)
        self.assertIn("Advisory provided by Google", markup)
        self.assertIn("No known match does not mean a link is safe", markup)
        self.assertNotIn("MALWARE", markup)
        self.assertNotIn("example.com/listed", markup)
        self.assertIn("70%", markup)

    def test_older_reports_and_malformed_optional_sections_still_render(self):
        report = fixture()
        for key in ("link_analysis", "comparison", "reputation"):
            report[key] = ["unsupported shape"]
        markup = html_report(report)
        self.assertNotIn("link-details\"><summary>", markup)
        self.assertIn("Verifact", markup)
        report["link_analysis"] = {"redirects": "bad", "warnings": [None, "bad", {}]}
        report["comparison"] = {"available": True, "changes": [None, "bad", {}]}
        self.assertIn("Not recorded", text_report(report))


if __name__ == "__main__":
    unittest.main()
