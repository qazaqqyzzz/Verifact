"""Visitor conclusions use only relevant observations, never configuration scores."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from websignal.network import Fetch, Response
from websignal.scanner import finish_report
from websignal import threat_feed as feed
from websignal.visitor_assessment import build_visitor_assessment


NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)


def report_fixture(body=b"<html><title>Example</title><p>Public page</p></html>", target="https://example.com/", final=None):
    final = final or target
    response = Response(final, 200, {"content-type": "text/html"}, body,
                        tls={"verified": True, "hostname": final.split("/")[2], "not_after": "Dec 31 23:59:59 2099 GMT"})
    route = [{"url": target, "status": 302}, {"url": final, "status": 200}] if final != target else [{"url": final, "status": 200}]
    https = Fetch(response, route)
    http = Fetch(response, [{"url": "http://example.com/", "status": 301}, {"url": final, "status": 200}])
    report = finish_report("example.com", http, https, len(route) + 1, target_url=target)
    hosts = list(dict.fromkeys(url.split("/")[2] for url in (target, final)))
    snapshot = feed.FeedSnapshot(frozenset({"listed.other.example"}), NOW, NOW + timedelta(minutes=5))
    report["community_reputation"] = feed.match_hosts(hosts, snapshot, NOW)
    return report


def finding(report, identifier):
    return next(item for item in report["findings"] if item["id"] == identifier)


class VisitorAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch("websignal.threat_feed._now", return_value=NOW)
        self.cache = patch("websignal.threat_feed._CACHE", feed.FeedCache())
        self.clock.start()
        self.cache.start()
        self.addCleanup(self.clock.stop)
        self.addCleanup(self.cache.stop)

    def test_missing_headers_and_low_configuration_score_do_not_imply_a_scam(self):
        report = report_fixture()
        self.assertLess(report["assessment"]["value"], 80)
        self.assertEqual(finding(report, "hsts")["status"], "attention")
        result = build_visitor_assessment(report)
        self.assertEqual((result["status"], result["tone"]), ("no_warning", "green"))
        self.assertEqual(result["label"], "No warning found")
        self.assertIn("identity is unverified", result["summary"])
        self.assertNotIn("score", result)
        self.assertEqual(result["coverage"]["optional_reputation"], "not_checked")
        self.assertEqual(result["expires_at"], (NOW + timedelta(minutes=5)).isoformat())

    def test_current_domain_match_warns_without_claiming_every_page_is_malicious(self):
        report = report_fixture()
        snapshot = feed.FeedSnapshot(frozenset({"example.com"}), NOW, NOW + timedelta(minutes=5))
        report["community_reputation"] = feed.match_hosts(["example.com"], snapshot, NOW)
        result = build_visitor_assessment(report)
        self.assertEqual((result["status"], result["tone"]), ("warning", "red"))
        self.assertEqual(result["reasons"][0]["id"], "community_match")
        self.assertEqual(result["reasons"][0]["detail"], "example.com is currently listed by CERT Polska.")
        self.assertNotIn("scam", result["reasons"][0]["detail"])

    def test_stale_unavailable_and_disabled_feed_results_never_become_green(self):
        for value in (feed.public_result(None), {"status": "unavailable"},
                      feed.match_hosts(["example.com"], feed.FeedSnapshot(frozenset({"example.com"}), NOW - timedelta(minutes=6), NOW - timedelta(minutes=1)), NOW - timedelta(minutes=6))):
            report = report_fixture()
            report["community_reputation"] = value
            with self.subTest(value=value):
                result = build_visitor_assessment(report)
                self.assertEqual((result["status"], result["tone"]), ("unknown", "gray"))
                self.assertEqual(result["reasons"][0]["id"], "community_gap")

    def test_feed_must_cover_all_observed_redirect_hosts(self):
        report = report_fixture(target="https://example.com/", final="https://login.example.net/")
        report["community_reputation"]["checked_hosts"] = ["example.com"]
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["coverage"]["community_feed"], "unavailable")

    def test_normal_cross_host_redirect_is_context_not_automatic_caution(self):
        report = report_fixture(target="https://example.com/", final="https://www.example.com/")
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "no_warning")
        self.assertFalse(any(item["id"] == "host_change" for item in result["reasons"]))

    def test_expected_domain_mismatch_and_spelling_signals_need_verification(self):
        report = report_fixture()
        report["link_analysis"].update(expected_domain="expected.example", expected_match=False)
        report["link_analysis"]["warnings"].append({"id": "mixed_script", "tone": "amber", "detail": "untrusted free text"})
        result = build_visitor_assessment(report)
        self.assertEqual((result["status"], result["tone"]), ("caution", "orange"))
        self.assertEqual({item["id"] for item in result["reasons"]}, {"domain_spelling", "unexpected_destination"})
        self.assertNotIn("untrusted free text", repr(result))

    def test_http_or_get_password_destinations_are_red_and_external_login_is_orange(self):
        cases = [(b'<form action="http://example.com/login" method="post"><input type="password" name="password"></form>', "warning"),
                 (b'<form method="get"><input type="password" name="password"></form>', "warning"),
                 (b'<form action="https://identity.example.net/" method="post"><input type="password" name="password"></form>', "caution")]
        for body, expected in cases:
            with self.subTest(body=body):
                result = build_visitor_assessment(report_fixture(body))
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["reasons"][0]["finding_id"], "password_forms")
                self.assertIn("No form was submitted", result["reasons"][0]["detail"] if expected == "warning" else "No form was submitted")

    def test_partial_html_http_error_and_unresolved_form_evidence_stay_unknown(self):
        for change in ("truncated", "http_error", "unknown_forms", "duplicate_tls", "contradictory_forms"):
            report = report_fixture()
            if change == "truncated":
                report["response"]["body_truncated"] = True
            elif change == "http_error":
                report["response"]["status"] = 403
            elif change == "unknown_forms":
                finding(report, "password_forms")["status"] = "unknown"
            elif change == "duplicate_tls":
                report["findings"].append(deepcopy(finding(report, "tls")))
            else:
                finding(report, "password_forms")["evidence"]["http_actions"] = 1
            with self.subTest(change=change):
                self.assertEqual(build_visitor_assessment(report)["status"], "unknown")

    def test_downgrade_warning_survives_incomplete_route(self):
        report = report_fixture()
        report["response"] = None
        report["link_analysis"].update(final_url=None, completed=False, error="Blocked downgrade", error_kind="downgrade")
        finding(report, "tls").update(status="attention", evidence={"error": "Blocked downgrade"})
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["reasons"][0]["id"], "downgrade")
        self.assertEqual(result["coverage"]["destination"], "unavailable")

    def test_current_google_match_is_independent_of_missing_community_data(self):
        report = report_fixture()
        report["community_reputation"] = feed.public_result(None)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=1)
        report["reputation"] = {"status": "listed", "provider": "Google Safe Browsing", "expires_at": expiry.isoformat(),
                                "matches": [{"url": "https://example.com/", "threat_type": "SOCIAL_ENGINEERING"}]}
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["reasons"][0]["id"], "known_threat")
        report["reputation"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.assertEqual(build_visitor_assessment(report)["status"], "unknown")

    def test_reasons_are_capped_and_imported_verdict_is_not_trusted(self):
        report = report_fixture(b'<form method="get"><input type="password" name="password"></form>')
        report["link_analysis"].update(expected_match=False, expected_domain="other.example")
        report["link_analysis"]["warnings"].extend([{"id": "mixed_script"}, {"id": "http_start"}])
        report["visitor_assessment"] = {"status": "no_warning", "summary": "Guaranteed safe"}
        original = deepcopy(report)
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "warning")
        self.assertEqual(len(result["reasons"]), 3)
        self.assertNotIn("Guaranteed safe", repr(result))
        self.assertEqual(report, original)

    def test_green_form_copy_distinguishes_no_active_forms_from_observed_forms(self):
        cases = [(b"<p>No sign-in here</p>", "0 active password forms"),
                 (b'<form method="post"><input type="password" name="pw"></form>', "1 password form checked"),
                 (b'<form method="post"><input type="password" name="pw"></form>'
                  b'<form method="post"><input type="password" name="pw"></form>', "2 password forms checked"),
                 (b'<form method="dialog"><input type="password" name="pw"></form>', "1 password form checked")]
        for body, title in cases:
            with self.subTest(title=title, body=body):
                result = build_visitor_assessment(report_fixture(body))
                self.assertEqual(result["status"], "no_warning")
                item = next(reason for reason in result["reasons"] if reason["id"] == "static_forms")
                self.assertEqual(item["title"], title)
                if title.startswith("0"):
                    self.assertIn("No active password form", item["detail"])
                else:
                    self.assertIn("No submission", item["detail"])
                    self.assertNotIn("use HTTPS POST", item["detail"])

    def test_missing_or_boolean_form_count_is_not_presented_as_zero(self):
        for count in (None, False, "0"):
            report = report_fixture()
            finding(report, "password_forms")["evidence"]["forms_with_password"] = count
            with self.subTest(count=count):
                result = build_visitor_assessment(report)
                item = next(reason for reason in result["reasons"] if reason["id"] == "static_forms")
                self.assertNotIn("0", item["title"])
                self.assertIn("count was not recorded", item["detail"])

    def test_community_gaps_distinguish_not_run_stale_and_unavailable(self):
        stale = feed.match_hosts(["example.com"], feed.FeedSnapshot(frozenset({"other.example"}), NOW - timedelta(minutes=6), NOW - timedelta(minutes=1)), NOW - timedelta(minutes=6))
        cases = [(feed.public_result(None), "Community check not run", "Turn on"),
                 (stale, "Community result needs refreshing", "refresh"),
                 ({"status": "unavailable", "detail": "PRIVATE provider error"}, "Community list unavailable", "refresh")]
        for value, title, action in cases:
            report = report_fixture()
            report["community_reputation"] = value
            with self.subTest(title=title):
                result = build_visitor_assessment(report)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reasons"][0]["title"], title)
                self.assertIn(action, result["next_action"])
                self.assertNotIn("PRIVATE", repr(result))

    def test_http_error_partial_body_and_non_html_have_concrete_reasons(self):
        cases = [("forbidden", "Page returned HTTP 403", "refused"),
                 ("not_found", "Page returned HTTP 404", "not found"),
                 ("limited", "Page returned HTTP 429", "limited"),
                 ("truncated", "Only part of the page was read", "incomplete"),
                 ("body_error", "Page download interrupted", "read completely"),
                 ("not_html", "No usable HTML", "not supported HTML")]
        for kind, title, detail in cases:
            report = report_fixture()
            if kind in {"forbidden", "not_found", "limited"}:
                report["response"]["status"] = {"forbidden": 403, "not_found": 404, "limited": 429}[kind]
            elif kind == "truncated":
                report["response"]["body_truncated"] = True
            elif kind == "body_error":
                report["response"]["body_error"] = "PRIVATE response error https://example.com/?token=SECRET"
            else:
                finding(report, "title").update(status="unknown", evidence="HTML unavailable")
                finding(report, "password_forms")["evidence"]["complete_html"] = False
            with self.subTest(kind=kind):
                result = build_visitor_assessment(report)
                self.assertEqual(result["status"], "unknown")
                item = next(reason for reason in result["reasons"] if reason["id"] == "page_gap")
                self.assertEqual(item["title"], title)
                self.assertIn(detail, item["detail"])
                self.assertNotIn("PRIVATE", repr(result))
                self.assertNotIn("SECRET", repr(result))
                self.assertTrue(result["next_action"])

    def test_connection_failures_are_classified_without_repeating_raw_messages(self):
        cases = [("DNS lookup failed for private.example: SECRET", "unavailable", "Domain lookup failed"),
                 ("Request unavailable: timed out at https://example.com/?secret=SECRET", "unavailable", "Connection timed out"),
                 ("Redirect limit reached.", "unavailable", "Too many redirects"),
                 ("Redirect loop detected.", "unavailable", "Redirect loop"),
                 ("Blocked private URL SECRET", "blocked", "Destination blocked")]
        for error, kind, title in cases:
            report = report_fixture()
            report["response"] = None
            report["link_analysis"].update(completed=False, final_url=None, error=error, error_kind=kind)
            finding(report, "tls").update(status="unknown", evidence={"error": error})
            with self.subTest(title=title):
                result = build_visitor_assessment(report)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reasons"], [{"id": "connection_gap", "title": title,
                                                     "detail": result["reasons"][0]["detail"], "source": "connection"}])
                self.assertNotIn("SECRET", repr(result))
                self.assertNotIn("private.example", repr(result))

    def test_expected_hostname_is_concrete_without_reflecting_query_or_imported_url(self):
        report = report_fixture(target="https://example.com/?q=PRIVATE_QUERY", final="https://login.example.net/?q=PRIVATE_QUERY")
        report["link_analysis"].update(expected_match=False, expected_domain="expected.example")
        result = build_visitor_assessment(report)
        item = next(reason for reason in result["reasons"] if reason["id"] == "unexpected_destination")
        self.assertEqual(item["detail"], "Ends at login.example.net; you expected expected.example.")
        self.assertNotIn("PRIVATE_QUERY", repr(result))
        report["link_analysis"]["expected_domain"] = "https://expected.example/?token=PRIVATE_TOKEN"
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "caution")
        self.assertNotIn("PRIVATE_TOKEN", repr(result))

    def test_conflicting_form_evidence_is_not_mislabeled_as_a_demo(self):
        report = report_fixture()
        finding(report, "password_forms")["evidence"]["http_actions"] = 1
        result = build_visitor_assessment(report)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reasons"][0]["title"], "Form records conflict")
        self.assertNotIn("sample", repr(result))


if __name__ == "__main__":
    unittest.main()
