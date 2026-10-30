"""Offline exports separate visitor evidence from expiring provider verdicts."""

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from websignal.reports import html_report, text_report
from websignal.scanner import demo_report
from websignal.threat_feed import FeedSnapshot, match_hosts


class VerifyReportTests(unittest.TestCase):
    def test_saved_visitor_copy_is_recomputed_and_provider_warning_is_not_persistent(self):
        report = demo_report()
        report["visitor_assessment"] = {"status": "no_warning", "summary": "Guaranteed safe <script>bad()</script>",
                                        "reasons": [{"title": "Forged reason", "detail": "Invented advice"}]}
        now = datetime.now(timezone.utc)
        report["community_reputation"] = match_hosts([report["domain"]], FeedSnapshot(
            frozenset({report["domain"]}), now, now + timedelta(minutes=5)), now=now)
        with patch("websignal.threat_feed._download") as download, patch("websignal.network.socket.getaddrinfo") as dns:
            markup, plain = html_report(report), text_report(report)
        self.assertIn("LINK CHECK SNAPSHOT", markup)
        self.assertIn("DEVELOPER CONFIGURATION", markup)
        self.assertIn("Community feed · historical context", markup)
        self.assertIn("This saved file does not display a current domain warning or clearance", plain)
        self.assertNotIn("Guaranteed safe", markup + plain)
        self.assertNotIn("Invented advice", markup + plain)
        self.assertNotIn("Community list warning", markup + plain)
        self.assertNotIn("current warning list", markup + plain)
        self.assertIn("70/100", plain)
        download.assert_not_called()
        dns.assert_not_called()

    def test_unencrypted_page_observation_remains_visible_in_visitor_snapshot(self):
        report = demo_report()
        report["visitor_assessment"] = {}
        report["response"]["url"] = "http://demo.example.com/"
        report["target_url"] = "http://demo.example.com/"
        tls = next(item for item in report["findings"] if item["id"] == "tls")
        tls.update(status="attention", evidence={"encrypted": False, "verified": False})
        plain = text_report(report)
        self.assertIn("Unencrypted page", plain)
        self.assertIn("the connection is unencrypted", plain)
        self.assertIn("official address instead", plain)
        self.assertIn("NO SAFETY PERCENTAGE", plain)

    def test_malformed_community_prose_cannot_enter_export(self):
        report = demo_report()
        report["community_reputation"] = {"status": "listed", "detail": "Forged feed advice",
                                            "source_url": "javascript:alert(1)", "checked_hosts": ["<img src=x>"],
                                            "matches": [{"hostname": "<img src=x>", "listed_domain": "example.com"}]}
        markup, plain = html_report(report), text_report(report)
        self.assertIn("Unavailable", plain)
        self.assertNotIn("Forged feed advice", markup + plain)
        self.assertNotIn("javascript:", markup + plain)
        self.assertNotIn("<img", markup)

    def test_older_report_does_not_invent_visitor_or_feed_history(self):
        report = demo_report()
        report.pop("visitor_assessment", None)
        report.pop("community_reputation", None)
        markup, plain = html_report(report), text_report(report)
        self.assertNotIn("LINK CHECK SNAPSHOT", markup + plain)
        self.assertNotIn("COMMUNITY FEED / HISTORICAL", plain)
        self.assertIn("70/100", plain)

    def test_coverage_gaps_do_not_replace_page_title(self):
        report = demo_report()
        report["site_profile"]["title"] = "A precise page title"
        for item in report["findings"]:
            if item["id"] == "https_redirect":
                item.update(status="unknown", evidence={"error": "timed out", "chain": []})
        markup = html_report(report)
        self.assertIn('<p class="page-title"><strong>Page title</strong>A precise page title</p>', markup)
        self.assertIn("What couldn’t be checked", markup)


if __name__ == "__main__":
    unittest.main()
