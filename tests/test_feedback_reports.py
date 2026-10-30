"""Saved reports use evidence-derived feedback, including incomplete checks."""

from copy import deepcopy
import html
import json
import re
import unittest

from websignal.assessment import assess
from websignal.check_feedback import check_feedback_for_report
from websignal.reports import html_report, render, text_report
from websignal.scanner import demo_report


def finding_card(markup, report, identifier, occurrence=0):
    indexes = [index for index, item in enumerate(report["findings"])
               if item["id"] == identifier]
    match = re.search(r'<article id="finding-' + str(indexes[occurrence])
                      + r'".*?</article>', markup, re.S)
    return match.group(0)


class FeedbackReportTests(unittest.TestCase):
    def test_saved_feedback_is_recomputed_in_every_export_without_mutating_report(self):
        report = demo_report()
        report["check_feedback"] = {"tls": {
            "result": "Guaranteed safe", "fact": "Forged fact", "fix": "Disable all checks", "state": "pass",
        }}
        original = deepcopy(report)
        markup, plain, saved = html_report(report), text_report(report), render(report, "json")
        for output in (markup, plain, saved):
            for forged in ("Guaranteed safe", "Forged fact", "Disable all checks"):
                self.assertNotIn(forged, output)
        self.assertEqual(json.loads(saved)["check_feedback"], check_feedback_for_report(report))
        self.assertEqual(report, original)

    def test_findings_show_result_fact_fix_instead_of_generic_test_explanation(self):
        report = demo_report()
        finding = next(item for item in report["findings"] if item["id"] == "csp")
        finding["explanation"] = "GENERIC EXPLANATION WHICH DOES NOT STATE THE RESULT"
        feedback = check_feedback_for_report(report)["csp"]
        markup, plain = html_report(report), text_report(report)
        card = finding_card(markup, report, "csp")
        self.assertIn('class="feedback-label">Test', card)
        self.assertIn('class="feedback-label">Result', card)
        self.assertIn("<dt>Fact</dt>", card)
        self.assertIn("<dt>Fix</dt>", card)
        for field in ("result", "fact", "fix"):
            self.assertIn(html.escape(feedback[field], quote=True), card)
            self.assertIn(feedback[field], plain)
        self.assertNotIn(finding["explanation"], card + plain)
        self.assertIn("Recorded evidence", card)
        self.assertNotIn('class="report-disclosure guidance-section"', markup)

    def test_information_is_not_promoted_to_passed_by_presence_credit(self):
        report = demo_report()
        finding = next(item for item in report["findings"] if item["id"] == "csp")
        finding.update(status="info", evidence={"header": "default-src 'self'", "meta": ""})
        feedback = check_feedback_for_report(report)["csp"]
        self.assertEqual(feedback["state"], "info")
        card = finding_card(html_report(report), report, "csp")
        self.assertIn('class="badge info"', card)
        self.assertNotIn('class="badge pass"', card)
        self.assertIn(html.escape(feedback["result"]), card)

    def test_unknown_has_concrete_feedback_and_does_not_become_a_failure(self):
        report = demo_report()
        finding = next(item for item in report["findings"] if item["id"] == "https_redirect")
        finding.update(status="unknown", evidence={"error": "timed out", "chain": []})
        feedback = check_feedback_for_report(report)["https_redirect"]
        self.assertEqual(feedback["state"], "unknown")
        self.assertTrue(feedback["fact"])
        self.assertTrue(feedback["fix"])
        score = assess(report)
        card = finding_card(html_report(report), report, "https_redirect")
        self.assertIn('class="badge unknown"', card)
        self.assertNotIn('class="badge attention"', card)
        self.assertIn(html.escape(feedback["fact"], quote=True), card)
        self.assertEqual(json.loads(render(report, "json"))["assessment"], score)

    def test_duplicate_findings_are_not_assigned_a_successful_result(self):
        report = demo_report()
        report["findings"].append(deepcopy(next(item for item in report["findings"] if item["id"] == "hsts")))
        markup = html_report(report)
        for occurrence in (0, 1):
            card = finding_card(markup, report, "hsts", occurrence)
            self.assertIn('class="badge unknown"', card)
            self.assertNotIn('class="badge pass"', card)


if __name__ == "__main__":
    unittest.main()
