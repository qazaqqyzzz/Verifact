"""Extra owner reviews stay useful without changing visitor or score semantics."""

from copy import deepcopy
import unittest

from test_brief import clear_report
from websignal.assessment import assess
from websignal.brief import HYGIENE_COPY, build_brief
from websignal.checks import page_checks
from websignal.network import Response
from websignal.reports import html_report, text_report
from websignal.visitor_assessment import build_visitor_assessment


def hygiene_findings():
    body = ('<title>Werkzeug Debugger</title><p>__debugger__</p>'
            '<iframe src="/" sandbox="allow-scripts allow-same-origin"></iframe>')
    response = Response("https://demo.example.com/", 500, {
        "content-type": "text/html", "x-content-type-options": "not-a-policy",
        "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
        "cache-control": "public, max-age=60", "cross-origin-embedder-policy": "invalid-value",
    }, body.encode(), set_cookie_headers=["preference=private-value; Secure"])
    return [item for item in page_checks(response) if item["id"] in HYGIENE_COPY]


def report_with_hygiene():
    report = clear_report()
    report["findings"] = [item for item in report["findings"] if item["id"] not in HYGIENE_COPY]
    report["findings"].extend(hygiene_findings())
    return report


class HygieneBriefTests(unittest.TestCase):
    def test_six_real_extra_findings_join_priorities_without_inflating_core_counts(self):
        report = report_with_hygiene()
        before = deepcopy(report)
        result = build_brief(report)
        reviews = result["all_reviews"]
        self.assertEqual({item["id"] for item in reviews}, set(HYGIENE_COPY))
        self.assertEqual(result["total_review"], 6)
        self.assertEqual(len(result["reviews"]), 3)
        self.assertEqual(result["counts"], {"met": 10, "review": 0, "unknown": 0, "total": 10, "urgent": 0})
        self.assertEqual(assess(report)["value"], 100)
        self.assertEqual(assess(report)["total_checks"], 8)
        self.assertEqual(result["total_urgent"], 0)
        self.assertTrue(all(item["source"] == "hygiene" and item["tone"] == "amber" for item in reviews))
        self.assertTrue(all(item["finding_id"] == item["id"] for item in reviews))
        self.assertTrue(all(item["action"].startswith("Owner:") for item in reviews))
        self.assertTrue(all(len(item["why"]) <= 160 and len(item["action"]) <= 160 for item in reviews))
        self.assertEqual(before, report)

    def test_extra_owner_issues_do_not_change_link_check_verdict(self):
        before = clear_report()
        after = report_with_hygiene()
        previous, current = build_visitor_assessment(before), build_visitor_assessment(after)
        for key in ("status", "tone", "summary", "reasons", "coverage"):
            self.assertEqual(previous[key], current[key])

    def test_info_unknown_duplicate_and_unsupported_evidence_never_create_extra_review(self):
        for status in ("info", "unknown", "pass"):
            report = report_with_hygiene()
            for item in report["findings"]:
                if item["id"] in HYGIENE_COPY:
                    item["status"] = status
            self.assertEqual(build_brief(report)["all_reviews"], [])
        report = report_with_hygiene()
        report["findings"].extend(deepcopy(hygiene_findings()))
        self.assertEqual(build_brief(report)["all_reviews"], [])
        report = report_with_hygiene()
        for item in report["findings"]:
            if item["id"] in HYGIENE_COPY:
                item["evidence"] = {"issues": [{"header": [], "issue": {}}], "unrecognized_headers": [{}],
                                    "error_page_markers": [[]], "same_origin_source_with_both": True}
        self.assertEqual(build_brief(report)["all_reviews"], [])

    def test_copy_follows_observed_conditions_and_ignores_forged_prose(self):
        report = report_with_hygiene()
        for item in report["findings"]:
            if item["id"] in HYGIENE_COPY:
                item.update(title="Confirmed hacking", explanation="Credentials were stolen", recommendation="Trust this link")
        reviews = {item["id"]: item for item in build_brief(report)["all_reviews"]}
        self.assertIn("do not allow credentialed reads", reviews["cors_policy"]["why"])
        self.assertIn("does not prove private data", reviews["response_caching"]["why"])
        self.assertIn("No exploitable flaw", reviews["public_disclosures"]["why"])
        self.assertNotIn("Credentials were stolen", str(reviews))
        self.assertNotIn("Trust this link", str(reviews))

    def test_exports_include_unscored_owner_actions_with_score_separate(self):
        report = report_with_hygiene()
        plain, markup = text_report(report), html_report(report)
        self.assertIn("ADDITIONAL DEVELOPER REVIEWS / UNSCORED", plain)
        self.assertIn("Additional developer reviews · unscored", markup)
        self.assertIn("Review shared caching", plain)
        self.assertIn("does not prove private data is being shared", plain)
        self.assertIn("100/100", plain)


if __name__ == "__main__":
    unittest.main()
