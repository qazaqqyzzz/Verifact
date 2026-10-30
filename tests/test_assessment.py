"""Offline tests for honest score coverage and deterministic explanations."""

from copy import deepcopy
import json
import unittest

from verifact.assessment import CHECKLIST, assess, built_in_guidance, enrich
from verifact.reports import html_report, render, text_report
from verifact.scanner import demo_report


class AssessmentTests(unittest.TestCase):
    def test_all_checks_pass_is_full_checklist_not_a_security_probability(self):
        report = demo_report()
        for finding in report["findings"]:
            finding["status"] = "pass"
        score = assess(report)
        self.assertEqual(sum(item[2] for item in CHECKLIST), 100)
        self.assertEqual((score["value"], score["potential"], score["coverage"]), (100, 100, 100))
        self.assertEqual(score["assessed_checks"], 8)
        self.assertIn("not a percentage probability", score["disclaimer"])

    def test_unknown_checks_keep_fixed_denominator_and_show_range(self):
        report = {"findings": [{"id": "tls", "status": "pass", "evidence": {}}]}
        score = assess(report)
        self.assertEqual(score["value"], 25)
        self.assertEqual(score["potential"], 100)
        self.assertEqual(score["coverage"], 25)
        self.assertEqual(score["assessed_checks"], 1)
        self.assertEqual(score["unknown_weight"], 75)
        self.assertEqual(score["possible"], 100)
        self.assertEqual(sum(item["weight"] for item in score["items"] if not item["assessed"]), 75)

    def test_no_assessed_evidence_is_not_a_zero_security_verdict(self):
        for findings in ([], [{"id": key, "status": "unknown"} for key, _, _ in CHECKLIST]):
            with self.subTest(findings=findings):
                score = assess({"findings": findings})
                self.assertIsNone(score["value"])
                self.assertEqual((score["potential"], score["coverage"], score["assessed_checks"]), (100, 0, 0))

    def test_attention_is_assessed_but_does_not_earn_weight(self):
        score = assess({"findings": [{"id": "tls", "status": "attention"}]})
        self.assertEqual((score["value"], score["potential"], score["coverage"]), (0, 75, 25))

    def test_presence_credit_requires_matching_observed_evidence(self):
        report = {"findings": [
            {"id": "csp", "status": "info", "evidence": {"header": "default-src *", "meta": ""}},
            {"id": "framing", "status": "info", "evidence": {"x_frame_options": "SAMEORIGIN"}},
        ]}
        score = assess(report)
        self.assertEqual((score["value"], score["coverage"]), (20, 20))
        self.assertTrue(all("Presence credit only" in item["note"] for item in score["items"] if item["assessed"]))
        for item in report["findings"]:
            item["evidence"] = {"header": "", "x_frame_options": "unexpected"}
        self.assertIsNone(assess(report)["value"])

    def test_other_info_and_duplicate_ids_are_not_counted_as_passes(self):
        score = assess({"findings": [
            {"id": "tls", "status": "info", "evidence": {"header": "present"}},
            {"id": "hsts", "status": "pass"}, {"id": "hsts", "status": "attention"},
        ]})
        self.assertEqual(score["coverage"], 0)

    def test_domain_and_nonsecurity_quality_do_not_change_score(self):
        original = demo_report()
        changed = deepcopy(original)
        for item in changed["findings"]:
            if item["id"] in {"dns", "title", "viewport", "language", "image_alt"}:
                item["status"] = "unknown"
        changed["findings"].append({"id": "rdap", "status": "pass", "category": "Domain",
                                    "evidence": {"registration": "1900-01-01"}})
        self.assertEqual(assess(original), assess(changed))

    def test_enrichment_is_deterministic_preserves_input_and_ignores_saved_score(self):
        report = demo_report()
        report["assessment"] = {"value": 999, "disclaimer": "Definitely safe"}
        report["guidance"] = {"items": [{"explanation": "A fabricated explanation"}]}
        original = deepcopy(report)
        first, second = enrich(report), enrich(report)
        self.assertEqual(first, second)
        self.assertEqual(report, original)
        self.assertEqual(first["assessment"]["value"], 70)
        self.assertEqual(first["guidance"]["kind"], "rules")
        first["findings"][0]["status"] = "unknown"
        self.assertEqual(report, original)

    def test_guidance_prioritizes_review_and_does_not_invent_claims(self):
        report = demo_report()
        guidance = built_in_guidance(report)
        self.assertEqual(len(guidance["items"]), 4)
        by_id = {item["id"]: item for item in report["findings"]}
        for item in guidance["items"]:
            source = by_id[item["finding_id"]]
            self.assertEqual(source["status"], "attention")
            self.assertEqual(item["explanation"], source["explanation"])
            self.assertEqual(item["next_step"], source["recommendation"])

    def test_json_html_and_text_recalculate_saved_scores(self):
        report = demo_report()
        report["assessment"] = {"value": 999}
        decoded = json.loads(render(report, "json"))
        self.assertEqual(decoded["assessment"]["value"], 70)
        html = html_report(report)
        self.assertIn("Security configuration score", html)
        self.assertIn("70/100", html)
        self.assertIn("Built-in explanation", html)
        self.assertIn('href="#finding-', html)
        self.assertNotIn("999/100", html)
        self.assertIn("70/100", text_report(report))


if __name__ == "__main__":
    unittest.main()
