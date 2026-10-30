"""Grounding and bounds for the richer optional explanation contract."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from verifact.ai import AIError, ITEM_LIMITS, explain, output_schema, prepare_messages, validate_output
from verifact.scanner import demo_report
from tests.test_ai import answer


class NarrativeTests(unittest.TestCase):
    def test_input_recalculates_checklist_and_prioritizes_security(self):
        report = demo_report()
        report["assessment"] = {"value": 999, "coverage": 999}
        report["dashboard"] = {"rating": {"label": "Absolutely safe"}, "priorities": []}
        original = deepcopy(report)
        data = json.loads(prepare_messages(report)[1]["content"])
        self.assertEqual(data["checklist"]["value"], 70)
        self.assertEqual(data["checklist"]["coverage"], 100)
        self.assertEqual(data["priority_finding_ids"], ["http_resources", "csp", "framing"])
        self.assertEqual({item["id"] for item in data["findings"]}, {"http_resources", "csp", "framing", "tls"})
        self.assertEqual(report, original)
        self.assertNotIn("Absolutely safe", json.dumps(data))

    def test_unknown_context_does_not_invent_missing_protections(self):
        report = demo_report()
        for item in report["findings"]:
            item["status"] = "unknown"
            item["evidence"] = "No completed observation."
        data = json.loads(prepare_messages(report)[1]["content"])
        self.assertIsNone(data["checklist"]["value"])
        self.assertEqual(data["checklist"]["coverage"], 0)
        self.assertTrue(all(item["status"] == "unknown" for item in data["findings"]))
        self.assertTrue(all("No missing protection" in item["observation_summary"] for item in data["findings"]))

    def test_model_gets_background_and_site_context_without_page_body(self):
        report = demo_report()
        report["site_profile"] = {"title": "Student login", "type": "University login page",
                                  "summary": "Appears to be a university account access page.",
                                  "basis": "Inferred from academic context and a login form.",
                                  "hostname": "portal.example.edu", "https": True, "http_status": 200}
        report["raw_html"] = "Private page body must not be sent."
        data = json.loads(prepare_messages(report)[1]["content"])
        self.assertIn(data["site_profile"]["type"], {"University login page", "Education login page"})
        self.assertTrue(data["site_profile"]["summary"])
        self.assertNotIn("Private page body", json.dumps(data))
        for finding in data["findings"]:
            self.assertTrue(finding["check_context"]["why_it_matters"])
            self.assertTrue(finding["check_context"]["limitation"])
            self.assertTrue(finding["observation_summary"])

    def test_summary_and_each_narrative_field_are_required_and_bounded(self):
        report = demo_report()
        for field, maximum in {"summary": 900, **ITEM_LIMITS}.items():
            for replacement in (None, "x" * (maximum + 1), "" if field != "next_step" else None):
                with self.subTest(field=field, replacement_type=type(replacement).__name__):
                    value = answer()
                    target = value if field == "summary" else value["items"][0]
                    target[field] = replacement
                    with self.assertRaises(AIError):
                        validate_output(value, report)
        value = answer()
        value["items"][0]["next_step"] = ""
        self.assertEqual(len(validate_output(value, report)), 3)
        del value["items"][0]["why_it_matters"]
        with self.assertRaises(AIError):
            validate_output(value, report)

    def test_short_report_does_not_force_invented_findings(self):
        report = demo_report()
        report["findings"] = [next(item for item in report["findings"] if item["id"] == "tls")]
        schema = output_schema(report)
        self.assertEqual(schema["properties"]["items"]["minItems"], 1)
        self.assertEqual(schema["properties"]["items"]["maxItems"], 1)
        value = answer("tls")
        value["items"] = value["items"][:1]
        self.assertEqual(validate_output(value, report)[0]["finding_id"], "tls")

    def test_recorded_observations_and_limits_are_not_rewritten_by_model(self):
        report = demo_report()
        value = answer()
        value["summary"] = "The model incorrectly declares this site safe and all tests passed."
        value["items"][0]["explanation"] = "The model incorrectly claims a strong content policy exists."
        value["items"][0]["limitation"] = "The model incorrectly claims every browser was tested."
        response = {"done": True, "message": {"content": json.dumps(value)}}
        with patch("verifact.ai._post", return_value=response):
            result = explain(report, provider="ollama")
        item = result["ai"]["items"][0]
        self.assertIn("No enforcing content policy was observed", item["explanation"])
        self.assertIn("does not prove", item["limitation"])
        self.assertEqual(item["why_it_matters"], value["items"][0]["why_it_matters"])
        self.assertIn("supplied by Verifact", result["ai"]["validation"])
        self.assertNotIn("incorrectly", result["ai"]["summary"])
        self.assertIn("70 out of 100", result["ai"]["summary"])
        self.assertEqual(result["findings"], report["findings"])

    def test_unknown_findings_request_evidence_not_configuration_changes(self):
        report = demo_report()
        for finding in report["findings"]:
            finding["status"] = "unknown"
            finding["evidence"] = "Unavailable."
        value = answer()
        identifiers = [item["id"] for item in report["findings"] if item["id"] in {"tls", "password_forms", "https_redirect"}]
        for item, identifier in zip(value["items"], identifiers):
            item["finding_id"] = identifier
            item["why_it_matters"] = "The model incorrectly infers a vulnerability."
            item["next_step"] = "The model incorrectly tells visitors to change the server."
        response = {"done": True, "message": {"content": json.dumps(value)}}
        with patch("verifact.ai._post", return_value=response):
            result = explain(report, provider="ollama")
        self.assertIn("percentage is unavailable", result["ai"]["summary"])
        for item in result["ai"]["items"]:
            self.assertNotIn("incorrectly", item["why_it_matters"])
            self.assertIn("ask the site owner for evidence", item["next_step"])
            self.assertIn("This check was not established", item["limitation"])

    def test_positive_checks_cannot_gain_false_model_purposes_or_actions(self):
        for identifier, status, expected in (
                ("tls", "pass", "requested hostname"),
                ("https_redirect", "pass", "start with an HTTP address"),
                ("csp", "info", "reduce some script-injection risks")):
            with self.subTest(finding=identifier):
                report = demo_report()
                report["findings"] = [next(f for f in report["findings"] if f["id"] == identifier)]
                report["findings"][0]["status"] = status
                original = deepcopy(report)
                value = answer(identifier)
                value["items"] = value["items"][:1]
                value["items"][0]["why_it_matters"] = "This check prevents mixed-content errors and proves support for every TLS version."
                value["items"][0]["next_step"] = "Immediately change the university server configuration."
                response = {"done": True, "message": {"content": json.dumps(value)}}
                with patch("verifact.ai._post", return_value=response):
                    result = explain(report, provider="ollama")
                item = result["ai"]["items"][0]
                self.assertIn(expected, item["why_it_matters"])
                self.assertNotIn("prevents mixed-content", item["why_it_matters"])
                self.assertNotIn("every TLS version", item["why_it_matters"])
                self.assertIn("No configuration change", item["next_step"])
                self.assertEqual(report, original)

    def test_hsts_absolute_claim_falls_back_without_replacing_review_advice(self):
        report = demo_report()
        report["findings"] = [next(f for f in report["findings"] if f["id"] == "hsts")]
        report["findings"][0]["status"] = "attention"
        original = deepcopy(report)
        for claim in (
                "HSTS acts as a long-term guarantee that users will be redirected to secure connections, but its absence means the site relies on client-side defaults rather than server-enforced policies.",
                "This ensures secure browsing.", "This is ensuring secure browsing.",
                "Users are always fully secure."):
            with self.subTest(claim=claim):
                value = answer("hsts")
                value["items"] = value["items"][:1]
                value["items"][0]["why_it_matters"] = claim
                response = {"done": True, "message": {"content": json.dumps(value)}}
                with patch("verifact.ai._post", return_value=response):
                    result = explain(report, provider="ollama")
                item = result["ai"]["items"][0]
                self.assertIn("future requests during the policy lifetime", item["why_it_matters"])
                self.assertEqual(item["next_step"], value["items"][0]["next_step"])
                self.assertEqual(report, original)
                self.assertEqual(value["items"][0]["why_it_matters"], claim)


if __name__ == "__main__":
    unittest.main()
