"""Traffic lights preserve uncertainty and prioritize observable security issues."""

from copy import deepcopy
import unittest

from websignal.assessment import CHECKLIST, assess, enrich
from websignal.dashboard import build_dashboard


def complete_report():
    findings = [{"id": key, "title": title, "status": "pass", "category": "Browser",
                 "evidence": {}, "explanation": "Observed configuration.", "recommendation": ""}
                for key, title, _ in CHECKLIST]
    findings.extend([
        {"id": "password_forms", "title": "Password form destinations", "status": "info",
         "category": "Browser", "evidence": {"complete_html": True, "forms_with_password": 0},
         "explanation": "No password form observed.", "recommendation": ""},
        {"id": "cookie_flags", "title": "Response cookie attributes", "status": "info",
         "category": "Browser", "evidence": {"limited": False, "malformed_count": 0, "cookies_observed": 0},
         "explanation": "No response cookies observed.", "recommendation": ""},
    ])
    return {"findings": findings}


def get_finding(report, identifier):
    return next(item for item in report["findings"] if item["id"] == identifier)


def dashboard(report):
    return build_dashboard(report, assess(report))


class DashboardTests(unittest.TestCase):
    def test_complete_clear_checklist_has_three_signals_and_no_invented_fixes(self):
        result = dashboard(complete_report())
        self.assertEqual(result["rating"]["tone"], "green")
        self.assertEqual(result["rating"]["label"], "Strong checklist result")
        self.assertIn("does not certify", result["rating"]["summary"])
        self.assertEqual([row["id"] for row in result["signals"]], ["connection", "browser", "page"])
        self.assertTrue(all(row["tone"] == "green" and row["label"] for row in result["signals"]))
        self.assertEqual(result["priorities"], [])
        self.assertEqual(result["security_counts"], {"attention": 0, "unknown": 0, "passed": 8})

    def test_rating_thresholds_are_inclusive_and_explained(self):
        report = complete_report()
        score = assess(report)
        # Isolate the documented display thresholds from finding overrides.
        for value, tone in ((0, "red"), (49, "red"), (50, "amber"), (79, "amber"), (80, "green"), (100, "green")):
            with self.subTest(value=value):
                score["value"] = value
                self.assertEqual(build_dashboard(report, score)["rating"]["tone"], tone)
        self.assertIn("80–100", result := dashboard(report)["rating"]["methodology"])
        self.assertIn("50–79", result)

    def test_high_score_with_a_recorded_issue_stays_amber(self):
        report = complete_report()
        get_finding(report, "hsts")["status"] = "attention"
        result = dashboard(report)
        self.assertEqual(assess(report)["value"], 85)
        self.assertEqual(result["rating"]["tone"], "amber")
        self.assertIn("prevent a green", result["rating"]["override"])
        self.assertEqual(result["priorities"][0]["finding_id"], "hsts")
        self.assertIn("valid positive", result["priorities"][0]["detail"])

    def test_partial_evidence_has_neutral_overall_light_even_when_known_checks_pass(self):
        report = complete_report()
        get_finding(report, "nosniff")["status"] = "unknown"
        score = assess(report)
        result = dashboard(report)
        self.assertEqual((score["value"], score["potential"], score["coverage"]), (90, 100, 90))
        self.assertEqual(result["rating"]["tone"], "unknown")
        self.assertEqual(result["signals"][1]["tone"], "unknown")
        self.assertEqual(result["priorities"][0]["tone"], "unknown")
        self.assertIn("Unknown is not a failure", result["priorities"][0]["detail"])

    def test_no_evidence_does_not_look_like_failure_or_pass(self):
        result = dashboard({"findings": []})
        self.assertEqual(result["rating"]["tone"], "unknown")
        self.assertTrue(all(row["tone"] == "unknown" for row in result["signals"]))
        self.assertEqual(result["priorities"], [])

    def test_http_timeout_explains_the_exact_missing_weight_without_failing_https(self):
        report = complete_report()
        get_finding(report, "https_redirect").update(
            status="unknown", evidence={"chain": [], "error": "Connection failed: timed out"})
        original = deepcopy(report)
        score, result = assess(report), dashboard(report)
        self.assertEqual((score["value"], score["potential"], score["coverage"]), (85, 100, 85))
        self.assertEqual(result["rating"]["tone"], "unknown")
        self.assertEqual(len(result["coverage_gaps"]), 1)
        gap = result["coverage_gaps"][0]
        self.assertEqual((gap["finding_id"], gap["weight"]), ("https_redirect", 15))
        self.assertIn("time limit", gap["detail"])
        self.assertIn("HTTPS was checked separately", gap["detail"])
        self.assertEqual(result["priorities"][0]["detail"], gap["detail"])
        self.assertIn("time limit", result["signals"][0]["detail"])
        self.assertEqual(report, original)

    def test_body_limit_and_interruption_are_distinct_from_security_failures(self):
        report = complete_report()
        get_finding(report, "http_resources")["status"] = "unknown"
        get_finding(report, "password_forms")["status"] = "unknown"
        report["response"] = {"status": 200, "body_truncated": True}
        result = dashboard(report)
        self.assertEqual(assess(report)["value"], 90)
        self.assertEqual([gap["weight"] for gap in result["coverage_gaps"]], [10, 0])
        self.assertTrue(all("reading limit" in gap["detail"] for gap in result["coverage_gaps"]))
        report["response"]["body_error"] = "Body read failed: timed out"
        self.assertTrue(all("download ended early" in gap["detail"] for gap in dashboard(report)["coverage_gaps"]))
        report["response"] = {"status": 403, "body_truncated": False}
        self.assertTrue(all("access-restriction page" in gap["detail"] for gap in dashboard(report)["coverage_gaps"]))

    def test_unscored_registration_failure_does_not_make_security_incomplete(self):
        report = complete_report()
        report["findings"].append({"id": "rdap", "status": "unknown", "evidence": "No supported HTTPS RDAP service found."})
        result = dashboard(report)
        self.assertEqual(assess(report)["value"], 100)
        self.assertEqual(result["rating"]["tone"], "green")
        self.assertEqual(result["coverage_gaps"], [])

    def test_observed_certificate_issue_is_red_even_with_incomplete_other_evidence(self):
        report = complete_report()
        get_finding(report, "tls")["status"] = "attention"
        get_finding(report, "http_resources")["status"] = "unknown"
        result = dashboard(report)
        self.assertEqual(result["rating"]["tone"], "red")
        self.assertEqual(result["signals"][0]["tone"], "red")
        self.assertEqual(result["priorities"][0]["finding_id"], "tls")
        self.assertIn("takes priority", result["rating"]["override"])
        self.assertIn("on this computer", result["priorities"][0]["detail"])

    def test_password_http_or_get_submission_is_red_without_changing_score(self):
        for issue in ("http_actions", "get_submissions"):
            with self.subTest(issue=issue):
                report = complete_report()
                get_finding(report, "password_forms").update(status="attention", evidence={issue: 1, "complete_html": True})
                score = assess(report)
                result = dashboard(report)
                self.assertEqual(score["value"], 100)
                self.assertEqual(result["rating"]["tone"], "red")
                self.assertEqual(result["signals"][2]["tone"], "red")
                self.assertEqual(result["priorities"][0]["finding_id"], "password_forms")

    def test_cross_origin_password_form_and_cookie_warning_are_amber(self):
        for identifier, evidence in (("password_forms", {"cross_origin_actions": 1, "complete_html": True}),
                                     ("cookie_flags", {"missing_secure": 1})):
            with self.subTest(identifier=identifier):
                report = complete_report()
                get_finding(report, identifier).update(status="attention", evidence=evidence)
                self.assertEqual(assess(report)["value"], 100)
                result = dashboard(report)
                self.assertEqual(result["rating"]["tone"], "amber")
                self.assertEqual(result["signals"][2]["tone"], "amber")

    def test_unknown_form_evidence_never_gets_promoted_to_observed_red_issue(self):
        report = complete_report()
        get_finding(report, "password_forms").update(status="unknown", evidence={"http_actions": 1, "complete_html": False})
        result = dashboard(report)
        self.assertEqual(result["rating"]["tone"], "unknown")
        self.assertEqual(result["signals"][2]["tone"], "unknown")
        self.assertIn("additional security check", result["rating"]["summary"])

    def test_legacy_reports_do_not_claim_unperformed_form_and_cookie_checks_passed(self):
        report = complete_report()
        report["findings"] = [item for item in report["findings"] if item["id"] not in {"password_forms", "cookie_flags"}]
        result = dashboard(report)
        self.assertEqual(result["rating"]["tone"], "green")
        self.assertEqual(result["signals"][2]["tone"], "unknown")
        self.assertEqual(result["signals"][2]["finding_ids"], ["http_resources"])
        self.assertIn("saved report", result["signals"][2]["detail"])

    def test_presence_credit_is_observed_and_does_not_claim_policy_strength(self):
        report = complete_report()
        get_finding(report, "csp").update(status="info", evidence={"header": "default-src *"})
        get_finding(report, "framing").update(status="info", evidence={"x_frame_options": "SAMEORIGIN"})
        result = dashboard(report)
        self.assertEqual(result["signals"][1]["tone"], "green")
        self.assertIn("Policy strength was not tested", result["signals"][1]["detail"])
        get_finding(report, "csp")["evidence"] = {"header": ""}
        self.assertEqual(dashboard(report)["signals"][1]["tone"], "unknown")

    def test_priorities_are_three_security_findings_and_put_observed_issues_before_unknown(self):
        report = complete_report()
        for key in ("hsts", "nosniff", "framing", "csp"):
            get_finding(report, key).update(status="attention", recommendation="Review this configuration.")
        get_finding(report, "tls")["status"] = "unknown"
        report["findings"].extend([
            {"id": "title", "status": "attention", "category": "Quality"},
            {"id": "rdap", "status": "unknown", "category": "Domain"},
            {"id": "image_alt", "status": "attention", "category": "Quality"},
        ])
        result = dashboard(report)
        self.assertEqual([item["finding_id"] for item in result["priorities"]], ["csp", "framing", "hsts"])
        self.assertTrue(all(item["next_step"] == "Review this configuration." for item in result["priorities"]))
        self.assertEqual(result["security_counts"], {"attention": 4, "unknown": 1, "passed": 3})

    def test_enrich_recalculates_dashboard_without_mutation_or_trusting_stored_rating(self):
        report = complete_report()
        report["dashboard"] = {"rating": {"tone": "red", "summary": "invented"}}
        original = deepcopy(report)
        result = enrich(report)
        self.assertEqual(report, original)
        self.assertEqual(result["dashboard"]["rating"]["tone"], "green")
        self.assertEqual(result, enrich(report))
        self.assertEqual(result["assessment"], assess(report))

    def test_duplicate_ids_and_malformed_extra_evidence_are_unknown(self):
        report = complete_report()
        report["findings"].append(deepcopy(get_finding(report, "tls")))
        get_finding(report, "cookie_flags")["evidence"] = {"limited": False, "malformed_count": 1}
        result = dashboard(report)
        self.assertEqual(result["rating"]["tone"], "unknown")
        self.assertEqual(result["signals"][0]["tone"], "unknown")
        self.assertEqual(result["signals"][2]["tone"], "unknown")
        self.assertEqual(result["security_counts"]["unknown"], 2)


if __name__ == "__main__":
    unittest.main()
