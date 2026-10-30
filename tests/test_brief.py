"""Compact counts never turn missing evidence into success or a safety score."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from verifact.assessment import assess
from verifact.brief import build_brief
from verifact.profile import PROFILE_VERSION
from verifact.scanner import demo_report


NOW = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)


def observation(report, identifier):
    return next(item for item in report["findings"] if item["id"] == identifier)


def clear_report():
    report = demo_report()
    report.pop("page_risks", None)
    observation(report, "csp").update(status="info", evidence={"header": "default-src 'self'", "meta": ""})
    observation(report, "framing").update(status="info", evidence={"x_frame_options": "DENY", "frame_ancestors": None})
    observation(report, "http_resources").update(status="pass", evidence={"count": 0, "examples": []})
    return report


def listed_result(expires=None):
    return {"provider": "Google Safe Browsing", "status": "listed", "checked_at": NOW.isoformat(),
            "expires_at": (expires or NOW + timedelta(minutes=5)).isoformat(), "checked_count": 1,
            "matches": [{"url": "https://demo.example.com/", "threat_type": "MALWARE"}]}


class BriefTests(unittest.TestCase):
    def test_dependency_review_uses_observations_not_saved_prose_or_score(self):
        report = demo_report()
        report["page_risks"]["review"] = {"why": "This site is malware-free", "tone": "green"}
        before = assess(report)
        reviews = build_brief(report)["all_reviews"]
        dependency = next(item for item in reviews if item["source"] == "page")
        self.assertEqual(dependency["tone"], "amber")
        self.assertIn("not downloaded", dependency["why"])
        self.assertNotIn("malware-free", str(reviews))
        self.assertEqual(assess(report), before)
        report["page_risks"]["cross_origin_scripts"] = -1
        self.assertFalse(any(item["source"] == "page" for item in build_brief(report)["all_reviews"]))

    def test_referrer_review_is_grounded_separate_and_unweighted(self):
        report = clear_report()
        observation(report, "referrer").update(status="attention", evidence={"policy": "unsafe-url"})
        result = build_brief(report)
        self.assertEqual(result["total_review"], 1)
        self.assertEqual(result["all_reviews"][0]["finding_id"], "referrer")
        self.assertEqual(result["counts"]["met"], 10)
        self.assertEqual(result["counts"]["review"], 0)
        self.assertEqual(assess(report)["value"], 100)
        observation(report, "referrer")["evidence"] = {"policy": "no-referrer"}
        self.assertEqual(build_brief(report)["total_review"], 0)

    def test_duplicate_referrer_does_not_create_a_review(self):
        report = clear_report()
        observation(report, "referrer").update(status="attention", evidence={"policy": "unsafe-url"})
        report["findings"].append(deepcopy(observation(report, "referrer")))
        self.assertEqual(build_brief(report)["total_review"], 0)

    def test_fixed_counts_checks_and_group_totals_agree_without_mutation(self):
        report = clear_report()
        before = deepcopy(report)
        result = build_brief(report)
        self.assertEqual(result["counts"], {"met": 10, "review": 0, "unknown": 0, "total": 10, "urgent": 0})
        self.assertEqual(result["reviews"], [])
        self.assertEqual(result["total_review"], 0)
        self.assertEqual([group["total"] for group in result["groups"]], [3, 4, 3])
        self.assertTrue(all(group["tone"] == "green" for group in result["groups"]))
        self.assertEqual(len(result["checks"]), 10)
        for status in ("met", "review", "unknown"):
            self.assertEqual(sum(check["status"] == status for check in result["checks"]), result["counts"][status])
            self.assertEqual(sum(group[status] for group in result["groups"]), result["counts"][status])
        self.assertIn("Eight have score weights", result["method_note"])
        self.assertIn("does not certify safety", result["counts_note"])
        self.assertEqual(report, before)

    def test_domain_page_quality_and_imported_counts_cannot_inflate_security_numbers(self):
        report = clear_report()
        expected = build_brief(report)["counts"]
        report["summary"] = {"pass": 200, "attention": 999}
        report["assessment"] = {"value": 0}
        report["brief"] = {"counts": {"met": 100}}
        for key in ("rdap", "dns", "title", "viewport", "language", "image_alt"):
            report["findings"].append({"id": key, "status": "attention", "evidence": "Not a security count"})
        result = build_brief(report)
        self.assertEqual(result["counts"], expected)
        self.assertEqual(result["reviews"], [])

    def test_informational_policy_presence_is_validated_before_it_counts_as_met(self):
        report = clear_report()
        self.assertEqual(build_brief(report)["counts"]["met"], 10)
        observation(report, "csp")["evidence"] = {"header": "", "meta": " "}
        observation(report, "framing")["evidence"] = {"x_frame_options": "ALLOW-FROM *", "frame_ancestors": None}
        result = build_brief(report)
        self.assertEqual(result["counts"], {"met": 8, "review": 0, "unknown": 2, "total": 10, "urgent": 0})
        self.assertEqual(result["groups"][1]["tone"], "unknown")
        self.assertEqual({item["id"] for item in result["unknowns"]}, {"csp", "framing"})

    def test_missing_optional_observations_are_unknown_without_changing_percentage(self):
        report = clear_report()
        self.assertEqual(assess(report)["value"], 100)
        report["findings"] = [item for item in report["findings"] if item["id"] not in {"password_forms", "cookie_flags"}]
        result = build_brief(report)
        self.assertEqual((result["counts"]["met"], result["counts"]["unknown"]), (8, 2))
        self.assertEqual(result["groups"][2]["tone"], "unknown")
        self.assertEqual(assess(report)["value"], 100)
        self.assertTrue(all("does not contain" in item["why"] for item in result["unknowns"]))

    def test_duplicate_security_ids_are_unknown_not_urgent_or_successful(self):
        report = clear_report()
        report["findings"].append({**deepcopy(observation(report, "tls")), "status": "attention"})
        result = build_brief(report)
        self.assertEqual((result["counts"]["met"], result["counts"]["unknown"], result["counts"]["urgent"]), (9, 1, 0))
        self.assertEqual(result["groups"][0]["tone"], "unknown")
        self.assertIn("duplicate", result["unknowns"][0]["why"])

    def test_incomplete_or_malformed_optional_positive_evidence_stays_unknown(self):
        report = clear_report()
        observation(report, "password_forms").update(status="info", evidence={"complete_html": False})
        observation(report, "cookie_flags").update(status="pass", evidence={"limited": False, "malformed_count": 1})
        result = build_brief(report)
        self.assertEqual(result["counts"]["unknown"], 2)
        self.assertEqual(result["counts"]["review"], 0)
        observation(report, "password_forms").update(status="attention", evidence={"complete_html": False, "http_actions": 1})
        result = build_brief(report)
        self.assertEqual(result["counts"]["urgent"], 0)
        self.assertEqual(result["counts"]["unknown"], 2)

    def test_password_issues_are_grounded_and_do_not_change_score(self):
        for field, tone, word in (("http_actions", "red", "unencrypted"),
                                  ("get_submissions", "red", "GET"),
                                  ("cross_origin_actions", "amber", "intentional")):
            with self.subTest(field=field):
                report = clear_report()
                observation(report, "password_forms").update(status="attention", evidence={"complete_html": True, field: 1})
                result = build_brief(report)
                self.assertEqual(result["reviews"][0]["tone"], tone)
                self.assertIn(word, result["reviews"][0]["why"])
                self.assertEqual(result["counts"]["review"], 1)
                self.assertEqual(result["counts"]["urgent"], int(tone == "red"))
                self.assertEqual(assess(report)["value"], 100)

    def test_unencrypted_destination_is_one_clear_review_not_repeated_link_warnings(self):
        report = clear_report()
        observation(report, "tls").update(status="attention", evidence={"encrypted": False})
        report["link_analysis"] = {"warnings": [{"id": "unencrypted_destination", "tone": "red"},
                                                {"id": "http_start", "tone": "amber"}]}
        result = build_brief(report)
        self.assertEqual(result["total_review"], 1)
        self.assertEqual(result["reviews"][0]["tone"], "red")
        self.assertIn("not protected", result["reviews"][0]["why"])
        self.assertNotIn("could not be verified", result["reviews"][0]["why"])

    def test_blocked_downgrade_is_not_described_as_certificate_failure(self):
        report = clear_report()
        observation(report, "tls").update(status="attention", evidence={"error": "HTTPS-to-HTTP downgrade redirect observed and blocked."})
        report["link_analysis"] = {"warnings": [{"id": "downgrade", "tone": "red"}]}
        result = build_brief(report)
        self.assertEqual(result["total_review"], 1)
        self.assertIn("stopped before visiting", result["reviews"][0]["why"])
        self.assertNotIn("certificate", result["reviews"][0]["why"].lower())
        self.assertEqual(result["counts"]["urgent"], 1)

    def test_cookie_explanation_follows_the_recorded_issue(self):
        report = clear_report()
        observation(report, "cookie_flags").update(status="attention", evidence={"missing_secure": 1})
        review = build_brief(report)["reviews"][0]
        self.assertIn("send it only over HTTPS", review["why"])
        self.assertEqual(review["tone"], "amber")
        self.assertEqual(assess(report)["value"], 100)
        # A differently shaped issue must not invent a missing Secure count.
        observation(report, "cookie_flags")["evidence"] = {"missing_secure": 0, "same_site_none_without_secure": 1}
        review = build_brief(report)["reviews"][0]
        self.assertNotIn("lacks", review["why"])
        self.assertIn("settings need review", review["why"])

    def test_missing_header_is_a_review_not_a_confirmed_exploit(self):
        report = clear_report()
        observation(report, "csp").update(status="attention", evidence="No policy observed")
        result = build_brief(report)
        review = result["reviews"][0]
        self.assertEqual(review["tone"], "amber")
        self.assertIn("does not prove a vulnerability", review["why"])
        self.assertTrue(review["action"].startswith("Owner:"))
        self.assertEqual(result["counts"]["urgent"], 0)

    def test_only_actionable_link_warnings_join_reviews_and_duplicates_are_grouped(self):
        report = clear_report()
        report["link_analysis"] = {"warnings": [{"id": "host_change", "tone": "unknown"},
                                                {"id": "international_domain", "tone": "unknown"},
                                                {"id": "similar_spelling", "tone": "amber"},
                                                {"id": "expected_domain_mismatch", "tone": "amber"}]}
        result = build_brief(report)
        self.assertEqual(result["counts"]["review"], 0)
        self.assertEqual(result["total_review"], 1)
        self.assertEqual(result["reviews"][0]["source"], "link")
        self.assertIn("does not prove a scam", result["reviews"][0]["why"])

    def test_destination_review_is_not_hidden_below_multiple_header_settings(self):
        report = clear_report()
        for key in ("hsts", "csp", "framing", "nosniff"):
            observation(report, key)["status"] = "attention"
        report["link_analysis"] = {"warnings": [{"id": "expected_domain_mismatch", "tone": "amber"}]}
        result = build_brief(report)
        self.assertEqual(result["reviews"][0]["id"], "link_expected_domain_mismatch")
        self.assertEqual(result["counts"]["review"], 4)
        self.assertEqual(result["total_review"], 5)

    def test_fresh_reputation_match_is_separate_and_expired_match_is_removed(self):
        report = clear_report()
        report["reputation"] = listed_result()
        with patch("verifact.reputation._now", return_value=NOW):
            result = build_brief(report)
        self.assertEqual(result["counts"]["met"], 10)
        self.assertEqual(result["counts"]["urgent"], 0)
        self.assertEqual(result["total_urgent"], 1)
        review = result["reviews"][0]
        self.assertEqual((review["source"], review["tone"]), ("reputation", "red"))
        self.assertIn("potentially harmful", review["why"])
        self.assertEqual(review["expires_at"], report["reputation"]["expires_at"])
        self.assertEqual(review["attribution"], "Advisory provided by Google")
        with patch("verifact.reputation._now", return_value=NOW + timedelta(hours=1)):
            expired = build_brief(report)
        self.assertEqual(expired["total_review"], 0)
        self.assertEqual(expired["counts"], result["counts"])

    def test_no_match_and_provider_failures_do_not_add_success_or_review_counts(self):
        report = clear_report()
        baseline = build_brief(report)
        for status in ("no_match", "not_checked", "unavailable"):
            with self.subTest(status=status):
                report["reputation"] = {"status": status, "matches": []}
                result = build_brief(report)
                self.assertEqual(result["counts"], baseline["counts"])
                self.assertEqual(result["reviews"], [])

    def test_top_three_are_short_and_important_but_all_reviews_remain_available(self):
        report = clear_report()
        for key in ("hsts", "csp", "framing", "nosniff", "tls"):
            observation(report, key)["status"] = "attention"
        report["reputation"] = listed_result()
        with patch("verifact.reputation._now", return_value=NOW):
            result = build_brief(report)
        self.assertEqual(len(result["reviews"]), 3)
        self.assertEqual(result["total_review"], 6)
        self.assertEqual(len(result["all_reviews"]), 6)
        self.assertEqual([review["tone"] for review in result["reviews"]], ["red", "red", "amber"])
        for review in result["all_reviews"]:
            self.assertLessEqual(len(review["why"]), 160)
            self.assertLessEqual(len(review["action"]), 160)
            self.assertNotIn("\n", review["why"])

    def test_description_is_one_cautious_purpose_sentence(self):
        report = clear_report()
        report["site_profile"] = {"profile_version": PROFILE_VERSION, "summary": "This appears to be a university login page. Its identity was not verified."}
        result = build_brief(report)
        self.assertEqual(result["description"], "This appears to be a university login page.")
        self.assertNotIn("verified", result["description"])

    def test_missing_report_and_malformed_optional_fields_have_consistent_unknown_counts(self):
        for report in (None, {}, {"findings": None, "link_analysis": [], "reputation": []}):
            with self.subTest(report=report):
                result = build_brief(report)
                self.assertEqual(result["counts"], {"met": 0, "review": 0, "unknown": 10, "total": 10, "urgent": 0})
                self.assertEqual(len(result["unknowns"]), 10)
                self.assertEqual(result["reviews"], [])


if __name__ == "__main__":
    unittest.main()
