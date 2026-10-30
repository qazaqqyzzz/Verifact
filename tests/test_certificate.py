"""Certificate countdown boundaries and faithful saved-report presentation."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch

from verifact.assessment import assess, enrich
from verifact.checks import certificate_expiry_presentation, transport_checks
from verifact.network import Fetch, Response
from verifact.reports import html_report, render, text_report
from verifact.scanner import demo_report


CHECKED_AT = datetime(2026, 10, 31, 12, 30, 45, tzinfo=timezone.utc)


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return CHECKED_AT.astimezone(tz) if tz else CHECKED_AT.replace(tzinfo=None)


class SnapshotClock(datetime):
    @classmethod
    def now(cls, tz=None):
        raise AssertionError("Saved certificate countdowns must not be recalculated")


def certificate_finding(report):
    return next(item for item in report["findings"] if item["id"] == "certificate_expiry")


def observed_expiry(not_after):
    tls = {"verified": True, "hostname": "example.com", "not_after": not_after}
    response = Response("https://example.com/", 200, {}, tls=tls)
    http = Fetch(response, [{"url": "http://example.com/", "status": 301},
                            {"url": response.url, "status": 200}])
    with patch("verifact.checks.datetime", FixedClock):
        findings = transport_checks(http, Fetch(response))
    return next(item for item in findings if item["id"] == "certificate_expiry")


def expiry_after(delta):
    return observed_expiry((CHECKED_AT + delta).strftime("%b %d %H:%M:%S %Y GMT"))


def legacy_report():
    report = demo_report()
    report["created_at"] = "2020-01-01T09:07:00+00:00"
    item = certificate_finding(report)
    item.update(status="pass", evidence={"days_remaining": 82,
                                         "expires": "Mar 23 09:07:00 2020 GMT"},
                explanation="A certificate expiring within 14 days is a renewal reminder. Automatic renewal may already be configured.",
                recommendation="")
    item.pop("presentation", None)
    return report


class CertificateBoundaryTests(unittest.TestCase):
    def test_exactly_fourteen_days_passes_outside_reminder_window(self):
        item = expiry_after(timedelta(days=14))
        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["evidence"]["days_remaining"], 14)
        self.assertIn("14 full days remained", item["explanation"])
        self.assertIn("outside", item["explanation"])
        self.assertEqual(item["recommendation"], "")

    def test_one_second_under_fourteen_days_needs_renewal_review(self):
        item = expiry_after(timedelta(days=14, seconds=-1))
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["days_remaining"], 13)
        self.assertIn("13 full days remained", item["explanation"])
        self.assertIn("inside", item["explanation"])
        self.assertTrue(item["recommendation"])

    def test_less_than_twenty_four_hours_is_not_presented_as_expired(self):
        item = expiry_after(timedelta(hours=23, minutes=59, seconds=59))
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["days_remaining"], 0)
        presentation = certificate_expiry_presentation(item)
        self.assertEqual(presentation["metrics"][0]["value"], "<1 day")
        self.assertIn("Less than 24 hours remained", presentation["explanation"])
        self.assertNotIn("already passed", presentation["explanation"])
        self.assertNotIn("Expired", presentation["metrics"][0]["value"])

    def test_expired_snapshot_does_not_claim_rounded_days_since_expiry(self):
        item = expiry_after(timedelta(seconds=-1))
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["days_remaining"], -1)
        presentation = certificate_expiry_presentation(item)
        self.assertEqual(presentation["metrics"][0]["value"], "Expired")
        self.assertIn("already passed when this check ran", presentation["explanation"])
        self.assertNotIn("day ago", presentation["explanation"])
        self.assertTrue(presentation["recommendation"])

    def test_unparseable_expiry_is_unknown_instead_of_zero_days(self):
        for expires in (None, "", "not a certificate date", "Feb 31 09:07:00 2020 GMT"):
            with self.subTest(expires=expires):
                item = observed_expiry(expires)
                self.assertEqual(item["status"], "unknown")
                self.assertIsNone(item["evidence"]["days_remaining"])
                self.assertEqual(item["evidence"]["expires"], expires)
                presentation = certificate_expiry_presentation(item)
                self.assertEqual(presentation["metrics"][0]["value"], "Unknown")
                self.assertEqual(presentation["metrics"][1]["value"], "Not recorded")
                self.assertEqual(presentation["recommendation"], "")


class CertificateSnapshotTests(unittest.TestCase):
    def test_unknown_or_invalid_countdowns_never_become_zero_or_one_day(self):
        cases = [("unknown", 82), ("unknown", 0), ("pass", True), ("attention", False),
                 ("pass", "82"), ("pass", None), ("attention", 0.5)]
        for status, days in cases:
            with self.subTest(status=status, days=days):
                item = {"status": status, "evidence": {"days_remaining": days}}
                presentation = certificate_expiry_presentation(item)
                self.assertEqual(presentation["metrics"][0]["value"], "Unknown")
                self.assertIn("could not be established", presentation["explanation"])
                self.assertEqual(presentation["recommendation"], "")

    def test_saved_status_disagreement_requests_recheck_without_rewriting_evidence(self):
        for status, days in (("pass", 3), ("attention", 82)):
            with self.subTest(status=status, days=days):
                item = {"status": status, "evidence": {"days_remaining": days}}
                original = deepcopy(item)
                presentation = certificate_expiry_presentation(item)
                self.assertIn("disagree", presentation["explanation"])
                self.assertIn("new check", presentation["recommendation"])
                self.assertEqual(item, original)

    def test_legacy_eighty_two_days_stays_a_snapshot_with_friendly_utc_date(self):
        report = legacy_report()
        original = deepcopy(report)
        expected_score = assess(report)
        with patch("verifact.checks.datetime", SnapshotClock):
            updated = enrich(report)
        item = certificate_finding(updated)
        self.assertEqual(item["evidence"], certificate_finding(original)["evidence"])
        self.assertEqual(item["status"], "pass")
        self.assertEqual(updated["assessment"], expected_score)
        self.assertIn("82 full days remained", item["explanation"])
        self.assertIn("outside", item["explanation"])
        self.assertEqual(item["recommendation"], "")
        metrics = item["presentation"]["metrics"]
        self.assertEqual(metrics[0]["value"], "82")
        self.assertIn("when checked", metrics[0]["label"])
        self.assertEqual(metrics[1]["value"], "23 Mar 2020")
        self.assertIn("09:07 UTC", metrics[1]["label"])
        self.assertEqual(report, original)
        item["evidence"]["days_remaining"] = 1
        metrics[0]["value"] = "1"
        self.assertEqual(report, original)

    def test_text_and_html_exports_explain_actual_days_and_json_keeps_raw_evidence(self):
        report = legacy_report()
        original = deepcopy(report)
        with patch("verifact.checks.datetime", SnapshotClock):
            plain = text_report(report)
            markup = html_report(report)
            exported = json.loads(render(report, "json"))
        for output in (plain, markup):
            self.assertIn("82 days remained when checked", output)
            self.assertIn("23 Mar 2020", output)
            self.assertIn("09:07 UTC", output)
            self.assertNotIn("A certificate expiring within 14 days is a renewal reminder", output)
        self.assertIn("Days remaining when checked: 82", plain)
        self.assertIn("<strong>82</strong>", markup)
        source = certificate_finding(original)
        result = certificate_finding(exported)
        self.assertEqual(result["evidence"], source["evidence"])
        self.assertEqual(result["status"], source["status"])
        self.assertEqual(result["presentation"]["metrics"][0]["value"], "82")
        self.assertEqual(exported["assessment"], assess(original))
        self.assertEqual(report, original)


if __name__ == "__main__":
    unittest.main()
