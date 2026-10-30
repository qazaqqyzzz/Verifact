"""Developer review totals must agree with current, relevant community warnings."""

from copy import deepcopy
from datetime import timedelta
import unittest
from unittest.mock import patch

from tests.test_visitor_assessment import NOW, report_fixture
from verifact.assessment import assess
from verifact.brief import build_brief
from verifact.scanner import community_blocked_report
from verifact import threat_feed as feed


class CommunityBriefTests(unittest.TestCase):
    def setUp(self):
        self.cache = feed.FeedCache()
        clock_patch = patch("verifact.threat_feed._now", return_value=NOW)
        self.clock = clock_patch.start()
        cache_patch = patch("verifact.threat_feed._CACHE", self.cache)
        cache_patch.start()
        self.addCleanup(clock_patch.stop)
        self.addCleanup(cache_patch.stop)

    def listed(self, host="example.com"):
        snapshot = feed.FeedSnapshot(frozenset({host}), NOW, NOW + timedelta(minutes=5))
        return feed.match_hosts([host], snapshot, NOW)

    def test_current_listing_is_red_priority_without_changing_core_counts_or_score(self):
        report = report_fixture()
        before_counts = build_brief(report)["counts"]
        before_score = assess(report)
        report["community_reputation"] = self.listed()
        original = deepcopy(report)
        result = build_brief(report)
        review = result["reviews"][0]
        self.assertEqual((review["id"], review["source"], review["tone"]), ("community_listed", "community", "red"))
        self.assertEqual(review["expires_at"], (NOW + timedelta(minutes=5)).isoformat())
        self.assertEqual(review["source_url"], feed.SOURCE_URL)
        self.assertEqual(result["counts"], before_counts)
        self.assertEqual(assess(report), before_score)
        self.assertEqual(result["total_urgent"], 1)
        self.assertEqual(report, original)

    def test_preflight_block_has_one_review_even_without_website_evidence(self):
        report = community_blocked_report("https://example.com/public", self.listed())
        result = build_brief(report)
        self.assertEqual((result["total_review"], result["total_urgent"]), (1, 1))
        self.assertEqual(result["all_reviews"][0]["source"], "community")
        self.assertEqual(result["counts"], {"met": 0, "review": 0, "unknown": 10, "total": 10, "urgent": 0})
        self.assertIsNone(assess(report)["value"])

    def test_stale_deleted_and_no_match_results_do_not_create_warning(self):
        report = report_fixture()
        self.assertFalse(any(item["source"] == "community" for item in build_brief(report)["all_reviews"]))
        report["community_reputation"] = self.listed()
        self.clock.return_value = NOW + timedelta(minutes=5)
        self.assertFalse(any(item["source"] == "community" for item in build_brief(report)["all_reviews"]))
        self.clock.return_value = NOW + timedelta(seconds=30)
        self.cache.snapshot = feed.FeedSnapshot(frozenset({"different.example.net"}), self.clock.return_value,
                                               self.clock.return_value + timedelta(minutes=5))
        self.assertFalse(any(item["source"] == "community" for item in build_brief(report)["all_reviews"]))

    def test_unrelated_or_malformed_saved_data_cannot_create_a_community_review(self):
        report = report_fixture()
        for value in (None, [], "listed", {"status": []}, self.listed("unrelated.example.net"),
                      {"status": "listed", "checked_hosts": [{}], "detail": "Guaranteed safe"}):
            with self.subTest(value=value):
                report["community_reputation"] = value
                result = build_brief(report)
                self.assertFalse(any(item["source"] == "community" for item in result["all_reviews"]))
                self.assertNotIn("Guaranteed safe", str(result))
        report.pop("community_reputation")
        self.assertFalse(any(item["source"] == "community" for item in build_brief(report)["all_reviews"]))


if __name__ == "__main__":
    unittest.main()
