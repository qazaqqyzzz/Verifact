"""Cross-layer freshness and score-isolation checks, with offline provider data."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch

from verifact import reputation
from verifact.scanner import demo_report
from verifact.server import AppState


KEY = "fake-key-for-offline-integration-review"
URL = "https://example.com/public?campaign=one"
NOW = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)


def report_fixture():
    report = demo_report()
    report.update(demo=False, domain="example.com", target_url=URL)
    report["response"]["url"] = URL
    report["link_analysis"] = {"input_url": URL, "final_url": URL,
                               "redirects": [{"url": URL, "status": 200}]}
    return report


def threat_response():
    return {"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
                         "threatEntryType": "URL", "threat": {"url": URL}, "cacheDuration": "300s"}]}


class ReputationIntegrationReviewTests(unittest.TestCase):
    def setUp(self):
        reputation._CACHE.clear()
        self.state = AppState()
        self.state.reputation_key = KEY
        self.identifier = self.state._new_job("example.com", report_fixture())

    def tearDown(self):
        reputation._CACHE.clear()

    def test_listing_does_not_change_configuration_or_expose_the_api_key(self):
        before = self.state.job(self.identifier)["report"]
        with patch("verifact.server.threading.Thread"):
            self.state.start_reputation(self.identifier, consent=True)
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value=threat_response()):
            self.state._reputation_worker(self.identifier, [URL], KEY)
            after = self.state.job(self.identifier)
        self.assertEqual(after["report"]["reputation"]["status"], "listed")
        for field in ("assessment", "dashboard", "findings", "summary"):
            self.assertEqual(after["report"][field], before[field])
        self.assertNotIn(KEY, json.dumps(after))
        self.assertNotIn(KEY, json.dumps(self.state.list_jobs()))
        self.assertNotIn(KEY, json.dumps(self.state.config()))

    def test_report_reads_expire_the_warning_without_overwriting_recorded_evidence(self):
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value=threat_response()):
            self.state._reputation_worker(self.identifier, [URL], KEY)
        stored = deepcopy(self.state.jobs[self.identifier]["report"]["reputation"])
        with patch.object(reputation, "_now", return_value=NOW + timedelta(minutes=6)), patch("verifact.server.inspect_urls") as lookup:
            displayed = self.state.job(self.identifier)["report"]["reputation"]
        self.assertEqual(displayed["status"], "unavailable")
        self.assertTrue(displayed["stale"])
        self.assertEqual(displayed["matches"], [])
        self.assertEqual(self.state.jobs[self.identifier]["report"]["reputation"], stored)
        lookup.assert_not_called()

    def test_same_link_across_reports_uses_unexpired_positive_cache(self):
        other = self.state._new_job("example.com", report_fixture())
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value=threat_response()) as post:
            self.state._reputation_worker(self.identifier, [URL], KEY)
            self.state._reputation_worker(other, [URL], KEY)
            shown = self.state.job(other)["report"]["reputation"]
        post.assert_called_once()
        self.assertEqual(shown["status"], "listed")
        self.assertEqual(shown["cached_count"], 1)
        self.assertEqual(shown["expires_at"], (NOW + timedelta(minutes=5)).isoformat())


if __name__ == "__main__":
    unittest.main()
