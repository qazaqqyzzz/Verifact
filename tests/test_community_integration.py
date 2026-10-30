"""Free community checking around the existing scanner and local web worker."""

from datetime import timedelta
import subprocess
import unittest
from unittest.mock import patch

from websignal.network import Client, Response
from websignal.scanner import scan
from websignal.server import AppState, WebError
from websignal import threat_feed as feed
from tests.test_visitor_assessment import NOW, report_fixture


class CommunityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.cache = feed.FeedCache()
        self.clock_patch = patch("websignal.threat_feed._now", return_value=NOW)
        self.cache_patch = patch("websignal.threat_feed._CACHE", self.cache)
        self.clock = self.clock_patch.start()
        self.cache_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.addCleanup(self.cache_patch.stop)

    def snapshot(self, *domains):
        return feed.FeedSnapshot(frozenset(domains or ("unrelated.example.net",)), NOW, NOW + timedelta(minutes=5))

    def test_cli_preflight_match_does_not_contact_target_or_rdap(self):
        with patch("websignal.threat_feed._download", return_value=self.snapshot("listed.example.com")) as download, \
                patch("websignal.scanner.Client") as client:
            report = scan("https://listed.example.com/public", include_rdap=True, community_check=True)
        download.assert_called_once_with(NOW)
        client.assert_not_called()
        self.assertEqual(report["community_reputation"]["status"], "listed")
        self.assertEqual(report["visitor_assessment"]["status"], "warning")
        self.assertTrue(report["inspection_skipped"])
        self.assertEqual(report["requests"], 0)
        self.assertIsNone(report["response"])
        self.assertIsNone(report["assessment"]["value"])
        self.assertFalse(report["link_analysis"]["completed"])
        self.assertEqual(report["target_url"], "https://listed.example.com/public")

    def test_observed_redirect_destinations_are_matched_without_another_download(self):
        target, final = "https://example.com/start", "https://listed.example.net/"
        requests = []

        def response(_client, url):
            requests.append(url)
            headers = {"content-type": "text/html"}
            if url == target:
                headers["location"] = final
                return Response(url, 302, headers)
            tls = {"verified": True, "hostname": url.split("/")[2], "not_after": "Dec 31 23:59:59 2099 GMT"} if url.startswith("https:") else {}
            return Response(url, 200, headers, b"<title>Page</title>", tls=tls)

        with patch("websignal.threat_feed._download", return_value=self.snapshot("listed.example.net")) as download, \
                patch.object(Client, "request", response):
            report = scan(target, community_check=True)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(report["community_reputation"]["checked_hosts"], ["example.com", "listed.example.net"])
        self.assertEqual(report["visitor_assessment"]["status"], "warning")
        self.assertEqual(report["response"]["url"], final)
        self.assertNotIn("inspection_skipped", report)
        self.assertIn(final, requests)  # Only the initial submitted host was checked before contact.

    def test_web_default_is_enabled_and_a_match_skips_the_scanner_process(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as thread:
            job = state.start_scan("https://example.com/", rdap=False)
            args = thread.call_args.kwargs["args"]
        self.assertTrue(args[4])
        with patch("websignal.threat_feed._download", return_value=self.snapshot("example.com")), \
                patch("websignal.server.run_scan") as scanner:
            state._scan_worker(*args)
        scanner.assert_not_called()
        result = state.job(job["id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["report"]["visitor_assessment"]["status"], "warning")
        self.assertFalse(state.scan_busy)
        self.assertTrue(state.config()["community_default"])

    def test_web_feed_failure_is_nonfatal_and_does_not_retry_immediately(self):
        state = AppState()
        report = report_fixture()
        with patch("websignal.server.threading.Thread") as thread:
            job = state.start_scan("https://example.com/", rdap=False)
            args = thread.call_args.kwargs["args"]
        with patch("websignal.threat_feed._download", side_effect=OSError("offline")) as download, \
                patch("websignal.server.run_scan", return_value=report) as scanner:
            state._scan_worker(*args)
        self.assertEqual(download.call_count, 1)
        scanner.assert_called_once_with("https://example.com/", False)
        result = state.job(job["id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["report"]["community_reputation"]["status"], "unavailable")
        self.assertEqual(result["report"]["visitor_assessment"]["status"], "unknown")
        self.assertEqual(result["report"]["assessment"], report["assessment"])

    def test_disabling_community_check_performs_no_feed_request(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as thread:
            job = state.start_scan("https://example.com/", rdap=False, community_check=False)
            args = thread.call_args.kwargs["args"]
        self.assertFalse(args[4])
        with patch("websignal.threat_feed._download") as download, \
                patch("websignal.server.run_scan", return_value=report_fixture()):
            state._scan_worker(*args)
        download.assert_not_called()
        self.assertEqual(state.job(job["id"])["report"]["community_reputation"]["status"], "not_checked")
        for value in (None, 0, 1, "true", [], {}):
            with self.subTest(value=value), self.assertRaises(WebError):
                state.start_scan("https://example.com/", community_check=value)

    def test_feed_process_timeout_is_nonfatal_to_the_actual_website_check(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as thread:
            job = state.start_scan("https://example.com/", rdap=False)
            args = thread.call_args.kwargs["args"]
        with patch("websignal.threat_feed.subprocess.run", side_effect=subprocess.TimeoutExpired("fixed-feed-worker", 12)) as download, \
                patch("websignal.server.run_scan", return_value=report_fixture()) as scanner:
            state._scan_worker(*args)
        self.assertEqual(download.call_count, 1)
        scanner.assert_called_once_with("https://example.com/", False)
        result = state.job(job["id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["report"]["community_reputation"]["status"], "unavailable")
        self.assertIsNone(self.cache.snapshot)
        self.assertFalse(self.cache.refreshing)

    def test_report_read_expires_green_without_refetching_or_mutating_saved_report(self):
        state = AppState()
        report = report_fixture()
        identifier = state._new_job("example.com", report)
        initial = state.job(identifier)
        self.assertEqual(initial["report"]["visitor_assessment"]["status"], "no_warning")
        self.clock.return_value = NOW + timedelta(minutes=5)
        with patch("websignal.threat_feed._download") as download:
            updated = state.job(identifier)
        download.assert_not_called()
        self.assertEqual(updated["report"]["visitor_assessment"]["status"], "unknown")
        self.assertEqual(updated["report"]["community_reputation"]["status"], "unavailable")
        self.assertEqual(state.jobs[identifier]["report"]["community_reputation"]["status"], "no_match")


if __name__ == "__main__":
    unittest.main()
