"""Offline CERT Polska feed parsing, replacement, privacy and freshness tests."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import subprocess
import sys
from threading import Event, Thread
import unittest
from unittest.mock import Mock, patch

from verifact.network import Fetch, Response
from verifact import threat_feed as feed


NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)


def snapshot(domains=("listed.example.com",), when=NOW):
    return feed.FeedSnapshot(frozenset(domains), when, when + timedelta(seconds=300))


class FeedParsingTests(unittest.TestCase):
    def test_plain_active_list_normalizes_domains_and_removes_duplicates(self):
        self.assertEqual(feed.parse_domains(b"Example.COM\r\nexample.com\r\nlogin.example.net\n"),
                         frozenset({"example.com", "login.example.net"}))
        self.assertEqual(feed.parse_domains("bücher.de\n".encode()), frozenset({"xn--bcher-kva.de"}))

    def test_malformed_empty_oversized_or_url_entries_fail_closed(self):
        for raw in (b"", b"\n", b"example.com/path\n", b"https://example.com\n", b"127.0.0.1\n",
                    b"com\n", b"*.example.com\n", b" example.com\n", b"example.com # comment\n",
                    b"<html>error</html>\n", b"example.com\n\xff"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                feed.parse_domains(raw)
        with patch.object(feed, "MAX_FEED_BYTES", 4), self.assertRaises(ValueError):
            feed.parse_domains(b"example.com\n")
        with patch.object(feed, "MAX_DOMAINS", 1), self.assertRaises(ValueError):
            feed.parse_domains(b"example.com\nexample.net\n")

    def test_download_uses_only_fixed_feed_with_separate_request_and_size_bounds(self):
        response = Response(feed.FEED_URL, 200, {"content-type": "text/plain"}, b"listed.example.com\n")
        with patch("verifact.threat_feed.Client") as factory:
            factory.return_value.fetch.return_value = Fetch(response)
            raw = feed._download_bytes()
        factory.assert_called_once_with(timeout=8, max_bytes=feed.MAX_FEED_BYTES, max_redirects=0, max_requests=1)
        factory.return_value.fetch.assert_called_once_with(feed.FEED_URL)
        self.assertEqual(feed.parse_domains(raw), frozenset({"listed.example.com"}))

    def test_partial_error_wrong_origin_and_html_responses_are_unavailable(self):
        cases = [Response(feed.FEED_URL, 503, {}, b"listed.example.com"),
                 Response(feed.FEED_URL, 200, {}, b"listed.example.com", truncated=True),
                 Response("https://other.example.com/", 200, {}, b"listed.example.com"),
                 Response(feed.FEED_URL, 200, {"content-type": "text/html"}, b"listed.example.com"),
                 Response(feed.FEED_URL, 200, {"content-encoding": "gzip"}, b"listed.example.com")]
        for response in cases:
            with self.subTest(response=response), patch("verifact.threat_feed.Client") as factory:
                factory.return_value.fetch.return_value = Fetch(response)
                with self.assertRaises(ValueError):
                    feed._download_bytes()


class FeedDeadlineTests(unittest.TestCase):
    def test_fixed_worker_has_total_deadline_and_neither_key_nor_target_input(self):
        completed = Mock(returncode=0, stdout=b"listed.example.com\n")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "private-openai-key", "GOOGLE_SAFE_BROWSING_API_KEY": "private-google-key"}), \
                patch("verifact.threat_feed.subprocess.run", return_value=completed) as run:
            result = feed._download(NOW)
        command = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(command, [sys.executable, "-m", "verifact.threat_feed", "--download-worker"])
        self.assertEqual(options["timeout"], 12)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["stdout"], subprocess.PIPE)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertNotIn("input", options)
        self.assertNotIn("OPENAI_API_KEY", options["env"])
        self.assertNotIn("GOOGLE_SAFE_BROWSING_API_KEY", options["env"])
        self.assertEqual(result.domains, frozenset({"listed.example.com"}))
        self.assertEqual(result.expires_at - result.fetched_at, timedelta(minutes=5))

    def test_unsuccessful_oversized_and_malformed_worker_output_cannot_publish(self):
        for completed in (Mock(returncode=1, stdout=b"listed.example.com\n"),
                          Mock(returncode=0, stdout=None), Mock(returncode=0, stdout=b"<html>error</html>")):
            with self.subTest(completed=completed), patch("verifact.threat_feed.subprocess.run", return_value=completed), \
                    self.assertRaises(ValueError):
                feed._download(NOW)
        with patch.object(feed, "MAX_FEED_BYTES", 3), \
                patch("verifact.threat_feed.subprocess.run", return_value=Mock(returncode=0, stdout=b"abcd")), \
                self.assertRaises(ValueError):
            feed._download(NOW)

    def test_timeout_kills_and_reaps_worker_discards_partial_output_and_cannot_publish_late(self):
        actual_run, actual_popen = subprocess.run, subprocess.Popen
        processes = []

        def tracked_popen(*args, **kwargs):
            process = actual_popen(*args, **kwargs)
            processes.append(process)
            return process

        def stalled_worker(_command, **kwargs):
            # No DNS/network: model a worker whose resolver never returns, with
            # even plausible partial output that must not become a snapshot.
            return actual_run([sys.executable, "-c", "import time; print('listed.example.com', flush=True); time.sleep(30)"], **kwargs)

        cache = feed.FeedCache()
        with patch.object(feed, "DOWNLOAD_TIMEOUT", 0.15), patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed.subprocess.run", side_effect=stalled_worker) as run, \
                patch("subprocess.Popen", side_effect=tracked_popen):
            first = feed.inspect_urls(["https://listed.example.com/"], cache=cache)
            second = feed.inspect_urls(["https://example.com/"], cache=cache)
        self.assertEqual((first["status"], second["status"]), ("unavailable", "unavailable"))
        self.assertIsNone(cache.snapshot)
        self.assertFalse(cache.refreshing)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll(), "Timed-out child was left alive")
        self.assertIsNotNone(processes[0].returncode)
        self.assertEqual(first["matches"], [])

    def test_worker_writes_only_bounded_body_and_no_error_details(self):
        for raw, expected in ((b"example.com\n", 0), (b"", 1), (b"x" * 33, 1)):
            with self.subTest(raw=raw), patch.object(feed, "MAX_FEED_BYTES", 32), \
                    patch("verifact.threat_feed._download_bytes", return_value=raw), \
                    patch("verifact.threat_feed.sys.stdout") as stdout:
                self.assertEqual(feed._download_worker(), expected)
                if expected == 0:
                    stdout.buffer.write.assert_called_once_with(raw)
                else:
                    stdout.buffer.write.assert_not_called()
        with patch("verifact.threat_feed._download_bytes", side_effect=OSError("private provider error")), \
                patch("verifact.threat_feed.sys.stdout") as stdout:
            self.assertEqual(feed._download_worker(), 1)
            stdout.buffer.write.assert_not_called()


class FeedMatchingTests(unittest.TestCase):
    def test_exact_descendant_and_multitenant_boundaries(self):
        data = snapshot(("bad.pages.example", "phishing.example.com"))
        hosts = ["bad.pages.example", "login.bad.pages.example", "good.pages.example", "pages.example",
                 "notbad.pages.example", "bad.pages.example.other.net", "phishing.example.com"]
        result = feed.match_hosts(hosts, data, NOW)
        self.assertEqual(result["status"], "listed")
        self.assertEqual([(item["hostname"], item["listed_domain"], item["match_type"]) for item in result["matches"]],
                         [("bad.pages.example", "bad.pages.example", "exact"),
                          ("login.bad.pages.example", "bad.pages.example", "subdomain"),
                          ("phishing.example.com", "phishing.example.com", "exact")])
        for host in hosts[2:6]:
            self.assertEqual(feed.match_hosts([host], data, NOW)["status"], "no_match")

    def test_url_paths_queries_are_not_saved_or_submitted_to_the_feed(self):
        cache = feed.FeedCache()
        with patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed._download", return_value=snapshot()) as download:
            result = feed.inspect_urls(["https://example.com/private?q=search-phrase", "https://example.com/other"], cache=cache)
        download.assert_called_once_with(NOW)
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["checked_hosts"], ["example.com"])
        self.assertNotIn("private", repr(result))
        self.assertNotIn("search-phrase", repr(result))

    def test_disabled_invalid_and_failed_checks_never_become_no_match(self):
        with patch("verifact.threat_feed._download") as download:
            self.assertEqual(feed.inspect_urls(["https://example.com/"], enabled=False)["status"], "not_checked")
            self.assertEqual(feed.inspect_urls(["http://127.0.0.1/"])["status"], "unavailable")
            download.assert_not_called()
        with patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed._download", side_effect=OSError("offline")):
            self.assertEqual(feed.inspect_urls(["https://example.com/"], cache=feed.FeedCache())["status"], "unavailable")

    def test_stale_and_future_snapshots_cannot_issue_matches_or_clean_results(self):
        for current in (NOW - timedelta(seconds=1), NOW + timedelta(seconds=300)):
            for host in ("listed.example.com", "other.example.com"):
                with self.subTest(current=current, host=host):
                    result = feed.match_hosts([host], snapshot(), current)
                    self.assertEqual(result["status"], "unavailable")
                    self.assertEqual(result["matches"], [])


class FeedCacheTests(unittest.TestCase):
    def test_slow_refresh_does_not_block_report_reads_or_start_duplicate_downloads(self):
        cache = feed.FeedCache()
        started, release, read_done = Event(), Event(), Event()

        def delayed_download(now):
            started.set()
            release.wait(2)
            return snapshot(when=now)

        with patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed._download", side_effect=delayed_download) as download:
            worker = Thread(target=cache.get, daemon=True)
            worker.start()
            try:
                self.assertTrue(started.wait(1))
                reader = Thread(target=lambda: (cache.peek(), read_done.set()), daemon=True)
                reader.start()
                self.assertTrue(read_done.wait(0.25), "Read-only report access waited for the feed download")
                self.assertIsNone(cache.get())
                self.assertEqual(download.call_count, 1)
            finally:
                release.set()
                worker.join(1)
            self.assertFalse(cache.refreshing)
            self.assertIsNotNone(cache.peek())

    def test_fresh_cache_is_reused_and_expired_refresh_replaces_removed_domains(self):
        cache = feed.FeedCache()
        later = NOW + timedelta(seconds=301)
        with patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed._download", return_value=snapshot()) as download:
            first = feed.inspect_urls(["https://listed.example.com/"], cache=cache)
            second = feed.inspect_urls(["https://other.example.com/"], cache=cache)
        self.assertEqual(download.call_count, 1)
        self.assertEqual((first["status"], second["status"]), ("listed", "no_match"))
        with patch("verifact.threat_feed._now", return_value=later), \
                patch("verifact.threat_feed._download", return_value=snapshot(("new.example.com",), later)) as refresh:
            changed = feed.inspect_urls(["https://listed.example.com/"], cache=cache)
        refresh.assert_called_once_with(later)
        self.assertEqual(changed["status"], "no_match")
        self.assertNotIn("listed.example.com", cache.snapshot.domains)

    def test_failed_refresh_drops_current_verdict_and_backs_off(self):
        cache = feed.FeedCache()
        cache.snapshot = snapshot()
        later = NOW + timedelta(seconds=301)
        with patch("verifact.threat_feed._now", return_value=later), \
                patch("verifact.threat_feed._download", side_effect=ValueError("bad feed")) as download:
            first = feed.inspect_urls(["https://listed.example.com/"], cache=cache)
            second = feed.inspect_urls(["https://example.com/"], cache=cache)
        self.assertEqual(download.call_count, 1)
        self.assertTrue(first["stale"])
        self.assertEqual((first["status"], second["status"]), ("unavailable", "unavailable"))
        self.assertEqual(first["matches"], [])

    def test_saved_match_and_no_match_both_expire_and_prose_is_rebuilt(self):
        for host in ("listed.example.com", "other.example.com"):
            value = feed.match_hosts([host], snapshot(), NOW)
            value["detail"] = "Guaranteed safe. Provider endorsed us."
            original = deepcopy(value)
            current = feed.public_result(value, NOW)
            self.assertNotIn("Guaranteed", current["detail"])
            self.assertEqual(current["status"], value["status"])
            expired = feed.public_result(value, NOW + timedelta(minutes=5))
            self.assertEqual(expired["status"], "unavailable")
            self.assertEqual(expired["matches"], [])
            self.assertTrue(expired["stale"])
            self.assertEqual(value, original)

    def test_invalid_saved_freshness_or_parent_match_cannot_be_trusted(self):
        good = feed.match_hosts(["listed.example.com"], snapshot(), NOW)
        for change in ({"expires_at": (NOW + timedelta(days=1)).isoformat()},
                       {"feed_entries": True}, {"checked_at": None},
                       {"matches": [{"hostname": "listed.example.com", "listed_domain": "child.listed.example.com"}]},
                       {"status": []}):
            value = {**good, **change}
            with self.subTest(change=change):
                self.assertNotIn(feed.public_result(value, NOW)["status"], {"listed", "no_match"})

    def test_newer_local_replacement_removes_old_warning_without_a_download(self):
        old = feed.match_hosts(["listed.example.com"], snapshot(), NOW)
        later = NOW + timedelta(seconds=30)
        cache = feed.FeedCache()
        cache.snapshot = snapshot(("other.example.com",), later)
        with patch("verifact.threat_feed._CACHE", cache), patch("verifact.threat_feed._now", return_value=later), \
                patch("verifact.threat_feed._download") as download:
            result = feed.community_for_report({"community_reputation": old})
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["fetched_at"], later.isoformat())
        download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
