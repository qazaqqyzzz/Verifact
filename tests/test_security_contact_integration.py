"""Opt-in public security contact plumbing, using only offline responses."""

from datetime import timedelta
import io
import json
import unittest
from unittest.mock import Mock, patch

from verifact.cli import main
from verifact.network import Client, Response
from verifact.scanner import demo_report, scan
from verifact.server import AppState, WebError, run_scan
from verifact import threat_feed as feed
from tests.test_visitor_assessment import NOW


TARGET = "https://example.com/page"
CONTACT = "https://example.com/.well-known/security.txt"


def response(url, contact_status=200):
    if url == "http://example.com/":
        return Response(url, 301, {"location": "https://example.com/"})
    tls = {"verified": True, "hostname": "example.com", "not_after": "Dec 31 23:59:59 2099 GMT"}
    if url == CONTACT:
        return Response(url, contact_status, {"content-type": "text/plain", "location": "https://another.example.net/security.txt"},
                        b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", tls=tls)
    return Response(url, 200, {"content-type": "text/html"}, b"<title>Example</title>", tls=tls)


class SecurityContactIntegrationTests(unittest.TestCase):
    def test_requested_contact_is_one_extra_unscored_request_on_the_final_origin(self):
        urls = []

        def request(client, url):
            urls.append(url)
            client.requests += 1
            return response(url)

        with patch.object(Client, "request", request):
            before = scan(TARGET)
            default_urls = list(urls)
            urls.clear()
            after = scan(TARGET, security_contact=True)
        self.assertNotIn(CONTACT, default_urls)
        self.assertEqual(urls, default_urls + [CONTACT])
        item = next(finding for finding in after["findings"] if finding["id"] == "security_contact")
        self.assertEqual(item["category"], "Domain")
        self.assertEqual(after["assessment"], before["assessment"])
        self.assertEqual(after["visitor_assessment"]["status"], before["visitor_assessment"]["status"])
        self.assertEqual(after["requests"], before["requests"] + 1)
        self.assertNotIn("security@example.com", json.dumps(item))

    def test_security_contact_redirect_is_not_followed(self):
        urls = []

        def request(client, url):
            urls.append(url)
            client.requests += 1
            return response(url, contact_status=302)

        with patch.object(Client, "request", request):
            report = scan(TARGET, security_contact=True)
        self.assertEqual(urls.count(CONTACT), 1)
        self.assertFalse(any("another.example.net" in url for url in urls))
        item = next(finding for finding in report["findings"] if finding["id"] == "security_contact")
        self.assertEqual(item["evidence"]["status"], "redirect")

    def test_preflight_listed_host_skips_contact_along_with_all_target_requests(self):
        snapshot = feed.FeedSnapshot(frozenset({"example.com"}), NOW, NOW + timedelta(minutes=5))
        with patch("verifact.threat_feed._CACHE", feed.FeedCache()), \
                patch("verifact.threat_feed._now", return_value=NOW), \
                patch("verifact.threat_feed._download", return_value=snapshot), \
                patch("verifact.scanner.Client") as client:
            report = scan(TARGET, community_check=True, security_contact=True)
        client.assert_not_called()
        self.assertTrue(report["inspection_skipped"])
        self.assertEqual(report["requests"], 0)
        item = next(finding for finding in report["findings"] if finding["id"] == "security_contact")
        self.assertEqual(item["status"], "unknown")
        self.assertEqual(report["visitor_assessment"]["status"], "warning")

    def test_server_forwards_explicit_option_and_rejects_nonboolean_values(self):
        state = AppState()
        with patch("verifact.server.threading.Thread") as thread:
            job = state.start_scan(TARGET, rdap=False, community_check=False, security_contact=True)
            args = thread.call_args.kwargs["args"]
        self.assertTrue(args[5])
        with patch("verifact.server.run_scan", return_value=demo_report()) as runner:
            state._scan_worker(*args)
        runner.assert_called_once_with(TARGET, False, None, security_contact=True)
        self.assertEqual(state.job(job["id"])["status"], "complete")
        for value in (None, 0, 1, "true", [], {}):
            with self.subTest(value=value), self.assertRaises(WebError):
                state.start_scan(TARGET, security_contact=value)

    def test_subprocess_adds_only_explicit_security_contact_flag(self):
        completed = Mock(returncode=0, stdout=json.dumps(demo_report()).encode())
        with patch("verifact.server.subprocess.run", return_value=completed) as runner:
            run_scan(TARGET, False, security_contact=True)
        command = runner.call_args.args[0]
        self.assertIn("--security-contact", command)
        self.assertNotIn("--community", command)
        self.assertNotIn(TARGET, command)
        self.assertEqual(runner.call_args.kwargs["input"], TARGET.encode())

    def test_cli_flag_forwards_option_without_enabling_other_optional_requests(self):
        with patch("verifact.cli.scan", return_value=demo_report()) as scanner, \
                patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            code = main(["scan", TARGET, "--security-contact", "--format", "json"])
        self.assertIn(code, (0, 1))
        self.assertIs(scanner.call_args.kwargs["security_contact"], True)
        self.assertNotIn("community_check", scanner.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
