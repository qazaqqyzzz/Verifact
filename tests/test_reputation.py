"""Offline reputation contract tests; no provider requests or real keys."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import Mock, patch

from verifact import reputation


FAKE_KEY = "test-google-key-not-a-real-credential"
URL = "https://example.com/account?campaign=public"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def match(url=URL, kind="SOCIAL_ENGINEERING", duration="300s"):
    return {"threatType": kind, "platformType": "ANY_PLATFORM", "threatEntryType": "URL",
            "threat": {"url": url}, "cacheDuration": duration}


class ReputationTests(unittest.TestCase):
    def setUp(self):
        reputation._CACHE.clear()

    def tearDown(self):
        reputation._CACHE.clear()

    def test_no_key_makes_no_request_even_when_environment_has_key(self):
        with patch.dict("os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": FAKE_KEY}), patch.object(reputation, "_post") as post:
            result = reputation.inspect_urls([URL])
        post.assert_not_called()
        self.assertEqual(result["status"], "not_checked")
        self.assertEqual(result["checked_count"], 0)

    def test_full_links_in_one_payload_not_the_key_or_fragment(self):
        with patch.object(reputation, "_post", return_value={}) as post:
            result = reputation.inspect_urls([URL + "#part", URL, "https://example.com/next"], FAKE_KEY)
        post.assert_called_once()
        payload, key, timeout = post.call_args.args
        self.assertEqual(key, FAKE_KEY)
        self.assertEqual(payload["threatInfo"]["threatEntries"], [{"url": URL}, {"url": "https://example.com/next"}])
        self.assertNotIn(FAKE_KEY, json.dumps(payload))
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["checked_count"], 2)
        self.assertIn("does not mean the link is safe", result["detail"])
        self.assertFalse(result["attribution"])

    def test_listed_response_has_source_qualified_language_and_expiry(self):
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value={"matches": [match()]}):
            result = reputation.inspect_urls([URL], FAKE_KEY)
        self.assertEqual(result["status"], "listed")
        self.assertIn("potentially", result["detail"])
        self.assertEqual(result["attribution"], "Advisory provided by Google")
        self.assertEqual(result["source_url"], reputation.ADVISORY_URL)
        self.assertEqual(result["expires_at"], (NOW + timedelta(minutes=5)).isoformat())
        self.assertEqual(result["matches"][0]["label"], "Potential phishing or deceptive content")

    def test_malformed_partial_unrelated_and_future_response_never_no_match(self):
        malformed = [None, [], {"error": {}}, {"matches": None}, {"future": True}, {"matches": [None]},
                     {"matches": [{"threatType": "MALWARE"}]}, {"matches": [match(url="https://other.example.com/")]},
                     {"matches": [match(kind="UNKNOWN_NEW_THREAT")]}, {"matches": [match(duration="NaNs")]},
                     {"matches": [match(duration="0s")]}, {"matches": [match(duration="-1s")]},
                     {"matches": [{**match(), "platformType": []}]},
                     {"matches": [{**match(), "threat": {"url": "http://user:pass@example.com/"}}]}]
        for value in malformed:
            with self.subTest(value=value), patch.object(reputation, "_post", return_value=value):
                result = reputation.inspect_urls([URL], FAKE_KEY)
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["checked_count"], 0)
            self.assertFalse(result["matches"])

    def test_invalid_inputs_never_send_anything(self):
        values = [[], [URL] * 13, ["https://127.0.0.1/"], ["http://user:pw@example.com/"],
                  ["ftp://example.com/"], ["https://example.com:8443/"], ["http://app.local/"],
                  ["https://example.com/\r\nX-Test: value"], ["https://example.com/" + "a" * 2048], [None]]
        with patch.object(reputation, "_post") as post:
            for urls in values:
                with self.subTest(urls=urls):
                    self.assertEqual(reputation.inspect_urls(urls, FAKE_KEY)["status"], "unavailable")
            for key in ("bad", "test-key-with-newline\n", "❌" * 30, 4):
                self.assertEqual(reputation.inspect_urls([URL], key)["status"], "unavailable")
            for timeout in (0, 31, True, float("nan"), float("inf"), "8"):
                self.assertEqual(reputation.inspect_urls([URL], FAKE_KEY, timeout)["status"], "unavailable")
        post.assert_not_called()

    def test_failure_never_exposes_key_and_never_becomes_no_match(self):
        with patch.object(reputation, "_post", side_effect=reputation.ReputationError("The service could not be reached.")):
            result = reputation.inspect_urls([URL], FAKE_KEY)
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn(FAKE_KEY, json.dumps(result))

    def test_expired_warning_is_removed_without_mutation_or_network(self):
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value={"matches": [match()]}):
            original = reputation.inspect_urls([URL], FAKE_KEY)
        saved = deepcopy(original)
        with patch.object(reputation, "_post") as post:
            fresh = reputation.public_result(original, NOW + timedelta(seconds=299))
            expired = reputation.public_result(original, NOW + timedelta(seconds=300))
        self.assertEqual(fresh["status"], "listed")
        self.assertEqual(expired["status"], "unavailable")
        self.assertTrue(expired["stale"])
        self.assertFalse(expired["matches"])
        self.assertFalse(expired["attribution"])
        self.assertEqual(original, saved)
        post.assert_not_called()

    def test_invalid_expiry_removes_warning(self):
        for value in (None, "not a date", "2026-10-30T12:00:00"):
            with self.subTest(value=value):
                result = reputation.public_result({"status": "listed", "expires_at": value}, NOW)
                self.assertEqual(result["status"], "unavailable")
                self.assertFalse(result["matches"])
        for value in (None, [], {"status": []}, {"status": "invented"}):
            self.assertEqual(reputation.public_result(value, NOW)["status"], "not_checked")

    def test_positive_cache_prevents_resubmission_during_validity(self):
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value={"matches": [match()]}):
            first = reputation.inspect_urls([URL], FAKE_KEY)
        with patch.object(reputation, "_now", return_value=NOW + timedelta(seconds=30)), patch.object(reputation, "_post") as post:
            cached = reputation.inspect_urls([URL], FAKE_KEY)
        post.assert_not_called()
        self.assertEqual(cached["status"], "listed")
        self.assertEqual(cached["checked_at"], first["checked_at"])
        self.assertEqual(cached["expires_at"], first["expires_at"])
        self.assertEqual(cached["cached_count"], 1)
        with patch.object(reputation, "_now", return_value=NOW + timedelta(minutes=6)), patch.object(reputation, "_post", return_value={}) as post:
            renewed = reputation.inspect_urls([URL], FAKE_KEY)
        post.assert_called_once()
        self.assertEqual(renewed["status"], "no_match")

    def test_mixed_cache_only_submits_new_urls(self):
        with patch.object(reputation, "_now", return_value=NOW), patch.object(reputation, "_post", return_value={"matches": [match()]}):
            reputation.inspect_urls([URL], FAKE_KEY)
        new = "https://example.com/other"
        with patch.object(reputation, "_now", return_value=NOW + timedelta(seconds=3)), patch.object(reputation, "_post", return_value={}) as post:
            result = reputation.inspect_urls([URL, new], FAKE_KEY)
        self.assertEqual(post.call_args.args[0]["threatInfo"]["threatEntries"], [{"url": new}])
        self.assertEqual(result["status"], "listed")
        self.assertEqual(result["checked_count"], 2)


class ReputationTransportTests(unittest.TestCase):
    def connection(self, body=b"{}", status=200, content_type="application/json; charset=utf-8"):
        connection = Mock()
        response = Mock()
        connection.getresponse.return_value = response
        response.status = status
        response.getheader.return_value = content_type
        response.isclosed.return_value = False
        response.read1.side_effect = [body, b""]
        response.length = 0
        return connection, response

    def test_fixed_https_host_header_key_body_urls_no_redirects(self):
        connection, response = self.connection()
        with patch.object(reputation.http.client, "HTTPSConnection", return_value=connection) as constructor:
            result = reputation._post({"url": URL}, FAKE_KEY, 8)
        self.assertEqual(result, {})
        self.assertEqual(constructor.call_args.args, ("safebrowsing.googleapis.com",))
        self.assertEqual(connection.request.call_args.args, ("POST", "/v4/threatMatches:find"))
        self.assertEqual(connection.request.call_args.kwargs["headers"]["X-Goog-Api-Key"], FAKE_KEY)
        self.assertNotIn(FAKE_KEY, connection.request.call_args.kwargs["body"].decode())
        response.close.assert_called_once()
        connection.close.assert_called_once()

    def test_provider_error_body_and_redirect_are_not_consumed(self):
        for status in (302, 400, 403, 429, 500):
            connection, response = self.connection(body=FAKE_KEY.encode(), status=status)
            with self.subTest(status=status), patch.object(reputation.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(reputation.ReputationError) as caught:
                    reputation._post({}, FAKE_KEY, 8)
            self.assertNotIn(FAKE_KEY, str(caught.exception))
            response.read1.assert_not_called()
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_oversize_incomplete_wrong_type_invalid_json_and_network_error(self):
        for body, content_type, remaining in ((b"x" * (reputation.MAX_RESPONSE_BYTES + 1), "application/json", 0),
                                             (b"{}", "application/json", 1), (b"{}", "text/html", 0),
                                             (b"not JSON", "application/json", 0),
                                             (b'{"matches": [{}], "matches": []}', "application/json", 0)):
            connection, response = self.connection(body, content_type=content_type)
            response.length = remaining
            with self.subTest(content_type=content_type, remaining=remaining), patch.object(reputation.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(reputation.ReputationError):
                    reputation._post({}, FAKE_KEY, 8)
            connection.close.assert_called_once()
        connection, response = self.connection()
        connection.request.side_effect = OSError("secret " + FAKE_KEY)
        with patch.object(reputation.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(reputation.ReputationError) as caught:
                reputation._post({}, FAKE_KEY, 8)
        self.assertNotIn(FAKE_KEY, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
