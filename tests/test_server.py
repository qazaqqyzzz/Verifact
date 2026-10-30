"""Local application tests. Target scanning and AI calls are always mocked."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import http.client
import json
import threading
import unittest
from unittest.mock import Mock, patch

from websignal.ai import AIError, PROMPT_VERSION
from websignal.scanner import demo_report
from websignal.server import AppServer, AppState, WebError, run_scan, target_domain


FAKE_KEY = "test-key-only-not-a-real-api-credential"
FAKE_REPUTATION_KEY = "fake-google-key-for-offline-tests-only"
PUBLIC_TARGET = "https://example.com/path?q=sample"


def live_fixture():
    report = demo_report()
    report["demo"] = False
    report["domain"] = "example.com"
    report["target_url"] = PUBLIC_TARGET
    report["response"]["url"] = PUBLIC_TARGET
    report["link_analysis"].update(input_url=PUBLIC_TARGET, final_url=PUBLIC_TARGET,
                                   redirects=[{"url": PUBLIC_TARGET, "status": 200}])
    return report


def completed_job(state):
    with patch("websignal.server.threading.Thread"):
        job = state.start_scan(PUBLIC_TARGET, rdap=False)
    with patch("websignal.server.run_scan", return_value=live_fixture()):
        state._scan_worker(job["id"], PUBLIC_TARGET, False)
    return state.job(job["id"])


def cached_ai_job(state, version):
    job = completed_job(state)
    state.jobs[job["id"]]["report"]["ai"] = {
        "prompt_version": version, "fixture": False, "provider": "ollama",
        "summary": "An existing explanation to keep until an update succeeds.", "items": [],
    }
    state.jobs[job["id"]].update(ai_status="complete", ai_provider="ollama")
    return state.job(job["id"])


class TargetInputTests(unittest.TestCase):
    def test_display_domain_can_be_extracted_without_changing_the_scan_target(self):
        for target in ["example.com", " EXAMPLE.COM. ", "http://example.com/", "https://example.com/path?x=1#part",
                       "example.com/path", "HTTPS://EXAMPLE.COM/path", "https://example.com:443/path"]:
            with self.subTest(target=target):
                self.assertEqual(target_domain(target), "example.com")

    def test_unsupported_destinations_and_credentials_are_rejected(self):
        for target in [None, 123, "", "localhost", "http://127.0.0.1/", "http://10.0.0.1/", "http://[::1]/",
                       "https://user:password@example.com/", "ftp://example.com/", "https://example.com:8443/",
                       "example.com:8080", "http://example.com/\r\nInjected: x", "http://example.com\\@localhost/",
                       "a" * 2049]:
            with self.subTest(target=target), self.assertRaises(WebError):
                target_domain(target)

    def test_subprocess_gets_exact_target_on_stdin_without_optional_provider_keys(self):
        response = Mock(returncode=0, stdout=json.dumps(live_fixture()).encode())
        with patch.dict("os.environ", {"OPENAI_API_KEY": FAKE_KEY,
                                      "GOOGLE_SAFE_BROWSING_API_KEY": FAKE_REPUTATION_KEY,
                                      "WEBSIGNAL_TEST_PUBLIC_SETTING": "kept"}), \
                patch("websignal.server.subprocess.run", return_value=response) as runner:
            report = run_scan(PUBLIC_TARGET, True, "example.com")
        self.assertEqual(report["target_url"], PUBLIC_TARGET)
        args, kwargs = runner.call_args
        self.assertIn("--target-stdin", args[0])
        self.assertNotIn(PUBLIC_TARGET, args[0])
        self.assertEqual(kwargs["input"], PUBLIC_TARGET.encode())
        self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
        self.assertNotIn("GOOGLE_SAFE_BROWSING_API_KEY", kwargs["env"])
        self.assertEqual(kwargs["env"]["WEBSIGNAL_TEST_PUBLIC_SETTING"], "kept")
        self.assertEqual(kwargs["timeout"], 90)
        self.assertEqual(args[0][-3:], ["--expected-domain", "example.com", "--rdap"])

    def test_scan_keeps_exact_url_and_expected_domain(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as worker:
            job = state.start_scan(PUBLIC_TARGET + "#section", rdap=False, expected_domain="EXAMPLE.COM")
        self.assertEqual(job["domain"], "example.com")
        self.assertEqual(job["target_url"], PUBLIC_TARGET)
        self.assertEqual(worker.call_args.kwargs["args"], (job["id"], PUBLIC_TARGET, False, "example.com", True, False))

    def test_sensitive_links_stop_before_worker_creation(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as worker:
            for target in ["https://example.com/login?token=private", "https://example.com/reset-password/private"]:
                with self.subTest(target=target), self.assertRaises(WebError):
                    state.start_scan(target)
        worker.assert_not_called()
        self.assertEqual(state.jobs, {})

    def test_expected_domain_rejects_falsey_nonstring_values(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as worker:
            for expected in [False, 0, [], {}, 12, "https://example.com/", "example.com/path"]:
                with self.subTest(expected=expected), self.assertRaises(WebError):
                    state.start_scan(PUBLIC_TARGET, expected_domain=expected)
        worker.assert_not_called()
        self.assertEqual(state.jobs, {})
        for blank in [None, "", "   "]:
            with self.subTest(blank=blank), patch("websignal.server.threading.Thread") as worker:
                state = AppState()
                job = state.start_scan(PUBLIC_TARGET, expected_domain=blank)
                self.assertIsNone(worker.call_args.kwargs["args"][3])
                self.assertEqual(job["status"], "running")


class AppStateTests(unittest.TestCase):
    def test_scan_lifecycle_and_parallel_scan_rejection(self):
        state = AppState()
        with patch("websignal.server.threading.Thread") as thread:
            job = state.start_scan("https://example.com/path", rdap=False)
            self.assertEqual(job["status"], "running")
            self.assertTrue(state.scan_busy)
            with self.assertRaises(WebError) as failure:
                state.start_scan("other.example.com")
            self.assertEqual(failure.exception.status, 409)
            thread.assert_called_once()
            thread.return_value.start.assert_called_once()
        with patch("websignal.server.run_scan", return_value=live_fixture()) as scan:
            state._scan_worker(job["id"], "example.com", False)
        scan.assert_called_once_with("example.com", False)
        self.assertFalse(state.scan_busy)
        self.assertEqual(state.job(job["id"])["status"], "complete")
        copy = state.job(job["id"])
        copy["report"]["domain"] = "mutated.invalid"
        self.assertEqual(state.job(job["id"])["report"]["domain"], "example.com")

    def test_failed_scan_unlocks_next_attempt(self):
        state = AppState()
        with patch("websignal.server.threading.Thread"):
            job = state.start_scan("example.com")
        with patch("websignal.server.run_scan", side_effect=WebError("Timed out")):
            state._scan_worker(job["id"], "example.com", True)
        self.assertEqual(state.job(job["id"])["error"], "Timed out")
        self.assertEqual(state.job(job["id"])["status"], "failed")
        self.assertFalse(state.scan_busy)

    def test_ai_requires_key_without_starting_any_request(self):
        state = AppState()
        state.set_settings({"provider": "openai"})
        job = completed_job(state)
        with patch.dict("os.environ", {}, clear=True), patch("websignal.server.threading.Thread") as thread, \
                patch("websignal.server.explain") as explain:
            with self.assertRaisesRegex(WebError, "API key"):
                state.start_ai(job["id"])
        thread.assert_not_called()
        explain.assert_not_called()
        self.assertEqual(state.job(job["id"])["report"], job["report"])

    def test_ai_is_one_call_and_cached_after_completion(self):
        state = AppState()
        state.set_key(FAKE_KEY)
        job = completed_job(state)
        enriched = deepcopy(job["report"])
        enriched["ai"] = {"fixture": False, "items": []}
        with patch("websignal.server.threading.Thread") as thread:
            first = state.start_ai(job["id"])
            second = state.start_ai(job["id"])
            self.assertEqual(first["ai_status"], "running")
            self.assertEqual(second["ai_status"], "running")
            thread.assert_called_once()
        with patch("websignal.server.explain", return_value=enriched) as explain:
            state._ai_worker(job["id"], job["report"], FAKE_KEY)
        explain.assert_called_once_with(job["report"], provider="openai", api_key=FAKE_KEY, timeout=60)
        self.assertFalse(state.ai_busy)
        with patch("websignal.server.threading.Thread") as thread:
            cached = state.start_ai(job["id"])
        thread.assert_not_called()
        self.assertEqual(cached["ai_status"], "complete")
        self.assertEqual(cached["report"]["findings"], job["report"]["findings"])

    def test_ai_failure_preserves_scan_results(self):
        state = AppState()
        state.set_key(FAKE_KEY)
        job = completed_job(state)
        with patch("websignal.server.threading.Thread"):
            state.start_ai(job["id"])
        with patch("websignal.server.explain", side_effect=AIError("Provider quota unavailable")):
            state._ai_worker(job["id"], job["report"], FAKE_KEY)
        failed = state.job(job["id"])
        self.assertEqual(failed["report"], job["report"])
        self.assertEqual(failed["status"], "complete")
        self.assertEqual(failed["ai_status"], "failed")
        self.assertEqual(failed["ai_error"], "Provider quota unavailable")
        self.assertFalse(state.ai_busy)

    def test_current_ai_answer_is_cached_even_when_update_is_requested(self):
        state = AppState()
        state.set_settings({"provider": "ollama"})
        job = cached_ai_job(state, PROMPT_VERSION)
        self.assertEqual(state.config()["ai_prompt_version"], PROMPT_VERSION)
        with patch("websignal.server.threading.Thread") as thread:
            for refresh in (False, True, True):
                cached = state.start_ai(job["id"], refresh=refresh)
                self.assertEqual(cached["report"]["ai"], job["report"]["ai"])
                self.assertEqual(cached["ai_status"], "complete")
        thread.assert_not_called()

    def test_stale_ai_requires_explicit_update_and_repeated_clicks_are_cached(self):
        state = AppState()
        state.set_settings({"provider": "ollama"})
        job = cached_ai_job(state, "older-prompt-version")
        with patch("websignal.server.threading.Thread") as thread:
            self.assertEqual(state.start_ai(job["id"])["ai_status"], "complete")
            thread.assert_not_called()
            first = state.start_ai(job["id"], refresh=True)
            repeated = state.start_ai(job["id"], refresh=True)
            self.assertEqual(first["ai_status"], "running")
            self.assertEqual(repeated["ai_status"], "running")
            self.assertEqual(first["report"]["ai"], job["report"]["ai"])
            thread.assert_called_once()
            worker_args = thread.call_args.kwargs["args"]
        updated = deepcopy(job["report"])
        updated["ai"]["prompt_version"] = PROMPT_VERSION
        updated["ai"]["summary"] = "A newly generated explanation."
        with patch("websignal.server.explain", return_value=updated) as explain:
            state._ai_worker(*worker_args)
        explain.assert_called_once()
        self.assertEqual(state.job(job["id"])["report"]["ai"]["prompt_version"], PROMPT_VERSION)
        with patch("websignal.server.threading.Thread") as thread:
            state.start_ai(job["id"], refresh=True)
        thread.assert_not_called()

    def test_failed_ai_update_preserves_previous_answer_and_requires_explicit_retry(self):
        state = AppState()
        state.set_settings({"provider": "ollama"})
        job = cached_ai_job(state, "older-prompt-version")
        with patch("websignal.server.threading.Thread") as thread:
            state.start_ai(job["id"], refresh=True)
            worker_args = thread.call_args.kwargs["args"]
        with patch("websignal.server.explain", side_effect=AIError("Local model unavailable")):
            state._ai_worker(*worker_args)
        failed = state.job(job["id"])
        self.assertEqual(failed["report"], job["report"])
        self.assertEqual(failed["ai_status"], "failed")
        self.assertEqual(failed["ai_error"], "Local model unavailable")
        self.assertFalse(state.ai_busy)
        with patch("websignal.server.threading.Thread") as thread:
            state.start_ai(job["id"])
            thread.assert_not_called()
            state.start_ai(job["id"], refresh=True)
            thread.assert_called_once()

    def test_ai_update_flags_are_boolean_and_fixture_answers_cannot_update(self):
        state = AppState()
        state.set_settings({"provider": "ollama"})
        job = cached_ai_job(state, "older-prompt-version")
        with patch("websignal.server.threading.Thread") as thread:
            for refresh in ("true", 1, None, [], {}):
                with self.subTest(refresh=refresh), self.assertRaises(WebError):
                    state.start_ai(job["id"], refresh=refresh)
            state.jobs[job["id"]]["report"]["ai"]["fixture"] = True
            with self.assertRaises(WebError):
                state.start_ai(job["id"], refresh=True)
        thread.assert_not_called()

    def test_demo_cannot_trigger_paid_ai(self):
        state = AppState()
        state.set_key(FAKE_KEY)
        job = state.demo()
        with patch("websignal.server.explain") as explain, self.assertRaises(WebError):
            state.start_ai(job["id"])
        explain.assert_not_called()

    def test_session_key_is_not_returned_in_configuration(self):
        state = AppState()
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(state.config()["openai_configured"])
            result = state.set_key(FAKE_KEY)
            self.assertIs(result["openai_configured"], True)
            self.assertNotIn(FAKE_KEY, json.dumps(result))
            self.assertFalse(state.set_key("")["openai_configured"])
        for key in [None, "short", " " * 32, "secret\r\nheader" * 3]:
            with self.subTest(key=key), self.assertRaises(WebError):
                state.set_key(key)

    def test_history_is_bounded_and_unknown_id_fails(self):
        state = AppState()
        with patch("websignal.server.MAX_JOBS", 2):
            first = state.demo()
            state.demo()
            state.demo()
        self.assertEqual(len(state.list_jobs()), 2)
        self.assertTrue(all("report" not in item for item in state.list_jobs()))
        with self.assertRaises(WebError) as failure:
            state.job(first["id"])
        self.assertEqual(failure.exception.status, 404)

    def test_builtin_default_cannot_spend_an_environment_key(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": FAKE_KEY}):
            state = AppState()
            config = state.config()
            self.assertEqual(config["provider"], "builtin")
            self.assertEqual(config["key_source"], "environment")
            self.assertNotIn(FAKE_KEY, json.dumps(config))
            job = completed_job(state)
            with patch("websignal.server.threading.Thread") as thread, self.assertRaisesRegex(WebError, "Built-in"):
                state.start_ai(job["id"])
            thread.assert_not_called()
            preview = state.preview_report(job["report"])
            self.assertEqual(preview["messages"], [])
            self.assertIsNone(preview["model"])

    def test_local_provider_never_receives_openai_key_and_is_captured(self):
        state = AppState()
        state.set_key(FAKE_KEY)
        state.set_settings({"provider": "ollama"})
        job = completed_job(state)
        with patch("websignal.server.threading.Thread") as thread:
            state.start_ai(job["id"])
            args = thread.call_args.kwargs["args"]
        self.assertIsNone(args[2])
        self.assertEqual(args[3], "ollama")
        self.assertEqual(state.job(job["id"])["ai_provider"], "ollama")
        state.set_settings({"provider": "openai"})
        with patch("websignal.server.explain", return_value=job["report"]) as explain:
            state._ai_worker(*args)
        explain.assert_called_once_with(job["report"], provider="ollama", api_key=None, timeout=120)

    def test_settings_preserve_keys_and_reject_invalid_updates_atomically(self):
        state = AppState()
        state.set_key(FAKE_KEY)
        state.set_settings({"provider": "builtin"})
        self.assertEqual(state.api_key, FAKE_KEY)
        for body in [{"provider": "untrusted-url", "api_key": ""}, {"provider": []},
                     {"provider": "ollama", "api_key": "short"}]:
            with self.subTest(body=body), self.assertRaises(WebError):
                state.set_settings(body)
            self.assertEqual(state.provider, "builtin")
            self.assertEqual(state.api_key, FAKE_KEY)
        with patch.dict("os.environ", {"OPENAI_API_KEY": FAKE_KEY}):
            self.assertEqual(state.config()["key_source"], "session")
            config = state.set_settings({"api_key": ""})
            self.assertEqual(config["key_source"], "environment")
            self.assertNotIn(FAKE_KEY, json.dumps(config))

    def test_local_preview_is_local_and_makes_no_request(self):
        state = AppState()
        state.set_settings({"provider": "ollama"})
        with patch("websignal.server.explain") as explain:
            preview = state.preview_report(live_fixture())
        explain.assert_not_called()
        self.assertEqual(preview["provider"], "ollama")
        self.assertEqual(preview["model"], "qwen3.5:2b-q4_K_M")

    def test_reputation_settings_are_optional_private_and_atomic(self):
        state = AppState()
        with patch.dict("os.environ", {}, clear=True), patch("websignal.server.inspect_urls") as lookup:
            self.assertFalse(state.config()["reputation_configured"])
            configured = state.set_settings({"api_key": FAKE_KEY, "reputation_key": FAKE_REPUTATION_KEY})
            self.assertEqual(configured["reputation_key_source"], "session")
            self.assertNotIn(FAKE_REPUTATION_KEY, json.dumps(configured))
            for body in [{"provider": "ollama", "api_key": "", "reputation_key": "short"},
                         {"provider": "unsupported", "reputation_key": ""},
                         {"api_key": "short", "reputation_key": ""}]:
                with self.subTest(body=body), self.assertRaises(WebError):
                    state.set_settings(body)
                self.assertEqual(state.provider, "builtin")
                self.assertEqual(state.api_key, FAKE_KEY)
                self.assertEqual(state.reputation_key, FAKE_REPUTATION_KEY)
            self.assertFalse(state.set_settings({"reputation_key": ""})["reputation_configured"])
            self.assertEqual(state.api_key, FAKE_KEY)
        lookup.assert_not_called()

    def test_environment_reputation_key_never_triggers_an_automatic_lookup(self):
        with patch.dict("os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": FAKE_REPUTATION_KEY}), \
                patch("websignal.server.inspect_urls") as lookup:
            state = AppState()
            config = state.config()
            self.assertTrue(config["reputation_configured"])
            self.assertEqual(config["reputation_key_source"], "environment")
            self.assertNotIn(FAKE_REPUTATION_KEY, json.dumps(config))
            job = completed_job(state)
            self.assertEqual(job["reputation_status"], "idle")
            state.preview_report(job["report"])
        lookup.assert_not_called()

    def test_reputation_requires_explicit_boolean_consent_key_and_live_report(self):
        state = AppState()
        job = completed_job(state)
        with patch.dict("os.environ", {}, clear=True), patch("websignal.server.threading.Thread") as worker:
            for consent in [False, None, 1, "true", [], {}]:
                with self.subTest(consent=consent), self.assertRaisesRegex(WebError, "Confirm sending"):
                    state.start_reputation(job["id"], consent=consent)
            with self.assertRaisesRegex(WebError, "key"):
                state.start_reputation(job["id"], consent=True)
            state.set_settings({"reputation_key": FAKE_REPUTATION_KEY})
            sample = state.demo()
            with self.assertRaisesRegex(WebError, "synthetic"):
                state.start_reputation(sample["id"], consent=True)
        worker.assert_not_called()
        self.assertFalse(state.reputation_busy)

    def test_reputation_deduplicates_running_clicks_and_bounds_parallel_work(self):
        state = AppState()
        state.set_settings({"reputation_key": FAKE_REPUTATION_KEY})
        job = completed_job(state)
        other = completed_job(state)
        with patch("websignal.server.threading.Thread") as worker:
            self.assertEqual(state.start_reputation(job["id"], True)["reputation_status"], "running")
            self.assertEqual(state.start_reputation(job["id"], True)["reputation_status"], "running")
            with self.assertRaises(WebError) as failure:
                state.start_reputation(other["id"], True)
        self.assertEqual(failure.exception.status, 409)
        worker.assert_called_once()
        self.assertEqual(worker.call_args.kwargs["args"], (job["id"], [PUBLIC_TARGET], FAKE_REPUTATION_KEY))

    def test_reputation_sends_only_deduplicated_exact_link_route(self):
        state = AppState()
        state.set_settings({"reputation_key": FAKE_REPUTATION_KEY})
        job = completed_job(state)
        final = "https://other.example.com/result?item=7"
        state.jobs[job["id"]]["report"]["link_analysis"].update(
            redirects=[{"url": PUBLIC_TARGET, "status": 302}, {"url": final, "status": 200}], final_url=final)
        with patch("websignal.server.threading.Thread") as worker:
            state.start_reputation(job["id"], consent=True)
        self.assertEqual(worker.call_args.kwargs["args"][1], [PUBLIC_TARGET, final])

    def test_optional_workers_merge_results_in_either_completion_order(self):
        for reputation_first in (True, False):
            with self.subTest(reputation_first=reputation_first):
                state = AppState()
                state.set_settings({"provider": "ollama", "reputation_key": FAKE_REPUTATION_KEY})
                job = completed_job(state)
                initial = deepcopy(job["report"])
                ai_result = {**initial, "ai": {"provider": "ollama", "summary": "Test explanation", "items": []}}
                reputation = {"provider": "Google Safe Browsing", "status": "no_match", "checked_count": 1,
                              "checked_at": "2026-10-30T12:00:00+00:00", "matches": [], "detail": "No known match."}
                with patch("websignal.server.threading.Thread"):
                    state.start_ai(job["id"])
                    state.start_reputation(job["id"], True)
                with patch("websignal.server.explain", return_value=ai_result) as explain, \
                        patch("websignal.server.inspect_urls", return_value=reputation) as lookup:
                    ai_work = lambda: state._ai_worker(job["id"], initial, None, "ollama")
                    reputation_work = lambda: state._reputation_worker(job["id"], [PUBLIC_TARGET], FAKE_REPUTATION_KEY)
                    first, second = (reputation_work, ai_work) if reputation_first else (ai_work, reputation_work)
                    first()
                    second()
                result = state.job(job["id"])
                self.assertEqual(result["report"]["ai"]["summary"], "Test explanation")
                self.assertEqual(result["report"]["reputation"]["status"], "no_match")
                self.assertEqual(result["report"]["findings"], initial["findings"])
                self.assertEqual(result["report"]["assessment"], initial["assessment"])
                self.assertEqual(result["ai_status"], "complete")
                self.assertEqual(result["reputation_status"], "complete")
                self.assertFalse(state.ai_busy)
                self.assertFalse(state.reputation_busy)
                explain.assert_called_once()
                lookup.assert_called_once_with([PUBLIC_TARGET], api_key=FAKE_REPUTATION_KEY, timeout=8)

    def test_reputation_failure_preserves_findings_and_does_not_echo_exception(self):
        state = AppState()
        state.set_settings({"reputation_key": FAKE_REPUTATION_KEY})
        job = completed_job(state)
        with patch("websignal.server.threading.Thread"):
            state.start_reputation(job["id"], True)
        with patch("websignal.server.inspect_urls", side_effect=RuntimeError(FAKE_REPUTATION_KEY)):
            state._reputation_worker(job["id"], [PUBLIC_TARGET], FAKE_REPUTATION_KEY)
        result = state.job(job["id"])
        self.assertEqual(result["report"]["reputation"]["status"], "unavailable")
        self.assertNotIn(FAKE_REPUTATION_KEY, json.dumps(result))
        self.assertEqual(result["report"]["findings"], job["report"]["findings"])
        self.assertFalse(state.reputation_busy)

    def test_history_does_not_evict_a_pending_reputation_worker(self):
        state = AppState()
        state.set_settings({"reputation_key": FAKE_REPUTATION_KEY})
        with patch("websignal.server.MAX_JOBS", 2):
            pending = completed_job(state)
            disposable = completed_job(state)
            with patch("websignal.server.threading.Thread"):
                state.start_reputation(pending["id"], True)
            fresh = state.demo()
        self.assertIn(pending["id"], state.jobs)
        self.assertIn(fresh["id"], state.jobs)
        self.assertNotIn(disposable["id"], state.jobs)

    def test_comparison_import_is_local_and_does_not_replace_scanned_evidence(self):
        state = AppState()
        job = completed_job(state)
        previous = deepcopy(job["report"])
        previous["created_at"] = "2026-01-01T00:00:00+00:00"
        next(item for item in previous["findings"] if item["id"] == "hsts")["status"] = "attention"
        with patch("websignal.server.run_scan") as scanner, patch("websignal.server.inspect_urls") as lookup, \
                patch("websignal.server.explain") as explain:
            compared = state.compare(job["id"], previous)
        self.assertTrue(compared["report"]["comparison"]["available"])
        self.assertIn("hsts", [change["id"] for change in compared["report"]["comparison"]["changes"]])
        self.assertEqual(compared["report"]["findings"], job["report"]["findings"])
        scanner.assert_not_called()
        lookup.assert_not_called()
        explain.assert_not_called()

    def test_comparison_rejects_other_targets_and_malformed_imports(self):
        state = AppState()
        job = completed_job(state)
        changed_target = deepcopy(job["report"])
        changed_target["target_url"] = "https://example.com/different"
        for previous in [{}, [], "not a report", changed_target]:
            with self.subTest(previous=type(previous).__name__), self.assertRaises(WebError):
                state.compare(job["id"], previous)
        self.assertEqual(state.job(job["id"])["report"], job["report"])

    def test_saved_brief_counts_are_recomputed_from_current_evidence(self):
        state = AppState()
        job = completed_job(state)
        forged = {"counts": {"met": 999, "review": 0, "unknown": 0}, "reviews": [], "all_reviews": []}
        state.jobs[job["id"]]["report"]["brief"] = deepcopy(forged)
        state.jobs[job["id"]]["report"]["assessment"] = {"value": 100}
        snapshot = state.job(job["id"])["report"]
        self.assertEqual(snapshot["brief"]["counts"], {"met": 7, "review": 3, "unknown": 0, "total": 10, "urgent": 0})
        self.assertEqual(snapshot["brief"]["total_review"], 4)
        self.assertEqual({item["finding_id"] for item in snapshot["brief"]["all_reviews"] if item["source"] == "security"},
                         {"csp", "framing", "http_resources"})
        self.assertEqual([item["id"] for item in snapshot["brief"]["all_reviews"] if item["source"] == "page"],
                         ["page_dependencies"])
        self.assertEqual(snapshot["brief"]["total_urgent"], 0)
        self.assertEqual(snapshot["assessment"]["value"], 70)
        self.assertEqual(state.jobs[job["id"]]["report"]["brief"], forged)

    def test_saved_reputation_expiry_refreshes_brief_without_provider_requests(self):
        state = AppState()
        job = completed_job(state)
        now = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)
        state.jobs[job["id"]]["report"]["reputation"] = {
            "provider": "Google Safe Browsing", "status": "listed", "checked_at": now.isoformat(),
            "checked_count": 1, "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "matches": [{"url": PUBLIC_TARGET, "threat_type": "MALWARE", "label": "Potential malware"}],
        }
        with patch("websignal.server.inspect_urls") as lookup:
            with patch("websignal.reputation._now", return_value=now):
                fresh = state.job(job["id"])["report"]
            with patch("websignal.reputation._now", return_value=now + timedelta(minutes=6)):
                expired = state.job(job["id"])["report"]
        self.assertEqual(fresh["brief"]["total_review"], 5)
        self.assertEqual(fresh["brief"]["total_urgent"], 1)
        self.assertEqual(fresh["brief"]["reviews"][0]["source"], "reputation")
        self.assertEqual(expired["brief"]["total_review"], 4)
        self.assertEqual(expired["brief"]["total_urgent"], 0)
        self.assertFalse(any(item["source"] == "reputation" for item in expired["brief"]["all_reviews"]))
        self.assertEqual([item for item in fresh["brief"]["all_reviews"] if item["source"] != "reputation"],
                         expired["brief"]["all_reviews"])
        self.assertEqual(expired["brief"]["counts"], {"met": 7, "review": 3, "unknown": 0, "total": 10, "urgent": 0})
        self.assertEqual(expired["reputation"]["status"], "unavailable")
        self.assertEqual(expired["reputation"]["matches"], [])
        self.assertEqual(expired["brief"]["counts"], fresh["brief"]["counts"])
        self.assertEqual(expired["assessment"], fresh["assessment"])
        lookup.assert_not_called()


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = AppServer(("127.0.0.1", 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.server.state = AppState()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        defaults = {}
        if data is not None:
            defaults = {"Content-Type": "application/json", "X-WebSignal-Token": self.server.state.csrf_token}
        defaults.update(headers or {})
        try:
            connection.request(method, path, body=json.dumps(data) if data is not None else None, headers=defaults)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_configuration_and_key_setup_do_not_echo_key(self):
        with patch.dict("os.environ", {}, clear=True):
            status, headers, raw = self.request("GET", "/api/config")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Cache-Control"], "no-store")
            config = json.loads(raw)
            self.assertEqual(config["csrf_token"], self.server.state.csrf_token)
            self.assertEqual(config["ai_prompt_version"], PROMPT_VERSION)
            self.assertFalse(config["openai_configured"])
            status, _, raw = self.request("POST", "/api/settings", {"api_key": FAKE_KEY})
            self.assertEqual(status, 200)
            self.assertIs(json.loads(raw)["openai_configured"], True)
            self.assertNotIn(FAKE_KEY.encode(), raw)
            _, _, subsequent = self.request("GET", "/api/config")
            self.assertNotIn(FAKE_KEY.encode(), subsequent)

    def test_reputation_key_endpoint_only_returns_configuration_state(self):
        with patch.dict("os.environ", {}, clear=True), patch("websignal.server.inspect_urls") as lookup:
            status, _, raw = self.request("POST", "/api/settings", {"reputation_key": FAKE_REPUTATION_KEY})
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(raw)["reputation_configured"])
            self.assertNotIn(FAKE_REPUTATION_KEY.encode(), raw)
            status, _, raw = self.request("GET", "/api/config")
            self.assertEqual(status, 200)
            self.assertNotIn(FAKE_REPUTATION_KEY.encode(), raw)
        lookup.assert_not_called()

    def test_exact_link_scan_endpoint_forwards_expected_domain(self):
        state = self.server.state
        expected_job = {"id": "a" * 24, "status": "running"}
        with patch.object(state, "start_scan", return_value=expected_job) as start:
            status, _, _ = self.request("POST", "/api/scans",
                                       {"target": PUBLIC_TARGET, "rdap": False, "expected_domain": "example.com"})
        self.assertEqual(status, 202)
        start.assert_called_once_with(PUBLIC_TARGET, False, "example.com", True, False)
        status, _, _ = self.request("POST", "/api/scans", {"target": "https://example.com/?access_token=private"})
        self.assertEqual(status, 400)
        self.assertFalse(state.jobs)

    def test_security_contact_endpoint_forwards_explicit_opt_in(self):
        expected_job = {"id": "a" * 24, "status": "running"}
        with patch.object(self.server.state, "start_scan", return_value=expected_job) as start:
            status, _, _ = self.request("POST", "/api/scans", {
                "target": PUBLIC_TARGET, "rdap": False,
                "community_check": False, "security_contact": True,
            })
        self.assertEqual(status, 202)
        start.assert_called_once_with(PUBLIC_TARGET, False, None, False, True)

    def test_reputation_endpoint_requires_consent_and_forwards_it_explicitly(self):
        state = self.server.state
        job = completed_job(state)
        path = f"/api/scans/{job['id']}/reputation"
        with patch("websignal.server.inspect_urls") as lookup:
            for body in [{}, {"consent": False}, {"consent": "true"}, {"consent": 1}]:
                self.assertEqual(self.request("POST", path, body)[0], 400)
        lookup.assert_not_called()
        with patch.object(state, "start_reputation", return_value=job) as start:
            status, _, _ = self.request("POST", path, {"consent": True})
        self.assertEqual(status, 202)
        start.assert_called_once_with(job["id"], consent=True)

    def test_comparison_endpoint_accepts_bounded_report_and_rejects_malformed_imports(self):
        state = self.server.state
        completed_job(state)
        job = completed_job(state)
        path = f"/api/scans/{job['id']}/compare"
        self.assertEqual(self.request("POST", path, {})[0], 200)
        for previous in [None, {}, ["not-a-report"], "not-a-report", {"schema_version": 1}]:
            with self.subTest(previous=previous):
                status, _, raw = self.request("POST", path, {"previous": previous})
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(raw))
        previous = deepcopy(job["report"])
        previous["created_at"] = "2026-01-01T00:00:00+00:00"
        previous["extra_ignored_padding"] = "a" * 9000
        with patch("websignal.server.run_scan") as scanner, patch("websignal.server.inspect_urls") as lookup:
            status, _, raw = self.request("POST", path, {"previous": previous})
        self.assertEqual(status, 200, raw)
        self.assertTrue(json.loads(raw)["report"]["comparison"]["available"])
        scanner.assert_not_called()
        lookup.assert_not_called()
        self.assertEqual(self.request("POST", path, {}, {"Content-Length": str(1024 * 1024 + 1)})[0], 413)
        self.assertEqual(self.request("POST", "/api/settings", {"padding": "a" * 9000})[0], 413)

    def test_report_view_asset_is_served_from_both_supported_paths(self):
        for path in ("/report_view.js", "/assets/report_view.js"):
            with self.subTest(path=path):
                status, headers, raw = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn(b"VerifyReportView", raw)

    def test_external_navigation_can_open_only_the_public_shell(self):
        headers = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
        status, _, raw = self.request("GET", "/", headers=headers)
        self.assertEqual(status, 200)
        self.assertIn(b"file-open-notice", raw)
        self.assertNotIn(self.server.state.csrf_token.encode(), raw)
        for path in ("/api/config", "/api/scans", "/app.js", "/report_view.js", "/?anything=1"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path, headers=headers)[0], 403)
        for change in ({"Sec-Fetch-Dest": "iframe"}, {"Sec-Fetch-Mode": "cors"}, {"Origin": "null"}):
            with self.subTest(change=change):
                self.assertEqual(self.request("GET", "/", headers={**headers, **change})[0], 403)
        self.assertEqual(self.request("POST", "/", data={}, headers=headers)[0], 403)

    def test_explain_route_forwards_explicit_update_and_rejects_nonboolean_flag(self):
        state = self.server.state
        state.set_settings({"provider": "ollama"})
        job = cached_ai_job(state, "older-prompt-version")
        path = "/api/scans/" + job["id"] + "/explain"
        with patch.object(state, "start_ai", return_value=job) as start:
            status, _, _ = self.request("POST", path, {"refresh": True})
            self.assertEqual(status, 202)
            start.assert_called_once_with(job["id"], refresh=True)
        with patch("websignal.server.explain") as explain:
            status, _, _ = self.request("POST", path, {"refresh": "true"})
            self.assertEqual(status, 400)
        explain.assert_not_called()

    def test_cross_origin_host_and_missing_csrf_are_rejected(self):
        for headers in [{"Host": "attacker.example"}, {"Origin": "https://attacker.example"},
                        {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}]:
            with self.subTest(headers=headers):
                status, _, _ = self.request("GET", "/api/config", headers=headers)
                self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/demo", {}, {"X-WebSignal-Token": ""})
        self.assertEqual(status, 403)
        self.assertEqual(self.server.state.list_jobs(), [])

    def test_demo_can_be_fetched_downloaded_and_previewed_without_ai(self):
        with patch("websignal.server.run_scan") as scan, patch("websignal.server.explain") as explain:
            status, _, raw = self.request("POST", "/api/demo", {})
            self.assertEqual(status, 200)
            job = json.loads(raw)
            self.assertTrue(job["report"]["demo"])
            identifier = job["id"]
            status, _, fetched = self.request("GET", f"/api/scans/{identifier}")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(fetched)["id"], identifier)
            for format, mime in [("json", "application/json"), ("html", "text/html")]:
                with self.subTest(format=format):
                    status, headers, content = self.request("GET", f"/api/scans/{identifier}/download?format={format}")
                    self.assertEqual(status, 200)
                    self.assertIn(mime, headers["Content-Type"])
                    self.assertIn(f'.{format}"', headers["Content-Disposition"])
                    if format == "json":
                        self.assertTrue(json.loads(content)["demo"])
                    else:
                        self.assertIn(b"SYNTHETIC DEMO", content)
            status, _, raw = self.request("GET", f"/api/scans/{identifier}/preview")
            self.assertEqual(status, 200)
            self.assertIn("messages", json.loads(raw))
            scan.assert_not_called()
            explain.assert_not_called()

    def test_unknown_report_and_unsupported_request_shapes(self):
        status, _, raw = self.request("GET", "/api/scans/" + "0" * 24)
        self.assertEqual(status, 404)
        self.assertIn("error", json.loads(raw))
        status, _, _ = self.request("POST", "/api/scans", {"target": "https://example.com:8443/"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/demo", {}, {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/demo", ["not-an-object"])
        self.assertEqual(status, 400)

    def test_public_bind_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            AppServer(("0.0.0.0", 0))


if __name__ == "__main__":
    unittest.main()
