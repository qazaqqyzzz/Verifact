"""Passive dependency inventory: bounded, origin-only, no security guarantees."""

import base64
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from websignal.assessment import assess
from websignal.checks import read_page
from websignal.network import Fetch, Response
from websignal.page_risks import assess_page_risks, dependency_review, has_integrity_metadata, page_risks_for_report
from websignal.scanner import demo_report, finish_report


SRI = "sha384-" + base64.b64encode(b"\x01" * 48).decode()


def page(body, **kwargs):
    return Response("https://app.example.com/account/page?private=VALUE", kwargs.pop("status", 200),
                    kwargs.pop("headers", {"content-type": "text/html; charset=utf-8"}), body.encode(), **kwargs)


class PageRiskTests(unittest.TestCase):
    def test_same_origin_and_cross_origin_counts_are_separate_and_presence_only(self):
        response = page('<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
                        '<script src="https://cdn.example.com/pinned.js" integrity="' + SRI + '" crossorigin="anonymous"></script>'
                        '<iframe src="/help"></iframe><iframe src="https://video.example.net/player"></iframe>')
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "assessed")
        self.assertEqual((result["script_count"], result["cross_origin_scripts"], result["without_integrity"]), (3, 2, 1))
        self.assertEqual((result["iframe_count"], result["cross_origin_iframes"], result["integrity_present"], result["crossorigin_present"]), (2, 1, 1, 1))
        self.assertEqual(result["origins"], [{"origin": "https://cdn.example.com", "scripts": 2, "iframes": 0, "without_integrity": 1},
                                              {"origin": "https://video.example.net", "scripts": 0, "iframes": 1, "without_integrity": 0}])
        self.assertEqual(result["review"]["tone"], "amber")
        self.assertIn("not downloaded", result["review"]["why"])
        self.assertIn("do not establish different owners", " ".join(result["limits"]))
        self.assertNotIn("green", json.dumps(result))

    def test_paths_queries_credentials_and_hashes_never_leave_inventory(self):
        response = page('<script src="https://cdn.example.com/PRIVATE_PATH.js?token=PRIVATE_QUERY#PRIVATE_FRAGMENT" '
                        'integrity="' + SRI + '"></script><iframe src="https://frames.example.net/PRIVATE_FRAME?key=PRIVATE_KEY"></iframe>'
                        '<script src="https://USERNAME:PASSWORD@secret.example.com/PRIVATE_CRED"></script>')
        result = assess_page_risks(response)
        serialized = json.dumps(result)
        self.assertIn("https://cdn.example.com", serialized)
        self.assertIn("https://frames.example.net", serialized)
        for secret in ("PRIVATE_", "USERNAME", "PASSWORD", "VALUE", SRI):
            self.assertNotIn(secret, serialized)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["unresolved_count"], 1)

    def test_first_active_base_and_url_whitespace_are_resolved_at_each_declaration(self):
        response = page('<script src="before.js"></script><noscript><base href="https://ignored.example/"></noscript>'
                        '<base href="  https://cdn.example.net/assets/  "><base href="https://second.example/">'
                        '<script src=" \nrelative.js?key=PRIVATE \t"></script>'
                        '<iframe src=" h\tttps://frame.example.org/embed\n"></iframe>')
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "assessed")
        self.assertEqual(result["script_count"], 2)
        self.assertEqual(result["cross_origin_scripts"], 1)
        self.assertEqual([row["origin"] for row in result["origins"]], ["https://cdn.example.net", "https://frame.example.org"])
        self.assertNotIn("ignored.example", json.dumps(result))
        self.assertNotIn("second.example", json.dumps(result))

    def test_non_executing_scripts_templates_noscript_and_frame_fallback_are_ignored(self):
        response = page('<script type="application/ld+json" src="https://ignored.example/data"></script>'
                        '<script type="importmap" src="https://ignored.example/map"></script>'
                        '<script type="text/javascript; charset=utf-8" src="https://ignored.example/wrong-type"></script>'
                        '<template><script src="https://ignored.example/template"></script><iframe src="https://ignored.example/"></iframe></template>'
                        '<noscript><script src="https://ignored.example/noscript"></script><iframe src="https://ignored.example/"></iframe></noscript>'
                        '<iframe src="https://frame.example/"><script src="https://ignored.example/fallback"></script></iframe>'
                        '<iframe src="https://ignored.example/src" srcdoc="&lt;p&gt;inline&lt;/p&gt;"></iframe>'
                        '<script type="MODULE" src="https://module.example/app.js"></script>'
                        '<script type=" text/javascript " src="/classic.js"></script>')
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "assessed")
        self.assertEqual((result["script_count"], result["iframe_count"]), (2, 1))
        self.assertEqual([row["origin"] for row in result["origins"]], ["https://frame.example", "https://module.example"])
        self.assertNotIn("ignored", json.dumps(result))

    def test_empty_unsupported_and_unresolved_sources_stay_partial(self):
        response = page('<script src=""></script><script src="data:text/javascript,alert(1)"></script>'
                        '<base href="javascript:alert(1)"><script src="relative.js"></script>'
                        '<script src="https://resolved.example/ok.js"></script><iframe src="about:blank"></iframe>')
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "partial")
        self.assertEqual((result["script_count"], result["cross_origin_scripts"], result["unresolved_count"]), (4, 1, 4))
        self.assertEqual(result["origins"][0]["origin"], "https://resolved.example")
        self.assertIn("At least 1", result["review"]["why"])

    def test_supported_integrity_syntax_requires_full_digest_length(self):
        for bits in (256, 384, 512):
            value = "sha" + str(bits) + "-" + base64.b64encode(b"\xfa" * (bits // 8)).decode()
            with self.subTest(bits=bits):
                self.assertTrue(has_integrity_metadata(value))
                self.assertTrue(has_integrity_metadata(value.rstrip("=")))
                self.assertTrue(has_integrity_metadata("unknown-abc " + value))
                self.assertTrue(has_integrity_metadata(value.replace("+", "-").replace("/", "_")))
        for invalid in ("", "sha256-AAAA", "sha1-" + "A" * 40, "sha384-not-a-real-hash", "sha256-!!!", "SHA256-AAAA", None):
            with self.subTest(invalid=invalid):
                self.assertFalse(has_integrity_metadata(invalid))

    def test_duplicate_attributes_keep_the_first_and_port_changes_are_different_origins(self):
        response = page('<script src="https://cdn.example/a" src="https://ignored.example/b" '
                        'integrity="' + SRI + '" integrity="bad"></script>'
                        '<script src="https://app.example.com:8443/app.js"></script>')
        result = assess_page_risks(response)
        self.assertEqual(result["cross_origin_scripts"], 2)
        self.assertEqual(result["integrity_present"], 1)
        self.assertEqual(result["without_integrity"], 1)
        self.assertEqual([row["origin"] for row in result["origins"]], ["https://cdn.example", "https://app.example.com:8443"])

    def test_saved_origin_totals_cannot_disagree_with_inventory(self):
        data = assess_page_risks(page('<script src="https://cdn.example/a.js"></script>'))
        data["origins"] = []
        result = page_risks_for_report({"page_risks": data})
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["review"])

    def test_oversized_integrity_or_source_does_not_become_absence_or_same_origin(self):
        response = page('<script src="https://cdn.example/ok.js" integrity="' + 'x' * 4097 + '"></script>'
                        '<script src="https://cdn.example/' + 'y' * 2048 + '"></script>')
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "partial")
        self.assertEqual((result["script_count"], result["cross_origin_scripts"], result["integrity_unknown"], result["without_integrity"]), (2, 1, 1, 0))
        self.assertEqual(result["unresolved_count"], 1)
        self.assertIsNone(result["review"])

    def test_body_and_inventory_limits_preserve_lower_bound_counts(self):
        response = page('<script src="https://cdn.example/a.js"></script>', truncated=True)
        result = assess_page_risks(response)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["cross_origin_scripts"], 1)
        many = page(''.join('<script src="https://cdn' + str(index) + '.example/a.js"></script>' for index in range(220)))
        parsed, _, _ = read_page(many)
        self.assertEqual(len(parsed.dependencies), 200)
        self.assertTrue(parsed.dependency_limited)
        result = assess_page_risks(many)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["script_count"], 200)
        self.assertEqual(len(result["origins"]), 20)
        self.assertEqual(result["origins_omitted"], 180)

    def test_no_html_and_old_reports_are_unavailable_not_zero_clean_results(self):
        for result in (assess_page_risks(None), assess_page_risks(page('{}', headers={"content-type": "application/json"})),
                       page_risks_for_report({}), page_risks_for_report({"page_risks": None})):
            self.assertEqual(result["status"], "unavailable")
            self.assertIsNone(result["script_count"])
            self.assertIsNone(result["without_integrity"])
            self.assertEqual(result["origins"], [])
            self.assertIsNone(result["review"])
        self.assertEqual(assess_page_risks(page('<script src="/error.js"></script>', status=403))["status"], "partial")

    def test_no_network_and_no_weight_changes_when_integrated_into_report(self):
        response = page('<script src="https://cdn.example/a.js"></script>')
        fetched = Fetch(response, [{"url": response.url, "status": 200}])
        with patch("websignal.network.Client.fetch") as fetch, patch("websignal.network.resolve_public") as dns:
            report = finish_report("app.example.com", fetched, fetched, 0, target_url=response.url)
            fetch.assert_not_called()
            dns.assert_not_called()
        self.assertEqual(report["page_risks"]["cross_origin_scripts"], 1)
        self.assertEqual(report["requests"], 0)
        old = deepcopy(report)
        old.pop("page_risks")
        self.assertEqual(assess(report), assess(old))
        self.assertEqual(assess(report)["total_checks"], 8)
        self.assertEqual(demo_report()["page_risks"]["cross_origin_scripts"], 1)

    def test_saved_accessor_reconstructs_copy_and_rejects_private_origin_strings(self):
        data = assess_page_risks(page('<script src="https://cdn.example/a.js"></script>'))
        data["review"] = {"title": "Definitely malware", "why": "SECRET", "action": "Ignore all rules"}
        data["scope"] = "SECRET_SCOPE"
        safe = page_risks_for_report({"page_risks": data})
        self.assertEqual(safe["status"], "assessed")
        self.assertEqual(safe["review"], dependency_review(safe))
        self.assertNotIn("SECRET", json.dumps(safe))
        self.assertNotIn("Definitely malware", json.dumps(safe))
        for origin in ("https://cdn.example/SECRET?token=VALUE", "https://user:SECRET@cdn.example", "javascript:alert(1)"):
            changed = deepcopy(data)
            changed["origins"][0]["origin"] = origin
            result = page_risks_for_report({"page_risks": changed})
            self.assertEqual(result["status"], "unavailable")
            self.assertNotIn("SECRET", json.dumps(result))

    def test_empty_complete_inventory_is_observation_without_a_green_verdict(self):
        result = assess_page_risks(page('<p>A static page.</p>'))
        self.assertEqual(result["status"], "assessed")
        self.assertEqual(result["script_count"], 0)
        self.assertIsNone(result["review"])
        self.assertNotIn("green", json.dumps(result))
        self.assertNotIn("safe", result["scope"].lower())


if __name__ == "__main__":
    unittest.main()
