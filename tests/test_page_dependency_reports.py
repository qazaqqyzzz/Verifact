"""Downloaded dependency summaries keep limits and expose only source origins."""

from copy import deepcopy
from html.parser import HTMLParser
import json
import re
import unittest
from unittest.mock import patch

from websignal.network import Response
from websignal.page_risks import assess_page_risks
from websignal.reports import html_report, render, text_report
from websignal.scanner import demo_report


def inventory_report(body, truncated=False):
    report = demo_report()
    response = Response("https://demo.example.com/", 200, {"content-type": "text/html"},
                        body.encode(), truncated=truncated)
    report["page_risks"] = assess_page_risks(response)
    return report


def dependency_section(markup):
    match = re.search(r'<details class="report-disclosure dependency-details">(.*?)</details>', markup, re.S)
    if not match:
        raise AssertionError("Dependency section is missing")
    return match.group(1)


class Markup(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.tags = []
        self.feed(markup)

    def handle_starttag(self, tag, attributes):
        self.tags.append((tag, dict(attributes)))


class PageDependencyReportTests(unittest.TestCase):
    def test_exports_show_counts_and_origins_without_fetching_resources(self):
        report = inventory_report('<script src="https://cdn.example.net/private/app.js?token=never-export"></script>'
                                  '<script src="/same-origin.js"></script><script>inline()</script>'
                                  '<iframe src="https://frames.example.net/private/embed?id=never-export"></iframe>')
        original = deepcopy(report)
        with patch("websignal.network.Client.request") as request:
            markup, plain = html_report(report), text_report(report)
        request.assert_not_called()
        section = dependency_section(markup)
        self.assertIn("Script src references", section)
        self.assertIn("2 observed · 1 from other origins", section)
        self.assertIn("1 observed · 1 from other origins", section)
        self.assertIn("1 without usable metadata", section)
        self.assertIn("https://cdn.example.net", section)
        self.assertIn("https://frames.example.net", section)
        self.assertNotIn("never-export", markup)
        self.assertNotIn("private/app.js", plain)
        self.assertNotIn("private/embed", plain)
        self.assertIn("PAGE DEPENDENCIES", plain)
        self.assertIn("pin fixed versions", plain)
        self.assertIn("does not change the configuration score", section)
        self.assertEqual(report, original)
        self.assertEqual(json.loads(render(report, "json"))["assessment"]["value"], original["assessment"]["value"])

    def test_older_reports_show_unassessed_inventory_not_zero_dependencies(self):
        report = demo_report()
        report.pop("page_risks", None)
        section = dependency_section(html_report(report))
        self.assertIn("Not assessed", section)
        self.assertIn("saved report does not contain", section)
        self.assertNotIn("0 observed", section)
        self.assertNotIn("0 from other origins", section)
        self.assertIn("This is not a malware scan", section)

    def test_partial_counts_are_labeled_as_observed_lower_bounds(self):
        report = inventory_report('<script src="https://cdn.example.net/app.js"></script>', truncated=True)
        section = dependency_section(html_report(report))
        self.assertIn("Partial · observed counts are lower bounds", section)
        self.assertIn("1 observed · 1 from other origins", section)
        self.assertIn("some content, sources or details were unavailable", section)
        self.assertIn("At least 1 script", section)

    def test_real_zero_counts_are_distinct_from_missing_evidence(self):
        report = inventory_report('<title>Static page</title><p>No dependency declarations</p>')
        section = dependency_section(html_report(report))
        self.assertIn("Recorded from the returned HTML", section)
        self.assertIn("0 observed · 0 from other origins", section)
        self.assertIn("No cross-origin source was recorded", section)
        self.assertNotIn("Not assessed", section)
        self.assertIn("Inline code, srcdoc frames", section)

    def test_malformed_saved_origins_and_prose_cannot_expose_private_paths_or_active_html(self):
        payload = '<script>alert("private-payload")</script><img src=x onerror=alert(1)>'
        report = inventory_report('<script src="https://cdn.example.net/app.js"></script>')
        report["page_risks"]["origins"][0]["origin"] = "https://person:private-password@cdn.example.net/private-path?token=private-query"
        report["page_risks"].update(reason=payload, scope=payload, review={"why": payload, "action": payload})
        markup, plain = html_report(report), text_report(report)
        section = dependency_section(markup)
        self.assertIn("Not assessed", section)
        for secret in ("private-password", "private-path", "private-query", "private-payload"):
            self.assertNotIn(secret, markup)
            self.assertNotIn(secret, plain)
        parsed = Markup(markup)
        self.assertFalse(any(tag in {"script", "iframe", "img"} for tag, _ in parsed.tags))
        self.assertFalse(any(name.startswith("on") for _, attributes in parsed.tags for name in attributes))

    def test_untrusted_review_text_is_replaced_with_count_based_owner_guidance(self):
        report = inventory_report('<script src="https://cdn.example.net/app.js"></script>')
        report["page_risks"]["review"] = {"why": "Definitely malware-free", "action": "Trust all downloads"}
        section = dependency_section(html_report(report))
        self.assertNotIn("Definitely malware-free", section)
        self.assertNotIn("Trust all downloads", section)
        self.assertIn("content was not downloaded or checked", section)
        self.assertIn("Owner: confirm these sources are needed", section)

    def test_invalid_saved_counts_remain_unknown(self):
        for invalid in (-1, True, "5", None):
            with self.subTest(invalid=invalid):
                report = inventory_report('<script src="https://cdn.example.net/app.js"></script>')
                report["page_risks"]["script_count"] = invalid
                section = dependency_section(html_report(report))
                self.assertIn("Not assessed", section)
                self.assertNotIn("0 observed", section)


if __name__ == "__main__":
    unittest.main()
