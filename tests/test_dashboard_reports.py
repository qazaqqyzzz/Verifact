"""Export behavior: readable summaries, honest uncertainty and safe HTML."""

from html.parser import HTMLParser
import json
import unittest
from unittest.mock import patch

from verifact.ai import add_ai_sample
from verifact.assessment import enrich
from verifact.reports import html_report, render, text_report
from verifact.scanner import demo_report


class ReportMarkup(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.nodes = []
        self.feed(markup)

    def handle_starttag(self, tag, attributes):
        self.nodes.append((tag, dict(attributes)))


class DashboardReportTests(unittest.TestCase):
    def test_compact_summary_has_three_signals_and_working_evidence_links(self):
        report = demo_report()
        markup = html_report(report)
        parsed = ReportMarkup(markup)
        signals = [attrs for tag, attrs in parsed.nodes if tag == "article" and attrs.get("class") == "signal"]
        self.assertEqual(len(signals), 3)
        ids = {attrs["id"] for _, attrs in parsed.nodes if "id" in attrs}
        links = [attrs["href"][1:] for tag, attrs in parsed.nodes if tag == "a" and attrs.get("href", "").startswith("#finding-")]
        self.assertTrue(links)
        self.assertTrue(all(target in ids for target in links))
        self.assertLess(markup.index('class="overview"'), markup.index('id="all-findings"'))
        self.assertIn("70%", markup)
        self.assertIn("70/100 checklist points", markup)
        self.assertIn("WHAT TO REVIEW FIRST", text_report(report))

    def test_profile_and_findings_cannot_insert_active_html(self):
        report = demo_report()
        payload = '<script>alert("profile")</script><img src=x onerror=alert(1)>'
        report["site_profile"] = {"title": payload, "description": payload, "type": payload,
                                  "basis": payload, "hostname": report["domain"], "https": True,
                                  "http_status": 200}
        report["findings"][0]["evidence"] = payload
        markup = html_report(report)
        parsed = ReportMarkup(markup)
        self.assertFalse(any(tag in {"script", "img", "iframe"} for tag, _ in parsed.nodes))
        self.assertFalse(any(key.startswith("on") for _, attrs in parsed.nodes for key in attrs))
        self.assertIn("&lt;script&gt;", markup)

    def test_richer_profile_description_leads_and_remains_plain_text(self):
        report = demo_report()
        profile = dict(report["site_profile"])
        profile.update(summary='Likely a university login page. <script>alert(1)</script>',
                       signals=['Academic domain <img src=x onerror=alert(1)>'])
        with patch("verifact.reports.profile_for_report", return_value=profile):
            markup = html_report(report)
            plain = text_report(report)
        self.assertLess(markup.index('class="site-summary"'), markup.index('class="page-title"'))
        self.assertIn("Likely a university login page.", markup)
        self.assertIn("&lt;script&gt;", markup)
        self.assertIn("Academic domain &lt;img", markup)
        self.assertFalse(any(tag in {"script", "img"} for tag, _ in ReportMarkup(markup).nodes))
        self.assertLess(plain.index("Likely a university login page."), plain.index("Page title:"))

    def test_partial_assessment_shows_range_and_neutral_text(self):
        report = demo_report()
        for finding in report["findings"]:
            finding["status"] = "pass" if finding["id"] == "tls" else "unknown"
        report["assessment"] = {"value": 100}
        report["dashboard"] = {"rating": {"label": "Definitely safe", "tone": "green"}}
        markup = html_report(report)
        self.assertIn("25–100%", markup)
        self.assertIn("25–100/100", text_report(report))
        self.assertIn("Incomplete assessment", markup)
        self.assertIn('class="score-overview tone-unknown"', markup)
        self.assertNotIn("Definitely safe", markup)
        decoded = json.loads(render(report, "json"))
        self.assertEqual(decoded["assessment"]["coverage"], 25)
        self.assertEqual(decoded["dashboard"]["rating"]["tone"], "unknown")

    def test_no_evidence_is_not_rendered_as_zero_percent_safe(self):
        report = demo_report()
        for finding in report["findings"]:
            finding["status"] = "unknown"
        markup = html_report(report)
        self.assertIn('class="score-number">—', markup)
        self.assertIn("Not established", markup)
        self.assertNotIn('class="score-number">0%', markup)

    def test_missing_check_names_reasons_and_weights_appear_beside_score(self):
        report = demo_report()
        for finding in report["findings"]:
            if finding["id"] == "https_redirect":
                finding.update(status="unknown", evidence={"error": "timed out", "chain": []})
            if finding["id"] == "cookie_flags":
                finding.update(status="unknown", evidence={"limited": True})
        markup = html_report(report)
        plain = text_report(report)
        self.assertIn("What couldn’t be checked", markup)
        self.assertLess(markup.index("What couldn’t be checked"), markup.index('class="signal-section"'))
        self.assertIn("15 checklist points unassessed", markup)
        self.assertIn("Additional check; no score weight", markup)
        self.assertIn("HTTP entry point did not respond before the time limit", markup)
        self.assertIn("WHAT COULDN’T BE CHECKED", plain)
        self.assertIn("HTTP upgrades to HTTPS — 15 checklist points unassessed", plain)
        self.assertIn("Response cookie attributes — Additional check; no score weight", plain)
        parsed = ReportMarkup(markup)
        ids = {attrs["id"] for _, attrs in parsed.nodes if "id" in attrs}
        self.assertTrue(all(attrs["href"][1:] in ids for tag, attrs in parsed.nodes
                            if tag == "a" and attrs.get("href", "").startswith("#finding-")))
        self.assertNotIn("What couldn’t be checked", html_report(demo_report()))

    def test_coverage_gap_content_is_escaped_and_terminal_controls_removed(self):
        report = enrich(demo_report())
        payload = '<img src=x onerror="alert(1)">\x1b[2J'
        report["dashboard"]["coverage_gaps"] = [{"finding_id": "https_redirect", "weight": 15,
                                                   "title": "Missing " + payload, "detail": "Reason " + payload}]
        with patch("verifact.reports.enrich", return_value=report):
            markup, plain = html_report(report), text_report(report)
        self.assertIn("Missing &lt;img", markup)
        self.assertIn("Reason &lt;img", markup)
        self.assertFalse(any(tag in {"script", "img", "iframe"} for tag, _ in ReportMarkup(markup).nodes))
        self.assertNotIn("\x1b", plain)

    def test_ai_is_absent_without_generation_and_collapsed_when_present(self):
        markup = html_report(demo_report())
        parsed = ReportMarkup(markup)
        self.assertFalse(any("ai-section" in attrs.get("class", "").split() for _, attrs in parsed.nodes))
        markup = html_report(add_ai_sample(demo_report()))
        sections = [(tag, attrs) for tag, attrs in ReportMarkup(markup).nodes if "ai-section" in attrs.get("class", "").split()]
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0][0], "details")
        self.assertNotIn("open", sections[0][1])
        self.assertIn("Hand-authored example; no model call", markup)

    def test_new_ai_narrative_fields_are_labeled_and_escaped(self):
        report = add_ai_sample(demo_report())
        payload = '<img src=x onerror="alert(1)">\x1b[2J'
        report["ai"]["summary"] = "Overview " + payload
        item = report["ai"]["items"][0]
        item.update(explanation="Observed " + payload, why_it_matters="Practical meaning " + payload,
                    next_step="Review " + payload, limitation="Not established " + payload)
        markup = html_report(report)
        parsed = ReportMarkup(markup)
        self.assertFalse(any(tag in {"script", "img", "iframe"} for tag, _ in parsed.nodes))
        self.assertFalse(any(key.startswith("on") for _, attrs in parsed.nodes for key in attrs))
        for label in ("Report summary", "What we found", "Why it matters", "What to do next", "What this does not prove"):
            self.assertIn(label, markup)
        self.assertIn("Practical meaning &lt;img", markup)
        self.assertIn("Not established &lt;img", markup)
        output = text_report(report)
        for content in ("Overview", "Practical meaning", "Not established"):
            self.assertIn(content, output)
        self.assertNotIn("\x1b", output)
        self.assertEqual(report["ai"]["items"][0]["why_it_matters"], "Practical meaning " + payload)

    def test_older_ai_items_remain_readable_without_new_fields(self):
        report = add_ai_sample(demo_report())
        report["ai"].pop("summary", None)
        for item in report["ai"]["items"]:
            item.pop("why_it_matters", None)
            item.pop("limitation", None)
        explanation = report["ai"]["items"][0]["explanation"]
        markup = html_report(report)
        self.assertIn(explanation, text_report(report))
        self.assertIn("What we found", markup)
        self.assertNotIn('<div class="ai-summary">', markup)
        self.assertNotIn('<h3>Why it matters</h3>', markup)


if __name__ == "__main__":
    unittest.main()
