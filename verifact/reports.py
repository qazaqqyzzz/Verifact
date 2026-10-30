"""Reports contain selected evidence, never complete bodies or cookie values."""

from collections import Counter
from functools import lru_cache
from pathlib import Path
import base64
import html
import json
import unicodedata

from .assessment import enrich
from .check_feedback import check_feedback_for_report
from .profile import profile_for_report


@lru_cache(maxsize=1)
def _report_fonts():
    """Keep downloaded reports self-contained, including their font licenses."""
    font_dir = Path(__file__).with_name("static") / "fonts"
    styles, licenses = [], []
    for family, filename, license_name, weight in [
        ("Space Grotesk", "SpaceGrotesk.ttf", "SpaceGrotesk-OFL.txt", "300 700"),
        ("IBM Plex Mono", "IBMPlexMono-Regular.ttf", "IBMPlexMono-OFL.txt", "400"),
    ]:
        encoded = base64.b64encode((font_dir / filename).read_bytes()).decode("ascii")
        styles.append(f"@font-face {{font-family:'{family}';src:url(data:font/ttf;base64,{encoded}) format('truetype');font-style:normal;font-weight:{weight};font-display:swap}}")
        license_text = (font_dir / license_name).read_text(encoding="utf-8")
        licenses.append(f"<!-- {family} font license\n{license_text}\n-->")
    return "\n".join(styles), "\n".join(licenses)


def clean_text(value):
    # Site-controlled content must not inject terminal escape/control sequences.
    return "".join(c for c in str(value) if c in "\n\t" or not unicodedata.category(c).startswith("C"))


def _score_label(assessment):
    if assessment["value"] is None:
        return "Not established"
    if assessment["unknown_weight"]:
        return f"{assessment['value']}–{assessment['potential']}/100"
    return f"{assessment['value']}/100"


def _score_percent(assessment):
    if assessment["value"] is None:
        return "—"
    if assessment["unknown_weight"]:
        return f"{assessment['value']}–{assessment['potential']}%"
    return f"{assessment['value']}%"


def _tone(value):
    return value if value in {"green", "amber", "red", "unknown"} else "unknown"


def _prepare_report(report):
    """Derive presentation from evidence; saved feedback is not authoritative."""
    result = enrich(report)
    result["check_feedback"] = check_feedback_for_report(result)
    return result


def _feedback(report, identifier):
    return report["check_feedback"].get(identifier, {
        "state": "unknown", "result": "Not assessed",
        "fact": "Duplicate or unsupported check data cannot be interpreted reliably.",
        "fix": "Run this check again with the current version of Verifact.",
    })


def _gap_weight(gap):
    weight = gap.get("weight")
    return f"{weight} checklist points unassessed" if type(weight) is int and weight > 0 else "Additional check; no score weight"


def _dashboard_text(report):
    profile = profile_for_report(report)
    dashboard = report["dashboard"]
    lines = ["SITE OVERVIEW", profile["type"],
             profile.get("summary") or "The page's purpose could not be established from the available observations.",
             "Page title: " + (profile["title"] or "Unavailable"),
             "How identified: " + profile["basis"]]
    if profile["description"]:
        lines.append("Site-provided description: " + profile["description"])
    lines.extend(["", "DEVELOPER CONFIGURATION / " + dashboard["rating"]["label"],
                  dashboard["rating"]["summary"]])
    for signal in dashboard["signals"]:
        lines.append(f"  {signal['title']}: {signal['label']}. {signal['detail']}")
    lines.extend(["", "WHAT TO REVIEW FIRST"])
    for item in dashboard["priorities"]:
        feedback = _feedback(report, item["finding_id"])
        lines.extend([f"  [{item['finding_id']}] {item['title']}",
                      "  Result: " + feedback["result"],
                      "  Fact: " + feedback["fact"],
                      "  Fix: " + feedback["fix"]])
    if not dashboard["priorities"]:
        lines.append("No review items were identified in the observed security checks. This is not a security certification.")
    return lines + [""]


def _dashboard_html(report, escape):
    e = escape
    score = report["assessment"]
    dashboard = report["dashboard"]
    rating = dashboard["rating"]
    profile = profile_for_report(report)
    indices = {finding["id"]: index for index, finding in enumerate(report["findings"])}
    description = f'<p class="site-description"><strong>Site-provided description</strong>{e(profile["description"])}</p>' if profile["description"] else ""
    profile_summary = profile.get("summary") or "The page's purpose could not be established from the available observations."
    profile_signals = "".join(f'<li>{e(signal)}</li>' for signal in profile.get("signals", []) if isinstance(signal, str))
    signal_list = f'<ul class="profile-signals">{profile_signals}</ul>' if profile_signals else ""
    title = profile["title"] or "Page title unavailable"
    location = "Returned host: " + (profile["hostname"] or "unavailable")
    if profile["http_status"] is not None:
        location += " · " + ("HTTPS" if profile["https"] else "HTTP") + " response " + str(profile["http_status"])
    score_caption = _score_label(score) + (" checklist points" if score["value"] is not None else "")
    gap_items = []
    for gap in dashboard.get("coverage_gaps", []):
        gap_title = e(gap["title"])
        if gap["finding_id"] in indices:
            gap_title = f'<a href="#finding-{indices[gap["finding_id"]]}">{gap_title}</a>'
        gap_items.append(f'<li><strong>{gap_title}</strong><span>{e(_gap_weight(gap))}</span><p>{e(gap["detail"])}</p></li>')
    coverage_gaps = (f'<div class="coverage-gaps"><h3>What couldn’t be checked</h3><ul>{"".join(gap_items)}</ul></div>'
                     if gap_items else "")
    signals = []
    for signal in dashboard["signals"]:
        references = []
        for identifier in signal["finding_ids"]:
            if identifier in indices:
                references.append(f'<a href="#finding-{indices[identifier]}">{e(identifier.replace("_", " "))}</a>')
        signals.append(f'<article class="signal"><h3>{e(signal["title"])}</h3>'
                       f'<div class="signal-status tone-{_tone(signal["tone"])}"><span class="light" aria-hidden="true"></span>{e(signal["label"])}</div>'
                       f'<p>{e(signal["detail"])}</p><div class="signal-links">{" · ".join(references)}</div></article>')
    priorities = []
    for item in dashboard["priorities"]:
        index = indices.get(item["finding_id"])
        if index is None:
            continue
        feedback = _feedback(report, item["finding_id"])
        next_step = f'<p class="next"><strong>Fix</strong>{e(feedback["fix"])}</p>'
        priorities.append(f'<li><span class="priority-index tone-{_tone(item["tone"])}">{len(priorities) + 1:02d}</span>'
                          f'<div><a class="priority-title" href="#finding-{index}">{e(item["title"])}</a>'
                          f'<p><strong>Fact</strong> {e(feedback["fact"])}</p>{next_step}</div><a class="evidence-link" href="#finding-{index}">Open test ↗</a></li>')
    if not priorities:
        priorities.append('<li class="no-priorities">No review items were identified in the observed security checks. This is not a security certification.</li>')
    return (f'<section class="overview" aria-label="Website and security overview"><div class="site-overview">'
            f'<span class="eyebrow">01 / THE WEBSITE</span><h2>{e(profile["type"])}</h2>'
            f'<p class="site-summary">{e(profile_summary)}</p><p class="page-title"><strong>Page title</strong>{e(title)}</p>'
            f'<p class="profile-location">{e(location)}</p>'
            f'<details class="profile-details"><summary>How this website was identified</summary><p class="profile-basis">{e(profile["basis"])}</p>{signal_list}{description}</details></div>'
            f'<div class="score-overview tone-{_tone(rating["tone"])}"><span class="eyebrow">02 / DEVELOPER CONFIGURATION</span>'
            f'<strong class="score-number">{e(_score_percent(score))}</strong><span class="score-points">{e(score_caption)}</span>'
            f'<div class="signal-status"><span class="light" aria-hidden="true"></span>{e(rating["label"])}</div>'
            f'<p>{e(rating["summary"])}</p><span class="coverage">{score["coverage"]}% evidence coverage · {score["assessed_checks"]}/{score["total_checks"]} checks assessed</span>'
            f'{coverage_gaps}</div></section><p class="dashboard-note">For website owners: a public configuration checklist, not the probability that a website is safe. Link check guidance and threat-list results are separate. Unknown checks remain unassessed.</p>'
            '<section class="signal-section" aria-labelledby="signals-heading"><div class="section-heading">'
            '<span class="eyebrow">SECURITY SIGNALS</span><h2 id="signals-heading">Three key security signals</h2></div>'
            f'<div class="signals">{"".join(signals)}</div></section>'
            '<section class="priorities" aria-labelledby="priorities-heading"><div class="section-heading"><span class="eyebrow">03 / THE IMPORTANT PART</span>'
            f'<h2 id="priorities-heading">What to review first</h2></div><ol>{"".join(priorities)}</ol></section>')


def _assessment_text(report):
    score = report["assessment"]
    lines = ["DEVELOPER " + score["label"].upper() + " / " + _score_label(score),
             f"Coverage: {score['coverage']}% of checklist weight; "
             f"{score['assessed_checks']}/{score['total_checks']} checks assessed."]
    if score["unknown_weight"]:
        lines.append(f"{score['earned']} confirmed points; {score['unknown_weight']} points remain unassessed. "
                     "The range is not a failure rate or statistical confidence interval.")
    else:
        lines.append(f"{score['earned']}% of this configuration checklist's points earned.")
    gaps = report["dashboard"].get("coverage_gaps", [])
    if gaps:
        lines.extend(["", "WHAT COULDN’T BE CHECKED"])
        for gap in gaps:
            lines.append(f"  {gap['title']} — {_gap_weight(gap)}. {gap['detail']}")
        lines.append("")
    lines.extend([score["disclaimer"], "", "SCORING METHODOLOGY / " + score["method_version"]])
    lines.extend("  " + entry for entry in score["methodology"])
    for item in score["items"]:
        outcome = f"{item['earned']}/{item['weight']} points" if item["assessed"] else f"{item['weight']} points unassessed"
        lines.append(f"  {item['title']}: {outcome}. {item['note']}")
    lines.extend(["", "Built-in explanations appear as Result, Fact and Fix under each test. No AI request is needed."])
    lines.append("")
    return lines


def _assessment_html(report, escape):
    e = escape
    score = report["assessment"]
    findings = {item["id"]: (index, item) for index, item in enumerate(report["findings"])}
    rows = []
    for item in score["items"]:
        matched = findings.get(item["finding_id"])
        title = e(item["title"])
        if matched:
            title = f'<a href="#finding-{matched[0]}">{title}</a>'
        result = f'{item["earned"]}/{item["weight"]}' if item["assessed"] else "Unassessed"
        rows.append(f'<tr><th scope="row">{title}</th><td>{item["weight"]}</td>'
                    f'<td>{result}</td><td>{e(item["note"])}</td></tr>')
    methodology = "".join(f"<li>{e(line)}</li>" for line in score["methodology"])
    meaning = (f'{score["earned"]} confirmed points; {score["unknown_weight"]} points remain unassessed. '
               'The upper end assumes those checks would earn full credit. This is not a statistical confidence interval.'
               if score["unknown_weight"] else f'{score["earned"]}% of this configuration checklist’s points earned.')
    return (f'<details class="report-disclosure score-section"><summary>How the score and lights work</summary>'
            f'<h2 id="score-heading">{e(score["label"])}</h2><p>{meaning}</p><p>{e(score["disclaimer"])}</p>'
            f'<p>{e(report["dashboard"]["rating"]["methodology"])}</p><p>Method: {e(score["method_version"])}</p>'
            f'<ul>{methodology}</ul><div class="score-table"><table><thead><tr><th>Check</th><th>Weight</th><th>Earned</th><th>Interpretation</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
            '<p>Built-in explanations appear as Result, Fact and Fix under <a href="#all-findings">each test</a>. No AI request is needed.</p></details>')


def _ai_text(report):
    ai = report.get("ai")
    if not ai:
        return []
    findings = {item["id"]: item for item in report["findings"]}
    lines = ["AI EXPLANATION / review suggested"]
    if ai.get("fixture"):
        lines.append("ILLUSTRATIVE FIXTURE — hand-authored example; no model call")
    lines.append(f"Provider: {ai['provider']} · Model: {ai['model']} · Generated: {ai['generated_at']}")
    lines.append("Citation checks confirm structure and known finding IDs, not factual accuracy.")
    if ai.get("summary"):
        lines.extend(["", "REPORT SUMMARY", ai["summary"], ""])
    for item in ai["items"]:
        finding = findings.get(item["finding_id"])
        citation = f"{finding['title']} [{finding['status'].upper()}]" if finding else "Unmatched finding"
        lines.extend([f"  [{item['finding_id']}] {citation}", "  What we found: " + item["explanation"]])
        if item.get("why_it_matters"):
            lines.append("  Why it matters: " + item["why_it_matters"])
        if item["next_step"]:
            lines.append("  What to do next: " + item["next_step"])
        if item.get("limitation"):
            lines.append("  What this does not prove: " + item["limitation"])
        lines.append("")
    if ai.get("unassessed_finding_ids"):
        lines.append("Evidence remains unknown for: " + ", ".join(ai["unassessed_finding_ids"]))
    usage = ai.get("usage") or {}
    if usage.get("input_tokens") is not None or usage.get("output_tokens") is not None:
        lines.append(f"Token usage: input {usage.get('input_tokens')}, output {usage.get('output_tokens')}")
    lines.extend(["", "RECORDED FINDINGS", ""])
    return lines


def _ai_html(report, escape):
    ai = report.get("ai")
    if not ai:
        return ""
    e = escape
    findings = {item["id"]: (index, item) for index, item in enumerate(report["findings"])}
    items = []
    for item in ai["items"]:
        matched = findings.get(item["finding_id"])
        if matched:
            index, finding = matched
            citation = (f'<a class="ai-citation" href="#finding-{index}">{e(finding["title"])} '
                        f'<span>· {e(finding["status"])} · view evidence</span></a>')
        else:
            citation = f'<span class="ai-citation">Unmatched finding: {e(item["finding_id"])}</span>'
        sections = [f'<div class="ai-reason"><h3>What we found</h3><p class="ai-copy">{e(item["explanation"])}</p></div>']
        if item.get("why_it_matters"):
            sections.append(f'<div class="ai-reason"><h3>Why it matters</h3><p>{e(item["why_it_matters"])}</p></div>')
        if item.get("next_step"):
            sections.append(f'<div class="ai-reason ai-next"><h3>What to do next</h3><p>{e(item["next_step"])}</p></div>')
        if item.get("limitation"):
            sections.append(f'<div class="ai-reason ai-limit"><h3>What this does not prove</h3><p>{e(item["limitation"])}</p></div>')
        items.append(f'<li>{citation}<div class="ai-reasons">{"".join(sections)}</div></li>')
    fixture = '<p class="ai-fixture">Illustrative fixture · Hand-authored example; no model call.</p>' if ai.get("fixture") else ""
    summary = (f'<div class="ai-summary"><h3>Report summary</h3><p>{e(ai["summary"])}</p></div>'
               if ai.get("summary") else "")
    unknown = ""
    if ai.get("unassessed_finding_ids"):
        links = []
        for identifier in ai["unassessed_finding_ids"]:
            matched = findings.get(identifier)
            if matched:
                index, finding = matched
                links.append(f'<a href="#finding-{index}">{e(finding["title"])}</a>')
            else:
                links.append(e(identifier))
        unknown = f'<p class="ai-unknown"><strong>Evidence remains unknown:</strong> {", ".join(links)}.</p>'
    usage = ai.get("usage") or {}
    usage_text = ""
    if usage.get("input_tokens") is not None or usage.get("output_tokens") is not None:
        usage_text = f'<br>Tokens: input {e(usage.get("input_tokens"))} · output {e(usage.get("output_tokens"))}'
    provenance = (f'<details class="ai-provenance"><summary>Model and validation details</summary>'
                  f'<p>{e(ai["provider"])} / {e(ai["model"])}<br>{e(ai["generated_at"])}'
                  f'<br>Prompt version: {e(ai["prompt_version"])}{usage_text}</p>'
                  f'<p>{e(ai["validation"])}</p></details>')
    return (f'<details class="report-disclosure ai-section"><summary>AI explanation · optional second perspective</summary><div class="ai-heading">'
            f'<h2 id="ai-heading">AI explanation</h2><span class="ai-review">Review suggested</span></div>'
            f'{fixture}<p class="ai-intro">A model’s interpretation of the recorded findings. '
            f'Follow each citation to inspect its source. Citation checks confirm structure and known finding IDs, not factual accuracy.</p>'
            f'{summary}<ol class="ai-items">{"".join(items)}</ol>{unknown}{provenance}</details>')


def _short(value, limit=1600):
    text = clean_text(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _link_details(report):
    link = report.get("link_analysis")
    if not isinstance(link, dict):
        return []
    lines = [("Checked link", _short(link.get("input_url") or report.get("target_url") or "Not recorded")),
             ("Final destination", _short(link.get("final_url") or "Not reached"))]
    if link.get("expected_domain"):
        lines.append(("Expected domain", _short(link["expected_domain"], 300)))
    if link.get("expected_match") is True:
        lines.append(("Domain comparison", "The returned host matches the expected domain or one of its subdomains. This does not establish its legitimacy."))
    elif link.get("expected_match") is False:
        lines.append(("Domain comparison", "The returned host does not match the expected domain or one of its subdomains."))
    redirects = link.get("redirects")
    if isinstance(redirects, list):
        for index, hop in enumerate(redirects[:12], 1):
            if isinstance(hop, dict):
                lines.append((f"Step {index}", _short(hop.get("url", "URL unavailable")) + " · HTTP " + _short(hop.get("status", "unknown"), 20)))
    if link.get("completed") is False:
        lines.append(("Trail status", "The submitted link did not reach a completed response. " + _short(link.get("error") or "See recorded evidence for the request limit or error.", 500)))
    warnings = link.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings[:12]:
            if isinstance(warning, dict):
                lines.append((_short(warning.get("title", "Link observation"), 180), _short(warning.get("detail", ""), 1000)))
    if link.get("note"):
        lines.append(("Interpretation", _short(link["note"])))
    lines.append(("Report privacy", "This report includes the checked URL path and query. Review it before sharing."))
    return lines


def _reputation_details(report):
    reputation = report.get("reputation")
    if not isinstance(reputation, dict):
        return []
    from .reputation import public_result
    reputation = public_result(reputation)
    # A downloaded document cannot expire its warning when reopened offline.
    # Preserve only neutral lookup provenance, never an active stale verdict.
    lines = [("Provider", _short(reputation.get("provider") or "Not selected", 120))]
    if reputation.get("checked_at"):
        lines.append(("Lookup recorded", _short(reputation["checked_at"], 80)))
        if reputation.get("expires_at"):
            lines.append(("Provider validity ended / ends", _short(reputation["expires_at"], 80)))
        lines.append(("Snapshot only", "A provider lookup was recorded at the time above. This saved report does not display a current threat warning or clearance. Run a new lookup in Verifact for a current result."))
    else:
        status = reputation.get("status")
        lines.append(("Lookup status", "Not checked" if status == "not_checked" else "Unavailable"))
        if reputation.get("detail"):
            lines.append(("Details", _short(reputation["detail"])))
    lines.append(("Separate from the score", "Threat reputation is separate from the configuration checklist percentage. No known match does not mean a link is safe; false positives and false negatives are possible."))
    if reputation.get("attribution"):
        lines.append(("Attribution", _short(reputation["attribution"], 200)))
    return lines


def _visitor_details(report):
    """Offline files show page observations, never a live provider verdict."""
    if not isinstance(report.get("visitor_assessment"), dict) and not isinstance(report.get("community_reputation"), dict):
        return []
    from .visitor_assessment import build_visitor_assessment
    observations = dict(report)
    # A static document cannot remove a provider warning when it expires. Keep
    # external lookups in separate historical-provenance sections instead.
    observations.pop("reputation", None)
    observations.pop("community_reputation", None)
    visitor = build_visitor_assessment(observations)
    lines = [("Recorded page", _short(report.get("created_at") or "Time unavailable", 80)),
             ("Snapshot scope", "Recorded page, connection and destination observations. This offline file does not provide a current threat verdict or a percentage safe.")]
    coverage = visitor["coverage"]
    lines.append(("Evidence coverage", " · ".join(name.capitalize() + ": " + coverage[name]
                                                  for name in ("page", "connection", "destination"))))
    reasons = [reason for reason in visitor["reasons"] if reason["source"] not in {"community", "reputation"}]
    for reason in reasons:
        lines.append((_short(reason["title"], 180), _short(reason["detail"], 700)))
    if not reasons:
        lines.append(("Recorded observations", "No visitor warning was established from these page and link observations. This does not establish that the website or its owner is trustworthy."))
    lines.append(("Next step", visitor["next_action"]))
    lines.append(("External lists", "Community and Google lookups, if recorded, appear separately as historical context. Run a new check in Verifact for a current result."))
    return lines


def _community_details(report):
    if not isinstance(report.get("community_reputation"), dict):
        return []
    from .threat_feed import community_for_report
    result = community_for_report(report)
    lines = [("Provider", result["provider"]), ("Source", result["source_url"])]
    for key, label in (("checked_at", "Lookup recorded"), ("fetched_at", "Feed retrieved"),
                       ("expires_at", "Feed validity ended / ends")):
        if result.get(key):
            lines.append((label, _short(result[key], 80)))
    if result.get("checked_at"):
        lines.append(("Snapshot only", "A community-list check was recorded at the time above. This saved file does not display a current domain warning or clearance. Run a new check in Verifact for a current result."))
    else:
        lines.append(("Lookup status", "Not checked" if result["status"] == "not_checked" else "Unavailable"))
    if result.get("checked_hosts"):
        lines.append(("Hostnames checked", ", ".join(result["checked_hosts"])))
    lines.extend([("Coverage", result["scope"]), ("Privacy", result["privacy_note"]),
                  ("Interpretation", result["notice"]),
                  ("Separate from the score", "This domain-list lookup never changes the developer configuration checklist percentage.")])
    return lines


def _hygiene_details(report):
    from .brief import build_brief
    reviews = [item for item in build_brief(report)["all_reviews"] if item["source"] == "hygiene"]
    if not reviews:
        return []
    lines = [("Scope", "Additional developer reviews from the returned response. These do not change the ten core counts, eight weighted checks or link-check verdict.")]
    for item in reviews:
        lines.append((item["title"], item["why"]))
        lines.append(("Next step", item["action"]))
    return lines


def _comparison_details(report):
    comparison = report.get("comparison")
    if not isinstance(comparison, dict):
        return []
    lines = [("Summary", _short(comparison.get("summary") or comparison.get("reason") or "No comparison available.", 700))]
    if not comparison.get("available"):
        if comparison.get("reason"):
            lines.append(("Scope", _short(comparison["reason"], 700)))
        return lines
    if comparison.get("previous_created_at"):
        lines.append(("Previous snapshot", _short(comparison["previous_created_at"], 80)))
    if comparison.get("current_created_at"):
        lines.append(("Current snapshot", _short(comparison["current_created_at"], 80)))
    changes = comparison.get("changes")
    if isinstance(changes, list):
        for change in changes[:25]:
            if isinstance(change, dict):
                title = _short(change.get("title", "Recorded change"), 180)
                lines.append((title + " · Before", _short(change.get("before", "Not recorded"), 900)))
                lines.append((title + " · After", _short(change.get("after", "Not recorded"), 900)))
    lines.append(("Interpretation", _short(comparison.get("note") or "Changes describe two snapshots, not proof of an attack or an improvement.", 700)))
    return lines


def _dependency_details(report):
    """Only bounded inventory counts and source origins belong in an export."""
    from .page_risks import page_risks_for_report
    inventory = page_risks_for_report(report)
    status = inventory.get("status")
    if status not in {"assessed", "partial"}:
        return [("Inventory", "Not assessed"),
                ("Reason", _short(inventory.get("reason") or "This report has no recorded dependency inventory. Check the link again to collect it.", 500)),
                ("Scope", "No dependency counts were established. This is not a malware scan.")]

    def number(key):
        value = inventory.get(key)
        return str(value) if type(value) is int and value >= 0 else "Unknown"

    lines = [("Inventory", "Partial · observed counts are lower bounds" if status == "partial" else "Recorded from the returned HTML"),
             ("Script src references", number("script_count") + " observed · " + number("cross_origin_scripts") + " from other origins"),
             ("Frame src references", number("iframe_count") + " observed · " + number("cross_origin_iframes") + " from other origins"),
             ("Cross-origin script integrity", number("integrity_present") + " with usable metadata · " + number("without_integrity")
              + " without usable metadata · " + number("integrity_unknown") + " unknown. Resource bytes and hashes were not checked.")]
    if inventory.get("reason"):
        lines.append(("Coverage", _short(inventory["reason"], 500)))
    unresolved = inventory.get("unresolved_count")
    if type(unresolved) is int and unresolved > 0:
        lines.append(("Unresolved references", str(unresolved) + " references could not be assigned a supported origin."))
    origins = inventory.get("origins")
    sources = []
    for item in origins[:20] if isinstance(origins, list) else []:
        if isinstance(item, dict) and isinstance(item.get("origin"), str):
            scripts, frames = item.get("scripts"), item.get("iframes")
            scripts = str(scripts) if type(scripts) is int and scripts >= 0 else "unknown"
            frames = str(frames) if type(frames) is int and frames >= 0 else "unknown"
            sources.append(_short(item["origin"], 320) + " · scripts: " + scripts + " · frames: " + frames)
    lines.append(("Source origins", "\n".join(sources) if sources else "No cross-origin source was recorded in the inspected HTML."))
    omitted = inventory.get("origins_omitted")
    if type(omitted) is int and omitted > 0:
        lines.append(("Origin list", str(omitted) + " additional origins are outside the retained list."))
    review = inventory.get("review")
    if isinstance(review, dict):
        if review.get("why"):
            lines.append(("Review", _short(review["why"], 500)))
        if review.get("action"):
            lines.append(("Next step", _short(review["action"], 500)))
    lines.extend([("Interpretation", "Cross-origin means a different scheme, hostname or port; it does not establish a different owner. Paths, query strings and script contents are not included in this inventory."),
                  ("Scope", "Static script-src and iframe-src declarations only. Inline code, srcdoc frames, stylesheets, module imports and JavaScript-created requests are outside this inventory. Dependencies are not downloaded or executed; vulnerabilities and malicious behavior are not assessed. This inventory does not change the configuration score.")])
    return lines


def _dependency_html(report, escape):
    body = "".join(f'<div><dt>{escape(label)}</dt><dd>{escape(value)}</dd></div>'
                   for label, value in _dependency_details(report))
    return ('<details class="report-disclosure dependency-details"><summary>Page dependencies</summary>'
            f'<dl>{body}</dl></details>')


def _additional_text(report):
    lines = []
    for title, details in (("LINK DETAILS", _link_details(report)),
                           ("PAGE DEPENDENCIES", _dependency_details(report)),
                           ("ADDITIONAL DEVELOPER REVIEWS / UNSCORED", _hygiene_details(report)),
                           ("COMMUNITY FEED / HISTORICAL CONTEXT", _community_details(report)),
                           ("KNOWN-THREAT LOOKUP / SEPARATE FROM CONFIGURATION", _reputation_details(report)),
                           ("SNAPSHOT COMPARISON", _comparison_details(report))):
        if details:
            lines.append(title)
            lines.extend(label + ": " + value for label, value in details)
            lines.append("")
    return lines


def _additional_html(report, escape):
    e = escape
    sections = []
    for title, details, extra_class in (("Link details & redirect trail", _link_details(report), ""),
                                       ("Additional developer reviews · unscored", _hygiene_details(report), " hygiene-details"),
                                       ("Community feed · historical context", _community_details(report), " community-details"),
                                       ("Known-threat lookup · separate from configuration", _reputation_details(report), ""),
                                       ("Changes since the previous check", _comparison_details(report), "")):
        if details:
            body = "".join(f'<div><dt>{e(label)}</dt><dd>{e(value)}</dd></div>' for label, value in details)
            sections.append(f'<details class="report-disclosure link-details{extra_class}"><summary>{e(title)}</summary><dl>{body}</dl></details>')
    return "".join(sections)


def text_report(report):
    report = _prepare_report(report)
    states = Counter(_feedback(report, finding["id"])["state"] for finding in report["findings"])
    lines = [f"VERIFACT / {report['domain']}",
             "SYNTHETIC DEMO — no network requests" if report["demo"] else report["created_at"],
             " · ".join(f"{states[k]} {k}" for k in ("pass", "attention", "info", "unknown")), ""]
    visitor = _visitor_details(report)
    if visitor:
        lines.append("LINK CHECK SNAPSHOT / NO SAFETY PERCENTAGE")
        lines.extend(label + ": " + value for label, value in visitor)
        lines.append("")
    lines.extend(_dashboard_text(report))
    lines.extend(_additional_text(report))
    lines.extend(_assessment_text(report))
    lines.extend(_ai_text(report))
    for finding in report["findings"]:
        feedback = _feedback(report, finding["id"])
        lines.extend(["Test: " + finding["title"],
                      "  Result: " + feedback["result"],
                      "  Fact: " + feedback["fact"],
                      "  Fix: " + feedback["fix"]])
        if finding["id"] == "certificate_expiry":
            lines.extend("  " + metric["label"] + ": " + metric["value"] for metric in finding.get("presentation", {}).get("metrics", []))
        lines.append("  Evidence: " + json.dumps(finding["evidence"], ensure_ascii=False))
        lines.append("")
    lines.append("Scope: " + report["scope"])
    return clean_text("\n".join(lines)) + "\n"


def html_report(report):
    report = _prepare_report(report)
    e = lambda value: html.escape(clean_text(value), quote=True)
    states = Counter(_feedback(report, finding["id"])["state"] for finding in report["findings"])
    counts = " · ".join(f'{states[status]} {label}'
                        for status, label in [("pass", "passed"), ("attention", "need review"), ("info", "observations"), ("unknown", "unknown")])
    groups = []
    for category, label in (("Transport", "Connection"), ("Browser", "Browser protection"), ("Domain", "Domain context"), ("Quality", "Page details")):
        cards = []
        for index, item in enumerate(report["findings"]):
            if item["category"] != category:
                continue
            feedback = _feedback(report, item["id"])
            status = feedback["state"]
            evidence = json.dumps(item["evidence"], indent=2, ensure_ascii=False) if not isinstance(item["evidence"], str) else item["evidence"]
            metrics = ""
            if item["id"] == "certificate_expiry":
                metrics = "".join(f'<p><strong>{e(metric["value"])}</strong> · {e(metric["label"])}</p>' for metric in item.get("presentation", {}).get("metrics", []))
            cards.append(f'<article id="finding-{index}" tabindex="-1"><div class="card-title"><div><span class="feedback-label">Test</span><h3>{e(item["title"])}</h3></div>'
                         f'<div class="feedback-result"><span class="feedback-label">Result</span><span class="badge {e(status)}">{e(feedback["result"])}</span></div></div>'
                         f'{metrics}<dl class="check-feedback"><div><dt>Fact</dt><dd>{e(feedback["fact"])}</dd></div>'
                         f'<div><dt>Fix</dt><dd>{e(feedback["fix"])}</dd></div></dl><details><summary>Recorded evidence</summary><pre>{e(evidence)}</pre></details></article>')
        if cards:
            groups.append(f'<section><h2>{e(label)}</h2>{"".join(cards)}</section>')
    limitations = "".join(f"<li>{e(x)}</li>" for x in report["limitations"])
    banner = '<div class="demo">SYNTHETIC DEMO · All observations below are fixtures. No live site was scanned.</div>' if report["demo"] else ""
    ai_section = _ai_html(report, e)
    assessment_section = _assessment_html(report, e)
    dashboard_section = _dashboard_html(report, e)
    additional_sections = _additional_html(report, e)
    dependency_section = _dependency_html(report, e)
    visitor_details = _visitor_details(report)
    visitor_section = ('<section class="visitor-snapshot"><span class="eyebrow">LINK CHECK SNAPSHOT</span>'
                       '<h2>What the recorded evidence means for a visitor</h2><dl>'
                       + "".join(f'<div><dt>{e(label)}</dt><dd>{e(value)}</dd></div>' for label, value in visitor_details)
                       + '</dl></section>') if visitor_details else ""
    font_styles, font_licenses = _report_fonts()
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'">
{font_licenses}
<title>Verifact · {e(report['domain'])}</title><style>
{font_styles}
:root {{color-scheme:dark;--ink:#edf2fa;--muted:#aebbcf;--line:#283a52;--paper:#0b1423;--card:#111e30;--surface:#18283c;--accent:#a9c8ff;--green:#82dca7;--amber:#edb260;--red:#f28f8b;--neutral:#adb9cb}}
* {{box-sizing:border-box}} body {{margin:0;background:linear-gradient(155deg,#18283c 0%,var(--paper) 45%,#101c2e 100%);color:var(--ink);font:16px/1.65 'Space Grotesk',system-ui,-apple-system,sans-serif}}
a {{color:inherit;text-underline-offset:3px}} main {{max-width:1100px;margin:auto;padding:42px 30px 70px}}
.brand,.eyebrow,.meta,.badge,.priority-index {{font-family:'IBM Plex Mono',ui-monospace,monospace}}
.brand {{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:22px;font-size:14px;letter-spacing:.08em}}
.brand strong {{color:var(--accent);display:inline-flex;align-items:center;gap:8px}} .brand-check {{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}} .brand span {{color:var(--muted);font-size:12px}} header {{margin:30px 0 24px}}
.eyebrow {{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}} h1 {{font-size:clamp(27px,4vw,40px);line-height:1.2;margin:8px 0 12px;overflow-wrap:anywhere;letter-spacing:-.04em}}
.meta {{font-size:12px;color:var(--muted)}} h2 {{font-size:22px;margin:0 0 12px;line-height:1.4;letter-spacing:-.02em}} h3 {{font-size:16px;margin:0;line-height:1.5}}
p {{font-size:16px;margin:12px 0;color:var(--muted)}} .overview {{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,1fr);border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--card)}}
.site-overview {{padding:30px}} .site-overview h2 {{font-size:26px;line-height:1.3;margin:20px 0 14px;overflow-wrap:anywhere}}
.site-type {{display:inline-block;padding:4px 9px;background:var(--surface);border:1px solid var(--line);border-radius:5px;font-size:12px}}
.site-description {{overflow-wrap:anywhere}} .site-description strong,.page-title strong {{display:block;font-size:12px;color:var(--muted);font-weight:500;margin-bottom:5px}}
.site-summary {{font-size:18px;color:var(--ink);line-height:1.7;margin:16px 0 22px;overflow-wrap:anywhere}}
.page-title {{font-size:14px;overflow-wrap:anywhere;padding-top:16px;border-top:1px solid var(--line)}}
.profile-details {{border-top:1px solid var(--line);padding-top:16px;margin-top:18px}} .profile-details summary {{font-size:14px;cursor:pointer}}
.profile-basis,.profile-signals {{font-size:14px;color:var(--muted);line-height:1.75}} .profile-signals {{padding-left:20px}}
.score-overview {{padding:30px;border-left:1px solid var(--line);display:flex;align-items:flex-start;flex-direction:column;--tone:var(--neutral)}}
.score-number {{color:var(--tone);font-size:clamp(42px,6vw,66px);font-weight:600;line-height:1;letter-spacing:-.06em;margin:23px 0 7px}}
.score-points {{font-size:12px;color:var(--muted)}} .score-overview .signal-status {{margin-top:20px}} .score-overview p {{font-size:14px;margin:10px 0 14px}}
.coverage {{font-size:12px;color:var(--muted)}} .tone-green {{--tone:var(--green)}} .tone-amber {{--tone:var(--amber)}} .tone-red {{--tone:var(--red)}} .tone-unknown {{--tone:var(--neutral)}}
.coverage-gaps {{width:100%;margin-top:18px;padding-top:16px;border-top:1px solid var(--line);overflow-wrap:anywhere}}
.coverage-gaps ul {{padding-left:18px;margin:12px 0 0}} .coverage-gaps li {{font-size:14px;margin-top:14px}}
.coverage-gaps li span {{display:block;font-size:12px;color:var(--muted);margin-top:4px}} .coverage-gaps li p {{margin:6px 0}}
.signal-status {{display:flex;align-items:center;gap:8px;color:var(--tone);font-size:14px;font-weight:600}} .light {{width:8px;height:8px;background:var(--tone);border-radius:50%;display:inline-block;flex:none}}
.dashboard-note {{font-size:12px;margin:13px 1px 24px}} .signal-section {{margin-top:30px}} .signals {{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}}
.signal {{border:1px solid var(--line);border-radius:10px;padding:20px;background:var(--card);margin:0}} .signal .signal-status {{margin-top:16px}} .signal p {{font-size:14px;margin:9px 0 14px}}
.signal-links {{font-size:12px;color:var(--muted);line-height:1.8}} .signal-links a {{white-space:normal}}
.priorities {{margin:34px 0;padding:24px;border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:12px;background:var(--card)}} .section-heading .eyebrow {{display:block;margin-bottom:9px;color:var(--accent)}} .priorities ol {{margin:17px 0 0;list-style:none;padding:0;border-top:1px solid var(--line)}}
.priorities li {{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:16px;padding:20px 0;border-bottom:1px solid var(--line);align-items:start}}
.priority-index {{color:var(--tone);font-size:14px;padding-top:2px}} .priority-title {{font-size:17px;font-weight:600;text-decoration:none}} .priority-title:hover {{text-decoration:underline}}
.priorities li p {{font-size:14px;max-width:720px;margin:7px 0}} .evidence-link {{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:4px}}
.priorities .no-priorities {{display:block;font-size:16px;color:var(--muted)}}
.report-disclosure {{border:1px solid var(--line);border-left:3px solid #6a8dbd;border-radius:9px;margin:16px 0;padding:0 22px;background:var(--card)}}
.report-disclosure>summary {{padding:17px 0;font-size:16px;font-weight:500;color:var(--ink);cursor:pointer}}
.report-disclosure[open] {{padding-bottom:20px}} .report-disclosure[open]>summary {{margin-bottom:18px;border-bottom:1px solid var(--line)}}
.report-disclosure>h2 {{font-size:18px}} .finding-counts {{font-size:12px;color:var(--muted);margin-bottom:22px}}
.grid {{display:grid;grid-template-columns:1fr 1fr;gap:22px;align-items:start}} .grid h2 {{font-size:16px;margin:3px 0 15px;color:var(--muted)}}
.grid article {{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:17px;margin-bottom:12px}}
.card-title {{display:flex;gap:12px;align-items:start;justify-content:space-between}} .badge {{border-radius:4px;padding:3px 6px;font-size:12px;white-space:nowrap}}
.feedback-label {{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}} .feedback-result {{text-align:right;flex:none;max-width:45%}} .feedback-result .badge {{display:inline-block;white-space:normal}} .check-feedback {{margin:16px 0 0}} .check-feedback>div {{margin-top:12px}} .check-feedback dt {{font-size:12px;font-weight:600;color:var(--ink)}} .check-feedback dd {{margin:4px 0 0;font-size:15px;color:var(--muted);overflow-wrap:anywhere}}
.badge.pass {{color:var(--green);background:#16261d}} .badge.attention {{color:var(--amber);background:#2e2518}} .badge.info,.badge.unknown {{background:var(--card);color:var(--muted)}}
article details,.ai-provenance {{border-top:1px solid var(--line);padding-top:10px;margin-top:14px}} article summary,.ai-provenance summary {{font-size:12px;cursor:pointer;color:var(--ink)}}
pre {{font:12px/1.7 'IBM Plex Mono',ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--card);border-radius:5px;padding:10px;max-height:350px;overflow:auto}}
.link-details dl,.dependency-details dl {{margin:20px 0 0}} .link-details dl>div,.dependency-details dl>div {{padding:14px 0;border-top:1px solid var(--line)}} .link-details dt,.dependency-details dt {{font-weight:600;font-size:14px;color:var(--ink)}} .link-details dd,.dependency-details dd {{margin:6px 0 0;font-size:14px;color:var(--muted);overflow-wrap:anywhere;white-space:pre-wrap}}
.visitor-snapshot {{margin:24px 0;padding:26px;border:1px solid var(--line);border-radius:14px;background:var(--card)}} .visitor-snapshot h2 {{margin-top:10px}} .visitor-snapshot dl {{margin:0}} .visitor-snapshot dl>div {{padding:12px 0;border-top:1px solid var(--line)}} .visitor-snapshot dt {{font-size:14px;font-weight:600}} .visitor-snapshot dd {{margin:5px 0 0;font-size:15px;color:var(--muted)}}
.next {{border-left:2px solid var(--accent);padding-left:10px}} .next strong {{display:block;font-size:12px;color:var(--ink);font-weight:500;margin-bottom:3px}}
.demo {{background:#172c46;border:1px solid #44658e;color:var(--accent);padding:10px 14px;border-radius:7px;margin-top:20px;font-size:12px}}
.ai-heading {{display:flex;align-items:center;justify-content:space-between;gap:16px}} .ai-heading h2 {{margin:0;font-size:18px}}
.ai-review {{font-size:12px;padding:3px 7px;border-radius:4px;background:#172c46;color:var(--accent)}} .ai-fixture {{font-size:14px;color:var(--accent)}}
.ai-items {{list-style:none;padding:0;margin:20px 0 0}} .ai-items li {{padding:16px 0;border-top:1px solid var(--line)}}
.ai-citation {{font-size:16px;font-weight:600}} .ai-citation span {{font-size:12px;font-weight:400}} .ai-copy {{white-space:pre-wrap;margin-bottom:8px}}
.ai-summary {{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--accent);padding:20px;border-radius:8px;margin:22px 0}}
.ai-summary h3 {{font-size:18px}} .ai-summary p {{font-size:16px;line-height:1.8;margin-bottom:0;white-space:pre-wrap}}
.ai-section .ai-items li {{padding:24px 0}} .ai-reasons {{display:grid;grid-template-columns:1fr 1fr;gap:20px 26px;margin-top:18px}}
.ai-reason {{min-width:0}} .ai-reason h3 {{font-size:14px;font-weight:600;color:var(--accent)}} .ai-reason p {{font-size:16px;line-height:1.8;margin:8px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}}
.ai-next {{border-left:2px solid var(--accent);padding-left:14px}} .ai-limit h3 {{color:var(--ink)}}
.ai-items .next {{margin-bottom:0}} .ai-unknown,.ai-provenance p {{font-size:14px}} article:target {{outline:2px solid var(--accent);outline-offset:3px;scroll-margin-top:20px}}
.score-section ul {{padding-left:20px;color:var(--muted);font-size:14px}} .score-section li {{margin:8px 0}} .score-table {{overflow:auto}}
.score-table table {{border-collapse:collapse;width:100%;font-size:12px}} .score-table th,.score-table td {{text-align:left;vertical-align:top;padding:10px 8px;border-bottom:1px solid var(--line)}}
.score-table th {{font-weight:500}} .score-table td:last-child {{min-width:190px;color:var(--muted)}}
a:focus-visible,summary:focus-visible {{outline:2px solid var(--accent);outline-offset:4px}}
footer {{margin-top:28px;padding-top:20px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}} footer p,footer li {{font-size:12px}} footer li {{margin:5px 0}}
@media(max-width:720px) {{.overview,.signals,.grid,.ai-reasons {{grid-template-columns:1fr}} .score-overview {{border-left:0;border-top:1px solid var(--line)}} .site-overview,.score-overview {{padding:24px}} .score-number {{font-size:58px}}
.priorities li {{grid-template-columns:25px minmax(0,1fr);gap:10px}} .evidence-link {{grid-column:2}} main {{padding:25px 18px}} .brand span {{font-size:12px}}}}
@media print {{:root {{color-scheme:light;--ink:#111111;--muted:#555;--line:#ccc;--paper:#fff;--card:#fff;--surface:#f7f7f7;--accent:#284e7b;--green:#196539;--amber:#82520c;--red:#a52222;--neutral:#555}}
body {{background:white}} main {{padding:0}} article,.overview,.signal {{break-inside:avoid}} details {{display:block}} .grid {{display:block}} .score-overview {{border-color:var(--line)}} .badge,.demo,.ai-review {{background:white}}}}
</style></head><body><main><div class="brand"><strong>Verifact<svg class="brand-check" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5 6.2 11.5 13 4.5"/></svg></strong><span>WEBSITE REPORT / v{e(report['tool_version'])}</span></div>{banner}
<header><div class="eyebrow">Website report</div><h1>{e(report['domain'])}</h1>
<div class="meta">{e(report['created_at'])} · {report['requests']} requests · {"Submitted URL" if report.get("target_url") else "Public homepage"}</div></header>
{visitor_section}
{dashboard_section}
{additional_sections}
{dependency_section}
<details class="report-disclosure" id="all-findings"><summary>All findings and evidence · {len(report['findings'])} checks</summary><div class="finding-counts">{counts}</div><div class="grid">{''.join(groups)}</div></details>
{assessment_section}{ai_section}
<footer><strong>Scope and interpretation</strong><p>{e(report['scope'])}</p><ul>{limitations}</ul>
<p>Pass means the named check passed. It does not certify the site as secure. An observation is context; unknown means evidence was insufficient.</p></footer>
</main></body></html>'''


def render(report, format):
    if format == "json":
        return json.dumps(_prepare_report(report), indent=2, ensure_ascii=False) + "\n"
    return html_report(report) if format == "html" else text_report(report)


def summarize(reports):
    counts = {}
    for report in reports:
        for item in report["findings"]:
            counts.setdefault(item["id"], Counter())[item["status"]] += 1
    lines = [f"VERIFACT / {len(reports)} report snapshots", "", "Check                    Pass  Review  Info  Unknown", "-" * 53]
    for key, values in sorted(counts.items()):
        lines.append(f"{key:24} {values['pass']:4}  {values['attention']:6}  {values['info']:4}  {values['unknown']:7}")
    lines.extend(["", "Counts describe this sample only. Repeated scans of a domain are separate snapshots.",
                  "Unknown checks are not failures; info checks are not passes. No overall safety score is calculated."])
    return clean_text("\n".join(lines)) + "\n"
