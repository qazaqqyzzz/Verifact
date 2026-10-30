"""Compact, deterministic summaries of public security observations.

Traffic-light labels are a project heuristic. They do not estimate the chance
that a website is safe and never change the versioned numeric checklist.
"""

from .checks import certificate_expiry_presentation


DASHBOARD_VERSION = "security-dashboard-v1"
RATING_METHODOLOGY = (
    "With complete checklist evidence, 80–100 points starts green, 50–79 amber, "
    "and below 50 red. Any recorded security issue prevents green. A certificate "
    "verification issue, unencrypted final page, or a password form using HTTP or GET makes the "
    "light red, even with a high score. Incomplete evidence stays neutral unless "
    "one of those priority issues was observed. Extra form and cookie checks do "
    "not change the numeric score. These are project-defined review priorities, "
    "not a safety verdict."
)

GROUPS = (
    ("connection", "Connection", ("tls", "https_redirect", "certificate_expiry")),
    ("browser", "Browser protection", ("hsts", "csp", "framing", "nosniff")),
    ("page", "Page exposure", ("http_resources", "password_forms", "cookie_flags")),
)
SECURITY_IDS = tuple(identifier for _, _, identifiers in GROUPS for identifier in identifiers)
OPTIONAL_IDS = {"password_forms", "cookie_flags"}
PRIORITY_ORDER = (
    "tls", "password_forms", "https_redirect", "http_resources", "csp",
    "framing", "hsts", "nosniff", "cookie_flags", "certificate_expiry",
)
TITLES = {
    "tls": "Certificate verification",
    "https_redirect": "HTTP to HTTPS redirect",
    "certificate_expiry": "Certificate renewal",
    "hsts": "HTTPS-only browser policy",
    "csp": "Content Security Policy",
    "framing": "Framing policy",
    "nosniff": "MIME sniffing protection",
    "http_resources": "Unencrypted resource references",
    "password_forms": "Password form destinations",
    "cookie_flags": "Response cookie attributes",
}
REVIEW_DETAILS = {
    "tls": "Certificate verification needs review on this computer. Inspect the recorded error before trusting this connection.",
    "https_redirect": "The HTTP entry point did not confirm a successful upgrade to HTTPS without a downgrade.",
    "certificate_expiry": "The certificate is within its renewal reminder window. Automatic renewal may already be configured.",
    "hsts": "No valid positive HSTS max-age was observed. Cached or preloaded browser policies were not checked.",
    "csp": "No enforcing content policy was observed. This does not establish whether an attack is possible.",
    "framing": "No supported framing restriction was observed. Some sites intentionally allow embedding.",
    "nosniff": "The expected nosniff header was not observed on the returned response.",
    "http_resources": "The page references resources over HTTP. Browsers may block or upgrade these requests.",
    "cookie_flags": "Some response cookies need an attribute review. Cookie purpose and sensitivity were not established.",
}


def _index_findings(report):
    """Keep only unique, relevant findings; ambiguity is not a positive result."""
    findings, duplicates = {}, set()
    for item in report.get("findings", []):
        if not isinstance(item, dict) or item.get("id") not in SECURITY_IDS:
            continue
        identifier = item["id"]
        if identifier in findings:
            duplicates.add(identifier)
        else:
            findings[identifier] = item
    return findings, duplicates


def _positive_count(evidence, key):
    value = evidence.get(key)
    return type(value) is int and value > 0


def _password_priority(finding):
    evidence = finding.get("evidence")
    return (finding.get("status") == "attention" and isinstance(evidence, dict)
            and any(_positive_count(evidence, key) for key in ("http_actions", "get_submissions")))


def _effective_status(identifier, finding, checklist, duplicates):
    if not finding or identifier in duplicates:
        return "unknown"
    status = finding.get("status", "unknown")
    if identifier in checklist:
        row = checklist[identifier]
        return status if row.get("assessed") else "unknown"
    if status not in {"pass", "attention", "info", "unknown"}:
        return "unknown"
    if status in {"pass", "info"}:
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            return "unknown"
        if identifier == "password_forms" and evidence.get("complete_html") is not True:
            return "unknown"
        if identifier == "cookie_flags" and (evidence.get("limited") is not False
                                               or _positive_count(evidence, "malformed_count")):
            return "unknown"
    return status


def _priority_detail(identifier, finding, status):
    if status == "unknown":
        return "This check could not be assessed from the available evidence. Unknown is not a failure."
    if identifier == "certificate_expiry":
        return certificate_expiry_presentation(finding)["explanation"]
    if identifier == "tls" and isinstance(finding.get("evidence"), dict) and finding["evidence"].get("encrypted") is False:
        return "The submitted link ended on an unencrypted HTTP page. No TLS certificate protected that response. Use a verified HTTPS address before sending private information."
    if identifier == "password_forms":
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            if _positive_count(evidence, "http_actions"):
                return "A password form points to an HTTP destination. Its submission behavior was not tested."
            if _positive_count(evidence, "get_submissions"):
                return "A password form declares GET submission, which may put entered data in the URL. No form was submitted."
            if _positive_count(evidence, "cross_origin_actions"):
                return "A password form points to another origin. This may be intentional; verify the destination before use."
        return "Review the recorded password form destination. No credentials were entered or submitted."
    return REVIEW_DETAILS[identifier]


def _unavailable_detail(identifier, finding, report, duplicated=False):
    """Explain missing evidence without treating it as a configuration defect."""
    if duplicated:
        return "Conflicting duplicate observations prevent a reliable result. Run a new check."
    if not finding:
        return "This saved report does not contain this check. Run a new check to collect it."
    evidence = finding.get("evidence")
    error = evidence.get("error", "") if isinstance(evidence, dict) else evidence
    error = error.lower() if isinstance(error, str) else ""
    if any(term in error for term in ("timed out", "timeout", "deadline")):
        return ("The HTTP entry point did not respond before the time limit. HTTPS was checked separately; try again later."
                if identifier == "https_redirect" else
                "The request did not finish before the time limit. Try again later; no failure is assumed.")
    if "bad file descriptor" in error:
        return "An earlier scanner version lost the response while reading it. Run a new check with the updated scanner."
    if "redirect limit" in error:
        return "The redirect chain exceeded the request limit. The remaining destination was not inspected."
    if "redirect loop" in error:
        return "The request encountered a redirect loop and stopped. Inspect the recorded redirect chain."
    if "dns lookup" in error or "no public dns" in error:
        return "The hostname could not be resolved to a usable public address at the time of this check."
    if "blocked" in error:
        return "The request was stopped by the scanner's destination safeguards. Inspect the recorded reason."
    response = report.get("response")
    response = response if isinstance(response, dict) else {}
    if identifier in {"http_resources", "password_forms"}:
        if response.get("body_error"):
            return "The page download ended early. Headers may still be available, but the complete HTML was not inspected."
        if response.get("body_truncated"):
            return "The page exceeded the reading limit. Content beyond that limit was not inspected."
        if type(response.get("status")) is int and not 200 <= response["status"] < 300:
            return "The server returned an error or access-restriction page, so the intended page could not be assessed."
        return "The complete page HTML was not available or usable for this check. JavaScript is not executed."
    if identifier == "cookie_flags" and isinstance(evidence, dict):
        if evidence.get("limited") or evidence.get("malformed_count"):
            return "Some cookie attributes were incomplete or could not be parsed reliably. Cookie values are not stored."
    return "This check could not be assessed from the available evidence. Unknown is not a failure."


def _signal(identifier, title, members, findings, statuses, critical, gap_details):
    observed = [key for key in members if key in findings]
    unknown = [key for key in members if statuses[key] == "unknown"]
    attention = [key for key in members if statuses[key] == "attention"]
    urgent = [key for key in members if key in critical]
    if urgent:
        tone, label = "red", "Review first"
        detail = _priority_detail(urgent[0], findings[urgent[0]], "attention")
    elif attention:
        tone, label = "amber", "Needs review"
        detail = _priority_detail(attention[0], findings[attention[0]], "attention")
        if len(attention) > 1:
            detail = str(len(attention)) + " checks need review. " + detail
    elif unknown:
        tone, label = "unknown", "Not fully assessed"
        detail = ("Password form or cookie evidence is unavailable in this saved report."
                  if identifier == "page" and any(key not in findings for key in OPTIONAL_IDS)
                  else str(len(unknown)) + " of " + str(len(members)) + " checks could not be assessed. " + gap_details.get(unknown[0], "No failure is assumed."))
    else:
        tone, label = "green", "Checks observed"
        detail = {
            "connection": "Certificate, HTTPS redirect and renewal-window checks passed for the observed connection.",
            "browser": "Expected headers or policies were observed. Policy strength was not tested.",
            "page": "No warning in the inspected markup or response cookies. Dynamic content was not checked.",
        }[identifier]
    return {"id": identifier, "title": title, "tone": tone, "label": label,
            "detail": detail, "finding_ids": observed}


def build_dashboard(report, assessment):
    """Build display data from findings plus a freshly computed assessment."""
    findings, duplicates = _index_findings(report)
    checklist = {row["finding_id"]: row for row in assessment.get("items", [])}
    statuses = {key: _effective_status(key, findings.get(key), checklist, duplicates) for key in SECURITY_IDS}
    critical = set()
    if statuses["tls"] == "attention":
        critical.add("tls")
    if statuses["password_forms"] == "attention" and _password_priority(findings["password_forms"]):
        critical.add("password_forms")
    attention = [key for key in PRIORITY_ORDER if statuses[key] == "attention"]
    explicit_unknown = [key for key in OPTIONAL_IDS if key in findings and statuses[key] == "unknown"]
    incomplete = assessment.get("coverage") != 100 or assessment.get("value") is None or bool(explicit_unknown)
    value = assessment.get("value")
    override = None
    if critical:
        tone, label = "red", "Priority review"
        override = "A connection, certificate or password-submission issue takes priority over the checklist percentage."
        summary = "Review the observed connection or password form issue first. This is a review priority, not proof of exploitation."
    elif incomplete:
        tone, label = "unknown", "Incomplete assessment"
        summary = ("The checklist is complete, but an additional security check is unavailable. Review its recorded limitation."
                   if assessment.get("coverage") == 100
                   else "Some security checks are unavailable. Missing evidence is not a failure or a reason to assume protection.")
    elif value < 50:
        tone, label = "red", "Priority review"
        summary = "Fewer than half of the weighted checklist points were confirmed. Start with the recorded configuration gaps."
    elif value < 80 or attention:
        tone, label = "amber", "Needs review"
        summary = "Security observations need review. Open the priority findings to see the evidence and next steps."
        if value >= 80 and attention:
            override = "Recorded security findings prevent a green light despite the high checklist score."
    else:
        tone, label = "green", "Strong checklist result"
        summary = "The assessed configuration met the checklist without a recorded security issue. This does not certify the website as safe."

    gaps = [{"finding_id": key, "title": checklist[key]["title"] if key in checklist else TITLES[key],
             "weight": checklist[key]["weight"] if key in checklist else 0,
             "detail": _unavailable_detail(key, findings.get(key), report, key in duplicates)}
            for key in SECURITY_IDS if statuses[key] == "unknown" and (key in checklist or key in findings)]
    gap_details = {item["finding_id"]: item["detail"] for item in gaps}
    priorities = []
    eligible = [key for key in PRIORITY_ORDER if key in findings and statuses[key] in {"attention", "unknown"}]
    eligible.sort(key=lambda key: (0 if key in critical else 1 if statuses[key] == "attention" else 2,
                                   PRIORITY_ORDER.index(key)))
    for key in eligible[:3]:
        finding = findings[key]
        status = statuses[key]
        recommendation = finding.get("recommendation", "")
        next_step = recommendation if status == "attention" and isinstance(recommendation, str) else ""
        if status == "unknown":
            next_step = "Inspect the recorded limitation before drawing a conclusion."
        title = "Unencrypted destination" if key == "tls" and isinstance(finding.get("evidence"), dict) and finding["evidence"].get("encrypted") is False else TITLES[key]
        priorities.append({"finding_id": key, "title": title,
                           "detail": gap_details.get(key) or _priority_detail(key, finding, status), "next_step": next_step,
                           "tone": "red" if key in critical else "amber" if status == "attention" else "unknown"})
    return {
        "method_version": DASHBOARD_VERSION,
        "rating": {"tone": tone, "label": label, "summary": summary,
                   "methodology": RATING_METHODOLOGY, "override": override},
        "signals": [_signal(key, title, members, findings, statuses, critical, gap_details) for key, title, members in GROUPS],
        "priorities": priorities,
        "coverage_gaps": gaps,
        "security_counts": {
            "attention": sum(statuses[key] == "attention" for key in findings),
            "unknown": sum(statuses[key] == "unknown" for key in findings),
            "passed": sum(statuses[key] == "pass" for key in findings),
        },
    }
