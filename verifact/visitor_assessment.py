"""Deterministic visitor guidance, separate from the developer checklist.

Configuration gaps never become a scam verdict. A scoped green result requires
current community-list coverage plus completed connection, route and static
form observations; it never verifies identity or establishes that a site is safe.
"""

from datetime import datetime, timezone
from urllib.parse import urlsplit

from .network import ScanError, normalize_domain, validate_url
from .reputation import public_result as reputation_for_display
from .threat_feed import community_for_report


VERSION = "visitor-v1"
LIMITATIONS = [
    "Site identity and trustworthiness are unverified.",
    "The community list mainly covers threats targeting Poland and can miss new scams.",
    "Scripts, downloads, payments and actual sign-in behavior were not tested.",
]


def _positive(value):
    return type(value) is int and value > 0


def _reason(identifier, title, detail, source, finding_id=None):
    result = {"id": identifier, "title": title, "detail": detail, "source": source}
    if finding_id:
        result["finding_id"] = finding_id
    return result


def _display_domain(value):
    """Only a short validated hostname may enter consumer copy, never a URL."""
    if not isinstance(value, str):
        return None
    try:
        host = normalize_domain(value)
    except (ScanError, ValueError, UnicodeError):
        return None
    return host if len(host) <= 100 else None


def _community_gap(community, status):
    if status != community["status"]:
        return _reason("community_gap", "Some destinations were not checked",
                       "The list result does not cover every hostname in the redirect route.", "community")
    if status == "not_checked":
        return _reason("community_gap", "Community check not run",
                       "No community-list lookup was included in this report.", "community")
    if community.get("stale"):
        return _reason("community_gap", "Community result needs refreshing",
                       "The saved list result is no longer current.", "community")
    return _reason("community_gap", "Community list unavailable",
                   "The latest list could not be downloaded or validated.", "community")


def _connection_gap(report, analysis, tls_evidence, duplicates, destination_known):
    if report.get("inspection_skipped") and report.get("skip_reason") == "community_match":
        title, detail = "Page inspection skipped", "Verifact did not visit the previously listed destination."
    elif "tls" in duplicates:
        title, detail = "Conflicting connection records", "This report contains more than one certificate result."
    elif analysis.get("error_kind") == "blocked":
        title, detail = "Destination blocked", "The destination failed Verifact's public-link checks."
    else:
        # These are fixed classifications, never an echo of arbitrary errors.
        raw = analysis.get("error") or tls_evidence.get("error")
        error = raw.casefold() if isinstance(raw, str) else ""
        if error.startswith("dns lookup failed"):
            title, detail = "Domain lookup failed", "The hostname could not be resolved."
        elif "timed out" in error or "timeout" in error or "deadline exceeded" in error:
            title, detail = "Connection timed out", "The site did not respond within the request limit."
        elif error.startswith("redirect limit reached"):
            title, detail = "Too many redirects", "The route exceeded the redirect limit."
        elif error.startswith("redirect loop detected"):
            title, detail = "Redirect loop", "The route repeated a URL instead of reaching a page."
        elif error.startswith("redirect response has no location"):
            title, detail = "Redirect destination missing", "The server sent a redirect without a destination."
        elif not destination_known:
            title, detail = "Destination not reached", "The complete redirect route was not recorded."
        else:
            title, detail = "HTTPS not verified", "Certificate verification was not established for the final hostname."
    return _reason("connection_gap", title, detail, "connection")


def _page_gap(response, findings, form_evidence, duplicates, form_known, form_safe):
    status = response.get("status")
    if type(status) is int and not 200 <= status < 300:
        descriptions = {401: "This page requires authentication.", 403: "The server refused the page request.",
                        404: "The requested page was not found.", 429: "The server limited this request."}
        title = f"Page returned HTTP {status}"
        detail = descriptions.get(status, "The server returned an unsuccessful response.")
    elif response.get("body_error"):
        title, detail = "Page download interrupted", "The response body could not be read completely."
    elif response.get("body_truncated") is True:
        title, detail = "Only part of the page was read", "The downloaded HTML was incomplete."
    elif any(findings.get(key, {}).get("evidence") == "HTML unavailable" for key in ("title", "http_resources")):
        title, detail = "No usable HTML", "The response was not supported HTML, so page checks could not run."
    elif "password_forms" in duplicates:
        title, detail = "Conflicting form records", "This report contains more than one password-form result."
    elif _positive(form_evidence.get("unsupported_actions")):
        title, detail = "Form destination unreadable", "A password-form destination could not be resolved."
    elif _positive(form_evidence.get("unassociated_password_inputs")):
        title, detail = "Password form unclear", "A password field could not be tied to a usable form."
    elif form_known and not form_safe:
        title, detail = "Form records conflict", "The form status conflicts with its recorded destinations."
    elif form_evidence.get("complete_html") is True:
        title, detail = "Form structure unclear", "The static password-form structure could not be assessed reliably."
    else:
        title, detail = "Page evidence missing", "This report has no complete HTML and password-form assessment."
    return _reason("page_gap", title, detail, "page")


def _form_observation(evidence):
    count = evidence.get("forms_with_password")
    if type(count) is int and count == 0:
        title, detail = "0 active password forms", "No active password form was found in the inspected HTML."
    elif type(count) is int and count > 0:
        title = f"{count} password {'form' if count == 1 else 'forms'} checked"
        detail = "No submission over HTTP, in a URL, or to another site is declared in the HTML."
    else:
        title, detail = "Password-form checks completed", "No risky static password submission was observed; the form count was not recorded."
    return _reason("static_forms", title, detail, "page", "password_forms")


def _urls(report):
    analysis = report.get("link_analysis")
    analysis = analysis if isinstance(analysis, dict) else {}
    values = [report.get("target_url"), analysis.get("input_url"), analysis.get("final_url")]
    response = report.get("response")
    if isinstance(response, dict):
        values.append(response.get("url"))
    chain = analysis.get("redirects")
    if isinstance(chain, list):
        values.extend(item.get("url") for item in chain[:16] if isinstance(item, dict))
    urls = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 2048:
            continue
        try:
            urls.add(validate_url(value)[0])
        except (ScanError, ValueError, TypeError):
            continue
    return urls


def build_visitor_assessment(report):
    report = report if isinstance(report, dict) else {}
    findings, duplicates = {}, set()
    values = report.get("findings")
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        key = item["id"]
        if key in findings:
            duplicates.add(key)
        findings[key] = item
    for key in duplicates:
        findings.pop(key, None)
    analysis = report.get("link_analysis")
    analysis = analysis if isinstance(analysis, dict) else {}
    response = report.get("response")
    response = response if isinstance(response, dict) else {}
    observed_urls = _urls(report)
    observed_hosts = {urlsplit(url).hostname for url in observed_urls}
    community = community_for_report(report)
    reputation = reputation_for_display(report.get("reputation"))
    community_status = community["status"]
    if community_status in {"listed", "no_match"} and not observed_hosts.issubset(set(community["checked_hosts"])):
        community_status = "unavailable"
    tls = findings.get("tls", {})
    tls_evidence = tls.get("evidence") if isinstance(tls.get("evidence"), dict) else {}
    form = findings.get("password_forms", {})
    form_evidence = form.get("evidence") if isinstance(form.get("evidence"), dict) else {}
    form_known = (form.get("status") in {"pass", "info", "attention"}
                  and form_evidence.get("complete_html") is True
                  and all(type(form_evidence.get(key)) is int and form_evidence[key] >= 0
                          for key in ("http_actions", "get_submissions", "cross_origin_actions", "unsupported_actions", "unassociated_password_inputs"))
                  and not form_evidence["unsupported_actions"] and not form_evidence["unassociated_password_inputs"])
    form_safe = form_known and not any(form_evidence[key] for key in ("http_actions", "get_submissions", "cross_origin_actions"))
    final = analysis.get("final_url")
    destination_known = (analysis.get("completed") is True and isinstance(final, str)
                         and final in observed_urls and response.get("url") == final and not analysis.get("error"))
    connection_known = (tls.get("status") == "pass" and tls_evidence.get("verified") is True
                        and isinstance(final, str) and final.startswith("https://")
                        and tls_evidence.get("hostname") == urlsplit(final).hostname)
    page_known = (type(response.get("status")) is int and 200 <= response["status"] < 300
                  and response.get("body_truncated") is False and not response.get("body_error") and form_known)
    coverage = {"page": "assessed" if page_known else "unavailable",
                "connection": "assessed" if connection_known else "unavailable",
                "destination": "assessed" if destination_known else "unavailable",
                "community_feed": community_status, "optional_reputation": reputation["status"]}
    red, orange = [], []
    if community_status == "listed" and any(item["hostname"] in observed_hosts for item in community["matches"]):
        matched = next(item for item in community["matches"] if item["hostname"] in observed_hosts)
        hostname = _display_domain(matched["hostname"])
        red.append(_reason("community_match", "Community list warning",
                           (hostname or "A checked hostname") + " is currently listed by CERT Polska.", "community"))
    if reputation["status"] == "listed":
        matches = reputation.get("matches")
        if isinstance(matches, list) and any(isinstance(item, dict) and item.get("url") in observed_urls for item in matches):
            red.append(_reason("known_threat", "Known-threat list warning",
                               "Google Safe Browsing currently flags an observed URL.", "reputation"))
    if (response.get("url") in observed_urls and isinstance(response.get("url"), str)
            and response["url"].startswith("http://")) or tls_evidence.get("encrypted") is False:
        red.append(_reason("unencrypted_destination", "Unencrypted page",
                           "The returned page uses HTTP, so the connection is unencrypted.", "connection", "tls"))
    elif analysis.get("error_kind") == "downgrade":
        red.append(_reason("downgrade", "Unencrypted redirect blocked",
                           "An HTTPS → HTTP redirect was stopped before contacting that destination.", "link", "tls"))
    elif tls.get("status") == "attention" and "could not be verified" in str(tls_evidence.get("error", "")):
        red.append(_reason("certificate_verification", "Certificate not verified",
                           "HTTPS verification failed; this computer's trust settings can also cause it.", "connection", "tls"))
    if form_known and form.get("status") == "attention":
        if _positive(form_evidence["http_actions"]) or _positive(form_evidence["get_submissions"]):
            detail = ("A password form points to HTTP. No form was submitted."
                      if _positive(form_evidence["http_actions"]) else
                      "A password form may put entered data in a URL. No form was submitted.")
            red.append(_reason("unsafe_password_form", "Risky password submission", detail, "page", "password_forms"))
        elif _positive(form_evidence["cross_origin_actions"]):
            orange.append(_reason("external_sign_in", "External sign-in destination",
                                  "A password form uses another origin. Confirm that this sign-in provider is intended.", "page", "password_forms"))
    warnings = analysis.get("warnings")
    warning_ids = {item["id"] for item in warnings if isinstance(item, dict) and isinstance(item.get("id"), str)} if isinstance(warnings, list) else set()
    if warning_ids.intersection({"misleading_subdomain", "similar_spelling", "mixed_script"}):
        detail = ("The expected name appears inside a different domain." if "misleading_subdomain" in warning_ids else
                  "A hostname resembles your expected domain but is different." if "similar_spelling" in warning_ids else
                  "The hostname mixes alphabets whose letters can look alike.")
        orange.append(_reason("domain_spelling", "Check the domain spelling",
                              detail, "link"))
    if analysis.get("expected_match") is False and analysis.get("expected_domain"):
        actual = _display_domain(urlsplit(final).hostname) if isinstance(final, str) and final in observed_urls else None
        expected = _display_domain(analysis["expected_domain"])
        detail = f"Ends at {actual}; you expected {expected}." if actual and expected else "The final hostname differs from your expected domain."
        orange.append(_reason("unexpected_destination", "Different destination", detail, "link"))
    if "http_start" in warning_ids:
        orange.append(_reason("http_start", "Link starts with HTTP",
                              "The first request is unencrypted, even if a later redirect uses HTTPS.", "link"))

    if red:
        status, tone, label = "warning", "red", "Warning found"
        summary = "Do not enter passwords or payment details yet."
        reasons = (red + orange)[:3]
        action = "Use the service's official address instead."
    elif orange:
        status, tone, label = "caution", "orange", "Check before continuing"
        summary = "Confirm the destination before sharing information."
        reasons = orange[:3]
        action = "Check the address with a trusted source before signing in."
    elif page_known and form_safe and connection_known and destination_known and community_status == "no_match" and not report.get("demo"):
        status, tone, label = "no_warning", "green", "No warning found"
        summary = "Limited to the checks below; site identity is unverified."
        reasons = [
            _reason("community_no_match", "No community-list match", "No observed hostname matched the current CERT Polska list.", "community"),
            _reason("verified_connection", "HTTPS verified", "The certificate passed verification for the final hostname.", "connection", "tls"),
            _form_observation(form_evidence),
        ]
        action = "Confirm the sender before sharing personal information."
    else:
        status, tone, label = "unknown", "gray", "Check incomplete"
        reasons = []
        if community_status not in {"listed", "no_match"}:
            reasons.append(_community_gap(community, community_status))
        if not destination_known or not connection_known:
            reasons.append(_connection_gap(report, analysis, tls_evidence, duplicates, destination_known))
        # A missing response is already explained by the connection reason.
        if response and (not page_known or not form_safe):
            reasons.append(_page_gap(response, findings, form_evidence, duplicates, form_known, form_safe))
        if not reasons:
            reasons.append(_reason("sample", "Illustrative sample", "No real website or community-list request was made.", "sample")
                           if report.get("demo") else
                           _reason("page_gap", "Recorded checks conflict", "Run a new check to collect consistent page evidence.", "page"))
        reasons = reasons[:3]
        http_status = response.get("status")
        if type(http_status) is int and not 200 <= http_status < 300:
            summary = f"The page returned HTTP {http_status}."
            action = ("Check a public page that does not require sign-in." if http_status in {401, 403} else
                      "Check the link for a typo and try again." if http_status == 404 else "Wait a moment, then check again.")
        elif not page_known or not destination_known or not connection_known or not form_safe:
            summary = "The page could not be fully inspected."
            action = "Run a new check for complete page and connection evidence."
        else:
            summary = "Page inspected; current community-list coverage is missing."
            action = ("Turn on the community check, then check again." if community_status == "not_checked" else
                      "Run a new check to refresh the community result.")
    expiries, observation_times = [], []
    for value in (report.get("created_at"), community.get("checked_at"), reputation.get("checked_at")):
        if not isinstance(value, str):
            continue
        try:
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is not None:
                observation_times.append(observed.astimezone(timezone.utc))
        except ValueError:
            pass
    for result in (community, reputation):
        if result.get("status") in {"listed", "no_match"} and isinstance(result.get("expires_at"), str):
            try:
                expiry = datetime.fromisoformat(result["expires_at"])
                if expiry.tzinfo is not None:
                    expiries.append(expiry.astimezone(timezone.utc))
            except ValueError:
                pass
    return {"version": VERSION, "status": status, "tone": tone, "label": label, "summary": summary,
            "reasons": reasons, "next_action": action, "coverage": coverage,
            "checked_at": max(observation_times).isoformat() if observation_times else None,
            "expires_at": min(expiries).isoformat() if expiries else None,
            "limitations": list(LIMITATIONS)}
