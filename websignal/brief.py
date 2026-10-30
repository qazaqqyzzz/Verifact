"""A small, factual UI summary. It never changes findings or score weights."""

import re
import unicodedata

from .assessment import assess
from .checks import certificate_expiry_presentation
from .dashboard import GROUPS, PRIORITY_ORDER, SECURITY_IDS, TITLES, _unavailable_detail
from .profile import profile_for_report
from .page_risks import dependency_review, page_risks_for_report
from .reputation import THREAT_TYPES, public_result


COUNTS_NOTE = "Met means the check recorded no review signal; it does not certify safety. Missing evidence is counted separately."
METHOD_NOTE = "Counts cover 10 core security observations. Eight have score weights; password-form and cookie checks have none. Additional owner reviews are unscored."
REVIEW_COPY = {
    "tls": ("Check the connection first", "The certificate could not be verified on this computer; the cause may be the site or local trust settings.",
            "Visitor: don't bypass browser warnings. Verify the site's address before signing in."),
    "https_redirect": ("HTTP upgrade needs review", "The HTTP route did not confirm a reliable switch to an encrypted HTTPS connection.",
                       "Owner: redirect HTTP visitors to HTTPS and remove any later redirects back to HTTP."),
    "certificate_expiry": ("Check certificate renewal", "The observed certificate is within the 14-day renewal reminder window; automatic renewal may already be set up.",
                           "Owner: check the expiry date and confirm automatic renewal is working."),
    "hsts": ("Browser HTTPS rule needs review", "This response did not set a usable rule to keep future visits on HTTPS; a browser may already remember one.",
             "Owner: confirm the site works over HTTPS, then set its browser HTTPS rule (HSTS)."),
    "csp": ("Page content rules need review", "No active rule limiting which scripts and resources the page may load was found. This alone does not prove a vulnerability.",
            "Owner: test a Content Security Policy for the page's required scripts and resources before enabling it."),
    "framing": ("Review display inside other sites", "No rule was found limiting who can show this page inside another page. Some sites allow this intentionally.",
                "Owner: block other sites from showing this page inside their pages unless that is intentional."),
    "nosniff": ("File-type protection is missing", "The page lacks the setting that tells supported browsers to use declared file types instead of guessing.",
                "Owner: set correct file types and add the X-Content-Type-Options: nosniff header."),
    "http_resources": ("Some resources use HTTP", "The page names unencrypted resources; browsers may block or upgrade them. Actual browser loading was not tested.",
                       "Owner: replace the observed HTTP resource links with HTTPS and test the page."),
    "password_forms": ("Check the sign-in destination", "A password form's destination needs review. No credentials were entered and no form was submitted.",
                       "Visitor: verify the intended sign-in provider before entering a password."),
    "cookie_flags": ("Cookie settings need review", "Some returned cookie settings need review. Their purpose and sensitivity were not established.",
                     "Owner: review the recorded cookie settings against how each cookie is used."),
}
LINK_COPY = {
    "mixed_script": ("Check the domain's spelling", "A hostname mixes writing systems, so some letters may look like letters in another alphabet.",
                     "Visitor: compare the full hostname with the address from an independent, trusted source."),
    "similar_spelling": ("Check the domain's spelling", "A hostname resembles the domain you expected, but it is a different address. Similarity alone does not prove a scam.",
                         "Visitor: use the address from an independent, trusted source before signing in or paying."),
    "misleading_subdomain": ("Check the complete domain", "The expected name appears inside a different domain; it is not the expected site or one of its subdomains.",
                            "Visitor: inspect the complete hostname, then use an independently verified address."),
    "expected_domain_mismatch": ("The destination is different", "The final hostname does not match the domain you expected or one of its subdomains.",
                                 "Visitor: confirm the destination independently before signing in or paying."),
    "http_start": ("This link starts without encryption", "The first request uses HTTP, even if a later redirect reaches HTTPS.",
                   "Visitor: use a verified HTTPS address when possible, especially before entering private information."),
    "unencrypted_destination": ("The destination uses HTTP", "The returned page is not protected by an encrypted HTTPS connection.",
                                "Visitor: use a verified HTTPS address before entering passwords or payment details."),
    "downgrade": ("An unencrypted redirect was blocked", "The link tried to redirect from HTTPS to HTTP. Verifact stopped before visiting that destination.",
                  "Visitor: verify the intended HTTPS destination independently; don't send private information over HTTP."),
}
FORM_COPY = {
    "http_actions": ("A password form points to HTTP", "The form's destination is unencrypted HTTP. Browser behavior was not tested and no password was submitted.",
                     "Visitor: don't enter a password until the site's owner confirms a secure HTTPS sign-in destination."),
    "get_submissions": ("A password form may expose URL data", "The form declares GET submission, which may put entered credentials in the URL. No form was submitted.",
                        "Owner: use HTTPS POST for credential forms. Visitors should avoid this form until it is reviewed."),
    "cross_origin_actions": ("Check the sign-in provider", "The password form points to another origin. This may be an intentional external sign-in provider.",
                             "Visitor: confirm that the destination is the service's intended sign-in provider before entering a password."),
}
HYGIENE_COPY = {
    "header_quality": ("Review header consistency",
                       "A returned security header contains a repeated or unrecognized declaration. Actual browser enforcement was not tested.",
                       "Owner: reconcile application and proxy settings, remove unintended duplicates, then check the final response."),
    "cors_policy": ("Review cross-origin sharing",
                    "A returned cross-origin sharing value needs review. No custom-origin request or authenticated data access was tested.",
                    "Owner: correct the observed sharing declaration and allow only the origins intended for this endpoint."),
    "response_caching": ("Review cache instructions",
                         "The returned cache instructions contain a syntax or repeated-value issue. Browser and shared-cache behavior were not tested.",
                         "Owner: make caching instructions consistent and confirm that private responses are not shared with other users."),
    "browser_isolation": ("Review optional browser policies",
                          "An optional browser isolation setting has an unrecognized value. This does not mean every page needs that policy.",
                          "Owner: correct the observed value if the policy is needed, then test embeds, sign-in and popups."),
    "public_disclosures": ("Review public error details",
                           "A server-error page contains debug or stack-trace markers that may reveal internal details. No exploitable flaw was established.",
                           "Owner: turn off public debug output, show a generic error page and keep detailed errors in private logs."),
    "iframe_sandbox": ("Review embed permissions",
                       "An embedded page from the same origin has permissions that can undo its sandbox. Its loaded content and behavior were not tested.",
                       "Owner: give untrusted embeds minimal permissions; avoid allowing scripts and same-origin access together."),
}


def _text(value, limit=160):
    if not isinstance(value, str):
        return ""
    value = " ".join("".join(char for char in value if not unicodedata.category(char).startswith("C") or char in "\n\t").split())
    if len(value) > limit:
        value = value[:limit - 1].rsplit(" ", 1)[0].rstrip(".,;:") + "…"
    return value


def _positive(evidence, key):
    return isinstance(evidence, dict) and type(evidence.get(key)) is int and evidence[key] > 0


def _index(report):
    findings, duplicates = {}, set()
    values = report.get("findings")
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict) or item.get("id") not in SECURITY_IDS:
            continue
        key = item["id"]
        if key in findings:
            duplicates.add(key)
        else:
            findings[key] = item
    return findings, duplicates


def _state(key, finding, checklist, duplicates):
    if not isinstance(finding, dict) or key in duplicates:
        return "unknown"
    status = finding.get("status")
    if key in checklist:
        row = checklist[key]
        if not row["assessed"]:
            return "unknown"
        return "met" if row["earned"] == row["weight"] else "review"
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or status not in {"pass", "info", "attention"}:
        return "unknown"
    if key == "password_forms":
        if evidence.get("complete_html") is not True:
            return "unknown"
        risks = any(_positive(evidence, field) for field in ("http_actions", "get_submissions", "cross_origin_actions"))
        if status == "attention":
            return "review" if risks else "unknown"
        if risks or any(_positive(evidence, field) for field in ("unsupported_actions", "unassociated_password_inputs")):
            return "unknown"
    if key == "cookie_flags":
        risk = _positive(evidence, "missing_secure") or _positive(evidence, "same_site_none_without_secure")
        if status == "attention":
            return "review" if risk else "unknown"
        if evidence.get("limited") is not False or _positive(evidence, "malformed_count") or risk:
            return "unknown"
    return "met"


def _review(identifier, source, tone, copy, **extra):
    title, why, action = copy
    return {"id": identifier, "source": source, "tone": tone, "title": _text(title, 80),
            "why": _text(why), "action": _text(action), **extra}


def _security_review(key, finding, urgent):
    copy = REVIEW_COPY[key]
    evidence = finding.get("evidence")
    if key == "certificate_expiry":
        presentation = certificate_expiry_presentation(finding)
        copy = ("Check certificate renewal", presentation["explanation"], presentation["recommendation"])
    elif key == "tls" and isinstance(evidence, dict) and evidence.get("encrypted") is False:
        copy = LINK_COPY["unencrypted_destination"]
    elif key == "tls" and isinstance(evidence, dict) and "downgrade" in str(evidence.get("error", "")).lower():
        copy = LINK_COPY["downgrade"]
    elif key == "password_forms":
        copy = next((FORM_COPY[field] for field in FORM_COPY if _positive(evidence, field)), copy)
    elif key == "cookie_flags" and _positive(evidence, "missing_secure"):
        copy = ("Cookie settings need review",
                "At least one cookie lacks the Secure setting that asks browsers to send it only over HTTPS. Its sensitivity is unknown.",
                "Owner: review each cookie's purpose and use Secure for cookies sent over HTTPS.")
    return _review(key, "security", "red" if key in urgent else "amber", copy, finding_id=key)


def _link_reviews(report, findings, states):
    analysis = report.get("link_analysis")
    warnings = analysis.get("warnings") if isinstance(analysis, dict) else []
    warnings = warnings if isinstance(warnings, list) else []
    seen, reviews = set(), []
    tls = findings.get("tls", {})
    tls_evidence = tls.get("evidence") if isinstance(tls.get("evidence"), dict) else {}
    unencrypted = states["tls"] == "review" and tls_evidence.get("encrypted") is False
    tls_downgrade = states["tls"] == "review" and "downgrade" in str(tls_evidence.get("error", "")).lower()
    # Several spelling heuristics can describe the same destination concern.
    spelling = {"mixed_script", "similar_spelling", "misleading_subdomain", "expected_domain_mismatch"}
    for warning in warnings:
        if not isinstance(warning, dict):
            continue
        key = warning.get("id")
        if not isinstance(key, str) or key not in LINK_COPY or warning.get("tone") not in {"amber", "red"}:
            continue
        bucket = "domain_spelling" if key in spelling else key
        if bucket in seen or (unencrypted and key in {"http_start", "unencrypted_destination"}) or (tls_downgrade and key == "downgrade"):
            continue
        seen.add(bucket)
        reviews.append(_review("link_" + key, "link", warning["tone"], LINK_COPY[key], warning_id=key))
    return reviews


def _reputation_review(report):
    result = public_result(report.get("reputation"))
    matches = result.get("matches")
    if result.get("status") != "listed" or not isinstance(matches, list) or not any(
            isinstance(match, dict) and match.get("threat_type") in THREAT_TYPES for match in matches):
        return []
    return [_review("reputation_listed", "reputation", "red", (
        "Google returned a threat-list match",
        "Google lists a checked URL as potentially harmful. Lists can be wrong and can miss threats.",
        "Visitor: avoid entering information or downloading files until you verify the intended destination."),
        expires_at=result.get("expires_at"), attribution="Advisory provided by Google",
        source_url="https://developers.google.com/safe-browsing/v4/advisory")]


def _community_review(report):
    from .threat_feed import community_for_report
    from .visitor_assessment import build_visitor_assessment
    result = community_for_report(report)
    if result["status"] != "listed":
        return []
    # Reuse the link view's observed-host and coverage validation. A saved
    # listing for an unrelated host must not become a developer warning.
    visitor = build_visitor_assessment({**report, "community_reputation": result})
    if not any(reason["id"] == "community_match" for reason in visitor["reasons"]):
        return []
    return [_review("community_listed", "community", "red", (
        "Community list warning",
        "A checked hostname appears on CERT Polska's current warning list. The list can be wrong and does not assess every page.",
        "Visitor: avoid signing in, paying or downloading here. Open the service through an independently verified address."),
        expires_at=result["expires_at"], attribution="Source: CERT Polska",
        source_url=result["source_url"])]


def _page_reviews(report):
    reviews = []
    dependency = dependency_review(page_risks_for_report(report))
    if dependency:
        reviews.append(_review("page_dependencies", "page", "amber", (
            dependency["title"], dependency["why"], dependency["action"])))
    findings = report.get("findings")
    referrers = [item for item in findings if isinstance(item, dict) and item.get("id") == "referrer"] if isinstance(findings, list) else []
    if len(referrers) == 1 and referrers[0].get("status") == "attention":
        evidence = referrers[0].get("evidence")
        if isinstance(evidence, dict) and evidence.get("policy") == "unsafe-url":
            reviews.append(_review("referrer", "security", "amber", (
                "Review address sharing",
                "The page declares unsafe-url: a browser may share its path and query with other sites. Individual requests can use different rules.",
                "Owner: consider strict-origin-when-cross-origin or a stricter policy, then test links and integrations."), finding_id="referrer"))
    return reviews


def _hygiene_reviews(report):
    """Authored owner advice for recorded extra issues, never a scam verdict."""
    values = report.get("findings")
    values = values if isinstance(values, list) else []
    reviews = []
    for key, default_copy in HYGIENE_COPY.items():
        candidates = [item for item in values if isinstance(item, dict) and item.get("id") == key]
        if len(candidates) != 1 or candidates[0].get("status") != "attention":
            continue
        evidence = candidates[0].get("evidence")
        if not isinstance(evidence, dict):
            continue
        raw_issues = evidence.get("issues")
        issues = {item for item in raw_issues[:128] if isinstance(item, str)} if isinstance(raw_issues, list) else set()
        copy, observed = default_copy, False
        if key == "header_quality":
            observed = isinstance(raw_issues, list) and any(
                isinstance(item, dict)
                and isinstance(item.get("header"), str) and isinstance(item.get("issue"), str)
                and item.get("header") in {"x-content-type-options", "x-frame-options", "content-security-policy"}
                and item.get("issue") in {"multiple_values", "unrecognized_value", "duplicate_directives"}
                for item in raw_issues[:128])
        elif key == "cors_policy":
            observed = bool(issues & {"wildcard_with_credentials", "null_origin_allowed", "unrecognized_origin_value", "unrecognized_credentials_value"})
            if "wildcard_with_credentials" in issues:
                copy = (default_copy[0],
                        "The response combines wildcard sharing (*) with credentials. Browsers do not allow credentialed reads with this combination.",
                        "Owner: use intended explicit origins for credentialed access, or remove the credentials setting for public content.")
            elif "null_origin_allowed" in issues:
                copy = (default_copy[0],
                        "The response allows the null origin, which can come from sandboxed or local documents. Intended sharing was not established.",
                        "Owner: confirm whether null origins are needed; use a deliberate origin allowlist for sensitive responses.")
        elif key == "response_caching":
            observed = bool(issues & {"shared_cache_with_account_context", "unrecognized_directive_syntax", "invalid_or_repeated_max-age", "invalid_or_repeated_s-maxage"})
            if ("shared_cache_with_account_context" in issues and evidence.get("explicit_shared_cache") is True
                    and (evidence.get("password_input_observed") is True or evidence.get("sets_cookie") is True)):
                copy = ("Review shared caching",
                        "Public caching is enabled on a response with sign-in or cookie context. This does not prove private data is being shared.",
                        "Owner: check for per-user content; use private or no-store when appropriate and keep public caching for shared content.")
            elif issues == {"shared_cache_with_account_context"}:
                observed = False
        elif key == "browser_isolation":
            headers = evidence.get("unrecognized_headers")
            observed = isinstance(headers, list) and any(isinstance(name, str) and name in {
                "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"}
                for name in headers[:128])
        elif key == "public_disclosures":
            markers = evidence.get("error_page_markers")
            observed = evidence.get("error_response_checked") is True and isinstance(markers, list) and any(
                isinstance(marker, str) and marker in {"django_debug_error", "werkzeug_debugger_error", "php_stack_trace_error"}
                for marker in markers[:128])
        elif key == "iframe_sandbox":
            observed = _positive(evidence, "same_origin_source_with_both")
        if observed:
            reviews.append(_review(key, "hygiene", "amber", copy, finding_id=key))
    return reviews


def build_brief(report):
    """Count a fixed security set and provide only short, grounded reviews."""
    report = report if isinstance(report, dict) else {}
    findings, duplicates = _index(report)
    # Recompute from observations; never accept an imported summary or AI score.
    assessment = assess({"findings": report.get("findings") if isinstance(report.get("findings"), list) else []})
    checklist = {row["finding_id"]: row for row in assessment["items"]}
    states = {key: _state(key, findings.get(key), checklist, duplicates) for key in SECURITY_IDS}
    urgent = {"tls"} if states["tls"] == "review" else set()
    if states["password_forms"] == "review" and any(_positive(findings["password_forms"].get("evidence"), key) for key in ("http_actions", "get_submissions")):
        urgent.add("password_forms")
    counts = {state: sum(value == state for value in states.values()) for state in ("met", "review", "unknown")}
    counts.update(total=len(SECURITY_IDS), urgent=len(urgent))
    groups = []
    for identifier, title, members in GROUPS:
        row = {"id": identifier, "title": title, "total": len(members),
               **{state: sum(states[key] == state for key in members) for state in ("met", "review", "unknown")}}
        row["tone"] = "red" if urgent.intersection(members) else "amber" if row["review"] else "unknown" if row["unknown"] else "green"
        groups.append(row)
    reviews = _reputation_review(report)
    reviews.extend(_community_review(report))
    reviews.extend(_security_review(key, findings[key], urgent) for key in PRIORITY_ORDER if states[key] == "review")
    reviews.extend(_link_reviews(report, findings, states))
    reviews.extend(_page_reviews(report))
    reviews.extend(_hygiene_reviews(report))
    # Destination/sign-in concerns should not disappear below several optional
    # header settings. Keep the stable configuration order within each tier.
    reviews.sort(key=lambda item: (
        0 if item["tone"] == "red" else 1,
        0 if item["source"] in {"reputation", "community"} else 1 if item["id"] in {"tls", "password_forms"}
        else 2 if item["source"] == "link" else 3))
    unknowns = [{"id": key, "title": TITLES[key],
                 "why": _text(_unavailable_detail(key, findings.get(key), report, key in duplicates))}
                for key in SECURITY_IDS if states[key] == "unknown"]
    checks = [{"id": key, "status": states[key], "title": TITLES[key], "group": group}
              for group, _, members in GROUPS for key in members]
    profile = profile_for_report({**report, "findings": report.get("findings") if isinstance(report.get("findings"), list) else []})
    summary = _text(profile.get("summary"), 600)
    description = re.split(r"(?<=[.!?])\s+", summary, maxsplit=1)[0] if summary else "The page's purpose could not be established."
    return {"counts": counts, "groups": groups, "checks": checks, "reviews": reviews[:3], "all_reviews": reviews,
            "total_review": len(reviews), "total_urgent": sum(item["tone"] == "red" for item in reviews),
            "unknowns": unknowns, "description": _text(description, 240), "counts_note": COUNTS_NOTE,
            "method_note": METHOD_NOTE}
