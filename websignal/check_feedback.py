"""Concise evidence-based presentation, independent of scoring and raw findings.

Only authored text, validated counts and allowlisted policy names are emitted.
Raw URLs, headers, cookie/contact values and network errors are never echoed.
This module performs no requests and does not mutate an imported or live report.
"""

import re

from .checks import REFERRER_POLICIES, _positive_hsts, certificate_expiry_presentation
from .security_hygiene import ISOLATION


NO_CHANGE = "No change needed for this check."
RECHECK = "Run a new check to obtain a consistent response and inspect the evidence if it remains unavailable."
STATES = frozenset({"pass", "attention", "info", "unknown"})
HTML_CHECKS = frozenset({"title", "viewport", "language", "image_alt", "http_resources", "password_forms", "iframe_sandbox", "csp"})


def _text(value, maximum=8192):
    return isinstance(value, str) and len(value) <= maximum and not any(ord(c) < 32 and c not in "\t\r\n" for c in value)


def _count(evidence, key):
    value = evidence.get(key)
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def _list(value, maximum=128):
    return value if isinstance(value, list) and len(value) <= maximum else None


def _result(item, result, fact, fix=NO_CHANGE):
    return {"result": result, "fact": fact, "fix": fix, "state": item["status"]}


def _unknown(fact="The saved result lacks consistent evidence for this check.", fix=RECHECK):
    return {"result": "Could not check", "fact": fact, "fix": fix, "state": "unknown"}


def _html_unknown(report):
    response = report.get("response")
    if isinstance(response, dict):
        if response.get("body_error"):
            return _unknown("The page body did not finish downloading.", "Check that the page loads fully, then run a new check.")
        if response.get("body_truncated") is True:
            return _unknown("The page exceeded the download limit; its complete HTML was not inspected.",
                            "Check the complete HTML in your browser or reduce the response size, then check again.")
        status = response.get("status")
        if type(status) is int and 100 <= status <= 599 and not 200 <= status < 300:
            return _unknown(f"The final response returned HTTP {status}; a successful page was not available to assess.",
                            "Resolve the page response or access restriction, then check the intended public page again.")
    return _unknown("A complete, supported HTML page was not available for this check.",
                    "Check that the public page returns a complete successful HTML response, then check again.")


def _unavailable(item, report):
    """Explain known gaps without laundering a raw error into user-facing prose."""
    identifier, evidence = item["id"], item.get("evidence")
    e = evidence if isinstance(evidence, dict) else {}
    if report.get("inspection_skipped") is True and report.get("skip_reason") == "community_match":
        return _unknown("The website was not contacted because its hostname matched the community warning list.",
                        "Review the warning-list result before investigating the website independently.")
    if identifier == "rdap":
        return _unknown("A usable public registration record was not returned for the queried name.",
                        "Use the registered domain in the registration lookup option and retry; some registries do not provide a usable record.")
    if identifier == "security_contact":
        if e.get("status") == "not_applicable":
            return _unknown("The final page used HTTP, so no HTTPS contact-file request was made.",
                            "Enable HTTPS on the intended site, then check its public security contact again.")
        if e.get("status") == "redirect":
            return _unknown("The standard security.txt location returned a redirect; this one-request check did not follow it.",
                            "Review the redirect destination independently or serve the contact file directly at the standard location.")
        codes = {issue.get("code") for issue in e.get("issues", [])[:32] if isinstance(issue, dict) and isinstance(issue.get("code"), str)} if isinstance(e.get("issues"), list) else set()
        if codes & {"body_limit", "line_limit"}:
            return _unknown("The contact file exceeded the bounded text inspection limits.", "Keep security.txt concise, with short UTF-8 text fields, then check again.")
        if "signature_format" in codes:
            return _unknown("The signed contact file's wrapper could not be interpreted; no signature was verified.", "Review its cleartext signature format independently and publish a supported security.txt file.")
        if "unsupported_expiry" in codes:
            return _unknown("The expiry uses a leap-second timestamp that this checker does not interpret.", "Verify the expiry independently or publish a supported future RFC 3339 timestamp.")
        status = e.get("http_status")
        if type(status) is int and 100 <= status <= 599 and status != 200:
            return _unknown(f"The contact-file location returned HTTP {status} rather than a usable file.", "Check the standard security.txt location and retry after resolving its response.")
        return _unknown("A complete, supported contact file was not available within the request and parsing limits.",
                        "Check that /.well-known/security.txt returns a small UTF-8 text/plain file over HTTPS, then retry.")
    if identifier == "certificate_expiry":
        return _unknown("The certificate's expiry countdown was not established for this response.",
                        "Check the currently served certificate and its expiry, then run a new check.")
    if identifier == "tls":
        return _unknown("No successfully verified TLS connection was recorded; this does not establish a certificate defect.",
                        "Check connectivity and the local certificate trust store, then retry the HTTPS address.")
    if identifier == "https_redirect":
        return _unknown("The HTTP entry-point request ended before an HTTPS upgrade could be confirmed.",
                        "Check the site's HTTP redirect and connectivity, then try again.")
    if identifier == "dns":
        return _unknown("No completed page response supplied a public-address observation.",
                        "Check the domain's DNS and network reachability, then try again.")
    if "response" in report and report["response"] is None:
        return _unknown("No final page response was available to inspect.", "Check that the public website is reachable, then run a new check.")
    if identifier == "cookie_flags":
        if e.get("limited") is True:
            return _unknown("The response returned more cookies than this bounded check can inspect.", "Review every Set-Cookie field in browser developer tools, including its intended purpose and attributes.")
        if _count(e, "malformed_count"):
            return _unknown(f"{e['malformed_count']} Set-Cookie field(s) could not be parsed completely.", "Inspect the original Set-Cookie fields and correct malformed or incorrectly combined headers.")
    if identifier == "password_forms" and e.get("complete_html") is True:
        if _count(e, "unsupported_actions"):
            return _unknown(f"{e['unsupported_actions']} password-form action(s) could not be interpreted.", "Review the form actions and submit-button overrides in the browser; use the intended HTTPS POST destination.")
        if _count(e, "unassociated_password_inputs"):
            return _unknown(f"{e['unassociated_password_inputs']} enabled password input(s) lacked an assessable named form association.", "Check form ownership, field names and JavaScript submission behavior in the browser.")
        return _unknown("Static password-form markup could not be resolved reliably.", "Review duplicate form IDs, nesting, disabled controls and JavaScript submission behavior in the browser.")
    if identifier == "iframe_sandbox":
        if e.get("limited") is True:
            return _unknown("The number or size of iframe declarations exceeded the inspection limits.", "Inspect all iframe sandbox declarations in browser developer tools.")
        if _count(e, "unresolved_sources"):
            return _unknown(f"{e['unresolved_sources']} iframe source origin(s) could not be resolved from static HTML.", "Check iframe destinations and sandbox permissions in the browser.")
    if identifier == "referrer":
        if e.get("limited") is True:
            return _unknown("Referrer declarations exceeded the bounded inspection limits.", "Review the Referrer-Policy header and HTML/element overrides in browser developer tools.")
        return _unknown("The available referrer metadata was incomplete; no supported declaration could be selected.", "Inspect the complete page and its Referrer-Policy declarations in the browser.")
    if identifier in HTML_CHECKS:
        return _html_unknown(report)
    details = {
        "header_quality": ("One or more selected security headers exceeded the parsing limits.", "Inspect the selected headers for excessive length, unsupported characters or malformed quoting."),
        "cors_policy": ("A CORS field could not be interpreted within the header limits.", "Inspect Access-Control-Allow-Origin and Access-Control-Allow-Credentials in the original response."),
        "response_caching": ("Cache-Control could not be interpreted within the header limits.", "Inspect Cache-Control for malformed quoting, excessive length and unsupported characters."),
        "browser_isolation": ("One or more optional browser-policy headers exceeded the parsing limits.", "Inspect the original COOP, COEP, CORP and Permissions-Policy fields."),
        "public_disclosures": ("One or more software-metadata headers exceeded the inspection limits.", "Review the original public response headers and error handling independently."),
    }
    return _unknown(*details[identifier]) if identifier in details else _unknown()


def _transport(item, report):
    identifier, status, evidence = item["id"], item["status"], item.get("evidence")
    if identifier == "dns":
        rows = _list(evidence)
        if status != "info" or not rows or any(not isinstance(row, dict) or not _text(row.get("hostname"), 253) or _list(row.get("addresses")) is None for row in rows):
            return _unknown()
        count = sum(len(row["addresses"]) for row in rows)
        return _result(item, "Addresses recorded", f"{count} address observation(s) were recorded across {len(rows)} completed response(s); the same address may appear more than once.", NO_CHANGE)
    if not isinstance(evidence, dict):
        return _unknown()
    e = evidence
    if identifier == "https_redirect":
        chain = _list(e.get("chain"), 32)
        if chain is None or any(not isinstance(hop, dict) or not _text(hop.get("url"), 8192) for hop in chain):
            return _unknown()
        schemes = [hop["url"].split(":", 1)[0] for hop in chain]
        if status == "pass" and "https" in schemes[1:]:
            suffix = " A later request did not complete." if e.get("error") else ""
            return _result(item, "Redirects to HTTPS", "The separate HTTP homepage entry point redirected to HTTPS." + suffix)
        if status == "attention":
            if "https" in schemes[1:]:
                return _result(item, "Redirect chain needs review", "An HTTPS upgrade was recorded, but the saved redirect check still requires review.", "Inspect the redirect chain for a subsequent HTTP downgrade and keep the entire route on HTTPS.")
            return _result(item, "HTTPS upgrade not observed", "The HTTP homepage entry point did not record a redirect to HTTPS.", "Configure the HTTP entry point to redirect to the intended HTTPS address.")
    elif identifier == "tls":
        if status == "pass" and e.get("verified") is True:
            version = e.get("version")
            version = version if version in {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"} else "TLS"
            return _result(item, "Certificate verified", f"The final HTTPS connection passed certificate and hostname verification using {version}; other supported protocol versions were not tested.")
        if status == "attention" and e.get("encrypted") is False:
            return _result(item, "Unencrypted final page", "The selected link returned its final page over HTTP, without TLS protection.", "Serve the intended page over verified HTTPS before accepting private information.")
        if status == "attention" and "error" in e:
            if e.get("error") == "HTTPS-to-HTTP downgrade redirect observed and blocked.":
                return _result(item, "HTTPS downgrade blocked", "An HTTPS response redirected to HTTP; the checker blocked that downgrade.", "Keep the redirect chain on HTTPS and remove the HTTP destination.")
            if _text(e.get("error")) and e["error"].startswith("TLS certificate could not be verified:"):
                return _result(item, "Certificate not verified", "The TLS certificate did not pass this machine's verification; a server certificate issue or local trust-store issue may be responsible.", "Check the served certificate's hostname, validity and chain, and confirm the local trust store before retrying.")
            return _result(item, "Connection needs review", "The HTTPS check recorded a certificate-verification or downgrade problem; local trust-store issues can also cause verification errors.", "Inspect the certificate chain, hostname, local trust store and redirects; correct the recorded connection issue, then retry.")
    elif identifier == "certificate_expiry":
        days = e.get("days_remaining")
        if type(days) is not int or not -365000 <= days <= 365000 or status not in {"pass", "attention"} or (status == "pass") != (days >= 14):
            return _unknown("The saved certificate countdown is missing or disagrees with its result.", "Check the currently served certificate and run a new check.")
        presentation = certificate_expiry_presentation(item)
        label = "Expired" if days < 0 else "Less than 1 day left" if days == 0 else f"{days} {'day' if days == 1 else 'days'} left"
        fact = f"{days} days remained when checked." if days >= 14 else presentation["explanation"]
        return _result(item, label, fact, presentation["recommendation"] or NO_CHANGE)
    elif identifier == "rdap" and status == "info":
        if not _text(e.get("queried_domain"), 253) or _list(e.get("events")) is None or _list(e.get("nameservers")) is None:
            return _unknown()
        return _result(item, "Record found", f"The registry returned {len(e['events'])} event record(s) and {len(e['nameservers'])} nameserver record(s); this does not verify the site's identity or trustworthiness.")
    return _unknown()


def _headers(item, report):
    identifier, status, evidence = item["id"], item["status"], item.get("evidence")
    e = evidence if isinstance(evidence, dict) else {}
    if identifier == "hsts":
        if not _text(evidence):
            return _unknown()
        valid = _positive_hsts(evidence)
        if status == "pass" and valid:
            return _result(item, "HSTS set", "The HTTPS response declares a syntactically valid HSTS policy with a positive max-age; preload and parent-domain policies were not checked.")
        if status == "attention":
            if evidence in {"", "No HSTS header returned"}:
                return _result(item, "Not set", "No Strict-Transport-Security header was returned on the assessed response.", "After confirming HTTPS and subdomain readiness, configure a suitable HSTS max-age on HTTPS responses.")
            if re.search(r'(?:^|;)\s*max-age\s*=\s*"?0+"?\s*(?:;|$)', evidence, re.I) and not valid:
                return _result(item, "Positive HSTS not set", "The returned HSTS header contains max-age=0; a valid positive policy was not established.", "Review the complete HSTS syntax and choose a positive max-age after confirming HTTPS readiness.")
            return _result(item, "HSTS needs review", "A valid positive HSTS policy on an HTTPS response was not established from the returned declaration.", "Review the response scheme and HSTS syntax, including one positive max-age; test deployment before including subdomains.")
    elif identifier == "nosniff":
        if not _text(evidence):
            return _unknown()
        if status == "pass" and evidence.strip().lower() == "nosniff":
            return _result(item, "nosniff set", "X-Content-Type-Options is set to nosniff on this response.")
        if status == "attention" and evidence.strip().lower() != "nosniff":
            absent = evidence in {"", "Header absent"}
            return _result(item, "Not set" if absent else "Unrecognized value", "The response did not return X-Content-Type-Options." if absent else "X-Content-Type-Options was returned without the recognized single value nosniff.", "Return X-Content-Type-Options: nosniff alongside accurate Content-Type values.")
    elif identifier == "csp":
        if status == "info" and all(_text(e.get(key)) for key in ("header", "meta")) and (e["header"] or e["meta"]):
            source = "both the response header and HTML metadata" if e["header"] and e["meta"] else "the response header" if e["header"] else "HTML metadata"
            return _result(item, "Policy found", f"An enforcing CSP declaration was found in {source}; its directive strength and browser enforcement were not validated.", "Review the policy against the application's required resources and test its restrictions in the browser.")
        if status == "attention" and evidence == "No enforcing CSP header or HTML meta policy observed":
            return _result(item, "Not set", "No enforcing CSP header or supported HTML meta policy was found in the complete page.", "Develop an application-specific CSP, test it in report-only mode, then enforce the reviewed policy.")
    elif identifier == "framing":
        xframe, ancestor = e.get("x_frame_options"), e.get("frame_ancestors")
        if not _text(xframe) or (ancestor is not None and not _text(ancestor)):
            return _unknown()
        xframe = xframe.strip().upper()
        recognized = xframe in {"DENY", "SAMEORIGIN"}
        if status == "info" and (ancestor or recognized):
            labels = (["CSP frame-ancestors"] if ancestor else []) + (["X-Frame-Options: " + xframe] if recognized else [])
            return _result(item, "Policy found", "The response declares " + " and ".join(labels) + "; effective embedding restrictions were not validated.", "Confirm that the policy permits only the embedding the application needs.")
        if status == "attention" and not ancestor and not recognized:
            return _result(item, "Recognized policy not found", "No frame-ancestors directive or recognized X-Frame-Options value was observed.", "If embedding is unnecessary, restrict it with CSP frame-ancestors; otherwise allow only intended parents.")
    elif identifier == "referrer":
        policy, source = e.get("policy"), e.get("source")
        if policy in REFERRER_POLICIES and source in {"header", "meta"}:
            if policy == "unsafe-url" and status == "attention":
                return _result(item, "Full URL sharing declared", "The selected declaration is unsafe-url, which can share the page's path and query with other origins; actual requests were not tested.", "Consider strict-origin-when-cross-origin or a stricter suitable policy, and review HTML and element overrides.")
            if status == "info" and policy != "unsafe-url":
                return _result(item, "Policy declared", f"The selected {'response header' if source == 'header' else 'HTML metadata'} declaration is {policy}; per-request overrides were not tested.")
        if status == "info" and policy is None and "policy" in e:
            return _result(item, "No supported declaration", "No supported explicit referrer policy was selected from the available response; absence alone is not a privacy failure.", "Set a deliberate referrer policy if the application needs behavior different from browser defaults.")
    return _unknown()


def _page(item, report):
    identifier, status, evidence = item["id"], item["status"], item.get("evidence")
    e = evidence if isinstance(evidence, dict) else {}
    labels = {
        "title": ("A nonempty page title was found; its accuracy was not assessed.", "No nonempty title was found in the complete HTML.", "Add a concise, descriptive title inside the document head."),
        "viewport": ("A viewport meta declaration was found; responsive layout was not tested.", "No nonempty viewport declaration was found in the complete HTML.", "Add a suitable viewport meta declaration and test the layout on small screens."),
        "language": ("A nonempty document lang attribute was found; its value was not compared with the page's language.", "No nonempty document lang attribute was found in the complete HTML.", "Set the html element's lang attribute to the page's primary language."),
    }
    if identifier in labels:
        if not _text(evidence, 8192) or status not in {"pass", "attention"}:
            return _unknown()
        found = bool(evidence.strip()) if identifier != "viewport" else bool(evidence)
        if found != (status == "pass"):
            return _unknown()
        present, absent, fix = labels[identifier]
        return _result(item, "Found" if found else "Not set", present if found else absent, NO_CHANGE if found else fix)
    if identifier == "image_alt":
        images, missing = _count(e, "images"), _count(e, "missing_alt_attributes")
        if images is None or missing is None or missing > images or (status == "pass") != (missing == 0) or status not in {"pass", "attention"}:
            return _unknown()
        if not images:
            return _result(item, "No images found", "No img elements were found in the complete static HTML.")
        if missing:
            return _result(item, "Alt attributes missing", f"{missing} of {images} image(s) have no alt attribute; the quality of existing alternative text was not assessed.", "Add descriptive alt text for meaningful images and an empty alt attribute for purely decorative images.")
        return _result(item, "Attributes present", f"All {images} image(s) have an alt attribute; empty values may be appropriate for decorative images.")
    if identifier == "http_resources":
        count = _count(e, "count")
        if count is None or status not in {"pass", "attention"} or (status == "pass") != (count == 0):
            return _unknown()
        if count:
            return _result(item, "HTTP references found", f"{count} explicit HTTP resource reference(s) were found in inspected HTML attributes; browser upgrades or blocking were not tested.", "Replace the references with working HTTPS resources or suitable relative URLs, then check the browser's network panel.")
        return _result(item, "None found in HTML", "No explicit HTTP resource references were found in the inspected attributes; CSS and JavaScript-created requests were not checked.")
    if identifier == "password_forms":
        keys = ("forms_with_password", "password_inputs", "http_actions", "get_submissions", "cross_origin_actions", "unsupported_actions", "unassociated_password_inputs")
        if any(_count(e, key) is None for key in keys) or e.get("complete_html") is not True:
            return _unknown()
        counts = [e[key] for key in ("http_actions", "get_submissions", "cross_origin_actions")]
        if status == "attention" and any(counts):
            facts = [f"{e[key]} {label}" for key, label in (("http_actions", "HTTP action(s)"), ("get_submissions", "GET submission option(s)"), ("cross_origin_actions", "cross-origin action(s)")) if e[key]]
            return _result(item, "Destinations need review", "Static password-form markup contains " + ", ".join(facts) + "; no credentials were submitted.", "Use the intended HTTPS POST destination; verify any cross-origin sign-in destination and submit-button overrides.")
        if any(counts) or e["unsupported_actions"] or e["unassociated_password_inputs"]:
            return _unknown()
        destinations = _list(e.get("destinations"), 10)
        if destinations is None:
            return _unknown()
        if status == "info" and not e["forms_with_password"] and not destinations:
            return _result(item, "No password form found", "No named, enabled password form was found in the static HTML; JavaScript login flows were not inspected.")
        if status == "info" and e["forms_with_password"] and not destinations:
            return _result(item, "Dialog submission only", "The recorded password forms have dialog-only submission; no static network destination was recorded.")
        if status == "pass" and e["forms_with_password"] and destinations and all(isinstance(d, dict) and d.get("scheme") == "https" and d.get("method") == "POST" and d.get("same_origin") is True for d in destinations):
            return _result(item, "HTTPS POST observed", f"The recorded destinations for {e['forms_with_password']} password form(s) use same-origin HTTPS POST; login behavior was not tested.")
    return _unknown()


def _cookies(item, report):
    e = item.get("evidence")
    keys = ("cookies_observed", "missing_secure", "missing_http_only", "missing_same_site", "same_site_none_without_secure", "malformed_count")
    if not isinstance(e, dict) or any(_count(e, key) is None for key in keys) or any(e[key] > e["cookies_observed"] for key in keys[1:]):
        return _unknown()
    count, status = e["cookies_observed"], item["status"]
    if status == "attention" and e["missing_secure"]:
        return _result(item, "Secure attribute missing", f"{e['missing_secure']} of {count} returned cookie field(s) lack Secure; cookie values and purpose were not assessed.", "Use Secure for cookies intended for HTTPS; choose HttpOnly and SameSite according to each cookie's purpose.")
    if e["limited"] is not False or e["malformed_count"] or e["missing_secure"]:
        return _unknown()
    if status == "info" and not count:
        return _result(item, "No cookies returned", "This response returned no Set-Cookie fields; later pages or scripts may still set cookies.")
    if status == "info" and count and (e["missing_http_only"] or e["missing_same_site"]):
        return _result(item, "Purpose review needed", f"Secure is declared on all {count} cookie(s); {e['missing_http_only']} lack HttpOnly and {e['missing_same_site']} lack a recognized SameSite value.", "Review cookie purpose before adding attributes; script-readable cookies may intentionally omit HttpOnly.")
    if status == "pass" and count and not e["missing_http_only"] and not e["missing_same_site"]:
        return _result(item, "Attributes present", f"All {count} observed cookie(s) declare Secure, HttpOnly and a recognized SameSite value; logged-in sessions were not tested.")
    return _unknown()


def _hygiene(item, report):
    identifier, status, e = item["id"], item["status"], item.get("evidence")
    if not isinstance(e, dict):
        return _unknown()
    if identifier == "header_quality":
        issues, limited = _list(e.get("issues")), _list(e.get("limited_headers"))
        if issues is None or limited is None:
            return _unknown()
        names = {"x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options", "content-security-policy": "CSP"}
        labels = {"multiple_values": "multiple values", "unrecognized_value": "an unrecognized value", "duplicate_directives": "repeated directives"}
        if status == "attention" and issues:
            if any(not isinstance(issue, dict) or issue.get("header") not in names or issue.get("issue") not in labels for issue in issues):
                return _unknown()
            details = list(dict.fromkeys(names[issue["header"]] + " has " + labels[issue["issue"]] for issue in issues))
            return _result(item, "Declarations need review", "; ".join(details[:3]) + ".", "Reconcile application and proxy headers; use one valid value for single-value fields and remove repeated directives within each CSP policy.")
        if status == "info" and not issues and not limited and e.get("checked_headers") == list(names):
            return _result(item, "No conflicts found", "No reviewed value conflicts were found in X-Content-Type-Options, X-Frame-Options or CSP; header presence is reported separately.")
    elif identifier == "cors_policy":
        issues = _list(e.get("issues"))
        if issues is None or e.get("origin_probe_performed") is not False:
            return _unknown()
        if status == "attention":
            if "wildcard_with_credentials" in issues:
                return _result(item, "Incompatible combination", "The response declares wildcard origin sharing with credentials; browsers reject this combination for credentialed CORS reads.", "For intended credentialed access, return an explicit allowed origin; otherwise omit the credentials header.")
            if "null_origin_allowed" in issues:
                return _result(item, "Null origin allowed", "The response allows the null origin, which sandboxed or local documents can use; authenticated access was not tested.", "Remove null-origin trust unless deliberately required and review the intended explicit origin allowlist.")
            if set(issues) & {"unrecognized_credentials_value", "unrecognized_origin_value"}:
                return _result(item, "CORS value unrecognized", "A returned CORS origin or credentials value was not recognized by this inspection.", "Use a supported single origin value and the exact credentials value true only when intended; inspect the complete response.")
        if status == "info" and not issues:
            values = {
                "absent": ("Not set", "No Access-Control-Allow-Origin declaration was returned; public pages do not always need cross-origin sharing."),
                "wildcard": ("Public sharing declared", "Access-Control-Allow-Origin permits wildcard sharing; this alone is not a vulnerability or permission for credentialed reads."),
                "single_origin": ("One origin declared", "The response declares one allowed origin; arbitrary-origin trust and authenticated access were not tested."),
            }
            if e.get("allow_origin") in values:
                return _result(item, *values[e["allow_origin"]], NO_CHANGE)
    elif identifier == "response_caching":
        issues, directives = _list(e.get("issues")), _list(e.get("directives"))
        if issues is None or directives is None or any(type(e.get(key)) is not bool for key in ("no_store", "private", "no_cache", "explicit_shared_cache", "password_input_observed", "sets_cookie")):
            return _unknown()
        if status == "attention" and "shared_cache_with_account_context" in issues:
            context = "a password input and Set-Cookie" if e["password_input_observed"] and e["sets_cookie"] else "a password input" if e["password_input_observed"] else "Set-Cookie"
            return _result(item, "Shared caching needs review", f"The response explicitly permits shared caching and includes {context}; personalized content was not confirmed.", "Check that shared caches never store per-user content; use private or no-store on responses that need it.")
        if status == "attention" and set(issues) & {"unrecognized_directive_syntax", "invalid_or_repeated_max-age", "invalid_or_repeated_s-maxage"}:
            return _result(item, "Cache syntax needs review", "Cache-Control contains unrecognized syntax or an invalid/repeated age directive.", "Reconcile the Cache-Control fields and return valid, deliberate caching directives.")
        if status == "info" and not issues:
            if e["no_store"]:
                return _result(item, "Storage prohibited", "Cache-Control declares no-store on this response; actual cache behavior was not tested.")
            if e["private"]:
                return _result(item, "Private caching declared", "Cache-Control declares private, restricting shared caches; browser storage can still occur.")
            if e["no_cache"]:
                return _result(item, "Revalidation required", "Cache-Control declares no-cache, which requires revalidation and does not prohibit storage.")
            if e["explicit_shared_cache"]:
                return _result(item, "Shared caching declared", "The response explicitly permits shared caching; no password input or Set-Cookie context was recorded.")
            return _result(item, "No shared-cache flag found", "No recognized explicit public-sharing, private, no-store or no-cache flag was recorded; public content can still be cacheable.")
    elif identifier == "browser_isolation":
        policies, issues, limited = e.get("policies"), _list(e.get("unrecognized_headers")), _list(e.get("limited_headers"))
        names = {"cross-origin-opener-policy": "COOP", "cross-origin-embedder-policy": "COEP", "cross-origin-resource-policy": "CORP", "permissions-policy": "Permissions-Policy"}
        if not isinstance(policies, dict) or issues is None or limited is None:
            return _unknown()
        if status == "attention" and issues and all(name in ISOLATION for name in issues):
            return _result(item, "Policy token unrecognized", ", ".join(names[name] for name in issues) + " contains an unrecognized declaration; browser behavior was not tested.", "Correct the declaration against browser support, then test affected embeds, sign-in and popups.")
        if status == "info" and not issues and not limited:
            if any(policies.get(name) not in allowed | {"absent"} for name, allowed in ISOLATION.items()) or policies.get("permissions-policy") not in {"absent", "present"}:
                return _unknown()
            active = [names[name] + (": " + policies[name] if name in ISOLATION else " present") for name in names if policies[name] != "absent"]
            if active:
                return _result(item, "Optional policies found", "; ".join(active) + "; actual isolation and feature permissions were not tested.", "Keep only policies suitable for the application and test affected browser integrations.")
            return _result(item, "Not set (optional)", "No COOP, COEP, CORP or Permissions-Policy declaration was returned; these are application-dependent, optional policies.")
    elif identifier == "public_disclosures":
        versions, markers = _list(e.get("version_hints")), _list(e.get("error_page_markers"))
        if versions is None or markers is None:
            return _unknown()
        labels = {"django_debug_error": "Django debug", "werkzeug_debugger_error": "Werkzeug debugger", "php_stack_trace_error": "PHP stack-trace"}
        if status == "attention" and markers and all(marker in labels for marker in markers) and e.get("error_response_checked") is True:
            return _result(item, "Debug markers found", "The returned server-error page contains " + ", ".join(labels[marker] for marker in markers) + " markers; no hidden paths were requested.", "Disable public debug output in production, return a generic error page and keep detailed errors in private logs.")
        if status == "info" and not markers and e.get("limited_headers") is False:
            if versions:
                return _result(item, "Version hints found", f"{len(versions)} software-version hint(s) were found in public metadata; installed versions and vulnerabilities were not verified.", "Keep software updated; consider removing unnecessary version banners without treating this as a substitute for updates.")
            return _result(item, "No selected hints found", "No selected software-version hints or matching server-error debug markers were recorded in this response.")
    elif identifier == "iframe_sandbox":
        keys = ("iframes_observed", "sandbox_present", "scripts_and_same_origin_allowed", "same_origin_source_with_both", "unresolved_sources")
        if any(_count(e, key) is None for key in keys) or any(e[key] > e["iframes_observed"] for key in keys[1:]):
            return _unknown()
        concern = e["same_origin_source_with_both"]
        if status == "attention" and concern:
            return _result(item, "Sandbox combination needs review", f"{concern} initially same-origin iframe(s) allow both scripts and same-origin access; frame responses and redirects were not loaded.", "For untrusted same-origin embeds, avoid combining allow-scripts and allow-same-origin; use the minimum permissions or a separate origin.")
        if status == "info" and not concern and e.get("complete_html") is True and e.get("limited") is False and not e["unresolved_sources"]:
            if not e["iframes_observed"]:
                return _result(item, "No iframes found", "No supported iframe elements were found in the complete static HTML.")
            return _result(item, "Declarations recorded", f"{e['sandbox_present']} of {e['iframes_observed']} iframe(s) declare sandbox; absence can be intentional for trusted embeds.", "Confirm that untrusted embeds have suitable sandbox permissions; no change is needed solely because a trusted embed omits sandbox.")
    return _unknown()


def _contact(item, report):
    e, status = item.get("evidence"), item["status"]
    if not isinstance(e, dict):
        return _unknown()
    issues = _list(e.get("issues"), 32)
    if issues is None or any(not isinstance(issue, dict) or not isinstance(issue.get("code"), str) for issue in issues):
        return _unknown()
    codes = {issue["code"] for issue in issues}
    if status == "info" and e.get("status") == "not_found" and e.get("http_status") in {404, 410}:
        return _result(item, "Not found (optional)", "No security.txt file was found at the standard public location; other reporting channels may exist.", "Consider publishing a maintained /.well-known/security.txt with the intended contact channel and a future expiry.")
    if status == "info" and e.get("status") == "current" and not issues and _count(e, "contact_count"):
        return _result(item, "Contact file found", f"{e['contact_count']} Contact field(s) and a future expiry were recorded when checked; contact delivery and identity were not verified.")
    if status == "attention" and e.get("status") == "review" and issues:
        options = (
            ("expired", "Contact file expired", "The contact file's stated expiry had passed when checked.", "Confirm that the contact channels still work and update Expires to a suitable future timestamp."),
            ("canonical_mismatch", "Canonical URL mismatch", "No Canonical field matched the contact file's retrieval URL.", "Verify the intended contact file independently and correct its Canonical URL before relying on its contacts."),
            ("missing_contact", "Contact field missing", "The returned contact file contains no Contact field.", "Publish a usable Contact URI and maintain its future Expires timestamp."),
            ("content_type", "Plain-text file not established", "The standard location did not return supported UTF-8 text/plain content.", "Serve the intended security.txt as UTF-8 text/plain instead of a generic HTML fallback."),
            ("expires_count", "Expiry field needs review", "The contact file did not contain exactly one Expires field.", "Publish one future RFC 3339 Expires timestamp with a timezone."),
            ("expires_format", "Expiry format needs review", "The Expires value was not a supported timestamp with a timezone.", "Use a future RFC 3339 timestamp with a timezone in the Expires field."),
            ("long_expiry", "Long freshness window", "The contact file's expiry was more than a year away when checked.", "Use a shorter freshness window and review the contact file regularly."),
        )
        for code, label, fact, fix in options:
            if code in codes:
                return _result(item, label, fact + (" Additional format issues are recorded in the evidence." if len(codes) > 1 else ""), fix)
        if codes & {"encoding", "byte_order_mark", "control_characters", "final_newline", "field_format", "contact_uri", "canonical_uri"}:
            return _result(item, "Contact format needs review", "The contact file contains unsupported encoding, field formatting or URI syntax; the exact issue codes are recorded in the evidence.", "Publish plain UTF-8 Name: value fields with usable absolute contact URIs, HTTPS web links and a final newline.")
    return _unknown()


HANDLERS = {
    **dict.fromkeys(("dns", "https_redirect", "tls", "certificate_expiry", "rdap"), _transport),
    **dict.fromkeys(("hsts", "csp", "framing", "nosniff", "referrer"), _headers),
    **dict.fromkeys(("title", "viewport", "language", "image_alt", "http_resources", "password_forms"), _page),
    "cookie_flags": _cookies,
    **dict.fromkeys(("header_quality", "cors_policy", "response_caching", "browser_isolation", "public_disclosures", "iframe_sandbox"), _hygiene),
    "security_contact": _contact,
}


def check_feedback_for_report(report):
    """Return Test→Result→Fact→Fix copy keyed by finding ID; keep raw data intact.

    Malformed, duplicated or unsupported findings receive an explicit unknown
    presentation. Feedback is recomputed on display/export, never trusted from
    imported presentation fields. It is not a second assessment or score.
    """
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return {}
    findings = report["findings"]
    result, seen = {}, set()
    for item in findings[:128]:
        if not isinstance(item, dict):
            continue
        identifier = item.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,47}", identifier):
            continue
        if len(findings) > 128:
            result[identifier] = _unknown("The report exceeds the finding-count limit for this presentation.")
            continue
        if identifier in seen:
            result[identifier] = _unknown("More than one finding uses this ID, so a single result cannot be established.", "Run a new check; do not rely on duplicated findings in an imported report.")
            continue
        seen.add(identifier)
        if item.get("status") not in STATES or identifier not in HANDLERS:
            result[identifier] = _unknown("This saved check or result format is not supported by the current presentation.")
            continue
        try:
            result[identifier] = _unavailable(item, report) if item["status"] == "unknown" else HANDLERS[identifier](item, report)
        except (TypeError, ValueError, KeyError, OverflowError, AttributeError):
            result[identifier] = _unknown()
    return result
