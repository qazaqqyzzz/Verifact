"""Unscored owner review of data already returned by the public page.

No requests, Origin probes, browser execution, version/CVE lookups or form
submissions occur here. Evidence deliberately omits raw headers and page text.
"""

import re
from urllib.parse import urljoin, urlsplit


MAX_HEADER = 8192
ASCII_SPACE = " \t\r\n\f"
ISOLATION = {
    "cross-origin-opener-policy": {"unsafe-none", "same-origin", "same-origin-allow-popups", "noopener-allow-popups"},
    "cross-origin-embedder-policy": {"unsafe-none", "require-corp", "credentialless"},
    "cross-origin-resource-policy": {"same-site", "same-origin", "cross-origin"},
}
TITLES = {
    "header_quality": "Security header consistency",
    "cors_policy": "Cross-origin response sharing",
    "response_caching": "Response caching",
    "browser_isolation": "Optional browser isolation policies",
    "public_disclosures": "Public software and error details",
    "iframe_sandbox": "Iframe sandbox declarations",
}


def _finding(identifier, status, evidence, explanation, recommendation=""):
    return {"id": identifier, "category": "Browser", "status": status,
            "title": TITLES[identifier], "evidence": evidence,
            "explanation": explanation, "recommendation": recommendation}


def _header(response, name):
    value = response.headers.get(name, "")
    if not isinstance(value, str) or len(value) > MAX_HEADER or any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
        return None
    return value.strip(" \t")


def _parts(value, separator=","):
    """Split list fields without splitting a quoted argument or report group."""
    result, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == separator and not quoted:
            result.append(value[start:index].strip(" \t"))
            start = index + 1
    if quoted or escaped:
        return None
    result.append(value[start:].strip(" \t"))
    return result if len(result) <= 128 else None


def header_quality(response):
    issues, limited = [], []
    checked = ("x-content-type-options", "x-frame-options", "content-security-policy")
    for name in checked:
        value = _header(response, name)
        if value is None:
            limited.append(name)
            continue
        if not value:
            continue  # Absence is already covered by the fixed checklist.
        if name in {"x-content-type-options", "x-frame-options"}:
            expected = {"nosniff"} if name == "x-content-type-options" else {"deny", "sameorigin"}
            if "," in value:
                issues.append({"header": name, "issue": "multiple_values",
                               "detail": "Multiple values were returned for a single-value policy; review the application and proxy configuration."})
            elif value.lower() not in expected:
                issues.append({"header": name, "issue": "unrecognized_value",
                               "detail": "The declared value is not one of this policy's supported values."})
        else:
            # Multiple enforcing CSP policies are valid; duplicate directive
            # names matter within one policy, not across separate policies.
            policies = _parts(value)
            if policies is None:
                limited.append(name)
                continue
            duplicate_policies = 0
            for policy in policies:
                names = []
                for directive in policy.split(";"):
                    match = re.match(r"^\s*([a-zA-Z0-9-]+)(?:\s|$)", directive)
                    if match:
                        names.append(match.group(1).lower())
                duplicate_policies += len(names) != len(set(names))
            if duplicate_policies:
                issues.append({"header": name, "issue": "duplicate_directives", "policy_count": duplicate_policies,
                               "detail": "A CSP policy repeats a directive name. Browsers use its first occurrence and ignore later occurrences."})
    return _finding("header_quality", "attention" if issues else "unknown" if limited else "info",
                    {"issues": issues, "limited_headers": limited, "checked_headers": list(checked)},
                    "Reviews selected declarations for multiple values and repeated CSP directives. This is not a full policy parser or browser enforcement test. Original duplicate field boundaries are not retained by this check.",
                    "Set each policy deliberately in one place, reconcile proxy/application values, and test the resulting response in a browser." if issues else "")


def cors_review(response):
    origin = _header(response, "access-control-allow-origin")
    credentials = _header(response, "access-control-allow-credentials")
    vary = _header(response, "vary")
    evidence = {"allow_origin": "absent", "credentials_allowed": credentials == "true",
                "vary_origin": None if vary is None else any(p.strip().lower() in {"origin", "*"} for p in vary.split(",")),
                "origin_probe_performed": False, "issues": []}
    explanation = "Only the ordinary public response was inspected. No Origin header was injected, no preflight was sent, and authenticated data access was not tested. "
    if origin is None or credentials is None:
        evidence["allow_origin"] = "unassessed"
        return _finding("cors_policy", "unknown", evidence, explanation + "A CORS field could not be interpreted within the inspection limits.")
    if credentials and credentials != "true":
        evidence["issues"].append("unrecognized_credentials_value")
    if origin == "*":
        evidence["allow_origin"] = "wildcard"
        explanation += "Wildcard sharing can be intentional for public content. It does not permit browsers to read a response using credentialed CORS. "
        if credentials == "true":
            evidence["issues"].append("wildcard_with_credentials")
            explanation += "The wildcard/credentials combination is incompatible for credentialed reads; this is not evidence of credential leakage. "
    elif origin == "null":
        evidence["allow_origin"] = "null"
        evidence["issues"].append("null_origin_allowed")
        explanation += "The null origin can be created by sandboxed or local documents. Review whether sharing with these origins is intended. "
    elif origin:
        try:
            parsed = urlsplit(origin)
            valid = (bool(parsed.scheme and parsed.hostname) and not parsed.path and not parsed.query and not parsed.fragment
                     and parsed.username is None and parsed.password is None and parsed.port != 0
                     and origin.isascii() and not any(c.isspace() or c in ",\\" for c in origin))
        except ValueError:
            valid = False
        evidence["allow_origin"] = "single_origin" if valid else "unrecognized"
        if not valid:
            evidence["issues"].append("unrecognized_origin_value")
        explanation += "A returned origin does not establish that arbitrary origins are trusted. If the response varies by requesting origin, send Vary: Origin and use a deliberate allowlist. "
    else:
        explanation += "No cross-origin sharing permission was observed; CORS headers are not required on every page. "
    issues = evidence["issues"]
    return _finding("cors_policy", "attention" if issues else "info", evidence, explanation.strip(),
                    "For credentialed access, allow only intended explicit origins and return Access-Control-Allow-Credentials: true. Omit the credentials header when not needed; avoid null-origin trust." if issues else "")


def cache_review(response, page):
    value = _header(response, "cache-control")
    evidence = {"directives": [], "no_store": False, "private": False, "no_cache": False,
                "explicit_shared_cache": False, "password_input_observed": bool(page.password_inputs),
                "sets_cookie": bool(getattr(response, "set_cookie_headers", None) or response.headers.get("set-cookie")),
                "personalized_content_confirmed": False, "issues": []}
    fields = _parts(value) if value is not None else None
    if fields is None:
        return _finding("response_caching", "unknown", evidence, "Cache-Control could not be interpreted within the inspection limits. Logged-in responses and cache behavior were not tested.")
    directives = {}
    for field in fields:
        if not field:
            continue
        match = re.fullmatch(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:\s*=\s*(.*))?", field)
        if not match:
            evidence["issues"].append("unrecognized_directive_syntax")
            continue
        name, argument = match.group(1).lower(), match.group(2)
        directives.setdefault(name, []).append(argument)
    # Names alone are not copied: extension names/arguments may contain values
    # unrelated to this review. Only recognized public policy flags leave here.
    known = {"no-store", "no-cache", "private", "public", "max-age", "s-maxage", "must-revalidate", "proxy-revalidate", "immutable"}
    evidence["directives"] = sorted(set(directives) & known)
    for name in ("no-store", "private", "no-cache"):
        evidence[name.replace("-", "_")] = None in directives.get(name, [])
    for name in ("max-age", "s-maxage"):
        arguments = directives.get(name, [])
        if len(arguments) > 1 or any(argument is None or not re.fullmatch(r'"?[0-9]{1,10}"?', argument) or argument.count('"') == 1 for argument in arguments):
            evidence["issues"].append("invalid_or_repeated_" + name)
    shared = (None in directives.get("public", []) or any(argument is not None and re.fullmatch(r'"?[0-9]{1,10}"?', argument)
                                                         and argument.count('"') != 1 and int(argument.strip('"')) > 0
                                                         for argument in directives.get("s-maxage", [])))
    evidence["explicit_shared_cache"] = bool(shared and not evidence["no_store"] and not evidence["private"])
    review = evidence["explicit_shared_cache"] and (evidence["password_input_observed"] or evidence["sets_cookie"])
    if review:
        evidence["issues"].append("shared_cache_with_account_context")
    explanation = "Describes caching instructions on this one public response. A login form or Set-Cookie field does not prove the content is personalized. "
    if review:
        explanation += "The response explicitly permits shared caching and has account/cookie context; verify that no personalized content or per-user values are shared. "
    if evidence["no_cache"]:
        explanation += "no-cache asks caches to revalidate; it does not prohibit storage. "
    if not value:
        explanation += "No Cache-Control field was observed. Public pages can intentionally be cacheable. "
    explanation += "Actual browser/CDN caches and responses after signing in were not tested."
    return _finding("response_caching", "attention" if evidence["issues"] else "info", evidence, explanation,
                    "Review caching for account pages. Use private for personalized responses that may be stored locally, or no-store when sensitive responses must not be stored; keep public caching for genuinely shared content." if evidence["issues"] else "")


def isolation_review(response):
    policies, issues, limited = {}, [], []
    for name, allowed in ISOLATION.items():
        value = _header(response, name)
        if value is None:
            limited.append(name)
            policies[name] = "unassessed"
        elif not value:
            policies[name] = "absent"
        else:
            parts = _parts(value)
            token = value.split(";", 1)[0].strip()
            no_parameters = name != "cross-origin-resource-policy" or ";" not in value
            policies[name] = token if token in allowed and parts is not None and len(parts) == 1 and no_parameters else "unrecognized"
            if policies[name] == "unrecognized":
                issues.append(name)
    permissions = _header(response, "permissions-policy")
    policies["permissions-policy"] = "unassessed" if permissions is None else "present" if permissions else "absent"
    if permissions is None:
        limited.append("permissions-policy")
    return _finding("browser_isolation", "attention" if issues else "unknown" if limited else "info",
                    {"policies": policies, "unrecognized_headers": issues, "limited_headers": limited,
                     "browser_isolation_tested": False},
                    "Known COOP, COEP and CORP policy tokens are recorded, not a complete grammar validation; Permissions-Policy is presence-only. These policies are optional and depend on the application's embeds, resources, sign-in and payment flows. Absence is not scored as a failure. Actual isolation and feature permissions were not tested.",
                    "Review the unrecognized declarations against browser support. Choose only policies suitable for the application and test third-party embeds, sign-in and popups before deployment." if issues else "")


def disclosure_review(response, page, html_available):
    versions, limited = [], False
    products = r"nginx|Apache|PHP|Microsoft-IIS|OpenResty|LiteSpeed|Werkzeug|Python|Express|ASP\.NET|WordPress|Drupal|Joomla"
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "generator"):
        value = page.profile_generator if name == "generator" and html_available else "" if name == "generator" else _header(response, name)
        if value is None:
            limited = True
            continue
        if name in {"x-aspnet-version", "x-aspnetmvc-version"}:
            match = re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,5}){1,3}", value)
            if match:
                versions.append({"source": name, "product": "ASP.NET", "version": match.group()})
        else:
            for match in list(re.finditer(r"\b(" + products + r")[/ ]([0-9]{1,3}(?:\.[0-9]{1,5}){1,3})(?![0-9.])", value, re.I))[:8]:
                versions.append({"source": name, "product": match.group(1), "version": match.group(2)})
    markers = []
    # Error responses only: quoted examples on successful tutorials should not
    # become debug findings. Raw text, paths, variable names and values stay out.
    if html_available and response.status >= 500:
        body = response.body[:262144].decode("utf-8", errors="ignore")
        if "Django Version:" in body and re.search(r"DEBUG\s*(?:</?[^>]+>\s*)*=\s*(?:</?[^>]+>\s*)*True", body):
            markers.append("django_debug_error")
        if "Werkzeug Debugger" in page.title and "__debugger__" in body:
            markers.append("werkzeug_debugger_error")
        if re.search(r"Fatal error\s*:\s*(?:</?[^>]+>\s*)*Uncaught", body, re.I) and "Stack trace:" in body:
            markers.append("php_stack_trace_error")
    return _finding("public_disclosures", "attention" if markers else "unknown" if limited else "info",
                    {"version_hints": versions, "error_page_markers": markers,
                     "error_response_checked": bool(html_available and response.status >= 500),
                     "version_vulnerabilities_checked": False, "limited_headers": limited},
                    ("The returned server-error page contains recognizable debug or stack-trace markers. Review its public error handling. " if markers else "")
                    + "Selected public headers and generator metadata may disclose software versions. These are unverified hints, not proof of an installed version, outdated software or a vulnerability. No hidden paths or credentials were searched, and no software vulnerability database was queried.",
                    "Disable public debug output in production, return a generic error page and keep detailed errors in private logs. Review unnecessary version banners without treating their removal as a substitute for updates." if markers else "")


def iframe_review(response, page, html_available, complete):
    evidence = {"iframes_observed": len(page.hygiene_frames), "sandbox_present": 0,
                "scripts_and_same_origin_allowed": 0, "same_origin_source_with_both": 0,
                "unresolved_sources": 0, "limited": page.hygiene_frames_limited, "complete_html": complete}
    if not html_available:
        evidence["iframes_observed"] = None
        return _finding("iframe_sandbox", "unknown", evidence, "Supported HTML was unavailable, so iframe sandbox declarations were not assessed.")
    for frame in page.hygiene_frames:
        if frame["sandbox"] is None:
            if frame["present"]:
                evidence["limited"] = True
            continue
        evidence["sandbox_present"] += 1
        tokens = frame["sandbox"].lower().split()
        if not {"allow-scripts", "allow-same-origin"} <= set(tokens):
            continue
        evidence["scripts_and_same_origin_allowed"] += 1
        try:
            if frame["srcdoc"] or frame["src"] in {"", "about:blank"}:
                same = True
            else:
                if frame["src"] is None or frame["base"] is False:
                    raise ValueError("Unresolved")
                source = frame["src"].strip(ASCII_SPACE).replace("\t", "").replace("\n", "").replace("\r", "")
                resolved = urljoin(urljoin(response.url, frame["base"] or ""), source)
                # Use the same cautious URL origin rules as existing form checks.
                from .checks import _origin
                same = _origin(resolved) == _origin(response.url)
            evidence["same_origin_source_with_both"] += same
        except ValueError:
            evidence["unresolved_sources"] += 1
    concern = evidence["same_origin_source_with_both"] > 0
    return _finding("iframe_sandbox", "attention" if concern else "unknown" if evidence["limited"] or evidence["unresolved_sources"] or not complete else "info", evidence,
                    "Records sandbox attributes in static HTML. A same-origin frame allowed both scripts and same-origin access may remove its sandbox. Initial source origins are observations only: frame responses, redirects, inherited policies and script changes were not tested. An absent sandbox can be intentional for trusted embeds.",
                    "For untrusted same-origin embeds, avoid combining allow-scripts with allow-same-origin; consider a separate origin and the minimum sandbox permissions the embed needs." if concern else "")


def hygiene_checks(response, page, html_available=False, complete=False):
    if response is None:
        return [_finding(identifier, "unknown", {}, "No response was available for this owner review.") for identifier in TITLES]
    return [header_quality(response), cors_review(response), cache_review(response, page),
            isolation_review(response), disclosure_review(response, page, html_available),
            iframe_review(response, page, html_available, complete)]
