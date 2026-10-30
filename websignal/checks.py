"""Deterministic checks. A positive observation is not a security guarantee."""

from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import unicodedata
from urllib.parse import urljoin, urlsplit

from .security_hygiene import hygiene_checks


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.document_title_seen = False
        self.head_closed = False
        self.meta_csp = []
        self.referrer_policies = []
        self.referrer_meta_limited = False
        self.meta = {}
        self.lang = ""
        self.images = 0
        self.images_without_alt = 0
        self.http_resources = []
        self.https_base = False
        self.base_href = None
        self.description = ""
        self.forms = []
        self.current_form = None
        self.password_inputs = []
        self.submit_controls = []
        self.form_markup_uncertain = False
        self.template_depth = 0
        self.seen_ids = set()
        self.duplicate_ids = set()
        # Used only to infer page purpose. Never included verbatim in reports.
        self.profile_text = ""
        self.profile_headings = ""
        self.profile_generator = ""
        self._profile_stack = []
        # Only bounded dependency attributes are kept for the optional static
        # page-dependency summary. Full resource URLs never leave this parser.
        self.dependencies = []
        self.dependency_base = None
        self.dependency_limited = False
        self.dependency_unsupported = 0
        self.hygiene_frames = []
        self.hygiene_frames_limited = False

    def _capture_hygiene_frame(self, tag, attrs):
        if tag != "iframe":
            return
        ancestors = {parent[0] for parent in self._profile_stack[:-1]}
        if ancestors.intersection({"template", "noscript", "iframe", "textarea", "title", "xmp", "noembed", "noframes", "plaintext", "style", "script", "svg", "math"}):
            return
        if len(self.hygiene_frames) >= 100:
            self.hygiene_frames_limited = True
            return
        sandbox, source = attrs.get("sandbox") or "", attrs.get("src") or ""
        self.hygiene_frames.append({"present": "sandbox" in attrs,
                                    "sandbox": sandbox if "sandbox" in attrs and len(sandbox) <= 1024 else None,
                                    "src": source if len(source) <= 2048 else None,
                                    "srcdoc": "srcdoc" in attrs, "base": self.dependency_base})

    def _capture_dependency(self, tag, attrs):
        stack = self._profile_stack if tag == "base" else self._profile_stack[:-1]
        ancestors = {parent[0] for parent in stack}
        if ancestors.intersection({"template", "noscript", "iframe", "textarea", "title", "xmp", "noembed", "noframes", "plaintext", "style", "script"}):
            return
        if tag == "base" and self.dependency_base is None and "href" in attrs:
            value = attrs.get("href") or ""
            self.dependency_base = value if len(value) <= 2048 else False
            return
        if tag not in {"script", "iframe"} or "src" not in attrs:
            return
        if ancestors.intersection({"svg", "math"}):
            self.dependency_unsupported = min(200, self.dependency_unsupported + 1)
            return
        if tag == "iframe" and "srcdoc" in attrs:
            return  # srcdoc takes precedence; inline frame contents are out of scope.
        kind = "iframe"
        if tag == "script":
            value = attrs.get("type")
            if value is None:
                value = "text/" + attrs["language"] if attrs.get("language") else "text/javascript"
            if value == "":
                value = "text/javascript"
            javascript = {"application/ecmascript", "application/javascript", "application/x-ecmascript", "application/x-javascript",
                          "text/ecmascript", "text/javascript", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
                          *("text/javascript1." + str(version) for version in range(6))}
            kind = "module" if value.lower() == "module" else "script" if value.strip(" \t\n\r\f").lower() in javascript else None
            if kind is None:
                return  # JSON, import maps and other data blocks do not fetch src.
        if len(self.dependencies) >= 200:
            self.dependency_limited = True
            return
        source = attrs.get("src") or ""
        integrity = attrs.get("integrity") or ""
        self.dependencies.append({"kind": kind, "src": source if len(source) <= 2048 else None,
                                  "base": self.dependency_base,
                                  "integrity": integrity if len(integrity) <= 4096 else None,
                                  "crossorigin": "crossorigin" in attrs})

    def _profile_start(self, tag, attrs):
        """Collect bounded visible-text cues without reading input values."""
        excluded = {"head", "script", "style", "template", "noscript", "textarea", "select", "output", "code", "pre"}
        void = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
        hidden = (tag in excluded or "hidden" in attrs or (attrs.get("aria-hidden") or "").lower() == "true"
                  or re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", attrs.get("style") or "", re.I))
        suppressed = bool(hidden or (self._profile_stack and self._profile_stack[-1][1]))
        heading = tag in {"h1", "h2", "h3"} or bool(self._profile_stack and self._profile_stack[-1][2])
        if tag not in void:
            self._profile_stack.append((tag, suppressed, heading))
        if (tag == "meta" and (attrs.get("name") or "").lower() == "generator"
                and not any(parent[0] in {"template", "noscript", "script", "style"} for parent in self._profile_stack)):
            self.profile_generator = (attrs.get("content") or "")[:160]

    def handle_starttag(self, tag, attrs):
        # HTML keeps the first occurrence of a duplicate attribute. Keeping the
        # last can hide an HTTP action or GET method behind a second value.
        attributes = {}
        for name, value in attrs:
            attributes.setdefault(name, value)
        attrs = attributes
        self._profile_start(tag, attrs)
        if tag == "template":
            self.template_depth += 1
        if self.template_depth:
            return
        self._capture_dependency(tag, attrs)
        self._capture_hygiene_frame(tag, attrs)
        if tag not in {"html", "head", "title", "base", "link", "meta", "style", "script", "noscript"}:
            self.head_closed = True
        if attrs.get("id"):
            if attrs["id"] in self.seen_ids:
                self.duplicate_ids.add(attrs["id"])
            self.seen_ids.add(attrs["id"])
        if tag == "fieldset" and "disabled" in attrs:
            # Browser ownership/disabled-fieldset rules have special cases.
            self.form_markup_uncertain = True
        if (tag == "title" and not self.document_title_seen
                and not any(parent[0] in {"svg", "math"} for parent in self._profile_stack)):
            self.in_title = True
            self.document_title_seen = True
        if tag == "html":
            self.lang = attrs.get("lang") or ""
        if tag == "meta":
            key = attrs.get("name") or attrs.get("http-equiv") or ""
            self.meta[key.lower()] = attrs.get("content") or ""
            if ((attrs.get("name") or "").lower() == "referrer"
                    and not any(parent[0] in {"noscript", "template", "iframe", "textarea", "title", "xmp",
                                               "noembed", "noframes", "plaintext", "svg", "math"}
                                for parent in self._profile_stack)):
                value = attrs.get("content") or ""
                if len(self.referrer_policies) < 32 and len(value) <= 256:
                    self.referrer_policies.append(value)
                else:
                    self.referrer_meta_limited = True
            # A name="content-security-policy" tag is only arbitrary metadata.
            # The http-equiv pragma is only supported in the document head.
            if ((attrs.get("http-equiv") or "").lower() == "content-security-policy"
                    and not self.head_closed and (attrs.get("content") or "").strip()
                    and not any(parent[0] == "noscript" for parent in self._profile_stack)):
                self.meta_csp.append(attrs["content"])
            description_key = attrs.get("name") or attrs.get("property") or ""
            if not self.description and description_key.lower() in {"description", "og:description"}:
                self.description = attrs.get("content") or ""
        if tag == "base" and self.base_href is None and "href" in attrs:
            self.base_href = attrs.get("href") or ""
        if tag == "base" and (attrs.get("href") or "").lower().startswith("https://"):
            self.https_base = True
        if tag == "img":
            self.images += 1
            if "alt" not in attrs:
                self.images_without_alt += 1
        source = attrs.get("src") if tag in {"img", "script", "iframe", "audio", "video", "source"} else None
        if tag == "link" and "stylesheet" in (attrs.get("rel") or "").lower().split():
            source = attrs.get("href")
        if source:
            # Browsers trim leading/trailing C0 whitespace and remove ASCII
            # tabs/newlines while parsing a URL, including inside its scheme.
            source = source.strip("".join(chr(code) for code in range(33)))
            source = source.replace("\t", "").replace("\r", "").replace("\n", "")
            if source.lower().startswith("http://"):
                self.http_resources.append(source)
        if tag == "form":
            if self.current_form is not None:
                self.form_markup_uncertain = True
            self.forms.append({"id": attrs.get("id"), "action": attrs.get("action"),
                               "method": attrs.get("method", "get")})
            self.current_form = len(self.forms) - 1
        if tag == "input" and (attrs.get("type") or "text").lower() == "password":
            self.password_inputs.append({"form": attrs.get("form"), "explicit_form": "form" in attrs,
                                         "owner": self.current_form, "named": bool(attrs.get("name")),
                                         "disabled": "disabled" in attrs})
        submit = (tag == "button" and (attrs.get("type") or "submit").lower() not in {"button", "reset"}) or (
            tag == "input" and (attrs.get("type") or "text").lower() in {"submit", "image"})
        if submit and "disabled" not in attrs:
            self.submit_controls.append({"form": attrs.get("form"), "explicit_form": "form" in attrs,
                                         "owner": self.current_form,
                                         "action": attrs.get("formaction") if "formaction" in attrs else None,
                                         "has_action": "formaction" in attrs,
                                         "method": attrs.get("formmethod") if "formmethod" in attrs else None})

    def handle_endtag(self, tag):
        for index in range(len(self._profile_stack) - 1, -1, -1):
            if self._profile_stack[index][0] == tag:
                del self._profile_stack[index:]
                break
        if tag == "template" and self.template_depth:
            self.template_depth -= 1
            return
        if self.template_depth:
            return
        if tag == "title":
            self.in_title = False
        if tag == "head":
            self.head_closed = True
        if tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if (data.strip() and not self.in_title
                and not any(parent[0] in {"style", "script", "template", "noscript"} for parent in self._profile_stack)):
            self.head_closed = True
        if self.in_title and not self.template_depth:
            self.title = (self.title + data)[:1000]
        if self.in_title or (self._profile_stack and self._profile_stack[-1][1]):
            return
        # Text resembling an exposed credential is not needed for classification.
        if re.search(r"\b(?:password|passwd|secret|token|api[_ -]?key)\s*[:=]\s*\S+|\bauthorization\s*:\s*bearer\b", data, re.I):
            return
        text = " ".join(data.split())
        if text:
            if len(self.profile_text) < 6000:
                self.profile_text = (self.profile_text + " " + text)[:6000]
            if self._profile_stack and self._profile_stack[-1][2]:
                self.profile_headings = (self.profile_headings + " " + text)[:1600]


def finding(identifier, category, status, title, evidence, explanation, recommendation=""):
    return {"id": identifier, "category": category, "status": status, "title": title,
            "evidence": evidence, "explanation": explanation, "recommendation": recommendation}


def read_page(response):
    """Parse only the already downloaded, supported HTML response."""
    page = Page()
    if response is None:
        return page, False, False
    content_type = response.headers.get("content-type", "").lower()
    available = (content_type.split(";", 1)[0].strip() == "text/html"
                 and response.headers.get("content-encoding", "identity").lower() in {"", "identity"})
    if available:
        encoding_match = re.search(r"charset\s*=\s*[\"']?([\w-]+)", content_type)
        try:
            page.feed(response.body.decode(encoding_match.group(1) if encoding_match else "utf-8", errors="replace"))
            page.close()
        except (LookupError, ValueError):
            available = False
    complete = available and not response.truncated and 200 <= response.status < 300
    return page, available, complete


def _origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Unsupported URL")
    if parsed.username is not None or parsed.password is not None or "\\" in url:
        raise ValueError("Ambiguous URL")
    if any(ord(char) < 32 for char in url):
        raise ValueError("Control character in URL")
    hostname = unicodedata.normalize("NFC", parsed.hostname.lower())
    if not hostname.isascii():
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
            # Python's codec uses IDNA 2003. Deviation mappings such as ß → ss
            # differ from modern browser URLs, so leave those cases unknown.
            if ascii_hostname.encode("ascii").decode("idna") != hostname:
                raise ValueError("Unsupported international hostname mapping")
            hostname = ascii_hostname
        except UnicodeError as exc:
            raise ValueError("Unsupported international hostname") from exc
    port = parsed.port
    return parsed.scheme, hostname, port if port is not None else (443 if parsed.scheme == "https" else 80)


def password_form_check(response, page, complete):
    evidence = {"forms_with_password": 0, "password_inputs": len(page.password_inputs),
                "http_actions": 0, "get_submissions": 0, "cross_origin_actions": 0,
                "unsupported_actions": 0, "unassociated_password_inputs": 0,
                "complete_html": complete, "destinations": []}
    explanation = ("Observes named, enabled password fields and static form destinations, including submit-button overrides. "
                   "No form is submitted, and JavaScript behavior and authentication are not tested. "
                   "This additional signal does not change the configuration score.")
    if response is None:
        return finding("password_forms", "Browser", "unknown", "Password form destinations", evidence,
                       "No page was available to inspect. " + explanation)
    form_ids = {}
    for index, form in enumerate(page.forms):
        if form["id"]:
            if form["id"] in form_ids or form["id"] in page.duplicate_ids:
                page.form_markup_uncertain = True
            else:
                form_ids[form["id"]] = index

    def owner(control):
        return form_ids.get(control["form"]) if control["explicit_form"] else control["owner"]

    password_forms = set()
    for control in page.password_inputs:
        if control["disabled"]:
            continue
        index = owner(control)
        if index is None or not control["named"]:
            evidence["unassociated_password_inputs"] += 1
        else:
            password_forms.add(index)
    evidence["forms_with_password"] = len(password_forms)
    try:
        document_origin = _origin(response.url)
    except (ValueError, TypeError):
        document_origin = None
    submit_by_owner = {}
    for control in page.submit_controls:
        submit_by_owner.setdefault(owner(control), []).append(control)
    for index in sorted(password_forms):
        form = page.forms[index]
        candidates = [(form["action"], form["method"])]
        candidates.extend((control["action"] if control["has_action"] else form["action"],
                           control["method"] if control["method"] is not None else form["method"])
                          for control in submit_by_owner.get(index, []))
        seen = set()
        for action, method in candidates:
            method = (method or "get").lower()
            method = method if method in {"get", "post", "dialog"} else "get"
            if method == "dialog":
                continue
            try:
                # Only an absent or exactly empty action uses the document URL.
                # A whitespace-only value is parsed against the document base.
                if action is None or action == "":
                    destination = response.url
                else:
                    base = urljoin(response.url, page.base_href.strip()) if page.base_href is not None else response.url
                    destination = urljoin(base, action.strip())
                target_origin = _origin(destination)
                if document_origin is None:
                    raise ValueError("Unknown document origin")
            except (ValueError, TypeError):
                evidence["unsupported_actions"] += 1
                continue
            key = (target_origin, method)
            if key in seen:
                continue
            seen.add(key)
            same_origin = target_origin == document_origin
            evidence["http_actions"] += int(target_origin[0] == "http")
            evidence["get_submissions"] += int(method == "get")
            evidence["cross_origin_actions"] += int(not same_origin)
            if len(evidence["destinations"]) < 10:
                evidence["destinations"].append({"scheme": target_origin[0], "hostname": target_origin[1],
                                                 "port": target_origin[2], "method": method.upper(), "same_origin": same_origin})
    observed_risk = evidence["http_actions"] or evidence["get_submissions"] or evidence["cross_origin_actions"]
    uncertain = (not complete or page.form_markup_uncertain or evidence["unsupported_actions"]
                 or evidence["unassociated_password_inputs"])
    if not complete or page.form_markup_uncertain:
        status, recommendation = "unknown", ""
        explanation = "Static password submission could not be fully assessed. " + explanation
    elif observed_risk:
        status = "attention"
        description = []
        if evidence["http_actions"]:
            description.append("An HTTP password-form action was observed; browser upgrades or blocking were not tested.")
        if evidence["get_submissions"]:
            description.append("A password form permits GET submission, which can place named fields in a URL.")
        if evidence["cross_origin_actions"]:
            description.append("A password-form destination differs from the page origin; this may be intentional.")
        explanation = " ".join(description) + " " + explanation
        recommendation = "Review the form's intended destination and use HTTPS POST for credential submission."
    elif uncertain:
        status, recommendation = "unknown", ""
        explanation = "Static password submission could not be fully assessed. " + explanation
    elif not password_forms:
        status, recommendation = "info", ""
        explanation = "No named, enabled password form was observed in the static HTML. " + explanation
    elif not evidence["destinations"]:
        status, recommendation = "info", ""
        explanation = "The observed password forms use dialog submission, which does not send form data. " + explanation
    else:
        status, recommendation = "pass", ""
        explanation = "Observed password-form destinations use HTTPS POST on the same origin. " + explanation
    return finding("password_forms", "Browser", status, "Password form destinations", evidence, explanation, recommendation)


def cookie_flag_check(response):
    evidence = {"cookies_observed": 0, "cookies": [], "missing_secure": 0, "missing_http_only": 0,
                "missing_same_site": 0, "same_site_none_without_secure": 0, "malformed_count": 0, "limited": False}
    explanation = ("Only Set-Cookie fields on this response are inspected; values are never included. "
                   "Cookie purpose and logged-in sessions are unknown. HttpOnly may be intentionally absent on cookies used by scripts; "
                   "browser SameSite defaults vary. This additional signal does not change the configuration score.")
    if response is None:
        return finding("cookie_flags", "Browser", "unknown", "Cookie attributes", evidence,
                       "No response headers were available. " + explanation)
    fields = getattr(response, "set_cookie_headers", None)
    if fields is None:
        # Support older fixtures only. Never split a combined Set-Cookie value.
        raw = response.headers.get("set-cookie")
        fields = [raw] if isinstance(raw, str) else []
    evidence["cookies_observed"] = len(fields)
    evidence["limited"] = len(fields) > 50
    token = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    for raw in fields[:50]:
        if not isinstance(raw, str) or len(raw) > 8192 or re.search(r",\s*" + token + r"=", raw):
            evidence["malformed_count"] += 1
            continue
        parts = raw.split(";")
        name, separator, _ = parts[0].partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(token, name) or len(name) > 128:
            evidence["malformed_count"] += 1
            continue
        attributes = {}
        for part in parts[1:]:
            key, _, value = part.strip().partition("=")
            attributes[key.lower()] = value.strip()
        secure, http_only = "secure" in attributes, "httponly" in attributes
        same_site = attributes.get("samesite", "").lower()
        same_site = same_site.capitalize() if same_site in {"strict", "lax", "none"} else None
        evidence["missing_secure"] += int(not secure)
        evidence["missing_http_only"] += int(not http_only)
        evidence["missing_same_site"] += int(same_site is None)
        evidence["same_site_none_without_secure"] += int(same_site == "None" and not secure)
        evidence["cookies"].append({"name": name, "secure": secure, "http_only": http_only, "same_site": same_site})
    recommendation = ""
    if evidence["missing_secure"]:
        status = "attention"
        explanation = "At least one returned cookie lacks an explicit Secure attribute. " + explanation
        recommendation = "Review each cookie's purpose; use Secure on HTTPS cookies and suitable HttpOnly and SameSite attributes for session cookies."
    elif evidence["malformed_count"] or evidence["limited"]:
        status = "unknown"
        explanation = "Some Set-Cookie fields could not be fully assessed. " + explanation
    elif not fields:
        status = "info"
        explanation = "No Set-Cookie fields were observed on this response; later pages may set cookies. " + explanation
    elif evidence["missing_http_only"] or evidence["missing_same_site"]:
        status = "info"
        explanation = "Secure attributes were observed; other attributes require review against cookie purpose. " + explanation
    else:
        status = "pass"
        explanation = "All observed cookies declare Secure, HttpOnly and a recognized SameSite attribute. " + explanation
    return finding("cookie_flags", "Browser", status, "Cookie attributes", evidence, explanation, recommendation)


def _certificate_datetime(value):
    # time.strptime/ssl.cert_time_to_seconds can normalize impossible dates
    # such as February 31. datetime validates the actual calendar date.
    if not isinstance(value, str) or len(value) > 120:
        raise ValueError("Unsupported certificate expiry date")
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def certificate_expiry_presentation(item):
    """Describe the recorded snapshot; never recalculate a saved countdown."""
    evidence = item.get("evidence") if isinstance(item, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    status = item.get("status") if isinstance(item, dict) else "unknown"
    days = evidence.get("days_remaining")
    known = status in {"pass", "attention"} and type(days) is int and -365000 <= days <= 365000
    expires = evidence.get("expires")
    date, time = "Not recorded", "Expiry date (UTC)"
    if isinstance(expires, str) and len(expires) <= 120:
        try:
            expiry = _certificate_datetime(expires)
            date, time = expiry.strftime("%d %b %Y"), expiry.strftime("Expires at %H:%M UTC")
        except (ValueError, TypeError, OverflowError, OSError):
            pass
    recommendation = ""
    if not known:
        value, label = "Unknown", "Time remaining when checked"
        explanation = "The certificate's remaining lifetime could not be established for this check."
    else:
        value, label = str(days), "Days remaining when checked"
        if days < 0:
            value, label = "Expired", "At the time of this check"
            explanation = "The recorded certificate expiry date had already passed when this check ran."
            recommendation = "Check the certificate currently served by the website and renew it if needed."
        elif days == 0:
            value, label = "<1 day", "Remaining when checked"
            explanation = "Less than 24 hours remained when checked. Confirm that automatic renewal is working."
            recommendation = "Confirm certificate renewal before the recorded expiry time."
        elif days < 14:
            label = "Day remaining when checked" if days == 1 else label
            explanation = f"{days} full {'day remained' if days == 1 else 'days remained'} when checked. This is inside the renewal reminder window (fewer than 14 days)."
            recommendation = "Confirm automatic renewal is working before the certificate expires."
        else:
            explanation = f"{days} full days remained when checked. This is outside the renewal reminder window (fewer than 14 days)."
        if (status == "pass") != (days >= 14):
            explanation = "The recorded countdown and saved result disagree. Run a new check to confirm the certificate's expiry."
            recommendation = "Run a new check; this saved result has not been changed."
    return {"explanation": explanation, "recommendation": recommendation,
            "metrics": [{"value": value, "label": label}, {"value": date, "label": time}]}


def transport_checks(http, https):
    checks = []
    upgraded = any(x["url"].startswith("https://") for x in http.chain[1:])
    status = "pass" if upgraded else ("unknown" if http.error else "attention")
    if http.error_kind == "downgrade":
        status = "attention"
    checks.append(finding("https_redirect", "Transport", status, "HTTP upgrades to HTTPS",
                          {"chain": http.chain, "error": http.error},
                          "Records whether the HTTP entry point redirects to HTTPS. A later request error is shown separately.",
                          "Serve an HTTP redirect to HTTPS; avoid subsequent downgrades." if status == "attention" else ""))
    response = https.response
    if response and response.tls:
        tls = response.tls
        checks.append(finding("tls", "Transport", "pass", "TLS certificate verification", tls,
                              "The final HTTPS host passed certificate and hostname verification using this machine's trust store. "
                              "The negotiated protocol is one connection, not a survey of supported TLS versions."))
        try:
            days = (_certificate_datetime(tls["not_after"]) - datetime.now(timezone.utc)).days
        except (ValueError, TypeError, KeyError):
            days = None
        expiry = finding("certificate_expiry", "Transport", "unknown" if days is None else ("attention" if days < 14 else "pass"),
                         "Certificate renewal window", {"days_remaining": days, "expires": tls.get("not_after")}, "")
        presentation = certificate_expiry_presentation(expiry)
        expiry.update(explanation=presentation["explanation"], recommendation=presentation["recommendation"])
        checks.append(expiry)
    else:
        checks.append(finding("tls", "Transport", "attention" if https.error_kind in {"tls_verification", "downgrade"} else "unknown",
                              "TLS certificate verification", {"error": https.error, "chain": https.chain},
                              "An unavailable check does not establish a site vulnerability. Certificate verification errors can also reflect local trust-store problems."))
    return checks


def _positive_hsts(header):
    """Recognize a syntactically valid positive HSTS policy (RFC 6797 §6.1).

    Do not convert an untrusted max-age into an arbitrarily large integer.
    This is a header observation, not a browser/preload-policy evaluation.
    """
    token = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    quoted = r'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t -~])*"'
    directive = re.compile(r"(" + token + r")[ \t]*(?:=[ \t]*(" + token + r"|" + quoted + r"))?[ \t]*(?=;|$)")
    position, seen, positive = 0, set(), False
    while position < len(header):
        if header[position] in " \t;":
            position += 1
            continue
        match = directive.match(header, position)
        if match is None:
            return False
        name, value = match.groups()
        name = name.lower()
        if name in seen:
            return False
        seen.add(name)
        if name == "max-age":
            if value and value.startswith('"'):
                value = re.sub(r"\\(.)", r"\1", value[1:-1])
            if not value or not re.fullmatch(r"[0-9]+", value):
                return False
            positive = any(digit != "0" for digit in value)
        elif name == "includesubdomains" and value is not None:
            return False
        position = match.end()
    return positive


REFERRER_POLICIES = frozenset({"no-referrer", "no-referrer-when-downgrade", "origin",
                              "origin-when-cross-origin", "same-origin", "strict-origin",
                              "strict-origin-when-cross-origin", "unsafe-url"})


def referrer_check(response, page, complete):
    """Review an explicit declaration, never simulate all browser overrides.

    Header lists use the last recognized token. Header observations are
    preferred for this report; supported active HTML metadata is a fallback.
    This preference is not a claim that headers override meta in browsers.
    """
    raw_header = response.headers.get("referrer-policy")
    header = raw_header if isinstance(raw_header, str) else ""
    bounded_header = len(header) <= 8192
    header_policy = None
    if bounded_header:
        for token in header.split(","):
            token = token.strip(" \t").lower()
            if token in REFERRER_POLICIES:
                header_policy = token
    meta = getattr(page, "referrer_policies", [])
    limited = getattr(page, "referrer_meta_limited", False)
    # HTML metadata takes one policy value, not a header-style comma list.
    # Whitespace, obsolete names and unsupported values remain observations.
    supported_meta = [value.lower() for value in meta if value.isascii() and value.lower() in REFERRER_POLICIES]
    policy, source = header_policy, "header" if header_policy else None
    if policy is None and complete and not limited and supported_meta:
        policy, source = supported_meta[-1], "meta"
    evidence = {"header": header[:8192], "header_policy": header_policy,
                "meta_policies": meta, "policy": policy, "source": source,
                "complete_html": complete, "limited": limited or not bounded_header}
    scope = ("This reviews an observed declaration, not the effective policy for every request. "
             "HTML metadata, element attributes, scripts and browser settings may change behavior; actual referrer traffic was not tested. "
             "This additional review does not change the configuration percentage.")
    if policy == "unsafe-url":
        explanation = ("An explicit unsafe-url policy was observed in the "
                       + ("Referrer-Policy header" if source == "header" else "HTML metadata")
                       + ". When applied, this policy can send the page's path and query string to other origins, including HTTP destinations. " + scope)
        recommendation = ("For the site owner: review whether full URLs need to be shared. Consider strict-origin-when-cross-origin "
                          "or a stricter policy if suitable, align any HTML and element overrides, and test the affected navigation and requests.")
        return finding("referrer", "Browser", "attention", "Referrer policy", evidence, explanation, recommendation)
    if policy:
        explanation = "The selected " + source + " declaration is " + policy + ". " + scope
        return finding("referrer", "Browser", "info", "Referrer policy", evidence, explanation)
    if not bounded_header or limited or (not complete and meta):
        return finding("referrer", "Browser", "unknown", "Referrer policy", evidence,
                       "The available declaration evidence was incomplete or exceeded the review limit. " + scope)
    return finding("referrer", "Browser", "info", "Referrer policy", evidence,
                   "No supported explicit policy was selected from the available response. Modern browsers normally default to strict-origin-when-cross-origin; "
                   "an absent or unsupported declaration is not automatically a privacy defect. " + scope)


def page_checks(response):
    keys = ["hsts", "csp", "framing", "nosniff", "referrer", "title", "viewport", "language", "image_alt", "http_resources"]
    if response is None:
        checks = [finding(key, "Browser" if index < 5 else "Quality", "unknown", key.replace("_", " ").title(),
                          "No final HTTPS response", "This check needs a reachable HTTPS page.") for index, key in enumerate(keys)]
        return checks + [password_form_check(None, Page(), False), cookie_flag_check(None)] + hygiene_checks(None, Page())
    headers = response.headers
    page, html_available, complete = read_page(response)
    checks = []
    hsts = headers.get("strict-transport-security", "")
    hsts_valid = urlsplit(response.url).scheme == "https" and _positive_hsts(hsts)
    checks.append(finding("hsts", "Browser", "pass" if hsts_valid else "attention",
                          "HTTPS-only browser policy", hsts or "No HSTS header returned",
                          "Checks for a valid HSTS header with one positive max-age on the HTTPS response. Preload lists, cached policies and parent-domain policies are not checked.",
                          "Review HSTS deployment and subdomain readiness before setting a policy."))
    csp = headers.get("content-security-policy", "")
    meta_csp = ", ".join(page.meta_csp)
    if csp or meta_csp:
        csp_status, csp_evidence = "info", {"header": csp, "meta": meta_csp}
    elif complete:
        csp_status, csp_evidence = "attention", "No enforcing CSP header or HTML meta policy observed"
    else:
        csp_status, csp_evidence = "unknown", "No enforcing CSP header; HTML meta policy could not be fully assessed"
    checks.append(finding("csp", "Browser", csp_status, "Content Security Policy", csp_evidence,
                          "Policy presence is recorded. Directive strength, browser behavior, and exploitability are not evaluated. Report-only policies do not enforce restrictions.",
                          "Develop a resource policy for this application and evaluate it in report-only mode before enforcement."))
    xframe = headers.get("x-frame-options", "")
    ancestor = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, flags=re.I)
    frame_seen = bool(ancestor) or xframe.strip().upper() in {"DENY", "SAMEORIGIN"}
    checks.append(finding("framing", "Browser", "info" if frame_seen else "attention", "Framing policy",
                          {"x_frame_options": xframe, "frame_ancestors": ancestor.group(1) if ancestor else None},
                          "Records an observed framing directive. Its effective restrictions are not validated. Some sites intentionally allow embedding.",
                          "If embedding is unnecessary, restrict it using CSP frame-ancestors."))
    nosniff = headers.get("x-content-type-options", "")
    checks.append(finding("nosniff", "Browser", "pass" if nosniff.strip().lower() == "nosniff" else "attention",
                          "MIME sniffing protection", nosniff or "Header absent", "Looks for X-Content-Type-Options: nosniff.",
                          "Return accurate Content-Type values and the nosniff header."))
    checks.append(referrer_check(response, page, complete))
    quality = [
        ("title", "Page title", bool(page.title.strip()), page.title.strip()[:250], "A title helps identify the page; its accuracy is not assessed."),
        ("viewport", "Mobile viewport declaration", bool(page.meta.get("viewport")), page.meta.get("viewport", ""), "A declaration is observed, but responsive layout is not tested."),
        ("language", "Document language declaration", bool(page.lang.strip()), page.lang, "A lang attribute is observed; the language value and page content are not compared."),
        ("image_alt", "Image alternative text attributes", page.images_without_alt == 0,
         {"images": page.images, "missing_alt_attributes": page.images_without_alt},
         "Checks attribute presence only. Empty alt can be correct for decorative images. This is not an accessibility audit."),
        ("http_resources", "Explicit HTTP resource references", len(page.http_resources) == 0,
         {"count": len(page.http_resources), "examples": page.http_resources[:5]},
         "Checks a subset of resource attributes in static HTML. Browser upgrades or blocking may apply. CSS, srcset and JavaScript-created requests are not inspected."),
    ]
    for key, title, observed_ok, evidence, explanation in quality:
        status = "pass" if observed_ok else "attention"
        if not complete:
            status = "unknown"
        checks.append(finding(key, "Quality", status, title, evidence if html_available else "HTML unavailable",
                              explanation + (" The response was unsuccessful, incomplete, compressed or not HTML." if not complete else "")))
    return checks + [password_form_check(response, page, complete), cookie_flag_check(response)] + hygiene_checks(response, page, html_available, complete)
