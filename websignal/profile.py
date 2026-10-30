"""A cautious, readable site overview from observed signals, without AI or requests."""

import re
import unicodedata
from urllib.parse import urlsplit

from .checks import read_page


PROFILE_VERSION = "site-profile-v4"
_LOGIN = r"\b(?:log[ -]?in|sign[ -]?in|вход|войти|кіру)\b"
_REGISTER = r"\b(?:register|registration|sign[ -]?up|create (?:an? )?account|регистрация|зарегистрироваться|тіркелу)\b"
_RESET = r"\b(?:(?:reset|forgot(?:ten)?|change) (?:your )?password|account recovery|recover (?:your )?account|восстановление пароля|смена пароля|құпия сөзді қалпына келтіру|парольді қалпына келтіру)\b"
_UNIVERSITY = r"\b(?:university|universities|университет\w*)\b"
_LEARNING = r"\b(?:moodle|learning management(?: system)?|learning platform|online learning|course portal|virtual learning)\b"
_EDUCATION = r"\b(?:student portal|course catalog|education|educational|online learning|students?|курсы|студент\w*|образовательн\w*|образовани\w*|білім беру|оқушылар\w*)\b"
_EDUCATION_PLATFORM = r"\b(?:education(?:al)? platform|образовательн\w* платформ\w*|білім беру платформ\w*)\b"


def _declared_purpose(declared):
    """Specific metadata takes precedence over an embedded sign-in form."""
    if re.search(_EDUCATION_PLATFORM, declared):
        return ("Education platform", "This appears to be an education platform, based on the page's own description. It may support learning or school services; those services and the provider's identity were not independently verified.")
    security = re.search(r"\b(?:hackers?|hacking|cybersecurity|cyber security|security)\b", declared)
    training = re.search(r"\b(?:training|exercises?|challenges?|ctfs?)\b", declared)
    if security and training:
        return ("Security training website", "The page describes a security training website with exercises or challenges. The training content, access rules and provider's identity were not independently verified.")
    candidates = (
        ("Documentation website", r"\b(documentation|api reference|developer docs|technical reference)\b",
         "This appears to be a documentation or technical-reference website, intended to help readers understand a product or API."),
        ("Software & developer website", r"\bprogramming language\b",
         "This appears to be a website for a programming language and its developer resources, based on the page's title or description. Downloads, software integrity and the provider's identity were not verified."),
        ("Software & developer website", r"\b(software development (?:platform|tools?)|developer (?:platform|tools?)|code hosting|source code collaboration)\b",
         "This appears to be a software or developer website, based on its title or description. It introduces a programming language, development tools or a software platform; downloads, software integrity and the provider's identity were not verified."),
        ("Shopping website", r"\b(online shop|shopping cart|add to cart|online store)\b",
         "This appears to be an online shopping website. Products, payment processing and merchant identity were not verified."),
        ("News website", r"\b(newsroom|breaking news|daily news|latest news)\b",
         "This appears to be a news or publishing website. The accuracy of its articles and publisher identity were not verified."),
    )
    return next(((label, summary) for label, pattern, summary in candidates if re.search(pattern, declared)), None)


def _text(value, limit):
    if not isinstance(value, str):
        return ""
    value = "".join(char for char in value if not unicodedata.category(char).startswith("C") or char in "\n\t")
    return " ".join(value.split())[:limit]


def _academic_suffix(hostname):
    """A suffix cue, never proof that an institution owns this hostname."""
    labels = hostname.lower().rstrip(".").split(".")
    if len(labels) >= 2 and labels[-1] == "edu":
        return ".edu"
    if len(labels) >= 3 and labels[-2] in {"edu", "ac"} and re.fullmatch(r"[a-z]{2}", labels[-1]):
        return "." + ".".join(labels[-2:])
    return ""


def _connection(response, domain):
    try:
        parsed = urlsplit(response.url if response else "")
        hostname = parsed.hostname or domain
        https = parsed.scheme == "https"
    except (ValueError, TypeError):
        hostname, https = domain, False
    return {"hostname": _text(hostname, 253), "https": https,
            "http_status": response.status if response and type(response.status) is int else None}


def _describe(title, description, hostname, *, headings="", page_text="", generator="", password=False,
              complete=True, legacy=False):
    primary = " ".join((title, headings)).lower()
    metadata = " ".join((title, description)).lower()
    declared = " ".join((primary, description)).lower()
    content = " ".join((declared, page_text)).lower()
    academic = _academic_suffix(hostname)
    labels = hostname.lower().rstrip(".").split(".")
    lms_host = any(label in {"lms", "moodle", "elearning", "e-learning"} for label in labels[:-1])
    platform = bool(re.search(_LEARNING, " ".join((declared, page_text, generator)).lower()))
    university_word = bool(re.search(_UNIVERSITY, content))
    school = bool(re.search(r"\b(?:primary school|secondary school|high school|k[ -]?12|школ[а-я]*|мектеп\w*)\b", declared))
    # A generic "students" link in a marketing footer is not a site-purpose cue.
    education = school or bool(re.search(_EDUCATION, declared))
    # Every h2/h3 is collected, including news feeds, sidebar login prompts and
    # footer navigation. Those are not reliable statements of page purpose.
    # Use the page title first, then its description, for categorical purposes.
    declared_purpose = _declared_purpose(title.lower()) or _declared_purpose(metadata)
    account_title = any(re.search(pattern, title.lower()) for pattern in (_LOGIN, _REGISTER, _RESET))
    # A sign-in link/heading without an observed account form is navigation,
    # unless the document title itself describes a login page.
    login = bool(re.search(_LOGIN, title.lower()) or (password and re.search(_LOGIN, primary)))
    register = bool(re.search(_REGISTER, primary))
    reset = bool(re.search(_RESET, primary))
    # Body navigation may contain links to registration/reset on a login page;
    # only title/headings decide whether the page itself has those purposes.
    if not login and not (register or reset):
        login = password and bool(re.search(_LOGIN, page_text.lower()))
    university = bool((university_word or (academic and (lms_host or platform))) and not school)
    learning = platform or lms_host
    signals = []
    if password:
        signals.append("A password field was observed in the returned HTML." if not legacy else "A password field was recorded in this saved report.")
    if login:
        signals.append("The page title, heading or form text includes sign-in wording.")
    if register:
        signals.append("The page title or heading includes registration wording.")
    if reset:
        signals.append("The page title or heading includes password-recovery wording.")
    if academic:
        signals.append("The hostname uses the academic-style " + academic + " suffix.")
    if lms_host:
        signals.append("An LMS-related label appears in the hostname.")
    if platform:
        signals.append("Learning-platform wording appears in the page's declared metadata or visible content.")
    if university_word:
        signals.append("University-related wording appears in the page's content.")
    if education and not university_word:
        signals.append("Education-related wording appears in the page's content.")

    kind = "Website"
    summary = "This is a public webpage. The available page signals do not establish a more specific purpose."
    if not complete:
        summary = "The page's purpose could not be fully identified because the returned HTML was unavailable, incomplete or unsuccessful."
        if password:
            kind = "Account access page"
            summary += " A password field was observed, but its intended use remains uncertain."
    elif declared_purpose and not account_title:
        kind, summary = declared_purpose
        if password:
            summary += " The page also includes account access; no login was attempted."
        signals.append("The page's title or description identify " + kind.lower() + " content.")
    elif password and reset:
        kind = "Account access page"
        summary = "This appears to be an account password-recovery or password-change page. The process was not submitted or tested."
    elif password and register and not login:
        kind = "Account access page"
        summary = "This appears to be an account-registration page, where users can create account credentials. Registration was not submitted or tested."
    elif login and university and (password or learning):
        kind = "University login page"
        if learning:
            summary = "This appears to be a university login page for an online learning platform. Users are asked to sign in; the learning services behind the login were not inspected."
        else:
            summary = "This appears to be a university account login page. Users are asked to sign in; the services behind the login were not inspected."
    elif learning and university and (platform or university_word or education):
        kind = "University learning portal"
        summary = "This appears to be a university learning portal or learning-management system (LMS). It is associated with online learning; course content and access behind sign-in were not inspected."
    elif login and (password or declared):
        kind = "Education login page" if academic or university_word or education else "Login page"
        summary = ("This appears to be an education account login page. " if kind == "Education login page"
                   else "This appears to be an account login page. ")
        summary += ("It presents a password field; signing in and account access were not tested." if password
                    else "Its title or heading suggests sign-in, but a working login process was not established.")
    elif password:
        kind = "Account access page"
        summary = "This page presents a password field and appears to support account access. The available wording does not establish whether it is sign-in, registration or another account form."
    elif learning and (platform or education):
        kind = "Learning portal"
        summary = "This appears to be an online learning portal or learning-management system (LMS). Its course content and any restricted areas were not inspected."
    elif university_word or education:
        kind = "Education website"
        summary = "This appears to be an education website, based on the page's own wording. Its institutional identity and educational services have not been independently verified."

    basis = "Purpose is inferred from the recorded page signals, not independently verified. "
    if signals:
        basis += " ".join(signals[:3]) + " "
    basis += "The hostname and page wording do not verify the site's identity or legitimacy."
    if not complete:
        basis += " The returned HTML was unavailable, incomplete or unsuccessful."
    if legacy:
        basis += " This description uses only evidence retained in the saved report; no new request was made."
    return {"type": kind, "summary": summary, "basis": basis, "signals": signals[:6], "profile_version": PROFILE_VERSION}


def site_profile(response, domain=""):
    page, available, complete = read_page(response)
    title = _text(page.title, 250) if available else ""
    description = _text(page.description, 320) if available else ""
    connection = _connection(response, domain)
    description_fields = _describe(title, description, connection["hostname"],
                                   headings=page.profile_headings if available else "",
                                   page_text=page.profile_text if available else "",
                                   generator=page.profile_generator if available else "",
                                   password=bool(page.password_inputs) and available, complete=complete)
    return {"title": title, "description": description, **description_fields, **connection}


def _current_profile(existing):
    return {"title": _text(existing.get("title"), 250),
            "description": _text(existing.get("description"), 320),
            "type": _text(existing.get("type"), 80) or "Website",
            "summary": _text(existing.get("summary"), 600),
            "basis": _text(existing.get("basis"), 700),
            "signals": [_text(item, 200) for item in existing.get("signals", [])[:6] if isinstance(item, str)]
                       if isinstance(existing.get("signals"), list) else [],
            "profile_version": PROFILE_VERSION,
            "hostname": _text(existing.get("hostname"), 253),
            "https": existing.get("https") is True,
            "http_status": existing.get("http_status") if type(existing.get("http_status")) is int else None}


def profile_for_report(report):
    """Upgrade saved metadata from retained evidence; never fetch a page here."""
    existing = report.get("site_profile")
    if isinstance(existing, dict) and existing.get("profile_version") == PROFILE_VERSION and _text(existing.get("summary"), 600):
        return _current_profile(existing)
    existing = existing if isinstance(existing, dict) else {}
    title = _text(existing.get("title"), 250) or next((_text(item.get("evidence"), 250) for item in report.get("findings", [])
                  if isinstance(item, dict) and item.get("id") == "title" and item.get("status") == "pass"), "")
    description = _text(existing.get("description"), 320)
    response = report.get("response")
    response = response if isinstance(response, dict) else {}
    try:
        parsed = urlsplit(response.get("url", ""))
        hostname = parsed.hostname or existing.get("hostname") or report.get("domain", "")
        https = parsed.scheme == "https" if parsed.scheme else existing.get("https") is True
    except (ValueError, TypeError):
        hostname, https = report.get("domain", ""), False
    hostname = _text(hostname, 253)
    status = response.get("status", existing.get("http_status"))
    status = status if type(status) is int else None
    complete = bool(status is not None and 200 <= status < 300 and not response.get("body_truncated"))
    password = False
    for item in report.get("findings", []):
        if not isinstance(item, dict) or item.get("id") != "password_forms" or not isinstance(item.get("evidence"), dict):
            continue
        count = item["evidence"].get("password_inputs")
        password = type(count) is int and count > 0
        break
    if not password and existing.get("type") == "Account access page" and "password field" in str(existing.get("basis", "")).lower():
        password = True
    description_fields = _describe(title, description, hostname, password=password, complete=complete, legacy=True)
    if existing.get("profile_version") in {"site-profile-v2", "site-profile-v3"} and _text(existing.get("summary"), 600):
        # Earlier reports did not retain all heading/body cues. Preserve their
        # useful description unless the retained metadata supports this upgrade.
        metadata_kinds = {"Education platform", "Security training website", "Software & developer website",
                          "Documentation website", "Shopping website", "News website"}
        unsupported_navigation_kind = (existing.get("type") in {"News website", "Login page", "Documentation website", "Shopping website"}
                                       and description_fields["type"] != existing.get("type"))
        useful_upgrade = (unsupported_navigation_kind
                          or (description_fields["type"] in metadata_kinds and description_fields["type"] != existing.get("type"))
                          or (existing.get("type") == "Website" and description_fields["type"] != "Website"))
        if not useful_upgrade:
            return _current_profile(existing)
    return {"title": title, "description": description, **description_fields, "hostname": hostname,
            "https": https, "http_status": status}
