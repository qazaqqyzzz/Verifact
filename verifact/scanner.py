from collections import Counter
from datetime import datetime, timezone
import json
from urllib.parse import urlsplit

from . import __version__
from .assessment import enrich
from .checks import finding, page_checks, transport_checks
from .network import Client, Fetch, ScanError, normalize_domain
from .links import analyze_link, normalize_expected_domain, normalize_target
from .profile import site_profile
from .page_risks import assess_page_risks
from . import threat_feed
from .visitor_assessment import build_visitor_assessment


def rdap_lookup(client, domain):
    """Use the IANA bootstrap; query the supplied name, never guess a parent."""
    bootstrap = client.fetch("https://data.iana.org/rdap/dns.json")
    if not bootstrap.response or bootstrap.response.status != 200 or bootstrap.response.truncated:
        raise ScanError("IANA RDAP directory unavailable or incomplete.")
    try:
        services = json.loads(bootstrap.response.body)["services"]
        urls = next(urls for tlds, urls in services if domain.rsplit(".", 1)[-1] in tlds)
        base = next(url for url in urls if url.startswith("https://"))
    except (ValueError, KeyError, StopIteration, TypeError) as exc:
        raise ScanError("No supported HTTPS RDAP service found.") from exc
    fetched = client.fetch(base.rstrip("/") + "/domain/" + domain)
    if not fetched.response or fetched.response.status != 200 or fetched.response.truncated:
        raise ScanError("RDAP record unavailable. For a subdomain, specify its registered domain with --rdap-domain.")
    try:
        record = json.loads(fetched.response.body)
        return {"queried_domain": domain, "source": fetched.response.url,
                "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")} for e in record.get("events", [])],
                "nameservers": [n.get("ldhName") for n in record.get("nameservers", [])],
                "status": record.get("status", [])}
    except (ValueError, TypeError, AttributeError) as exc:
        raise ScanError("RDAP response was not a supported record.") from exc


def finish_report(domain, http, https, requests, rdap=None, demo=False, target_url=None, expected_domain=None, security_contact=None):
    findings = transport_checks(http, https) + page_checks(https.response)
    if target_url is not None:
        next(item for item in findings if item["id"] == "https_redirect")["explanation"] = (
            "Records whether the target hostname's separate HTTP homepage entry point redirects to HTTPS. "
            "The page and TLS observations apply to the supplied link's final response. A later request error is shown separately.")
    if https.response and urlsplit(https.response.url).scheme == "http":
        findings = [finding("tls", "Transport", "attention", "TLS certificate verification",
                           {"url": https.response.url, "encrypted": False},
                           "The selected link returned its final page over unencrypted HTTP. No TLS certificate protected that response.",
                           "Use a verified HTTPS address before sending private information.")
                    if item["id"] == "tls" else item for item in findings]
    responses = [fetch.response for fetch in (http, https) if fetch.response]
    # Preserve which hostname each address belongs to after redirects.
    dns = [{"hostname": urlsplit(response.url).hostname, "addresses": response.addresses} for response in responses]
    findings.insert(0, finding("dns", "Domain", "info" if dns else "unknown", "Public address observations", dns or "No completed response",
                               "A/AAAA addresses resolved for final response hosts. They may belong to a CDN; they do not establish owner identity or hosting location."))
    if rdap:
        findings.append(rdap)
    if security_contact is not None:
        findings.append(security_contact)
    summary = dict(Counter(item["status"] for item in findings))
    report = {"schema_version": 1, "tool_version": __version__, "domain": domain,
            "created_at": datetime.now(timezone.utc).isoformat(), "demo": demo,
            "scope": "Public configuration observations; the supplied link and its redirects, a separate HTTP homepage upgrade check, and optional RDAP lookup. No exploitation or crawling.",
            "requests": requests, "summary": summary, "findings": findings,
            "site_profile": site_profile(https.response, domain),
            "page_risks": assess_page_risks(https.response),
            "response": {"url": https.response.url, "status": https.response.status,
                         "body_truncated": https.response.truncated,
                         "body_error": getattr(https.response, "body_error", None)} if https.response else None,
            "limitations": ["A snapshot from one network and one client, not proof that a website is safe or unsafe.",
                            "JavaScript is not executed. Login flows, application logic and vulnerabilities are not tested.",
                            "Header and certificate observations apply to the returned response; redirects may change the hostname.",
                            "Network failures remain unknown. Domain age and missing privacy links do not determine legitimacy.",
                            "Full accepted URL paths and query strings are included in this report. Common private-token links are blocked, but not every sensitive URL can be recognized."]}
    if target_url is not None:
        report["target_url"] = target_url
        report["scan_mode"] = "exact_link"
        report["link_analysis"] = analyze_link(target_url, https, expected_domain)
    report["community_reputation"] = threat_feed.public_result(None)
    report = enrich(report)
    report["visitor_assessment"] = build_visitor_assessment(report)
    return report


def community_blocked_report(target, community, expected_domain=None, security_contact=False):
    """Keep the regular report shape without contacting a listed target."""
    target = normalize_target(target)
    domain = urlsplit(target).hostname
    unavailable = Fetch(None, [], "Page inspection was skipped because the submitted hostname matched the current community warning list.", "community_match")
    contact = None
    if security_contact:
        from .security_contact import inspect_security_contact
        contact = inspect_security_contact(None, None)
    report = finish_report(domain, unavailable, unavailable, 0, target_url=target,
                           expected_domain=expected_domain, security_contact=contact)
    report.update(community_reputation=threat_feed.public_result(community),
                  inspection_skipped=True, skip_reason="community_match")
    report["scope"] = "The submitted hostname was compared locally with the community warning list. The listed website, its redirects and its HTTP homepage were not contacted."
    report["visitor_assessment"] = build_visitor_assessment(report)
    return report


def add_community_result(report, enabled=True):
    """Match observed route hosts locally; this never revisits those sites."""
    analysis = report.get("link_analysis") or {}
    urls = [report.get("target_url") or "https://" + report["domain"] + "/"]
    urls.extend(item["url"] for item in analysis.get("redirects", []) if isinstance(item, dict) and isinstance(item.get("url"), str))
    if analysis.get("final_url"):
        urls.append(analysis["final_url"])
    report["community_reputation"] = threat_feed.inspect_urls(list(dict.fromkeys(urls)), enabled=enabled)
    report["visitor_assessment"] = build_visitor_assessment(report)
    return report


def scan(domain, include_rdap=False, rdap_domain=None, timeout=8, expected_domain=None, community_check=False, security_contact=False):
    target = normalize_target(domain)
    expected = normalize_expected_domain(expected_domain)
    domain = urlsplit(target).hostname
    registration = normalize_domain(rdap_domain) if rdap_domain else domain
    if registration != domain and not domain.endswith("." + registration):
        raise ScanError("The RDAP domain must equal the target or be its parent domain.", "blocked")
    if type(community_check) is not bool:
        raise ScanError("The community checking option must be true or false.", "blocked")
    if type(security_contact) is not bool:
        raise ScanError("The security contact option must be true or false.", "blocked")
    if community_check:
        community = threat_feed.inspect_urls([target])
        if community["status"] == "listed":
            return community_blocked_report(target, community, expected, security_contact)
    client = Client(timeout=timeout)
    # Assess the actual submitted destination. In particular an HTTP link is
    # never silently swapped for a different HTTPS page. The root upgrade
    # observation remains a separate, clearly labelled configuration check.
    https = client.fetch(target, url_validator=normalize_target)
    http = client.fetch("http://" + domain + "/", url_validator=normalize_target)
    rdap = None
    if include_rdap:
        try:
            evidence = rdap_lookup(client, registration)
            rdap = finding("rdap", "Domain", "info", "Registration record", evidence,
                           "Public registration metadata; redactions and registry differences are normal. Registration age is not a trust verdict.")
        except ScanError as exc:
            rdap = finding("rdap", "Domain", "unknown", "Registration record", str(exc), "No conclusions drawn from unavailable registration data.")
    contact = None
    if security_contact:
        from .security_contact import inspect_security_contact
        contact = inspect_security_contact(client, https.response)
    report = finish_report(domain, http, https, client.requests, rdap,
                           target_url=target, expected_domain=expected, security_contact=contact)
    return add_community_result(report) if community_check else report


def demo_report():
    """Synthetic, offline fixture; never presented as a live site assessment."""
    from .network import Fetch, Response
    body = b'''<!doctype html><html lang="en"><head><title>Demo Studio</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"></head>
    <body><h1>Demo Studio</h1><img src="/photo.jpg"><script src="http://assets.example.com/app.js"></script></body></html>'''
    response = Response("https://demo.example.com/", 200,
                        {"content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=31536000",
                         "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin"}, body,
                        addresses=["192.0.2.20 (synthetic documentation address)"],
                        tls={"hostname": "demo.example.com", "verified": True, "version": "TLSv1.3",
                             "not_after": "Dec 31 23:59:59 2099 GMT", "issuer": "Synthetic fixture CA"})
    http = Fetch(response, [{"url": "http://demo.example.com/", "status": 301}, {"url": response.url, "status": 200}])
    https = Fetch(response, [{"url": response.url, "status": 200}])
    return finish_report("demo.example.com", http, https, 0, demo=True,
                         target_url="https://demo.example.com/")
