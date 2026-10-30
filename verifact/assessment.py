"""A versioned configuration checklist, not a security probability model."""

from copy import deepcopy
from .checks import certificate_expiry_presentation

from .dashboard import build_dashboard


METHOD_VERSION = "configuration-v1"
# Fixed weights are a documented product heuristic, not an industry standard.
CHECKLIST = (
    ("tls", "TLS certificate verification", 25),
    ("https_redirect", "HTTP upgrades to HTTPS", 15),
    ("certificate_expiry", "Certificate renewal window", 5),
    ("hsts", "HTTPS-only browser policy", 15),
    ("nosniff", "MIME sniffing protection", 10),
    ("csp", "Content policy presence", 10),
    ("framing", "Framing policy presence", 10),
    ("http_resources", "No explicit HTTP resource references", 10),
)
DISCLAIMER = (
    "This is a weighted checklist of observed public security configuration, "
    "not a percentage probability that the website is secure. Even 100/100 "
    "does not establish that a site is safe or free of vulnerabilities."
)
METHODOLOGY = [
    "Version configuration-v1 uses fixed, heuristic weights totaling 100 points; "
    "they are not a standardized or independently validated security rating.",
    "A passed checklist check earns its weight. CSP and framing observations "
    "earn presence credit only; directive strength and effective restrictions are not validated.",
    "Unavailable or missing checks remain unassessed. Their weights produce a possible range, "
    "rather than being treated as failures or removed from the denominator.",
    "Coverage is the percentage of checklist weight that was assessed. "
    "The upper end of a partial range assumes every unassessed check would earn its weight.",
    "Domain registration age, DNS addresses, page title, mobile viewport, language and "
    "image descriptions do not change this security configuration score.",
    "No authentication, application logic, exploitation, malicious content or complete "
    "TLS/cipher audit is performed. AI cannot change the measured findings or scoring rules.",
]


def _presence_seen(identifier, evidence):
    if not isinstance(evidence, dict):
        return False
    if identifier == "csp":
        return any(isinstance(evidence.get(key), str) and evidence[key].strip()
                   for key in ("header", "meta"))
    if identifier == "framing":
        frame = evidence.get("x_frame_options")
        ancestors = evidence.get("frame_ancestors")
        return ((isinstance(frame, str) and frame.strip().upper() in {"DENY", "SAMEORIGIN"})
                or (isinstance(ancestors, str) and bool(ancestors.strip())))
    return False


def assess(report):
    """Calculate from findings each time; never trust a stored or AI-authored score."""
    findings = {}
    duplicates = set()
    for item in report.get("findings", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        identifier = item["id"]
        if identifier in findings:
            duplicates.add(identifier)
        findings[identifier] = item
    rows = []
    for identifier, title, weight in CHECKLIST:
        finding = findings.get(identifier, {})
        status = finding.get("status", "unknown")
        passed = status == "pass"
        assessed = status in {"pass", "attention"}
        note = "Passed the named check." if passed else "Review the observed configuration."
        if status == "info":
            passed = _presence_seen(identifier, finding.get("evidence"))
            assessed = passed
        if identifier in duplicates:
            assessed = passed = False
        if assessed and identifier in {"csp", "framing"} and passed:
            note = "Presence credit only; policy strength and effective restrictions are not validated."
        if not assessed:
            status = "unknown"
            note = "Unassessed; this weight remains in the possible range, not a recorded failure."
        rows.append({"finding_id": identifier, "title": title, "weight": weight,
                     "earned": weight if passed and assessed else 0,
                     "assessed": assessed, "status": status, "note": note})
    earned = sum(row["earned"] for row in rows)
    coverage = sum(row["weight"] for row in rows if row["assessed"])
    unknown_weight = 100 - coverage
    return {"label": "Security configuration score", "method_version": METHOD_VERSION,
            "value": earned if coverage else None, "potential": earned + unknown_weight,
            "earned": earned, "possible": 100, "coverage": coverage,
            "assessed_checks": sum(row["assessed"] for row in rows), "total_checks": len(rows),
            "unknown_weight": unknown_weight, "items": rows,
            "disclaimer": DISCLAIMER, "methodology": list(METHODOLOGY)}


def built_in_guidance(report):
    """Select existing authored explanations; no model, network, or new claims."""
    priority = {"attention": 0, "unknown": 1, "pass": 2, "info": 3}
    findings = [item for item in report.get("findings", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
                and isinstance(item.get("explanation"), str)]
    findings.sort(key=lambda item: priority.get(item.get("status"), 4))
    items, seen = [], set()
    for item in findings:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        recommendation = item.get("recommendation", "") if item.get("status") == "attention" else ""
        items.append({"finding_id": item["id"], "explanation": item["explanation"],
                      "next_step": recommendation if isinstance(recommendation, str) else ""})
        if len(items) == 4:
            break
    return {"kind": "rules", "label": "Built-in explanation", "items": items}


def enrich(report):
    enriched = deepcopy(report)
    for item in enriched.get("findings", []):
        if isinstance(item, dict) and item.get("id") == "certificate_expiry":
            presentation = certificate_expiry_presentation(item)
            item.update(explanation=presentation["explanation"], recommendation=presentation["recommendation"],
                        presentation={"metrics": presentation["metrics"]})
    enriched["assessment"] = assess(enriched)
    enriched["guidance"] = built_in_guidance(enriched)
    enriched["dashboard"] = build_dashboard(enriched, enriched["assessment"])
    return enriched
