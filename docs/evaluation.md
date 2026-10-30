# Evaluation plan

## Verification record — 30 October 2026

The v0.3.1 audit followed the URL form through the local API, scanner, scoring, dashboard and JSON/HTML downloads. The starting symptom was Kundelik's 85–100 range: its HTTP entry-point request had timed out while the HTTPS checks succeeded. The range correctly represented missing evidence, but address fallback needed improvement.

### Defects reproduced and corrected

- A complete `Connection: close` response could be discarded with `Bad file descriptor` after its final body bytes were read.
- A premature body EOF could look complete. Body interruptions now retain received headers and verified certificate evidence while marking HTML incomplete.
- One unresponsive DNS address could consume the whole connection budget. Up to eight validated addresses now share that budget; public-address validation and TLS hostname verification remain in place.
- Some malformed HSTS values could pass, and extremely long numeric values could raise an exception. Duplicate field/directive behavior is covered by regressions.
- SVG titles polluted document titles; duplicate attributes and URL whitespace could hide static form/resource observations; unsupported CSP metadata could receive presence credit.
- Ambiguous Unicode domain conversion could silently select a different hostname. Those spellings are rejected; exact punycode remains supported.
- Russian/Kazakh education metadata was missed, and a sidebar sign-in form could override a page's stated training purpose.

The HTML reading limit increased from 512 KiB to a bounded 2 MiB. Exceeding it still produces unknown HTML-based results. The dashboard and exports now name each unavailable check and its cause instead of relying on the incomplete label alone.

### Observational smoke test

These are four named public-homepage snapshots from this computer, not a representative safety study. No login, form submission, attack payload or AI call was used. Optional registration lookup was enabled only for the Kundelik application test.

| Homepage | Scored checks assessed | Checklist result | Observed outcome |
| --- | --- | --- | --- |
| portal.kundelik.kz | 8/8 | 100/100 | Final application rescan confirmed the HTTP-to-HTTPS redirect after the address-fallback fix; education-platform description rendered. |
| github.com | 8/8 | 100/100 | The larger bounded body read completed; no HTML-limit gap remained. |
| www.hackthissite.org | 8/8 | 65/100 | HTTP returned 403 without an upgrade; this was recorded as an observed configuration review item instead of a scanner exception. |
| example.com | 8/8 | 40/100 | Plain HTTP returned 200 without an upgrade; configuration gaps remained visible. |

The final offline suite passed 155 tests, including real standard-library HTTP response parsing over local socket pairs, timeout/fallback fixtures, malformed headers, incomplete bodies, destination safeguards, scoring, export escaping and local-server behavior. Fresh Kundelik JSON and HTML downloads matched the displayed assessment; its older timed-out report retained its original observations and showed the new missing-evidence explanation. Earlier reports were not silently rescanned.

These checks establish the reproduced fixes and a functioning end-to-end flow. They do not establish universal detection accuracy, website legitimacy, application security or the absence of other defects. Results may vary with server address, network conditions and time. Registration data unavailable for a suffix remains unknown and does not reduce the security checklist score.

## First: controlled fixtures

Run the offline test suite. It covers destination validation, private/mixed DNS answers, connecting to the validated IP, redirect revalidation, downgrade/loop handling, bounded response bodies, escaped report output and conservative interpretation of incomplete evidence.

Expand fixtures when adding a new rule. Include good, missing, malformed and unavailable examples; explicitly describe what the rule cannot infer. For transport integration, use a controlled public endpoint or an isolated test harness. Do not add a production flag that disables private-address protection.

## Then: a small observational study

Choose a clear sample of 20–30 sites you are permitted to observe. Record the selection criteria, scan date, tool version, requests made, and any sites excluded. Use a sequential, low-volume approach. Save one JSON report per intended observation.

Manually review a subset with browser developer tools. Record differences caused by redirects, CDN behavior, user agent, cookies or location rather than automatically calling them scanner errors. Preserve unknown results. Do not use brand popularity or domain age as ground-truth labels for safety.

For each check, report the counts of pass, attention, info and unknown. Explain the denominator if publishing percentages. Track false alerts against the check's own documented rule, not against a claim that the entire site is secure. Findings from a convenience sample cannot be generalized to all websites.

## AI integration checks

Use offline provider doubles to check request construction, input limits, citation validation, invalid JSON, refusals/incomplete responses, missing keys, timeouts and output escaping. Verify that failures leave the source report unchanged and that `--preview` and `render` make no provider request. A mocked provider test verifies integration behavior; it does not establish model quality or live account access.

The `demo --ai-sample` content is hand-authored to exercise the report layout. Keep it clearly marked and exclude it from accuracy or cost measurements. Record actual live validation separately, including the provider/model used and any blocked setup steps. Do not claim successful generation simply because the request-building tests pass.

## Evaluate real explanations

Use a fixed collection of structured reports and human-reviewed expectations. Include successful checks, attention findings, error pages, incomplete scans and reports with several unknown results. Run the same inputs against each selected model and save the enriched JSON rather than regenerating it each time the HTML changes.

For each generated item, use this rubric:

| Criterion | Review question | Record |
| --- | --- | --- |
| Citation validity | Does the finding ID exist? | Valid/invalid; checked automatically |
| Evidence support | Does every factual claim follow from the cited evidence? | Supported, unsupported or ambiguous |
| Scope | Does the text avoid claiming a full security or legitimacy verdict? | Pass/fail with example |
| Uncertainty | Are unavailable checks and relevant limitations preserved? | Preserved/omitted/misrepresented |
| Advice | Is the proposed next step relevant and proportionate? | Useful, generic or misleading |
| Coverage | Were the most useful findings explained? | Important omissions |

Citation validity and JSON shape do not measure factual accuracy. Report unsupported-claim counts separately from integration failures. If using percentages, state the number of reports, generated items or factual claims used as the denominator. Review a second sample independently where possible and record disagreements.

Include malicious instructions inside evidence fields, such as a page title asking the model to ignore its task or mark every check as passed. Confirm that the scanner's original findings stay unchanged and inspect whether the explanation repeats or follows the malicious content. A few successful cases are not proof that prompt injection is solved.

Record provider, model, prompt version, scan version, generation date, input/output token counts, timing and observed errors. For costs, use the provider's applicable rates and reported usage; local inference has no per-request API bill but consumes hardware resources. Avoid rerunning failed paid requests automatically during evaluation.

The CV evidence is a working AI integration, explicit validation, measured failure modes and a documented evaluation. Describe it as model integration and evaluation; this project does not train an ML model.

## Link-checker release verification — 30 October 2026 (v0.4.0)

This release adds exact-link inspection, domain-spelling cues, an optional Google Safe Browsing lookup and comparison with earlier report snapshots. The configuration-v1 weights remain unchanged. The homepage-only benchmark above describes the earlier release.

- **227 automated tests passed** across network boundaries, exact-link routing, sensitive-link rejection, parsing, scoring, profile classification, report comparisons, provider adapters, local HTTP routes and export rendering. External scan/model/provider requests in these tests use controlled fixtures; local HTTP route tests use temporary loopback servers.
- A real UI check of `https://www.python.org/about/?websignal=public-check` retained the path and query, returned HTTP 200, used 3 ordinary requests and produced an 80/100 configuration result with full checklist coverage. A repeat check automatically compared both snapshots and found no changes in the compared security observations. Importing the earlier JSON through the UI produced the same comparison.
- A real UI check of `http://portal.kundelik.kz/` recorded 301 → 302 → 302 → 200, ending at `https://portal.kundelik.kz/v2`, using 4 requests. It produced 100/100 with full coverage and separately explained that the submitted HTTP URL began unencrypted. Its expected-domain comparison matched `kundelik.kz`; that is a hostname comparison, not verification of ownership.
- The live check exposed an overly broad page-purpose rule: a “Latest news” sidebar could make a software site appear to be a news site. Profile v4 now uses title/description evidence for specific categories and correctly describes the saved Python report as software/developer resources. Four regressions cover the change, including upgrading saved reports without another request.
- Desktop and 390-pixel mobile layouts were checked in the browser. The mobile page and expanded redirect details had no horizontal overflow. New-check navigation, history, settings, expandable technical evidence, evidence filtering, report downloads and saved-report import worked. No browser warning/error logs were recorded during these flows.
- JSON and self-contained HTML exports preserved the exact target and comparison information. The synthetic bundled examples were regenerated offline for v0.4.0.

**Provider verification limit:** Google Safe Browsing was tested with controlled responses, including matches, no match, expiry, malformed data, provider errors, duplicate clicks and concurrent AI completion. No real Google key was configured, so live authentication and the provider's verdict for a website were not tested. No OpenAI credit or local-model generation was used in this release verification. A future live lookup requires the user's own key and the explicit URL-sharing action in the interface.

These checks establish tested behavior, not a phishing-detection accuracy benchmark. The small spelling-rule set can miss convincing lookalikes and flag legitimate international domains. A no-match reputation result is never proof of safety. Reports reflect their recorded time and network conditions.

## Numeric overview and owner reviews — 31 October 2026 (v0.5.0)

The interface now separates Overview, Evidence and Changes. The overview uses a configuration score, a combined review count, a separate threat-list result and ten fixed security observation counts. Important reviews use authored explanations and owner actions. These changes preserve the eight configuration-v1 weights.

**287 automated tests passed** in the final regression run, along with JavaScript syntax and HTML element-reference checks. External providers use controlled fixtures; no live threat-list or model claim is implied by this count.

New passive checks inventory script and iframe origins, review cross-origin scripts lacking usable integrity metadata, and review explicit unsafe-url referrer declarations. They reuse already-fetched content, make no dependency requests and do not declare software malicious or safe. Test cases cover inert markup, base URLs, declaration limits, unsupported/partial content, origin-only persistence, malformed saved inventories, declaration parsing and unchanged scores. HTML/text exports include the dependency observations; the bundled examples were regenerated offline.

Browser verification covered the landing screen, live recheck, history, keyboard tab navigation, evidence search/status consistency, copied summaries, expandable owner reviews and dependency evidence. The saved incomplete Kundelik report retained its 85–100% range, neutral status and one unknown security observation. A fresh openai.com check returned HTTP 200, full checklist coverage and a separate cookie review; its dependency inventory was recorded without extra resource requests. Desktop (1280px) and narrow preview (608px) layouts were inspected. No model generation or paid API request was made.

Live verification also exposed a format-only referrer comparison change between older string evidence and current structured evidence. The comparison normalizes compatible declarations while retaining actual policy and coverage changes. UI status filters now match displayed badges, and invalid comparison imports cannot silently fall back to session comparison.

These are regression and integration checks, not a malware-detection benchmark. VirusTotal's vendor detections and Sucuri's signature checks are not provided by the local ten-check summary. The optional Google integration still requires the installer's own key and explicit sharing; live provider authentication was not tested in this release.

### Certificate explanation correction — v0.5.1

A passed certificate check previously displayed the generic renewal reminder description. It now shows recorded days remaining and a friendly UTC expiry date, with status-specific wording in the interface, exports and grounded AI observations. Saved evidence and scores remain unchanged; archived countdowns are not recalculated. Calendar parsing rejects impossible dates instead of silently normalizing them. **296 tests passed**, including nine new certificate regressions. The existing LMS report was verified in the browser as 82 days remaining when checked, expiring 21 January 2027 at 11:06 UTC; no rescan or model call was needed.
