# Verifact

**One link. Two views. Clear evidence.**

**Free to use, modify, share, and fork.** Keep attribution. New material uses a
source-available license requiring separate permission for selling or paid
access. Previously MIT-released code retains its MIT permissions, including sale.
See the [license and earlier MIT release notice](#license).

Verifact is a free local website checker with two views of the same recorded evidence:

| Mode | For | What you see |
| --- | --- | --- |
| **Link check** | Someone deciding what to do with a public link | What the page appears to be, where the link leads, important warnings, threat-list coverage and a practical next step. No invented “percent safe.” |
| **Developer** | Someone reviewing their website's public setup | A transparent configuration checklist, missing or unassessed protections, page dependencies, and evidence-linked fixes. |

Paste a public link, choose a view, and export HTML or JSON when you want to keep the result. Switching views does not rescan the website or call AI. The local community-feed check needs no API key; optional Google Safe Browsing and AI have separate settings and disclosure. Built by [qazaqqyzzz](https://github.com/qazaqqyzzz).

This is a portfolio project in defensive security, analysis and AI integration. Explicit rules produce the measured findings and built-in explanations. Those features work without AI. An optional AI layer adds a separate review with references to the findings, using your own OpenAI credit or a local Ollama model.

## Start locally

Requires Python 3.10 or later. There are **no third-party Python runtime dependencies**, hosting fees or database requirements. Core checks, community-feed matching, built-in explanations and report downloads need no API key or subscription. Network access is needed for live checks and feed refreshes; the synthetic demo runs offline.

Download the repository from [qazaqqyzzz/Verifact](https://github.com/qazaqqyzzz/Verifact) using **Code → Download ZIP**, then extract it. Or clone it:

```sh
git clone https://github.com/qazaqqyzzz/Verifact.git
cd Verifact
```

From the extracted or cloned project folder, start the app on macOS or Linux:

```sh
python3 -m verifact serve --open
```

On Windows, use the Python launcher:

```powershell
py -3 -m verifact serve --open
```

No package installation or virtual environment is required. If you already use a virtual environment, run its Python instead.

For VS Code, open **Verifact.code-workspace** from the project folder, then use the integrated terminal. On a Mac, you can also double-click **Start Verifact.command**; it uses `.venv/bin/python` when available and otherwise tries `python3`. Keep the terminal window open while using the app.

The app listens at [http://127.0.0.1:8765](http://127.0.0.1:8765). `--open` opens your browser; omit it to open the address yourself. Use `--port 8766` if the default port is occupied. Press **Ctrl+C** in the terminal to stop the server. Opening `verifact/static/index.html` directly shows launch instructions; that source file cannot run website checks on its own. Downloaded HTML reports and `examples/demo.html` can be opened directly.

### Check a website

1. Choose **Link check** or **Developer**, then paste a domain or an HTTP/HTTPS link.
2. Optionally enter the domain you expected. The path and accepted query are preserved; fragments are omitted. A separate HTTP homepage request checks the hostname's upgrade to HTTPS.
3. Read the result in your selected view. Link check guidance prioritizes observed connection, destination and threat-list warnings. Developer mode shows the configuration checklist and owner recommendations. Both keep unknown or incomplete evidence visible.
4. Open the evidence for recorded findings, scripts and embeds, redirect details and score methodology. Each important review has an explanation and next step. Download HTML or JSON to keep a snapshot.
5. Check again after a fix and compare an earlier session snapshot or a saved Verifact JSON report for the same exact URL. AI and Google Safe Browsing remain optional; saving a key does not start either service.

In Developer mode, ten core security observations feed the compact counts and eight have numeric weights. Additional link, dependency, referrer and configuration-hygiene observations do not change those weights. In Link check mode, “no warning found” describes the checks that ran; it never promises that a link is safe. The two views use different interpretation rules because a missing developer hardening header alone is not evidence that a visitor is being scammed.

Use public links only. Common access-token, password-reset and one-time action links are rejected before visiting them, including redirects, but these rules cannot recognize every private URL. Reports retain accepted paths and query strings; review downloads before sharing them. No login, form submission, hidden-page search or JavaScript execution is performed.

Website checks, scoring, built-in explanations and downloads are free. The app starts in built-in mode and makes no AI request automatically. Local Ollama runs on your computer without an API fee; OpenAI uses the key owner's API credit. Adding a key does not make a model request, verify the key or check your balance. The app sends selected report evidence to OpenAI only when you select that provider and request an explanation; a failed AI request leaves the scan report available. Repeated requests for an explanation that is running or already completed reuse that job's result.

The key entered in settings stays in the local server's memory. Verifact does not put it in browser storage or write it to files. It is lost when the server stops; an active request may retain its copy until it finishes. An `OPENAI_API_KEY` environment variable is an alternative: OpenAI settings recognize the configured key without asking you to paste it again. Its presence does not turn on paid requests automatically. Removing a session key does not remove a key inherited from that environment. Provider preferences also last only for the server session.

The session holds up to **20 check/demo snapshots** in memory. Stopping the server clears them, so download reports you want to keep. The demo uses synthetic findings and hand-authored AI examples; it is labeled and makes no model request. Real AI output requires either a running local model or your own working key and provider access.

### Command-line workflow

Commands work without starting the web server. Run these from the project folder:

```sh
python3 -m verifact demo
python3 -m verifact demo --format html --output reports/demo.html
```

Open `reports/demo.html` in your browser. The demo is synthetic and makes no network requests. A ready-made copy is also in `examples/demo.html`.

To check a public domain or exact link:

```sh
python3 -m verifact scan example.com
python3 -m verifact scan example.com --format html --output reports/example.html
python3 -m verifact scan example.com --format json --output reports/example.json
python3 -m verifact scan 'https://example.com/catalog?item=12' --expected-domain example.com --format json --output reports/link.json
```

The browser app enables the free community-feed check by default. CLI scans use only the website observations unless you add `--community`:

```sh
python3 -m verifact scan example.com --community
```

This downloads a public domain feed and compares the submitted/observed hostnames locally. It does not send your checked URL to the feed provider. A fresh match for the input hostname stops the page visit; a later redirect match can only be identified after that redirect was observed. Feed problems do not become a clean result or silently prevent the ordinary website checks.

An optional registration lookup uses IANA's RDAP directory and the relevant registry:

```sh
python3 -m verifact scan example.com --rdap
python3 -m verifact scan www.example.com --rdap-domain example.com
```

The tool queries the exact supplied registration domain. It does not guess registrable domains from the last two labels, which would be wrong for names under suffixes such as `co.uk`. RDAP availability and public fields vary by registry. Nameserver data is provided through RDAP; DNS resolution itself covers A/AAAA only.

For an optional disclosure-contact check, add `--security-contact` or enable the corresponding scan option in the app. It retrieves the standard public `/.well-known/security.txt` file and reviews its supported contact/expiry declarations. This adds a bounded public request; it is off by default and does not search hidden paths. A missing file is an owner maintenance suggestion, not a vulnerability, a permission to test the site, or a score penalty.

For scripted use, `scan --target-stdin` reads one URL from standard input so it need not appear in the process command line. Supply either the positional link or `--target-stdin`, not both. The web app uses this route for its scanner subprocess.

If using the virtual environment prepared for this checkout, replace `python3` with `.venv/bin/python`. Optional installation with `python3 -m pip install -e .` adds the shorter `verifact` command, for example `verifact serve --open`. Installation is not necessary for `python3 -m verifact`.

Existing schema-version-1 JSON reports can still be rendered and compared. The distribution name is `verifact-cli`; this repository does not imply that a package has been published to PyPI.

## What it reports

| Area | Observations | Interpretation limits |
| --- | --- | --- |
| Transport | HTTP → HTTPS chain, verified certificate, expiry, negotiated TLS | One connection; no complete protocol/cipher scan |
| Browser | HSTS, enforcing CSP, framing policy, nosniff, referrer policy | Policy presence is not proof of strength or exploitability |
| Header consistency | Selected multiple-value headers and repeated directives within a CSP policy | Not a complete CSP parser; original duplicate field boundaries are not retained |
| Sharing and caching | Returned CORS declarations, cache instructions and optional isolation policies | No Origin/preflight probes, authenticated reads or cache-behavior tests; public sharing/caching can be intentional |
| Public details and embeds | Bounded software-version hints, error markers on server-error pages, and static iframe sandbox declarations | No outdated-software/CVE claim or browser execution; absence of a sandbox or optional policy alone is not a defect |
| Page exposure | Static password-form destinations and methods; response cookie attributes; HTTP resource references | No credentials are entered, forms submitted or JavaScript executed; cookie purpose and browser behavior remain untested |
| Page dependencies | Script and iframe references; cross-origin source counts; scripts lacking usable integrity metadata | Sources are not fetched or executed; origin differences do not establish ownership or maliciousness. Partial inventories remain partial |
| Address sharing | Explicit `unsafe-url` referrer declarations, with owner guidance | Declaration review only; per-element, metadata and runtime overrides can change browser behavior. No explicit policy is not automatically a defect |
| Quality | Title, viewport, language attribute, missing image alt attributes, explicit HTTP resource references | Static HTML only; not a browser, SEO or accessibility audit |
| Domain | Resolved public IPs; optional RDAP dates, nameservers and status | No owner identity, geolocation, reputation or legitimacy verdict |
| Link destination | Supplied path/query, response redirect trail, hostname changes, optional expected-domain comparison | Up to three redirects; only observed destinations are shown; no JavaScript redirects |
| Domain spelling | International domain spelling, mixed writing systems, limited similar-spelling and misleading-subdomain rules | Explainable review cues, not an impersonation detector; legitimate international domains are common |
| Known threats, optional | Google Safe Browsing matches for submitted and observed redirect URLs | Requires your own key and explicit URL-sharing consent; no known match does not mean safe |
| Community threat feed | Local hostname matching against a downloaded CERT Polska domain feed | No URL is submitted to the feed provider. Coverage is limited to that feed; stale/unavailable data remains unknown, and a non-match does not establish safety |
| Disclosure contact, optional | Supported fields in the public security.txt file | Explicit opt-in adds a bounded request. Missing contact information is a maintenance observation, not a vulnerability or authorization for testing |
| Snapshot changes | Earlier-to-current header, TLS, form, cookie, response and redirect changes | Same exact target only; imported observations are user-supplied and not independently verified |

Every finding includes its evidence, explanation and, where useful, a suggested next step. Results use four states:

- **Pass:** the particular check passed; this is not a security certification.
- **Attention:** a configuration or markup observation deserves review.
- **Info:** contextual evidence with no good/bad judgment.
- **Unknown:** insufficient evidence, a blocked destination or a failed request.

Missing headers are not confirmed vulnerabilities; error and partial pages have unknown quality results. Modern browser defaults are acknowledged where appropriate.

### How this compares with larger scanners

[VirusTotal](https://docs.virustotal.com/docs/results-reports) aggregates security-vendor verdicts. Verifact borrows the count-first overview, timestamps, rechecks and separate evidence view; its ten security observations are **not ten antivirus engines**. [Sucuri SiteCheck](https://sitecheck.sucuri.net/) checks public source against malware signatures and other security signals. Verifact focuses on explainable configuration, link and page-dependency observations that new website makers can review for free. It does not include Sucuri's malware-signature database, certify installed software as current, or inspect server-side files. Optional Google threat-list results remain separate from the configuration score.

### Two focused views

The report begins with a plain-language description of what the page appears to be, followed by its declared title and supporting evidence. A university-domain cue combined with learning-platform and login signals can identify a likely university login page; a password field alone only establishes an account-access form. Registration and password-reset wording are considered separately. Classification uses bounded static page observations, not AI or an independent verification of ownership. Saved reports use the evidence already available and leave unsupported purpose claims unknown.

Link check mode explains the most relevant visitor-facing observations and a next action, with separate coverage for the returned page, connection, destination, community feed and optional provider lookup. It does not translate a developer score into a visitor safety percentage.

Developer mode summarizes **connection**, **browser protection** and **page exposure**, with owner review items and the configuration checklist. Domain context, page-quality details, full evidence, score methodology and optional AI remain available without crowding the overview. Downloaded reports preserve both contexts when recorded, clearly labeled as snapshots.

The overview follows **Results → Fix priorities → Security areas**. The searchable **All checks** tab and exported reports use **Test → Result → Fact → Fix**, derived from recorded evidence. Unavailable checks explain the gap and next step; optional settings are not presented as failed requirements. The interface uses white glass for Link check and brighter midnight-blue glass for Developer mode.

When a result is incomplete, **What couldn’t be checked** names the missing checks, their unassessed points, and the observed reason. For example, a timed-out HTTP entry point can leave an 85–100 range even when the HTTPS page passed the other seven scored checks. Unavailable registration data does not change this security score. Old reports keep their original observations; run a new check to apply scanner fixes or collect fresh evidence.

Password-form checks inspect already-fetched markup, including relative actions and static submission overrides. An HTTP destination or GET submission deserves priority review; a cross-origin destination needs human review because external sign-in services can be intentional. Missing or incomplete markup stays unknown. No form is submitted and no login is attempted.

Cookie checks summarize names and the `Secure`, `HttpOnly` and `SameSite` attributes from the returned response. Cookie values are never saved in reports or sent to AI. Missing `Secure` is flagged for review; absent `HttpOnly` or `SameSite` alone remains contextual because cookie purpose and browser defaults matter. These extra observations use the same returned page, with no additional requests, and do not change the existing numeric checklist weights.

Developer hygiene reviews also use only the response already downloaded. They explain selected header conflicts, CORS declarations, shared-cache/account context, optional browser isolation, software/error hints and iframe sandbox combinations. A public CORS wildcard is informational; wildcard plus credentials is an incompatible browser configuration, not proof of credential theft. A login form or cookie does not prove personalized content, and `no-cache` does not mean `no-store`. Version hints do not establish a vulnerable version. These observations remain outside the fixed score and ten core counts.

### Free community feed

Verifact can download [CERT Polska's public domain list](https://cert.pl/en/warning-list/), cache it in memory for five minutes, and match hostnames on your computer. The provider receives a normal feed-download request, not the URL you entered. Matching covers hostnames and listed parent domains. The list focuses mainly on threats targeting Poland; it does not inspect page contents or cover every phishing, malware or scam site. Its use does not imply endorsement by CERT Polska.

Results retain the feed source, fetch/check time and validity. A fresh input-domain match can stop the visit before the website is contacted. Missing, stale or failed feed data remains unavailable. **No match is not proof of safety.** The developer configuration percentage is independent of the feed result. Saved HTML/text reports show historical lookup context; they do not provide live protection.

### Optional Google known-threat lookup

Core checks work immediately without a key. To add Google Safe Browsing:

1. Follow Google's [setup guide](https://developers.google.com/safe-browsing/v4/get-started): create or select a Google Cloud project, create an API key and activate the Safe Browsing API.
2. Restrict the key to `safebrowsing.googleapis.com` using Google's [API-key restrictions](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys). Verifact calls from its local Python server; browser/referrer restrictions are not suitable for that request.
3. In Verifact, open **Settings → Google Safe Browsing**, enter your key locally and save. Alternatively, start the app with `GOOGLE_SAFE_BROWSING_API_KEY` set in its environment. Verifact does not load `.env` files automatically.
4. Complete a link check, select **Check known threats**, review the exact URLs to be shared and select **Send URLs & check**. Saving a key never starts a lookup.

The lookup sends the supplied URL and its observed redirect URLs—including paths and queries—to Google in at most one HTTPS request; still-valid listed results are reused from the local cache. Keys stay in the local server's memory or its environment; they are never included in reports, browser storage or request logs. There is no shared project key. A provider error stays **Unavailable**, not a clean result.

Results distinguish **potentially harmful matches**, **no known match**, **not checked** and **unavailable**. Matches are advisory and can be false positives; lists can also miss harmful links. **No known match does not mean safe.** Reputation never changes the configuration percentage. The app timestamps results and expires listed warnings according to Google's returned validity interval. Saved HTML/text reports include historical lookup provenance, not a persistent current threat warning; request a fresh lookup for current information.

Google documents Safe Browsing as free for **non-commercial use**, subject to its terms and quotas. Commercial products need a suitable service such as Web Risk; this integration does not make a commercial license available. See [usage limits and terms](https://developers.google.com/safe-browsing/v4/usage-limits). This is a third-party list lookup, not Verifact's own malware engine or trained AI detector.

### What the Developer score means

The **Security configuration score** is a custom, weighted checklist out of 100. It is **not the probability that a site is secure**, a vulnerability assessment, or an industry-standard rating. Even 100/100 only means that this small set of observed conditions met its rules. Application logic, authentication, data handling, JavaScript behavior and many other risks remain outside the scan.

| Scored observation | Maximum points |
| --- | ---: |
| Verified TLS certificate | 25 |
| HTTP upgrades to HTTPS | 15 |
| Certificate renewal window | 5 |
| Positive HSTS policy | 15 |
| MIME sniffing protection | 10 |
| Enforcing CSP observed | 10 |
| Framing policy observed | 10 |
| No explicit HTTP resource references in the inspected markup | 10 |

These weights are project heuristics, not measured probabilities. CSP and framing points recognize observed policy presence; they do not establish policy strength. Domain age, IP addresses, page titles, mobile layout declarations and image accessibility do not increase this security configuration score.

The denominator stays at 100. Unknown or missing checks remain unassessed rather than being treated as failures or silently removed. For example, 60 confirmed points with 20 unassessed points produces a **60–80/100 range** and **80% weighted coverage**. Coverage describes how much of this checklist could be assessed, not how much of the website's security was tested. If every scored check is unknown, the report says the score is unavailable. Expand the methodology to see each check's points and evidence.

Built-in explanations select useful findings and their existing guidance using deterministic rules. They are labeled as built-in content, not AI output. AI can explain the evidence but cannot change the measured statuses or score.

The dashboard adds project-defined traffic lights, always paired with a text label. With complete evidence, 80–100 points starts green, 50–79 amber and below 50 red. A recorded security issue prevents green; an observed certificate-verification issue or a password form using HTTP or GET makes the light red even when the checklist percentage is high. Incomplete evidence stays neutral unless one of those priority issues is observed. Extra form and cookie checks can therefore change the review label without changing the percentage. A green light means a strong result on this limited checklist, never that a site is safe. The report explains its applicable rating and the full rules.

## Add an AI explanation

In the web app, **Settings** offers three explanation choices:

| Mode | Setup | Who pays for model use? |
| --- | --- | --- |
| Built-in explanations | None; this is the default | No model call or API charge |
| Local AI with Ollama | Install Ollama and download the local model | No API fee; uses your computer's memory, compute and electricity |
| OpenAI | Your own API key, entered locally or provided through the environment | The owner of that key |

The optional key field appears only for OpenAI when a key is needed. A configured environment key is recognized without another paste step. Selecting a mode or saving settings never generates an explanation by itself. The web worker uses a 60-second request timeout for OpenAI and 120 seconds for local Ollama; the commands below offer a separate workflow for saved files.

First save a scan as JSON. The `explain` command reads that saved report, makes one model request, and adds an AI section to a new report. It does not rescan the site or change the measured findings. The input file is preserved; an output path pointing to the input is rejected.

Inspect the exact messages and output schema before making a request:

```sh
python3 -m verifact explain reports/example.json --provider openai --preview
```

`--preview` needs no key and makes no network requests. The model receives selected report fields with bounded evidence and masked URL query strings/fragments. It does not receive complete HTML, cookies or your API key as prompt content. This masking is limited redaction, not a guarantee that every sensitive detail has been removed; inspect the preview before sending a private report to an external provider.

### Use your OpenAI credit

Use `--prompt-key` to enter your key at a hidden terminal prompt:

```sh
python3 -m verifact explain reports/example.json --provider openai --prompt-key --format json --output reports/example-ai.json
python3 -m verifact render reports/example-ai.json --format html --output reports/example-ai.html
```

If `OPENAI_API_KEY` is already set in your terminal environment, omit `--prompt-key`. Keep the key out of source files, chat messages and GitHub. Verifact does not automatically load `.env` files. The `render` command uses only the saved JSON and makes no model request, so you can regenerate the HTML without another API charge.

The default OpenAI model is `gpt-6-luna`; override it with `--model` in the CLI if your account uses another compatible model. Account access, available credit and usage charges are determined by OpenAI. See the [official model catalog](https://developers.openai.com/api/docs/models) and [current pricing](https://developers.openai.com/api/docs/pricing).

### Run a local model without an API bill

Install [Ollama](https://ollama.com/download), open the Ollama app and keep it running, then download the model once. With a CLI-only installation, start `ollama serve` in a separate terminal first:

```sh
ollama pull qwen3.5:2b-q4_K_M
python3 -m verifact explain reports/example.json --provider ollama --format json --output reports/example-ai-local.json
python3 -m verifact render reports/example-ai-local.json --format html --output reports/example-ai-local.html
```

After pulling the model, select **Local AI · Qwen via Ollama** in the web app's Settings, save, and request an explanation from a completed report. Ollama is also the default provider for the command-line `explain` command. The default local model is [Qwen 3.5 2B (`qwen3.5:2b-q4_K_M`)](https://ollama.com/library/qwen3.5:2b-q4_K_M), with an approximately **1.9 GB model download**, plus Ollama itself. Running it needs additional memory beyond the file size. It uses your computer's memory and compute; speed and output quality depend on the hardware, available memory and input length. It is a lightweight option, not a guarantee of comfortable performance on every computer. Verifact contacts only `127.0.0.1:11434/api/chat` for this provider. It does not download models or switch to a cloud service automatically. See the [Ollama local setup FAQ](https://docs.ollama.com/faq) and [structured outputs documentation](https://docs.ollama.com/capabilities/structured-outputs).

### Controls and interpretation

| Option | Default | Purpose |
| --- | --- | --- |
| `--provider` | `ollama` | Choose local Ollama or `openai` |
| `--model` | Provider default | Select a compatible installed/accessible model |
| `--max-output-tokens` | `1800` | Limit requested output; accepts 256–4096 |
| `--ai-timeout` | `90` seconds | Wait limit for the AI request; accepts 1–300 |
| `--preview` | Off | Print messages and schema without sending them |
| `--prompt-key` | Off | Read an OpenAI key through a hidden prompt |

New AI explanations begin with a report summary, then connect each selected finding through **what we found**, **why it matters**, **what to do next**, and **what this does not prove**. The model receives the site's inferred purpose as context, rather than being asked to invent its identity. Older saved explanations remain readable in their original shorter format.

Each explanation cites a known finding ID. Verifact checks the response structure and citations, and displays the original finding's status beside its explanation. These checks **do not prove that the generated explanation is factually correct**. Review advice against the evidence, especially for unknown results. The AI cannot run tools, scan targets or revise measured statuses.

There is one model request per `explain` invocation, with no automatic retry or provider fallback. Failed or invalid responses leave the source report intact. OpenAI requests use `store: false`; this setting is not a promise of zero data retention. Provider policies still apply. The enriched JSON records the provider, model, prompt version, generation time, available token counts and validation scope.

In the web app, an older saved answer can be updated only through an explicit **Update explanation** action when the explanation format has changed. This makes a new request to the selected provider and can use OpenAI credit if that provider is selected. The old answer remains available until a successful replacement; refreshing the page or repeatedly clicking while generation is running does not start duplicate requests.

To preview the AI section's layout without installing a model or using credit:

```sh
python3 -m verifact demo --ai-sample --format html --output reports/ai-layout-demo.html
```

This sample is explicitly **hand-authored illustrative content**, not output from a real model call. It must not be used as an AI accuracy result.

## Share the project without sharing your API bill

A public GitHub repository can distribute the code and a static sample report. Other people can download the project, run the checker on their own computer and use the built-in explanations immediately. For AI, they can run their own local model or supply their own OpenAI key. Your private API credit is not part of the repository and is not required to try the project.

**Never put a real API key in source code, a frontend bundle, sample configuration, screenshots or GitHub.** Use a server environment variable or the local session setting. `.gitignore` excludes `.env` files in this project, but it cannot protect a key hardcoded into a tracked file, and it does not erase Git history. Verifact does not automatically load `.env` files. OpenAI recommends loading keys on the server from environment variables or a key management service and keeping them out of client-side code. See the [OpenAI authentication guidance](https://developers.openai.com/api/reference/overview).

Publishing code is different from hosting a live scanner. [GitHub Pages serves static HTML, CSS and JavaScript](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages); it cannot run this Python backend. It can host a sample report or project introduction. A public, click-and-scan service would need a separately hosted backend and safeguards for abuse, network access and resource use. If that service pays for everyone's AI, its operator pays those costs too; hiding the key does not make usage free. Authentication, rate limits and spending controls would be part of a separate hosting project. The source code is public at [qazaqqyzzz/Verifact](https://github.com/qazaqqyzzz/Verifact); a hosted scanning service is not provided.

## Study and compare results

The web app automatically compares a newly completed check with the latest compatible earlier report in the session. Under **What changed?**, you can also choose an earlier downloaded Verifact JSON file (up to 1 MiB) for the same exact URL, including its path and query. The earlier timestamp must precede the current one. Imports are compared locally: they do not rescan a website, invoke AI or send the imported data to Google.

The comparison shows changes to selected security observations, response status and destination, and redirect trail. Ordinary certificate countdown and rotating CSP nonces are suppressed. Query values and cookie values are omitted from comparison summaries. Changes alone do not prove an attack or an improvement; content, policy and network conditions may differ. Downloaded JSON remains user-supplied evidence, not an authenticated scan record.

Save reports from a documented sample, then compare them locally:

```sh
python3 -m verifact summarize reports/site-a.json reports/site-b.json
```

This prints per-check counts. Demo fixtures are excluded. Each file counts as one snapshot, so repeated scans of a site must be handled explicitly in your study. Use `docs/evaluation.md` to plan a small study without claiming the sample represents the whole web.

## Scope and request limits

Verifact performs low-volume public observation. It contacts websites, so **“non-invasive” is more precise than strictly passive**. Site terms and applicable rules still matter; for development use fixtures or sites you control. Public visibility alone is not blanket permission for security testing.

- Ordinary GETs for the supplied public link and a separate HTTP homepage upgrade check on ports 80/443, with at most three redirects per entry point.
- At most 12 HTTP requests per scan including optional RDAP; cached duplicate URLs are reused.
- At least 250 ms between request starts and a 2 MiB body limit per response. Interrupted or oversized HTML remains incomplete; received headers and certificate evidence are retained.
- The CLI defaults to an 8-second socket/body budget per request; `--timeout` accepts 1–30 seconds. OS DNS lookup timing and header parsing do not have a strict overall CLI deadline. Web-app scans use a 7-second request budget and a separate scanner process with a 90-second overall deadline.
- No crawling, port enumeration, hidden-path discovery, logins, form submissions, exploitation or JavaScript execution.
- Input and every redirect are validated. All resolved addresses must be public; connections are pinned to a validated IP with hostname verification retained for TLS.
- Up to eight validated DNS addresses share the existing connection time budget, so one unresponsive address cannot consume the entire budget before alternatives are tried.
- HTTPS downgrades, credentials in URLs, nonstandard ports and private destinations are blocked. Common private-token/action links are rejected before their initial request and on redirects. This is conservative detection, not a guarantee that all confidential links are recognized. Environment proxies are not used.
- Reports store selected evidence, not cookies or complete response bodies. Redirect URLs and resource references can still contain query data; review reports before sharing them.

The web interface binds only to `127.0.0.1`, checks Host and Origin headers, and requires a session token for state-changing requests. It is intended for trusted use on your own computer. Do not expose or forward its port as a public service. Public hosting would require additional network egress controls, authentication, abuse prevention and process isolation.

## Project layout

```text
verifact/
  cli.py        # Commands and output files
  network.py    # Validated, bounded HTTP/TLS transport
  links.py      # Exact-link normalization and explainable URL observations
  checks.py     # Evidence-based checks and HTML parsing
  security_hygiene.py # Unscored header, sharing, cache and embed observations
  security_contact.py # Optional security.txt contact/expiry inspection
  page_risks.py # Passive script/iframe inventory and integrity observations
  scanner.py    # Scan orchestration, RDAP and offline demo
  assessment.py # Weighted configuration score and free built-in guidance
  brief.py      # Compact security counts and grounded owner reviews
  comparison.py # Local, bounded differences between earlier/current snapshots
  reputation.py # Explicit Google Safe Browsing lookups and warning expiry
  threat_feed.py # Free community-feed cache and local hostname matching
  visitor_assessment.py # Link check guidance, independent of configuration points
  ai.py         # Optional model requests, bounded input and citation checks
  reports.py    # Terminal, JSON, HTML and study summaries
  server.py     # Local HTTP API, in-memory jobs and scanner subprocesses
  static/       # Browser interface; no frontend build required
tests/          # Offline security and interpretation tests
examples/       # Clearly labeled synthetic report
docs/           # Architecture and evaluation plan
```

Run the tests with:

```sh
python3 -m unittest discover -s tests -v
```

With Node.js available, test browser verdict freshness independently (no browser or API calls):

```sh
node --test tests/report_view.test.cjs
```

Exit codes: `0` successful command (`scan` has a final HTTP or HTTPS response), `1` scan has no final response, `2` command/input/output/provider error, `130` interrupted. Attention findings do not change the exit code.

## Roadmap

1. Evaluate the scanner on a small, documented sample and improve ambiguous findings.
2. Evaluate real OpenAI and local-model explanations for unsupported claims, omissions and useful next steps using the rubric in `docs/evaluation.md`.
3. Add CSV export and a documented evaluation of the new link and comparison features.
4. Improve the local interface using feedback from real scans and explanation reviews.

## References

- [OWASP: SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN: HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
- [MDN: Referrer-Policy and browser defaults](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [ICANN: RDAP](https://www.icann.org/rdap/)
- [IANA: RDAP DNS bootstrap](https://data.iana.org/rdap/dns.json)
- [OpenAI: structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses)
- [Ollama: structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
- [Google Safe Browsing: setup](https://developers.google.com/safe-browsing/v4/get-started)
- [Google Safe Browsing: usage limits](https://developers.google.com/safe-browsing/v4/usage-limits)

## License

The project uses the custom [Verifact Free Sharing License 1.0](LICENSE),
copyright 2026 qazaqqyzzz, effective 31 October 2026.

| Activity | Under the new license |
| --- | --- |
| Run locally, study the code, or modify it | Allowed |
| Use it internally, including to check your own business website | Allowed |
| Share free copies or publish free forks | Allowed; retain the license and attribution, and identify material changes |
| Sell copies, modified versions, or substantial portions of the code | Requires separate written permission |
| Charge for hosted access, an API, or a paid bundle containing the software | Requires separate written permission |

This is **source-available software** with a no-sale restriction, not an
OSI-approved open-source license. Paying an independent provider for your own
AI, hardware, or infrastructure use is allowed; provider terms still apply.

**Earlier MIT releases keep their permissions.** All code publicly released
through commit [`c1c5960`](https://github.com/qazaqqyzzz/Verifact/tree/c1c596026c04b9435de9e33a0c3b9e007f912bfb),
inclusive, remains usable under its
[original MIT license](https://github.com/qazaqqyzzz/Verifact/blob/c1c596026c04b9435de9e33a0c3b9e007f912bfb/LICENSE),
including its sale and redistribution permissions. The new license does not
take those rights back, including for unchanged code carried into later
versions. New material first released under the new license follows its terms.

Bundled Space Grotesk and IBM Plex Mono fonts retain their separate
[SIL Open Font Licenses](verifact/static/fonts/README.txt). Their permissions,
and the terms of external data and optional provider services, are unchanged.
