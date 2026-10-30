"use strict";

const $ = (id) => document.getElementById(id);
const state = { config: null, jobs: new Map(), selected: null, mode: "simple", category: "all", status: "all", findingIds: null, poll: null, pollErrors: 0, busy: false, reportKey: null };
const labels = { pass: "Passed", attention: "Needs action", info: "Additional fact", unknown: "Could not check" };
const categoryLabels = { Transport: "Connection", Browser: "Browser protection", Quality: "Page quality", Domain: "Domain" };

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function notify(text) { $("status-region").textContent = text; }
function showError(id, error) { const box = $(id); box.textContent = error?.message || String(error); box.hidden = false; }
function hideError(id) { $(id).hidden = true; $(id).textContent = ""; }
function dateText(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }); }
function apiPath(id) { return "/api/scans/" + encodeURIComponent(id); }

function setMode(mode, announce = true) {
  if (announce) state.interacted = true;
  state.mode = mode === "developer" ? "developer" : "simple";
  const developer = state.mode === "developer";
  document.body.dataset.mode = state.mode;
  $("mode-simple").setAttribute("aria-pressed", String(!developer));
  $("mode-developer").setAttribute("aria-pressed", String(developer));
  $("consumer-report").hidden = developer;
  $("developer-report").hidden = !developer;
  $("security-contact-option").hidden = !developer;
  $("page-title").replaceChildren(document.createTextNode(developer ? "Build with care." : "A little clarity."), document.createElement("br"), document.createTextNode(developer ? "Check with " : "Before you "), element("span", "", developer ? "clarity." : "click."));
  $("hero-eyebrow").textContent = developer ? "YOUR PUBLIC SECURITY, EXPLAINED" : "A CLEARER VIEW OF THE WEB";
  $("hero-description").textContent = developer ? "Check your website’s security basics. See what to fix first." : "Check the link. Understand the risks. Know your next step.";
  $("target-label").textContent = developer ? "Your website, under the lens" : "Where does your link lead?";
  $("target").placeholder = developer ? "https://your-website.com" : "Paste a link or enter a domain";
  $("report-label").textContent = developer ? "DEVELOPER SECURITY REPORT" : "YOUR LINK CHECK";
  $("scope-one").textContent = developer ? "HTTPS & certificates" : "Real destination";
  $("scope-two").textContent = developer ? "Browser protections" : "Reported threats";
  $("scope-three").textContent = developer ? "Forms & page resources" : "Connection & page clues";
  $("scope-limit").textContent = developer ? "Public configuration checks. No login, exploits or penetration testing." : "A useful first check. No tool can guarantee that a link is safe.";
  document.querySelector('meta[name="theme-color"]').content = developer ? "#102552" : "#f4f7fc";
  document.title = developer ? "Verifact — Developer security check" : "Verifact — A clearer view of the web";
  setBusy(state.busy);
  if (announce) notify(developer ? "Developer mode. The same report, with security evidence and fixes." : "Link check mode. A short risk summary of the same report.");
}

function visibleReportTitle() { return $(state.mode === "developer" ? "result-domain" : "visitor-title"); }

function safeDisplayURL(value) {
  try { const url = new URL(value); if (url.search) { url.search = ""; return url.href + " [query hidden]"; } return url.href; }
  catch { return typeof value === "string" ? value : "Not established"; }
}

function renderVisitor(report) {
  clearTimeout(state.visitorExpiryTimer);
  const value = report.visitor_assessment;
  const assessment = VerifactReportView.visitor(report);
  const profile = report.site_profile || {};
  const tone = ({orange:"amber",gray:"unknown"})[assessment.tone] || toneName(assessment.tone);
  $("visitor-card").className = "visitor-card tone-" + tone;
  $("visitor-domain").textContent = profile.hostname || report.domain;
  $("visitor-monogram").textContent = (profile.hostname || report.domain || "↗").slice(0,1).toUpperCase();
  $("visitor-type").textContent = profile.type || "Public website";
  $("visitor-description").textContent = report.inspection_skipped ? "Page inspection stopped before contacting this reported destination." : report.brief?.description || profile.summary || "The page’s purpose could not be established.";
  $("visitor-title").textContent = assessment.label;
  $("visitor-summary").textContent = assessment.summary;
  $("visitor-icon").textContent = ({warning:"!",caution:"!",no_warning:"✓",unknown:"?"})[assessment.status] || "?";
  $("visitor-next").textContent = assessment.next_action;
  $("visitor-reasons").replaceChildren();
  for (const [index, reason] of (assessment.reasons || []).slice(0,3).entries()) {
    const item = element("li");
    const copy = element("div");
    copy.append(element("strong", "", reason.title), element("p", "", reason.detail));
    item.append(element("span", "reason-marker", index + 1), copy);
    $("visitor-reasons").append(item);
  }
  $("visitor-coverage").replaceChildren();
  const coverage = assessment.coverage || {};
  for (const [label, status] of [["Connection",coverage.connection],["Page",coverage.page],["Warning list",coverage.community_feed]]) {
    const complete = ["assessed","no_match","listed"].includes(status);
    const chip = element("span", "tone-" + (status === "listed" ? "red" : complete ? "green" : "unknown"));
    chip.append(element("i"), document.createTextNode(label + ": " + (status === "listed" ? "match found" : complete ? "checked" : status === "not_checked" ? "not checked" : "unavailable")));
    $("visitor-coverage").append(chip);
  }
  const feed = report.community_reputation || {};
  const sourceStatus = feed.expires_at && new Date(feed.expires_at).getTime() <= Date.now() ? "outdated" : ({listed:"Match found",no_match:"No match",unavailable:"Unavailable",not_checked:"Not checked"})[feed.status] || "Not checked";
  $("visitor-facts").replaceChildren();
  const facts = [["Submitted link",safeDisplayURL(report.target_url || report.domain)],["Destination",safeDisplayURL(report.link_analysis?.final_url || report.response?.url)],["Checked",dateText(report.created_at)],["Public warning list","CERT Polska · " + sourceStatus]];
  if (report.link_analysis?.expected_domain) facts.splice(2,0,["Expected domain",report.link_analysis.expected_domain]);
  if (feed.fetched_at) facts.push(["List updated",dateText(feed.fetched_at)]);
  const google = report.reputation;
  if (google) facts.push(["Optional Google lookup",google.expires_at && new Date(google.expires_at).getTime() <= Date.now() ? "Expired" : ({listed:"Potential threat reported",no_match:"No match",unavailable:"Unavailable",not_checked:"Not checked"})[google.status] || "Not checked"]);
  for (const [label, text] of facts) { const row = element("div"); row.append(element("dt", "", label), element("dd", "", text)); $("visitor-facts").append(row); }
  $("visitor-scope").textContent = feed.scope || "The public list covers a limited set of reported domains, with a focus on threats targeting people in Poland. New or unreported scams may be missed.";
  const expiry = value?.expires_at ? new Date(value.expires_at).getTime() - Date.now() : 0;
  if (expiry > 0) {
    const id = state.selected;
    state.visitorExpiryTimer = setTimeout(async () => {
      if (state.selected !== id) return;
      // Expired data stops displaying a current verdict before any network work.
      const current = selectedJob();
      if (current?.report) { renderVisitor(current.report); renderReputation(current); renderDashboard(current.report); }
      try { const job = await api(apiPath(id)); if (state.selected === id) selectJob(job); }
      catch { /* The expired state above remains visible if the local app is offline. */ }
    }, Math.min(expiry + 50, 2147483647));
  }
}

async function api(path, data) {
  const options = { cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } };
  if (data !== undefined) {
    if (!state.config) throw new Error("The local app is not ready yet. Refresh and try again.");
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-Verifact-Token"] = state.config.csrf_token;
    options.body = JSON.stringify(data);
  }
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("Cannot reach Verifact. Make sure the local server is still running, then refresh."); }
  let body;
  try { body = await response.json(); }
  catch { throw new Error("The local server returned an unreadable response. Please refresh and try again."); }
  if (!response.ok) {
    const error = new Error(body.error || "The request could not be completed.");
    error.status = response.status;
    throw error;
  }
  return body;
}

function selectedProvider() { return state.config?.provider || "builtin"; }
function outdatedAI(ai) { return Boolean(ai && !ai.fixture && state.config?.ai_prompt_version && ai.prompt_version !== state.config.ai_prompt_version); }

function renderConfig(config) {
  state.config = config;
  $("key-status").textContent = "Settings";
  $("reputation-config-label").textContent = config.reputation_configured ? "Connected" : "Not connected";
  $("reputation-key").disabled = Boolean(config.reputation_configured);
  $("reputation-key").placeholder = config.reputation_configured ? "Key is configured locally" : "Only needed for threat lookups";
  $("clear-reputation-key").hidden = config.reputation_key_source !== "session";
  $("reputation-key-note").textContent = config.reputation_key_source === "environment" ? "Configured through this computer’s environment. No key entry needed." : "Kept in local server memory for this session. A lookup only happens when you request one.";
  $("connection-dot").classList.toggle("ready", config.provider === "openai" && Boolean(config.openai_configured));
  $("ai-provider").value = config.provider || "builtin";
  $("settings-status").textContent = config.provider === "ollama" ? "Local AI selected" : config.provider === "openai" ? (config.openai_configured ? "OpenAI configured on this computer" : "OpenAI selected · key needed to generate") : "Built-in explanations active";
  $("settings-model").textContent = config.provider && config.provider !== "builtin" ? "Model: " + (config.model || config.models?.[config.provider] || "") : "No model, account or API credit required.";
  $("version").textContent = "v" + config.version;
  updateSettingsMode();
  updateAI();
  if (selectedJob()?.report) renderReputation(selectedJob());
}

function updateSettingsMode() {
  const provider = $("ai-provider").value;
  const configured = Boolean(state.config?.openai_configured);
  $("settings-key-fields").hidden = provider !== "openai" || configured;
  $("api-key").disabled = provider !== "openai" || configured;
  $("local-ai-help").hidden = provider !== "ollama";
  $("local-model-command").textContent = "ollama pull " + (state.config?.models?.ollama || "qwen3.5:2b-q4_K_M");
  $("configured-key-note").hidden = provider !== "openai" || !configured;
  $("configured-key-note").textContent = state.config?.key_source === "environment" ? "OpenAI is configured through this computer’s environment. No key entry is needed here." : "Your session key is configured. It will be cleared when the local server stops.";
  $("clear-key").hidden = provider !== "openai" || state.config?.key_source !== "session";
  $("clear-key").disabled = state.config?.key_source !== "session";
  $("provider-description").textContent = provider === "ollama" ? "Generate an explanation with a model running on your computer. No external AI service or API charge is involved." : provider === "openai" ? "Generate an explanation using your own OpenAI credit. Selected report evidence is sent to OpenAI only when you request it." : "Get clear, rule-based explanations and suggested next steps immediately. Nothing is sent to an AI provider.";
}

function openSettings() {
  hideError("settings-error");
  $("settings-success").hidden = true;
  $("api-key").value = "";
  $("ai-provider").value = selectedProvider();
  updateSettingsMode();
  $("settings-dialog").showModal();
  $("ai-provider").focus();
}

function setBusy(busy) {
  state.busy = busy;
  $("scan-button").disabled = busy;
  $("recheck-button").disabled = busy || Boolean(selectedJob()?.report?.demo);
  $("demo-button").disabled = busy;
  $("scan-button").textContent = busy ? "Checking…" : state.mode === "developer" ? "Check website →" : "Check link →";
}

function renderHistory() {
  const jobs = [...state.jobs.values()].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  $("history-count").textContent = String(jobs.length);
  renderHistoryList(jobs, "history");
}

function renderHistoryList(jobs, containerId) {
  const container = $(containerId);
  container.replaceChildren();
  if (!jobs.length) { container.append(element("p", "history-empty", "Your recent checks will appear here.")); return; }
  for (const job of jobs) {
    const button = element("button", "history-item" + (job.id === state.selected ? " active" : ""));
    button.type = "button";
    button.append(element("strong", "", job.domain || "Website check"));
    const status = job.report?.demo ? "Sample report" : job.status === "running" ? "Checking…" : job.status === "failed" ? "Check unavailable" : "Report ready";
    button.append(element("span", "", status + " · " + dateText(job.created_at)));
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const completeJob = await api(apiPath(job.id));
        selectJob(completeJob);
        notify("Showing saved report for " + completeJob.domain + ".");
        if (containerId === "history") {
          $("history-disclosure").open = false;
          if (completeJob.report) {
            visibleReportTitle().focus({ preventScroll: true });
            $("results").scrollIntoView({ behavior: "smooth", block: "start" });
          }
        }
      }
      catch (error) {
        if (error.status === 404) {
          state.jobs.delete(job.id);
          if (state.selected === job.id) resetChecker();
          renderHistory();
        }
        showError("form-error", error);
      } finally { button.disabled = false; }
    });
    container.append(button);
  }
}

function selectedJob() { return state.jobs.get(state.selected); }

async function refreshHistory() {
  const history = await api("/api/scans");
  const current = state.jobs;
  state.jobs = new Map((history.scans || []).map((job) => [job.id, { ...current.get(job.id), ...job }]));
  renderHistory();
}

function resetChecker() {
  state.interacted = true;
  clearTimeout(state.visitorExpiryTimer);
  document.body.classList.remove("report-mode");
  state.selected = null;
  state.reportKey = null;
  state.category = "all";
  state.status = "all";
  state.findingIds = null;
  $("status-filter").value = "all";
  $("finding-search").value = "";
  showReportTab("overview");
  state.allReviews = false;
  $("target").value = "";
  $("expected-domain").value = "";
  $("community-check").checked = true;
  $("security-contact").checked = false;
  $("results").hidden = true;
  $("progress").hidden = true;
  $("empty-state").hidden = false;
  $("history-disclosure").open = false;
  hideError("form-error");
  renderHistory();
  $("target").focus();
  notify("Ready for a new public link.");
  $("main").scrollIntoView({ behavior: "smooth" });
}

function selectJob(job) {
  state.jobs.set(job.id, job);
  const changed = state.selected !== job.id;
  state.selected = job.id;
  if (changed) {
    showReportTab("overview"); state.allReviews = false; $("finding-search").value = "";
    state.category = "all"; state.status = "all"; state.findingIds = null; state.reportKey = null; $("status-filter").value = "all";
    for (const id of ["evidence-section", "ai-section", "method-section", "link-section", "dependencies-section", "technical-section", "comparison-section"]) $(id).open = false;
  }
  hideError("form-error");
  renderHistory();
  renderJob(job);
  schedulePoll();
}

function renderJob(job) {
  const running = job.status === "running" || job.status === "queued";
  $("progress").hidden = !running;
  $("empty-state").hidden = running || Boolean(job.report);
  $("results").hidden = !job.report;
  document.body.classList.toggle("report-mode", running || Boolean(job.report));
  setBusy([...state.jobs.values()].some((j) => j.status === "running" || j.status === "queued"));
  if (running) {
    $("progress-title").textContent = "Checking " + job.domain;
    $("progress-description").textContent = job.phase || "Reading public configuration. Some services can take a moment to respond.";
    const elapsed = Math.max(0, Math.round((Date.now() - new Date(job.created_at).getTime()) / 1000));
    $("progress-time").textContent = Number.isFinite(elapsed) ? elapsed + "s" : "";
  }
  if (job.status === "failed") { showError("form-error", job.error || "This check could not be completed."); notify("Check could not be completed."); }
  if (!job.report) return;
  const key = job.id + ":" + (job.report.ai?.generated_at || "raw") + ":" + JSON.stringify([job.report.reputation, job.report.community_reputation, job.report.visitor_assessment, job.report.comparison, job.reputation_status]);
  if (state.reportKey !== key) { renderReport(job); state.reportKey = key; }
  updateAI();
}

function schedulePoll() {
  clearTimeout(state.poll);
  const active = [...state.jobs.values()].filter((j) => j.status === "running" || j.status === "queued" || j.ai_status === "running" || j.reputation_status === "running");
  if (!active.length) return;
  state.poll = setTimeout(async () => {
    try {
      for (const old of active) {
        const job = await api(apiPath(old.id));
        state.jobs.set(job.id, job);
        if (job.id === state.selected) renderJob(job);
        if ((old.status === "running" || old.status === "queued") && job.status === "complete") notify("Website report ready for " + job.domain + ".");
        if (old.ai_status === "running" && job.ai_status === "complete") notify("AI explanation ready.");
      }
      state.pollErrors = 0;
      renderHistory();
      setBusy([...state.jobs.values()].some((j) => j.status === "running" || j.status === "queued"));
      schedulePoll();
    } catch (error) {
      state.pollErrors += 1;
      showError("form-error", error);
      if (state.pollErrors < 3) schedulePoll();
      else { $("progress").hidden = true; setBusy(false); notify("Connection lost. Refresh to reconnect."); }
    }
  }, 1000);
}

function renderReport(job) {
  const report = job.report;
  $("demo-banner").hidden = !report.demo;
  $("result-domain").textContent = report.domain;
  $("target").value = report.target_url || report.domain;
  $("expected-domain").value = report.link_analysis?.expected_domain || "";
  $("site-scope").textContent = report.scan_mode === "exact_link" ? "Submitted link" : "Homepage (earlier report)";
  $("result-meta").textContent = "Checked " + dateText(report.created_at) + (report.demo ? " · Sample" : report.scan_mode === "exact_link" ? "" : " · Earlier homepage check");
  $("tab-evidence-count").textContent = report.findings.length;
  $("tab-change-count").textContent = report.comparison?.available ? report.comparison.changes.length : "";
  $("download-json").href = apiPath(job.id) + "/download?format=json";
  $("download-html").href = apiPath(job.id) + "/download?format=html";
  $("result-summary").replaceChildren();
  const summaryLabels = { pass: "Passed", attention: "Needs action", info: "Additional facts", unknown: "Could not check" };
  for (const status of ["pass", "attention", "info", "unknown"]) {
    const count = report.findings.filter((finding) => findingStatus(finding, report) === status).length;
    const card = element("button", "summary-card " + status);
    card.type = "button";
    card.setAttribute("aria-label", count + " " + summaryLabels[status] + ". Filter findings.");
    card.append(element("strong", "", count), element("span", "", summaryLabels[status]), element("span", "summary-marker"));
    card.addEventListener("click", () => { state.status = status; state.category = "all"; state.findingIds = null; $("finding-search").value = ""; $("status-filter").value = status; renderFindings(); $("findings").scrollIntoView({ behavior: "smooth", block: "start" }); });
    $("result-summary").append(card);
  }
  $("coverage-note").textContent = "Choose a test to see the fact and fix.";
  $("evidence-caption").textContent = report.findings.length + " tests & facts";
  $("limitations-list").replaceChildren();
  for (const limitation of report.limitations || []) $("limitations-list").append(element("li", "", limitation));
  renderAssessment(report);
  renderSiteProfile(report);
  renderVisitor(report);
  renderDashboard(report);
  renderReputation(job);
  renderLinkAnalysis(report);
  renderPageRisks(report);
  renderComparison(report);
  renderFindings();
}

function toneName(value) { return ["green", "amber", "red", "unknown"].includes(value) ? value : "unknown"; }

function renderSiteProfile(report) {
  const profile = report.site_profile || {};
  const title = profile.title || report.findings.find((finding) => finding.id === "title" && finding.status === "pass" && typeof finding.evidence === "string")?.evidence;
  $("site-title").textContent = typeof title === "string" && title ? title : "No page title was available in this report.";
  $("site-type").textContent = profile.type || "Website type not established";
  $("site-summary").textContent = report.brief?.description || profile.summary || "This is the public homepage returned by the website. Its purpose could not be established from this saved report.";
  $("site-description").hidden = !profile.description;
  $("site-description").textContent = profile.description ? "Website's own description: " + profile.description : "";
  $("site-signals").replaceChildren();
  for (const signal of profile.signals || []) if (typeof signal === "string") $("site-signals").append(element("li", "", signal));
  $("site-host").textContent = profile.hostname || report.domain;
  const status = profile.http_status ?? report.response?.status;
  const protocol = profile.https === true ? "HTTPS" : profile.https === false && status ? "HTTP" : "";
  $("site-response").textContent = [protocol, Number.isInteger(status) ? "HTTP " + status : "No completed response"].filter(Boolean).join(" · ");
  $("site-basis").textContent = [profile.summary, profile.basis].filter(Boolean).join(" ") || "Title supplied by the website. Its purpose and organization identity have not been independently verified.";
}

function openEvidence(ids = null, label = "Selected tests") {
  if (state.mode !== "developer") setMode("developer");
  showReportTab("evidence");
  $("finding-search").value = "";
  $("technical-section").open = true;
  $("evidence-section").open = true;
  state.category = "all"; state.status = "all"; state.findingIds = ids;
  state.selectionLabel = label;
  $("status-filter").value = "all";
  renderFindings();
  $("evidence-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showReportTab(name, focus = false) {
  if (!["overview", "evidence", "changes"].includes(name)) return;
  state.tab = name;
  for (const value of ["overview", "evidence", "changes"]) {
    const active = value === name;
    $("panel-" + value).hidden = !active;
    $("tab-" + value).setAttribute("aria-selected", String(active));
    $("tab-" + value).tabIndex = active ? 0 : -1;
  }
  if (focus) $("tab-" + name).focus();
}

function currentReviews(report) {
  return (report.brief?.all_reviews || report.brief?.reviews || []).filter((item) =>
    !["reputation","community"].includes(item.source) || (item.expires_at && new Date(item.expires_at).getTime() > Date.now()));
}

function reviewEvidence(item) {
  if (item.finding_id) focusFinding(item.finding_id);
  else if (item.source === "link") revealDetails("link-section");
  else if (item.source === "page") revealDetails("dependencies-section");
  else if (item.source === "community") {
    showReportTab("overview");
    $("community-details").open = true;
    $("reputation-card").scrollIntoView({ behavior: "smooth", block: "center" });
  }
  else {
    showReportTab("overview");
    $("threat-details").open = true;
    $("reputation-card").scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

function renderDashboard(report) {
  const brief = report.brief;
  const counts = brief?.counts;
  const reviews = currentReviews(report);
  const urgent = reviews.filter((item) => item.tone === "red").length;
  const tone = urgent ? "red" : reviews.length ? "amber" : !counts || counts.unknown ? "unknown" : "green";
  $("review-card").className = "review-card tone-" + tone;
  $("review-total").textContent = brief ? String(reviews.length) : "—";
  $("review-label").textContent = urgent ? urgent + (urgent === 1 ? " urgent concern" : " urgent concerns") : reviews.length ? "Items to review" : counts ? "No fixes identified" : "Check again for a result";
  $("review-hint").textContent = "";
  $("review-card").disabled = !reviews.length && !counts?.unknown;
  $("review-card").querySelector(".metric-link").textContent = reviews.length ? "See fixes →" : counts?.unknown ? "See incomplete tests →" : "For completed checks";
  const missing = new Set([...(brief?.checks || []).filter((item) => item.status === "unknown").map((item) => item.id), ...report.findings.filter((item) => ["Browser", "Transport"].includes(item.category) && findingStatus(item, report) === "unknown").map((item) => item.id)]);
  state.incompleteIds = [...missing];
  $("pending-checks").hidden = !missing.size;
  $("pending-checks").textContent = missing.size + (missing.size === 1 ? " security test could not finish" : " security tests could not finish") + " · See why and how to retry →";
  $("security-signals").replaceChildren();
  for (const group of brief?.groups || []) {
    const extraIds = ({browser:["referrer","header_quality","cors_policy","browser_isolation"], page:["response_caching","public_disclosures","iframe_sandbox"]})[group.id] || [];
    const extras = report.findings.filter((item) => extraIds.includes(item.id));
    const extraReviews = extras.filter((item) => findingStatus(item, report) === "attention").length;
    const extraUnknown = extras.filter((item) => findingStatus(item, report) === "unknown").length;
    const tone = group.tone === "red" ? "red" : group.review || extraReviews ? "amber" : group.unknown || extraUnknown ? "unknown" : group.tone;
    const card = element("button", "signal-card tone-" + toneName(tone));
    card.type = "button";
    const header = element("span", "signal-top");
    header.append(element("span", "", group.title), element("span", "signal-indicator"));
    const count = element("strong", "group-number", group.met);
    count.append(element("span", "", "/" + group.total));
    const outcome = [group.review + extraReviews ? group.review + extraReviews + " to review" : "", group.unknown + extraUnknown ? group.unknown + extraUnknown + " incomplete" : ""].filter(Boolean).join(" · ");
    card.append(header, count, element("span", "group-caption", "Basic checks met"), element("span", "group-detail", outcome), element("span", "group-open", "View tests →"));
    card.setAttribute("aria-label", group.title + ": " + group.met + " of " + group.total + " met. View checks.");
    card.addEventListener("click", () => openEvidence([...(brief.checks || []).filter((item) => item.group === group.id).map((item) => item.id), ...extras.map((item) => item.id)], group.title));
    $("security-signals").append(card);
  }
  $("count-strip").replaceChildren();
  for (const [key, label, color] of [["met", "Met", "green"], ["review", "Review", "amber"], ["unknown", "Unknown", "unknown"]]) {
    const button = element("button", "count-chip tone-" + color);
    button.type = "button";
    button.append(element("i", "count-dot"), element("strong", "", counts ? counts[key] : "—"), document.createTextNode(label));
    button.setAttribute("aria-label", (counts?.[key] ?? "Unknown") + " security checks: " + label + ". Filter evidence.");
    button.addEventListener("click", () => openEvidence((brief?.checks || []).filter((item) => item.status === key).map((item) => item.id)));
    $("count-strip").append(button);
  }
  $("count-strip").append(element("span", "count-caption", "10 security checks · 8 weighted"));
  $("priority-count").textContent = reviews.length ? (urgent ? urgent + " urgent" : reviews.length + (reviews.length === 1 ? " item" : " items")) : "";
  $("priorities-caption").textContent = "";
  $("priority-panel").hidden = !reviews.length;
  $("priority-list").replaceChildren();
  for (const item of (state.allReviews ? reviews : reviews.slice(0, 3))) {
    const row = element("article", "review-item tone-" + toneName(item.tone));
    const top = element("div", "review-item-heading");
    top.append(element("span", "review-light"), element("h4", "", item.title), element("span", "review-level", item.tone === "red" ? "URGENT" : "REVIEW"));
    const feedback = report.check_feedback?.[item.finding_id];
    row.append(top);
    const fact = element("div", "review-why feedback-line");
    fact.append(element("strong", "feedback-label", "Fact"), element("p", "", feedback?.fact || item.why));
    const next = element("div", "review-action feedback-line");
    next.append(element("strong", "feedback-label", "Fix"), element("p", "", feedback?.fix || item.action));
    const evidence = element("button", "text-button", "Open test →");
    evidence.type = "button";
    evidence.addEventListener("click", () => reviewEvidence(item));
    row.append(fact, next, evidence);
    $("priority-list").append(row);
  }
  $("all-reviews-button").hidden = reviews.length <= 3;
  $("all-reviews-button").textContent = state.allReviews ? "Show top 3" : "Show all " + reviews.length + " review items";
}

function renderAssessment(report) {
  const score = report.assessment;
  $("assessment").hidden = !score;
  if (!score) return;
  const known = Number.isFinite(score.value);
  const partial = known && score.coverage < 100;
  const rating = report.dashboard?.rating;
  const tone = toneName(rating?.tone);
  $("assessment").className = "assessment tone-" + tone;
  $("score-rating").className = "status-pill tone-" + tone;
  $("score-rating").textContent = ({green:"Checks passed",amber:"Needs improvement",red:"Priority fixes",unknown:"Tests incomplete"})[tone];
  $("score-ring").style.setProperty("--score-angle", (known ? Math.max(0, Math.min(100, score.value)) * 3.6 : 0) + "deg");
  $("score-ring").classList.toggle("partial", partial);
  $("score-value").textContent = known ? String(score.value) + (partial ? "–" + score.potential : "") + "%" : "—";
  $("score-caption").textContent = known ? (partial ? "score range" : "setup score") : "no score";
  $("assessment-description").textContent = !known ? "Run the checks again." : partial ? score.unknown_weight + " points could not be tested." : "Weighted security checklist";
  $("score-coverage-label").textContent = score.assessed_checks + " of " + score.total_checks + " scored tests completed";
  $("score-progress").value = score.coverage;
  const reviewPriority = report.dashboard?.priorities?.find((item) => item.tone === tone);
  const explainColour = Boolean(rating?.override && reviewPriority);
  $("score-reason").hidden = !explainColour;
  $("score-reason").replaceChildren();
  if (explainColour) {
    $("score-reason").append(element("strong", "", tone === "amber" ? "Why orange? " : "Why red? "), document.createTextNode(reviewPriority.title + ": " + reviewPriority.detail));
  }
  $("score-disclaimer").textContent = "";
  const gaps = report.dashboard?.coverage_gaps || [];
  $("assessment-gaps").hidden = !gaps.length;
  $("assessment-gap-list").replaceChildren();
  for (const gap of gaps.slice(0, 2)) {
    const row = element("li");
    const label = gap.title + (gap.weight ? " · " + gap.weight + " points unassessed" : " · additional check");
    const hasFinding = report.findings.some((item) => item.id === gap.finding_id);
    const link = element(hasFinding ? "button" : "strong", "gap-link", label);
    if (hasFinding) {
      link.type = "button";
      link.addEventListener("click", () => focusFinding(gap.finding_id));
    }
    row.append(link, element("p", "", gap.detail));
    $("assessment-gap-list").append(row);
  }
  if (gaps.length > 2) {
    const row = element("li");
    const more = element("button", "gap-link", "Review unavailable security evidence ↗");
    more.type = "button";
    more.addEventListener("click", () => {
      showReportTab("evidence"); $("finding-search").value = "";
      state.status = "all"; state.category = "all";
      state.findingIds = gaps.map((item) => item.finding_id);
      $("status-filter").value = "all";
      $("technical-section").open = true;
  $("evidence-section").open = true;
      renderFindings();
      $("evidence-section").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    row.append(more); $("assessment-gap-list").append(row);
  }
  $("score-full-disclaimer").textContent = score.disclaimer || "Application vulnerabilities and site legitimacy are not assessed.";
  $("rating-methodology").textContent = rating?.methodology || "Status lights require the latest dashboard assessment.";
  $("score-methodology").textContent = Array.isArray(score.methodology) ? score.methodology.join(" ") : score.methodology || "Fixed project-defined weights. Unknown checks remain unassessed, and AI cannot change this score.";
  $("score-method-version").textContent = "Method: " + score.method_version + ". Page quality and domain age do not affect this score.";
  $("score-breakdown").replaceChildren();
  for (const item of score.items || []) {
    const row = element("tr");
    const name = element("td");
    const hasFinding = report.findings.some((finding) => finding.id === item.finding_id);
    const citation = element(hasFinding ? "button" : "span", hasFinding ? "score-citation" : "", item.title);
    if (hasFinding) {
      citation.type = "button";
      citation.addEventListener("click", () => focusFinding(item.finding_id));
    }
    name.append(citation);
    if (item.note) name.append(element("small", "", item.note));
    row.append(name, element("td", "", (item.assessed ? item.earned : "?") + "/" + item.weight), element("td", "", item.assessed ? item.earned > 0 ? "Confirmed" : "Needs review" : "Unknown"));
    $("score-breakdown").append(row);
  }
}

function appendExplanation(container, item, report, className = "ai-item") {
  const finding = report.findings.find((f) => f.id === item.finding_id);
  const row = element("div", className);
  const citation = element("button", "ai-citation", (finding?.title || item.finding_id) + (finding ? " · " + (labels[finding.status] || finding.status) : ""));
  citation.type = "button";
  citation.addEventListener("click", () => focusFinding(item.finding_id));
  row.append(citation);
  const sections = [["What was observed", item.explanation, "ai-observation"], ["Why it matters", item.why_it_matters, "ai-meaning"], ["What to do next", item.next_step, "ai-action"], ["What this does not tell us", item.limitation, "ai-limitation"]];
  for (const [label, text, type] of sections) {
    if (typeof text !== "string" || !text.trim()) continue;
    const section = element("div", "ai-explanation-part " + type);
    section.append(element("h4", "", label), element("p", "", text));
    row.append(section);
  }
  container.append(row);
}

function findingStatus(finding, report) {
  const feedbackState = report.check_feedback?.[finding.id]?.state;
  if (["pass", "attention", "info", "unknown"].includes(feedbackState)) return feedbackState;
  const observed = report.brief?.checks?.find((item) => item.id === finding.id)?.status;
  const effective = { met: "pass", review: "attention", unknown: "unknown" }[observed];
  return effective || (["pass", "attention", "info", "unknown"].includes(finding.status) ? finding.status : "unknown");
}

function renderFindings() {
  const report = selectedJob()?.report;
  if (!report) return;
  const needle = $("finding-search").value.trim().toLowerCase();
  const order = {attention:0, unknown:1, pass:2, info:3};
  const list = report.findings.filter((f) => (!state.findingIds || state.findingIds.includes(f.id)) && (state.category === "all" || f.category === state.category) && (state.status === "all" || findingStatus(f, report) === state.status) && (!needle || [f.title, f.category, report.check_feedback?.[f.id]?.fact || f.explanation].join(" ").toLowerCase().includes(needle))).sort((a,b) => order[findingStatus(a, report)] - order[findingStatus(b, report)]);
  $("finding-count").textContent = list.length + " shown";
  $("active-selection").hidden = !state.findingIds;
  $("active-selection").textContent = (state.selectionLabel || "Selected tests") + " · Show all tests ×";
  for (const button of $("category-tabs").querySelectorAll("button")) {
    const active = !state.findingIds && button.dataset.category === state.category;
    button.classList.toggle("active", active); button.setAttribute("aria-pressed", String(active));
    const category = button.dataset.category;
    const total = report.findings.filter((f) => category === "all" || f.category === category).length;
    button.replaceChildren(document.createTextNode(category === "all" ? "All checks" : categoryLabels[category] || category), element("span", "category-count", total));
  }
  $("findings").replaceChildren();
  const absent = (state.findingIds || []).filter((id) => !report.findings.some((finding) => finding.id === id));
  if (absent.length) $("findings").append(element("p", "empty-filter", absent.length + " checks were not recorded in this earlier report. Check the link again to collect them."));
  if (!list.length && !absent.length) { $("findings").append(element("p", "empty-filter", "No matching findings. Clear the search or choose another filter.")); return; }
  for (const finding of list) {
    const index = report.findings.indexOf(finding);
    const card = element("article", "finding check-row");
    card.id = "finding-" + index; card.tabIndex = -1;
    const status = findingStatus(finding, report);
    const feedback = report.check_feedback?.[finding.id];
    const label = feedback?.result || labels[status];
    const details = element("details", "check-disclosure");
    const heading = element("summary", "check-heading");
    const name = element("span", "check-name", finding.title);
    name.append(element("small", "", categoryLabels[finding.category] || finding.category));
    heading.append(name, element("span", "badge " + status, label), element("span", "row-plus", "+"));
    details.append(heading);
    const body = element("div", "check-body");
    if (finding.id === "certificate_expiry" && Array.isArray(finding.presentation?.metrics)) {
      const facts = element("dl", "observation-metrics " + (status === "pass" ? "tone-green" : status === "attention" ? "tone-amber" : "tone-unknown"));
      for (const metric of finding.presentation.metrics.slice(0, 2)) {
        const fact = element("div");
        fact.append(element("dt", "", metric.label), element("dd", "", metric.value));
        facts.append(fact);
      }
      body.append(facts);
    }
    const fact = element("div", "feedback-line check-fact");
    fact.append(element("strong", "feedback-label", "Fact"), element("p", "", feedback?.fact || "This saved report needs to be checked again for a concise evidence summary."));
    const next = element("div", "feedback-line check-fix");
    next.append(element("strong", "feedback-label", "Fix"), element("p", "", feedback?.fix || "Run a new check to get the current result and next step."));
    body.append(fact, next);
    const raw = element("details", "raw-evidence");
    raw.append(element("summary", "", "Technical evidence"), element("pre", "", typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence, null, 2)));
    body.append(raw); details.append(body); card.append(details); $("findings").append(card);
  }
}

function focusFinding(id) {
  if (state.mode !== "developer") setMode("developer");
  showReportTab("evidence");
  $("finding-search").value = "";
  const report = selectedJob()?.report;
  const index = report?.findings.findIndex((finding) => finding.id === id) ?? -1;
  if (index < 0) return;
  $("technical-section").open = true;
  $("evidence-section").open = true;
  state.category = "all"; state.status = "all"; state.findingIds = null; $("status-filter").value = "all";
  renderFindings();
  const card = $("finding-" + index);
  card.querySelector("details").open = true;
  card.classList.add("focused");
  card.focus({ preventScroll: true });
  card.scrollIntoView({ behavior: "smooth", block: "center" });
}

function updateAI() {
  const job = selectedJob();
  if (!job?.report) return;
  const report = job.report;
  const ai = report.ai;
  const provider = selectedProvider();
  const running = job.ai_status === "running";
  const stale = outdatedAI(ai);
  $("ai-summary-label").textContent = running ? "Generating an explanation…" : stale ? "Earlier explanation · a more detailed version is available" : ai ? (ai.fixture ? "Illustrative example · no model was called" : "Your findings, explained with practical next steps") : "Optional · no effect on the score";
  $("explain-button").disabled = running || (Boolean(ai) && !stale) || Boolean(report.demo);
  $("explain-button").textContent = running ? "Generating…" : ai && !stale ? (ai.fixture ? "Illustrative sample" : "Explanation ready") : provider === "builtin" ? "Choose AI ↗" : provider === "openai" && !state.config?.openai_configured ? "Set up OpenAI ↗" : provider === "ollama" ? (stale ? "Update with local AI ↗" : "Explain with local AI ↗") : (stale ? "Update with OpenAI ↗" : "Explain with OpenAI ↗");
  $("ai-description").textContent = running ? "Explaining the recorded evidence, why it matters and the next steps. Your measured score stays unchanged." : "Explain the important findings and next steps.";
  const activeProvider = (running ? job.ai_provider : stale ? provider : ai?.provider) || provider;
  $("ai-disclosure").textContent = report.demo ? "This synthetic sample makes no API call and uses no credit." : activeProvider === "ollama" ? "Runs on your computer with Ollama. No external AI provider or API charge." : activeProvider === "openai" ? "Uses your OpenAI credit and sends selected report evidence to OpenAI." : "Optional · Local AI has no API fee. OpenAI uses your own credit.";
  $("preview-button").hidden = provider === "builtin";
  $("preview-button").disabled = running;
  if (job.ai_error) showError("ai-error", job.ai_error); else hideError("ai-error");
  const aiKey = ai ? job.id + ai.generated_at : "";
  if ($("ai-content").dataset.key === aiKey) return;
  $("ai-content").dataset.key = aiKey;
  $("ai-content").replaceChildren();
  if (!ai) return;
  if (ai.fixture) $("ai-content").append(element("div", "ai-fixture", "Hand-authored illustration — this text was not generated by a model."));
  if (typeof ai.summary === "string" && ai.summary.trim()) {
    const overview = element("section", "ai-overview");
    overview.append(element("h3", "", "The overall picture"), element("p", "", ai.summary));
    $("ai-content").append(overview);
  }
  for (const item of ai.items || []) appendExplanation($("ai-content"), item, report);
  let provenance = ai.model + " · " + dateText(ai.generated_at) + ". ";
  if (Number.isInteger(ai.usage?.input_tokens) && Number.isInteger(ai.usage?.output_tokens)) provenance += ai.usage.input_tokens + " input / " + ai.usage.output_tokens + " output tokens. ";
  provenance += "References are checked; advice still needs review against the evidence.";
  const details = element("details", "ai-provenance");
  details.append(element("summary", "", "Model and explanation details"), element("p", "", provenance));
  if (typeof ai.validation === "string") details.append(element("p", "", ai.validation));
  $("ai-content").append(details);
}

function revealDetails(id) {
  if (state.mode !== "developer") setMode("developer");
  showReportTab(["link-section","method-section","dependencies-section"].includes(id) ? "evidence" : id === "comparison-section" ? "changes" : "overview");
  $(id).open = true;
  $(id).scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderPageRisks(report) {
  const page = report.page_risks;
  const available = page && ["assessed", "partial"].includes(page.status);
  const partial = page?.status === "partial";
  const number = (key) => available && Number.isInteger(page[key]) ? String(page[key]) + (partial ? "+" : "") : "—";
  $("dependencies-number").textContent = number("cross_origin_scripts");
  $("dependencies-caption").textContent = !available ? "Not recorded · check again" : page.without_integrity ? page.without_integrity + " without integrity" : partial ? "Partial HTML evidence" : "From the returned HTML";
  $("dependencies-shortcut").classList.toggle("has-clues", Boolean(available && page.without_integrity));
  $("dependencies-summary").textContent = !available ? "Not assessed" : partial ? "Partial inventory · counts are minimums" : "Origins referenced in the returned HTML";
  $("dependencies-note").textContent = available ? "Cross-origin code can affect your page. Verify the sources you use; a different origin does not prove a different owner or malicious code." : "This report has no supported page-dependency inventory. Check the link again; older reports are not silently rescanned.";
  $("dependency-counts").replaceChildren();
  for (const [key, label] of [["script_count", "Script references"], ["cross_origin_scripts", "Cross-origin scripts"], ["without_integrity", "Without integrity"], ["iframe_count", "Embeds"]]) {
    const cell = element("div", key === "without_integrity" && page?.without_integrity ? "dependency-stat tone-amber" : "dependency-stat tone-unknown");
    cell.append(element("strong", "", number(key)), element("span", "", label));
    $("dependency-counts").append(cell);
  }
  $("dependency-origins").replaceChildren();
  const origins = available && Array.isArray(page.origins) ? page.origins : [];
  $("dependency-table").hidden = !origins.length;
  for (const origin of origins) {
    const row = element("tr");
    row.append(element("th", "", origin.origin), element("td", "", origin.scripts), element("td", "", origin.iframes), element("td", "", origin.without_integrity));
    $("dependency-origins").append(row);
  }
  $("dependency-limits").textContent = available ? "No scripts or embeds were downloaded or run. Integrity metadata presence is recorded, not verified against a file. Dynamic scripts, server files and malware signatures are not checked." : "No malware-clean verdict is inferred from missing evidence.";
}

function renderLinkAnalysis(report) {
  const link = report.link_analysis;
  const trail = Array.isArray(link?.redirects) ? link.redirects : [];
  const warnings = Array.isArray(link?.warnings) ? link.warnings : [];
  const flagged = warnings.filter((item) => ["amber","red"].includes(item.tone));
  $("journey-number").textContent = link ? String(link.redirect_count ?? 0) : "—";
  $("domain-number").textContent = link ? String(flagged.length) : "—";
  const hops = trail.filter((item) => [301, 302, 303, 307, 308].includes(item.status)).length;
  $("journey-summary").textContent = link ? "Redirects" : "Journey not recorded";
  let destination;
  try { destination = new URL(link?.final_url || report.response?.url).hostname; } catch { destination = "No final response"; }
  $("journey-caption").textContent = destination;
  $("domain-summary").textContent = link ? "URL warnings" : "URL check unavailable";
  $("domain-caption").textContent = !link ? "Earlier report" : flagged.length ? "Review the destination" : "No flagged URL patterns";
  $("domain-shortcut").classList.toggle("has-clues", flagged.length > 0);
  $("link-note").textContent = link?.note || "This earlier report checked the homepage. Run the link again to record its full journey and domain clues.";
  $("redirect-trail").replaceChildren();
  for (const [index, item] of trail.entries()) {
    const row = element("li", "redirect-step");
    const copy = element("div");
    copy.append(element("strong", "", index === 0 ? "Submitted link" : index === trail.length - 1 && link.completed ? "Final response" : "Redirect destination"), element("code", "", item.url));
    row.append(element("span", "step-number", String(index + 1).padStart(2, "0")), copy, element("span", "http-code", "HTTP " + item.status));
    $("redirect-trail").append(row);
  }
  if (link && !trail.length) $("redirect-trail").append(element("li", "empty-filter", "No completed response was recorded for the submitted link."));
  if (link?.error) $("redirect-trail").append(element("li", "link-stop", "Stopped: " + link.error));
  $("domain-clues").replaceChildren();
  if (link?.expected_domain) {
    const note = element("div", "domain-expectation");
    note.append(element("strong", "", "Expected domain: " + link.expected_domain), element("p", "", link.expected_match === true ? "The observed destination matches this domain or one of its subdomains. This checks the spelling, not the organization’s identity." : link.expected_match === false ? "The observed destination is outside the expected domain. Verify it before sharing information." : "The destination could not be established."));
    $("domain-clues").append(note);
  }
  for (const warning of warnings) {
    const item = element("article", "domain-warning tone-" + toneName(warning.tone));
    item.append(element("h4", "", warning.title), element("p", "", warning.detail));
    $("domain-clues").append(item);
  }
  if (link && !warnings.length) $("domain-clues").append(element("p", "input-hint", "No configured URL heuristics were triggered. New scams and convincing lookalikes can still pass these checks."));
  const rdap = report.findings.find((item) => item.id === "rdap");
  if (rdap) {
    const details = element("details", "registration-details");
    details.append(element("summary", "", "Registration information"), element("p", "", rdap.explanation), element("pre", "", typeof rdap.evidence === "string" ? rdap.evidence : JSON.stringify(rdap.evidence, null, 2)));
    $("domain-clues").append(details);
  }
}

function renderReputation(job) {
  renderGoogleReputation(job);
  const feed = job.report.community_reputation;
  const expired = Boolean(feed?.expires_at && new Date(feed.expires_at).getTime() <= Date.now());
  const status = expired ? "unavailable" : feed?.status || "not_checked";
  const google = job.report.reputation;
  const googleListed = google?.status === "listed" && google.expires_at && new Date(google.expires_at).getTime() > Date.now();
  const tone = status === "listed" || googleListed ? "red" : status === "no_match" ? "green" : "unknown";
  const available = ["listed","no_match"].includes(status);
  $("reputation-card").className = "reputation-card tone-" + tone;
  $("community-number").textContent = available ? String(new Set((feed?.matches || []).map((item) => item.hostname)).size) : "—";
  $("community-label").textContent = available ? "of " + (feed.checked_count || 0) + (feed.checked_count === 1 ? " domain listed" : " domains listed") : "No current list result";
  $("community-status").className = "status-pill tone-" + tone;
  $("community-status").textContent = ({listed:"Reported domain",no_match:"No match in this list",unavailable:expired ? "List expired" : "List unavailable",not_checked:"Not checked"})[status] || "Not checked";
  $("community-detail").textContent = available ? "Free · Domain matches · Limited coverage" : expired ? "Run a new check for current data." : feed?.detail || "Run a check with the public warning list enabled.";
  if (googleListed) {
    $("community-number").textContent = String(new Set((google.matches || []).map((item) => item.url)).size);
    $("community-label").textContent = "URLs flagged by Google";
    $("community-status").textContent = "Threat warning found";
    $("community-detail").textContent = status === "listed" ? "CERT Polska also reported a domain match." : status === "no_match" ? "CERT Polska: no domain match." : "CERT Polska: no current result.";
    document.querySelector(".google-optional").open = true;
  }
  $("community-details").hidden = status !== "listed";
  $("community-matches").replaceChildren();
  if (status === "listed") for (const match of feed.matches || []) {
    $("community-matches").append(element("li", "", match.hostname + " · matches " + match.listed_domain));
  }
}

function renderGoogleReputation(job) {
  clearTimeout(state.reputationExpiryTimer);
  const rep = job.report.reputation;
  const running = job.reputation_status === "running";
  const expired = Boolean(rep?.expires_at && new Date(rep.expires_at).getTime() <= Date.now());
  const status = expired ? "unavailable" : rep?.status || "not_checked";
  const tone = status === "listed" ? "red" : "unknown";
  const matched = new Set((rep?.matches || []).map((item) => item.url)).size;
  const established = !expired && ["listed", "no_match"].includes(status);
  $("reputation-number").textContent = established ? String(matched) : "—";
  $("reputation-number-label").textContent = established ? "of " + rep.checked_count + " URLs flagged" : "No verdict yet";
  $("threat-details").hidden = status !== "listed";
  $("reputation-card").className = "reputation-card tone-" + tone;
  $("reputation-status").className = "status-pill tone-" + tone;
  $("reputation-status").textContent = running ? "Checking threat lists…" : ({ listed: "Potentially harmful", no_match: "No known match", unavailable: "Lookup unavailable", not_checked: "Not checked" }[status] || "Not checked");
  $("reputation-detail").textContent = running ? "Checking the submitted URL and observed redirects with Google Safe Browsing." : expired ? "This lookup has expired. Run a new lookup for a current result." : rep?.detail || "Compare this link and its redirects with Google’s lists of known phishing and malware URLs.";
  $("reputation-time").textContent = rep?.checked_at ? "Checked " + dateText(rep.checked_at) + (rep.checked_count ? " · " + rep.checked_count + " URLs" : "") : "";
  $("reputation-button").disabled = running || Boolean(job.report.demo);
  $("reputation-button").textContent = running ? "Checking…" : job.report.demo ? "Live links only" : !state.config?.reputation_configured ? "Connect lookup ↗" : rep ? "Check again ↗" : "Check threats ↗";
  $("reputation-attribution").hidden = !rep?.checked_at;
  $("reputation-footnote").textContent = status === "listed" ? "Potential threat · false positives possible" : status === "no_match" ? "No known match ≠ safe" : expired ? "Previous result expired" : status === "unavailable" ? "No result · try again later" : "Optional Google Safe Browsing lookup";
  $("reputation-matches").replaceChildren();
  if (status === "listed") for (const match of rep.matches || []) {
    const row = element("div", "threat-match");
    row.append(element("strong", "", match.label || "Potential threat"), element("code", "", match.url));
    const education = { MALWARE: "https://developers.google.com/search/docs/monitor-debug/security/malware", SOCIAL_ENGINEERING: "https://www.antiphishing.org/", UNWANTED_SOFTWARE: "https://www.google.com/about/unwanted-software-policy.html", POTENTIALLY_HARMFUL_APPLICATION: "https://developers.google.com/safe-browsing/v4/advisory" };
    const learn = element("a", "", "About this warning ↗");
    learn.href = education[match.threat_type] || "https://developers.google.com/safe-browsing/v4/advisory";
    learn.target = "_blank"; learn.rel = "noreferrer";
    row.append(learn);
    $("reputation-matches").append(row);
  }
  const expiry = rep?.expires_at ? new Date(rep.expires_at).getTime() - Date.now() : 0;
  if (expiry > 0) state.reputationExpiryTimer = setTimeout(() => {
    const current = selectedJob();
    if (current?.id === job.id) { renderReputation(current); renderDashboard(current.report); }
  }, Math.min(expiry + 50, 2147483647));
}

function renderComparison(report) {
  hideError("comparison-error");
  const comparison = report.comparison;
  $("comparison-changes").replaceChildren();
  const changedCount = comparison?.changes?.length || 0;
  $("comparison-caption").textContent = comparison?.available ? changedCount + (changedCount === 1 ? " change" : " changes") + " from the earlier report" : "Compare with an earlier check of this exact link";
  $("comparison-summary").textContent = comparison?.available ? comparison.summary + " Earlier check: " + dateText(comparison.previous_created_at) + "." : "Run the same link again to compare it with an earlier check, or choose a saved Verifact JSON report.";
  for (const change of comparison?.changes || []) {
    const item = element("article", "comparison-change");
    item.append(element("h4", "", change.title));
    const grid = element("div", "change-grid");
    for (const [label, value] of [["Before", change.before], ["Now", change.after]]) {
      const block = element("div");
      block.append(element("span", "small-label", label), element("p", "", value));
      grid.append(block);
    }
    item.append(grid); $("comparison-changes").append(item);
  }
}

$("journey-shortcut").addEventListener("click", () => revealDetails("link-section"));
$("dependencies-shortcut").addEventListener("click", () => revealDetails("dependencies-section"));
$("domain-shortcut").addEventListener("click", () => {
  showReportTab("evidence");
  $("link-section").open = true;
  $("domain-clues").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("reputation-close").addEventListener("click", () => $("reputation-dialog").close());
$("reputation-button").addEventListener("click", () => {
  const job = selectedJob();
  if (!job?.report || job.report.demo) return;
  if (!state.config?.reputation_configured) {
    openSettings();
    document.querySelector(".integration-settings").open = true;
    $("reputation-key").focus();
    return;
  }
  const report = job.report;
  const values = [report.target_url || "https://" + report.domain + "/", ...(report.link_analysis?.redirects || []).map((row) => row.url), report.link_analysis?.final_url || report.response?.url];
  $("reputation-url-list").replaceChildren();
  for (const value of [...new Set(values.filter(Boolean))]) $("reputation-url-list").append(element("li", "", value));
  hideError("reputation-error");
  $("reputation-dialog").dataset.jobId = job.id;
  $("reputation-dialog").showModal();
});
$("reputation-confirm").addEventListener("click", async () => {
  $("reputation-confirm").disabled = true;
  hideError("reputation-error");
  try {
    const job = await api(apiPath($("reputation-dialog").dataset.jobId) + "/reputation", { consent: true });
    $("reputation-dialog").close();
    selectJob(job);
    notify("Threat lookup started.");
  } catch (error) { showError("reputation-error", error); }
  finally { $("reputation-confirm").disabled = false; }
});
$("clear-reputation-key").addEventListener("click", async () => {
  hideError("settings-error");
  $("clear-reputation-key").disabled = true;
  try { renderConfig(await api("/api/settings", { reputation_key: "" })); }
  catch (error) { showError("settings-error", error); }
  finally { $("clear-reputation-key").disabled = false; }
});
async function compareSnapshot(previous) {
  const job = selectedJob();
  if (!job?.report) return;
  hideError("comparison-error");
  $("compare-session").disabled = true;
  $("compare-file").disabled = true;
  try {
    if (previous !== undefined && (!previous || typeof previous !== "object" || Array.isArray(previous))) {
      throw new Error("Choose a saved Verifact JSON report, not a single value or list.");
    }
    const result = await api(apiPath(job.id) + "/compare", previous !== undefined ? { previous } : {});
    selectJob(result);
    showReportTab("changes");
    $("comparison-section").open = true;
    notify("Report comparison ready.");
  } catch (error) { showError("comparison-error", error); }
  finally { $("compare-session").disabled = false; $("compare-file").disabled = false; }
}
$("compare-session").addEventListener("click", () => compareSnapshot());
$("compare-file").addEventListener("change", async () => {
  const file = $("compare-file").files?.[0];
  $("compare-file").value = "";
  if (!file) return;
  try {
    if (file.size > 1000000) throw new Error("Choose a Verifact JSON report smaller than 1 MB.");
    let previous;
    try { previous = JSON.parse(await file.text()); } catch { throw new Error("This file is not valid JSON. Choose a downloaded Verifact JSON report."); }
    await compareSnapshot(previous);
  } catch (error) { showError("comparison-error", error); }
});

$("finding-search").addEventListener("input", renderFindings);
$("active-selection").addEventListener("click", () => openEvidence());
$("pending-checks").addEventListener("click", () => openEvidence(state.incompleteIds || [], "Incomplete tests"));
$("all-reviews-button").addEventListener("click", () => { state.allReviews = !state.allReviews; renderDashboard(selectedJob().report); });
$("review-card").addEventListener("click", () => {
  const report = selectedJob()?.report;
  if (!report) return;
  if (currentReviews(report).length) $("priority-panel").scrollIntoView({behavior:"smooth",block:"center"});
  else openEvidence((report.brief?.checks || []).filter((item) => item.status === "unknown").map((item) => item.id));
});
document.querySelector(".report-tabs").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-tab]");
  if (button) showReportTab(button.dataset.tab);
});
document.querySelector(".report-tabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) return;
  const names = ["overview","evidence","changes"];
  const current = names.indexOf(event.target.dataset.tab);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "Home" ? 0 : event.key === "End" ? 2 : (current + (event.key === "ArrowRight" ? 1 : -1) + 3) % 3;
  showReportTab(names[next], true);
});
$("recheck-button").addEventListener("click", () => {
  const job = selectedJob();
  if (!job?.report || job.report.demo || state.busy) return;
  $("target").value = job.report.target_url || job.domain;
  $("scan-form").requestSubmit();
});
$("copy-summary").addEventListener("click", async () => {
  const report = selectedJob()?.report;
  if (!report) return;
  let target = report.target_url || report.domain;
  try { const url = new URL(target); if (url.search) { url.search = ""; target = url.href + " [query omitted]"; } } catch {}
  const score = report.assessment;
  const scoreText = Number.isFinite(score?.value) ? score.value + (score.unknown_weight ? "–" + score.potential : "") + "/100" : "Unknown";
  const reviews = currentReviews(report);
  const rep = report.reputation;
  const expired = rep?.expires_at && new Date(rep.expires_at).getTime() <= Date.now();
  const status = expired ? "unavailable (expired)" : rep?.status || "not checked";
  const visitor = VerifactReportView.visitor(report);
  const lines = state.mode === "simple" ? ["Verifact · " + target, "Checked: " + dateText(report.created_at), "Link check: " + visitor.label, ...(visitor.reasons || []).slice(0,3).map((item) => "• " + item.title + ": " + item.detail), "Next: " + visitor.next_action, "A snapshot of basic checks. New scams can be missed."] : ["Verifact · " + target, "Checked: " + dateText(report.created_at), "Security setup: " + scoreText, "Review items: " + reviews.length, ...reviews.slice(0,3).map((item) => "• " + item.title + ": " + (report.check_feedback?.[item.finding_id]?.fact || item.why) + " Fix: " + (report.check_feedback?.[item.finding_id]?.fix || item.action)), "Optional Google lookup: " + status, "Public configuration checks, not a safety guarantee."];
  const text = lines.join("\n");
  $("copy-text").value = text;
  try {
    await navigator.clipboard.writeText(text);
    $("copy-summary").textContent = "Copied ✓"; notify("Short report summary copied.");
    setTimeout(() => { $("copy-summary").textContent = "Copy summary"; }, 1800);
  } catch {
    $("copy-dialog").showModal(); $("copy-text").select();
  }
});
$("copy-close").addEventListener("click", () => $("copy-dialog").close());

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.busy) return;
  state.interacted = true;
  state.selected = null;
  state.reportKey = null;
  clearTimeout(state.visitorExpiryTimer);
  $("results").hidden = true;
  $("empty-state").hidden = false;
  document.body.classList.remove("report-mode");
  hideError("form-error");
  setBusy(true);
  try {
    const job = await api("/api/scans", { target: $("target").value.trim(), rdap: $("rdap").checked, community_check: $("community-check").checked, security_contact: state.mode === "developer" && $("security-contact").checked, expected_domain: $("expected-domain").value.trim() || null });
    selectJob(job);
    notify("Checking " + job.domain + ".");
    await refreshHistory();
  } catch (error) { showError("form-error", error); setBusy(false); }
});

$("demo-button").addEventListener("click", async () => {
  hideError("form-error");
  $("demo-button").disabled = true;
  try { selectJob(await api("/api/demo", {})); notify("Synthetic sample report loaded."); await refreshHistory(); }
  catch (error) { showError("form-error", error); }
  finally { $("demo-button").disabled = state.busy; }
});

$("new-check").addEventListener("click", resetChecker);
$("home-link").addEventListener("click", (event) => { event.preventDefault(); resetChecker(); });
$("target").addEventListener("input", () => { state.interacted = true; });
$("mode-simple").addEventListener("click", () => setMode("simple"));
$("mode-developer").addEventListener("click", () => setMode("developer"));
$("open-developer-report").addEventListener("click", () => { setMode("developer"); $("result-domain").focus({preventScroll:true}); $("developer-report").scrollIntoView({behavior:"smooth",block:"start"}); });
$("settings-open").addEventListener("click", openSettings);
$("ai-provider").addEventListener("change", () => { $("api-key").value = ""; $("settings-success").hidden = true; updateSettingsMode(); });
$("settings-close").addEventListener("click", () => $("settings-dialog").close());
$("settings-dialog").addEventListener("close", () => { $("api-key").value = ""; $("reputation-key").value = ""; });
$("preview-close").addEventListener("click", () => $("preview-dialog").close());
$("status-filter").addEventListener("change", () => { state.findingIds = null; state.status = $("status-filter").value; renderFindings(); });
$("category-tabs").addEventListener("click", (event) => { const button = event.target.closest("button"); if (button) { state.findingIds = null; state.category = button.dataset.category; renderFindings(); } });

$("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideError("settings-error");
  $("save-key").disabled = true;
  $("settings-success").hidden = true;
  const provider = $("ai-provider").value;
  const key = $("api-key").value.trim();
  const payload = { provider };
  if (provider === "openai" && key) payload.api_key = key;
  if ($("reputation-key").value.trim()) payload.reputation_key = $("reputation-key").value.trim();
  $("reputation-key").value = "";
  $("api-key").value = "";
  try {
    const config = await api("/api/settings", payload);
    renderConfig(config);
    $("settings-success").textContent = "Preferences saved. No AI or threat-lookup request was made.";
    $("settings-success").hidden = false;
  } catch (error) { showError("settings-error", error); }
  finally { $("save-key").disabled = false; }
});

$("clear-key").addEventListener("click", async () => {
  hideError("settings-error");
  $("clear-key").disabled = true;
  $("api-key").value = "";
  try {
    const config = await api("/api/settings", { provider: $("ai-provider").value, api_key: "" });
    renderConfig(config);
    $("settings-success").textContent = config.openai_configured ? "Session key removed. A key supplied through this computer’s environment is still configured." : "Session key removed.";
    $("settings-success").hidden = false;
  } catch (error) { showError("settings-error", error); updateSettingsMode(); }
});

$("explain-button").addEventListener("click", async () => {
  const provider = selectedProvider();
  if (provider === "builtin" || (provider === "openai" && !state.config?.openai_configured)) { openSettings(); return; }
  const job = selectedJob();
  if (!job?.report || (job.report.ai && !outdatedAI(job.report.ai)) || job.ai_status === "running") return;
  $("explain-button").disabled = true;
  hideError("ai-error");
  try { selectJob(await api(apiPath(job.id) + "/explain", { refresh: outdatedAI(job.report.ai) })); notify("Generating an AI explanation."); }
  catch (error) { showError("ai-error", error); $("explain-button").disabled = false; }
});

$("preview-button").addEventListener("click", async () => {
  const job = selectedJob();
  if (!job) return;
  $("preview-content").textContent = "Loading preview…";
  $("preview-dialog").showModal();
  try { $("preview-content").textContent = JSON.stringify(await api(apiPath(job.id) + "/preview"), null, 2); }
  catch (error) { $("preview-content").textContent = error.message; }
});

async function start() {
  setMode("simple", false);
  if (location.protocol === "file:") {
    document.querySelector(".app-shell").hidden = true;
    document.querySelector(".skip-link").hidden = true;
    $("file-open-notice").hidden = false;
    document.title = "Open Verifact";
    return;
  }
  $("scan-button").disabled = true;
  try {
    renderConfig(await api("/api/config"));
    await refreshHistory();
    const jobs = [...state.jobs.values()];
    const recent = jobs.find((job) => job.status === "running" || job.ai_status === "running" || job.reputation_status === "running");
    if (recent && !state.interacted) {
      const job = await api(apiPath(recent.id));
      if (!state.interacted) selectJob(job);
      else setBusy(jobs.some((item) => item.status === "running" || item.status === "queued"));
    } else setBusy(jobs.some((item) => item.status === "running" || item.status === "queued"));
  } catch (error) { showError("form-error", error); $("scan-button").disabled = false; }
}

start();
