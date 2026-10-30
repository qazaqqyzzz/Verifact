"use strict";

// Refresh the presentation without discarding independent recorded warnings.
// No requests, DOM access or score changes happen here.
const VerifactReportView = (() => {
  function visitor(report, now = Date.now()) {
    const value = report.visitor_assessment;
    if (!value) return {
      status: "unknown", label: "Check this link again", tone: "gray",
      summary: "This saved report does not include the current link checks.",
      reasons: [], next_action: "Run a new check.", coverage: {},
    };
    if (!value.expires_at || new Date(value.expires_at).getTime() > now) return value;
    const providers = {community: report.community_reputation, reputation: report.reputation};
    const fresh = (source) => {
      const item = providers[source];
      return item && ["listed", "no_match"].includes(item.status) && new Date(item.expires_at).getTime() > now;
    };
    const remaining = (value.reasons || []).filter((reason) => !["community", "reputation"].includes(reason.source) || fresh(reason.source));
    const red = new Set(["community_match", "known_threat", "unencrypted_destination", "downgrade", "certificate_verification", "unsafe_password_form"]);
    const orange = new Set(["external_sign_in", "domain_spelling", "unexpected_destination", "http_start"]);
    const warnings = remaining.filter((reason) => red.has(reason.id));
    const cautions = remaining.filter((reason) => orange.has(reason.id));
    const coverage = {...value.coverage};
    if (!fresh("community")) coverage.community_feed = "unavailable";
    if (!fresh("reputation")) coverage.optional_reputation = "unavailable";
    const gap = {id: "expired_list", title: "Warning-list result expired", detail: "Run a new check for current list data.", source: "coverage"};
    if (warnings.length || cautions.length) return {
      ...value, status: warnings.length ? "warning" : "caution", tone: warnings.length ? "red" : "orange",
      label: warnings.length ? "Warning found" : "Check before continuing",
      summary: "The recorded warning still needs attention. Some list data has expired.",
      reasons: [...warnings, ...cautions, gap].slice(0, 3), coverage,
      next_action: warnings.length ? "Avoid signing in or paying. Use a trusted address." : "Confirm the destination before entering personal information.",
    };
    return {...value, status: "unknown", tone: "gray", label: "Check this link again",
      summary: "The warning-list result has expired.",
      reasons: [gap, ...remaining.filter((reason) => !["community", "reputation"].includes(reason.source))].slice(0, 3),
      next_action: "Run a new check for a current result.", coverage};
  }
  return {visitor};
})();

if (typeof module !== "undefined" && module.exports) module.exports = VerifactReportView;
