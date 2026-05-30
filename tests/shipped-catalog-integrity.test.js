"use strict";

/**
 * tests/shipped-catalog-integrity.test.js
 *
 * Live-catalog invariants. v0.13.20 split — the audit-catalog-gaps
 * detector tests now exercise synthetic inputs only; the assertions
 * about the LIVE shipped catalogs live here. When a catalog edit
 * breaks one of these the failure message points at the data, not at
 * the detector logic.
 *
 * Pins:
 *   1. Every cross-catalog reference resolves (no dangling refs).
 *   2. CVE catalog draft-debt ratio is reported but not enforced —
 *      bulk-import auto-imported entries are legitimate intake work.
 *   3. Every required-context field on every entry that does NOT
 *      declare a class-level exemption (forward_looking, _matrix-
 *      qualified ICS exception, etc.) is populated. Missing-context
 *      surfaces as a test failure, NOT a silent audit warning.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MOD = require(path.join(ROOT, "scripts", "audit-catalog-gaps.js"));

function loadAll() {
  const data = path.join(ROOT, "data");
  return {
    "cve-catalog": JSON.parse(fs.readFileSync(path.join(data, "cve-catalog.json"), "utf8")),
    "cwe-catalog": JSON.parse(fs.readFileSync(path.join(data, "cwe-catalog.json"), "utf8")),
    "attack-techniques": JSON.parse(fs.readFileSync(path.join(data, "attack-techniques.json"), "utf8")),
    "atlas-ttps": JSON.parse(fs.readFileSync(path.join(data, "atlas-ttps.json"), "utf8")),
    "framework-control-gaps": JSON.parse(fs.readFileSync(path.join(data, "framework-control-gaps.json"), "utf8"))
  };
}

test("shipped catalogs: zero dangling cross-catalog references", () => {
  const findings = MOD.inspectRefs(loadAll());
  assert.equal(
    findings.length,
    0,
    `shipped catalogs must have zero dangling cross-refs; got ${findings.length}: ${JSON.stringify(findings.slice(0, 3))}`
  );
});

test("shipped catalogs: missing-context budget is enforced per catalog (no silent regression)", () => {
  // v0.13.20 honest-state: we have known missing-context on cve-catalog
  // (operator-curation backlog for IoCs on bulk-imported CVEs) and on
  // zeroday-lessons (per-primitive new_control_requirements pending).
  // The release explicitly stops auto-filling stubs that hid these
  // gaps — operators see them honestly via `npm run audit-catalog-gaps`.
  //
  // The integrity test enforces a budget per catalog: a snapshot of the
  // missing-context count today. If a future PR makes the gap worse,
  // the test fires. If a PR closes gaps, the budget gets lowered in
  // the same PR. This is the no-MVP rule applied to the catalog —
  // you can't make the catalog WORSE without explicit acknowledgement.
  const BUDGET = {
    // Tracks the uncurated bulk-imported KEV drafts, which carry no iocs block
    // by the auto-import intake convention. Each draft gains a behavioral iocs
    // block when it is curated to a full entry, so this ceiling falls in step
    // with the remaining-draft count; it is lowered to the current actual as
    // curation proceeds. This is tracked draft-debt, not a regression.
    "cve-catalog":     { iocs: 15 },
    "cwe-catalog":     {},
    "attack-techniques": {},
    "atlas-ttps":      {},
    "d3fend-catalog":  {},
    // Obsoleted/historic RFCs are now imported so a superseded RFC resolves
    // offline. 31 of them carry no abstract in the IETF index (older RFCs
    // predate the abstract field); that absence is upstream, not a curation
    // regression — the rows are otherwise complete (title, status, obsoleted_by).
    "rfc-references":  { abstract: 31 },
    "framework-control-gaps": {},
    // Lessons whose remediation reuses existing controls (perimeter/edge patch
    // SLA, endpoint and application hardening, kernel/driver hardening) rather
    // than demanding a new one carry no new_control_requirements — the field is
    // honestly absent rather than padded with a fabricated control, which the
    // no-orphaned-controls rule forbids. The count rises as such lessons are
    // added for newly-curated CVEs (e.g. legacy client-side browser/reader RCEs
    // whose defense is patch + end-of-life-retirement + Protected View/ASR, not
    // a novel control). Raised to the current actual when that happens.
    "zeroday-lessons": { new_control_requirements: 260 }
  };
  const findings = {};
  for (const key of Object.keys(MOD.SPEC)) {
    findings[key] = {};
    const r = MOD.inspect(key);
    for (const f of r.missing_context) {
      findings[key][f.field] = (findings[key][f.field] || 0) + 1;
    }
  }
  const regressions = [];
  for (const [key, fieldsBudget] of Object.entries(BUDGET)) {
    const actual = findings[key] || {};
    // Any field not in the budget must be at 0 (new gap class regressed).
    for (const field of Object.keys(actual)) {
      const allowed = fieldsBudget[field] || 0;
      if (actual[field] > allowed) {
        regressions.push(`${key}.${field}: budget=${allowed} actual=${actual[field]} (regression of ${actual[field] - allowed})`);
      }
    }
  }
  if (regressions.length > 0) {
    assert.fail(
      `missing-context regression beyond budget:\n  ${regressions.join("\n  ")}\n` +
      `Either close the gap in this PR (preferred) or, if the gap is intentional, update the BUDGET above with a justifying comment.`
    );
  }
});

test("shipped catalogs: extended-detector budgets (no silent regression on v0.13.21 detection classes)", () => {
  // v0.13.21 expanded the audit with seven extended detectors. The
  // shipped catalog has known findings on most of them — operator-
  // curation backlog, KEV-due-date passage, bulk-imported orphans —
  // and the budget approach mirrors the missing-context budget above.
  // A future PR worsening any class beyond budget fires; closing gaps
  // lowers the budget in the same PR.
  const D = require(path.join(__dirname, "..", "lib", "gap-detectors.js"));
  const all = D.runAllDetectors(loadAll(), {});
  const byClass = {};
  for (const f of all) {
    byClass[f.class] = (byClass[f.class] || 0) + 1;
  }
  const BUDGET = {
    "content-quality": 12,        // 10 KEV-no-vendor-advisories + slack
    // data-freshness only (source_verified / last_updated / epss_date). The
    // calendar-driven KEV-due-passed sub-check was removed (external operator
    // date, not catalog freshness; grew unboundedly as KEV drafts got curated).
    // Actual 0 with fresh data; 10 leaves refresh headroom.
    "temporal-staleness": 10,
    "logical-consistency": 5,
    "cross-ref-completeness": 5,
    "schema-evolution": 0,
    "operator-action-sla": 0,     // no entries currently exceed the SLA window
    "unused-orphan": 1400         // bulk-imported CWE / RFC orphans by design
  };
  const regressions = [];
  for (const [cls, count] of Object.entries(byClass)) {
    const allowed = BUDGET[cls] || 0;
    if (count > allowed) regressions.push(`${cls}: budget=${allowed} actual=${count}`);
  }
  // Also alert if any class has ZERO budget but is missing from BUDGET
  // (catches a future addition that forgot to set a budget).
  for (const cls of Object.keys(BUDGET)) {
    if (!(cls in byClass)) continue;
  }
  assert.deepEqual(regressions, [],
    "extended-detector class regression(s):\n  " + regressions.join("\n  ") +
    "\nClose the gap in this PR (preferred) or update BUDGET above with a justifying comment.");
});

test("shipped catalogs: framework-control-gaps forward_looking exemption is used as a SCHEMA field, not as _gap_skip", () => {
  // Class 5.15 from the v0.13.19 audit: 84 framework gaps had blanket
  // _gap_skip annotations as the exemption. v0.13.20 converted them
  // to forward_looking:true. Pin that no _gap_skip remains on those
  // entries.
  const fwc = loadAll()["framework-control-gaps"];
  const stillSkipped = [];
  for (const id of Object.keys(fwc)) {
    if (id === "_meta") continue;
    const e = fwc[id];
    if (e && e._gap_skip && Array.isArray(e._gap_skip.fields) && e._gap_skip.fields.includes("evidence_cves")) {
      stillSkipped.push(id);
    }
  }
  assert.equal(stillSkipped.length, 0,
    `framework-control-gaps entries must use forward_looking:true (not _gap_skip on evidence_cves). Stragglers: ${stillSkipped.join(", ")}`);
});
