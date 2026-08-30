#!/usr/bin/env node
"use strict";
/**
 * Predeploy gate: runs the gap detectors and asserts no class exceeds its
 * budget. Exit 0 within budget, 1 regressed, 2 internal error.
 *
 * The budget is duplicated in tests/shipped-catalog-integrity.test.js so a
 * regression shows in both the test output and the gate-summary table, and so
 * the gate still reports when the suite is skipped or failing elsewhere. Both
 * copies move together.
 */

const path = require("path");
const fs = require("fs");
const ROOT = path.join(__dirname, "..");

let D;
try {
  D = require(path.join(ROOT, "lib", "gap-detectors.js"));
} catch (e) {
  console.error("[check-catalog-gap-budget] failed to load lib/gap-detectors.js:", e.message);
  process.exit(2);
}

function loadAll() {
  const data = path.join(ROOT, "data");
  const read = (name) => JSON.parse(fs.readFileSync(path.join(data, name), "utf8"));
  return {
    "cve-catalog": read("cve-catalog.json"),
    "cwe-catalog": read("cwe-catalog.json"),
    "attack-techniques": read("attack-techniques.json"),
    "atlas-ttps": read("atlas-ttps.json"),
    "d3fend-catalog": read("d3fend-catalog.json"),
    "rfc-references": read("rfc-references.json"),
    "framework-control-gaps": read("framework-control-gaps.json"),
    "zeroday-lessons": read("zeroday-lessons.json")
  };
}

// Per-class regression budgets, mirrored in
// tests/shipped-catalog-integrity.test.js.
const BUDGET = {
  // Five KEV-listed entries whose vendors published no advisory at all. Each
  // absence is control-tested rather than assumed: the Nagios XI changelog
  // names sibling CVE-2021-25299 and none of -25296/-25297/-25298, so the
  // search that finds nothing for those three is working. WinRAR's only vendor
  // reference is a rolling release-notes page that no longer mentions the
  // defect, and Grandstream's advisory paths 404. An entry cannot cite an
  // advisory that does not exist, and inventing a plausible URL would send an
  // operator somewhere authoritative-looking and wrong.
  "content-quality": 14,
  // temporal-staleness counts only the maintainer-controllable freshness fields,
  // which sit at 0 on fresh data; the headroom covers entries aging past a
  // threshold between refreshes.
  "temporal-staleness": 10,
  "logical-consistency": 5,
  "cross-ref-completeness": 5,
  "schema-evolution": 0,
  "operator-action-sla": 0,
  "unused-orphan": 1400
};

function main() {
  const all = D.runAllDetectors(loadAll(), {});
  const byClass = {};
  for (const f of all) byClass[f.class] = (byClass[f.class] || 0) + 1;
  const regressions = [];

  // Fail-closed: a class the detectors emit without a budget entry fires an
  // unbudgeted-class error rather than passing unmeasured.
  const unbudgeted = [];
  for (const cls of Object.keys(byClass)) {
    if (!(cls in BUDGET)) {
      unbudgeted.push({ class: cls, count: byClass[cls] });
    }
  }
  // The inverse: a class declared in DETECTOR_CLASSES needs a budget even when
  // it emits nothing on this run, or the first regression has no cap to hit.
  const missingBudget = [];
  if (Array.isArray(D.DETECTOR_CLASSES)) {
    for (const cls of D.DETECTOR_CLASSES) {
      if (!(cls in BUDGET)) missingBudget.push(cls);
    }
  }

  for (const cls of Object.keys(BUDGET)) {
    const actual = byClass[cls] || 0;
    const allowed = BUDGET[cls];
    if (actual > allowed) {
      regressions.push({ class: cls, allowed, actual, delta: actual - allowed });
    }
  }
  const summary = Object.keys(BUDGET).map((cls) => {
    const actual = byClass[cls] || 0;
    const allowed = BUDGET[cls];
    const mark = actual > allowed ? "✗" : "✓";
    return `  ${mark} ${cls.padEnd(28)} actual=${actual}  budget=${allowed}`;
  }).join("\n");
  console.log("[check-catalog-gap-budget] extended detection classes:");
  console.log(summary);

  if (unbudgeted.length > 0) {
    console.error("\n[check-catalog-gap-budget] UNBUDGETED detector classes — fail-closed:");
    for (const u of unbudgeted) {
      console.error(`  ${u.class}: ${u.count} finding(s), no BUDGET entry`);
    }
    console.error("Add an explicit budget entry in both:");
    console.error("  scripts/check-catalog-gap-budget.js");
    console.error("  tests/shipped-catalog-integrity.test.js");
    process.exitCode = 1; return;
  }
  if (missingBudget.length > 0) {
    console.error("\n[check-catalog-gap-budget] BUDGET missing entries for declared classes:");
    for (const c of missingBudget) console.error(`  ${c}: declared by lib/gap-detectors.js DETECTOR_CLASSES, no BUDGET entry`);
    process.exitCode = 1; return;
  }
  if (regressions.length > 0) {
    console.error("\n[check-catalog-gap-budget] REGRESSION beyond budget:");
    for (const r of regressions) {
      console.error(`  ${r.class}: actual=${r.actual} > budget=${r.allowed} (delta +${r.delta})`);
    }
    console.error("\nClose the gap in this PR (preferred) or update BUDGET in both:");
    console.error("  scripts/check-catalog-gap-budget.js");
    console.error("  tests/shipped-catalog-integrity.test.js");
    process.exitCode = 1; return;
  }
  console.log("[check-catalog-gap-budget] all classes within budget; every class is budgeted.");
}

main();
