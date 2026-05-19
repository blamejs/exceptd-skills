#!/usr/bin/env node
"use strict";
/**
 * scripts/check-catalog-gap-budget.js
 *
 * Predeploy / CI gate that runs the v0.13.21 extended gap detectors
 * and asserts no class exceeds its budget. Mirrors the budget in
 * tests/shipped-catalog-integrity.test.js but runs as a standalone
 * predeploy gate so the check is visible in the gate summary even
 * when the broader test suite is skipped (or is the gate that's
 * failing for an unrelated reason).
 *
 * Exit codes:
 *   0 — every extended class within budget
 *   1 — at least one class regressed
 *   2 — internal error
 *
 * The budget is intentionally duplicated (here + integrity test) for
 * fail-loud-at-two-levels. Operators see the regression in BOTH the
 * test-suite output AND the predeploy gate-summary table.
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

// Per-class regression budgets. Kept in sync with the canonical version
// in tests/shipped-catalog-integrity.test.js.
const BUDGET = {
  "content-quality": 12,
  "temporal-staleness": 260,
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
  if (regressions.length > 0) {
    console.error("\n[check-catalog-gap-budget] REGRESSION beyond budget:");
    for (const r of regressions) {
      console.error(`  ${r.class}: actual=${r.actual} > budget=${r.allowed} (delta +${r.delta})`);
    }
    console.error("\nClose the gap in this PR (preferred) or update BUDGET in both:");
    console.error("  scripts/check-catalog-gap-budget.js");
    console.error("  tests/shipped-catalog-integrity.test.js");
    process.exit(1);
  }
  console.log("[check-catalog-gap-budget] all classes within budget.");
}

main();
