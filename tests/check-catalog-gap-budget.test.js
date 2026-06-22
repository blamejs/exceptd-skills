"use strict";

/**
 * tests/check-catalog-gap-budget.test.js
 *
 * Subject coverage for the scripts/check-catalog-gap-budget.js predeploy gate.
 * The script has no exported pure functions (it runs main() at module load and
 * signals via exit code), so the contract is exercised as a subprocess:
 *
 *  - PASS contract: against the LIVE catalogs it exits 0 and prints the
 *    within-budget summary (the shipped tree must always pass this gate);
 *  - PASS contract (isolated): a copy of the gate driven against an empty
 *    synthetic catalog tree (zero findings) exits 0;
 *  - FAIL contract: the same copy driven against a catalog tree engineered to
 *    overflow a class budget exits 1 and names the regressed class — proving
 *    the gate actually fails when a class regresses, not just that it passes.
 *
 * The copy preserves the scripts/ + lib/ relative layout the script's
 * `path.join(__dirname, "..")` ROOT and `require("../lib/gap-detectors.js")`
 * resolution depend on. No tracked repo file is mutated.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const GATE = path.join(ROOT, "scripts", "check-catalog-gap-budget.js");

// All 8 catalogs the gate's loadAll() reads.
const CATALOG_FILES = [
  "cve-catalog.json", "cwe-catalog.json", "attack-techniques.json",
  "atlas-ttps.json", "d3fend-catalog.json", "rfc-references.json",
  "framework-control-gaps.json", "zeroday-lessons.json",
];

function run(scriptPath) {
  return spawnSync(process.execPath, [scriptPath], { encoding: "utf8" });
}

// Stand up an isolated copy of the gate with the scripts/ + lib/ layout it
// resolves against, plus a `data/` dir populated with the given catalog map.
function stageGate(dataMap) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-gap-budget-"));
  fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(dir, "lib"), { recursive: true });
  fs.mkdirSync(path.join(dir, "data"), { recursive: true });
  fs.copyFileSync(GATE, path.join(dir, "scripts", "check-catalog-gap-budget.js"));
  fs.copyFileSync(
    path.join(ROOT, "lib", "gap-detectors.js"),
    path.join(dir, "lib", "gap-detectors.js")
  );
  for (const name of CATALOG_FILES) {
    const content = dataMap[name] != null ? dataMap[name] : { _meta: {} };
    fs.writeFileSync(path.join(dir, "data", name), JSON.stringify(content));
  }
  return dir;
}

test("PASS contract: the gate exits 0 against the live shipped catalogs", () => {
  const r = run(GATE);
  assert.equal(r.status, 0, `live gate must pass\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /within budget/);
  // Every declared class line is rendered (no asymmetric absent-class skip).
  assert.match(r.stdout, /content-quality/);
  assert.match(r.stdout, /unused-orphan/);
});

test("PASS contract (isolated): empty catalogs -> zero findings -> exit 0", () => {
  const dir = stageGate({}); // all catalogs default to { _meta: {} }
  try {
    const r = run(path.join(dir, "scripts", "check-catalog-gap-budget.js"));
    assert.equal(r.status, 0, `empty-catalog gate must pass\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /within budget/);
    // No regression / unbudgeted / missing-budget banner.
    assert.doesNotMatch(r.stdout + r.stderr, /REGRESSION beyond budget/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("FAIL contract: a class over budget exits 1 and names the regressed class", () => {
  // 13 CVEs with a sub-50-char `vector` each -> 13 content-quality findings,
  // which exceeds the content-quality budget of 12.
  const cve = { _meta: {} };
  for (let i = 0; i < 13; i++) {
    cve["CVE-2020-" + (1000 + i)] = { name: "n" + i, vector: "short", cvss_score: 5 };
  }
  const dir = stageGate({ "cve-catalog.json": cve });
  try {
    const r = run(path.join(dir, "scripts", "check-catalog-gap-budget.js"));
    assert.equal(r.status, 1, `an over-budget class must fail the gate (exit 1)\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /REGRESSION beyond budget/);
    assert.match(r.stderr, /content-quality/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the regression line reports actual > budget for the offending class", () => {
  const cve = { _meta: {} };
  for (let i = 0; i < 14; i++) {
    cve["CVE-2019-" + (2000 + i)] = { name: "x" + i, vector: "tiny", cvss_score: 7 };
  }
  const dir = stageGate({ "cve-catalog.json": cve });
  try {
    const r = run(path.join(dir, "scripts", "check-catalog-gap-budget.js"));
    assert.equal(r.status, 1);
    // The detail line shape: "content-quality: actual=14 > budget=12".
    assert.match(r.stderr, /content-quality: actual=14 > budget=12/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
