"use strict";

/**
 * tests/check-framework-gap-coverage.test.js
 *
 * Subject coverage for the scripts/check-framework-gap-coverage.js predeploy
 * gate (AGENTS.md Hard Rule #5, global-first framework-gap coverage). The
 * script runs main() at load and signals via exit code, so the contract is
 * exercised as a subprocess with the catalog path passed as argv[2]:
 *
 *  - PASS contract (live): against the shipped catalog it exits 0 — every
 *    curated entry must declare all five jurisdiction buckets;
 *  - PASS contract (fixture): a synthetic entry covering NIST/EU/UK/AU/ISO
 *    exits 0;
 *  - FAIL contract: a synthetic entry missing a bucket exits 1 and names the
 *    CVE + the missing bucket;
 *  - draft exemption: a partial _auto_imported entry does NOT fail the gate.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const GATE = path.join(ROOT, "scripts", "check-framework-gap-coverage.js");
const LIVE_CATALOG = path.join(ROOT, "data", "cve-catalog.json");

function run(catalogPath) {
  return spawnSync(process.execPath, [GATE, catalogPath], { encoding: "utf8" });
}

const FULL_GAPS = {
  "NIST-800-53-SI-2": "nist gap",
  "NIS2-Art21-patch-management": "eu gap",
  "UK-CAF-B4": "uk gap",
  "AU-Essential-8-Patch": "au gap",
  "ISO-27001-2022-A.8.8": "iso gap",
};

function writeFixture(map) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-cov-"));
  const p = path.join(dir, "cve-catalog.json");
  fs.writeFileSync(p, JSON.stringify(map, null, 2));
  return p;
}

test("PASS (live): shipped catalog covers every jurisdiction on every curated entry", () => {
  const r = run(LIVE_CATALOG);
  assert.equal(r.status, 0, `gate failed on live catalog:\n${r.stdout}`);
  assert.match(r.stdout, /all \d+ curated entries declare framework-gap coverage/);
});

test("PASS (fixture): a full five-bucket entry exits 0", () => {
  const p = writeFixture({ _meta: {}, "CVE-2024-0001": { framework_control_gaps: FULL_GAPS } });
  const r = run(p);
  assert.equal(r.status, 0, r.stdout);
});

test("FAIL: an entry missing a bucket exits 1 and names it", () => {
  const partial = { ...FULL_GAPS };
  delete partial["AU-Essential-8-Patch"];
  const p = writeFixture({ _meta: {}, "CVE-2024-0002": { framework_control_gaps: partial } });
  const r = run(p);
  assert.equal(r.status, 1, "gate must fail when a bucket is missing");
  assert.match(r.stdout, /CVE-2024-0002: missing AU/);
});

test("draft exemption: a partial _auto_imported entry does not fail the gate", () => {
  const partial = { ...FULL_GAPS };
  delete partial["UK-CAF-B4"];
  const p = writeFixture({
    _meta: {},
    "CVE-2024-0003": { _auto_imported: true, framework_control_gaps: partial },
  });
  const r = run(p);
  assert.equal(r.status, 0, "draft entries are exempt from the coverage gate");
});
