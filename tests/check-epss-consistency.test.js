"use strict";

/**
 * tests/check-epss-consistency.test.js
 *
 * Subject coverage for the scripts/check-epss-consistency.js predeploy gate.
 * The gate proves, without network access, that each entry's epss_score and
 * epss_percentile were taken from the same EPSS publication — the percentile is
 * the score's rank within its day, so a cohort sorted by score must come out
 * sorted by percentile.
 *
 *  - PASS contract (live): the shipped catalog exits 0;
 *  - PASS contract (fixture): a consistent cohort exits 0;
 *  - FAIL contract: a stale-percentile pair exits 1 and names both CVEs;
 *  - rounding tolerance: a sub-1e-3 inversion is published rounding, not drift;
 *  - half-populated pair: score without percentile fails and names the field;
 *  - cohort isolation: entries from different dates are never compared;
 *  - no-EPSS entries are ignored rather than treated as violations.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-epss-consistency.js");
const { ROUNDING_TOLERANCE } = require(SCRIPT);

function runGate(catalog) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "epss-gate-"));
  const file = path.join(dir, "catalog.json");
  try {
    fs.writeFileSync(file, JSON.stringify(catalog, null, 2));
    const r = spawnSync(process.execPath, [SCRIPT, file], { encoding: "utf8" });
    return { status: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function entry(score, percentile, date) {
  return { epss_score: score, epss_percentile: percentile, epss_date: date };
}

test("the shipped catalog's EPSS pairs are internally consistent", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout || ""}${r.stderr || ""}`);
  assert.match(r.stdout, /every cohort ranks monotonically/);
});

test("a cohort whose percentiles track its scores passes", () => {
  const r = runGate({
    "CVE-2026-0001": entry(0.1, 0.5, "2026-08-07"),
    "CVE-2026-0002": entry(0.4, 0.8, "2026-08-07"),
    "CVE-2026-0003": entry(0.9, 0.99, "2026-08-07"),
  });
  assert.equal(r.status, 0, r.out);
});

test("a percentile left behind from an earlier publication fails and names both CVEs", () => {
  // 0001 scores lower but ranks higher — impossible within one publication.
  const r = runGate({
    "CVE-2026-0001": entry(0.013, 0.926, "2026-08-07"),
    "CVE-2026-0002": entry(0.5, 0.6, "2026-08-07"),
  });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /CVE-2026-0001/);
  assert.match(r.out, /CVE-2026-0002/);
  assert.match(r.out, /different publications/);
});

test("an inversion smaller than published rounding is not reported as drift", () => {
  // EPSS publishes five decimals, so adjacent ranks can invert by a hair.
  const r = runGate({
    "CVE-2026-0001": entry(0.20001, 0.70002, "2026-08-07"),
    "CVE-2026-0002": entry(0.20002, 0.70001, "2026-08-07"),
  });
  assert.equal(r.status, 0, r.out);
});

test("an inversion just past the tolerance IS reported", () => {
  const gap = ROUNDING_TOLERANCE * 10;
  const r = runGate({
    "CVE-2026-0001": entry(0.2, 0.7, "2026-08-07"),
    "CVE-2026-0002": entry(0.3, 0.7 - gap, "2026-08-07"),
  });
  assert.equal(r.status, 1, r.out);
});

test("a score written without its percentile fails and names the missing field", () => {
  const r = runGate({
    "CVE-2026-0001": { epss_score: 0.42, epss_date: "2026-08-07" },
  });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /epss_percentile/);
  assert.match(r.out, /CVE-2026-0001/);
});

test("a percentile written without its score fails and names the missing field", () => {
  const r = runGate({
    "CVE-2026-0001": { epss_percentile: 0.42, epss_date: "2026-08-07" },
  });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /epss_score/);
});

test("entries from different publications are never compared against each other", () => {
  // Across dates the whole distribution shifts, so this ordering is normal.
  const r = runGate({
    "CVE-2026-0001": entry(0.9, 0.99, "2026-08-07"),
    "CVE-2026-0002": entry(0.1, 0.2, "2026-08-07"),
    "CVE-2026-0003": entry(0.95, 0.5, "2026-01-01"),
  });
  assert.equal(r.status, 0, r.out);
});

test("entries carrying no EPSS data at all are ignored", () => {
  const r = runGate({
    "CVE-2026-0001": entry(0.1, 0.5, "2026-08-07"),
    "CVE-2026-0002": { cvss_score: 9.8 },
  });
  assert.equal(r.status, 0, r.out);
});

test("cohorts() groups by publication date and separates half-populated pairs", () => {
  const { cohorts } = require(SCRIPT);
  const { groups, incomplete } = cohorts({
    "CVE-2026-0001": entry(0.1, 0.5, "2026-08-07"),
    "CVE-2026-0002": entry(0.2, 0.6, "2026-08-07"),
    "CVE-2026-0003": entry(0.3, 0.7, "2026-01-01"),
    "CVE-2026-0004": { epss_score: 0.4 },
    "CVE-2026-0005": { cvss_score: 9.8 },
  });
  assert.equal(groups.size, 2);
  assert.equal(groups.get("2026-08-07").length, 2);
  assert.equal(groups.get("2026-01-01").length, 1);
  assert.deepEqual(incomplete, [{ id: "CVE-2026-0004", missing: "epss_percentile" }]);
});

test("inversions() reports the offending pair and the size of the gap", () => {
  const { inversions } = require(SCRIPT);
  const found = inversions([
    { id: "LOW-SCORE-HIGH-RANK", score: 0.01, percentile: 0.93 },
    { id: "HIGH-SCORE-LOW-RANK", score: 0.9, percentile: 0.5 },
  ]);
  assert.equal(found.length, 1);
  assert.equal(found[0].lower.id, "HIGH-SCORE-LOW-RANK");
  assert.equal(found[0].higher.id, "LOW-SCORE-HIGH-RANK");
  assert.ok(found[0].delta > 0.4, `expected a large gap, got ${found[0].delta}`);
});

test("check() returns the failure list and the corpus size it examined", () => {
  const { check } = require(SCRIPT);
  const live = check(path.join(ROOT, "data", "cve-catalog.json"));
  assert.deepEqual(live.failures, []);
  assert.ok(live.entryCount > 500, `expected the shipped corpus, got ${live.entryCount}`);
  assert.ok(live.cohortCount >= 1);
});

test("a derived note left describing the previous publication is caught", () => {
  const r = runGate({
    "CVE-2026-0001": {
      epss_score: 0.00501,
      epss_percentile: 0.40192,
      epss_date: "2026-08-08",
      epss_note: "FIRST EPSS 0.00125 (31st percentile) as of 2026-05-26.",
    },
  });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /epss_note/);
  assert.match(r.out, /0\.00125/);
});

test("a note that restates the current fields passes", () => {
  const { renderNote } = require(SCRIPT);
  const e = { epss_score: 0.00501, epss_percentile: 0.40192, epss_date: "2026-08-08" };
  const r = runGate({ "CVE-2026-0001": { ...e, epss_note: renderNote(e) } });
  assert.equal(r.status, 0, r.out);
});

test("renderNote() picks the ordinal suffix the teens exception requires", () => {
  const { renderNote } = require(SCRIPT);
  const at = (p) => renderNote({ epss_score: 0.5, epss_percentile: p, epss_date: "2026-08-08" });
  assert.match(at(0.11), /11th percentile/);
  assert.match(at(0.12), /12th percentile/);
  assert.match(at(0.13), /13th percentile/);
  assert.match(at(0.21), /21st percentile/);
  assert.match(at(0.22), /22nd percentile/);
  assert.match(at(0.23), /23rd percentile/);
  assert.match(at(0.4), /40th percentile/);
});
