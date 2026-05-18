"use strict";

/**
 * tests/doctor-bucketing.test.js
 *
 * v0.13.11 regression pin for the doctor checks-to-buckets rule.
 *
 * Pre-fix bug: a check with `{ ok: false, severity: "warn" }` (e.g. the
 * signing-status check on a non-contributor install, where `.keys/private.pem`
 * is absent and the operator is being nudged to enable signing rather than
 * blocked from a release) was bucketed into `failed_checks` because the
 * `ok === false` branch fired before the `severity === "warn"` branch.
 * A fresh global `npm install -g @blamejs/exceptd-skills` would then
 * print `all_green: false`, `issues_count: 1`, `failed_checks: ["signing"]`,
 * `warnings_count: 0` — directly contradicting the `[!! warn]` icon shown
 * in the human text-mode output.
 *
 * Post-fix: severity wins. `severity === "warn"` always routes to
 * `warning_checks`, regardless of `ok`.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { bucketChecks } = require(path.join(__dirname, "..", "lib", "doctor-bucketing.js"));

test("doctor-bucketing: severity warn + ok false routes to warnList (not errorList)", () => {
  const checks = {
    signing: { ok: false, severity: "warn", private_key_present: false },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["signing"],
    "ok:false + severity:warn must be a warning, not a failure");
  assert.deepEqual(errorList, [],
    "no errors expected when only severity-warn checks are present");
});

test("doctor-bucketing: ok false without severity warn routes to errorList", () => {
  const checks = {
    signatures: { ok: false, exit_code: 1 },
    cves: { ok: false, error: "catalog unreadable" },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, []);
  assert.deepEqual(errorList.sort(), ["cves", "signatures"]);
});

test("doctor-bucketing: ok true with no severity routes to neither bucket (green)", () => {
  const checks = {
    signatures: { ok: true, skills_passed: 42, skills_total: 42 },
    currency: { ok: true, total_skills: 42 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, []);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: severity warn + ok true also routes to warnList", () => {
  // Some checks are advisory: they may set severity:warn while still
  // returning ok:true (e.g. a soft "consider upgrading" hint). These
  // belong in the warning bucket.
  const checks = {
    catalog_freshness: { ok: true, severity: "warn", days_since_refresh: 75 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["catalog_freshness"]);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: mixed input partitions correctly into both buckets", () => {
  const checks = {
    signatures: { ok: true },
    cves: { ok: false, error: "catalog missing" },
    signing: { ok: false, severity: "warn", private_key_present: false },
    currency: { ok: true, severity: "warn", days_since_refresh: 95 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList.sort(), ["currency", "signing"]);
  assert.deepEqual(errorList, ["cves"]);
});

test("doctor-bucketing: tolerates null / non-object check values without throwing", () => {
  // Defensive: a future check that fails to populate its slot must not
  // crash the bucketing. assert: ignored entries don't appear in either
  // bucket and no exception escapes.
  const checks = {
    legit: { ok: false, severity: "warn" },
    busted: null,
    also_busted: "not-an-object",
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["legit"]);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: empty input returns empty buckets (no exception)", () => {
  assert.deepEqual(bucketChecks({}), { warnList: [], errorList: [] });
  assert.deepEqual(bucketChecks(null), { warnList: [], errorList: [] });
  assert.deepEqual(bucketChecks(undefined), { warnList: [], errorList: [] });
});
