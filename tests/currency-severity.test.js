"use strict";

/**
 * tests/currency-severity.test.js
 *
 * Subject: lib/currency-severity.js — the doctor's currency verdict.
 *
 * The regression these pin: `doctor` used to fail on any skill whose
 * currency_label was not exactly "current". A skill's label drops from
 * "current" to "acceptable" the day it crosses 90 days since its
 * last_threat_review, so the health check was a scheduled failure — it went
 * red on a fixed cadence with no code change and nothing wrong, and took the
 * suite down with it.
 *
 * The boundary cases below are driven through the real scoring model
 * (_skillCurrencyRow) rather than hand-written labels, so a change to the
 * penalty schedule that moves the tier boundary fails here instead of
 * silently re-arming the same failure.
 */

const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");

const { classifyCurrency } = require(path.join(__dirname, "..", "lib", "currency-severity.js"));
const { bucketChecks } = require(path.join(__dirname, "..", "lib", "doctor-bucketing.js"));
const { _skillCurrencyRow } = require(path.join(__dirname, "..", "orchestrator", "pipeline.js"));

// A fixed reference date keeps every case deterministic — the row's day count
// is computed from (now - last_threat_review), so both sides must be pinned.
const NOW = new Date("2026-08-05T00:00:00Z");

/** Build a real currency row for a skill last reviewed `days` ago. */
function rowAtAge(name, days) {
  const reviewed = new Date(NOW.getTime() - days * 86400000);
  return _skillCurrencyRow(
    { name, last_threat_review: reviewed.toISOString().slice(0, 10) },
    NOW
  );
}

test("currency-severity: an all-current report is healthy with no severity", () => {
  const rows = [rowAtAge("a", 1), rowAtAge("b", 30), rowAtAge("c", 89)];
  const v = classifyCurrency(rows, false);
  assert.equal(v.ok, true);
  assert.equal(v.severity, null);
  assert.deepEqual(v.drifting, []);
  assert.deepEqual(v.actionable, []);
});

test("currency-severity: day 90 is still 'current' — the last healthy day", () => {
  const row = rowAtAge("edge", 90);
  assert.equal(row.days_since_review, 90);
  assert.equal(row.currency_label, "current");
  const v = classifyCurrency([row], false);
  assert.equal(v.ok, true);
  assert.equal(v.severity, null);
});

test("currency-severity: day 91 drifts to 'acceptable' and WARNS — it must not fail", () => {
  // This is the exact transition that turned the health check red. The tier
  // is real (drawn from the scoring model), not asserted from a literal.
  const row = rowAtAge("drifter", 91);
  assert.equal(row.days_since_review, 91);
  assert.equal(row.currency_label, "acceptable");
  assert.equal(row.action_required, false);

  const v = classifyCurrency([row], false);
  assert.equal(v.ok, true, "an acceptable-tier skill must not fail the health check");
  assert.equal(v.severity, "warn");
  assert.equal(v.drifting.length, 1);
  assert.equal(v.drifting[0].skill, "drifter");
  assert.equal(v.actionable.length, 0);
});

test("currency-severity: the whole acceptable tier (91-180 days) warns, never fails", () => {
  for (const days of [91, 120, 150, 180]) {
    const row = rowAtAge(`d${days}`, days);
    assert.equal(row.currency_label, "acceptable", `${days}d must be acceptable`);
    const v = classifyCurrency([row], false);
    assert.equal(v.ok, true, `${days}d must not fail`);
    assert.equal(v.severity, "warn", `${days}d must warn`);
  }
});

test("currency-severity: past the review window (>180 days) is a hard error", () => {
  const row = rowAtAge("abandoned", 181);
  assert.equal(row.currency_label, "stale");
  assert.equal(row.action_required, true);

  const v = classifyCurrency([row], true);
  assert.equal(v.ok, false, "a skill past its review window must still fail");
  assert.equal(v.severity, null, "an error must not be downgraded to a warning");
  assert.equal(v.actionable.length, 1);
  assert.equal(v.drifting.length, 0);
});

test("currency-severity: a critical_stale skill fails and is counted critical", () => {
  const row = rowAtAge("dead", 400);
  assert.equal(row.currency_label, "critical_stale");
  assert.equal(row.currency_score < 50, true);

  const v = classifyCurrency([row], true);
  assert.equal(v.ok, false);
  assert.equal(v.severity, null);
  assert.equal(v.critical.length, 1);
});

test("currency-severity: a mixed report fails on the actionable skill, not the drifting one", () => {
  const rows = [rowAtAge("fine", 10), rowAtAge("drifting", 100), rowAtAge("overdue", 300)];
  const v = classifyCurrency(rows, true);
  assert.equal(v.ok, false);
  assert.equal(v.severity, null);
  assert.deepEqual(v.drifting.map(r => r.skill), ["drifting"]);
  assert.deepEqual(v.actionable.map(r => r.skill), ["overdue"]);
  // stale_skills keeps its original meaning — every non-current skill.
  assert.deepEqual(v.stale.map(r => r.skill).sort(), ["drifting", "overdue"]);
});

test("currency-severity: report-level action_required fails closed even with clean rows", () => {
  // An upstream that raises the flag without marking a row must not pass.
  const v = classifyCurrency([rowAtAge("fine", 5)], true);
  assert.equal(v.ok, false);
  assert.equal(v.severity, null);
});

test("currency-severity: a malformed report degrades without throwing", () => {
  for (const bad of [null, undefined, "nope", 42, [null, "x", 7]]) {
    const v = classifyCurrency(bad, false);
    assert.equal(v.ok, true);
    assert.equal(v.severity, null);
    assert.equal(Array.isArray(v.stale), true);
  }
});

// ---------------------------------------------------------------------------
// Integration with the bucketing layer: the verdict must land in the bucket
// that drives the exit code. A warn that buckets as an error would reproduce
// the original failure one layer down.
// ---------------------------------------------------------------------------

test("currency-severity: the drift verdict buckets to warnings, keeping the exit code 0", () => {
  const v = classifyCurrency([rowAtAge("drifter", 100)], false);
  const check = { ok: v.ok, ...(v.severity ? { severity: v.severity } : {}) };
  const { warnList, errorList } = bucketChecks({ currency: check });
  assert.deepEqual(warnList, ["currency"]);
  assert.deepEqual(errorList, []);
  // The doctor's exit predicate is `errorList.length > 0`.
  assert.equal(errorList.length > 0, false);
});

test("currency-severity: the overdue verdict buckets to errors, forcing exit 1", () => {
  const v = classifyCurrency([rowAtAge("overdue", 300)], true);
  const check = { ok: v.ok, ...(v.severity ? { severity: v.severity } : {}) };
  const { warnList, errorList } = bucketChecks({ currency: check });
  assert.deepEqual(warnList, []);
  assert.deepEqual(errorList, ["currency"]);
  assert.equal(errorList.length > 0, true);
});
