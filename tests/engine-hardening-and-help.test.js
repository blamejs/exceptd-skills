"use strict";

/**
 * Regression suite for an engine-hardening + UX cluster:
 *
 *   Deeply-nested evidence overflowed the stack (canonicalStringify recursion
 *     runs on every run via evidence_hash) with an opaque "internal error";
 *     it is now rejected at a bounded depth with an actionable message.
 *   --strict-preconditions missed a false skip_phase precondition (verdict
 *     skipped, exit 0) — a CI gate silently passed. It now fails (exit 1).
 *   A signal_overrides value that doesn't canonicalize (e.g. "maybe") was
 *     silently dropped; it now surfaces a runtime_error.
 *   A not_detected/clean classification override that would bury a
 *     DETERMINISTIC hit is refused (substituted inconclusive) and no longer
 *     reported as classification_override_applied. A probabilistic hit's
 *     confirm-benign override is still honored.
 *   run --all swallowed a mid-batch session-id collision (exit 0); it now
 *     surfaces exit 7 like the single-run path.
 *   watch --help started the blocking daemon (hung the terminal); collect
 *     --help had no content. Both now print usage.
 *
 * Discipline: exact exit codes; value + type assertions.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-enginehard-"));

test("deeply-nested evidence is rejected with an actionable message, not a stack overflow", () => {
  let o = { x: 1 };
  for (let i = 0; i < 3000; i++) o = { n: o };
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": o } }) });
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body && body.ok === false, "must reject, not crash");
  assert.match(body.error, /nesting exceeds the maximum depth/, "must name the depth limit");
});

test("--strict-preconditions fails (exit 1) on a false skip_phase precondition", () => {
  const r = cli(["run", "mcp", "--evidence", "-", "--strict-preconditions", "--json"],
    { input: JSON.stringify({ precondition_checks: { "any-ai-coding-assistant-installed": false } }) });
  assert.equal(r.status, 1, "a false skip precondition under --strict-preconditions must fail");
  const body = tryJson(r.stdout);
  assert.ok(body && Array.isArray(body.strict_preconditions_violated), "must surface the violation list");
  assert.ok(body.strict_preconditions_violated.some(v => v.kind === "precondition_skip"), "the skip must be in the violation list");
});

test("an unrecognized signal_overrides value surfaces a runtime_error (not silently dropped)", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "maybe" } }) });
  const j = tryJson(r.stdout);
  const kinds = (j.phases.analyze.runtime_errors || []).map(e => e.kind);
  assert.ok(kinds.includes("signal_override_unrecognized"), `expected signal_override_unrecognized; got ${JSON.stringify(kinds)}`);
});

test("a not_detected override is refused when it would mask a deterministic hit", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "hit" }, signals: { detection_classification: "not_detected" } }) });
  const j = tryJson(r.stdout);
  assert.equal(j.phases.analyze._detect_classification, "inconclusive", "deterministic hit must not be downgraded to not_detected");
  assert.equal(j.phases.detect.classification_override_applied, null, "a refused override must not be reported as applied");
  const kinds = (j.phases.analyze.runtime_errors || []).map(e => e.kind);
  assert.ok(kinds.includes("classification_override_masks_deterministic_hit"), "must explain the refusal");
});

test("a probabilistic hit's not_detected confirm-benign override is still honored", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "jwt-token-with-secret-context": "hit" }, signals: { detection_classification: "not_detected" } }) });
  const j = tryJson(r.stdout);
  assert.equal(j.phases.analyze._detect_classification, "not_detected", "a probabilistic hit remains overridable");
  assert.equal(j.phases.detect.classification_override_applied, "not_detected", "the honored override is reported as applied");
});

test("run --all surfaces exit 7 when a reused --session-id collides across the whole batch", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-batchcol-"));
  try {
    const env = { EXCEPTD_HOME: home };
    const first = cli(["run", "--scope", "code", "--evidence", "-", "--session-id", "fixedsid123", "--json"], { input: "{}", env });
    // first run persists; some playbooks may be clean — that's fine.
    assert.ok(first.status === 0 || first.status === 2, `first run should succeed/escalate; got ${first.status}`);
    const second = cli(["run", "--scope", "code", "--evidence", "-", "--session-id", "fixedsid123", "--json"], { input: "{}", env });
    assert.equal(second.status, 7, "a batch re-run with a reused session-id must exit 7 (session-id collision), not 0");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("watch --help prints usage and exits 0 (does not start the blocking daemon)", () => {
  const r = cli(["watch", "--help"], { timeout: 8000 });
  assert.equal(r.status, 0, "watch --help must exit 0, not hang");
  assert.match(r.stdout, /forward-watch daemon/i, "must describe the daemon");
  assert.match(r.stdout, /watchlist/, "must point at watchlist for the one-shot aggregator");
});

test("collect --help prints usage (not 'no per-verb help available')", () => {
  const r = cli(["collect", "--help"]);
  assert.match(r.stdout, /collect <playbook>/, "must show the collect synopsis");
  assert.doesNotMatch(r.stdout, /no per-verb help available/, "must not fall back to the no-help message");
});
