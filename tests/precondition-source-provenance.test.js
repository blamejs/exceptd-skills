"use strict";

/**
 * Regression suite for precondition_check_source provenance accuracy.
 *
 * Before the fix, a CLI `run` reported EVERY precondition as "merged" because
 * the CLI copied the submission's precondition_checks into runOpts (the value
 * then appeared in both the submission and runOpts maps). And an
 * engine-auto-detected precondition was mislabeled "submission". Now:
 *   - a submission-supplied precondition → "submission"
 *   - an engine-auto-detected precondition → "auto"
 *   - (engine-level) a value in both submission and runOpts → "merged"
 * Gating is unchanged — preconditions still block correctly.
 *
 * Discipline: exact provenance value assertions + a gating guard.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-pcsource-"));

test("a submission-supplied precondition reports provenance 'submission' (not 'merged')", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], {
    input: JSON.stringify({ precondition_checks: { "repo-context": true }, signal_overrides: { "aws-access-key-id": "hit" } }),
  });
  const j = tryJson(r.stdout);
  assert.ok(j && j.precondition_check_source, "must surface precondition_check_source");
  assert.equal(j.precondition_check_source["repo-context"], "submission",
    "an operator-submitted precondition must be tagged submission, not merged");
});

test("an engine-auto-detected precondition reports provenance 'auto' (not 'submission')", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "hit" } }),
  });
  const j = tryJson(r.stdout);
  const src = j.precondition_check_source || {};
  // repo-context (cwd readability) is auto-detected by the engine when not submitted.
  assert.ok("repo-context" in src, "the auto-detected precondition must appear");
  assert.equal(src["repo-context"], "auto",
    "an engine-auto-detected precondition must be tagged auto, not submission");
});

test("gating is unchanged: a false halt precondition still blocks the run", () => {
  const r = cli(["run", "kernel", "--evidence", "-", "--json"], {
    input: JSON.stringify({ precondition_checks: { "linux-platform": false } }),
  });
  const j = tryJson(r.stdout);
  assert.equal(j.verdict, "blocked", "a false halt precondition must still block");
  assert.equal(j.blocked_by, "precondition");
});

test("engine-level: a precondition in both the submission and runOpts is still 'merged'", () => {
  // Direct runner call (the programmatic-override path the CLI never produces):
  // the same key in both maps is a genuine merge.
  const runner = require("../lib/playbook-runner");
  const res = runner.run("secrets", "full-repo-secret-scan",
    { precondition_checks: { "repo-context": true }, signal_overrides: {} },
    { precondition_checks: { "repo-context": true }, force_replay: true });
  assert.ok(res, "run must return a result");
  if (res.precondition_check_source) {
    assert.equal(res.precondition_check_source["repo-context"], "merged",
      "submission ∩ runOpts is a genuine merge");
  }
});
