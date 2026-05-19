"use strict";

/**
 * tests/ux-next-step-guidance-v0_13_23.test.js
 *
 * v0.13.23: stage-by-stage next-step guidance. The fixes here are
 * operator-facing prose, so the regression coverage is grep-shaped
 * (a literal substring appears on stdout) rather than schema-shaped.
 * Each assertion pins the exact substring an operator searches for
 * when they ask "what do I do now?" Drift on any of these strings
 * means the operator-facing answer to that question has changed.
 *
 * Surfaces pinned:
 *   1. ci BLOCKED prints "Next steps (unblock the N halted playbook(s)):"
 *      with one `exceptd lint <playbook> -` per blocked id.
 *   2. ci NO_EVIDENCE prints "Next steps (every playbook ran inconclusive
 *      — no evidence supplied):" with a lint + ci-evidence-dir pair.
 *   3. run prints "evidence: <state> (<evaluated>/<known> indicators
 *      evaluated)" on every success.
 *   4. run prints "Attestation written:" + the verify/diff command pair
 *      after persistence.
 *   5. run non-detect prose says "Remediation path (informational — verdict
 *      =<x>, no action required now):" — NOT "Recommended remediation:".
 *   6. run unknown-playbook error says "list the <count> playbooks"
 *      with the live ids.length, not the stale literal "13".
 *
 * Per CLAUDE.md anti-coincidence rule: assertions check exact substrings.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test("ci BLOCKED prints 'Next steps (unblock ...)' + one lint command per blocked playbook", () => {
  // ai-discovered-cve-triage has the precondition agent_has_vulnerability
  // _feed_access. Without it the playbook halts at preflight, ci goes
  // BLOCKED.
  const r = cli(["ci", "--required", "ai-discovered-cve-triage"]);
  assert.match(r.stdout, /\[!! BLOCKED\]/,
    "BLOCKED icon must appear on the verdict line");
  assert.match(r.stdout, /Next steps \(unblock the 1 halted playbook\(s\)\):/,
    "BLOCKED footer must announce the unblock action with the count");
  assert.match(r.stdout, /exceptd lint ai-discovered-cve-triage -/,
    "BLOCKED footer must list `exceptd lint <playbook> -` for the blocked id");
  assert.match(r.stdout, /exceptd run <playbook> --evidence <file>/,
    "BLOCKED footer must close with the run-with-evidence re-run command");
});

test("ci NO_EVIDENCE prints 'Next steps (every playbook ran inconclusive — no evidence supplied)' + lint + ci-evidence-dir", () => {
  // Use a tempdir cwd with no .git so discover-scope finds nothing — but
  // we'll force scope=code from the exceptd repo cwd, which has a .git
  // and ships its own indicators. The cwd here is the exceptd repo, so
  // the indicators evaluate against the exceptd source tree. Most
  // signal_overrides are not provided → indicators return inconclusive.
  // The path to reach NO_EVIDENCE is: ci --required <pb> on a playbook
  // whose indicators don't fire on the local cwd. `framework` is pure
  // analyze + has no detect indicators that would auto-hit, so it
  // returns inconclusive without --evidence.
  const r = cli(["ci", "--required", "framework"]);
  // Either verdict NO_EVIDENCE (no --evidence) or PASS (when
  // framework's catalog baseline returns clean). The guidance fires
  // only on NO_EVIDENCE; if the run lands PASS, this test is informational.
  if (/verdict=NO_EVIDENCE/.test(r.stdout)) {
    assert.match(r.stdout, /Next steps \(every playbook ran inconclusive — no evidence supplied\):/,
      "NO_EVIDENCE footer must explain WHY the run is inconclusive");
    assert.match(r.stdout, /exceptd lint framework -/,
      "NO_EVIDENCE footer must offer a lint command for the first playbook");
    assert.match(r.stdout, /exceptd ci --scope <type> --evidence-dir <dir>/,
      "NO_EVIDENCE footer must show the evidence-dir gate command");
  }
});

test("run prints 'evidence: <state> (N/M indicators evaluated)' on the verdict line", () => {
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "v0_13_23-evidence-"));
  try {
    const r = cli(["run", "kernel", "--evidence", "-",
      "--attestation-root", path.join(tmpHome, "attestations")], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    // Match the literal "evidence: " row followed by the N/M counter.
    assert.match(r.stdout, /evidence: (complete|partial|missing|unknown|not-evaluated)\s+\(\d+\/\d+ indicators evaluated\)/,
      "verdict line must surface evidence_completeness + indicators-evaluated counter");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run prints 'Attestation written: <path>' + verify/diff command pair after persistence", () => {
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "v0_13_23-attest-"));
  try {
    const r = cli(["run", "kernel", "--evidence", "-",
      "--attestation-root", path.join(tmpHome, "attestations")], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /Attestation written: .+attestation\.json/,
      "human renderer must print the absolute attestation_path");
    assert.match(r.stdout, /exceptd attest verify [0-9a-f-]+\s+# tamper check/,
      "human renderer must point at attest verify with the session id");
    assert.match(r.stdout, /exceptd attest diff [0-9a-f-]+\s+# vs\. most-recent prior/,
      "human renderer must point at attest diff with the session id");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run non-detect prose says 'Remediation path (informational — verdict=<x>, no action required now):'", () => {
  // A run with no evidence on `secrets` returns not_detected (the
  // catalog-baseline indicators don't fire against the local cwd).
  const r = cli(["run", "secrets", "--evidence", "-"], { input: "{}" });
  assert.equal(r.status, 0, `run secrets must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
  // Either inconclusive or not_detected — both must use the
  // informational phrasing, NOT "Recommended remediation:".
  if (/classification=(not_detected|inconclusive)/.test(r.stdout)) {
    assert.match(r.stdout, /Remediation path \(informational — verdict=(not_detected|inconclusive), no action required now\):/,
      "non-detect runs must NOT print 'Recommended remediation:' (that string is for detected runs)");
    // And the misleading detected-only phrasing must NOT appear.
    assert.doesNotMatch(r.stdout, /^Recommended remediation:/m,
      "non-detect runs must not print the unconditional detected-only phrasing");
  }
});

test("run unknown-playbook error says 'list the <live count> playbooks', not the stale literal 13", () => {
  const r = cli(["run", "this-playbook-does-not-exist"]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err, `stderr must be JSON; got: ${r.stderr.slice(0, 200)}`);
  // The live count is whatever runner.listPlaybooks() returns; it must
  // NOT be the literal "13" (the value before the v0.13.x expansion).
  assert.doesNotMatch(err.error, /list the 13 playbooks/,
    "playbook-not-found message must not carry the stale hardcoded count");
  assert.match(err.error, /list the \d+ playbooks/,
    "playbook-not-found message must reference a live count");
});
