"use strict";

/**
 * tests/jurisdiction-pending-v0_13_25.test.js
 *
 * v0.13.25: surface pending notification obligations on detected runs.
 * The detection IS the regulatory event in many jurisdictions — the
 * operator must see the obligation landscape at the same moment they
 * see the finding, not after they remember to grep
 * `phases.close.notification_actions` in the JSON.
 *
 * Test pins:
 *   - Detected run with no clocks started prints the "Pending
 *     jurisdiction obligations (N)" block on the human renderer.
 *   - Obligations are grouped by `clock_start_event` (one row per
 *     start event, NOT one row per regulation).
 *   - The next-step pointer suggests `--format csaf-2.0` for the
 *     draft advisory + notification bodies.
 *   - Non-detect verdicts (not_detected / inconclusive) do NOT print
 *     the Pending block (irrelevant — no regulatory event).
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
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

test("detected run prints 'Pending jurisdiction obligations' grouped by clock_start_event", () => {
  // kernel playbook with the deterministic CVE indicator firing is the
  // canonical detected-with-obligations shape.
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "pending-obl-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "kernel", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    // Codex P2 on PR #65: pin the detected classification as a precondition
    // BEFORE checking the pending-obligation output. If the deterministic
    // hit indicator regresses and the run no longer classifies as detected,
    // this assertion fires loudly. Pre-fix the test wrapped the pending-
    // obligation checks in `if (/DETECTED/.test(...))` — a silent skip
    // that would let the underlying feature break without alerting.
    assert.match(r.stdout, /\[!! DETECTED\]/,
      "kernel + kver-in-affected-range:hit must classify as detected — the test scenario depends on this");
    assert.match(r.stdout, /Pending jurisdiction obligations \(\d+\) — clock starts on operator action:/,
      "detected run must surface pending jurisdiction obligations");
    // At least one grouped event row. Format: `  on <event>:  <jur>/<reg> (Nh), ...`
    assert.match(r.stdout, /\s+on \w+:\s+\w/,
      "obligations must be grouped by clock_start_event");
    // Next-step pointer.
    assert.match(r.stdout, /→ next: exceptd run kernel --evidence <file> --format csaf-2\.0/,
      "must point at csaf-2.0 format for draft advisory + notification bodies");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("non-detect runs do NOT print the Pending block (irrelevant — no regulatory event)", () => {
  // Empty submission → classification=not_detected. The renderer must
  // not surface the Pending jurisdiction block in that case — there is
  // no detection to trigger an obligation.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "non-detect-obl-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: "{}", env });
    assert.equal(r.status, 0);
    assert.doesNotMatch(r.stdout, /Pending jurisdiction obligations/,
      "not_detected / inconclusive runs must NOT print the Pending block — no regulatory event to track");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});
