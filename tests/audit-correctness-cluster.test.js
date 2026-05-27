"use strict";

/**
 * Regression suite for a correctness cluster found auditing the run/ci/ai-run
 * verbs and the close/framework-gap surfaces for silent-wrong-answer bugs:
 *
 *   H1 — `ci <playbook> --evidence -` given a FLAT submission (the same shape
 *        `run` accepts) silently produced a PASS: the runner keyed the bundle
 *        by playbook id, found nothing, and evaluated an empty submission.
 *        ci must now treat a single-positional flat submission as belonging to
 *        that playbook, matching `run`'s verdict.
 *
 *   H2 — `ai-run <pb> --no-stream --evidence -` bypassed the evidence-shape
 *        guard `run` enforces, so `null` / `[]` / a scalar ran as if empty.
 *        It must be rejected at the read boundary with an actionable message.
 *
 *   H3 — the ci framework_gap_rollup read a nonexistent `why_insufficient`
 *        key, so every rollup entry's explanation was null. The data lives in
 *        `actual_gap`; the rollup must surface it.
 *
 *   M1 — the regulatory clock only started when the AGENT submitted
 *        detection_classification:'detected'. An engine-confirmed detection
 *        (indicators fired, engine classified 'detected') with --ack never
 *        started the clock, so notification deadlines silently stalled.
 *
 *   M2 — `framework-gap <bogus> <scenario>` produced a zero-gap report
 *        indistinguishable from a real "no gaps" result, so a typo read as
 *        proof the framework covered the scenario. An unknown framework must
 *        be refused; documented short forms ("NIST-800-53") must still resolve.
 *
 * Discipline: exact exit codes; presence assertions paired with value/type.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-auditcorrect-"));

// A flat secrets submission whose overrides fire real indicators.
const FLAT_SECRETS = JSON.stringify({
  signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" },
});

test("H1: ci accepts a flat single-positional submission and matches run's verdict", () => {
  const runR = cli(["run", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const run = tryJson(runR.stdout);
  assert.ok(run, "run must emit JSON");
  assert.equal(run.phases.analyze._detect_classification, "detected", "run classifies the flat submission as detected");

  const ciR = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const ci = tryJson(ciR.stdout);
  assert.ok(ci, "ci must emit JSON");
  const r0 = (ci.results || [])[0] || {};
  assert.equal(r0.verdict, "detected", "ci must NOT false-PASS a flat submission — it must match run");
  assert.equal(r0.rwep_score, run.phases.analyze.rwep.adjusted, "ci rwep must equal run's");
});

test("H1: a real bundle (keyed by playbook id) is still treated as a bundle", () => {
  const bundle = JSON.stringify({ secrets: { signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } } });
  const r = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: bundle });
  const ci = tryJson(r.stdout);
  assert.ok(ci, "ci must emit JSON");
  assert.equal((ci.results || [])[0]?.verdict, "detected", "the keyed bundle entry must still be evaluated");
});

test("H2: ai-run --no-stream rejects a non-object evidence submission", () => {
  const r = cli(["ai-run", "secrets", "--no-stream", "--evidence", "-"], { input: "null" });
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false, "must emit a structured error");
  assert.match(body.error, /evidence must be a JSON object/, "must name the shape requirement");
  assert.match(body.error, /got null/, "must name what it got");
});

test("H2: ai-run --no-stream still accepts a well-formed object submission", () => {
  const sub = JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } });
  const r = cli(["ai-run", "secrets", "--no-stream", "--evidence", "-", "--json"], { input: sub });
  const body = tryJson(r.stdout);
  assert.ok(body, "must emit JSON for a valid object submission");
  assert.notEqual(body.ok, false, "a well-formed object must not be rejected"); // allow-notEqual: assert valid path is NOT the rejected one
});

test("H3: ci framework_gap_rollup populates why_insufficient from actual_gap", () => {
  const r = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const ci = tryJson(r.stdout);
  assert.ok(ci, "ci must emit JSON");
  const rollup = ci.framework_gap_rollup || ci.summary?.framework_gap_rollup || [];
  assert.ok(Array.isArray(rollup) && rollup.length >= 1, "expected at least one rollup entry for a detected secrets finding");
  const entry = rollup[0];
  assert.equal(typeof entry.why_insufficient, "string", "why_insufficient must be a string, not null");
  assert.ok(entry.why_insufficient.length > 0, "why_insufficient must carry the actual_gap text");
  assert.equal(typeof entry.required_control, "string", "required_control must also be surfaced");
});

const AI_API_FIRES = JSON.stringify({
  signal_overrides: {
    "cleartext-api-key-in-dotfile": "hit",
    "ai-api-beaconing-cadence": "hit",
    "long-lived-aws-keys": "hit",
  },
});

test("M1: an engine-confirmed detection starts the clock with --ack (no agent classification submitted)", () => {
  const r = cli(["run", "ai-api", "--evidence", "-", "--ack", "--json"], { input: AI_API_FIRES });
  const j = tryJson(r.stdout);
  assert.ok(j, "run must emit JSON");
  assert.equal(j.phases.analyze._detect_classification, "detected", "engine must classify detected from the fired signals");
  const notifs = j.phases.close?.jurisdiction_notifications || j.phases.close?.notification_actions || [];
  // The detect_confirmed obligations must have a real ISO deadline, not the
  // pending sentinel — the engine classification started the clock.
  const started = notifs.filter(n => (n.deadline || n.notification_deadline) && (n.deadline || n.notification_deadline) !== "pending_clock_start_event");
  assert.ok(started.length >= 1, "at least one obligation's clock must start from the engine-confirmed detection + --ack");
  for (const n of started) {
    assert.match(n.deadline || n.notification_deadline, /^\d{4}-\d{2}-\d{2}T/, "a started clock yields an ISO deadline");
  }
});

test("M1: without --ack an engine-confirmed detection leaves the clock pending", () => {
  const r = cli(["run", "ai-api", "--evidence", "-", "--json"], { input: AI_API_FIRES });
  const j = tryJson(r.stdout);
  assert.ok(j, "run must emit JSON");
  const notifs = j.phases.close?.jurisdiction_notifications || j.phases.close?.notification_actions || [];
  const detectConfirmed = notifs.filter(n => n.clock_pending_ack === true);
  assert.ok(detectConfirmed.length >= 1, "detect_confirmed obligations must surface clock_pending_ack without --ack");
  for (const n of detectConfirmed) {
    assert.equal(n.deadline || n.notification_deadline, "pending_clock_start_event", "pending obligations carry the sentinel, not an ISO date");
  }
});

test("M2: framework-gap refuses an unknown framework", () => {
  const r = cli(["framework-gap", "ZZZ-NOT-A-FRAMEWORK", "CVE-2025-53773", "--json"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body && body.ok === false, "must emit a structured refusal");
  assert.match(body.error, /unknown framework/, "must name the failure");
  assert.ok(Array.isArray(body.known_frameworks) && body.known_frameworks.length > 0, "must list known frameworks");
});

test("M2: documented short forms (NIST-800-53, PCI-DSS-4.0) still resolve", () => {
  for (const fw of ["NIST-800-53", "nist-800-53", "PCI-DSS-4.0"]) {
    const r = cli(["framework-gap", fw, "prompt injection", "--json"]);
    const body = tryJson(r.stdout);
    assert.ok(body, `framework-gap ${fw} must emit JSON`);
    assert.notEqual(body.ok, false, `documented short form ${fw} must not be rejected`); // allow-notEqual: short forms must resolve, not refuse
    assert.ok(body.frameworks && Object.keys(body.frameworks).length >= 1, `${fw} must match at least one catalog framework`);
  }
});

test("M2: 'all' is unaffected by framework validation", () => {
  const r = cli(["framework-gap", "all", "prompt injection", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body && body.ok !== false, "'all' must still run");
  assert.ok(body.frameworks && Object.keys(body.frameworks).length > 1, "'all' must expand to many frameworks");
});
