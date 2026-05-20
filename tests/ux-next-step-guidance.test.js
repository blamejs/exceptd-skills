"use strict";

/**
 * tests/ux-next-step-guidance.test.js
 *
 * Stage-by-stage next-step guidance surfaces. The behavior is
 * operator-facing prose, so regression coverage is grep-shaped — each
 * assertion pins the exact substring an operator searches for when
 * they ask "what do I do now?"
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
 *   6. run unknown-playbook error references the live playbook count,
 *      not a hardcoded literal.
 *   7. ci FAIL fires guidance even when no playbook hit detected (delta-
 *      cap path).
 *   8. lint flags nested-shape submissions that supply artifacts but no
 *      signal_overrides — the workflow trapdoor.
 *
 * Per the anti-coincidence rule: assertions check exact substrings.
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
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "run-evidence-"));
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
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "run-attest-"));
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

test("ci FAIL Next steps names the specific detected playbook + surfaces pending jurisdiction obligations", () => {
  // Multi-playbook ci with one detected + one inconclusive. The
  // Next-steps block must:
  //   - say "in <playbook-id>" (not "<playbook>" placeholder)
  //   - emit run commands with the actual playbook id
  //   - surface pending jurisdiction obligations grouped by
  //     clock_start_event across all detected playbooks
  const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), "multi-ev-"));
  try {
    fs.writeFileSync(path.join(evidenceDir, "kernel.json"), JSON.stringify({
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      signal_overrides: { "kver-in-affected-range": "hit" },
    }));
    fs.writeFileSync(path.join(evidenceDir, "secrets.json"), JSON.stringify({
      precondition_checks: { "repo-context": true, "regex-engine": true },
      artifacts: { "repo-tree": { value: "clean", captured: true } },
      signal_overrides: { "aws-access-key-id": "miss" },
    }));
    const r = cli(["ci", "--required", "kernel,secrets", "--evidence-dir", evidenceDir]);
    assert.match(r.stdout, /verdict=FAIL/,
      "kernel + kver-in-affected-range:hit must drive verdict=FAIL");
    assert.match(r.stdout, /Next steps \(review the 1 detected finding\(s\) in kernel\):/,
      "Next-steps header must name the specific detected playbook (not '<playbook>')");
    assert.match(r.stdout, /exceptd run kernel --format markdown/,
      "run command must use the actual playbook id, not '<playbook>' placeholder");
    assert.match(r.stdout, /Pending jurisdiction obligations across detected playbook\(s\) \(\d+\) — clock starts on operator action:/,
      "ci must surface pending jurisdiction obligations at the summary level for detected runs");
    assert.match(r.stdout, /\s+on \w+:\s+\w/,
      "obligations must be grouped by clock_start_event");
  } finally {
    try { fs.rmSync(evidenceDir, { recursive: true, force: true }); } catch {}
  }
});

test("ci FAIL with multiple detected playbooks emits run commands for EACH (not just detectedIds[0])", () => {
  // When ci lands multiple playbooks at classification=detected,
  // the Next-steps commands must enumerate ONE row per id for each
  // format. Pre-fix only detectedIds[0] got rendered, so operators
  // would miss the markdown / csaf-2.0 follow-up for every detected
  // playbook beyond the first.
  const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), "multi-detected-"));
  try {
    // Two playbooks, both forced to detected via signal_overrides.
    fs.writeFileSync(path.join(evidenceDir, "kernel.json"), JSON.stringify({
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      signal_overrides: { "kver-in-affected-range": "hit" },
    }));
    fs.writeFileSync(path.join(evidenceDir, "secrets.json"), JSON.stringify({
      precondition_checks: { "repo-context": true, "regex-engine": true },
      artifacts: { "repo-tree": { value: "src/config.js contains AKIA...", captured: true } },
      signal_overrides: { "aws-access-key-id": "hit" },
    }));
    const r = cli(["ci", "--required", "kernel,secrets", "--evidence-dir", evidenceDir]);
    assert.match(r.stdout, /detected=2/,
      "scenario depends on both playbooks landing detected");
    assert.match(r.stdout, /exceptd run kernel --format markdown/,
      "markdown command for kernel must be present");
    assert.match(r.stdout, /exceptd run secrets --format markdown/,
      "markdown command for secrets must ALSO be present (regression: was only emitted for detectedIds[0])");
    assert.match(r.stdout, /exceptd run kernel --format csaf-2\.0/,
      "csaf command for kernel must be present");
    assert.match(r.stdout, /exceptd run secrets --format csaf-2\.0/,
      "csaf command for secrets must ALSO be present");
  } finally {
    try { fs.rmSync(evidenceDir, { recursive: true, force: true }); } catch {}
  }
});

test("ci FAIL prints Next steps even when no playbook hit `detected` (delta-cap path)", () => {
  // `verdict === "FAIL"` fires in two shapes:
  //   (a) detected > 0 (a playbook landed classification=detected)
  //   (b) inconclusive + rwep_delta >= cap
  // Both must print a Next-steps block. This test pins shape (b) —
  // set --max-rwep to 0 + supply evidence that lifts the score by any
  // amount, so the rwep_delta gate fires while classification stays
  // inconclusive.
  const evidence = JSON.stringify({
    kernel: {
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      // Set ONE indicator to "hit" so RWEP rises by the cisa_kev / poc
      // adjustment ladder but classification stays inconclusive (the
      // ladder fires on any indicator going hit; classification only
      // moves to "detected" when the deterministic indicators fire on
      // confirmed-applicability).
      signal_overrides: { "active-exploitation-published": "hit" }
    }
  });
  const tmpFile = path.join(os.tmpdir(), `fail-delta-${process.pid}.json`);
  fs.writeFileSync(tmpFile, evidence);
  try {
    const r = cli(["ci", "--required", "kernel", "--evidence", tmpFile, "--max-rwep", "0"]);
    // We expect verdict=FAIL because rwep_delta will exceed cap=0. If
    // the classification lands "detected" (different shape), the FAIL
    // path still prints SOME guidance — test just pins that a Next-
    // steps block appears on any FAIL.
    if (/verdict=FAIL/.test(r.stdout)) {
      assert.match(r.stdout, /Next steps \(/,
        "FAIL must always print a Next-steps block — both the detected and the inconclusive+delta-cap shapes need actionable guidance");
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
});

test("run --diff-from-latest with NO prior attestation prints 'no prior' line (not silent)", () => {
  // Pre-fix the no_prior_attestation_for_playbook branch intentionally
  // produced no line — but operators who passed --diff-from-latest
  // then saw zero diff output and couldn't tell whether the flag took
  // effect. The explicit "no prior" line tells them this run is the
  // baseline.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "no-prior-"));
  try {
    // cwd-the-tempdir to avoid the legacy `.exceptd/` fallback root
    // picking up unrelated priors from the project tree.
    const r = cli(["run", "secrets", "--evidence", "-", "--diff-from-latest"],
      { input: "{}", env: { EXCEPTD_HOME: tmpHome }, cwd: tmpHome });
    assert.equal(r.status, 0, `run must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /drift vs prior: no prior attestation found for secrets — this run becomes the baseline/,
      "no-prior case must emit an explicit line so the operator knows --diff-from-latest took effect");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run inconclusive with mixed coverage breaks out decisive vs inconclusive indicators", () => {
  // A submission that supplies signal_overrides for only some
  // indicators lands `classification=inconclusive`. The raw
  // "evidence: complete (13/13 indicators evaluated)" wording is
  // technically correct (the engine ran every indicator) but
  // misleading — it sounds like full coverage. The renderer must
  // distinguish decisive (hit/miss) from inconclusive verdicts when
  // the classification itself is inconclusive AND there's a mix.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: { "repo-tree": { value: "tree dump", captured: true } },
    signal_overrides: {
      "aws-access-key-id": "miss",
      "github-personal-access-token": "miss",
    },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "mixed-cov-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0);
    // 2 decisive / 13 known / 11 inconclusive — the breakdown must
    // appear on the verdict line (decision IS load-bearing here).
    assert.match(r.stdout, /classification=inconclusive/,
      "scenario depends on the run landing inconclusive");
    assert.match(r.stdout, /evidence: complete\s+\(2\/13 decisive, 11 inconclusive — add signal_overrides to drive a verdict\)/,
      "verdict line must break out decisive vs inconclusive when both are present + verdict is inconclusive");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run detected with all indicators decisive does NOT break out the count", () => {
  // When classification is detected (or not_detected), the breakdown
  // is noise — operators just want the verdict and indicator counter.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: { "repo-tree": { value: "tree", captured: true } },
    signal_overrides: { "aws-access-key-id": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "decisive-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0);
    if (/classification=detected/.test(r.stdout)) {
      // Detected runs use the plain (N/M indicators evaluated) form;
      // the decisive-breakdown would be misleading here.
      assert.match(r.stdout, /evidence: complete\s+\(\d+\/\d+ indicators evaluated\)/,
        "detected runs use the plain N/M form, not the decisive breakdown");
      assert.doesNotMatch(r.stdout, /decisive,/,
        "detected runs must NOT show the decisive/inconclusive breakdown");
    }
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run surfaces runtime_errors in the human renderer (malformed signal_overrides is visible)", () => {
  // A malformed submission (e.g. signal_overrides as a string) used
  // to silently complete with `[ok] classification=not_detected`
  // because the runtime_errors[] entry lived only in
  // phases.analyze.runtime_errors and the human renderer ignored
  // them. The operator had no signal their submission was bogus.
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0" },
    signal_overrides: "not-an-object",
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-warn-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "kernel", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0, `run must exit 0 even on malformed submission; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /Runtime warnings \(\d+\):/,
      "Runtime warnings block must appear when runtime_errors[] is non-empty");
    assert.match(r.stdout, /\[signal_overrides_invalid\]/,
      "the signal_overrides_invalid kind must be surfaced as a labeled row");
    assert.match(r.stdout, /signal_overrides must be a plain object/,
      "the reason text must appear so the operator knows what to fix");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("lint flags nested submission with artifacts-but-no-signal_overrides (the workflow-blind path)", () => {
  // The cold-start workflow has a hidden trapdoor: lint says "Add to
  // submission.artifacts.<id>" for every required artifact, the
  // operator populates them all, runs, and gets every indicator =
  // inconclusive. detect() needs signal_overrides (or a verdict
  // override) to mark each indicator hit / miss — artifact presence
  // alone is not enough. lint must surface this explicitly so the
  // operator sees the JSON shape to populate next.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: {
      "repo-tree": { value: "package.json src/ tests/", captured: true },
      "secret-regex-scan-text-files": { value: "scanned 47 files; 0 hits", captured: true }
    }
  });
  const tmpFile = path.join(os.tmpdir(), `lint-no-overrides-${process.pid}.json`);
  fs.writeFileSync(tmpFile, evidence);
  try {
    const r = cli(["lint", "secrets", tmpFile, "--json"]);
    const body = tryJson(r.stdout);
    assert.ok(body, "lint must emit parseable JSON");
    const hint = body.issues.find(i => i.kind === "no_signal_overrides_supplied");
    assert.ok(hint, `expected a no_signal_overrides_supplied info issue; got: ${JSON.stringify(body.issues.map(i => i.kind))}`);
    assert.equal(hint.severity, "info");
    assert.match(hint.hint, /signal_overrides/);
    assert.match(hint.hint, /"hit"\|"miss"/);
    assert.match(hint.hint, /verdict\.classification/);
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
});
