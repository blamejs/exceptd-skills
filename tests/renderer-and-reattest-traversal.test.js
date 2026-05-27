"use strict";

/**
 * Regression suite for a cluster found auditing the human-readable output
 * paths and the attestation read verbs:
 *
 *   SECURITY — `reattest` joined an unvalidated session-id into a filesystem
 *     path, so `reattest "../.."` escaped the attestation root to read a forged
 *     attestation and write a signed replay record outside the root. It now
 *     validates the session-id at the same boundary the other read verbs use.
 *
 *   run-multi (`run --all` / `run-all`) had no human renderer and dumped the
 *     full (hundreds-of-KB) JSON even in default mode; it now prints a table.
 *
 *   `attest diff --against` dumped raw JSON while the no-against branch
 *     rendered a summary; both now share one renderer.
 *
 *   run-renderer detail: CVE KEV renders Y/N (not the raw boolean), a
 *     deterministic indicator doesn't print "deterministic/deterministic",
 *     and a `message`-shaped preflight warning isn't shown as "(no detail)".
 *
 * Discipline: exact exit codes; value + type assertions; the security test
 * asserts BOTH the refusal AND that nothing was written outside the root.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-renderer-"));

// The shared harness sets EXCEPTD_RAW_JSON=1, which forces JSON and bypasses
// the human renderer. Human-mode tests pass HUMAN env to disable it ("" is
// falsy under the `!!process.env.EXCEPTD_RAW_JSON` check).
const HUMAN = { EXCEPTD_RAW_JSON: "" };

const DET2 = JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } });

test("SECURITY: reattest refuses a path-traversal session-id and writes nothing outside the root", () => {
  // Isolated home so the attestation root is a known tempdir.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-trav-"));
  try {
    const env = { EXCEPTD_HOME: home };
    // seed a real attestation so the root exists
    cli(["run", "secrets", "--evidence", "-"], { input: DET2, env });
    // plant a forged attestation OUTSIDE the attestations root (sibling under home)
    const escape = path.join(home, "escape-target");
    fs.mkdirSync(escape, { recursive: true });
    fs.writeFileSync(path.join(escape, "attestation.json"), JSON.stringify({
      session_id: "v", playbook_id: "secrets", directive_id: "full-repo-secret-scan",
      evidence_hash: "deadbeef", submission: { signal_overrides: {} }, captured_at: "2026-01-01T00:00:00Z",
    }));
    // attestations root is <home>/attestations; traverse up into escape-target
    const r = cli(["reattest", "../escape-target", "--force-replay", "--json"], { env });
    assert.equal(r.status, 1, "traversal must be refused with exit 1");
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false, "must emit a structured refusal");
    assert.match(body.error, /Invalid session-id/, "must name the validation failure");
    // and CRUCIALLY: no replay record was written into the out-of-root dir
    const wrote = fs.readdirSync(escape).some(f => f.startsWith("replay-"));
    assert.equal(wrote, false, "reattest must NOT write a replay record outside the attestation root");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("reattest still works for a valid session-id", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-trav2-"));
  try {
    const env = { EXCEPTD_HOME: home };
    const run = tryJson(cli(["run", "secrets", "--evidence", "-", "--json"], { input: DET2, env }).stdout);
    const r = cli(["reattest", run.session_id, "--force-replay", "--json"], { env });
    const body = tryJson(r.stdout);
    assert.ok(body, "valid reattest must emit JSON");
    assert.equal(body.status, "unchanged", "replaying the recorded submission reproduces the prior hash");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("run --all renders a per-playbook table in human mode (not a raw JSON dump)", () => {
  const r = cli(["run-all"], { env: HUMAN });
  const out = r.stdout;
  assert.doesNotMatch(out.trimStart().slice(0, 1), /[{[]/, "default human output must not start with JSON");
  assert.match(out, /playbook\s+verdict\s+rwep\s+evidence\s+finding/, "must render the summary table header");
  assert.match(out, /detected=\d+\s+inconclusive=\d+/, "must render the rollup line");
});

test("attest diff --against renders a human summary (not raw JSON)", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-diff-"));
  try {
    const env = { EXCEPTD_HOME: home };
    const a = tryJson(cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } }), env }).stdout);
    const b = tryJson(cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "github-personal-access-token": "hit" } }), env }).stdout);
    const r = cli(["attest", "diff", a.session_id, "--against", b.session_id], { env: { ...env, ...HUMAN } });
    assert.doesNotMatch(r.stdout.trimStart().slice(0, 1), /[{[]/, "must not dump JSON in human mode");
    assert.match(r.stdout, /attest diff:/, "must render the diff header");
    assert.match(r.stdout, /artifact diff:/, "must render the artifact diff line");
    assert.match(r.stdout, /sidecar verify:/, "must render the sidecar class");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("run CVE line renders KEV=Y/N, and a deterministic indicator is not doubled", () => {
  // ai-api with firing signals produces a matched CVE + deterministic indicators.
  const r = cli(["run", "ai-api", "--evidence", "-"], {
    input: JSON.stringify({ signal_overrides: { "cleartext-api-key-in-dotfile": "hit", "ai-api-beaconing-cadence": "hit", "long-lived-aws-keys": "hit" } }),
    env: HUMAN,
  });
  const out = r.stdout;
  assert.doesNotMatch(out, /KEV=(true|false)/, "KEV must render Y/N, never the raw boolean");
  assert.match(out, /KEV=[YN]/, "KEV must render as Y or N");
  assert.doesNotMatch(out, /deterministic\/deterministic/, "must not double-print deterministic/deterministic");
});

test("run preflight warning surfaces a message-shaped detail (not '(no detail)')", () => {
  const r = cli(["run", "ai-api", "--evidence", "-"], { input: JSON.stringify({ signal_overrides: { "ai-api-beaconing-cadence": "hit" } }), env: HUMAN });
  const out = r.stdout;
  if (/Preflight warnings/.test(out)) {
    // If a preflight warning rendered, it must not be the bare "(no detail)".
    const warnBlock = out.slice(out.indexOf("Preflight warnings"));
    assert.doesNotMatch(warnBlock.split("\n").slice(1, 3).join("\n"), /: \(no detail\)\s*$/m,
      "a message-shaped preflight warning must show its message, not (no detail)");
  }
});
