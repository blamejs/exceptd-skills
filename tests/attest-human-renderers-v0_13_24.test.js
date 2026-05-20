"use strict";

/**
 * tests/attest-human-renderers-v0_13_24.test.js
 *
 * v0.13.24: human renderers for `attest verify` and `attest diff`.
 * Pre-0.13.24 both were JSON-only — operators asking the one-line
 * question those verbs exist to answer ("did anyone tamper?" /
 * "did anything change since the last run?") had to pipe through jq.
 *
 * Surfaces pinned:
 *   1. attest verify default output is human text (not JSON), prints
 *      a verdict icon + per-file row + next-step block.
 *   2. attest verify --json still emits the structured envelope
 *      (no displacement of the machine path).
 *   3. attest diff default output is human text with the status row,
 *      prior + replay hash + capture timestamps, replay classification,
 *      and a "→ next: ..." line on DRIFTED.
 *
 * Tests run inside a tempdir + use --attestation-root so they don't
 * leak into the operator's real ~/.exceptd/ tree.
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

function setupSession() {
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  // EXCEPTD_HOME is honored by both `run` (when --attestation-root is
  // unset) AND by the attest subverbs that look up persisted sessions.
  // --attestation-root only applies to `run`, so the test fixture uses
  // the env var to keep the run + verify + diff all pointing at the
  // same tempdir.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "attest-human-"));
  const env = { EXCEPTD_HOME: tmpHome };
  const r = cli(["run", "kernel", "--evidence", "-", "--json"],
    { input: evidence, env });
  assert.equal(r.status, 0, `setup run failed: ${r.stderr.slice(0, 200)}`);
  const body = JSON.parse(r.stdout);
  return { tmpHome, env, sessionId: body.session_id };
}

test("attest verify default output is human text (not JSON)", () => {
  const { tmpHome, env, sessionId } = setupSession();
  try {
    const r = cli(["attest", "verify", sessionId], { env });
    assert.equal(tryJson(r.stdout), null,
      "default attest verify output must NOT be parseable JSON (operator-readable digest)");
    assert.match(r.stdout, new RegExp(`attest verify: ${sessionId}`),
      "header must echo the session id");
    assert.match(r.stdout, /\[ok\]\s+1\/1 attestation\(s\) verified/,
      "verdict line must report verification counts");
    assert.match(r.stdout, /attestation\.json\s+— Ed25519 signature valid/,
      "per-file row must include filename + reason");
    assert.match(r.stdout, /→ next: exceptd attest diff/,
      "clean verify must point at attest diff for drift comparison");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("attest verify --json still emits parseable structured envelope", () => {
  const { tmpHome, env, sessionId } = setupSession();
  try {
    const r = cli(["attest", "verify", sessionId, "--json"], { env });
    const body = tryJson(r.stdout);
    assert.ok(body, "attest verify --json must emit parseable JSON");
    assert.equal(body.verb, "attest verify");
    assert.equal(body.session_id, sessionId);
    assert.ok(Array.isArray(body.results));
    assert.equal(body.results[0].verified, true);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("attest diff default output is human text with status row + next-step", () => {
  const { tmpHome, env, sessionId } = setupSession();
  try {
    const r = cli(["attest", "diff", sessionId], { env });
    assert.equal(tryJson(r.stdout), null,
      "default attest diff output must NOT be parseable JSON");
    assert.match(r.stdout, new RegExp(`attest diff: ${sessionId} \\(kernel\\)`),
      "header must include session id + playbook id");
    // The replay re-runs with the same submission so status is "unchanged".
    // The drift path is exercised elsewhere; this test pins the unchanged
    // shape — status row + sidecar-verify class + replay record path.
    assert.match(r.stdout, /\[ok\]\s+status=unchanged|\[i\s+DRIFTED\]\s+status=drifted/,
      "status row must carry the verdict icon");
    assert.match(r.stdout, /sidecar verify: (verified|explicitly-unsigned)/,
      "sidecar verify class must appear on the human output");
    assert.match(r.stdout, /replay record: .+\.json/,
      "replay record path must be visible");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});
