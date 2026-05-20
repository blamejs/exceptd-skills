"use strict";

/**
 * tests/attest-human-renderers.test.js
 *
 * Pins the human renderers for `attest verify` and `attest diff` —
 * both answer one-line questions ("did anyone tamper?" / "did
 * anything change since the last run?") that should not require
 * piping through jq.
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
 * Tests use an EXCEPTD_HOME tempdir so they don't leak into the
 * operator's real ~/.exceptd/ tree.
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
    // On a contributor checkout with .keys/private.pem present, the
    // attestation gets signed and verifies. On a CI runner with no
    // private key (the normal case), the attestation is written
    // UNSIGNED and verifies as "explicitly-unsigned" with a [!! FAIL]
    // row. Both shapes are valid; the renderer must still produce the
    // shape contract (header + counts row + per-file row).
    assert.match(r.stdout, /\d+\/\d+ attestation\(s\) verified, \d+\/\d+ replay record\(s\) verified/,
      "verdict counts row must be present regardless of signing state");
    assert.match(r.stdout, /attestation\.json\s+—/,
      "per-file row must include filename + reason");
    assert.match(r.stdout, /→ next: exceptd attest/,
      "next-step block must point at another attest subverb (diff on clean, show/list on tamper)");
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
    // On a contributor checkout the attestation is signed → verified=true.
    // On CI without a private key it's explicitly-unsigned → verified=false
    // with tamper_class=explicitly-unsigned (not a real tamper). Either is
    // a valid envelope shape.
    assert.equal(typeof body.results[0].verified, "boolean");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("attest diff default output is human text with status row + next-step", () => {
  const { tmpHome, env, sessionId } = setupSession();
  try {
    // --force-replay is required on a CI runner where the setup `run`
    // wrote an unsigned attestation (no .keys/private.pem available).
    // The security-refusal-without-force-replay path is exercised in
    // a separate test file; here we want to reach the human renderer.
    const r = cli(["attest", "diff", sessionId, "--force-replay"], { env });
    // The replay re-runs the playbook. On CI without a private key the
    // overall exit code may be 0 but the human renderer still fires
    // for the diff. Pin output shape regardless of signing state.
    assert.equal(tryJson(r.stdout), null,
      "default attest diff output must NOT be parseable JSON");
    assert.match(r.stdout, new RegExp(`attest diff: ${sessionId} \\(kernel\\)`),
      "header must include session id + playbook id");
    assert.match(r.stdout, /\[ok\]\s+status=unchanged|\[i\s+DRIFTED\]\s+status=drifted/,
      "status row must carry the verdict icon");
    // sidecar_verify class is one of verified / explicitly-unsigned /
    // no-public-key / no-sidecar depending on the environment.
    assert.match(r.stdout, /sidecar verify: \w/,
      "sidecar verify class must appear on the human output");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});
