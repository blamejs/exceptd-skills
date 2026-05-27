"use strict";

/**
 * Regression suite for the attestation-durability cluster:
 *
 *   Atomic writes — the attestation body and its .sig are written to fsync'd
 *     tmp files then placed via linkSync (create) / rename (force), so a crash
 *     can't leave a truncated body and the body never lands without its sig.
 *     A successful run leaves exactly attestation.json + .sig, no .tmp churn.
 *   attest verify now flags a deleted sidecar as tamper (exit 6) when one was
 *     expected (signing key present or a signed peer), matching reattest —
 *     instead of accepting it as a benign "unsigned" (exit 0).
 *   run() blocks (blocked_by:mutex) when a live foreign process holds the run
 *     lock, instead of proceeding unlocked on a lost acquire race.
 *
 * Discipline: exact exit codes; the durability test asserts the placed pair
 * AND the absence of tmp residue.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeCli, tryJson } = require("./_helpers/cli");

function freshHome(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return d;
}
function sessionDir(home, sid) { return path.join(home, "attestations", sid); }

test("a run places attestation.json + .sig atomically, with no .tmp residue", () => {
  const home = freshHome("exceptd-atomwrite-");
  try {
    const cli = makeCli(home);
    const r = cli(["run", "secrets", "--evidence", "-", "--session-id", "aw1", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } }), env: { EXCEPTD_HOME: home } });
    assert.equal(r.status === 0 || r.status === 2, true, `run should succeed/escalate; got ${r.status}`);
    const dir = sessionDir(home, "aw1");
    const files = fs.readdirSync(dir);
    assert.ok(files.includes("attestation.json"), "attestation.json must be placed");
    assert.ok(files.includes("attestation.json.sig"), "the .sig sidecar must be placed alongside the body");
    assert.ok(!files.some(f => f.endsWith(".tmp")), `no .tmp residue should remain; got ${files.join(", ")}`);
    // The placed body is fully-formed JSON (not truncated).
    const body = tryJson(fs.readFileSync(path.join(dir, "attestation.json"), "utf8"));
    assert.ok(body && body.session_id === "aw1", "the placed attestation must be complete, parseable JSON");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("attest verify flags a deleted sidecar as tamper when one was expected (matches reattest)", () => {
  const home = freshHome("exceptd-sigdel-");
  try {
    const cli = makeCli(home);
    const env = { EXCEPTD_HOME: home };
    const run = cli(["run", "secrets", "--evidence", "-", "--session-id", "sd1"], { input: "{}", env });
    assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 160)}`);
    const dir = sessionDir(home, "sd1");
    const sigPath = path.join(dir, "attestation.json.sig");
    const wasSigned = (() => { try { return JSON.parse(fs.readFileSync(sigPath, "utf8")).algorithm === "Ed25519"; } catch { return false; } })();
    fs.rmSync(sigPath, { force: true });
    const v = cli(["attest", "verify", "sd1", "--json"], { env });
    if (wasSigned) {
      assert.equal(v.status, 6, "a deleted sidecar where one was expected must be tamper (exit 6)");
      const body = tryJson(v.stdout) || tryJson(v.stderr);
      assert.ok(body, "must emit a structured verify result");
    } else {
      // keyless host: no key, no signed peer → genuinely unsigned → benign.
      assert.equal(v.status, 0, "keyless-host stripped sidecar stays benign");
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("run blocks (blocked_by:mutex) when a live foreign process holds the run lock", () => {
  const home = freshHome("exceptd-mutex-");
  const lockDir = freshHome("exceptd-lockdir-");
  try {
    const cli = makeCli(home);
    // Plant a lock for `secrets` held by THIS test runner's pid (alive, and
    // distinct from the CLI subprocess pid) so the run sees a live foreign
    // holder and must block rather than proceed unlocked.
    fs.writeFileSync(path.join(lockDir, "secrets.lock"),
      JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: "secrets" }, null, 2));
    const r = cli(["run", "secrets", "--evidence", "-", "--session-id", "mx1", "--json"],
      { input: "{}", env: { EXCEPTD_HOME: home, EXCEPTD_LOCK_DIR: lockDir } });
    assert.notEqual(r.status, 0, "a run blocked on a live foreign mutex holder must exit non-zero"); // allow-notEqual: blocked is any non-zero; shape asserted below
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.ok(body && body.ok === false, "must emit a structured blocked result");
    assert.equal(body.blocked_by, "mutex", "must identify the mutex as the blocker");
    assert.match(body.reason, /concurrent run/i, "must explain the concurrent-run block");
    // and no attestation was persisted for the blocked run
    assert.ok(!fs.existsSync(sessionDir(home, "mx1")), "a mutex-blocked run must not persist an attestation");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
});

test("a malformed/unparsable run lock does NOT permanently block (proceeds best-effort, not held_by_live_pid:null)", () => {
  const home = freshHome("exceptd-badlock-");
  const lockDir = freshHome("exceptd-badlockdir-");
  try {
    const cli = makeCli(home);
    // A truncated/garbage lockfile has no parseable pid — must NOT be treated
    // as a live holder (that would let a crash-left corrupt lock deny all runs).
    fs.writeFileSync(path.join(lockDir, "secrets.lock"), "not-json-garbage");
    const r = cli(["run", "secrets", "--evidence", "-", "--session-id", "bl1", "--json"],
      { input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } }), env: { EXCEPTD_HOME: home, EXCEPTD_LOCK_DIR: lockDir } });
    const body = tryJson(r.stdout);
    assert.ok(body, "run must emit JSON");
    assert.notEqual(body.blocked_by, "mutex", "a malformed lock must not be reported as a live mutex holder"); // allow-notEqual: must NOT be the mutex-blocked shape
    // It ran (best-effort): a verdict was produced and an attestation persisted.
    assert.ok(fs.existsSync(sessionDir(home, "bl1")), "the run should proceed despite the malformed lock");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
});
