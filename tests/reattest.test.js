'use strict';

/**
 * Subject: the `exceptd reattest` CLI verb — replay of a persisted session's
 * original submission against the live catalog, with sidecar-tamper refusal.
 *
 * Consolidated from per-finding test files; each source file's contribution is
 * wrapped in a describe() block carrying its original basename so file-local
 * helper/const names cannot collide across merged sources.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

test('reattest CLI subject file loaded', () => {
  assert.ok(true);
});

// ===========================================================================
describe('attest-replay-and-discover-cwd (reattest slice)', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-replayfix-reattest-');
  const cli = makeCli(SUITE_HOME);

  test("reattest reports 'unchanged' for an unchanged session (no false drift)", () => {
    const sid = 'replayfix-base';
    const run = cli(['run', 'secrets', '--evidence', '-', '--session-id', sid], { input: '{"artifacts":{},"signals":{}}' });
    assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 200)}`);
    const r = cli(['reattest', sid, '--force-replay', '--json']);
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.ok(body, `reattest must emit JSON; got stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 200)}`);
    assert.equal(body.status, 'unchanged');
    assert.equal(body.prior_evidence_hash, body.replay_evidence_hash);
  });
});

// ===========================================================================
describe('attestation-signature-roundtrip (reattest slice)', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-reattest-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  function locateAttestationFiles(sid) {
    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find((p) => fs.existsSync(p));
    if (!attRoot) return null;
    const files = fs.readdirSync(attRoot);
    const jsonFiles = files.filter((f) => f.endsWith('.json') && !f.endsWith('.sig'));
    return {
      dir: attRoot,
      files: jsonFiles,
      primaryJson: jsonFiles.includes('attestation.json')
        ? path.join(attRoot, 'attestation.json')
        : path.join(attRoot, jsonFiles[0]),
      primarySig: jsonFiles.includes('attestation.json')
        ? path.join(attRoot, 'attestation.json.sig')
        : path.join(attRoot, jsonFiles[0] + '.sig'),
    };
  }

  test('KK P1-2 — reattest --force-replay writes replay-<isoZ>.json under the session dir',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-replay-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);

      fs.writeFileSync(att.primarySig, JSON.stringify({
        algorithm: 'unsigned',
        signed: false,
        note: 'forged',
      }, null, 2));

      const r = cli(['reattest', sid, '--force-replay', '--json']);
      assert.equal(r.status, 0,
        `reattest --force-replay must succeed; got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || {};
      assert.equal(body.ok, true, 'replay body must carry ok:true');
      assert.equal(body.force_replay, true, 'replay body must record force_replay:true');

      assert.ok(body.replay_persisted && typeof body.replay_persisted === 'object',
        'replay_persisted must be an object handle');
      assert.equal(body.replay_persisted.ok, true,
        `replay_persisted.ok must be true. Got ${JSON.stringify(body.replay_persisted)}`);
      assert.equal(typeof body.replay_persisted.path, 'string',
        'replay_persisted.path must be a string');
      assert.ok(/[\\/]replay-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.json$/.test(body.replay_persisted.path),
        `replay_persisted.path must match the replay-<isoZ>.json shape. Got ${body.replay_persisted.path}`);

      assert.ok(fs.existsSync(body.replay_persisted.path),
        `replay file must exist at the persisted path: ${body.replay_persisted.path}`);
      const replayBody = JSON.parse(fs.readFileSync(body.replay_persisted.path, 'utf8'));
      assert.equal(replayBody.kind, 'replay',
        'persisted body must carry kind:"replay" so auditors can distinguish from primary attestations');
      assert.equal(replayBody.session_id, sid);
      assert.equal(replayBody.force_replay, true,
        'persisted body must record force_replay:true');
      assert.ok(
        replayBody.sidecar_verify_class === 'unsigned-substitution' ||
        replayBody.sidecar_verify_class === 'explicitly-unsigned',
        `persisted body must record sidecar_verify_class. Got ${JSON.stringify(replayBody.sidecar_verify_class)}`
      );
      assert.equal(typeof replayBody.prior_evidence_hash, 'string',
        'persisted body must record prior_evidence_hash (string)');
      assert.equal(typeof replayBody.replayed_at, 'string',
        'persisted body must record replayed_at (ISO-8601 string)');
    });

  test('KK P1-3 — reattest refuses sidecar with algorithm:"HMAC-SHA256" (exit 6, algorithm-unsupported)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-algo-replay-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);
      const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
      sigDoc.algorithm = 'HMAC-SHA256';
      fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

      const r = cli(['reattest', sid, '--json']);
      assert.equal(r.status, 6,
        `reattest must exit 6 on a downgrade-bait algorithm field. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stderr.split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
      assert.equal(body.ok, false);
      assert.equal(body.verb, 'reattest');
      assert.equal(body.sidecar_verify && body.sidecar_verify.tamper_class, 'algorithm-unsupported',
        `sidecar_verify.tamper_class must be "algorithm-unsupported"; got ${JSON.stringify(body.sidecar_verify)}`);
    });
});

// ===========================================================================
describe('attestation-trust-boundary (reattest slice)', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-trust-reattest-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  function locateAttestation(sid) {
    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find(p => fs.existsSync(p));
    if (!attRoot) return null;
    const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
    if (files.length === 0) return null;
    return {
      dir: attRoot,
      jsonFile: path.join(attRoot, files[0]),
      sigFile: path.join(attRoot, files[0] + '.sig'),
    };
  }

  test('Fix 2(a) — reattest refuses a corrupt-JSON sidecar without --force-replay (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const sid = 'aa-trust-corrupt-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0, `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

      const att = locateAttestation(sid);
      assert.ok(att, 'attestation must exist after producer run');
      fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25');  // truncated JSON

      const r = cli(['reattest', sid, '--json']);
      assert.equal(r.status, 6,
        `reattest against a corrupt-JSON sidecar must exit 6 (TAMPERED), not fall through to the benign NOTE branch. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stderr.split('\n').filter(l => l.trim().startsWith('{')).pop() || '') || {};
      assert.equal(body.ok, false,
        'corrupt-sidecar refusal body must carry ok:false (not just an exit code)');
      assert.equal(body.verb, 'reattest');
      assert.equal(body.session_id, sid);
      assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
        'refusal body must include the full sidecar_verify object for audit');
      assert.equal(body.sidecar_verify.tamper_class, 'sidecar-corrupt',
        'sidecar_verify.tamper_class must be "sidecar-corrupt" — substring matching on the reason is fragile');
    });

  test('Fix 2(a) — reattest --force-replay accepts a corrupt sidecar and persists sidecar_verify + force_replay',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'aa-trust-corrupt-force-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestation(sid);
      assert.ok(att);
      fs.writeFileSync(att.sigFile, 'not-valid-json{{{');

      const r = cli(['reattest', sid, '--force-replay', '--json']);
      assert.equal(r.status, 0,
        `reattest --force-replay must succeed (exit 0) against a corrupt sidecar so the override is audit-visible. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);

      const body = tryJson(r.stdout) || {};
      assert.equal(body.ok, true, 'replay body must carry ok:true after --force-replay');
      assert.equal(body.verb, 'reattest');
      assert.equal(body.force_replay, true,
        'emitted body must record force_replay:true so the override is audit-visible');
      assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
        'emitted body must persist the full sidecar_verify object');
      assert.equal(body.sidecar_verify.tamper_class, 'sidecar-corrupt',
        'sidecar_verify.tamper_class must be preserved through the --force-replay branch so auditors can see what was overridden');
      assert.equal(body.sidecar_verify_class, 'sidecar-corrupt',
        'sidecar_verify_class one-token label must be "sidecar-corrupt"');
    });

  test('Fix 3 — reattest --force-replay records sidecar_verify class for explicitly-unsigned + force_replay:true',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'aa-trust-replay-explicit-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestation(sid);
      assert.ok(att);
      fs.writeFileSync(att.sigFile, JSON.stringify({
        algorithm: 'unsigned',
        signed: false,
        signs_path: path.basename(att.jsonFile),
      }, null, 2));

      const r0 = cli(['reattest', sid, '--json']);
      assert.equal(r0.status, 6,
        `reattest must refuse an explicitly-unsigned sidecar without --force-replay (exit 6). Got status=${r0.status}. stderr=${r0.stderr.slice(0, 400)}`);

      const r = cli(['reattest', sid, '--force-replay', '--json']);
      assert.equal(r.status, 0,
        `reattest --force-replay must succeed against an explicitly-unsigned sidecar. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || {};
      assert.equal(body.ok, true);
      assert.equal(body.force_replay, true, 'emit body must record force_replay:true');
      assert.ok(
        body.sidecar_verify_class === 'explicitly-unsigned' ||
        body.sidecar_verify_class === 'unsigned-substitution',
        `sidecar_verify_class must be "explicitly-unsigned" or "unsigned-substitution"; got ${JSON.stringify(body.sidecar_verify_class)}`
      );
      assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
        'full sidecar_verify object must be persisted alongside the one-token class label');
      assert.equal(body.sidecar_verify.signed, false,
        'sidecar_verify.signed must be false on the unsigned path');
      assert.equal(body.sidecar_verify.verified, false,
        'sidecar_verify.verified must be false on the unsigned path');
      assert.equal(typeof body.sidecar_verify.reason, 'string',
        'sidecar_verify.reason must be a string operators can read');
    });
});


// ---- routed from renderer-and-reattest-traversal ----
require("node:test").describe("renderer-and-reattest-traversal", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from runtime-errors-and-vex-disposition ----
require("node:test").describe("runtime-errors-and-vex-disposition", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Tests for the audit-AA P1 closures:
 *
 *   AA P1-1  `algorithm: "unsigned"` sidecar substitution is now detected
 *            by both `attest verify` (exit 6 when private key present) and
 *            `cmdReattest` (requires --force-replay regardless).
 *   AA P1-2  Corrupt-JSON .sig sidecar surfaces as a structured tamper-class
 *            result rather than throwing through the dispatcher. Both
 *            `attest verify` and `cmdReattest` exit 6.
 *   AA P1-3  `lib/verify.js verifyManifestSignature()` consults
 *            `keys/EXPECTED_FINGERPRINT` BEFORE crypto.verify. Library
 *            callers (refresh-network, verify-shipped-tarball, downstream
 *            consumers) can no longer bypass the pin.
 *
 * Per the "coincidence-passing tests" rule: every exit-code assertion
 * is EXACT (assert.equal(r.status, 6)), never notEqual(0).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestation(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
  if (files.length === 0) return null;
  return { dir: attRoot, jsonFile: path.join(attRoot, files[0]), sigFile: path.join(attRoot, files[0] + '.sig') };
}

// ---------------------------------------------------------------------------
// AA P1-1 — `algorithm: "unsigned"` substitution detection
// ---------------------------------------------------------------------------

test('AA P1-1: reattest refuses an explicitly-unsigned attestation without --force-replay',
  { skip: !HAS_PRIV_KEY && 'private key required to produce a signed attestation that we then convert to unsigned' },
  () => {
    // Produce a signed attestation, swap the .sig for the unsigned stub
    // (mimics either substitution OR a legitimately-unsigned attestation
    // surfaced to a host with a private key). Reattest must refuse without
    // --force-replay regardless of host private-key state.
    const sid = 'aa-p11-unsigned-replay-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0, 'producer run must succeed');

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    // No --force-replay → exit 6.
    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest against an unsigned/substituted sidecar must exit 6 without --force-replay. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
  });

test('AA P1-1: reattest --force-replay accepts explicitly-unsigned and records sidecar_verify_class + force_replay',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key to create signed attestation we then re-sidecar' },
  () => {
    const sid = 'aa-p11-force-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    const r = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r.status, 0,
      `reattest --force-replay against an unsigned sidecar must succeed (exit 0). Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || {};
    assert.equal(body.force_replay, true, 'emit body must record force_replay:true');
    // The classification label captures WHICH override class was overridden.
    // Both "unsigned-substitution" (when private key present) and
    // "explicitly-unsigned" (no private key) are acceptable here — the host
    // private-key state determines which the verifier reports.
    assert.ok(
      body.sidecar_verify_class === 'explicitly-unsigned' || body.sidecar_verify_class === 'unsigned-substitution',
      `sidecar_verify_class must be "explicitly-unsigned" or "unsigned-substitution"; got ${JSON.stringify(body.sidecar_verify_class)}`
    );
  });
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
