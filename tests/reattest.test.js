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


// ---- routed from reattest-pin-and-persist ----
require("node:test").describe("reattest-pin-and-persist", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/reattest-pin-and-persist.test.js
 *
 * Two trust-boundary regressions on the attestation surface:
 *
 *   1. A keys/public.pem failing the EXPECTED_FINGERPRINT pin must be a
 *      TAMPER class, not a benign "unsigned attestation" config state.
 *      verifyAttestationSidecar tags the pin-failure return with
 *      tamper_class:"fingerprint-mismatch"; the shared replay-refusal
 *      predicate and the sidecar classifier must both honour it —
 *      otherwise reattest replays against a swapped key while the sibling
 *      `attest verify` correctly refuses.
 *
 *   2. persistAttestation's create path must not orphan the placed body
 *      when the sidecar rename fails after the body landed: an orphaned
 *      unsigned body holds the slot forever (every retry collides EEXIST,
 *      verification reports the attestation unsigned).
 *
 * Exit-code/predicate assertions are exact; every field-presence check is
 * paired with a content-shape check.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const cliMod = require(path.join(ROOT, 'bin', 'exceptd.js'));

test('replay-refusal predicate treats every tamper class as tamper, benign states as benign', () => {
  const tampered = [
    { signed: true, verified: false, reason: 'signature mismatch' },
    { signed: false, verified: false, tamper_class: 'sidecar-corrupt', reason: 'sidecar JSON parse failed' },
    { signed: false, verified: false, tamper_class: 'unsigned-substitution', reason: 'unsigned sidecar on signing host' },
    { signed: false, verified: false, tamper_class: 'algorithm-unsupported', reason: 'algorithm "none"' },
    { signed: false, verified: false, tamper_class: 'fingerprint-mismatch', reason: 'EXPECTED_FINGERPRINT mismatch: live=A pin=B' },
  ];
  for (const v of tampered) {
    assert.equal(cliMod._isTamperedSidecarVerify(v), true,
      `must refuse replay for ${v.tamper_class || 'signed-but-invalid'}`);
  }
  const benign = [
    { signed: true, verified: true },
    { signed: false, verified: false, reason: 'no .sig sidecar' },
    { signed: false, verified: false, reason: 'attestation explicitly unsigned (no private key on host)' },
    null,
    undefined,
  ];
  for (const v of benign) {
    assert.equal(cliMod._isTamperedSidecarVerify(v), false,
      `must not classify ${v ? JSON.stringify(v).slice(0, 60) : String(v)} as tamper`);
  }
});

test('sidecar classifier labels the pin-failure class', () => {
  const label = cliMod._classifySidecarVerify({
    signed: false, verified: false,
    tamper_class: 'fingerprint-mismatch',
    reason: 'EXPECTED_FINGERPRINT mismatch: live=A pin=B',
  });
  assert.equal(label, 'fingerprint-mismatch');
});

test('verifyAttestationSidecar pin-failure return carries the tamper class (source wiring)', () => {
  // The pin failure cannot be triggered end-to-end without swapping the
  // repository's own keys/public.pem (forbidden in tests), so pin the
  // wiring structurally: inside verifyAttestationSidecar, the pinError
  // branch must return tamper_class:"fingerprint-mismatch".
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnIdx = src.indexOf('function verifyAttestationSidecar(');
  assert.notEqual(fnIdx, -1, 'verifyAttestationSidecar must exist'); // allow-notEqual: refusal-pin (structural existence check)
  const window = src.slice(fnIdx, fnIdx + 2500);
  assert.match(window, /assertExpectedFingerprint/,
    'the sidecar verifier must consult the fingerprint pin');
  assert.match(window, /tamper_class:\s*"fingerprint-mismatch"/,
    'the pin-failure return must carry tamper_class:"fingerprint-mismatch" so consumers refuse replay');
});

test('persistAttestation releases the slot when the sidecar cannot be placed after the body landed', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'persist-orphan-'));
  const prevHome = process.env.EXCEPTD_HOME;
  process.env.EXCEPTD_HOME = tmp;
  try {
    const sid = 'orphan-slot-check';
    const sessionDir = path.join(tmp, 'attestations', sid);
    fs.mkdirSync(sessionDir, { recursive: true });
    const bodyPath = path.join(sessionDir, 'kernel.json');
    // Block the sidecar destination with a DIRECTORY: the body hard-link
    // succeeds, the sidecar rename onto a directory fails on every
    // platform, and the create path must then release the slot.
    fs.mkdirSync(bodyPath + '.sig');

    const args = {
      sessionId: sid,
      playbookId: 'kernel',
      directiveId: 'all-catalogued-kernel-cves',
      evidenceHash: '0'.repeat(64),
      operator: 'fixture',
      operatorConsent: { explicit: true },
      submission: { signals: {} },
      runOpts: {},
      forceOverwrite: false,
      filename: 'kernel.json',
    };
    const failed = cliMod.persistAttestation(args);
    assert.equal(failed.ok, false, 'sidecar placement failure must not report success');
    assert.equal(typeof failed.error, 'string');
    assert.match(failed.error, /Failed to write attestation/,
      'the failure surfaces as the structured write-failure envelope');
    assert.equal(fs.existsSync(bodyPath), false,
      'the placed body must be removed so the slot is not held by an orphaned unsigned attestation');

    // Once the obstruction is gone, the same create succeeds cleanly —
    // proving the failed attempt left no EEXIST residue.
    fs.rmdirSync(bodyPath + '.sig');
    const r = cliMod.persistAttestation(args);
    assert.equal(r.ok, true, `retry after obstruction removal must succeed; got ${JSON.stringify(r).slice(0, 200)}`);
    assert.equal(fs.existsSync(bodyPath), true, 'body placed');
    assert.equal(fs.statSync(bodyPath + '.sig').isFile(), true, 'sidecar placed as a file');
  } finally {
    if (prevHome === undefined) delete process.env.EXCEPTD_HOME;
    else process.env.EXCEPTD_HOME = prevHome;
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* tempdir cleanup is best-effort */ }
  }
});
});
