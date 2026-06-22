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
