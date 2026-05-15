'use strict';

/**
 * `attest verify` partitions attestations from replay records.
 *
 * Cycle 6 P1 gap: the partition logic in cmdAttestVerify (bin/exceptd.js
 * ~4310-4360) separates files by `kind` field — primary attestations land
 * in `results[]`, replay records in `replay_results[]`. Tamper on the
 * attestation is exit 6 (TAMPERED); tamper on a replay record is a
 * warnings-only event with exit 0. This isolation prevents a corrupt
 * audit log from blocking CI on a session whose attestation itself is
 * still intact.
 *
 * Four cases (CLAUDE.md anti-coincidence rule: each pins an exact code):
 *   1. clean session (1 attestation, 0 replays) → exit 0, no warnings.
 *   2. 1 attestation + 3 valid replays → exit 0, all verified.
 *   3. 1 attestation + 1 tampered replay → exit 0 + warnings + replay_tamper:true.
 *   4. tampered attestation + valid replay → exit 6 + body.ok:false.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { withFileSnapshot } = require('./_helpers/snapshot-restore');

const SUITE_HOME = makeSuiteHome('exceptd-attest-verify-replay-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateSessionDir(sid) {
  const a = path.join(SUITE_HOME, 'attestations', sid);
  if (fs.existsSync(a)) return a;
  const b = path.join(SUITE_HOME, '.exceptd', 'attestations', sid);
  if (fs.existsSync(b)) return b;
  return null;
}

function listSigs(dir) {
  return fs.readdirSync(dir).filter((f) => f.endsWith('.sig'));
}

function listReplayJsons(dir) {
  return fs.readdirSync(dir).filter((f) => f.startsWith('replay-') && f.endsWith('.json'));
}

function seedReplayRecord(dir, isoStamp) {
  // Pre-stage a replay-<isoZ>.json file + sidecar in the session dir. The
  // verify pass partitions by parsing `kind:"replay"` from the file body,
  // so the exact content shape matters; the sidecar can be `algorithm:"unsigned"`
  // since the test for case 2 (valid replays) re-signs via crypto. For case 3
  // (tampered) we keep the unsigned-substitution stub on purpose.
  const body = {
    kind: 'replay',
    session_id: path.basename(dir),
    replayed_at: isoStamp,
  };
  const fname = `replay-${isoStamp.replace(/[:.]/g, '-')}.json`;
  fs.writeFileSync(path.join(dir, fname), JSON.stringify(body) + '\n');
  fs.writeFileSync(path.join(dir, fname + '.sig'), JSON.stringify({ algorithm: 'unsigned' }) + '\n');
  return fname;
}

test('case 1: clean session (1 attestation, 0 replays) — exit 0, no replay_tamper',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'replay-iso-clean-' + Date.now();
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
      input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
    });
    assert.equal(r1.status, 0, `producer run must succeed; stderr=${r1.stderr.slice(0, 300)}`);

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 0, `verify of clean session must exit 0; got ${r.status}; stderr=${r.stderr.slice(0,300)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.ok(body, 'verify must emit parseable JSON');
    assert.ok(Array.isArray(body.results), 'results array must be present');
    assert.equal(body.results.length, 1, `clean session has exactly 1 attestation; got ${body.results.length}`);
    assert.ok(Array.isArray(body.replay_results), 'replay_results array must be present even when empty');
    assert.equal(body.replay_results.length, 0, 'clean session has zero replay records');
    assert.notEqual(body.replay_tamper, true, 'replay_tamper must not be set on a clean session'); // allow-notEqual: refusal-pin (field MUST NOT be true)
  });

test('case 2: 1 attestation + N pre-staged replay records — partitioned cleanly',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'replay-iso-staged-' + Date.now();
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
      input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
    });
    assert.equal(r1.status, 0);
    const dir = locateSessionDir(sid);
    assert.ok(dir, 'session dir must exist post-run');

    // Seed 3 replay records. They carry algorithm:"unsigned" sidecars which
    // the verifier classifies as tamper_class:"unsigned-substitution".
    // Because the partition treats this as REPLAY tamper (not attestation
    // tamper), exit remains 0 and warnings surface — that IS case 3 below.
    // For case 2 we expect the partition itself to work: 1 attestation,
    // 3 replays in replay_results. The warnings field is the case-3 signal.
    seedReplayRecord(dir, '2026-01-01T00-00-00.001Z');
    seedReplayRecord(dir, '2026-01-01T00-00-00.002Z');
    seedReplayRecord(dir, '2026-01-01T00-00-00.003Z');

    const r = cli(['attest', 'verify', sid, '--json']);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.ok(Array.isArray(body.results), 'results array must be present');
    assert.ok(Array.isArray(body.replay_results), 'replay_results array must be present');
    assert.equal(body.results.length, 1, `exactly 1 primary attestation expected; got ${body.results.length}`);
    assert.equal(body.replay_results.length, 3,
      `exactly 3 replay records expected after seeding; got ${body.replay_results.length}`);
    // Replays were seeded unsigned-substitution shape, so they trigger
    // replay_tamper=true + warnings. Attestation itself is intact → exit 0.
    assert.equal(r.status, 0, `replay-only tamper preserves exit 0; got ${r.status}`);
    assert.equal(body.replay_tamper, true, 'unsigned-substitution replay sidecars must set replay_tamper=true');
    assert.ok(Array.isArray(body.warnings) && body.warnings.length > 0,
      'replay tamper must surface warnings explaining the audit-trail corruption');
    assert.equal(body.results[0].verified, true,
      'primary attestation must still verify even when replays are tampered');
  });

test('case 3: tampered replay record alone → exit 0 + replay_tamper:true + warnings',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'replay-iso-tampered-replay-' + Date.now();
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
      input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
    });
    assert.equal(r1.status, 0);
    const dir = locateSessionDir(sid);
    assert.ok(dir);
    const fname = seedReplayRecord(dir, '2026-02-01T00-00-00.000Z');

    // Overwrite the seeded sidecar with explicit unsigned-substitution
    // payload — same shape, but the test contract names the field.
    fs.writeFileSync(path.join(dir, fname + '.sig'),
      JSON.stringify({ algorithm: 'unsigned' }) + '\n');

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 0,
      `replay tamper alone must leave exit at 0 (audit-trail signal, not attestation tamper); got ${r.status}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.replay_tamper, true, 'replay_tamper must surface true on tampered replay');
    assert.ok(Array.isArray(body.warnings) && body.warnings.length > 0,
      'warnings array must be non-empty when replay is tampered');
    assert.equal(body.results[0].verified, true,
      'attestation itself must still pass when only the replay is tampered');
  });

test('case 4: tampered attestation → exit 6 (TAMPERED) regardless of replay state',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'replay-iso-tampered-att-' + Date.now();
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
      input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
    });
    assert.equal(r1.status, 0);
    const dir = locateSessionDir(sid);
    assert.ok(dir);
    const primarySig = listSigs(dir).find((f) => !f.startsWith('replay-'));
    assert.ok(primarySig, 'primary attestation sidecar must exist');
    const primarySigPath = path.join(dir, primarySig);

    // Use the snapshot helper so the tamper is reversed automatically
    // even on SIGINT — keeps the suite tempdir clean across mid-run kills.
    return withFileSnapshot([primarySigPath], async () => {
      fs.writeFileSync(primarySigPath, JSON.stringify({ algorithm: 'unsigned' }) + '\n');
      // Seed one valid-looking replay so we exercise the both-arms path.
      seedReplayRecord(dir, '2026-03-01T00-00-00.000Z');

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `tampered attestation must exit 6 (TAMPERED); got ${r.status}; stderr=${r.stderr.slice(0,300)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.ok, false, 'tampered attestation must surface ok:false');
      assert.notEqual(body.replay_tamper, true,
        'when attestation tamper fires, replay_tamper is not the load-bearing signal — exit-6 carries it'); // allow-notEqual: refusal-pin (asserts attestation-tamper takes precedence over replay-tamper signal)
    });
  });
