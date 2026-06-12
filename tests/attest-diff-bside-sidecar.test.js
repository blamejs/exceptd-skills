'use strict';

/**
 * Regression: `attest diff <A> --against <B>` must verify the B-side
 * (comparison) attestation's sidecar, not only the A-side. Pre-fix it emitted
 * a single A-side `sidecar_verify` and exited 0 even when the --against
 * attestation was forged — the drift verdict was computed against tampered
 * input under a green sidecar line. It now verifies both sides, surfaces
 * a_/b_sidecar_verify, and refuses (exit 6 TAMPERED, ok:false) on either side
 * tampered unless --force-replay — matching reattest's refusal contract.
 *
 * Exact exit-code + content-shape assertions per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-bside-');
const cli = makeCli(SUITE_HOME);
const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

function locate(sid) {
  const cands = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const dir = cands.find((p) => fs.existsSync(p));
  if (!dir) return null;
  const f = fs.readdirSync(dir).filter((x) => x.endsWith('.json') && !x.endsWith('.sig'))[0];
  return f ? { dir, jsonFile: path.join(dir, f), sigFile: path.join(dir, f + '.sig') } : null;
}

function makeSession(sid) {
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
  const att = locate(sid);
  assert.ok(att, `attestation must exist after producer run for ${sid}`);
  return att;
}

function lastJson(s) {
  return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
}

test('attest diff --against verifies the B-side sidecar and refuses a tampered comparison (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const a = 'adiff-a-' + Date.now();
    const b = 'adiff-b-' + Date.now();
    makeSession(a);
    const bAtt = makeSession(b);

    // Baseline: a clean diff exits 0 and surfaces a verified B-side.
    const ok = cli(['attest', 'diff', a, '--against', b, '--json']);
    assert.equal(ok.status, 0, `clean diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
    const okBody = lastJson(ok.stdout);
    assert.ok(okBody.b_sidecar_verify && typeof okBody.b_sidecar_verify === 'object',
      'clean diff must surface a b_sidecar_verify object');
    assert.equal(okBody.b_sidecar_verify.verified, true, 'clean B-side sidecar must verify');

    // Tamper the B-side attestation.json (keep its .sig) → signature mismatch.
    const forged = JSON.parse(fs.readFileSync(bAtt.jsonFile, 'utf8'));
    forged.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
    fs.writeFileSync(bAtt.jsonFile, JSON.stringify(forged, null, 2));

    const r = cli(['attest', 'diff', a, '--against', b, '--json']);
    assert.equal(r.status, 6,
      `diff against a tampered B-side must exit 6 (TAMPERED), not 0. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
    assert.equal(body.verb, 'attest diff');
    assert.ok(body.b_sidecar_verify
      && body.b_sidecar_verify.signed === true
      && body.b_sidecar_verify.verified === false,
      'b_sidecar_verify must show the tampered B-side (signed:true, verified:false)');

    // --force-replay overrides and still records the failed B-side verify.
    const f = cli(['attest', 'diff', a, '--against', b, '--force-replay', '--json']);
    assert.equal(f.status, 0, `--force-replay must override the B-side tamper refusal; got ${f.status}. stderr=${f.stderr.slice(0, 300)}`);
    const fBody = lastJson(f.stdout);
    assert.equal(fBody.b_sidecar_verify.verified, false,
      'force-replay output must still record the failed B-side verify for audit');
  });
