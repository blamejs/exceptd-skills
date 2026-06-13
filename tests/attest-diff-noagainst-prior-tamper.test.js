'use strict';

/**
 * Regression: `attest diff <session>` WITHOUT --against auto-selects the most
 * recent prior attestation for the same playbook and computes the drift
 * verdict from its evidence_hash. Pre-fix this branch verified only the A-side
 * sidecar and NEVER the auto-selected prior — so a forged prior produced a
 * drift verdict at exit 0 under a green A-side line. It now verifies the
 * prior's actual file (prior.file) and refuses on either side tampered
 * (exit 6 TAMPERED, ok:false), matching the --against branch's contract.
 *
 * Uses ordinary single-`run` sessions (attestation.json) so this isolates the
 * no-against prior-verify gap from the run-all A-side resolution. Exact
 * exit-code + content-shape assertions per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-noagainst-');
const cli = makeCli(SUITE_HOME);
const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

const TAMPERED = EXIT_CODES.TAMPERED; // 6

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

function makeSession(sid, playbook) {
  // crypto gates on a Linux-platform precondition; satisfy it so the producer
  // run proceeds (and signs an attestation) regardless of the test host's OS.
  const sub = JSON.stringify({ precondition_checks: { 'linux-platform': true }, observations: {}, verdict: { classification: 'not_detected' } });
  const r = cli(['run', playbook, '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
  const att = locate(sid);
  assert.ok(att, `attestation must exist after producer run for ${sid}`);
  return att;
}

function lastJson(s) {
  return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
}

test('attest diff (no --against) verifies the auto-selected prior and refuses a tampered prior (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    // Prior must exist FIRST so it is the most-recent prior for the playbook;
    // the session under test is created after it.
    const prior = 'noagainst-prior-' + Date.now();
    const priorAtt = makeSession(prior, 'crypto');
    const a = 'noagainst-self-' + (Date.now() + 1);
    makeSession(a, 'crypto');

    // Positive control: untampered prior → exit 0 and a VERIFIED b_sidecar_verify.
    const ok = cli(['attest', 'diff', a, '--json']);
    assert.equal(ok.status, 0, `clean no-against diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
    const okBody = lastJson(ok.stdout);
    assert.ok(okBody.b_sidecar_verify && typeof okBody.b_sidecar_verify === 'object',
      'no-against clean diff must surface a b_sidecar_verify object (prior was never verified pre-fix)');
    assert.equal(okBody.b_sidecar_verify.verified, true,
      'untampered prior (B-side) must verify');

    // Tamper the prior (B-side): forge its evidence_hash, keep its .sig.
    const forged = JSON.parse(fs.readFileSync(priorAtt.jsonFile, 'utf8'));
    forged.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
    fs.writeFileSync(priorAtt.jsonFile, JSON.stringify(forged, null, 2));

    const r = cli(['attest', 'diff', a, '--json']);
    assert.equal(r.status, TAMPERED,
      `a tampered auto-selected prior must exit ${TAMPERED} (TAMPERED), not 0/drifted. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
    assert.equal(body.verb, 'attest diff');
    assert.ok(body.b_sidecar_verify
      && body.b_sidecar_verify.signed === true
      && body.b_sidecar_verify.verified === false,
      'b_sidecar_verify must show the tampered prior (signed:true, verified:false)');

    // --force-replay overrides and still records the failed prior verify.
    const f = cli(['attest', 'diff', a, '--force-replay', '--json']);
    assert.equal(f.status, 0, `--force-replay must override the prior tamper refusal; got ${f.status}. stderr=${f.stderr.slice(0, 300)}`);
    const fBody = lastJson(f.stdout);
    assert.equal(fBody.b_sidecar_verify.verified, false,
      'force-replay output must still record the failed prior verify for audit');
  });
