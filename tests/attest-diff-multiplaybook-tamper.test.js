'use strict';

/**
 * Regression: `attest diff` must verify the A-side attestation's ACTUAL signed
 * file, not a hardcoded attestation.json. A multi-playbook (run-all) session
 * writes per-playbook `<id>.json` + `<id>.json.sig` and NO attestation.json —
 * so the hardcoded path resolved to a missing file and reported
 * reason:"no .sig sidecar", a benign state that let a forged run-all A-side
 * pass diff at exit 0. The A-side now resolves to its real file, so a forged
 * evidence_hash (with the stale .sig left in place) is caught and refused
 * (exit 6 TAMPERED, ok:false, a_sidecar_verify.signed:true + verified:false).
 *
 * Covered: the `--against` branch AND the default (no --against) branch, each
 * paired with an untampered positive control so neither can pass by
 * coincidence. Exact exit-code + content-shape assertions per the
 * anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-multipb-');
const cli = makeCli(SUITE_HOME);
const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

const TAMPERED = EXIT_CODES.TAMPERED; // 6

function sessionDir(sid) {
  const cands = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  return cands.find((p) => fs.existsSync(p)) || null;
}

function lastJson(s) {
  return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
}

/**
 * Produce a single signed attestation via `run`, then reshape its session dir
 * into the run-all layout: copy attestation.json → <playbook>.json (same bytes,
 * so its Ed25519 signature stays valid) and remove attestation.json. The result
 * is a multi-playbook-shaped session with NO attestation.json — exactly what
 * run-all writes and what the hardcoded-path bug failed to verify.
 */
function makeMultiPlaybookSession(sid, playbook) {
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r = cli(['run', playbook, '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
  const dir = sessionDir(sid);
  assert.ok(dir, `attestation dir must exist after producer run for ${sid}`);

  const canonical = path.join(dir, 'attestation.json');
  const canonicalSig = canonical + '.sig';
  assert.ok(fs.existsSync(canonical), 'producer run must write attestation.json');
  assert.ok(fs.existsSync(canonicalSig), 'producer run must write attestation.json.sig');

  const perPlaybook = path.join(dir, `${playbook}.json`);
  const perPlaybookSig = perPlaybook + '.sig';
  // Same bytes → the signature over those bytes remains valid under the new name.
  fs.copyFileSync(canonical, perPlaybook);
  fs.copyFileSync(canonicalSig, perPlaybookSig);
  fs.rmSync(canonical);
  fs.rmSync(canonicalSig);

  return { dir, jsonFile: perPlaybook, sigFile: perPlaybookSig };
}

function forgeEvidenceHash(jsonFile) {
  const doc = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
  doc.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
  // Leave the .sig untouched → signature no longer matches the bytes.
  fs.writeFileSync(jsonFile, JSON.stringify(doc, null, 2));
}

test('attest diff --against verifies a run-all A-side by its real file and refuses tamper (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const a = 'multipb-a-' + Date.now();
    const b = 'multipb-b-' + Date.now();
    const aSess = makeMultiPlaybookSession(a, 'library-author');
    makeMultiPlaybookSession(b, 'library-author');

    // Positive control: an untampered run-all A-side diffs cleanly, exit 0,
    // and surfaces a VERIFIED a_sidecar_verify (proving the resolved-file
    // path actually found and verified the per-playbook signature — not the
    // pre-fix "no .sig sidecar" benign miss).
    const ok = cli(['attest', 'diff', a, '--against', b, '--json']);
    assert.equal(ok.status, 0, `clean run-all diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
    const okBody = lastJson(ok.stdout);
    assert.ok(okBody.a_sidecar_verify && typeof okBody.a_sidecar_verify === 'object',
      'clean diff must surface an a_sidecar_verify object');
    assert.equal(okBody.a_sidecar_verify.signed, true, 'A-side must be recognized as signed');
    assert.equal(okBody.a_sidecar_verify.verified, true,
      'untampered run-all A-side must VERIFY — pre-fix it reported no .sig sidecar');

    // Tamper the run-all A-side (forge evidence_hash, keep the stale .sig).
    forgeEvidenceHash(aSess.jsonFile);

    const r = cli(['attest', 'diff', a, '--against', b, '--json']);
    assert.equal(r.status, TAMPERED,
      `forged run-all A-side must exit ${TAMPERED} (TAMPERED), not 0/drifted. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
    assert.equal(body.verb, 'attest diff');
    assert.ok(body.a_sidecar_verify
      && body.a_sidecar_verify.signed === true
      && body.a_sidecar_verify.verified === false,
      'a_sidecar_verify must show the tampered A-side (signed:true, verified:false) — NOT reason:"no .sig sidecar"');
    assert.notEqual(body.a_sidecar_verify.reason, 'no .sig sidecar',
      'the bug is the benign "no .sig sidecar" miss; the fix must report a real signature failure');
  });

test('attest diff (no --against) verifies a run-all A-side by its real file and refuses tamper (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    // Create a PRIOR first so findLatestAttestation auto-selects it as B-side,
    // then the session under test second.
    const prior = 'multipb-prior-' + Date.now();
    makeMultiPlaybookSession(prior, 'mcp');
    const a = 'multipb-self-' + (Date.now() + 1);
    const aSess = makeMultiPlaybookSession(a, 'mcp');

    // Positive control: no --against, untampered → exit 0 with a verified A-side.
    const ok = cli(['attest', 'diff', a, '--json']);
    assert.equal(ok.status, 0, `clean no-against diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
    const okBody = lastJson(ok.stdout);
    assert.ok(okBody.a_sidecar_verify, 'no-against clean diff must surface a_sidecar_verify');
    assert.equal(okBody.a_sidecar_verify.verified, true,
      'untampered run-all A-side must verify in the no-against branch too');

    // Tamper the A-side; the default branch must now refuse (pre-fix it never
    // verified the A-side sidecar against the real file and exited 0).
    forgeEvidenceHash(aSess.jsonFile);

    const r = cli(['attest', 'diff', a, '--json']);
    assert.equal(r.status, TAMPERED,
      `forged run-all A-side (no --against) must exit ${TAMPERED}. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
    assert.ok(body.a_sidecar_verify
      && body.a_sidecar_verify.signed === true
      && body.a_sidecar_verify.verified === false,
      'a_sidecar_verify must show the tampered A-side (signed:true, verified:false)');
    assert.notEqual(body.a_sidecar_verify.reason, 'no .sig sidecar',
      'must report a real signature failure, not the benign no-.sig miss');
  });
