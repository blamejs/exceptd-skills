'use strict';

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
