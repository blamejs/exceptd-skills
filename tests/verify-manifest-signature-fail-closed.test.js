'use strict';

/**
 * lib/verify.js manifest-signature path must FAIL CLOSED on the two states an
 * attacker can engineer with write access to keys/:
 *
 *   1. delete keys/public.pem        -> verifyManifestSignature returns no-key.
 *      loadManifestValidated() must THROW (not warn-and-return the unverified
 *      manifest) so a direct library caller can never receive an
 *      unauthenticated manifest. verifyAll()/verifyOne() short-circuit no-key
 *      earlier, so this guards the exported-API path.
 *   2. delete keys/EXPECTED_FINGERPRINT -> checkExpectedFingerprint returns
 *      no-pin. The pin ships in the tarball AND is committed, so its absence is
 *      tampering, not a legacy state: verifyManifestSignature must return
 *      status:'invalid' (pin_absent) rather than verifying against an unpinned
 *      (possibly swapped) public key. A MISSING pin fails closed
 *      UNCONDITIONALLY — KEYS_ROTATED governs a fingerprint MISMATCH (a new key
 *      plus a new pin), never a missing pin (a rotation updates the pin in
 *      place; it never removes it).
 *
 * The missing-pin contract is checked behaviorally via checkExpectedFingerprint
 * on a nonexistent pin path (no destructive mutation of the real keys); the
 * no-key branch is pinned structurally plus the live positive case.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
const verify = require('../lib/verify.js');

test('loadManifestValidated() throws on no-key (does not warn-and-return an unverified manifest)', () => {
  // The no-key branch must THROW, and the old warn-and-continue message must be
  // gone, so a refactor cannot silently reopen the gap.
  assert.match(SRC, /sigResult\.status === 'no-key'[\s\S]{0,800}?throw new Error\(/,
    'the no-key branch must THROW');
  assert.ok(!SRC.includes('WARN: cannot verify manifest_signature'),
    'the old no-key warn-and-continue message must be gone');
});

test('a missing key pin fails closed unconditionally (no-pin never carries a rotation override, even with KEYS_ROTATED=1)', () => {
  const saved = process.env.KEYS_ROTATED;
  // A uniquely-named (mkdtemp) directory; the pin path inside it intentionally
  // does NOT exist — checkExpectedFingerprint must treat that as no-pin.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-nopin-'));
  try {
    process.env.KEYS_ROTATED = '1';
    const noPin = verify.checkExpectedFingerprint({ sha256: 'SHA256:abc' }, path.join(dir, 'EXPECTED_FINGERPRINT'));
    assert.equal(noPin.status, 'no-pin');
    assert.equal(noPin.rotationOverride, undefined,
      'no-pin must NOT carry rotationOverride even with KEYS_ROTATED=1 — a missing pin fails closed (KEYS_ROTATED governs a MISMATCH, not a missing pin)');
  } finally {
    if (saved === undefined) delete process.env.KEYS_ROTATED; else process.env.KEYS_ROTATED = saved;
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // The source resolves no-pin directly to invalid (pin_absent) — the dead
  // `!pinResult.rotationOverride` guard is gone — and the no-pin reason no
  // longer dangles KEYS_ROTATED, which cannot apply to a missing pin.
  assert.match(SRC, /pinResult\.status === 'no-pin'\)/, 'no-pin is rejected directly, without a dead rotationOverride guard');
  assert.match(SRC, /pin_absent: true/, 'no-pin must resolve to status:invalid with pin_absent:true');
  assert.ok(!SRC.includes('set KEYS_ROTATED=1 for an intentional rotation'),
    'the old no-pin message suggesting KEYS_ROTATED for a missing pin must be gone');
  assert.match(SRC, /restore it from the package or version control/,
    'the no-pin reason must direct operators to restore the committed pin');
});

test('a fingerprint MISMATCH is the case KEYS_ROTATED governs (rotationOverride reflects the env var)', () => {
  // Write the pin into a uniquely-named (mkdtemp) directory, not a predictable
  // name in the OS temp dir.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-mm-pin-'));
  const tmpPin = path.join(dir, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(tmpPin, 'SHA256:A-DIFFERENT-PIN\n');
  const saved = process.env.KEYS_ROTATED;
  try {
    process.env.KEYS_ROTATED = '1';
    const mm = verify.checkExpectedFingerprint({ sha256: 'SHA256:live-key' }, tmpPin);
    assert.equal(mm.status, 'mismatch');
    assert.equal(mm.rotationOverride, true, 'a mismatch honors KEYS_ROTATED=1 as the rotation escape');
    process.env.KEYS_ROTATED = '0';
    const mm2 = verify.checkExpectedFingerprint({ sha256: 'SHA256:live-key' }, tmpPin);
    assert.equal(mm2.rotationOverride, false, 'without KEYS_ROTATED=1 a mismatch is not overridden');
  } finally {
    if (saved === undefined) delete process.env.KEYS_ROTATED; else process.env.KEYS_ROTATED = saved;
    fs.rmSync(tmpPin, { force: true });
  }
});

test('the live manifest still verifies valid (the fail-closed change does not break the real signed manifest)', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const r = verify.verifyManifestSignature(manifest);
  assert.equal(r.status, 'valid', `the committed manifest must verify valid against the committed key + pin; got ${JSON.stringify(r)}`);
});
