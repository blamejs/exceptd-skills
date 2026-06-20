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
 *      (possibly swapped) public key. KEYS_ROTATED=1 stays the rotation escape.
 *
 * Behavioral testing would require removing the real keys (a destructive,
 * CI-divergent filesystem mutation), so the contract is pinned structurally on
 * the source plus the live positive case (the real manifest still verifies).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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

test('verifyManifestSignature rejects a missing key pin (no-pin => invalid, not verify-against-unpinned-key)', () => {
  assert.match(SRC, /pinResult\.status === 'no-pin' && !pinResult\.rotationOverride/,
    'no-pin must be rejected unless KEYS_ROTATED=1 (rotationOverride)');
  assert.match(SRC, /pin_absent: true/, 'no-pin must resolve to status:invalid with pin_absent:true');
});

test('the live manifest still verifies valid (the fail-closed change does not break the real signed manifest)', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const r = verify.verifyManifestSignature(manifest);
  assert.equal(r.status, 'valid', `the committed manifest must verify valid against the committed key + pin; got ${JSON.stringify(r)}`);
});
