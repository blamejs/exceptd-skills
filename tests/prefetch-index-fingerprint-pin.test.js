'use strict';

/**
 * The --from-cache trust gate verifies _index.json.sig with verifyIndexSignature.
 * Every other signature-verifying ingest site cross-checks the live public key
 * against keys/EXPECTED_FINGERPRINT before crypto.verify, so a host-local
 * keys/public.pem swap paired with an attacker-signed _index.json.sig cannot
 * authenticate against the attacker's own key. verifyIndexSignature must apply
 * the same pin.
 *
 * The happy path is asserted end-to-end (sign with the real key, verify against
 * the real pin -> valid). The mismatch path is asserted against the exact
 * building blocks verifyIndexSignature now consumes — checkExpectedFingerprint
 * over publicKeyFingerprint, with an attacker key and a pin file the attacker
 * cannot satisfy — proving the gate refuses a swapped key.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const prefetch = require(path.join(ROOT, 'lib', 'prefetch.js'));
const { publicKeyFingerprint, checkExpectedFingerprint } = require(path.join(ROOT, 'lib', 'verify.js'));

test('verifyIndexSignature returns valid when the real key matches the real pin', () => {
  // The signing key on the working tree matches keys/EXPECTED_FINGERPRINT, so
  // a freshly-signed index must verify — confirming the new pin check passes
  // legitimate caches through rather than blocking them.
  if (!fs.existsSync(path.join(ROOT, '.keys', 'private.pem'))) {
    return; // no signing key available in this environment; nothing to assert
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-ok-'));
  try {
    fs.writeFileSync(
      path.join(dir, '_index.json'),
      JSON.stringify({ entries: { 'kev/x': { sha256: 'abc' } } }, null, 2) + '\n',
    );
    const s = prefetch.signIndex(dir);
    assert.equal(s.signed, true, 'index signed with the real key');
    const v = prefetch.verifyIndexSignature(dir);
    assert.equal(v.status, 'valid', `expected valid; got ${JSON.stringify(v)}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the pin gate refuses a swapped public key (attacker-signed index would not authenticate)', () => {
  // Generate an attacker keypair and a pin file naming a DIFFERENT (legitimate)
  // fingerprint. The pin check verifyIndexSignature performs is exactly this:
  // checkExpectedFingerprint(publicKeyFingerprint(<live public.pem>)).
  const attacker = crypto.generateKeyPairSync('ed25519');
  const legit = crypto.generateKeyPairSync('ed25519');
  const attackerPem = attacker.publicKey.export({ type: 'spki', format: 'pem' });
  const legitFp = publicKeyFingerprint(legit.publicKey.export({ type: 'spki', format: 'pem' }));

  const pinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-mismatch-'));
  try {
    const pinPath = path.join(pinDir, 'EXPECTED_FINGERPRINT');
    fs.writeFileSync(pinPath, legitFp.sha256 + '\n');

    const result = checkExpectedFingerprint(publicKeyFingerprint(attackerPem), pinPath);
    assert.equal(result.status, 'mismatch', 'swapped key must mismatch the pin');
    assert.equal(result.expected, legitFp.sha256);
    assert.notEqual(result.actual, legitFp.sha256);
    // Without KEYS_ROTATED=1 the rotation override stays false, so
    // verifyIndexSignature returns status:"invalid" on this branch.
    assert.equal(result.rotationOverride, process.env.KEYS_ROTATED === '1');
  } finally {
    fs.rmSync(pinDir, { recursive: true, force: true });
  }
});

test('the pin gate matches when the live fingerprint equals the pin', () => {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  const fp = publicKeyFingerprint(pem);
  const pinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-match-'));
  try {
    const pinPath = path.join(pinDir, 'EXPECTED_FINGERPRINT');
    fs.writeFileSync(pinPath, fp.sha256 + '\n');
    const result = checkExpectedFingerprint(publicKeyFingerprint(pem), pinPath);
    assert.equal(result.status, 'match');
  } finally {
    fs.rmSync(pinDir, { recursive: true, force: true });
  }
});
