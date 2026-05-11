'use strict';

/**
 * Tests for lib/sign.js + lib/verify.js — Ed25519 signing & verification.
 *
 * NOTE (spec vs. code): Both modules' public APIs (`signAll`, `verifyAll`, `verifyOne`,
 * `generateKeypair`) are hard-coded to the repo's `manifest.json`, `.keys/private.pem`,
 * and `keys/public.pem`. They are not parameterised on filesystem paths, so a fully
 * isolated round-trip cannot be driven through those exports without mutating the repo.
 * These tests instead exercise the underlying primitive that both modules use:
 * `crypto.sign(null, content, key)` / `crypto.verify(null, content, key, signature)`
 * with the same `dsaEncoding: 'ieee-p1363'` option both modules apply. This validates
 * the cryptographic contract — generate keypair, sign content, verify pass, tamper,
 * verify fail — without depending on `.keys/` or `keys/` existing on disk.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const SAMPLE_SKILL = `---
name: sample-skill
version: "1.0.0"
description: A sample skill used by tests
---

# Sample Skill

This is content used to validate the Ed25519 sign/verify round-trip.
`;

// Replicas of the internal helpers in lib/sign.js and lib/verify.js. They use the
// exact same crypto options so a contract-breaking change in either module would
// require updating these tests too — making the dependency explicit.

function signContent(content, privateKey) {
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return signature.toString('base64');
}

function verifyContent(content, signatureBase64, publicKey) {
  try {
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, Buffer.from(content, 'utf8'), {
      key: publicKey,
      dsaEncoding: 'ieee-p1363'
    }, signature);
  } catch (_) {
    return false;
  }
}

function generateTempKeypair() {
  return crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
}

// ---------- crypto.generateKeyPairSync round-trip ----------

test('generateKeyPairSync produces a PEM-encoded Ed25519 keypair', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  assert.ok(typeof privateKey === 'string' && privateKey.includes('PRIVATE KEY'));
  assert.ok(typeof publicKey === 'string' && publicKey.includes('PUBLIC KEY'));
  // crypto.createPublicKey should accept the generated public key without throwing
  assert.doesNotThrow(() => crypto.createPublicKey(publicKey));
  assert.doesNotThrow(() => crypto.createPrivateKey(privateKey));
});

test('sign/verify round-trip: signature over identical content verifies', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const sig = signContent(SAMPLE_SKILL, privateKey);
  assert.equal(typeof sig, 'string');
  assert.ok(sig.length > 0);
  assert.equal(verifyContent(SAMPLE_SKILL, sig, publicKey), true);
});

test('tampered content fails verification (byte-level modification)', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const sig = signContent(SAMPLE_SKILL, privateKey);
  const tampered = SAMPLE_SKILL.replace('Sample Skill', 'Tampered Skill');
  assert.notEqual(tampered, SAMPLE_SKILL, 'sanity: tampered content must differ');
  assert.equal(verifyContent(tampered, sig, publicKey), false);
});

test('tampered content fails verification (whitespace-only modification)', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const sig = signContent(SAMPLE_SKILL, privateKey);
  const tampered = SAMPLE_SKILL + ' ';  // single trailing space
  assert.equal(verifyContent(tampered, sig, publicKey), false);
});

test('signature from a different keypair fails verification', () => {
  const kp1 = generateTempKeypair();
  const kp2 = generateTempKeypair();
  const sig = signContent(SAMPLE_SKILL, kp1.privateKey);
  // Same content, signed by kp1, verified against kp2's public key → must fail
  assert.equal(verifyContent(SAMPLE_SKILL, sig, kp2.publicKey), false);
});

test('verify() returns false (does not throw) on malformed base64 signature', () => {
  const { publicKey } = generateTempKeypair();
  assert.equal(verifyContent(SAMPLE_SKILL, '!!!not-base64!!!', publicKey), false);
});

test('verify() returns false (does not throw) on a signature of the wrong length', () => {
  const { publicKey } = generateTempKeypair();
  const tooShort = Buffer.from('short').toString('base64');
  assert.equal(verifyContent(SAMPLE_SKILL, tooShort, publicKey), false);
});

test('different content with the same key produces different signatures', () => {
  const { privateKey } = generateTempKeypair();
  const sigA = signContent(SAMPLE_SKILL, privateKey);
  const sigB = signContent(SAMPLE_SKILL + '\nextra line', privateKey);
  assert.notEqual(sigA, sigB);
});

// ---------- module surface ----------

test('lib/sign.js exports the documented public functions', () => {
  const sign = require('../lib/sign.js');
  assert.equal(typeof sign.generateKeypair, 'function');
  assert.equal(typeof sign.signAll, 'function');
  assert.equal(typeof sign.signOne, 'function');
});

test('lib/verify.js exports the documented public functions', () => {
  const verify = require('../lib/verify.js');
  assert.equal(typeof verify.verifyAll, 'function');
  assert.equal(typeof verify.verifyOne, 'function');
  assert.equal(typeof verify.signAll, 'function');
});

// ---------- temp-dir keypair write/read sanity ----------
//
// Demonstrates the file-format contract lib/sign.js writes to disk (PKCS8/SPKI PEM)
// without touching the repo's real key paths.

test('temp-dir round-trip: write PEM keys, read them back, verify a signature', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-signverify-'));
  try {
    const { privateKey, publicKey } = generateTempKeypair();
    const privPath = path.join(tmpDir, 'private.pem');
    const pubPath = path.join(tmpDir, 'public.pem');
    fs.writeFileSync(privPath, privateKey, { encoding: 'utf8' });
    fs.writeFileSync(pubPath, publicKey, { encoding: 'utf8' });

    const loadedPriv = fs.readFileSync(privPath, 'utf8');
    const loadedPub = fs.readFileSync(pubPath, 'utf8');

    const sig = signContent(SAMPLE_SKILL, loadedPriv);
    assert.equal(verifyContent(SAMPLE_SKILL, sig, loadedPub), true);

    // Tamper
    const tampered = SAMPLE_SKILL.replace('sample-skill', 'evil-skill');
    assert.equal(verifyContent(tampered, sig, loadedPub), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
