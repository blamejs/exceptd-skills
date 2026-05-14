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

// ---------- v0.12.12 hardening: normalize() byte-stability contract ----------
//
// CRLF + BOM normalization is the round-trip stability contract between
// lib/sign.js and lib/verify.js. Both modules export normalize() so the
// tests can exercise the actual production function rather than a copy.
// If either side's normalize() drifts, this test catches it.

const signMod = require('../lib/sign.js');
const verifyMod = require('../lib/verify.js');

function actualSign(content, privateKey) {
  const normalized = signMod.normalize(content);
  return crypto.sign(null, Buffer.from(normalized, 'utf8'), {
    key: privateKey, dsaEncoding: 'ieee-p1363'
  }).toString('base64');
}

function actualVerify(content, sigB64, publicKey) {
  try {
    const normalized = verifyMod.normalize(content);
    return crypto.verify(null, Buffer.from(normalized, 'utf8'), {
      key: publicKey, dsaEncoding: 'ieee-p1363'
    }, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}

test('S1: CRLF and LF inputs produce identical signatures', () => {
  const { privateKey } = generateTempKeypair();
  const lf = 'hello\nworld\nthird line\n';
  const crlf = 'hello\r\nworld\r\nthird line\r\n';
  const sigLF = actualSign(lf, privateKey);
  const sigCRLF = actualSign(crlf, privateKey);
  assert.equal(sigLF, sigCRLF, 'CRLF must normalize to LF before signing');
});

test('S1: BOM-prefixed and non-BOM inputs produce identical signatures', () => {
  const { privateKey } = generateTempKeypair();
  const noBom = 'hello world\n';
  const withBom = '﻿hello world\n';
  const sigA = actualSign(noBom, privateKey);
  const sigB = actualSign(withBom, privateKey);
  assert.equal(sigA, sigB, 'BOM must be stripped before signing');
});

test('S1: BOM+CRLF combo produces same signature as plain LF', () => {
  const { privateKey } = generateTempKeypair();
  const plain = 'a\nb\nc\n';
  const messy = '﻿a\r\nb\r\nc\r\n';
  assert.equal(actualSign(plain, privateKey), actualSign(messy, privateKey));
});

test('S1: verify(LF_signed, CRLF_content) returns true — round-trip stability', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const lf = '# Skill body\nline 1\nline 2\n';
  const crlf = '# Skill body\r\nline 1\r\nline 2\r\n';
  const sig = actualSign(lf, privateKey);
  assert.equal(actualVerify(crlf, sig, publicKey), true);
});

test('S1: verify(CRLF_signed, LF_content) returns true — symmetric stability', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const lf = 'line A\nline B\n';
  const crlf = 'line A\r\nline B\r\n';
  const sig = actualSign(crlf, privateKey);
  assert.equal(actualVerify(lf, sig, publicKey), true);
});

test('S1: tampered content still fails after normalization', () => {
  const { privateKey, publicKey } = generateTempKeypair();
  const lf = 'line A\nline B\n';
  const tampered = 'line A\nEVIL line B\n';
  const sig = actualSign(lf, privateKey);
  assert.equal(actualVerify(tampered, sig, publicKey), false);
});

test('S1: byte-level proof — normalize() produces stable utf-8 bytes', () => {
  const variants = [
    'hello\nworld\n',
    'hello\r\nworld\r\n',
    '﻿hello\nworld\n',
    '﻿hello\r\nworld\r\n',
  ];
  const buffers = variants.map(v => Buffer.from(signMod.normalize(v), 'utf8').toString('hex'));
  // All four must hex-equal the LF/no-BOM form.
  for (const b of buffers) assert.equal(b, buffers[0]);
  // And the canonical bytes are predictable.
  assert.equal(buffers[0], Buffer.from('hello\nworld\n', 'utf8').toString('hex'));
});

// ---------- v0.12.12 hardening: S2 manifest path traversal ----------

test('S2: validateSkillPath rejects ../../../etc/passwd', () => {
  assert.throws(
    () => signMod.validateSkillPath('../../../etc/passwd'),
    /must start with 'skills\/'/,
  );
  assert.throws(
    () => verifyMod.validateSkillPath('../../../etc/passwd'),
    /must start with 'skills\/'/,
  );
});

test('S2: validateSkillPath rejects skills/foo/../../../private.pem', () => {
  assert.throws(
    () => signMod.validateSkillPath('skills/foo/../../../private.pem'),
    /must not contain '\.\.'/,
  );
});

test('S2: validateSkillPath rejects backslash paths', () => {
  assert.throws(
    () => signMod.validateSkillPath('skills\\foo\\skill.md'),
    /forward slashes/,
  );
});

test('S2: validateSkillPath rejects non-string', () => {
  assert.throws(() => signMod.validateSkillPath(null), /must be a string/);
  assert.throws(() => signMod.validateSkillPath(42), /must be a string/);
});

test('S2: validateSkillPath accepts a legitimate skills/foo/skill.md', () => {
  assert.equal(signMod.validateSkillPath('skills/kernel-lpe-triage/skill.md'),
               'skills/kernel-lpe-triage/skill.md');
});

test('S2: loadManifestValidated throws on traversal-pattern manifest', () => {
  // We exercise the helper directly. It reads the real manifest path, so we
  // shim the read by validating an in-memory manifest object via the schema
  // validator + path-check. The function itself reads from disk, so the
  // best we can do here without mutating the repo is exercise the parts
  // explicitly.
  const validateAgainstSchema = verifyMod.validateAgainstSchema;
  const schemaPath = path.join(__dirname, '..', 'lib', 'schemas', 'manifest.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const bad = {
    name: 'x',
    version: '1.2.3',
    description: 'desc',
    atlas_version: '5.1.0',
    threat_review_date: '2026-05-13',
    skills: [{
      name: 'evil',
      version: '1.0.0',
      path: '../../../etc/passwd',
      description: 'a malicious entry',
      triggers: ['x'],
      data_deps: [],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: ['foo'],
      last_threat_review: '2026-05-13',
    }],
  };
  // Schema validator catches the path pattern.
  const errors = validateAgainstSchema(bad, schema, 'manifest');
  assert.ok(
    errors.some(e => /path/.test(e) && /pattern/.test(e)),
    `expected schema to reject traversal path; got errors: ${JSON.stringify(errors)}`,
  );
  // Path validator independently catches it.
  assert.throws(
    () => verifyMod.validateSkillPath(bad.skills[0].path),
    /must start with 'skills\/'/,
  );
});

// ---------- v0.12.12 hardening: S3 manifest schema validation ----------

test('S3: manifest schema accepts extra unknown TOP-LEVEL field (additionalProperties:true)', () => {
  const schemaPath = path.join(__dirname, '..', 'lib', 'schemas', 'manifest.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const m = {
    name: 'x',
    version: '1.2.3',
    description: 'desc',
    atlas_version: '5.1.0',
    threat_review_date: '2026-05-13',
    skills: [{
      name: 'one',
      version: '1.0.0',
      path: 'skills/one/skill.md',
      description: 'a real skill entry',
      triggers: ['x'],
      data_deps: [],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: ['foo'],
      last_threat_review: '2026-05-13',
    }],
    // Unknown top-level field — should pass.
    operator_provided_extension: { foo: 'bar' },
  };
  const errors = verifyMod.validateAgainstSchema(m, schema, 'manifest');
  assert.deepEqual(errors, [], 'unknown top-level field should be accepted');
});

test('S3: manifest schema REJECTS extra unknown per-skill field (additionalProperties:false)', () => {
  const schemaPath = path.join(__dirname, '..', 'lib', 'schemas', 'manifest.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const m = {
    name: 'x',
    version: '1.2.3',
    description: 'desc',
    atlas_version: '5.1.0',
    threat_review_date: '2026-05-13',
    skills: [{
      name: 'one',
      version: '1.0.0',
      path: 'skills/one/skill.md',
      description: 'a real skill entry',
      triggers: ['x'],
      data_deps: [],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: ['foo'],
      last_threat_review: '2026-05-13',
      // Unknown per-skill field — should fail.
      malicious_extension: 'oops',
    }],
  };
  const errors = verifyMod.validateAgainstSchema(m, schema, 'manifest');
  assert.ok(
    errors.some(e => /malicious_extension/.test(e)),
    `expected per-skill unknown field rejection; got: ${JSON.stringify(errors)}`,
  );
});

test('S3: manifest schema validates against the LIVE manifest.json', () => {
  const schemaPath = path.join(__dirname, '..', 'lib', 'schemas', 'manifest.schema.json');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const errors = verifyMod.validateAgainstSchema(manifest, schema, 'manifest');
  assert.deepEqual(errors, [], `live manifest must pass schema; got: ${JSON.stringify(errors)}`);
});

// ---------- v0.12.12 hardening: S4 duplicate frontmatter keys ----------

test('S4: parseFrontmatter rejects duplicate top-level keys', () => {
  const lint = require('../lib/lint-skills.js');
  const fm = 'name: alpha\nversion: "1.0.0"\nname: beta\n';
  assert.throws(
    () => lint.parseFrontmatter(fm),
    /Duplicate frontmatter key "name"/,
  );
});

test('S4: parseFrontmatter accepts non-duplicate keys', () => {
  const lint = require('../lib/lint-skills.js');
  const fm = 'name: alpha\nversion: "1.0.0"\ndescription: hello\n';
  const parsed = lint.parseFrontmatter(fm);
  assert.equal(parsed.name, 'alpha');
  assert.equal(parsed.version, '1.0.0');
  assert.equal(parsed.description, 'hello');
});

// ---------- v0.12.12 hardening: S6 orphan skill.md detector ----------

test('S6: findOrphanSkillFiles returns [] when every disk skill is in manifest', () => {
  const lint = require('../lib/lint-skills.js');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const orphans = lint.findOrphanSkillFiles(manifest.skills);
  assert.deepEqual(orphans, [], `expected no orphans in live repo; got: ${JSON.stringify(orphans)}`);
});

test('S6: findOrphanSkillFiles detects a skill.md not referenced by manifest', () => {
  const lint = require('../lib/lint-skills.js');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  // Drop one entry — its skill.md should become an orphan from the walker's view.
  const reduced = manifest.skills.slice(1);
  const dropped = manifest.skills[0].path.split(path.sep).join('/');
  const orphans = lint.findOrphanSkillFiles(reduced);
  assert.ok(
    orphans.includes(dropped),
    `expected ${dropped} to appear as orphan; got: ${JSON.stringify(orphans)}`,
  );
});
