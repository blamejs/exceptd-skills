'use strict';

/**
 * Tests for the v0.12.19 audit-O / audit-Q / audit-R P1 closures:
 *
 *   - Audit O P1-A: manifest_signature no longer carries `signed_at`
 *                   (replay-then-rewrite-signed_at attack class closed).
 *   - Audit O P1-B + Q P1: refresh-network verifies tarball manifest_signature
 *                   against the LOCAL public key. Tampered envelope refused.
 *   - Audit O P1-C: verify-shipped-tarball exports an in-line verifier and
 *                   uses it against the EXTRACTED manifest before passing
 *                   the publish gate.
 *   - Audit O P1-D: manifest-unsigned warning is deduplicated via
 *                   process.emitWarning() with a stable code.
 *   - Audit O P1-E: manifest_signature.algorithm field MUST equal 'Ed25519'
 *                   (missing or empty is refused, not silently accepted).
 *   - Audit Q P1 + R F6: bin/exceptd.js exposes assertExpectedFingerprint
 *                   and calls it from the attest verify / reattest sites.
 *   - Audit P P1-C: bin/exceptd.js exposes a normalizeAttestationBytes()
 *                   helper and uses it at sign + verify sites.
 *   - Audit Q P2 (missing-sidecar): cmdReattest refuses to replay when the
 *                   .sig sidecar is absent unless --force-replay is set.
 *   - Audit Q P2 (force-replay audit trail): reattest's emitted body carries
 *                   sidecar_verify + force_replay on every code path so
 *                   auditors see the override happened.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const signMod = require(path.join(ROOT, 'lib', 'sign.js'));
const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
const refreshMod = require(path.join(ROOT, 'lib', 'refresh-network.js'));
const tarballMod = require(path.join(ROOT, 'scripts', 'verify-shipped-tarball.js'));

function genKeypair() {
  return crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
}

// --- Audit O P1-A: signed_at must be absent from manifest_signature ---

test('O P1-A: signCanonicalManifest no longer emits signed_at', () => {
  const { privateKey } = genKeypair();
  const manifest = {
    name: 'x', version: '1.0.0', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  const sig = signMod.signCanonicalManifest(manifest, privateKey);
  assert.equal(sig.algorithm, 'Ed25519');
  assert.equal(typeof sig.signature_base64, 'string');
  assert.ok(
    !('signed_at' in sig),
    'signed_at must NOT appear on manifest_signature — it was stripped from the signed ' +
    'canonical bytes, so retaining it on the output object gave replay-then-rewrite-signed_at ' +
    'false freshness authority. Drop it entirely; freshness lives outside the signed bytes.'
  );
});

test('O P1-A: live manifest.json has no signed_at on manifest_signature', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.ok(manifest.manifest_signature, 'live manifest must carry manifest_signature');
  assert.ok(
    !('signed_at' in manifest.manifest_signature),
    'live manifest_signature must not carry signed_at — re-run sign-all after the audit-O fix'
  );
});

// --- Audit O P1-E: algorithm must be strictly 'Ed25519' ---

test('O P1-E: verifyManifestSignature refuses when algorithm is MISSING', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  delete tampered.manifest_signature.algorithm;
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid', 'missing algorithm field must be refused, not silently accepted');
  assert.match(result.reason, /algorithm must be exactly 'Ed25519'/);
});

test('O P1-E: verifyManifestSignature refuses when algorithm is the empty string', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  tampered.manifest_signature.algorithm = '';
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
});

test('O P1-E: verifyManifestSignature accepts the live (Ed25519) signature', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const result = verifyMod.verifyManifestSignature(manifest);
  assert.equal(result.status, 'valid');
});

// --- Audit O P1-D: warning dedupe via emitWarning ---

test('O P1-D: missing manifest_signature uses process.emitWarning with stable code', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  // Assert the emitWarning() path is wired — without it, repeat calls to
  // loadManifestValidated() spam stderr per call (the pre-fix shape).
  assert.match(
    src,
    /process\.emitWarning\(\s*['"][\s\S]*?manifest_signature[\s\S]*?['"],\s*\{\s*code:\s*['"]EXCEPTD_MANIFEST_UNSIGNED['"]/,
    'lib/verify.js missing-signature warning must use process.emitWarning() with ' +
    'code: "EXCEPTD_MANIFEST_UNSIGNED" so Node dedupes by code'
  );
  // Negative: no bare console.warn for the missing-signature branch.
  const missingBlock = src.slice(
    src.indexOf("sigResult.status === 'missing'"),
    src.indexOf("sigResult.status === 'missing'") + 800
  );
  assert.ok(
    !/console\.warn\([^)]*no top-level manifest_signature/.test(missingBlock),
    'lib/verify.js must not console.warn() the missing-signature message (use emitWarning() instead)'
  );
});

// --- Audit O P1-B + Q P1: refresh-network verifies manifest_signature ---

test('O P1-B + Q P1: refresh-network exports verifyTarballManifestSignature', () => {
  assert.equal(typeof refreshMod.verifyTarballManifestSignature, 'function');
});

test('O P1-B + Q P1: refresh-network verifier returns valid on a round-tripped manifest', () => {
  const { privateKey, publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  manifest.manifest_signature = signMod.signCanonicalManifest(manifest, privateKey);
  const r = refreshMod.verifyTarballManifestSignature(manifest, publicKey);
  assert.equal(r.status, 'valid', `expected valid, got ${JSON.stringify(r)}`);
});

test('O P1-B + Q P1: refresh-network verifier rejects a tampered envelope', () => {
  const { privateKey, publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  manifest.manifest_signature = signMod.signCanonicalManifest(manifest, privateKey);
  // Tamper a skill name — covered by manifest_signature, NOT by the per-
  // skill body signatures (which sign only skill.md bytes).
  const tampered = JSON.parse(JSON.stringify(manifest));
  tampered.skills[0].name = 'attacker-renamed';
  const r = refreshMod.verifyTarballManifestSignature(tampered, publicKey);
  assert.equal(r.status, 'invalid');
});

test('O P1-B + Q P1: refresh-network verifier rejects missing algorithm (downgrade bait)', () => {
  const { privateKey, publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  manifest.manifest_signature = signMod.signCanonicalManifest(manifest, privateKey);
  delete manifest.manifest_signature.algorithm;
  const r = refreshMod.verifyTarballManifestSignature(manifest, publicKey);
  assert.equal(r.status, 'invalid');
});

test('O P1-B + Q P1: refresh-network verifier reports "missing" on tarballs that predate manifest signing', () => {
  const { publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  const r = refreshMod.verifyTarballManifestSignature(manifest, publicKey);
  assert.equal(r.status, 'missing');
});

// --- Audit O P1-C: verify-shipped-tarball verifies manifest_signature ---

test('O P1-C: verify-shipped-tarball exports verifyExtractedManifestSignature', () => {
  assert.equal(typeof tarballMod.verifyExtractedManifestSignature, 'function');
});

test('O P1-C: verify-shipped-tarball verifier matches refresh-network on byte-identical manifests', () => {
  // Symmetric byte-stability: both verifiers MUST agree on every input.
  // Diverging here would mean operators (refresh-network) and the publish
  // gate (verify-shipped-tarball) authenticate against different canonical
  // forms — that's the v0.11.x regression class.
  const { privateKey, publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1',
    skills: [{ name: 'a', path: 'skills/a/skill.md' }, { name: 'b', path: 'skills/b/skill.md' }],
  };
  manifest.manifest_signature = signMod.signCanonicalManifest(manifest, privateKey);
  const r1 = refreshMod.verifyTarballManifestSignature(manifest, publicKey);
  const r2 = tarballMod.verifyExtractedManifestSignature(manifest, publicKey);
  assert.equal(r1.status, 'valid');
  assert.equal(r2.status, 'valid');
});

test('O P1-C: shipped-tarball verifier refuses a tampered envelope', () => {
  const { privateKey, publicKey } = genKeypair();
  const manifest = {
    name: 't', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  manifest.manifest_signature = signMod.signCanonicalManifest(manifest, privateKey);
  const tampered = JSON.parse(JSON.stringify(manifest));
  tampered.version = '99.0.0';
  const r = tarballMod.verifyExtractedManifestSignature(tampered, publicKey);
  assert.equal(r.status, 'invalid');
});

test('O P1-C: scripts/verify-shipped-tarball.js wires the verifier into the gate body', () => {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', 'verify-shipped-tarball.js'), 'utf8');
  // The gate body MUST call verifyExtractedManifestSignature against the
  // extracted manifest BEFORE iterating per-skill verifies. Without this,
  // a tarball with a tampered envelope but valid body signatures would
  // pass the publish gate. The string match below catches a refactor
  // that drops the call.
  assert.match(
    src,
    /verifyExtractedManifestSignature\(\s*manifest\s*,\s*pubPem\s*\)/,
    'scripts/verify-shipped-tarball.js must call verifyExtractedManifestSignature ' +
    'on the extracted manifest before publish'
  );
});

// --- Audit Q P1 + R F6: EXPECTED_FINGERPRINT consulted in bin/exceptd.js ---

test('Q P1 + R F6: bin/exceptd.js defines assertExpectedFingerprint', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(
    src,
    /function assertExpectedFingerprint\(pubKeyPem\)/,
    'bin/exceptd.js must define assertExpectedFingerprint() to centralize the pin check'
  );
  // Helper must read keys/EXPECTED_FINGERPRINT under PKG_ROOT.
  const helperStart = src.indexOf('function assertExpectedFingerprint(pubKeyPem)');
  const helperBlock = src.slice(helperStart, helperStart + 1500);
  assert.match(helperBlock, /EXPECTED_FINGERPRINT/);
  assert.match(helperBlock, /KEYS_ROTATED/);
});

test('Q P1 + R F6: verifyAttestationSidecar calls assertExpectedFingerprint', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function verifyAttestationSidecar(attFile)');
  assert.ok(fnStart > 0, 'verifyAttestationSidecar must be present');
  const fnBody = src.slice(fnStart, fnStart + 2500);
  assert.match(
    fnBody,
    /assertExpectedFingerprint\(/,
    'verifyAttestationSidecar() must call assertExpectedFingerprint() per Q P1 + R F6'
  );
});

test('Q P1 + R F6: attest verify subverb calls assertExpectedFingerprint', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Locate the `if (subverb === "verify")` branch inside cmdAttest. Match
  // the call to assertExpectedFingerprint() within a bounded slice.
  const idx = src.indexOf('if (subverb === "verify")');
  assert.ok(idx > 0, 'attest verify subverb must be present');
  const block = src.slice(idx, idx + 2500);
  assert.match(
    block,
    /assertExpectedFingerprint\(/,
    'attest verify subverb must call assertExpectedFingerprint() per Q P1 + R F6'
  );
});

// --- Audit P P1-C: normalize() applied at all three attestation sites ---

test('P P1-C: bin/exceptd.js defines normalizeAttestationBytes', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /function normalizeAttestationBytes\(input\)/);
});

test('P P1-C: maybeSignAttestation normalizes content before sign', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function maybeSignAttestation(filePath)');
  const fnEnd = src.indexOf('function ', fnStart + 30);
  const block = src.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 3000);
  assert.match(
    block,
    /normalizeAttestationBytes\(/,
    'maybeSignAttestation() must call normalizeAttestationBytes() so sign + verify agree'
  );
});

test('P P1-C: verifyAttestationSidecar normalizes content before verify', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function verifyAttestationSidecar(attFile)');
  const fnEnd = src.indexOf('function cmdReattest', fnStart + 30);
  const block = src.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 3000);
  assert.match(
    block,
    /normalizeAttestationBytes\(/,
    'verifyAttestationSidecar() must call normalizeAttestationBytes() before crypto.verify'
  );
});

test('P P1-C: attest verify subverb normalizes content before verify', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const idx = src.indexOf('if (subverb === "verify")');
  const block = src.slice(idx, idx + 2500);
  assert.match(
    block,
    /normalizeAttestationBytes\(/,
    'attest verify subverb must call normalizeAttestationBytes() before crypto.verify'
  );
});

// --- Audit Q P2: missing .sig sidecar refuses unless --force-replay ---

test('Q P2: cmdReattest refuses on missing .sig without --force-replay', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Find cmdReattest body.
  const fnStart = src.indexOf('function cmdReattest(');
  assert.ok(fnStart > 0, 'cmdReattest must be present');
  const fnEnd = src.indexOf('\nfunction ', fnStart + 50);
  const fnBody = src.slice(fnStart, fnEnd);
  // The refuse-on-missing-sidecar path MUST set process.exitCode = 6 and
  // emit a body with sidecar_verify. Without these, the override path is
  // not audit-trailed.
  assert.match(
    fnBody,
    /no \.sig sidecar/,
    'cmdReattest must check for "no .sig sidecar" reason'
  );
  assert.match(
    fnBody,
    /TAMPERED-OR-MISSING/,
    'cmdReattest must surface a TAMPERED-OR-MISSING signal on missing sidecar'
  );
  // The refuse branch must set exitCode = 6 (same as the tamper branch).
  // Count occurrences of `process.exitCode = 6` — pre-fix there was 1
  // (tamper only); post-fix there are >= 2 (tamper + missing-sidecar).
  const matches = fnBody.match(/process\.exitCode\s*=\s*6/g) || [];
  assert.ok(
    matches.length >= 2,
    `cmdReattest must set exitCode=6 on BOTH tamper and missing-sidecar paths (found ${matches.length})`
  );
});

test('Q P2 (force-replay audit trail): reattest emit body always carries sidecar_verify + force_replay', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function cmdReattest(');
  const fnEnd = src.indexOf('\nfunction ', fnStart + 50);
  const fnBody = src.slice(fnStart, fnEnd);
  // The final emit() must include both fields. Without them, an auditor
  // reading the replay output cannot distinguish a clean replay from an
  // override-on-tamper or override-on-missing-sidecar replay.
  const emitIdx = fnBody.lastIndexOf('emit({');
  assert.ok(emitIdx > 0, 'cmdReattest must end with emit({...})');
  const emitBlock = fnBody.slice(emitIdx);
  assert.match(emitBlock, /sidecar_verify:/, 'final emit must include sidecar_verify');
  assert.match(emitBlock, /force_replay:/,   'final emit must include force_replay');
});
