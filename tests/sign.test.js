"use strict";


// ---- routed from sign-verify ----
require("node:test").describe("sign-verify", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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









// ---------- module surface ----------



// ---------- temp-dir keypair write/read sanity ----------
//
// Demonstrates the file-format contract lib/sign.js writes to disk (PKCS8/SPKI PEM)
// without touching the repo's real key paths.


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








// ---------- v0.12.12 hardening: S2 manifest path traversal ----------







// ---------- v0.12.12 hardening: S3 manifest schema validation ----------




// ---------- sign-side schema gate: signer must be at least as strict as verifier ----------
//
// lib/verify.js signAll()/loadManifestValidated() schema-validate the manifest
// before (re-)signing / verifying. lib/sign.js — the canonical signer behind
// `node lib/sign.js sign-all` + `npm run bootstrap` — must NOT be the weaker
// check: a manifest that is path-safe but schema-invalid must be REFUSED by the
// signer, otherwise it gets a valid manifest_signature here and then
// lib/verify.js loadManifestValidated() throws on the same schema at install
// time and refuses to verify any skill (producer emits what the consumer
// rejects). signAll()/signOne() read the repo's real manifest/keys, so we
// exercise the extracted validateManifestSchema() helper that both call.

function validBaseManifest() {
  return {
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
  };
}







// ---------- v0.12.12 hardening: S4 duplicate frontmatter keys ----------



// ---------- v0.12.12 hardening: S6 orphan skill.md detector ----------

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

test('lib/sign.js exports the documented public functions', () => {
  const sign = require('../lib/sign.js');
  assert.equal(typeof sign.generateKeypair, 'function');
  assert.equal(typeof sign.signAll, 'function');
  assert.equal(typeof sign.signOne, 'function');
});

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

test('sign-side: validateManifestSchema is exported by lib/sign.js', () => {
  assert.equal(typeof signMod.validateManifestSchema, 'function');
});

test('sign-side: validateManifestSchema accepts a well-formed manifest (no throw)', () => {
  assert.doesNotThrow(() => signMod.validateManifestSchema(validBaseManifest(), 'sign-all'));
});

test('sign-side: validateManifestSchema THROWS on an unknown per-skill field (the verifier-reject case)', () => {
  const bad = validBaseManifest();
  bad.skills[0].malicious_extension = 'oops';
  assert.throws(
    () => signMod.validateManifestSchema(bad, 'sign-all'),
    /failed schema validation.*refusing to sign[\s\S]*malicious_extension/,
  );
});

test('sign-side: validateManifestSchema THROWS on a malformed per-skill version', () => {
  const bad = validBaseManifest();
  bad.skills[0].version = 'not-a-semver';
  assert.throws(
    () => signMod.validateManifestSchema(bad, 'sign'),
    /failed schema validation.*refusing to sign/,
  );
});

test('sign-side: validateManifestSchema THROWS on a missing required per-skill field', () => {
  const bad = validBaseManifest();
  delete bad.skills[0].triggers;
  assert.throws(
    () => signMod.validateManifestSchema(bad, 'sign-all'),
    /failed schema validation.*refusing to sign[\s\S]*triggers/,
  );
});

test('sign-side: signer and verifier agree — same manifest, same verdict (no asymmetry)', () => {
  // A schema-invalid manifest the verifier rejects must also be rejected by
  // the signer. Drive verify's validator directly and sign's helper on the
  // SAME object; both must flag the violation.
  const schemaPath = path.join(__dirname, '..', 'lib', 'schemas', 'manifest.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const bad = validBaseManifest();
  bad.skills[0].malicious_extension = 'oops';

  // Verifier side: validator surfaces the error (loadManifestValidated would throw).
  const verifyErrors = verifyMod.validateAgainstSchema(bad, schema, 'manifest');
  assert.ok(verifyErrors.length > 0, 'verifier must flag the schema-invalid manifest');

  // Signer side: validateManifestSchema must throw on the SAME manifest.
  assert.throws(() => signMod.validateManifestSchema(bad, 'sign-all'));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from v0_12_41-fixes ----
require("node:test").describe("v0_12_41-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_12_41-fixes.test.js
 *
 * Per-fix regression pins for the v0.12.41 release. Each test reads the
 * source byte-for-byte or invokes a unit under test against a known
 * input and asserts the exact post-fix shape.
 *
 * Fixes covered:
 *   F1 — lib/sign.js generateKeypair refuses to overwrite an existing
 *        keys/public.pem without --rotate (prevents the v0.11.x signature
 *        regression class where doctor --fix orphans shipped signatures).
 *   F2 — bin/exceptd.js sidecar .sig writes use mode 0o600 + restrictWindowsAcl
 *        (analogue of v0.12.38 attestation.json hardening).
 *   F3 — bin/exceptd.js doctor --fix chains sign-all after key generation
 *        AND refuses if keys/public.pem exists without matching privkey.
 *   F4 — bin/exceptd.js attest unknown subverb emits did_you_mean array
 *        (closes the v0.12.37 typo-suggestion class for the attest dispatcher).
 *   F5 — bin/exceptd.js attest diff guards against empty attestations[]
 *        (TypeError on session dirs containing only replay records).
 *   F6 — bin/exceptd.js cmdAsk honors --pretty as an implicit --json opt-in
 *        (alignment with discover/doctor convention).
 *   F7 — lib/scoring.js compare() surfaces "no scoring signal" distinctly
 *        from "broadly aligned" when both rwep and cvss are zero/null
 *        (coincidence-passing fix per the common-pitfall list).
 *   F8 — lib/playbook-runner.js normalizeSubmission clones submission
 *        before pushing to _runErrors (prevents TypeError on frozen input).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', cwd: ROOT, ...opts });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// ---------- F1 — sign.js generate-keypair public-key overwrite refusal ----------

test('F1: lib/sign.js generateKeypair() guards keys/public.pem overwrite', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'sign.js'), 'utf8');
  // The guard must create the public key EXCLUSIVELY (O_EXCL via the 'wx' flag,
  // gated on !rotate) so an existing pubkey is refused atomically — no racy
  // existsSync pre-check — AND surface the refusal reason. Pin the exclusive
  // flag derivation, the exclusive open of PUBLIC_KEY_PATH, and the
  // operator-facing message so a future refactor that drops one is caught.
  assert.match(src, /openFlag\s*=\s*rotate\s*\?\s*'w'\s*:\s*'wx'/,
    'generateKeypair must derive an exclusive (wx) create flag unless --rotate');
  assert.match(src, /openSync\(PUBLIC_KEY_PATH,\s*openFlag/,
    'generateKeypair must create the public key with the exclusive flag, not overwrite blindly');
  assert.match(src, /Refusing to overwrite the public key/,
    'lib/sign.js must surface the refusal reason to the operator');
});

// ---------- F2 — sidecar .sig 0o600 + Windows ACL ----------

test('F2: bin/exceptd.js sidecar + body writes use mode 0o600 and ACL-harden the sidecar', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // The atomic-write refactor writes the body + sidecar to fsync'd tmp files
  // via a shared writeFsync helper that opens each with mode 0o600
  // (openSync(p, "w", 0o600)); the mode survives the rename into place. The
  // 0o600 protection must still be present, and restrictWindowsAcl must still
  // be applied to the sidecar path (Windows multi-tenant hardening).
  assert.match(src, /fs\.openSync\([^,]+,\s*"w",\s*0o600\)/,
    'attestation writes must create files with mode 0o600 (via openSync)');
  assert.match(src, /restrictWindowsAcl\(sigPath\)/,
    'bin/exceptd.js must call restrictWindowsAcl on the .sig sidecar (Windows multi-tenant hardening)');
});

// ---------- F3 — doctor --fix chains sign-all + refuses on pubkey mismatch ----------

test('F3: bin/exceptd.js doctor --fix refuses when keys/public.pem present without privkey', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /pubKeyExists/, 'doctor --fix must check pubkey existence before generating');
  assert.match(src, /ed25519_keypair_generation_declined/,
    'doctor --fix must surface a distinct decline reason when pubkey exists without privkey');
  assert.match(src, /sign-all/, 'doctor --fix must chain sign-all after generate-keypair succeeds');
});

test('F3b: doctor --fix detects post-rotate stale signatures and chains sign-all (codex P2)', () => {
  // codex P2 v0.12.41: after `generate-keypair --rotate` the private key
  // IS present, so the missing-key remediation path never fires.
  // doctor --fix must ALSO detect signatures-failing-while-key-present
  // and chain sign-all so the post-rotate flow converges to verified.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /skills_resigned_against_current_keypair/,
    'doctor --fix must support the post-rotation re-sign path');
  // Pin the precondition: only fires when key IS present AND signatures
  // check failed AND no earlier --fix path already ran.
  assert.match(src, /checks\.signing\.private_key_present[\s\S]{0,200}checks\.signatures[\s\S]{0,50}ok === false/,
    'post-rotate sign-all path must gate on private_key_present && signatures.ok === false');
});

// ---------- F4 — attest unknown subverb did-you-mean ----------

test('F4: attest unknown subverb returns did_you_mean[] in JSON body', () => {
  const r = cli(['attest', 'verfy', 'some-sid', '--json']);
  // Exit 1 (GENERIC_FAILURE) is the canonical code for unknown-subverb
  // usage errors via emitError(). The JSON body lands on stderr (per
  // emitError contract).
  assert.equal(r.status, 1, `attest verfy should exit 1; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false, `expected ok:false body; got ${r.stderr.slice(0, 200)}`);
  assert.ok(Array.isArray(body.did_you_mean), `expected did_you_mean[] array; got ${typeof body.did_you_mean}`);
  assert.ok(body.did_you_mean.includes('verify'),
    `expected did_you_mean to include "verify" for input "verfy"; got ${JSON.stringify(body.did_you_mean)}`);
  assert.ok(Array.isArray(body.accepted_subverbs), 'accepted_subverbs[] must be present');
  // Pin the canonical subverb set so a future addition/removal updates
  // the test consciously.
  assert.deepEqual(body.accepted_subverbs.slice().sort(), ['diff', 'export', 'list', 'prune', 'show', 'verify']);
});

// ---------- F6 — cmdAsk honors --pretty ----------

test('F6: cmdAsk --pretty emits JSON output (not human text)', () => {
  const r = cli(['ask', 'kernel privilege escalation', '--pretty']);
  // --pretty alone (without --json) should produce parseable JSON.
  assert.equal(r.status, 0, `ask --pretty should exit 0; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout);
  assert.ok(body, `expected JSON body on stdout; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'ask');
  assert.equal(typeof body.question, 'string');
  assert.ok(Array.isArray(body.routed_to));
});

// ---------- F7 — scoring compare() no-signal branch ----------

test('F7: lib/scoring.js compare() surfaces "no scoring signal" when rwep+cvss are zero', () => {
  const { compare } = require('../lib/scoring.js');
  // compare() takes the catalog map directly (cveId -> entry).
  const stubCatalog = {
    'CVE-TEST-NO-SIGNAL': {
      cvss_score: 0,
      rwep_score: 0,
      rwep_factors: {},
      cisa_kev: false,
      poc_available: false,
      ai_discovered: false,
      active_exploitation: 'none',
      patch_available: false,
    },
  };
  const r = compare('CVE-TEST-NO-SIGNAL', stubCatalog);
  assert.ok(r, 'compare() must return a result');
  assert.match(r.explanation, /No scoring signal/i,
    `expected "no scoring signal" branch; got: ${r.explanation}`);
});

// ---------- F8 — normalizeSubmission clones before _runErrors push ----------

test('F8: lib/playbook-runner.js normalizeSubmission accepts frozen submissions', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'playbook-runner.js'), 'utf8');
  // The fix must build a fresh carry array from the original (or empty)
  // and pass it INTO the spread, not mutate the input in place. Pin
  // both the pattern shape AND the absence of the pre-fix in-place
  // mutation.
  assert.match(src, /const carry = Array\.isArray\(submission\._runErrors\) \? submission\._runErrors\.slice\(\) : \[\];/,
    'normalizeSubmission must clone _runErrors before pushing');
  assert.ok(!src.includes('if (!submission._runErrors) submission._runErrors = [];\n    pushRunError(submission._runErrors'),
    'pre-fix in-place mutation pattern must not return');
});

// ---------- Additional regression pins ----------

test('attest diff guards against empty attestations[]', () => {
  // Build a temp session dir with ONLY a replay record (no attestation
  // proper) and verify cmdAttest diff returns ok:false rather than
  // throwing TypeError on `self.captured_at`.
  const os = require('node:os');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-attest-diff-empty-'));
  try {
    // EXCEPTD_HOME is the parent; attestations live under
    // <EXCEPTD_HOME>/attestations/<sid>/ per the resolver convention.
    const attDir = path.join(tmp, 'attestations');
    fs.mkdirSync(attDir, { recursive: true });
    const sid = 'test-sid-empty-' + Date.now();
    const sessionDir = path.join(attDir, sid);
    fs.mkdirSync(sessionDir, { recursive: true });
    // Replay record only — no attestation.json.
    fs.writeFileSync(path.join(sessionDir, 'replay-001.json'), JSON.stringify({
      kind: 'replay',
      session_id: sid,
      captured_at: new Date().toISOString(),
    }));
    // Create a second session to diff against.
    const sid2 = 'test-sid-other-' + Date.now();
    const otherDir = path.join(attDir, sid2);
    fs.mkdirSync(otherDir, { recursive: true });
    fs.writeFileSync(path.join(otherDir, 'attestation.json'), JSON.stringify({
      session_id: sid2,
      captured_at: new Date().toISOString(),
      evidence_hash: 'sha256:abc',
      submission: { artifacts: {}, signal_overrides: {} },
    }));
    const r = cli(['attest', 'diff', sid, '--against', sid2, '--json'], { env: { ...process.env, EXCEPTD_HOME: tmp } });
    // Exit 1 (emitError sets exitCode=1); body on stderr.
    assert.equal(r.status, 1, `attest diff on empty-attestations should exit 1; got ${r.status}. stdout: ${r.stdout.slice(0, 200)} stderr: ${r.stderr.slice(0, 200)}`);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false, `expected ok:false body; got: ${(r.stderr || r.stdout).slice(0, 200)}`);
    assert.match(body.error || '', /no attestation/i,
      'error message must point at the missing attestation, not throw TypeError');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Note: orchestrator exit-code harmonization (framework-gap, report,
// watchlist usage errors collide with DETECTED_ESCALATE on exit 2) is
// pinned by operator-contract tests today. Splitting that envelope is
// a v0.13 minor-bump change requiring explicit confirmation per the
// project's cadence rule. Tracked in CHANGELOG forward-watch.

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from openvex-emission ----
require("node:test").describe("openvex-emission", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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



// --- Audit O P1-E: algorithm must be strictly 'Ed25519' ---




// --- Audit O P1-D: warning dedupe via emitWarning ---

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
