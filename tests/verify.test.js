"use strict";


// ---- routed from predeploy-gates ----
require("node:test").describe("predeploy-gates", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/predeploy-gates.test.js
 *
 * Meta-tests for the predeploy gate runners. The pre-existing
 * tests/predeploy.test.js asserts the GATES list maps to ci.yml job
 * names — it does not exercise the gates themselves. This file fills
 * that gap: for each gate that ships a script under lib/ or scripts/,
 * stage a known-bad state in a per-test tempdir and assert the gate
 * actually fires (non-zero exit OR an error-shape return).
 *
 * Why these specific gates: tests/predeploy.test.js only checks the
 * mapping. Other tests cover the data the gates consume but not the
 * gate runners themselves. This file is the regression-prevention layer
 * for the gate runners — when a gate's "bad state" detection regresses
 * (the false-negative class that shipped invisible signature drift in
 * v0.11.x — v0.12.2), one of these tests fires.
 *
 * Isolation model:
 *
 *   - Every test mkdtempSync's its own working tree under os.tmpdir().
 *   - Every test copies the script-under-test (and its strict
 *     dependencies) into <tempdir>/lib/ or <tempdir>/scripts/ so the
 *     script's __dirname anchor resolves to <tempdir>/lib (or
 *     <tempdir>/scripts), and __dirname/.. resolves to <tempdir>.
 *   - No test mutates the real repo ROOT. ROOT is read-only; tempdirs
 *     are the only writable surface.
 *   - Tempdirs are removed in a try/finally even when assertions fail
 *     so a CI run that ends with N failing tests still leaves /tmp clean.
 *
 * No --dir / --root flag was added to any existing script as part of
 * this work — every gate is testable via the cwd + __dirname anchor
 * pattern, except scripts/check-sbom-currency.js which already accepted
 * --root (it was extracted out of an inline `node -e` block in
 * scripts/predeploy.js during this same change; the extracted script
 * is the gate-10 runner going forward).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

// ---------- tempdir helpers ----------

function mktmp(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "predeploy-gate-" + label + "-"));
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best effort — Windows file locks may keep a handle briefly */
  }
}

function writeFile(dir, rel, content) {
  const abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

function copyFile(srcAbs, dstAbs) {
  fs.mkdirSync(path.dirname(dstAbs), { recursive: true });
  fs.copyFileSync(srcAbs, dstAbs);
}

// Every staged lib validator now requires lib/exit-codes.js (for safeExit);
// stage it alongside so the mirrored script doesn't crash on require (which
// would yield empty stdout and a confusing content-assertion failure).
function copyExitCodes(tmp) {
  copyFile(path.join(ROOT, "lib", "exit-codes.js"), path.join(tmp, "lib", "exit-codes.js"));
}

// Generate an Ed25519 keypair in PEM form, matching lib/verify.js conventions.
function genKeypair() {
  return crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function signContent(content, privateKeyPem) {
  return crypto
    .sign(null, Buffer.from(content, "utf8"), {
      key: privateKeyPem,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64");
}

// ---------- Gate 1: Verify skill signatures (Ed25519) ----------


// ---------- Gate 7: Lint skill files ----------


// ---------- Gate 9: validate-catalog-meta ----------


// ---------- Audit G F2: SBOM gate catches renamed skill ----------



// ---------- Audit G F1: validate-indexes rejects empty source_hashes ----------


// ---------- Gate 10: SBOM currency ----------


// ---------- Gate 11: validate-indexes ----------


// ---------- Gate 12: validate-vendor ----------







// ---------- Gate 13: validate-package ----------


// ---------- Gate 14: verify-shipped-tarball ----------
//
// This is the gate that closed v0.12.4's signature regression. The bug
// class: lib/verify.js against the SOURCE tree passes 38/38, but a fresh
// `npm install` against the SHIPPED tarball produces 0/38. The cause is
// keys/public.pem being swapped between sign and pack (the test that
// did it lived in `tests/operator-bugs.test.js` and synchronously
// regenerated keys mid-suite — see the common-pitfalls list).
//
// The simulated regression here: sign the skill against PRIVATE_KEY_A
// (the original ceremony), then post-sign tamper the skill body but
// leave the signature unchanged. After `npm pack`, the extracted tarball
// will have the tampered body + the original signature, and the gate
// must fail.

test("gate 1: verify.js fires on a byte-flipped signature in manifest.json", () => {
  const tmp = mktmp("verify");
  try {
    // Stage a minimal verify.js-compatible repo layout.
    copyFile(
      path.join(ROOT, "lib", "verify.js"),
      path.join(tmp, "lib", "verify.js")
    );
    // verify.js v0.12.12+ schema-validates the manifest before any skill
    // I/O. The schema lives at lib/schemas/manifest.schema.json — copy it
    // into the temp tree alongside verify.js so the validator can load it.
    copyFile(
      path.join(ROOT, "lib", "schemas", "manifest.schema.json"),
      path.join(tmp, "lib", "schemas", "manifest.schema.json")
    );
    const { privateKey, publicKey } = genKeypair();
    writeFile(tmp, "keys/public.pem", publicKey);
    const skillBody = "---\nname: t\n---\n# tempdir skill body\n";
    writeFile(tmp, "skills/t/skill.md", skillBody);
    const goodSig = signContent(skillBody, privateKey);
    // Byte-flip: flip first character of base64 signature deterministically.
    const flipped =
      (goodSig[0] === "A" ? "B" : "A") + goodSig.slice(1);
    assert.notEqual(flipped, goodSig, "sanity: flipped signature must differ");
    // Manifest must satisfy the schema's required top-level + per-skill
    // fields. Anything missing fails before we ever reach signature
    // verification — which would silently mask the test's intent.
    const manifest = {
      name: "test",
      version: "0.0.1",
      description: "test fixture manifest",
      atlas_version: "5.1.0",
      threat_review_date: "2026-01-01",
      skills: [
        {
          name: "t",
          version: "1.0.0",
          path: "skills/t/skill.md",
          description: "tempdir skill for predeploy-gate test",
          triggers: ["t"],
          data_deps: [],
          atlas_refs: [],
          attack_refs: [],
          framework_gaps: ["G1"],
          last_threat_review: "2026-01-01",
          signature: flipped,
          signed_at: "2026-01-01T00:00:00.000Z",
        },
      ],
    };
    writeFile(tmp, "manifest.json", JSON.stringify(manifest, null, 2));

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "verify.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // lib/verify.js exit-1 path covers the `invalid` branch
    // (line 253: "if (result.invalid.length > 0) { ... process.exit(1); }").
    // Pin to exact code 1: notEqual(0) would silently pass if a future
    // change made verify.js exit 2/3 on tamper.
    assert.equal(
      r.status,
      1,
      `verify.js must exit 1 on a tampered signature (process.exit(1) branch).\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      (r.stderr || "") + (r.stdout || ""),
      /TAMPERED|FAIL/i,
      "verify.js should label the failure as TAMPERED / FAIL"
    );
  } finally {
    rmrf(tmp);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


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

test('lib/verify.js exports the documented public functions', () => {
  const verify = require('../lib/verify.js');
  assert.equal(typeof verify.verifyAll, 'function');
  assert.equal(typeof verify.verifyOne, 'function');
  assert.equal(typeof verify.signAll, 'function');
});

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

test('O P1-A: live manifest.json has no signed_at on manifest_signature', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.ok(manifest.manifest_signature, 'live manifest must carry manifest_signature');
  assert.ok(
    !('signed_at' in manifest.manifest_signature),
    'live manifest_signature must not carry signed_at — re-run sign-all after the audit-O fix'
  );
});

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
  // Window widened post-AA P1-1 / P1-2: the verify subverb body grew with
  // substitution-detection + corrupt-sidecar wrapping; the 2500-byte slice
  // no longer reaches the normalize / pin call sites.
  const block = src.slice(idx, idx + 4500);
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

test('P P1-C: the attestation write path normalizes content before computing the sidecar', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // The signing helper (computeSidecarBytes) signs the bytes it is GIVEN; the
  // persist path must hand it normalized bytes so sign + verify agree. Assert
  // the call site normalizes (computeSidecarBytes(normalizeAttestationBytes(…))).
  assert.match(
    src,
    /computeSidecarBytes\(\s*normalizeAttestationBytes\(/,
    'writeAttestation must call computeSidecarBytes(normalizeAttestationBytes(...)) so sign + verify agree'
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
  // Window widened again: the verify subverb body grew with the
  // sidecar-missing tamper detection (the peer-signed scan + the expanded
  // missing-sidecar branch), pushing the normalize call deeper.
  const block = src.slice(idx, idx + 6500);
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
  // The refuse branch must set exitCode = 6 / TAMPERED (same as the tamper
  // branch). Count occurrences across both the literal `6` and the
  // v0.12.24 named-constant form `EXIT_CODES.TAMPERED` — pre-fix there
  // was 1 (tamper only); post-fix there are >= 2 (tamper + missing-sidecar).
  const matches = fnBody.match(/process\.exitCode\s*=\s*(6|EXIT_CODES\.TAMPERED)/g) || [];
  assert.ok(
    matches.length >= 2,
    `cmdReattest must set exitCode=TAMPERED on BOTH tamper and missing-sidecar paths (found ${matches.length})`
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

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
