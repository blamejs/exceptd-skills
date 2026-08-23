'use strict';

/**
 * Skill integrity verifier — Ed25519 signatures over normalized skill content.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.json');
const SKILLS_DIR = path.join(ROOT, 'skills');
const PUBLIC_KEY_PATH = path.join(ROOT, 'keys', 'public.pem');
const PRIVATE_KEY_PATH = path.join(ROOT, '.keys', 'private.pem');
const MANIFEST_SCHEMA_PATH = path.join(__dirname, 'schemas', 'manifest.schema.json');
// Key pin: one line "SHA256:<base64>", compared against live keys/public.pem.
const EXPECTED_FINGERPRINT_PATH = path.join(ROOT, 'keys', 'EXPECTED_FINGERPRINT');

// Returns per-status name lists; an absent public key returns no_key:true.
function verifyAll() {
  const publicKey = loadPublicKey();
  if (!publicKey) {
    console.error('[verify] No public key at keys/public.pem — run `exceptd doctor --fix` (or `node $(exceptd path)/lib/sign.js generate-keypair` from a contributor checkout)');
    return { valid: [], invalid: [], missing_sig: [], missing_file: [], no_key: true };
  }

  const manifest = loadManifestValidated();
  const result = { valid: [], invalid: [], missing_sig: [], missing_file: [], no_key: false };

  for (const skill of manifest.skills) {
    const outcome = verifySkill(skill, publicKey);
    result[outcome.status].push(skill.name);
    if (outcome.status !== 'valid') {
      console.error(`[verify] FAIL ${skill.name}: ${outcome.reason}`);
    }
  }

  return result;
}

// Throws where verifyAll() reports a status: no public key, or name not in manifest.
function verifyOne(skillName) {
  const publicKey = loadPublicKey();
  if (!publicKey) throw new Error('No public key at keys/public.pem');

  const manifest = loadManifestValidated();
  const skill = manifest.skills.find(s => s.name === skillName);
  if (!skill) throw new Error(`Skill not in manifest: ${skillName}`);

  return verifySkill(skill, publicKey);
}

// Rewrites manifest.json in place. Requires .keys/private.pem.
function signAll() {
  const privateKey = loadPrivateKey();
  if (!privateKey) throw new Error('No private key at .keys/private.pem — run `exceptd doctor --fix` (or `node $(exceptd path)/lib/sign.js generate-keypair` from a contributor checkout)');

  // Loaded without the signature gate: this run rewrites the signatures, so a
  // stale manifest_signature is expected here. Schema + path checks still run.
  const manifest = loadManifest();
  const schema = JSON.parse(fs.readFileSync(MANIFEST_SCHEMA_PATH, 'utf8'));
  const errors0 = validateAgainstSchema(manifest, schema, 'manifest');
  if (errors0.length > 0) {
    const detail = errors0.slice(0, 10).map(e => '  - ' + e).join('\n');
    throw new Error(`[verify] manifest.json failed schema validation before re-sign:\n${detail}`);
  }
  for (const skill of (manifest.skills || [])) validateSkillPath(skill.path);

  const result = { signed: [], errors: [] };

  for (const skill of manifest.skills) {
    const skillPath = path.join(ROOT, skill.path);
    if (!fs.existsSync(skillPath)) {
      result.errors.push(`${skill.name}: file not found at ${skill.path}`);
      continue;
    }
    const content = fs.readFileSync(skillPath, 'utf8');
    skill.signature = sign(content, privateKey);
    skill.signed_at = new Date().toISOString();
    delete skill.sha256;
    result.signed.push(skill.name);
  }

  delete manifest.manifest_signature;
  const canonical = canonicalManifestBytes(manifest);
  const manifestSig = crypto.sign(null, canonical, {
    key: privateKey, dsaEncoding: 'ieee-p1363',
  });
  // No `signed_at` here: unsigned metadata, so a replayed known-valid signature
  // could carry any timestamp. Freshness comes from git log / npm publish time.
  manifest.manifest_signature = {
    algorithm: 'Ed25519',
    signature_base64: manifestSig.toString('base64'),
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[verify] Signed ${result.signed.length} skills with Ed25519 private key. Manifest signed.`);
  return result;
}

// Strips a leading UTF-8 BOM, then CRLF → LF. lib/sign.js applies the identical
// transform; diverging breaks the sign→verify round trip for every skill.
function normalize(content) {
  let s = content;
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, '\n');
}

// Throws unless skillPath is a string under skills/ with no ".." and no
// backslashes. Deliberately duplicated in lib/sign.js — change both together.
function validateSkillPath(skillPath) {
  if (typeof skillPath !== 'string') {
    throw new Error(`[verify] manifest skill.path must be a string, got ${typeof skillPath}`);
  }
  // Before the prefix check: a Windows-style "skills\foo\skill.md" earns the
  // "use forward slashes" diagnostic, not the misleading "must start with skills/".
  if (skillPath.includes('\\')) {
    throw new Error(`[verify] manifest skill.path must use forward slashes, not backslashes: ${JSON.stringify(skillPath)}`);
  }
  if (!skillPath.startsWith('skills/')) {
    throw new Error(`[verify] manifest skill.path must start with 'skills/': ${JSON.stringify(skillPath)}`);
  }
  if (skillPath.includes('..')) {
    throw new Error(`[verify] manifest skill.path must not contain '..': ${JSON.stringify(skillPath)}`);
  }
  return skillPath;
}

function verifySkill(skill, publicKey) {
  if (!skill.signature) {
    return { status: 'missing_sig', reason: 'No Ed25519 signature in manifest — run `exceptd doctor --fix` (or `node $(exceptd path)/lib/sign.js sign-all` from a contributor checkout)' };
  }

  const skillPath = path.join(ROOT, skill.path);
  if (!fs.existsSync(skillPath)) {
    return { status: 'missing_file', reason: `File not found: ${skill.path}` };
  }

  const content = fs.readFileSync(skillPath, 'utf8');
  const valid = verify(content, skill.signature, publicKey);

  if (!valid) {
    return {
      status: 'invalid',
      reason: `Ed25519 signature verification failed — skill content has been modified since last signing`
    };
  }

  return { status: 'valid' };
}

function sign(content, privateKey) {
  const normalized = normalize(content);
  const signature = crypto.sign(null, Buffer.from(normalized, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return signature.toString('base64');
}

function verify(content, signatureBase64, publicKey) {
  try {
    const signature = Buffer.from(signatureBase64, 'base64');
    const normalized = normalize(content);
    return crypto.verify(null, Buffer.from(normalized, 'utf8'), {
      key: publicKey,
      dsaEncoding: 'ieee-p1363'
    }, signature);
  } catch (_) {
    return false;
  }
}

function loadPublicKey() {
  if (!fs.existsSync(PUBLIC_KEY_PATH)) return null;
  return fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
}

function loadPrivateKey() {
  if (!fs.existsSync(PRIVATE_KEY_PATH)) return null;
  return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
}

// Deep key sort, never a top-level JSON.stringify replacer array: a replacer
// acts as a property allowlist at EVERY object level, dropping skills[].path and
// skills[].signature out of the signed bytes. Mirrors lib/sign.js
// canonicalManifestBytes(); diverging breaks the verify-after-sign round trip.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalize(value[key]);
    }
    return out;
  }
  return value;
}

function canonicalManifestBytes(manifest) {
  const clone = { ...manifest };
  delete clone.manifest_signature;
  const json = JSON.stringify(canonicalize(clone), null, 2);
  return Buffer.from(normalize(json), 'utf8');
}

/**
 * Verify the top-level manifest_signature against keys/public.pem. Status is
 * one of 'valid'; 'missing' (field absent — a caller may warn and proceed);
 * 'invalid' or 'no-key', both carrying a `reason`.
 */
function verifyManifestSignature(manifest) {
  // The key pin is consulted FIRST, before the signature-present branch: an
  // attacker who swaps keys/public.pem AND strips manifest_signature would
  // otherwise take the early `missing` return. A missing pin file fails closed —
  // the pin is committed and ships in the tarball. KEYS_ROTATED=1 overrides.
  const publicKey = loadPublicKey();
  if (publicKey) {
    const liveFp = publicKeyFingerprint(publicKey);
    const pinResult = checkExpectedFingerprint(liveFp);
    if (pinResult.status === 'mismatch' && !pinResult.rotationOverride) {
      return {
        status: 'invalid',
        reason: `fingerprint-mismatch: live=${pinResult.actual} pin=${pinResult.expected} — keys/public.pem does not match keys/EXPECTED_FINGERPRINT. If this is an intentional rotation, set KEYS_ROTATED=1 and update the pin.`,
        fingerprint_mismatch: true,
        expected: pinResult.expected,
        actual: pinResult.actual,
      };
    }
    if (pinResult.status === 'no-pin') {
      return {
        status: 'invalid',
        reason: `key-pin absent: keys/EXPECTED_FINGERPRINT is missing, so a swapped keys/public.pem cannot be detected. The pin ships in the tarball and is committed — restore it from the package or version control.`,
        pin_absent: true,
      };
    }
  }
  const sig = manifest && manifest.manifest_signature;
  if (!sig || typeof sig !== 'object') return { status: 'missing' };
  if (typeof sig.signature_base64 !== 'string') {
    return { status: 'invalid', reason: 'manifest_signature.signature_base64 missing or not a string' };
  }
  // Exact match, never `sig.algorithm && sig.algorithm !== 'Ed25519'`: tolerating
  // an absent field lets a downgrade attacker drop it. lib/sign.js always writes it.
  if (sig.algorithm !== 'Ed25519') {
    return {
      status: 'invalid',
      reason: `manifest_signature.algorithm must be exactly 'Ed25519' (got ${JSON.stringify(sig.algorithm)})`,
    };
  }
  if (!publicKey) {
    return { status: 'no-key', reason: 'public key missing at keys/public.pem' };
  }
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(sig.signature_base64, 'base64');
  } catch (e) {
    return { status: 'invalid', reason: `malformed base64 in manifest_signature: ${e.message}` };
  }
  const bytes = canonicalManifestBytes(manifest);
  let ok = false;
  try {
    ok = crypto.verify(null, bytes, {
      key: publicKey,
      dsaEncoding: 'ieee-p1363',
    }, signatureBytes);
  } catch (e) {
    return { status: 'invalid', reason: `crypto.verify threw: ${e.message}` };
  }
  return ok ? { status: 'valid' } : { status: 'invalid', reason: 'Ed25519 manifest signature did not verify against keys/public.pem — manifest.json has been tampered or signed with a different key' };
}

/**
 * Returns a manifest that passed schema validation, the path-traversal guard and
 * the manifest_signature check, or throws — a verified manifest or nothing. An
 * absent signature field is the sole tolerated case: it warns and proceeds.
 */
function loadManifestValidated() {
  const manifest = loadManifest();
  const schema = JSON.parse(fs.readFileSync(MANIFEST_SCHEMA_PATH, 'utf8'));
  const errors = validateAgainstSchema(manifest, schema, 'manifest');
  if (errors.length > 0) {
    const detail = errors.slice(0, 10).map(e => '  - ' + e).join('\n');
    const more = errors.length > 10 ? `\n  ...and ${errors.length - 10} more` : '';
    throw new Error(`[verify] manifest.json failed schema validation:\n${detail}${more}`);
  }
  if (!Array.isArray(manifest.skills)) {
    throw new Error('[verify] manifest.json: skills must be an array');
  }
  for (const skill of manifest.skills) {
    validateSkillPath(skill.path);
  }
  // After schema + path validation: structural failures report before crypto ones.
  const sigResult = verifyManifestSignature(manifest);
  if (sigResult.status === 'invalid') {
    throw new Error(`[verify] manifest_signature verification FAILED — ${sigResult.reason}. The manifest has been modified (or signed with a different key) since last sign-all. Refusing to verify any skill against this manifest.`);
  }
  if (sigResult.status === 'missing') {
    // emitWarning with a stable `code` collapses repeats; CLI verbs call
    // loadManifestValidated() several times per invocation.
    process.emitWarning(
      'manifest.json has no top-level manifest_signature field. This tarball predates v0.12.17 manifest signing; skills will still be verified but a coordinated rewrite of manifest.json could go undetected. Re-run `exceptd doctor --fix` (or `node $(exceptd path)/lib/sign.js sign-all` from a contributor checkout) to add the signature.',
      { code: 'EXCEPTD_MANIFEST_UNSIGNED' }
    );
  } else if (sigResult.status === 'no-key') {
    // verifyAll()/verifyOne() short-circuit on a missing key before reaching
    // here, so this fires only for a direct library caller.
    throw new Error(`[verify] manifest_signature verification FAILED — ${sigResult.reason}. Cannot verify the manifest without keys/public.pem; refusing to return an unauthenticated manifest.`);
  }
  return manifest;
}

// JSON-schema subset, mirroring lib/validate-cve-catalog.js's inline validator:
// type, required, properties, additionalProperties, items, pattern, minLength,
// minItems, and root-relative $ref ("#/$defs/foo") only.

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function typeMatches(value, expected) {
  if (Array.isArray(expected)) return expected.some(t => typeMatches(value, t));
  const actual = typeOf(value);
  if (expected === 'integer') return actual === 'number' && Number.isInteger(value);
  return actual === expected;
}

function resolveRef(ref, root) {
  if (!ref.startsWith('#/')) {
    throw new Error(`[verify] unsupported $ref form (must be root-relative): ${ref}`);
  }
  const parts = ref.slice(2).split('/');
  let cur = root;
  for (const p of parts) {
    if (cur === undefined || cur === null) {
      throw new Error(`[verify] cannot resolve $ref ${ref}`);
    }
    cur = cur[p];
  }
  if (cur === undefined) {
    throw new Error(`[verify] $ref ${ref} did not resolve`);
  }
  return cur;
}

function validateAgainstSchema(value, schema, here, root) {
  const rootSchema = root || schema;
  const errors = [];
  let effectiveSchema = schema;
  if (schema && schema.$ref) {
    effectiveSchema = resolveRef(schema.$ref, rootSchema);
  }

  if (effectiveSchema.type !== undefined) {
    if (!typeMatches(value, effectiveSchema.type)) {
      errors.push(`${here}: expected type ${JSON.stringify(effectiveSchema.type)}, got ${typeOf(value)}`);
      return errors;
    }
  }

  const t = typeOf(value);

  if (t === 'string') {
    if (effectiveSchema.minLength !== undefined && value.length < effectiveSchema.minLength) {
      errors.push(`${here}: string shorter than minLength ${effectiveSchema.minLength}`);
    }
    if (effectiveSchema.pattern !== undefined) {
      const re = new RegExp(effectiveSchema.pattern); // allow:dynamic-regex — bundled schema.pattern, not operator input
      if (!re.test(value)) {
        errors.push(`${here}: string ${JSON.stringify(value)} does not match pattern /${effectiveSchema.pattern}/`);
      }
    }
    if (effectiveSchema.format === 'uri') {
      try { new URL(value); } catch { errors.push(`${here}: not a valid URI`); }
    }
  }

  if (t === 'array') {
    if (effectiveSchema.minItems !== undefined && value.length < effectiveSchema.minItems) {
      errors.push(`${here}: array shorter than minItems ${effectiveSchema.minItems}`);
    }
    if (effectiveSchema.items !== undefined) {
      value.forEach((item, idx) => {
        errors.push(...validateAgainstSchema(item, effectiveSchema.items, `${here}[${idx}]`, rootSchema));
      });
    }
  }

  if (t === 'object') {
    if (effectiveSchema.required) {
      for (const req of effectiveSchema.required) {
        if (!(req in value)) errors.push(`${here}: missing required field "${req}"`);
      }
    }
    const props = effectiveSchema.properties || {};
    const allowAdditional = effectiveSchema.additionalProperties !== false;
    for (const [k, v] of Object.entries(value)) {
      if (k in props) {
        errors.push(...validateAgainstSchema(v, props[k], `${here}.${k}`, rootSchema));
      } else if (!allowAdditional) {
        errors.push(`${here}: unexpected property "${k}"`);
      }
    }
  }

  return errors;
}

/**
 * First non-comment, non-blank line of keys/EXPECTED_FINGERPRINT, or null when
 * the file is unreadable or empty. Strips a BOM and tolerates CRLF. Every site
 * that reads the pin normalises through here, so a pin that works in one works
 * in all; tests/normalize-contract.test.js asserts that.
 */
function loadExpectedFingerprintFirstLine(pinPath) {
  let buf;
  try { buf = fs.readFileSync(pinPath); }
  catch { return null; }
  if (buf.length >= 2) {
    const b0 = buf[0];
    const b1 = buf[1];
    // A UTF-16 pin file decodes as UTF-8 mojibake, so the first line silently
    // never matches a live fingerprint. Refuse it; the fix is re-saving as UTF-8.
    if ((b0 === 0xFF && b1 === 0xFE) || (b0 === 0xFE && b1 === 0xFF)) return null;
    // UTF-16BE whose BOM was stripped: "00 <printable ASCII>" repeating. The
    // leading NUL survives into the string and defeats the compare the same way.
    if (b0 === 0x00 && b1 >= 0x20 && b1 <= 0x7E) return null;
  }
  let raw = buf.toString('utf8');
  if (raw.length > 0 && raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  return lines[0] || null;
}

// Status is 'no-pin' (no pin file — the caller decides whether that is fatal),
// 'match', or 'mismatch' with expected/actual and rotationOverride set from
// KEYS_ROTATED=1. pinPath overrides the default location for tests.
function checkExpectedFingerprint(liveFp, pinPath) {
  const p = pinPath || EXPECTED_FINGERPRINT_PATH;
  if (!fs.existsSync(p)) return { status: 'no-pin' };
  if (!liveFp || typeof liveFp.sha256 !== 'string') {
    return { status: 'mismatch', expected: 'unknown', actual: '(invalid)', rotationOverride: false };
  }
  // The shared loader tolerates a BOM-prefixed pin file identically across every
  // verify site. A verbatim split-trim-find here would instead yield a
  // allow:bidi-codepoint-literal — illustrative BOM-prefixed first-line in the pin-loader doc comment
  // first-line of "﻿SHA256:..." (with leading BOM) that would never equal
  // a live fingerprint.
  const firstLine = loadExpectedFingerprintFirstLine(p) || '';
  if (firstLine === liveFp.sha256) return { status: 'match' };
  return {
    status: 'mismatch',
    expected: firstLine,
    actual: liveFp.sha256,
    rotationOverride: process.env.KEYS_ROTATED === '1',
  };
}

function publicKeyFingerprint(pemKey) {
  if (!pemKey) return { sha256: '(no key)', sha3_512: '(no key)' };
  try {
    const keyObj = crypto.createPublicKey(pemKey);
    const der = keyObj.export({ type: 'spki', format: 'der' });
    return {
      sha256: 'SHA256:' + crypto.createHash('sha256').update(der).digest('base64'),
      sha3_512: 'SHA3-512:' + crypto.createHash('sha3-512').update(der).digest('base64'),
    };
  } catch (err) {
    const errStr = `(invalid: ${err.message})`;
    return { sha256: errStr, sha3_512: errStr };
  }
}

if (require.main === module) {
  const arg = process.argv[2];

  if (arg === 'update') {
    const result = signAll();
    if (result.errors.length > 0) {
      console.error('[verify] Errors during signing:', result.errors);
      process.exit(1);
    }
    console.log('[verify] All skills signed. Run node lib/verify.js to confirm.');
    process.exit(0);
  }

  if (arg === 'check-key') {
    const pub = loadPublicKey();
    if (!pub) {
      console.error('[verify] No public key — run `exceptd doctor --fix` (or `node $(exceptd path)/lib/sign.js generate-keypair` from a contributor checkout)');
      process.exit(1);
    }
    console.log('[verify] Public key present at keys/public.pem');
    try {
      crypto.createPublicKey(pub);
      console.log('[verify] Public key is valid Ed25519.');
      process.exit(0);
    } catch (e) {
      console.error('[verify] Public key is malformed:', e.message);
      process.exit(1);
    }
  }

  if (arg && arg !== 'verify') {
    const outcome = verifyOne(arg);
    console.log(`${arg}: ${outcome.status}${outcome.reason ? ' — ' + outcome.reason : ''}`);
    process.exit(outcome.status === 'valid' ? 0 : 1);
  }

  const result = verifyAll();
  if (result.no_key) process.exit(1);

  const total = Object.values(result).filter(Array.isArray).flat().length;
  // Verdict first, fingerprint banner after: a banner printed above a TAMPERED /
  // UNSIGNED / MISSING verdict reads as success at a glance.
  if (result.invalid.length > 0) {
    console.error(`\n[verify] ${result.invalid.length}/${total} FAILED — TAMPERED: ${result.invalid.join(', ')}`);
  } else if (result.missing_sig.length > 0) {
    console.warn(`\n[verify] ${result.missing_sig.length}/${total} UNSIGNED: ${result.missing_sig.join(', ')}`);
  } else if (result.missing_file.length > 0) {
    console.error(`\n[verify] ${result.missing_file.length}/${total} MISSING: ${result.missing_file.join(', ')}`);
  } else {
    console.log(`\n[verify] All skills verified. ${result.valid.length}/${total} skills passed Ed25519 verification.`);
  }

  const pubKey = loadPublicKey();
  const fp = publicKeyFingerprint(pubKey);
  console.log(`[verify] Public key: keys/public.pem`);
  console.log(`[verify] ${fp.sha256}`);
  console.log(`[verify] ${fp.sha3_512}`);

  // On this path an absent pin warns and continues: a fresh clone has no pin yet.
  const pinResult = checkExpectedFingerprint(fp);
  if (pinResult.status === 'no-pin') {
    console.warn(
      `[verify] WARN: keys/EXPECTED_FINGERPRINT not present — key-pin check skipped. ` +
      `Create it with the current ${fp.sha256} line to enable pinning.`
    );
  } else if (pinResult.status === 'mismatch') {
    if (pinResult.rotationOverride) {
      process.emitWarning(
        `live key fingerprint ${pinResult.actual} differs from pin ${pinResult.expected}; ` +
        `KEYS_ROTATED=1 accepted. Update keys/EXPECTED_FINGERPRINT to lock the new pin.`,
        { code: 'EXCEPTD_KEYS_ROTATED_OVERRIDE' }
      );
      // Mirrored to stderr: NODE_NO_WARNINGS=1 silences emitWarning.
      console.error(
        `[verify] KEYS_ROTATED=1 override accepted; live fingerprint ${pinResult.actual} ` +
        `differs from pin ${pinResult.expected}. Update keys/EXPECTED_FINGERPRINT to lock the new pin.`
      );
    } else {
      console.error(
        `[verify] FAIL: live key fingerprint ${pinResult.actual} does not match ` +
        `keys/EXPECTED_FINGERPRINT ${pinResult.expected}. ` +
        `If this is an intentional rotation, re-run with KEYS_ROTATED=1 and ` +
        `then commit the new fingerprint to keys/EXPECTED_FINGERPRINT.`
      );
      process.exit(1);
    }
  }

  if (result.invalid.length > 0) process.exit(1);
  if (result.missing_sig.length > 0) process.exit(1);
  if (result.missing_file.length > 0) process.exit(1);

  process.exit(0);
}

module.exports = {
  verifyAll,
  verifyOne,
  signAll,
  normalize,
  validateSkillPath,
  loadManifestValidated,
  validateAgainstSchema,
  publicKeyFingerprint,
  checkExpectedFingerprint,
  loadExpectedFingerprintFirstLine,
  canonicalManifestBytes,
  verifyManifestSignature,
  EXPECTED_FINGERPRINT_PATH,
};
