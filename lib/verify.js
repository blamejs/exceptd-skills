'use strict';

/**
 * Skill integrity verifier — Ed25519 cryptographic signatures.
 *
 * SHA-256 hashes alone protect against accidental corruption; anyone with repo
 * write access can update the hash after tampering. Ed25519 signatures prove a
 * specific keypair signed each skill. Even if the manifest is updated, a valid
 * signature requires the private key, which never enters this repository.
 *
 * Byte-stability contract (must mirror lib/sign.js):
 *   Skill content is normalized BEFORE the signature is verified:
 *     1. Strip a UTF-8 BOM (U+FEFF) if present.
 *     2. Convert CRLF line endings to LF.
 *   The same normalization runs in lib/sign.js. A skill file checked
 *   out with core.autocrlf=true on Windows therefore verifies against
 *   a signature produced on Linux CI (LF). ANY change to normalize()
 *   requires the matching change in lib/sign.js — round-trip stability
 *   is a hard contract. The v0.11.x signature regression (operators
 *   ran `exceptd doctor --signatures` and saw 0/38) was a single
 *   instance of this contract drifting; do not relax it.
 *
 * Manifest entries are validated through validateSkillPath() before
 * any file is read. A tampered manifest with `path: "../../../etc/passwd"`
 * cannot escape the skills/ tree. The whole manifest is rejected on
 * the first traversal attempt.
 *
 * The manifest object itself is validated against
 * lib/schemas/manifest.schema.json before any skill is touched.
 * additionalProperties=false at the skill level catches typos and
 * unknown fields that would otherwise silently be dropped.
 *
 * Manifest signature contract (must mirror lib/sign.js):
 *   The manifest carries a top-level `manifest_signature` field. Before
 *   iterating skills, loadManifestValidated() extracts the signature,
 *   recomputes the canonical bytes, and verifies against keys/public.pem.
 *   On failure, all skill verification is blocked with a structured
 *   error. When the field is absent (older v0.11.x / pre-v0.12.17
 *   tarballs in the wild), a warning is emitted but verification
 *   continues — this preserves backward compatibility for installs that
 *   predate manifest signing.
 *
 *   Canonical bytes are computed identically to lib/sign.js
 *   canonicalManifestBytes():
 *     1. Clone, delete manifest_signature.
 *     2. JSON.stringify with top-level keys sorted lexicographically.
 *     3. Apply normalize() — strip BOM, CRLF → LF.
 *   ANY change to the canonical form requires the matching change in
 *   lib/sign.js. Round-trip stability is a hard contract.
 *
 * Signing ceremony: see lib/sign.js
 * Public key: keys/public.pem (tracked in repo)
 * Private key: .keys/private.pem (gitignored, kept off-repo)
 *
 * Usage:
 *   node lib/verify.js           — verify all skills
 *   node lib/verify.js <name>    — verify one skill
 *   node lib/verify.js update    — re-sign all skills (requires private key)
 *   node lib/verify.js check-key — verify the public key is present and valid
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
// Audit G F4 — key-pin file. When present, lib/verify.js compares the live
// public-key fingerprint against the pinned one and fails the verify run
// if they differ (unless the operator sets KEYS_ROTATED=1). The file format
// is a single line "SHA256:<base64>" matching the publicKeyFingerprint()
// shape. The file is OPTIONAL: when missing, the gate warns-and-continues
// rather than failing — this preserves bootstrap compatibility on fresh
// clones / new key ceremonies. Patch-class semantics.
const EXPECTED_FINGERPRINT_PATH = path.join(ROOT, 'keys', 'EXPECTED_FINGERPRINT');

// --- public API ---

/**
 * Verify all skills in manifest.json against the Ed25519 public key.
 * @returns {{ valid: string[], invalid: string[], missing_sig: string[], missing_file: string[], no_key: boolean }}
 */
function verifyAll() {
  const publicKey = loadPublicKey();
  if (!publicKey) {
    console.error('[verify] No public key at keys/public.pem — run: node lib/sign.js generate-keypair');
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

/**
 * Verify one skill by name.
 * @param {string} skillName
 * @returns {{ status: string, reason?: string }}
 */
function verifyOne(skillName) {
  const publicKey = loadPublicKey();
  if (!publicKey) throw new Error('No public key at keys/public.pem');

  const manifest = loadManifestValidated();
  const skill = manifest.skills.find(s => s.name === skillName);
  if (!skill) throw new Error(`Skill not in manifest: ${skillName}`);

  return verifySkill(skill, publicKey);
}

/**
 * Re-sign all skills using the private key and write signatures to manifest.json.
 * Requires .keys/private.pem — never checked in.
 * @returns {{ signed: string[], errors: string[] }}
 */
function signAll() {
  const privateKey = loadPrivateKey();
  if (!privateKey) throw new Error('No private key at .keys/private.pem — run: node lib/sign.js generate-keypair');

  // P1-4: load the manifest without the signature gate. We're about to
  // mutate the manifest (re-sign skills + re-sign the manifest itself),
  // so a stale manifest_signature mismatch here is expected — not a
  // tampering signal. Schema + path validation still apply.
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

  // P1-4: re-sign the manifest after the per-skill signatures changed.
  delete manifest.manifest_signature;
  const canonical = canonicalManifestBytes(manifest);
  const manifestSig = crypto.sign(null, canonical, {
    key: privateKey, dsaEncoding: 'ieee-p1363',
  });
  manifest.manifest_signature = {
    algorithm: 'Ed25519',
    signature_base64: manifestSig.toString('base64'),
    signed_at: new Date().toISOString(),
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[verify] Signed ${result.signed.length} skills with Ed25519 private key. Manifest signed.`);
  return result;
}

// --- private helpers ---

/**
 * Normalize skill content for byte-stable verification.
 *
 * Strips a leading UTF-8 BOM (U+FEFF) if present, then converts CRLF
 * line endings to LF. lib/sign.js applies the exact same transform —
 * see the byte-stability contract in the file header.
 *
 * @param {string} content
 * @returns {string}
 */
function normalize(content) {
  let s = content;
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, '\n');
}

/**
 * Validate a manifest skill.path entry to prevent path traversal.
 *
 *   skill.path MUST be a string.
 *   skill.path MUST start with "skills/".
 *   skill.path MUST NOT contain "..".
 *   skill.path MUST NOT contain backslashes.
 *
 * Same shape as lib/sign.js validateSkillPath(); the two functions
 * are intentionally duplicated rather than cross-imported so the
 * verify path has no runtime dependency on the sign path.
 *
 * @param {string} skillPath
 * @returns {string}
 */
function validateSkillPath(skillPath) {
  if (typeof skillPath !== 'string') {
    throw new Error(`[verify] manifest skill.path must be a string, got ${typeof skillPath}`);
  }
  // Backslash check runs BEFORE the prefix check so a Windows-style
  // path ("skills\foo\skill.md") returns the clearer "use forward
  // slashes" diagnostic, not the misleading "must start with skills/".
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
    return { status: 'missing_sig', reason: 'No Ed25519 signature in manifest — run: node lib/sign.js sign-all' };
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

/**
 * Audit I P1-4 — canonical byte form of the manifest.
 *
 * Mirrors lib/sign.js canonicalManifestBytes(). Any divergence here
 * breaks the verify-after-sign round trip; do not modify in isolation.
 *
 * @param {object} manifest
 * @returns {Buffer} canonical UTF-8 bytes
 */
function canonicalManifestBytes(manifest) {
  const clone = { ...manifest };
  delete clone.manifest_signature;
  const sortedKeys = Object.keys(clone).sort();
  const json = JSON.stringify(clone, sortedKeys, 2);
  return Buffer.from(normalize(json), 'utf8');
}

/**
 * Verify the top-level manifest_signature against keys/public.pem.
 *
 * Returns one of:
 *   { status: 'missing' }  — field absent (legacy tarball; warn-but-proceed)
 *   { status: 'valid' }    — signature verifies
 *   { status: 'invalid',   — signature malformed, wrong key, or tampered
 *     reason: string }
 *   { status: 'no-key',    — keys/public.pem absent
 *     reason: string }
 *
 * @param {object} manifest
 */
function verifyManifestSignature(manifest) {
  const sig = manifest && manifest.manifest_signature;
  if (!sig || typeof sig !== 'object') return { status: 'missing' };
  if (typeof sig.signature_base64 !== 'string') {
    return { status: 'invalid', reason: 'manifest_signature.signature_base64 missing or not a string' };
  }
  if (sig.algorithm && sig.algorithm !== 'Ed25519') {
    return { status: 'invalid', reason: `unsupported manifest_signature.algorithm: ${sig.algorithm}` };
  }
  const publicKey = loadPublicKey();
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
 * Load the manifest and validate it against
 * lib/schemas/manifest.schema.json + the path-traversal guard.
 *
 * Throws on schema violation OR traversal-pattern paths. Either case
 * is a fatal-class bug — surface it loudly rather than verify-against-
 * a-corrupt-manifest.
 *
 * Audit I P1-4: also verifies the top-level manifest_signature. On
 * invalid signature, throws a structured error blocking all skill
 * verification (a coordinated attacker who rewrote manifest.json +
 * manifest-snapshot.json + manifest-snapshot.sha256 still cannot forge
 * the Ed25519 signature without the private key). When the signature
 * field is absent, emits a stderr warning but proceeds — preserves
 * backward compatibility for v0.12.16-and-earlier tarballs.
 *
 * @returns {object}
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
  // Audit I P1-4 — manifest signature gate. Runs after schema + path
  // validation so a malformed manifest reports the structural failure
  // before the cryptographic one.
  const sigResult = verifyManifestSignature(manifest);
  if (sigResult.status === 'invalid') {
    throw new Error(`[verify] manifest_signature verification FAILED — ${sigResult.reason}. The manifest has been modified (or signed with a different key) since last sign-all. Refusing to verify any skill against this manifest.`);
  }
  if (sigResult.status === 'missing') {
    console.warn('[verify] WARN: manifest.json has no top-level manifest_signature field. This tarball predates v0.12.17 manifest signing; skills will still be verified but a coordinated rewrite of manifest.json could go undetected. Re-run `node lib/sign.js sign-all` to add the signature.');
  } else if (sigResult.status === 'no-key') {
    // Surfaced separately so the warning matches the missing-key path
    // that verifyAll() already handles — don't fail here, the verifyAll
    // entry point will emit a no_key result of its own.
    console.warn(`[verify] WARN: cannot verify manifest_signature — ${sigResult.reason}.`);
  }
  return manifest;
}

// --- JSON schema validator (subset) ---
//
// Mirrors lib/validate-cve-catalog.js's inline validator. Supports the
// schema features manifest.schema.json actually uses: type, required,
// properties, additionalProperties, items, pattern, minLength,
// minItems, $defs / $ref (root-relative only — "#/$defs/foo"). Zero
// external deps.

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
      const re = new RegExp(effectiveSchema.pattern);
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
 * Public key fingerprint(s) of the DER-encoded SPKI public key,
 * base64-encoded. Emits both:
 *
 *   - SHA-256: the universal convention. Matches `ssh-keygen -lf`
 *     output for the same key, matches GPG / npm provenance / CT log
 *     fingerprints. Operators cross-referencing the key against an
 *     external pin will use this line.
 *
 *   - SHA3-512: SHA-3 family (Keccak / sponge construction), different
 *     mathematical foundation than SHA-2. Hedges against future SHA-2
 *     weaknesses. 512-bit output (~88 b64 chars) so collision +
 *     second-preimage resistance both exceed the 256-bit Ed25519 key
 *     itself. SHA-3 is also the hash family ML-KEM / ML-DSA use
 *     internally, so this fingerprint travels well with the project's
 *     PQ posture.
 *
 * @param {string|null} pemKey  PEM-encoded public key (or null)
 * @returns {{sha256: string, sha3_512: string}|{error: string}}
 */
/**
 * Audit G F4 — compare the live public-key fingerprint against the optional
 * pinned fingerprint in keys/EXPECTED_FINGERPRINT. Returns one of:
 *   { status: 'no-pin' }      — keys/EXPECTED_FINGERPRINT not present.
 *                               Callers should warn and continue.
 *   { status: 'match' }       — live fingerprint matches the pin.
 *   { status: 'mismatch',     — divergence; caller should fail unless
 *     expected, actual,         KEYS_ROTATED=1 is set in the environment.
 *     rotationOverride }
 *
 * @param {{sha256:string}|null} liveFp  publicKeyFingerprint() output
 * @param {string} [pinPath]             optional override (testability)
 */
function checkExpectedFingerprint(liveFp, pinPath) {
  const p = pinPath || EXPECTED_FINGERPRINT_PATH;
  if (!fs.existsSync(p)) return { status: 'no-pin' };
  if (!liveFp || typeof liveFp.sha256 !== 'string') {
    return { status: 'mismatch', expected: 'unknown', actual: '(invalid)', rotationOverride: false };
  }
  const expected = fs.readFileSync(p, 'utf8').trim();
  // Tolerate trailing comment / whitespace on the same line; the file's
  // first non-empty line is the canonical fingerprint.
  const firstLine = expected.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0) || '';
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

// --- CLI ---

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
      console.error('[verify] No public key — run: node lib/sign.js generate-keypair');
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
  // S5 ordering: verdict line first, fingerprint banner after.
  // An operator scanning `gh run watch` output should never see a
  // fingerprint banner without first seeing whether the verdict
  // was pass or fail. The previous order printed the success
  // summary then the fingerprint; if verification was actually
  // failing (TAMPERED / UNSIGNED / MISSING) the success line was
  // never reached but the fingerprint had already been printed,
  // which can read as "success" at a glance.
  if (result.invalid.length > 0) {
    console.error(`\n[verify] ${result.invalid.length}/${total} FAILED — TAMPERED: ${result.invalid.join(', ')}`);
  } else if (result.missing_sig.length > 0) {
    console.warn(`\n[verify] ${result.missing_sig.length}/${total} UNSIGNED: ${result.missing_sig.join(', ')}`);
  } else if (result.missing_file.length > 0) {
    console.error(`\n[verify] ${result.missing_file.length}/${total} MISSING: ${result.missing_file.join(', ')}`);
  } else {
    console.log(`\n[verify] All skills verified. ${result.valid.length}/${total} skills passed Ed25519 verification.`);
  }

  // Fingerprint banner comes AFTER the verdict.
  const pubKey = loadPublicKey();
  const fp = publicKeyFingerprint(pubKey);
  console.log(`[verify] Public key: keys/public.pem`);
  console.log(`[verify] ${fp.sha256}`);
  console.log(`[verify] ${fp.sha3_512}`);

  // Audit G F4 — pin check. When keys/EXPECTED_FINGERPRINT exists, the
  // live fingerprint MUST match it (or KEYS_ROTATED=1 must be set to
  // intentionally override). When the file is absent, emit a single-line
  // warning but continue — fresh clones / bootstrap workflows should not
  // fail the gate before the operator has committed a fingerprint.
  const pinResult = checkExpectedFingerprint(fp);
  if (pinResult.status === 'no-pin') {
    console.warn(
      `[verify] WARN: keys/EXPECTED_FINGERPRINT not present — key-pin check skipped. ` +
      `Create it with the current ${fp.sha256} line to enable pinning.`
    );
  } else if (pinResult.status === 'mismatch') {
    if (pinResult.rotationOverride) {
      console.warn(
        `[verify] WARN: live key fingerprint ${pinResult.actual} differs from pin ` +
        `${pinResult.expected}. KEYS_ROTATED=1 set — accepting rotation. ` +
        `Update keys/EXPECTED_FINGERPRINT to lock the new pin.`
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
  canonicalManifestBytes,
  verifyManifestSignature,
  EXPECTED_FINGERPRINT_PATH,
};
