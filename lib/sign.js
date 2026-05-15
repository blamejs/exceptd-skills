#!/usr/bin/env node
'use strict';

/**
 * Skill signing utility — Ed25519 keypair management and skill signing.
 *
 * The private key never enters this repository. It is stored at .keys/private.pem
 * which is gitignored. The public key at keys/public.pem is tracked and used
 * by lib/verify.js for signature verification.
 *
 * Byte-stability contract (must mirror lib/verify.js):
 *   Skill content is normalized BEFORE the bytes are signed:
 *     1. Strip a UTF-8 BOM (U+FEFF) if present.
 *     2. Convert CRLF line endings to LF.
 *   The same normalization runs in lib/verify.js. A skill file checked
 *   out with core.autocrlf=true on Windows therefore signs to the SAME
 *   signature as the LF copy on Linux CI — closing the regression class
 *   that broke v0.11.x signatures across the Windows/CI line-ending
 *   boundary. ANY change to normalize() requires the matching change in
 *   lib/verify.js; round-trip stability is a hard contract.
 *
 * Manifest entries are also validated before iteration: skill.path must
 * begin with "skills/" and must not contain ".." or backslashes (see
 * validateSkillPath() below). Without this a tampered manifest could
 * sign or verify arbitrary files outside the skills/ tree.
 *
 * Manifest signing contract (must mirror lib/verify.js):
 *   After all individual skill signatures are written, sign-all signs
 *   the manifest itself. The canonical bytes are computed as:
 *     1. Read the manifest object after all skill signatures land.
 *     2. Delete the top-level `manifest_signature` field if present
 *        (idempotency — re-signing after rotation must produce the same
 *        canonical bytes whether or not a stale signature is there).
 *     3. Serialize via JSON.stringify(obj, sortedTopLevelKeys, 2). The
 *        top-level keys are stringified in lexicographic order so a
 *        re-ordered manifest signs to the same bytes. Nested objects
 *        keep their natural key order (skills[] entries already follow
 *        a stable convention).
 *     4. Apply normalize() (CRLF→LF, BOM strip) — same transform skills
 *        use, so the manifest signature survives any line-ending churn.
 *   ANY change to canonicalManifestBytes() or this contract requires
 *   the matching change in lib/verify.js. A coordinated attacker who
 *   rewrites manifest.json + manifest-snapshot.json + manifest-snapshot.sha256
 *   without the private key produces a manifest_signature mismatch that
 *   lib/verify.js refuses to load.
 *
 * Windows ACL contract:
 *   On win32, `fs.writeFileSync(..., { mode: 0o600 })` only affects
 *   read-only attributes — it does NOT establish a POSIX-style restrictive
 *   ACL. Any process running under the same desktop user can read the key
 *   by default ACL inheritance from the parent. After writing
 *   .keys/private.pem on Windows, restrictWindowsAcl() shells to icacls
 *   to strip inherited entries and grant Full Control only to the current
 *   user. If icacls is unavailable (Server Core, exotic shells), the call
 *   warns to stderr but does not fail keypair generation — generating the
 *   key was the load-bearing step; ACL tightening is best-effort hardening
 *   on top.
 *
 * Signing ceremony:
 *   1. node lib/sign.js generate-keypair    — generate keypair (one time, per deployment)
 *   2. node lib/sign.js sign-all            — sign all skills (after any content change)
 *   3. node lib/verify.js                   — verify all signatures
 *
 * Key rotation:
 *   1. node lib/sign.js generate-keypair --rotate    — generate new keypair, old sigs become invalid
 *   2. node lib/sign.js sign-all                     — re-sign all skills with new key
 *   3. Commit keys/public.pem update
 *
 * Usage:
 *   node lib/sign.js generate-keypair [--rotate]   — generate Ed25519 keypair
 *   node lib/sign.js sign-all                      — sign all skills in manifest
 *   node lib/sign.js sign <skill-name>             — sign one skill
 *   node lib/sign.js show-pubkey                   — print the public key
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.json');
const KEYS_DIR = path.join(ROOT, '.keys');
const PUBLIC_KEYS_DIR = path.join(ROOT, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(PUBLIC_KEYS_DIR, 'public.pem');

// --- public API ---

/**
 * Generate an Ed25519 keypair.
 * Private key → .keys/private.pem (gitignored)
 * Public key → keys/public.pem (tracked)
 *
 * @param {{ rotate: boolean }} options
 */
function generateKeypair({ rotate = false } = {}) {
  if (fs.existsSync(PRIVATE_KEY_PATH) && !rotate) {
    console.error('[sign] Private key already exists at .keys/private.pem');
    console.error('[sign] Use --rotate to generate a new keypair and invalidate existing signatures.');
    process.exit(1);
  }

  fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(PUBLIC_KEYS_DIR, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { encoding: 'utf8', mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { encoding: 'utf8', mode: 0o644 });

  // on win32, fs.writeFileSync `mode` does not produce
  // a POSIX-style restrictive ACL. Tighten via icacls so other desktop
  // users on the same workstation / CI runner can't read the key.
  restrictWindowsAcl(PRIVATE_KEY_PATH);

  if (rotate) {
    console.log('[sign] Keypair rotated. All existing signatures are now invalid — run: node lib/sign.js sign-all');
  } else {
    console.log('[sign] Ed25519 keypair generated.');
    console.log(`  Private key: .keys/private.pem (gitignored — do not commit)`);
    console.log(`  Public key:  keys/public.pem (tracked — commit this)`);
  }

  console.log('\nNext steps:');
  console.log('  1. node lib/sign.js sign-all    — sign all current skills');
  console.log('  2. node lib/verify.js           — confirm all signatures');
  console.log('  3. git add keys/public.pem && git commit -m "add signing public key"');
}

/**
 * Sign all skills in manifest.json using the private key.
 * Updates manifest.json with Ed25519 signatures.
 *
 * Each manifest entry's `path` is validated through validateSkillPath()
 * BEFORE the file is read — a tampered manifest with an out-of-tree
 * path will reject the whole run.
 */
function signAll() {
  const privateKey = loadPrivateKey();
  const manifest = loadManifest();
  // Validate every entry's path before doing any I/O. Reject the whole
  // manifest on the first traversal attempt — we never want to sign
  // half a manifest then exit non-zero with a partial mutation.
  for (const skill of manifest.skills) {
    validateSkillPath(skill.path);
  }
  let signed = 0;
  let errors = 0;

  for (const skill of manifest.skills) {
    const skillPath = path.join(ROOT, skill.path);
    if (!fs.existsSync(skillPath)) {
      console.error(`[sign] SKIP ${skill.name}: file not found at ${skill.path}`);
      errors++;
      continue;
    }
    const content = fs.readFileSync(skillPath, 'utf8');
    skill.signature = signContent(content, privateKey);
    skill.signed_at = new Date().toISOString();
    delete skill.sha256;
    console.log(`[sign] Signed: ${skill.name}`);
    signed++;
  }

  // sign the manifest itself. Removes any existing
  // manifest_signature field so the canonical bytes are deterministic
  // across re-runs, signs with the private key, then writes the result.
  // A coordinated attacker who rewrites the manifest (and snapshot, and
  // snapshot SHA) without the private key produces an invalid manifest
  // signature; lib/verify.js refuses to load the manifest.
  delete manifest.manifest_signature;
  const manifestSig = signCanonicalManifest(manifest, privateKey);
  manifest.manifest_signature = manifestSig;

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  // S5: verdict line FIRST, fingerprint banner after. An operator
  // scrolling output should not be able to see "fingerprint: SHA256..."
  // and assume success when errors > 0.
  if (errors > 0) {
    console.error(`\n[sign] FAILED — ${signed} signed, ${errors} errors.`);
  } else {
    console.log(`\n[sign] ${signed} skills signed. Manifest signed.`);
  }
  printFingerprintBanner();

  if (errors > 0) process.exit(1);
}

/**
 * Sign a single skill by name.
 * @param {string} skillName
 */
function signOne(skillName) {
  const privateKey = loadPrivateKey();
  const manifest = loadManifest();
  const skill = manifest.skills.find(s => s.name === skillName);
  if (!skill) { console.error(`Skill not found: ${skillName}`); process.exit(1); }

  validateSkillPath(skill.path);
  const skillPath = path.join(ROOT, skill.path);
  const content = fs.readFileSync(skillPath, 'utf8');
  skill.signature = signContent(content, privateKey);
  skill.signed_at = new Date().toISOString();
  delete skill.sha256;

  // P1-4: re-sign the manifest after the per-skill signature changes.
  // Without this a single-skill sign leaves manifest_signature stale.
  delete manifest.manifest_signature;
  manifest.manifest_signature = signCanonicalManifest(manifest, privateKey);

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[sign] Signed: ${skillName}`);
  printFingerprintBanner();
}

// --- helpers ---

/**
 * Normalize skill content for byte-stable signing.
 *
 * Strips a leading UTF-8 BOM (U+FEFF) if present, then converts CRLF
 * line endings to LF. lib/verify.js applies the exact same transform.
 *
 * Without this, a Windows checkout with core.autocrlf=true reads a
 * skill with \r\n while CI reads the same skill with \n — same bytes
 * on disk in git, different bytes in the working tree, different
 * signature. v0.11.x shipped 0/38 verifies for exactly this reason.
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
 *   skill.path MUST NOT contain backslashes (POSIX-style forward slashes
 *     only — manifest paths are not platform-specific).
 *
 * A tampered manifest with "../../../etc/passwd" or
 * "skills/foo/../../.keys/private.pem" is refused; the whole run
 * aborts before any file I/O.
 *
 * @param {string} skillPath
 * @returns {string}
 */
function validateSkillPath(skillPath) {
  if (typeof skillPath !== 'string') {
    throw new Error(`[sign] manifest skill.path must be a string, got ${typeof skillPath}`);
  }
  // Backslash check runs BEFORE the prefix check so a Windows-style
  // path ("skills\foo\skill.md") returns the clearer "use forward
  // slashes" diagnostic, not the misleading "must start with skills/".
  if (skillPath.includes('\\')) {
    throw new Error(`[sign] manifest skill.path must use forward slashes, not backslashes: ${JSON.stringify(skillPath)}`);
  }
  if (!skillPath.startsWith('skills/')) {
    throw new Error(`[sign] manifest skill.path must start with 'skills/': ${JSON.stringify(skillPath)}`);
  }
  if (skillPath.includes('..')) {
    throw new Error(`[sign] manifest skill.path must not contain '..': ${JSON.stringify(skillPath)}`);
  }
  return skillPath;
}

function signContent(content, privateKey) {
  const normalized = normalize(content);
  const signature = crypto.sign(null, Buffer.from(normalized, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return signature.toString('base64');
}

function loadPrivateKey() {
  if (!fs.existsSync(PRIVATE_KEY_PATH)) {
    console.error('[sign] No private key at .keys/private.pem');
    console.error('[sign] Run: node lib/sign.js generate-keypair');
    process.exit(1);
  }
  return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
}

/**
 * canonical byte form of the manifest, used for both
 * signing (lib/sign.js) and verification (lib/verify.js).
 *
 * Contract: the same logical manifest content must produce the same bytes
 * regardless of (a) whether a stale manifest_signature is present, (b)
 * key order at any depth, (c) line endings or BOM.
 *
 *   1. Clone, delete manifest_signature.
 *   2. Recursively sort object keys at every depth (NOT the top-level
 *      whitelist trap — see codex P1 PR #12: passing
 *      `Object.keys(manifest).sort()` as the JSON.stringify replacer-array
 *      treats it as a property allowlist applied to EVERY object level.
 *      Nested fields like `skills[].path` and `skills[].signature` got
 *      silently dropped from the canonical bytes, letting an attacker
 *      swap them without breaking the signature. Now we deep-canonicalize
 *      every object).
 *   3. Apply normalize() — strip leading BOM, convert CRLF → LF.
 *
 * @param {object} manifest
 * @returns {Buffer} canonical UTF-8 bytes
 */
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
 * Sign the canonical manifest bytes with the Ed25519 private key.
 * Returns the manifest_signature object literal to splice into the
 * manifest top level.
 *
 * A: the previous shape included a `signed_at` ISO timestamp.
 * That field was stripped from the canonical bytes before signing (via
 * `delete clone.manifest_signature`), so it was NOT covered by the
 * signature — an attacker who replayed a known-valid signature could
 * rewrite `signed_at` to any value, lending false freshness authority to
 * a stale signature. The field is now omitted entirely. Freshness signal
 * lives outside the signed bytes (git-log mtime of manifest.json, npm
 * publish timestamp).
 *
 * @param {object} manifest
 * @param {string} privateKey PEM-encoded Ed25519 private key
 * @returns {{algorithm:'Ed25519', signature_base64:string}}
 */
function signCanonicalManifest(manifest, privateKey) {
  const bytes = canonicalManifestBytes(manifest);
  const sig = crypto.sign(null, bytes, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return {
    algorithm: 'Ed25519',
    signature_base64: sig.toString('base64'),
  };
}

/**
 * tighten Windows ACL on the private key.
 *
 * fs.writeFileSync({mode: 0o600}) on win32 only affects read-only
 * attributes; the file inherits its ACL from the parent. icacls strips
 * inheritance and grants Full Control only to the current user. Any
 * failure (icacls missing, exotic shell, environment without USERNAME)
 * is warned to stderr — generating the key was the load-bearing step,
 * ACL tightening is best-effort hardening.
 *
 * @param {string} targetPath absolute path of the private key file
 */
function restrictWindowsAcl(targetPath) {
  if (process.platform !== 'win32') return;
  const user = process.env.USERNAME;
  if (!user) {
    console.warn('[sign] WARN: USERNAME env var not set — skipping Windows ACL hardening on ' + targetPath);
    return;
  }
  try {
    execFileSync('icacls', [
      targetPath,
      '/inheritance:r',
      '/grant:r',
      `${user}:F`,
    ], { stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (err) {
    console.warn(
      '[sign] WARN: icacls hardening failed on ' + targetPath + ': ' +
      ((err && err.message) || String(err)) +
      ' — the key was written but ACL inheritance was not stripped. ' +
      'Other desktop users on this machine may be able to read it.'
    );
  }
}

function printFingerprintBanner() {
  if (!fs.existsSync(PUBLIC_KEY_PATH)) return;
  try {
    const pem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const keyObj = crypto.createPublicKey(pem);
    const der = keyObj.export({ type: 'spki', format: 'der' });
    const sha256 = 'SHA256:' + crypto.createHash('sha256').update(der).digest('base64');
    const sha3_512 = 'SHA3-512:' + crypto.createHash('sha3-512').update(der).digest('base64');
    console.log(`[sign] Public key: keys/public.pem`);
    console.log(`[sign] ${sha256}`);
    console.log(`[sign] ${sha3_512}`);
  } catch (_) {
    // Best-effort banner — never let a fingerprint failure poison the run.
  }
}

// --- CLI ---

if (require.main === module) {
  const cmd = process.argv[2];
  const arg = process.argv[3];

  switch (cmd) {
    case 'generate-keypair':
      generateKeypair({ rotate: process.argv.includes('--rotate') });
      break;
    case 'sign-all':
      signAll();
      break;
    case 'sign':
      if (!arg) { console.error('Usage: node lib/sign.js sign <skill-name>'); process.exit(1); }
      signOne(arg);
      break;
    case 'show-pubkey':
      if (!fs.existsSync(PUBLIC_KEY_PATH)) {
        console.error('[sign] No public key found. Run: node lib/sign.js generate-keypair');
        process.exit(1);
      }
      process.stdout.write(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
      break;
    default:
      console.log(`
exceptd Skill Signing Utility

Commands:
  generate-keypair [--rotate]   Generate Ed25519 keypair (.keys/ is gitignored)
  sign-all                      Sign all skills in manifest.json
  sign <skill-name>             Sign one skill
  show-pubkey                   Print the public key

Signing ceremony (first time):
  1. node lib/sign.js generate-keypair
  2. node lib/sign.js sign-all
  3. node lib/verify.js
  4. git add keys/public.pem
`);
  }
}

module.exports = {
  generateKeypair,
  signAll,
  signOne,
  normalize,
  validateSkillPath,
  canonicalManifestBytes,
  signCanonicalManifest,
  restrictWindowsAcl,
};
