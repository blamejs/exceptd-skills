#!/usr/bin/env node
'use strict';

/**
 * Ed25519 keypair management and skill signing.
 *
 * normalize() and canonicalManifestBytes() are one half of a contract with
 * lib/verify.js — a change to either requires the matching change there, or the
 * verifier rejects everything this signs.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { safeExit } = require('./exit-codes');
// The verifier's own validator, so signer and verifier cannot disagree about
// what a well-formed manifest is. verify.js does not require sign.js.
const { validateAgainstSchema } = require('./verify');

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.json');
const KEYS_DIR = path.join(ROOT, '.keys');
const PUBLIC_KEYS_DIR = path.join(ROOT, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(PUBLIC_KEYS_DIR, 'public.pem');
const MANIFEST_SCHEMA_PATH = path.join(__dirname, 'schemas', 'manifest.schema.json');

/**
 * Generate an Ed25519 keypair: private key → .keys/private.pem, public key →
 * keys/public.pem. `aclHardened` comes back false on win32 when icacls failed.
 */
function generateKeypair({ rotate = false } = {}) {
  fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(PUBLIC_KEYS_DIR, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });

  // 'wx' (O_CREAT|O_EXCL) refuses an existing key in the open itself: no
  // existsSync to race against, and no following a preplanted symlink. Only
  // --rotate re-keys ('w'); silently regenerating orphans every signature.
  const openFlag = rotate ? 'w' : 'wx';
  let privFd;
  try {
    privFd = fs.openSync(PRIVATE_KEY_PATH, openFlag, 0o600);
  } catch (e) {
    if (e.code === 'EEXIST') {
      console.error('[sign] Private key already exists at .keys/private.pem');
      console.error('[sign] Use --rotate to generate a new keypair and invalidate existing signatures.');
      process.exit(1);
    }
    throw e;
  }
  let pubFd;
  try {
    pubFd = fs.openSync(PUBLIC_KEY_PATH, openFlag, 0o644);
  } catch (e) {
    fs.closeSync(privFd);
    // A public-key clash must not leave a half signing identity behind.
    try { fs.unlinkSync(PRIVATE_KEY_PATH); } catch { /* best effort */ }
    if (e.code === 'EEXIST') {
      console.error('[sign] Public key already exists at keys/public.pem but no matching private key.');
      console.error('[sign] Refusing to overwrite the public key — that would orphan every existing signature.');
      console.error('[sign] If you are setting up a fresh signing identity, pass --rotate to confirm. After --rotate you must re-sign all skills with sign-all.');
      process.exit(1);
    }
    throw e;
  }
  try {
    fs.writeSync(privFd, privateKey);
    fs.writeSync(pubFd, publicKey);
  } finally {
    fs.closeSync(privFd);
    fs.closeSync(pubFd);
  }

  const aclHardened = restrictWindowsAcl(PRIVATE_KEY_PATH);

  if (rotate) {
    console.log('[sign] Keypair rotated. All existing signatures are now invalid — re-sign with sign-all.');
  } else {
    console.log('[sign] Ed25519 keypair generated.');
    console.log(`  Private key: .keys/private.pem (gitignored — do not commit)`);
    console.log(`  Public key:  keys/public.pem (tracked — commit this)`);
  }
  if (process.platform === 'win32') {
    console.log(`  Windows ACL hardened: ${aclHardened ? 'yes' : 'NO — other desktop users on this machine may be able to read the private key'}`);
  }

  console.log('\nNext steps:');
  if (rotate) {
    console.log('  1. exceptd doctor --fix     — detects post-rotate stale signatures and chains sign-all');
    console.log('     (or: node $(exceptd path)/lib/sign.js sign-all   — re-sign directly)');
    console.log('  2. exceptd doctor           — confirm signatures verify against the new public key');
    console.log('  3. git add keys/public.pem && git commit -m "rotate signing public key"');
  } else {
    console.log('  1. exceptd doctor --fix     — chains sign-all after first key generation');
    console.log('  2. exceptd doctor           — confirm signatures verify');
    console.log('  3. git add keys/public.pem && git commit -m "add signing public key"');
  }
  return { aclHardened };
}

/** Sign every skill in manifest.json and then the manifest itself, in place. */
function signAll() {
  const privateKey = loadPrivateKey();
  const manifest = loadManifest();
  // Schema and every skill.path are checked before any I/O, so a tampered
  // manifest is refused whole rather than left half-signed.
  validateManifestSchema(manifest, 'sign-all');
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

  // Drop any existing signature first so the canonical bytes are re-run stable.
  delete manifest.manifest_signature;
  const manifestSig = signCanonicalManifest(manifest, privateKey);
  manifest.manifest_signature = manifestSig;

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  // Verdict before the fingerprint banner, so "SHA256..." cannot read as success.
  if (errors > 0) {
    console.error(`\n[sign] FAILED — ${signed} signed, ${errors} errors.`);
  } else {
    console.log(`\n[sign] ${signed} skills signed. Manifest signed.`);
  }
  printFingerprintBanner();

  if (errors > 0) { safeExit(1); return; }
}

function signOne(skillName) {
  const privateKey = loadPrivateKey();
  const manifest = loadManifest();
  validateManifestSchema(manifest, 'sign');
  const skill = manifest.skills.find(s => s.name === skillName);
  if (!skill) { console.error(`Skill not found: ${skillName}`); process.exit(1); }

  validateSkillPath(skill.path);
  const skillPath = path.join(ROOT, skill.path);
  const content = fs.readFileSync(skillPath, 'utf8');
  skill.signature = signContent(content, privateKey);
  skill.signed_at = new Date().toISOString();
  delete skill.sha256;

  // Changing one skill signature stales the manifest signature, so recompute it.
  delete manifest.manifest_signature;
  manifest.manifest_signature = signCanonicalManifest(manifest, privateKey);

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[sign] Signed: ${skillName}`);
  printFingerprintBanner();
}

/**
 * Normalize content for byte-stable signing: strip a leading UTF-8 BOM, then
 * CRLF → LF, so a core.autocrlf=true checkout signs the bytes CI reads.
 * lib/verify.js applies the identical transform.
 */
function normalize(content) {
  let s = content;
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, '\n');
}

/**
 * Throw unless skillPath is a POSIX-style string under "skills/" with no "..",
 * so a tampered manifest cannot point the signer outside the skills tree.
 */
function validateSkillPath(skillPath) {
  if (typeof skillPath !== 'string') {
    throw new Error(`[sign] manifest skill.path must be a string, got ${typeof skillPath}`);
  }
  // Before the prefix check, so a backslash path reports the backslash.
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
 * Validate the manifest against lib/schemas/manifest.schema.json before signing:
 * anything schema-invalid signed here throws in lib/verify.js
 * loadManifestValidated() at install time. `who` is the calling verb.
 */
function validateManifestSchema(manifest, who) {
  const schema = JSON.parse(fs.readFileSync(MANIFEST_SCHEMA_PATH, 'utf8'));
  const errors = validateAgainstSchema(manifest, schema, 'manifest');
  if (errors.length > 0) {
    const detail = errors.slice(0, 10).map(e => '  - ' + e).join('\n');
    const more = errors.length > 10 ? `\n  ...and ${errors.length - 10} more` : '';
    throw new Error(`[sign] manifest.json failed schema validation before ${who} — refusing to sign:\n${detail}${more}`);
  }
}

/**
 * Sort object keys recursively, at every depth. A top-level-only sort — passing
 * `Object.keys(manifest).sort()` as the JSON.stringify replacer array — makes
 * that array a property allowlist applied to EVERY object, dropping
 * `skills[].path` and `skills[].signature` out of the signed bytes.
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

// The signed bytes: identical for the same logical manifest whatever its key
// order, line endings, or leftover manifest_signature. lib/verify.js matches this.
function canonicalManifestBytes(manifest) {
  const clone = { ...manifest };
  delete clone.manifest_signature;
  const json = JSON.stringify(canonicalize(clone), null, 2);
  return Buffer.from(normalize(json), 'utf8');
}

/**
 * Sign the canonical manifest bytes, returning the manifest's top-level
 * `manifest_signature` object. No `signed_at` in that shape: a timestamp
 * stripped from the bytes before signing is unsigned metadata, so a replayed
 * signature could carry any date and lend false freshness.
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
 * Tighten the Windows ACL on the private key: `mode: 0o600` on win32 only sets
 * the read-only attribute, so the file otherwise inherits the parent's ACL and
 * every desktop user can read it. Returns true off win32; returns false and
 * warns on any failure, which is best-effort hardening, not the key write.
 */
function restrictWindowsAcl(targetPath) {
  if (process.platform !== 'win32') return true;
  const user = process.env.USERNAME;
  if (!user) {
    console.warn('[sign] WARN: USERNAME env var not set — skipping Windows ACL hardening on ' + targetPath);
    return false;
  }
  try {
    execFileSync('icacls', [
      targetPath,
      '/inheritance:r',
      '/grant:r',
      `${user}:F`,
    ], { stdio: ['ignore', 'ignore', 'pipe'] });
    return true;
  } catch (err) {
    console.warn(
      '[sign] WARN: icacls hardening failed on ' + targetPath + ': ' +
      ((err && err.message) || String(err)) +
      ' — the key was written but ACL inheritance was not stripped. ' +
      'Other desktop users on this machine may be able to read it.'
    );
    return false;
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

if (require.main === module) {
  const cmd = process.argv[2];
  const arg = process.argv[3];

  switch (cmd) {
    case 'generate-keypair': {
      const { aclHardened } = generateKeypair({ rotate: process.argv.includes('--rotate') });
      // A non-zero exit so automation (bootstrap.js, doctor --fix) sees it, not a
      // clean 0. safeExit, not process.exit, so the banner drains.
      if (process.platform === 'win32' && aclHardened === false) {
        if (process.env.EXCEPTD_ALLOW_WEAK_KEY_ACL === '1') {
          console.warn('[sign] WARN: private-key ACL was NOT hardened; continuing because EXCEPTD_ALLOW_WEAK_KEY_ACL=1.');
        } else {
          console.error('[sign] ERROR: private key written but Windows ACL hardening FAILED — the key may be readable by other desktop users on this machine. Strip inheritance manually (icacls .keys\\private.pem /inheritance:r /grant:r "%USERNAME%":F), or set EXCEPTD_ALLOW_WEAK_KEY_ACL=1 to accept the weaker ACL on a single-user host.');
          safeExit(1);
        }
      }
      break;
    }
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
  validateManifestSchema,
  canonicalManifestBytes,
  signCanonicalManifest,
  restrictWindowsAcl,
};
