#!/usr/bin/env node
'use strict';

/**
 * Skill signing utility — Ed25519 keypair management and skill signing.
 *
 * The private key never enters this repository. It is stored at .keys/private.pem
 * which is gitignored. The public key at keys/public.pem is tracked and used
 * by lib/verify.js for signature verification.
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
 */
function signAll() {
  const privateKey = loadPrivateKey();
  const manifest = loadManifest();
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

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`\n[sign] ${signed} skills signed. ${errors} errors.`);

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

  const skillPath = path.join(ROOT, skill.path);
  const content = fs.readFileSync(skillPath, 'utf8');
  skill.signature = signContent(content, privateKey);
  skill.signed_at = new Date().toISOString();
  delete skill.sha256;

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[sign] Signed: ${skillName}`);
}

// --- helpers ---

function signContent(content, privateKey) {
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), {
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

module.exports = { generateKeypair, signAll, signOne };
