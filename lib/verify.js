'use strict';

/**
 * Skill integrity verifier — Ed25519 cryptographic signatures.
 *
 * SHA-256 hashes alone protect against accidental corruption; anyone with repo
 * write access can update the hash after tampering. Ed25519 signatures prove a
 * specific keypair signed each skill. Even if the manifest is updated, a valid
 * signature requires the private key, which never enters this repository.
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

  const manifest = loadManifest();
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

  const manifest = loadManifest();
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

  const manifest = loadManifest();
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

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`[verify] Signed ${result.signed.length} skills with Ed25519 private key.`);
  return result;
}

// --- private helpers ---

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
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return signature.toString('base64');
}

function verify(content, signatureBase64, publicKey) {
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
  // Compute + print the public key fingerprints so operators can pin
  // the key out-of-band. Without this, a swapped keys/public.pem
  // would still produce a "verified" message — undetectable from the
  // exit code alone. Dual fingerprint (SHA-256 + SHA3-512) gives
  // ssh-keygen compatibility AND a SHA-3 family diversity hedge.
  const pubKey = loadPublicKey();
  const fp = publicKeyFingerprint(pubKey);
  console.log(`\n[verify] ${result.valid.length}/${total} skills passed Ed25519 verification.`);
  console.log(`[verify] Public key: keys/public.pem`);
  console.log(`[verify] ${fp.sha256}`);
  console.log(`[verify] ${fp.sha3_512}`);

  if (result.invalid.length > 0) { console.error('[verify] TAMPERED:', result.invalid.join(', ')); process.exit(1); }
  if (result.missing_sig.length > 0) { console.warn('[verify] UNSIGNED:', result.missing_sig.join(', ')); process.exit(1); }
  if (result.missing_file.length > 0) { console.error('[verify] MISSING:', result.missing_file.join(', ')); process.exit(1); }

  console.log('[verify] All skills verified.');
  process.exit(0);
}

module.exports = { verifyAll, verifyOne, signAll };
