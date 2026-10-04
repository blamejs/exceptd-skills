'use strict';

/**
 * A copy of the package in a tempdir that signs attestations with an ephemeral
 * Ed25519 key, so tests that need a signed attestation run on any checkout,
 * including CI, where .keys/private.pem does not exist.
 *
 * The copy holds the shipped tree (the package.json `files` set), a fresh key
 * pair in .keys/private.pem and keys/public.pem, keys/EXPECTED_FINGERPRINT
 * re-pinned to that key, and manifest.json with every skill and the manifest
 * envelope re-signed under it. The repository's own keys and .keys/ are never
 * read or written. The copy is built once per process on first use and removed
 * when the process exits.
 *
 *   const { signedInstall } = require('./_helpers/signed-install.js');
 *   const { root, cli } = signedInstall();   // cli: path to the copy's bin/exceptd.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..', '..');
let _install = null;

function signedInstall() {
  if (_install) return _install;
  const sign = require(path.join(ROOT, 'lib', 'sign.js'));
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-signed-install-'));
  process.on('exit', () => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* non-fatal */ }
  });

  for (const entry of ['package.json'].concat(pkg.files)) {
    const rel = entry.replace(/\/$/, '');
    const src = path.join(ROOT, rel);
    if (!fs.existsSync(src)) continue;
    fs.cpSync(src, path.join(root, rel), { recursive: true });
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  fs.mkdirSync(path.join(root, '.keys'), { recursive: true });
  fs.writeFileSync(path.join(root, '.keys', 'private.pem'), privateKey, { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'keys', 'public.pem'), publicKey);
  const fingerprint = crypto.createHash('sha256')
    .update(crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' }))
    .digest('base64');
  fs.writeFileSync(path.join(root, 'keys', 'EXPECTED_FINGERPRINT'), `SHA256:${fingerprint}\n`);

  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const skill of manifest.skills) {
    const body = fs.readFileSync(path.join(root, skill.path), 'utf8');
    skill.signature = crypto.sign(null, Buffer.from(sign.normalize(body), 'utf8'),
      { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  }
  delete manifest.manifest_signature;
  manifest.manifest_signature = sign.signCanonicalManifest(manifest, privateKey);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

  _install = { root, cli: path.join(root, 'bin', 'exceptd.js'), publicKey };
  return _install;
}

module.exports = { signedInstall };
