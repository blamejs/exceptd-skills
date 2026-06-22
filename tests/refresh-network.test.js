'use strict';

/**
 * tests/refresh-network.test.js
 *
 * lib/refresh-network.js regression pins:
 *   #16 — `refresh --network --air-gap` was silently bypassed when
 *         EXCEPTD_REGISTRY_FIXTURE was set; the air-gap refusal is now
 *         unconditional w.r.t. the fixture env var.
 *   #51 — isAllowedTarballHost validated u.hostname but the connect reused
 *         u.host (port-inclusive); the guard now rejects a non-default port.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const REFRESH_NETWORK = path.join(ROOT, 'lib', 'refresh-network.js');

const { isAllowedTarballHost } = require(REFRESH_NETWORK);

// ===========================================================================
// #16 — air-gap refusal is unconditional w.r.t. EXCEPTD_REGISTRY_FIXTURE.
// ===========================================================================

test('#16 refresh --network --air-gap refuses even with EXCEPTD_REGISTRY_FIXTURE set (exit 4)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-F-ag-'));
  const fixturePath = path.join(dir, 'meta.json');
  // A complete metadata fixture (version + dist.tarball + shasum). Pre-fix
  // the air-gap predicate `&& !process.env.EXCEPTD_REGISTRY_FIXTURE` would
  // short-circuit FALSE here and proceed to a live tarball fetch.
  fs.writeFileSync(fixturePath, JSON.stringify({
    version: '999.0.0',
    dist: { tarball: 'https://registry.npmjs.org/x.tgz', shasum: 'deadbeef' },
  }));
  const r = spawnSync(process.execPath, [REFRESH_NETWORK, 'refresh', '--network', '--air-gap', '--json'], {
    env: { ...process.env, EXCEPTD_REGISTRY_FIXTURE: fixturePath },
    encoding: 'utf8',
  });
  assert.equal(r.status, 4, `air-gap must refuse with exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 300)})`);
  const body = JSON.parse((r.stdout || r.stderr).trim().split('\n').pop());
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /requires network egress; refused/,
    'the refusal message must name the air-gap egress block');
});

// ===========================================================================
// #51 — host-allowlist port hole.
// ===========================================================================

test('#51 isAllowedTarballHost rejects a non-default port', () => {
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org:9999/x.tgz'), false,
    'a port-bearing allowlisted host must be rejected (validate/connect must agree)');
});

test('#51 isAllowedTarballHost accepts the default and explicit-443 ports', () => {
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org/x.tgz'), true);
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org:443/x.tgz'), true);
});

test('#51 isAllowedTarballHost still rejects look-alike and internal hosts', () => {
  // The anchored regex must stay intact — the port fix must not relax it.
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org.attacker.test/x.tgz'), false);
  assert.equal(isAllowedTarballHost('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(isAllowedTarballHost('not a url'), false);
});

// ===========================================================================
// parseTar + fingerprintPublicKey unit smoke.
// ===========================================================================

test('refresh-network parseTar + fingerprintPublicKey unit smoke', () => {
  const { parseTar, fingerprintPublicKey } = require(path.join(ROOT, 'lib', 'refresh-network.js'));
  assert.equal(typeof parseTar, 'function');
  assert.equal(typeof fingerprintPublicKey, 'function');
  // Empty tar buffer parses to empty entries (defensive).
  const empty = parseTar(Buffer.alloc(1024));
  assert.deepEqual(empty, [], 'parseTar handles empty/zero tar gracefully');
  // Local public key fingerprints to a non-null base64 string.
  const pem = fs.readFileSync(path.join(ROOT, 'keys', 'public.pem'), 'utf8');
  const fp = fingerprintPublicKey(pem);
  assert.match(fp, /^[A-Za-z0-9+/=]+$/, 'fingerprint is base64');
});

const test_describe = typeof test.describe === 'function' ? test.describe : (name, fn) => fn();

// ===========================================================================
// refresh-npm-registry-signature — verifyNpmRegistrySignature classifier
//
// RC-3: the `refresh --network` swap path authenticates the npm registry's
// ECDSA signature over `<pkg>@<version>:<integrity>` against pinned registry
// keys before trusting the metadata response — a forged metadata response
// (man-in-the-middle on the registry) cannot reproduce this signature.
// verifyNpmRegistrySignature is a pure classifier; these pin its status
// outcomes so the live swap path's branch can't silently invert.
// ===========================================================================

test_describe('refresh-npm-registry-signature', () => {
  const { verifyNpmRegistrySignature, NPM_REGISTRY_KEYS } = require('../lib/refresh-network.js');

  const PINNED_KEYID = Object.keys(NPM_REGISTRY_KEYS)[0];
  const INTEGRITY = 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

  test('at least one npm registry key is pinned in-tree', () => {
    assert.ok(Object.keys(NPM_REGISTRY_KEYS).length >= 1, 'NPM_REGISTRY_KEYS must pin the registry signing key(s)');
    assert.match(PINNED_KEYID, /^SHA256:/, 'a pinned keyid is the registry SHA256 fingerprint form');
  });

  test('absent: no dist.signatures[] entries → status absent (transport hashes still gate)', () => {
    assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, []).status, 'absent');
    assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, null).status, 'absent');
    assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, undefined).status, 'absent');
  });

  test('unverifiable: missing integrity → no canonical message to verify over', () => {
    const sigs = [{ keyid: PINNED_KEYID, sig: 'AAAA' }];
    assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', '', sigs).status, 'unverifiable');
    assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', null, sigs).status, 'unverifiable');
  });

  test('unknown-keyid: a signature keyid that is not pinned → forged-metadata signal (refused upstream)', () => {
    const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
      { keyid: 'SHA256:not-a-pinned-registry-key', sig: 'AAAA' },
    ]);
    assert.equal(r.status, 'unknown-keyid');
    assert.equal(r.keyid, 'SHA256:not-a-pinned-registry-key');
  });

  test('invalid: a pinned keyid whose signature does not verify → tampering (refused upstream)', () => {
    // A syntactically-valid base64 signature that is not a real registry
    // signature over the message must NOT verify against the pinned key.
    const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
      { keyid: PINNED_KEYID, sig: Buffer.from('not a real signature over this message').toString('base64') },
    ]);
    assert.equal(r.status, 'invalid');
  });

  test('malformed entries are skipped, not crashed on', () => {
    // Entries missing keyid/sig are ignored; with no usable entry the result is
    // the no-entry-verified "invalid" (a present-but-unusable signatures array).
    const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
      null,
      { keyid: 123 },
      { sig: 'AAAA' },
    ]);
    assert.equal(r.status, 'invalid');
  });
});

// ===========================================================================
// air-gap-and-refresh-correctness — isAllowedTarballHost + transport-integrity
//
// The `refresh --network` swap loop replaces data/ + manifest-snapshot.json,
// which carry no per-content Ed25519 signature — a transport hash is their only
// integrity anchor. These exercise the host allowlist and the swap path's
// transport-hash gate end-to-end with https.get stubbed to serve a poisoned
// tarball offline.
// ===========================================================================

test_describe('air-gap-and-refresh-correctness', () => {
  const os = require('node:os');
  const crypto = require('node:crypto');
  const { tryJson } = require('./_helpers/cli');

  // Per-block scratch dir so the swap install-copies never touch the repo tree.
  const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-rn-scratch-'));
  process.on('exit', () => { try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* non-fatal */ } });

  // 2b. tarball fetch-destination allowlist (SSRF guard)
  test('refresh-network pins the tarball fetch host to the npm registry', () => {
    const { isAllowedTarballHost } = require('../lib/refresh-network.js');
    // The registry the /latest metadata is queried from, and its tarball path.
    assert.equal(isAllowedTarballHost('https://registry.npmjs.org/@blamejs/exceptd-skills/-/exceptd-skills.tgz'), true);
    assert.equal(isAllowedTarballHost('https://npmjs.com/x.tgz'), true);
    // A tampered metadata response / fixture must not be able to steer the fetch
    // at an internal or attacker-controlled host.
    assert.equal(isAllowedTarballHost('https://registry.npmjs.org.attacker.test/x.tgz'), false);
    assert.equal(isAllowedTarballHost('https://evil.example/x.tgz'), false);
    assert.equal(isAllowedTarballHost('http://169.254.169.254/latest/meta-data/'), false);
    assert.equal(isAllowedTarballHost('not a url'), false);
  });

  // 10. refresh --network transport-integrity floor
  //
  // Build an isolated install copy + a signed-but-data-poisoned npm-style
  // tarball, then drive the real lib/refresh-network.js main() with https.get
  // stubbed to serve that tarball, so the full swap path runs offline. The
  // install copy is a sibling tempdir so the swap never touches the repo tree.
  function refreshNetworkSwapHarness() {
    const sign = require('../lib/sign.js');
    const REPO = ROOT;
    const inst = fs.mkdtempSync(path.join(SCRATCH, 'rn-install-'));
    for (const rel of ['keys', 'manifest.json', 'package.json', 'lib', 'vendor', 'skills', 'data']) {
      fs.cpSync(path.join(REPO, rel), path.join(inst, rel), { recursive: true });
    }
    // EPHEMERAL signing identity — never read the repo's .keys/private.pem, which
    // is gitignored and absent on a fresh CI checkout. The install copy's public
    // key, every per-skill signature, and the manifest envelope are all re-signed
    // with this key, so the swap path's signature + fingerprint checks verify
    // against an identity that exists only inside this test.
    const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    fs.writeFileSync(path.join(inst, 'keys', 'public.pem'), pub);
    // Re-pin keys/EXPECTED_FINGERPRINT to the ephemeral key (same SHA256:<base64-
    // of-spki-der> form the swap path compares), else the fingerprint-pin guard
    // refuses the swap because the install copy still carries the repo key's pin.
    const ephFp = crypto.createHash('sha256')
      .update(crypto.createPublicKey(pub).export({ type: 'spki', format: 'der' }))
      .digest('base64');
    fs.writeFileSync(path.join(inst, 'keys', 'EXPECTED_FINGERPRINT'), `SHA256:${ephFp}\n`);

    // Version bumped so the swap is not a no-op; re-sign every per-skill body and
    // the manifest envelope with the ephemeral key so they verify against the
    // ephemeral public key written above.
    const signBody = (body) =>
      crypto.sign(null, Buffer.from(sign.normalize(body), 'utf8'), { key: priv, dsaEncoding: 'ieee-p1363' }).toString('base64');
    const manifest = JSON.parse(fs.readFileSync(path.join(inst, 'manifest.json'), 'utf8'));
    manifest.version = '999.0.0';
    for (const sk of manifest.skills) {
      sk.signature = signBody(fs.readFileSync(path.join(inst, sk.path), 'utf8'));
    }
    delete manifest.manifest_signature;
    manifest.manifest_signature = sign.signCanonicalManifest(manifest, priv);

    // Poison data/cve-catalog.json — the file with no per-content signature.
    const poisonedCatalog = fs
      .readFileSync(path.join(inst, 'data', 'cve-catalog.json'), 'utf8')
      .replace(/^\{/, '{"__ATTACKER_INJECTED__":"transport-integrity regression marker",');

    const tarHeader = (name, size) => {
      const b = Buffer.alloc(512, 0);
      b.write(name.slice(0, 100), 0, 'utf8');
      b.write('0000644\0', 100); b.write('0000000\0', 108); b.write('0000000\0', 116);
      b.write(size.toString(8).padStart(11, '0') + '\0', 124);
      b.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136);
      b.write('        ', 148); b.write('0', 156);
      b.write('ustar\0', 257); b.write('00', 263);
      let sum = 0; for (let i = 0; i < 512; i++) sum += b[i];
      b.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
      return b;
    };
    const tarEntry = (name, body) => {
      const x = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
      return Buffer.concat([tarHeader(name, x.length), x, Buffer.alloc((512 - (x.length % 512)) % 512, 0)]);
    };
    const parts = [
      tarEntry('package/manifest.json', JSON.stringify(manifest, null, 2)),
      tarEntry('package/keys/public.pem', pub),
      tarEntry('package/manifest-snapshot.json', '{"snapshot":"attacker-controlled"}'),
      tarEntry('package/data/cve-catalog.json', poisonedCatalog),
    ];
    for (const sk of manifest.skills) parts.push(tarEntry('package/' + sk.path, fs.readFileSync(path.join(inst, sk.path))));
    parts.push(Buffer.alloc(1024, 0));
    const tgz = require('node:zlib').gzipSync(Buffer.concat(parts));
    const tgzPath = path.join(inst, 'tarball.tgz');
    fs.writeFileSync(tgzPath, tgz);

    // Preload that serves `tgz` for any npmjs.org *.tgz GET (offline; no network).
    const preloadPath = path.join(inst, 'preload.js');
    fs.writeFileSync(preloadPath,
      '"use strict";const https=require("https");const fs=require("fs");' +
      'const {PassThrough}=require("stream");const {EventEmitter}=require("events");' +
      'const TGZ=fs.readFileSync(process.env.RN_TGZ);const o=https.get;' +
      'https.get=function(opts,cb){const h=(opts&&opts.host)||"";const p=(opts&&opts.path)||"";' +
      'if(String(h).includes("npmjs.org")&&/\\.tgz$/.test(p)){' +
      'const res=new PassThrough();res.statusCode=200;const req=new EventEmitter();req.destroy=()=>{};' +
      'process.nextTick(()=>{cb(res);process.nextTick(()=>res.end(TGZ));});return req;}' +
      'return o.apply(this,arguments);};');

    const sri = 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64');
    const tarballUrl = 'https://registry.npmjs.org/@blamejs/exceptd-skills/-/exceptd-skills-999.0.0.tgz';

    const run = (distMeta) => {
      const fixturePath = path.join(inst, 'fixture.json');
      fs.writeFileSync(fixturePath, JSON.stringify({ version: '999.0.0', dist: distMeta }));
      const r = spawnSync(process.execPath,
        ['-r', preloadPath, path.join(inst, 'lib', 'refresh-network.js'), 'refresh', '--network', '--json'],
        { env: { ...process.env, RN_TGZ: tgzPath, EXCEPTD_REGISTRY_FIXTURE: fixturePath }, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
      const poisoned = fs.readFileSync(path.join(inst, 'data', 'cve-catalog.json'), 'utf8').includes('__ATTACKER_INJECTED__');
      return { r, poisoned };
    };
    return { run, sri, tarballUrl };
  }

  test('refresh --network refuses the swap when dist.integrity AND dist.shasum are both absent (exit 4)', () => {
    const { run, tarballUrl } = refreshNetworkSwapHarness();
    // dist.tarball present, NO dist.integrity, NO dist.shasum.
    const { r, poisoned } = run({ tarball: tarballUrl });
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 300)} stderr: ${r.stderr.slice(0, 300)})`);
    const body = tryJson(r.stdout.trim().split('\n').pop()) || tryJson(r.stderr.trim().split('\n').pop());
    assert.ok(body, `expected JSON refusal; got stdout=${r.stdout.slice(0, 300)}`);
    assert.equal(body.ok, false);
    assert.equal(typeof body.error, 'string');
    assert.match(body.error, /no verifiable transport integrity/);
    // The unauthenticated catalog bytes must NOT have been installed.
    assert.equal(poisoned, false, 'poisoned data/cve-catalog.json must NOT be swapped in when no transport hash is verifiable');
  });

  test('refresh --network still swaps when a valid sha512 dist.integrity is present (exit 0)', () => {
    const { run, sri, tarballUrl } = refreshNetworkSwapHarness();
    // Valid sha512 SRI over the served bytes — the legitimate path must keep working.
    const { r } = run({ tarball: tarballUrl, integrity: sri });
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stdout: ${r.stdout.slice(0, 300)} stderr: ${r.stderr.slice(0, 300)})`);
    const body = tryJson(r.stdout.trim().split('\n').pop());
    assert.ok(body, `expected JSON success; got stdout=${r.stdout.slice(0, 300)}`);
    assert.equal(body.ok, true);
    assert.equal(typeof body.files_written, 'number');
    assert.ok(body.files_written > 0, 'a successful swap writes at least one file');
  });
});
