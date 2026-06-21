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
