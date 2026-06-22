"use strict";


// ---- routed from fetch-destination-from-constants ----
;(() => {
/**
 * The two network fetchers build their request destination from constants plus
 * validated components, never directly from unvalidated file/metadata data, so a
 * tampered registry response or _PROVENANCE.json cannot steer the fetch at an
 * internal or attacker-controlled address (SSRF / file-data-to-network).
 *
 *  - lib/refresh-network.js: the tarball URL is the canonical npm URL built from
 *    string literals + a strict-semver-validated version; a non-semver version
 *    is refused before any fetch.
 *  - scripts/validate-vendor-online.js: rawUrlForPin embeds owner/repo/commit/
 *    path only after each passes a shape guard (GitHub-name / hex git id /
 *    traversal-free path); a tampered component yields null (no fetch).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');

test('rawUrlForPin refuses tampered provenance components (no metadata-steered fetch)', () => {
  const { rawUrlForPin } = require('../scripts/validate-vendor-online.js');

  // Legitimate provenance resolves to a raw.githubusercontent.com URL.
  const ok = rawUrlForPin('https://github.com/blamejs/blamejs.git', '1442f17758a4bd511c63877561c0ffa759f66a87', 'lib/retry.js');
  assert.equal(typeof ok, 'string');
  assert.ok(ok.startsWith('https://raw.githubusercontent.com/blamejs/blamejs/'), `unexpected url: ${ok}`);
  assert.ok(ok.endsWith('/lib/retry.js'));

  // A commit that is not a hex git object id is refused (no fetch built).
  assert.equal(rawUrlForPin('https://github.com/blamejs/blamejs', 'HEAD; curl evil', 'lib/x.js'), null);
  assert.equal(rawUrlForPin('https://github.com/blamejs/blamejs', '../../etc', 'lib/x.js'), null);

  // A path-traversal upstream_path is refused.
  assert.equal(rawUrlForPin('https://github.com/blamejs/blamejs', '1442f17758a4', '../../../etc/passwd'), null);
  assert.equal(rawUrlForPin('https://github.com/blamejs/blamejs', '1442f17758a4', 'a/../../b'), null);

  // A source_repo that is not a github.com repo URL is refused.
  assert.equal(rawUrlForPin('https://evil.example/x/y', '1442f17758a4', 'lib/x.js'), null);
});

test('refresh --network refuses a non-semver registry version before fetching', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'fetch-dest-'));
  try {
    // Fixture metadata with a non-semver version + a hostile dist.tarball. The
    // version guard must reject before any tarball fetch is attempted, and the
    // hostile dist.tarball must never be used (the canonical URL is built from
    // constants, so this fixture cannot even reach the fetch).
    const fixture = path.join(home, 'meta.json');
    fs.writeFileSync(fixture, JSON.stringify({
      version: 'not-a-semver/../@evil',
      dist: { tarball: 'https://169.254.169.254/latest/meta-data/', shasum: 'x' },
    }));
    const r = spawnSync(process.execPath,
      [path.join(ROOT, 'lib', 'refresh-network.js'), 'refresh', '--network', '--json', '--force'],
      { env: { ...process.env, EXCEPTD_REGISTRY_FIXTURE: fixture }, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    assert.notEqual(r.status, 0, 'a non-semver version must be refused'); // allow-notEqual: structured refusal; any non-zero exit is correct
    let body = null;
    for (const s of [r.stdout, r.stderr]) { try { const j = JSON.parse(String(s).trim().split('\n').pop()); if (j) { body = j; break; } } catch { /* not this stream */ } }
    assert.ok(body && body.ok === false, `expected a JSON refusal; got stdout=${r.stdout?.slice(0, 300)} stderr=${r.stderr?.slice(0, 300)}`);
    assert.match(String(body.error), /not valid semver/, 'the refusal must name the non-semver version');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
})();
