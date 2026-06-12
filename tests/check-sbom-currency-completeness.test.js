'use strict';

/**
 * Regression for the SBOM-currency gate hardening:
 *   [12] the free-text "N catalogs" / "N jurisdictions" counts in the
 *        description are validated (not only the per-CVE/CWE tokens + skills);
 *   [14] every shipped file (package.json.files expansion) must have a file:
 *        component, and the aggregate bundle digest is recomputed and compared.
 *
 * Shadow-repo pattern (copy the SBOM into a tempdir, mutate it, symlink the
 * rest from ROOT) — mirrors check-sbom-currency-file-hashes.test.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const { checkSbomCurrency, DESCRIPTION_ENTRY_TOKENS, catalogEntryCount } = require(path.join(ROOT, 'scripts', 'check-sbom-currency.js'));
const { expandAllowlist, bundleDigest } = require(path.join(ROOT, 'scripts', 'refresh-sbom.js'));

const BRING = ['manifest.json', 'package.json', 'data', 'keys', 'agents', 'bin', 'lib', 'orchestrator',
  'scripts', 'sources', 'vendor', 'skills', 'manifest-snapshot.json', 'manifest-snapshot.sha256',
  'AGENTS.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CONTEXT.md', 'LICENSE', 'NOTICE', 'README.md', 'SECURITY.md'];

function shadow(mutate) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-complete-'));
  const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
  mutate(sbom);
  fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
  for (const rel of BRING) {
    const src = path.join(ROOT, rel);
    const dst = path.join(tmp, rel);
    if (!fs.existsSync(src)) continue;
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? 'dir' : 'file'); }
    catch { fs.cpSync(src, dst, { recursive: true }); }
  }
  return tmp;
}

test('the SBOM helper exports are usable (DESCRIPTION_ENTRY_TOKENS / catalogEntryCount / expandAllowlist / bundleDigest)', () => {
  // These are reused across check-sbom-currency, sync-package-description, and
  // the completeness check; pin the exported surface + basic behavior.
  assert.ok(Array.isArray(DESCRIPTION_ENTRY_TOKENS) && DESCRIPTION_ENTRY_TOKENS.length > 0,
    'DESCRIPTION_ENTRY_TOKENS must be a non-empty array');
  assert.equal(typeof catalogEntryCount, 'function');
  const n = catalogEntryCount(path.join(ROOT, 'data'), 'cve-catalog.json');
  assert.ok(typeof n === 'number' && n > 0, `catalogEntryCount must count cve-catalog entries; got ${n}`);
  assert.equal(typeof expandAllowlist, 'function');
  const files = expandAllowlist(['manifest.json']);
  assert.ok(Array.isArray(files) && files.includes('manifest.json'),
    'expandAllowlist must expand a file entry to its repo-relative path');
  assert.equal(typeof bundleDigest, 'function');
  const digest = bundleDigest([{ name: 'a', hashes: [{ content: 'deadbeef' }] }]);
  assert.equal(typeof digest, 'string');
  assert.ok(/^[0-9a-f]{64}$/.test(digest), 'bundleDigest must return a SHA-256 hex string');
});

test('check-sbom-currency: a stale "N catalogs" description count fails the gate', () => {
  const tmp = shadow((sbom) => {
    sbom.metadata.component.description =
      sbom.metadata.component.description.replace(/\b\d+ catalogs\b/, '99 catalogs');
  });
  try {
    const r = checkSbomCurrency(tmp);
    assert.equal(r.ok, false, 'stale catalog count must fail the gate');
    assert.ok(r.errors.some((e) => /catalog count is 99/.test(e)),
      `expected a catalog-count error; got ${JSON.stringify(r.errors.slice(0, 4))}`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('check-sbom-currency: a shipped file with no file: component fails the gate', () => {
  const tmp = shadow((sbom) => {
    sbom.components = sbom.components.filter((c) => c.name !== 'manifest.json');
  });
  try {
    const r = checkSbomCurrency(tmp);
    assert.equal(r.ok, false, 'a missing file: component must fail the gate');
    assert.ok(r.errors.some((e) => /Shipped file "manifest\.json".*no file: component/.test(e)),
      `expected a completeness error; got ${JSON.stringify(r.errors.slice(0, 6))}`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('check-sbom-currency: a tampered aggregate bundle digest fails the gate', () => {
  const tmp = shadow((sbom) => {
    const h = (sbom.metadata.component.hashes || []).find((x) => x.alg === 'SHA-256');
    if (h) h.content = 'c'.repeat(64);
  });
  try {
    const r = checkSbomCurrency(tmp);
    assert.equal(r.ok, false, 'a tampered bundle digest must fail the gate');
    assert.ok(r.errors.some((e) => /bundle digest mismatch/.test(e)),
      `expected a bundle-digest error; got ${JSON.stringify(r.errors.slice(0, 4))}`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
