'use strict';

/**
 * Regression: an auto-refresh that changes a catalog entry count must keep
 * package.json.description in sync (refresh-sbom copies it into the SBOM and
 * the SBOM-currency gate validates each "<N> <label>" token). syncPackageDescription
 * rewrites only the integer in each known token from the live counts.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const { syncPackageDescription } = require(path.join(ROOT, 'scripts', 'sync-package-description.js'));

function shadow(stalePkgDescription) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sync-desc-'));
  for (const rel of ['data', 'manifest.json']) {
    const src = path.join(ROOT, rel);
    const dst = path.join(tmp, rel);
    try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? 'dir' : 'file'); }
    catch { fs.cpSync(src, dst, { recursive: true }); }
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  pkg.description = stalePkgDescription(pkg.description);
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
  return tmp;
}

test('syncPackageDescription rewrites a stale count token to the live value', () => {
  const tmp = shadow((d) => d.replace(/\b\d+ skills\b/, '999 skills').replace(/\b\d+ catalogs\b/, '888 catalogs'));
  try {
    const r = syncPackageDescription(tmp);
    assert.equal(r.changed, true, 'a stale token must produce a change');
    const updated = JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8')).description;
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
    const liveSkills = manifest.skills.length;
    const liveCatalogs = fs.readdirSync(path.join(ROOT, 'data')).filter((f) => f.endsWith('.json')).length;
    assert.match(updated, new RegExp('\\b' + liveSkills + ' skills\\b'));
    assert.match(updated, new RegExp('\\b' + liveCatalogs + ' catalogs\\b'));
    assert.equal(/\b999 skills\b/.test(updated), false, 'stale skill count must be gone');
    assert.equal(/\b888 catalogs\b/.test(updated), false, 'stale catalog count must be gone');
    // Idempotent: a second run makes no further change.
    assert.equal(syncPackageDescription(tmp).changed, false);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});


// ---- routed from j-package-description-counts ----
require("node:test").describe("j-package-description-counts", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/j-package-description-counts.test.js
 *
 * The package.json `description` is rendered on the npm package page and
 * states a catalog count plus six per-catalog cardinalities. These are
 * hand-edited per release and drift silently when a data/*.json catalog is
 * added/removed or a catalog grows. This gate pins every count in the
 * description to the live data so the npm-page copy cannot lie.
 *
 * Every assertion compares the EXACT documented integer against the live
 * count (no presence-only coincidence passes).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const description = pkg.description || '';

function liveCount(file) {
  const obj = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', file), 'utf8'));
  return Object.keys(obj).filter((k) => !k.startsWith('_')).length;
}

// Number of top-level catalog files shipped under data/ (subdirectories like
// data/playbooks/ and data/_indexes/ are not top-level catalog files).
function liveCatalogFileCount() {
  return fs
    .readdirSync(path.join(ROOT, 'data'), { withFileTypes: true })
    .filter((d) => d.isFile() && d.name.endsWith('.json')).length;
}

// Pull the integer that precedes a label in the description (e.g. "11 catalogs",
// "439 CVEs"). The label is matched literally up to a word boundary.
function describedCount(label) {
  const re = new RegExp('(\\d+)\\s+' + label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const m = description.match(re);
  assert.ok(m, `package.json description is missing a "<N> ${label}" token`);
  return Number(m[1]);
}

test('package.json description "N catalogs" matches the live catalog-file count', () => {
  assert.equal(describedCount('catalogs'), liveCatalogFileCount());
});

const CARDINALITY_LABELS = [
  ['CVEs', 'cve-catalog.json'],
  ['CWEs', 'cwe-catalog.json'],
  ['ATLAS', 'atlas-ttps.json'],
  ['D3FEND', 'd3fend-catalog.json'],
  ['RFCs', 'rfc-references.json'],
];

for (const [label, file] of CARDINALITY_LABELS) {
  test(`package.json description "N ${label}" matches data/${file}`, () => {
    assert.equal(describedCount(label), liveCount(file));
  });
}

test('package.json description "N ATT&CK + ICS" matches data/attack-techniques.json', () => {
  // The ATT&CK label carries a "+ ICS" suffix; match the integer before it.
  const m = description.match(/(\d+)\s+ATT&CK \+ ICS/);
  assert.ok(m, 'package.json description is missing a "<N> ATT&CK + ICS" token');
  assert.equal(Number(m[1]), liveCount('attack-techniques.json'));
});

test('package.json description "N jurisdictions" matches data/global-frameworks.json', () => {
  assert.equal(describedCount('jurisdictions'), liveCount('global-frameworks.json'));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
