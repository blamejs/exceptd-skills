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
