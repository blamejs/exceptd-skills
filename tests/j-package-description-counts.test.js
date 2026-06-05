'use strict';

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
