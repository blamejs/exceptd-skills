"use strict";


// ---- routed from context-inventory ----
;(() => {
/**
 * tests/context-inventory.test.js
 *
 * CONTEXT.md ships in the npm tarball and carries an "Authoritative catalog
 * inventory" table that hand-states an entry count per data/*.json catalog.
 * Hand-maintained counts drift as the catalogs grow; this gate pins every
 * row of the table to the live entry count so an operator reading the table
 * never sees a stale number.
 *
 * Each assertion compares the EXACT documented count against the live count
 * (no "is non-empty" coincidence passes). Catalogs are ID-keyed objects with
 * `_`-prefixed metadata keys; the counted population is every non-metadata
 * top-level key. The playbooks row counts the .json files under
 * data/playbooks/.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CONTEXT = fs.readFileSync(path.join(ROOT, 'CONTEXT.md'), 'utf8');

function liveCatalogCount(file) {
  const obj = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', file), 'utf8'));
  return Object.keys(obj).filter((k) => !k.startsWith('_')).length;
}

function livePlaybookCount() {
  return fs
    .readdirSync(path.join(ROOT, 'data', 'playbooks'))
    .filter((f) => f.endsWith('.json')).length;
}

// Pull the integer count from the inventory table row whose first cell is the
// backtick-wrapped name. The Entries cell may carry a trailing word (e.g.
// "35 jurisdictions"); capture only the leading integer.
function tableCount(name) {
  const re = new RegExp(
    '^\\|\\s*`' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '`\\s*\\|\\s*(\\d+)',
    'm'
  );
  const m = CONTEXT.match(re);
  assert.ok(m, `CONTEXT.md inventory table is missing a row for \`${name}\``);
  return Number(m[1]);
}

// Catalog file -> the table row name that documents its entry count.
const CATALOG_ROWS = [
  'cve-catalog.json',
  'atlas-ttps.json',
  'attack-techniques.json',
  'framework-control-gaps.json',
  'exploit-availability.json',
  'global-frameworks.json',
  'zeroday-lessons.json',
  'cwe-catalog.json',
  'd3fend-catalog.json',
  'rfc-references.json',
  'dlp-controls.json',
];

for (const file of CATALOG_ROWS) {
  test(`CONTEXT.md inventory pins ${file} to the live entry count`, () => {
    const documented = tableCount(file);
    const live = liveCatalogCount(file);
    assert.equal(
      documented,
      live,
      `CONTEXT.md says ${file} has ${documented} entries; data/${file} has ${live}`
    );
  });
}

test('CONTEXT.md inventory pins playbooks/ to the live file count', () => {
  const documented = tableCount('playbooks/');
  const live = livePlaybookCount();
  assert.equal(
    documented,
    live,
    `CONTEXT.md says playbooks/ has ${documented} entries; data/playbooks/ has ${live} .json files`
  );
});

// ARCHITECTURE.md and CONTEXT.md must agree on the CWE entry count so the two
// shipped docs cannot disagree about the same catalog.
test('ARCHITECTURE.md CWE count matches the live cwe-catalog.json count', () => {
  const arch = fs.readFileSync(path.join(ROOT, 'ARCHITECTURE.md'), 'utf8');
  const m = arch.match(/(\d+)\s+CWE entries pinned to/);
  assert.ok(m, 'ARCHITECTURE.md is missing the "<N> CWE entries pinned to" line');
  const documented = Number(m[1]);
  const live = liveCatalogCount('cwe-catalog.json');
  assert.equal(
    documented,
    live,
    `ARCHITECTURE.md says ${documented} CWE entries; data/cwe-catalog.json has ${live}`
  );
});
})();
