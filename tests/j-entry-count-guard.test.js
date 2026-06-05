'use strict';

/**
 * tests/j-entry-count-guard.test.js
 *
 * The CVE-catalog validator guards hand-maintained _meta.entry_count fields
 * against silent drift. The guard must cover EVERY loaded catalog that carries
 * a numeric _meta.entry_count, not a fixed two-entry allowlist — so a catalog
 * that newly adopts the field is checked without editing the guard.
 *
 * entryCountMismatches() is the extracted pure form of that check. These tests
 * feed it synthetic catalogs (no repo state touched) and assert the exact
 * mismatch shape.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { entryCountMismatches } = require('../lib/validate-cve-catalog.js');

test('entryCountMismatches flags a declared count that disagrees with the live count', () => {
  const catalogs = [
    {
      name: 'fixture',
      catalog: { _meta: { entry_count: 5 }, A: {}, B: {} },
    },
  ];
  const failures = entryCountMismatches(catalogs);
  assert.equal(failures.length, 1);
  assert.equal(failures[0].name, 'fixture');
  assert.equal(failures[0].declared, 5);
  assert.equal(failures[0].actual, 2);
});

test('entryCountMismatches passes when the declared count matches the live count', () => {
  const catalogs = [
    {
      name: 'fixture',
      catalog: { _meta: { entry_count: 2 }, A: {}, B: {} },
    },
  ];
  assert.deepEqual(entryCountMismatches(catalogs), []);
});

test('entryCountMismatches skips catalogs without a numeric _meta.entry_count', () => {
  const catalogs = [
    { name: 'no-meta', catalog: { A: {}, B: {} } },
    { name: 'no-count', catalog: { _meta: {}, A: {} } },
    { name: 'non-numeric', catalog: { _meta: { entry_count: 'three' }, A: {} } },
    { name: 'absent', catalog: null },
  ];
  assert.deepEqual(entryCountMismatches(catalogs), []);
});

test('entryCountMismatches covers any catalog passed in, not a fixed two-entry set', () => {
  // Six distinct catalogs, three with a wrong count — the guard must flag all
  // three regardless of name, proving coverage is general.
  const catalogs = [
    { name: 'one', catalog: { _meta: { entry_count: 1 }, A: {} } }, // ok
    { name: 'two', catalog: { _meta: { entry_count: 9 }, A: {}, B: {} } }, // wrong
    { name: 'three', catalog: { _meta: { entry_count: 0 }, A: {} } }, // wrong
    { name: 'four', catalog: { _meta: { entry_count: 3 }, A: {}, B: {}, C: {} } }, // ok
    { name: 'five', catalog: { _meta: { entry_count: 100 } } }, // wrong (zero live)
    { name: 'six', catalog: { _meta: {}, A: {} } }, // skipped (no count)
  ];
  const failures = entryCountMismatches(catalogs);
  assert.deepEqual(
    failures.map((f) => f.name).sort(),
    ['five', 'three', 'two']
  );
});

test('entryCountMismatches ignores _-prefixed keys when counting live entries', () => {
  const catalogs = [
    {
      name: 'fixture',
      catalog: {
        _meta: { entry_count: 2 },
        _notification_summary: {},
        _patch_sla_summary: {},
        A: {},
        B: {},
      },
    },
  ];
  // Two real entries (A, B); the three _-prefixed keys are metadata.
  assert.deepEqual(entryCountMismatches(catalogs), []);
});
