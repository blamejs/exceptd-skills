"use strict";
/**
 * tests/codebase-patterns-readability-rules.test.js
 *
 * Covers the two opt-in readability detectors added to
 * scripts/check-codebase-patterns.js (unsorted-marked-array,
 * misaligned-marked-run), the dynamic-regex severity pin, and the
 * doctor flag-allowlist drift guard. Anti-coincidence: each detector is
 * asserted to FIRE on a bad sample AND stay silent on a good/unmarked one,
 * so a future no-op refactor cannot pass these by accident.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const gate = require('../scripts/check-codebase-patterns.js');
const { VERB_FLAG_ALLOWLIST, flagsFor } = require('../lib/flag-suggest.js');

const ROOT = path.join(__dirname, '..');

// ---- unsorted-marked-array ----
test('unsorted-marked-array: fires on a // keep-sorted array that is out of order', () => {
  const lines = ['const X = [ // keep-sorted', "  'gamma', 'alpha', 'beta',", '];'];
  const hits = gate.scanUnsortedMarkedArray('synthetic.js', lines);
  assert.equal(hits.length, 1, 'must flag the out-of-order marked array');
  assert.match(hits[0].why, /alphabetical order/);
});
test('unsorted-marked-array: silent on a sorted marked array', () => {
  const lines = ['const X = [ // keep-sorted', "  'alpha', 'beta', 'gamma',", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});
test('unsorted-marked-array: opt-in — an UNmarked out-of-order array is not flagged', () => {
  const lines = ['const X = [', "  'gamma', 'alpha',", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});
test('unsorted-marked-array: skips non-flat arrays (object elements)', () => {
  const lines = ['const X = [ // keep-sorted', "  { id: 'z' }, { id: 'a' },", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});

// ---- misaligned-marked-run ----
test('misaligned-marked-run: fires when // keep-aligned columns differ', () => {
  const lines = ['  // keep-aligned', '  alpha = 1,', '  bb = 2,', ''];
  const hits = gate.scanMisalignedMarkedRun('synthetic.js', lines);
  assert.equal(hits.length, 1, 'must flag the misaligned run');
  assert.match(hits[0].why, /columns are not all equal/);
});
test('misaligned-marked-run: silent on an aligned run', () => {
  const lines = ['  // keep-aligned', '  alpha = 1,', '  bb    = 2,', ''];
  assert.equal(gate.scanMisalignedMarkedRun('synthetic.js', lines).length, 0);
});
test('misaligned-marked-run: opt-in — an UNmarked misaligned run is not flagged', () => {
  const lines = ['  alpha = 1,', '  bb = 2,', ''];
  assert.equal(gate.scanMisalignedMarkedRun('synthetic.js', lines).length, 0);
});

// ---- detector wrappers (tree walk) ----
test('detectUnsortedMarkedArray / detectMisalignedMarkedRun scan the tree and return arrays', () => {
  assert.ok(Array.isArray(gate.detectUnsortedMarkedArray()), 'detectUnsortedMarkedArray returns an array');
  assert.ok(Array.isArray(gate.detectMisalignedMarkedRun()), 'detectMisalignedMarkedRun returns an array');
  // the engine file holds the detector + marker prose, so it self-skips → no hits
  assert.deepEqual(gate.detectUnsortedMarkedArray(['scripts/check-codebase-patterns.js']), []);
  assert.deepEqual(gate.detectMisalignedMarkedRun(['scripts/check-codebase-patterns.js']), []);
});

// ---- severity pins / registration ----
test('dynamic-regex is registered as a blocking class (warnOnly === false)', () => {
  const c = gate.CLASSES.find((x) => x.id === 'dynamic-regex');
  assert.ok(c, 'dynamic-regex class present');
  assert.equal(c.warnOnly, false, 'dynamic-regex must be blocking now that all sites carry markers');
});
test('the two new readability classes are registered and blocking', () => {
  for (const id of ['unsorted-marked-array', 'misaligned-marked-run']) {
    const c = gate.CLASSES.find((x) => x.id === id);
    assert.ok(c, `${id} registered`);
    assert.equal(c.warnOnly, false, `${id} blocking`);
  }
});

// ---- doctor flag-allowlist drift guard ----
test('VERB_FLAG_ALLOWLIST.doctor stays in sync with bin KNOWN_DOCTOR_FLAGS', () => {
  const bin = fs.readFileSync(path.join(ROOT, 'bin/exceptd.js'), 'utf8');
  const m = bin.match(/KNOWN_DOCTOR_FLAGS\s*=\s*new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, 'KNOWN_DOCTOR_FLAGS Set literal found in bin/exceptd.js');
  const known = new Set([...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]));
  // Globals + parser-internal keys that KNOWN_DOCTOR_FLAGS carries beyond the
  // doctor-specific surface (documented here so the comparison is exact).
  const NON_VERB = new Set(['json', 'pretty', 'quiet', 'verbose', '_', 'json-stdout-only', '_jsonMode']);
  const knownVerbFlags = [...known].filter((f) => !NON_VERB.has(f)).sort();
  const allowlistDoctor = [...VERB_FLAG_ALLOWLIST.doctor].sort();
  assert.deepEqual(knownVerbFlags, allowlistDoctor,
    'doctor-specific flags in bin KNOWN_DOCTOR_FLAGS must set-equal VERB_FLAG_ALLOWLIST.doctor — ' +
    'add the flag to BOTH or the suggester and the parser disagree');
  // Every allowlisted doctor flag must actually be accepted by the parser.
  for (const f of VERB_FLAG_ALLOWLIST.doctor) {
    assert.ok(known.has(f), `doctor flag "${f}" is allowlisted but missing from KNOWN_DOCTOR_FLAGS (parser would reject it)`);
  }
  // flagsFor includes globals; doctor flags are a subset.
  for (const f of VERB_FLAG_ALLOWLIST.doctor) assert.ok(flagsFor('doctor').includes(f));
});
