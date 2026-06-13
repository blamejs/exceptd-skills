'use strict';

/**
 * Regression: diffArtifacts must not report a false 'changed' when two equal
 * artifacts differ only in JSON key insertion order. Pre-fix the comparison was
 * `JSON.stringify(av) !== JSON.stringify(bv)`, which is key-order sensitive — so
 * a side stored as `{captured, value}` (raw operator order) vs a side normalized
 * to `{value, captured}` serialized unequal and was pushed to changed[], while
 * top-level `status` (computed from the key-sorted evidence_hash) said
 * "unchanged" — a self-contradicting diff. The comparison now canonicalizes
 * (recursive key sort) so field-level changed[] agrees with status by
 * construction, while a genuine value change is still reported.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { _diffArtifacts: diffArtifacts } = require('../bin/exceptd.js');

test('key-order-only difference is unchanged, not changed', () => {
  const a = { x: { captured: true, value: 'v' } };
  const b = { x: { value: 'v', captured: true } };
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 0, 'reordered-but-equal artifacts must not be "changed"');
  assert.equal(d.unchanged_count, 1, 'reordered-but-equal artifacts must count as unchanged');
});

test('nested extra-key reordering is unchanged', () => {
  const a = { x: { captured: true, foo: 1, bar: 2 } };
  const b = { x: { captured: true, bar: 2, foo: 1 } };
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 0, 'nested key reordering must compare equal');
  assert.equal(d.unchanged_count, 1);
});

test('a genuine value change is still reported as changed', () => {
  const a = { x: { captured: true, value: 'a' } };
  const b = { x: { captured: true, value: 'b' } };
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 1, 'a real value difference must still be detected');
  assert.equal(d.unchanged_count, 0);
});

test('changed[] count agrees with the unchanged verdict for reordered duplicates', () => {
  // The status-vs-field-diff disagreement class: two key-reordered duplicates
  // are evidence-hash-equal (status "unchanged"), so changed.length must be 0.
  const a = { artifactA: { captured: true, value: 'v', note: 'n' } };
  const b = { artifactA: { note: 'n', value: 'v', captured: true } };
  const d = diffArtifacts(a, b);
  const statusUnchanged = d.changed.length === 0 && d.added.length === 0 && d.removed.length === 0;
  assert.ok(statusUnchanged, 'reordered duplicates must produce an all-unchanged diff to match status');
});
