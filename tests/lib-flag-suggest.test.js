'use strict';

/**
 * Unit coverage for lib/flag-suggest.js.
 *
 * suggestFlag() returns the closest allowlisted flag at Levenshtein
 * distance ≤ min(2, floor(flag.length / 2)). The distance cap prevents
 * "did you mean: --help" suggestions on flags too short to share useful
 * structure with the allowlist.
 *
 * Per-verb allowlists are exported via flagsFor(verb). Adding a flag to
 * the CLI surface MUST land here too; the dispatch + this allowlist are
 * the two parallel sources of truth.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { editDistance, suggestFlag, flagsFor, VERB_FLAG_ALLOWLIST } =
  require(path.join(ROOT, 'lib', 'flag-suggest.js'));

test('--evidnce suggests "evidence" (single-char insertion)', () => {
  const s = suggestFlag('evidnce', flagsFor('run'));
  assert.equal(s, 'evidence', `expected "evidence"; got ${JSON.stringify(s)}`);
});

test('--csaf-stats suggests "csaf-status" (transposition + substitution)', () => {
  const s = suggestFlag('csaf-stats', flagsFor('run'));
  assert.equal(s, 'csaf-status', `expected "csaf-status"; got ${JSON.stringify(s)}`);
});

test('--xyzzy returns null — too far from any allowlisted flag', () => {
  const s = suggestFlag('xyzzy', flagsFor('run'));
  assert.equal(s, null, `expected null (distance > floor(5/2)=2); got ${JSON.stringify(s)}`);
});

test('--ack matches itself exactly (distance 0)', () => {
  const s = suggestFlag('ack', flagsFor('run'));
  assert.equal(s, 'ack');
});

test('short typos cap suggestion distance at floor(len/2)', () => {
  // For a 3-char input, cap = floor(3/2) = 1. "hep" → "help" (distance 1).
  const s1 = suggestFlag('hep', flagsFor('run'));
  assert.equal(s1, 'help');
  // For a 2-char input, cap = 1; "ja" is distance 2 from "json" → no suggestion.
  const s2 = suggestFlag('ja', flagsFor('run'));
  assert.equal(s2, null,
    'short inputs must reject suggestions whose distance exceeds floor(len/2)');
});

test('flagsFor(verb) prepends global flags before verb-specific', () => {
  const runFlags = flagsFor('run');
  for (const g of VERB_FLAG_ALLOWLIST._global) {
    assert.ok(runFlags.includes(g), `global flag ${g} must appear in flagsFor('run')`);
  }
});

test('per-verb scoping: --operator typo on `plan` is rejected (plan does not consume --operator)', () => {
  // VERB_FLAG_ALLOWLIST has no entry for 'plan' (it is an alias for
  // `brief --all`). flagsFor('plan') returns the global flags only.
  // suggestFlag('opetator', plan-scope) must NOT suggest 'operator'
  // because the verb does not consume it.
  const planFlags = flagsFor('plan');
  assert.ok(!planFlags.includes('operator'),
    'plan verb must not list operator in its allowlist');
  const s = suggestFlag('opetator', planFlags);
  assert.equal(s, null,
    'suggestion against plan-scoped allowlist must not resolve to "operator" (verb does not accept it)');
});

test('per-verb scoping: --operator on `run` IS suggested (run consumes it)', () => {
  const runFlags = flagsFor('run');
  assert.ok(runFlags.includes('operator'), 'run accepts operator');
  const s = suggestFlag('opetator', runFlags);
  assert.equal(s, 'operator',
    'run-scoped allowlist resolves typo to "operator"');
});

test('editDistance: identity, insertion, deletion, substitution', () => {
  assert.equal(editDistance('foo', 'foo'), 0, 'identical strings → distance 0');
  assert.equal(editDistance('foo', 'fooo'), 1, 'single insertion');
  assert.equal(editDistance('foo', 'fo'), 1, 'single deletion');
  assert.equal(editDistance('foo', 'fox'), 1, 'single substitution');
  assert.equal(editDistance('foo', ''), 3, 'empty target = length of source');
  assert.equal(editDistance('', 'bar'), 3, 'empty source = length of target');
});

test('suggestFlag handles empty allowlist and non-string inputs gracefully', () => {
  assert.equal(suggestFlag('foo', []), null, 'empty allowlist → null');
  assert.equal(suggestFlag('', ['help']), null, 'empty input → null');
  assert.equal(suggestFlag(null, ['help']), null, 'non-string input → null');
  assert.equal(suggestFlag('foo', null), null, 'non-array allowlist → null');
});
