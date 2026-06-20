'use strict';

/**
 * The e2e scenario runner's --filter selects scenarios by plain substring
 * (String.includes), never by a regex compiled from the CLI argument. Compiling
 * a regex from an operator-supplied string is a regex-injection / ReDoS sink:
 * a pattern like (a+)+$ drives catastrophic backtracking. Scenario directories
 * are literal NN-name strings, so substring selection is behavior-equivalent
 * for every legitimate filter while removing the sink entirely.
 *
 * selectScenarios is the shipped predicate main() uses, so this binds to the
 * real selection logic rather than a copy.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { selectScenarios } = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

test('--filter substring selects exactly the matching scenario', () => {
  const selected = selectScenarios('library-author');
  assert.deepEqual(selected, ['11-library-author-static-token']);
});

test('--filter with no value returns all numbered scenarios (none filtered out)', () => {
  const all = selectScenarios(null);
  // Every entry is a numbered scenario dir; README.md is excluded by the NN- gate.
  assert.ok(all.length >= 20, `expected the full scenario set, got ${all.length}`);
  assert.ok(all.every(d => /^\d+-/.test(d)), 'all selected dirs must be NN-named');
  assert.ok(!all.includes('README.md'), 'README.md must not be selected');
});

test('--filter is a literal substring, not a compiled regex (ReDoS-safe)', () => {
  // (a+)+$ is a catastrophic-backtracking pattern. As a literal substring it
  // matches no scenario name and returns instantly; if it were compiled with
  // new RegExp it would hang on adversarial input. Bounding the time proves no
  // regex compilation happens.
  const t0 = Date.now();
  const selected = selectScenarios('(a+)+$');
  const elapsed = Date.now() - t0;
  assert.deepEqual(selected, [], 'a regex metachar string must match no scenario as a literal substring');
  assert.ok(elapsed < 1000, `selection must be near-instant (was ${elapsed}ms) — proves the filter is not compiled as a regex`);
});

test('--filter treats regex metacharacters literally (no special meaning)', () => {
  // "." in a regex means "any char"; as a literal substring it matches nothing
  // here because no scenario name contains a "." (dirs are NN-name only).
  assert.deepEqual(selectScenarios('crypto.codebase'), [], '"." must be literal, not regex any-char');
  // The literal hyphenated substring that DOES occur is selected normally.
  assert.deepEqual(selectScenarios('crypto-codebase'), ['12-crypto-codebase-md5-eol']);
});
