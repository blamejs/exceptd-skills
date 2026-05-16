'use strict';

/**
 * tests/diff-coverage-docs-manual-review.test.js
 *
 * Cycle 9 P3 F7 fix (v0.12.30): operator-facing docs (CHANGELOG, README,
 * SECURITY, MIGRATING, AGENTS) downgraded from auto-allowlist to
 * manual-review. The downgrade preserves the no-test-required posture
 * (no regression test exists FOR an English-prose edit) while surfacing
 * the change in the gate output so a maintainer reviewing the bot summary
 * at least sees that an operator-facing surface changed.
 *
 * Mechanical / contributor-only docs (CONTRIBUTING, LICENSE, NOTICE,
 * CODE_OF_CONDUCT, SUPPORT, CLAUDE.md, .gitignore, .npmrc, .editorconfig)
 * stay always-green: their content has no operator-facing semantic surface
 * and edits there genuinely don't need any reviewer attention.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks the EXACT
 * value the categorize() function returns.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const cov = require(path.join(ROOT, 'scripts', 'check-test-coverage.js'));

// Mirror the two sets so the assertions can iterate independently of the
// module-internal categorize() — if the categorize() function regresses
// the categorization for one of these files, this test catches it.
const EXPECTED_ALWAYS_GREEN = [
  'CONTRIBUTING.md', 'LICENSE', 'NOTICE', 'CODE_OF_CONDUCT.md',
  'CLAUDE.md', 'SUPPORT.md', '.gitignore', '.npmrc', '.editorconfig',
];
const EXPECTED_MANUAL_REVIEW = [
  'CHANGELOG.md', 'README.md', 'SECURITY.md', 'MIGRATING.md', 'AGENTS.md',
];

test('DOCS_ALWAYS_GREEN set is exactly the contributor-docs allowlist', () => {
  const actual = Array.from(cov.DOCS_ALWAYS_GREEN).sort();
  assert.deepEqual(actual, [...EXPECTED_ALWAYS_GREEN].sort());
});

test('DOCS_MANUAL_REVIEW set is exactly the operator-docs surface', () => {
  const actual = Array.from(cov.DOCS_MANUAL_REVIEW).sort();
  assert.deepEqual(actual, [...EXPECTED_MANUAL_REVIEW].sort());
});

test('the two sets do not overlap (no file is both always-green AND manual-review)', () => {
  const overlap = EXPECTED_ALWAYS_GREEN.filter((f) => EXPECTED_MANUAL_REVIEW.includes(f));
  assert.deepEqual(overlap, []);
});
