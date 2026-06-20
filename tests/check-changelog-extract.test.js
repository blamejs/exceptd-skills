'use strict';

/**
 * tests/check-changelog-extract.test.js
 *
 * Pins the release-notes extract + operator-facing lint gate
 * (scripts/check-changelog-extract.js): the extractor matches the release
 * workflow's `## <version>` section boundaries (and the version-prefix
 * collision guard), the operator-facing lint catches each internal-narrative
 * class AND is silent on clean prose, and the live CHANGELOG top section both
 * extracts non-empty and passes the lint.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const G = require('../scripts/check-changelog-extract.js');

const SAMPLE = [
  '# Changelog',
  '',
  '## 0.15.50 — 2026-05-30',
  '',
  'Adds a thing operators can now do.',
  'A second behavior-change line.',
  '',
  '## 0.15.5 — 2026-01-01',
  '',
  'An older entry that must NOT be captured for 0.15.50.',
  '',
].join('\n');

test('extractSection captures only the requested version section', () => {
  const s = G.extractSection(SAMPLE, '0.15.50');
  assert.deepEqual(s, ['Adds a thing operators can now do.', 'A second behavior-change line.']);
});

test('extractSection version-prefix collision guard (0.15.5 vs 0.15.50)', () => {
  // The trailing-space heading match must not let 0.15.5 capture 0.15.50's body.
  const s = G.extractSection(SAMPLE, '0.15.5');
  assert.deepEqual(s, ['An older entry that must NOT be captured for 0.15.50.']);
});

test('extractSection returns empty for an absent version', () => {
  assert.equal(G.extractSection(SAMPLE, '9.9.9').length, 0);
});

test('lintOperatorClean catches each internal-narrative class', () => {
  const cases = {
    'phase-number': 'Closed the gap in Phase 9.11k.',
    'pass-number': 'This was drift-audit pass 41.',
    'slice-number': 'Shipped slice 4 of the audit.',
    'agent-dispatch': 'Fanned out to sub-agents to do it.',
    'conversation-residue': 'As discussed, fixed the thing.',
    'tautological-green': 'All tests passing and CI green.',
  };
  for (const [rule, line] of Object.entries(cases)) {
    const f = G.lintOperatorClean([line]);
    assert.ok(f.some((x) => x.rule === rule), `expected a ${rule} finding for: ${line}`);
  }
});

test('tautological-green rule catches numbered, count, and synonym forms (not just "all tests green")', () => {
  // The previous rule pinned the literal adjacency "all tests <pass|green>",
  // so a number ("all 288 tests green"), the count form ("288/288 tests pass",
  // "21/21 gates pass"), and synonyms ("full suite green", "every check passes")
  // all escaped — the exact family CLAUDE.md names as forbidden release residue.
  const mustFlag = [
    'all 288 tests green',
    '288/288 tests pass',
    '21/21 gates pass',
    '42/42 checks pass',
    '15/15 gates green',
    'full suite green',
    'full suite is green',
    'the entire test suite is green',
    'every check is green',
    'every check passes',
    'all gates green',
    'every test passes',
    // Forms the original rule already caught — must keep catching them.
    'all tests passing',
    'all tests green',
    'CI green',
    'tests are passing',
  ];
  for (const line of mustFlag) {
    const f = G.lintOperatorClean([line]);
    assert.ok(
      f.some((x) => x.rule === 'tautological-green'),
      `expected a tautological-green finding for: ${JSON.stringify(line)}`
    );
  }
});

test('tautological-green rule does not false-positive on legitimate prose', () => {
  // Descriptive prose that merely contains "green", "suite", "pass", or a count
  // must NOT trip the rule.
  const mustNotFlag = [
    'The green-field deployment path is now supported.',
    'A new test suite for the engine covers the collectors.',
    'The 288-test suite covers the new collector.',
    'Passes the new validation step before emit.',
    'The full suite of collectors now runs against sibling repos.',
    'Adds green badges to the README install section.',
  ];
  for (const line of mustNotFlag) {
    const f = G.lintOperatorClean([line]);
    assert.ok(
      !f.some((x) => x.rule === 'tautological-green'),
      `unexpected tautological-green false positive for: ${JSON.stringify(line)}`
    );
  }
});

test('lintOperatorClean is silent on clean operator-facing prose', () => {
  const clean = [
    'Adds a typosquat detector that flags name-impersonation by edit-distance.',
    'A new dependency-confusion resolution check correlates to the MOIKA campaign.',
    'Each ships with a false-positive profile. Upgrade with npm update.',
    'Supports a multi-phase attack model and per-tier escalation.', // "phase"/"tier" without a number must NOT trip
  ];
  assert.equal(G.lintOperatorClean(clean).length, 0);
});

test('FORBIDDEN registry is non-empty and well-formed', () => {
  assert.ok(Array.isArray(G.FORBIDDEN) && G.FORBIDDEN.length >= 6);
  for (const r of G.FORBIDDEN) {
    assert.equal(typeof r.id, 'string');
    assert.ok(r.re instanceof RegExp);
    assert.equal(typeof r.why, 'string');
  }
});

test('live CHANGELOG top section extracts non-empty and passes the operator-facing lint', () => {
  const text = fs.readFileSync(path.join(__dirname, '..', 'CHANGELOG.md'), 'utf8');
  const version = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version;
  const heading = G.headingLine(text, version);
  assert.ok(heading, `CHANGELOG must have a '## ${version}' heading`);
  const section = G.extractSection(text, version);
  assert.ok(section.length > 0, 'live release notes must be non-empty (no workflow fallback)');
  assert.equal(G.lintOperatorClean(section).length, 0, 'live release notes must be operator-facing-clean');
});

test("missingReleasedHeadings flags a released version whose heading was replaced", () => {
  // The failure shape: a new entry REPLACES the previous release heading
  // instead of inserting above it, merging the prior notes into the new
  // section. The guard catches it by requiring a heading per released tag.
  const missing = G.missingReleasedHeadings(SAMPLE, ["0.15.50", "0.15.5", "0.15.49"]);
  assert.deepEqual(missing, ["0.15.49"], "the version with no surviving heading must be reported");
  assert.deepEqual(G.missingReleasedHeadings(SAMPLE, ["0.15.50", "0.15.5"]), [],
    "all headings present -> no findings");
});

test("every tagged release keeps its heading in the live CHANGELOG", () => {
  const text = fs.readFileSync(path.join(__dirname, "..", "CHANGELOG.md"), "utf8");
  const released = G.releasedVersionsFromTags();
  // Tolerate tagless environments (shallow checkout); locally there are tags.
  const missing = G.missingReleasedHeadings(text, released);
  assert.deepEqual(missing, [],
    "released versions missing their CHANGELOG heading: " + missing.join(", "));
});
