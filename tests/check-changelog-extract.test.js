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
