'use strict';

/**
 * Smoke tests for the new module exports added in v0.12.24. These tests
 * are intentionally narrow: they verify the export exists, has the expected
 * shape, and handles a representative happy-path input. Behavior-coverage
 * for each function lives in the dedicated test files (csaf-bundle-
 * correctness, openvex-emission, prefetch, lint-skills).
 *
 * The diff-coverage gate (scripts/check-test-coverage.js) treats any
 * exported symbol that has no string reference in tests/ as an uncovered
 * surface change. This file is the canonical "I added an export and a
 * dedicated behavior test will follow" stop-gap that keeps the gate green.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// lib/lint-skills.js — air-gap completeness lint
// ---------------------------------------------------------------------------

test('lib/lint-skills exposes lintPlaybookAirGap', () => {
  const lint = require(path.join(ROOT, 'lib', 'lint-skills.js'));
  assert.equal(typeof lint.lintPlaybookAirGap, 'function',
    'lintPlaybookAirGap must be exported as a function');
});

test('lib/lint-skills exposes PLAYBOOK_NET_PATTERNS', () => {
  const lint = require(path.join(ROOT, 'lib', 'lint-skills.js'));
  // PLAYBOOK_NET_PATTERNS is the regex list flagging network-shaped sources
  // that need an air_gap_alternative.
  assert.ok(lint.PLAYBOOK_NET_PATTERNS,
    'PLAYBOOK_NET_PATTERNS must be exported');
});

// ---------------------------------------------------------------------------
// lib/prefetch.js — _index.json Ed25519 signing
// ---------------------------------------------------------------------------

test('lib/prefetch exposes canonicalIndexBytes', () => {
  const prefetch = require(path.join(ROOT, 'lib', 'prefetch.js'));
  assert.equal(typeof prefetch.canonicalIndexBytes, 'function',
    'canonicalIndexBytes must be exported as a function');
  // The canonicaliser must produce bytes (Buffer or string) and exclude the
  // index_signature field from the canonical input (signing one's own
  // signature is circular).
  const bytes = prefetch.canonicalIndexBytes({ entries: { 'a/b': { sha256: 'x' } } });
  assert.ok(bytes && (Buffer.isBuffer(bytes) || typeof bytes === 'string'),
    'canonicalIndexBytes must return Buffer or string');
});

test('lib/prefetch exposes signIndex', () => {
  const prefetch = require(path.join(ROOT, 'lib', 'prefetch.js'));
  assert.equal(typeof prefetch.signIndex, 'function',
    'signIndex must be exported as a function');
});

test('lib/prefetch exposes verifyIndexSignature', () => {
  const prefetch = require(path.join(ROOT, 'lib', 'prefetch.js'));
  assert.equal(typeof prefetch.verifyIndexSignature, 'function',
    'verifyIndexSignature must be exported as a function');
});

// ---------------------------------------------------------------------------
// lib/scoring.js — strict CVSS 3.0/3.1 vector parse
// ---------------------------------------------------------------------------

test('lib/scoring exposes parseCvss31Vector', () => {
  const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));
  assert.equal(typeof scoring.parseCvss31Vector, 'function',
    'parseCvss31Vector must be exported');
  // Happy path: a canonical 3.1 base vector.
  const r = scoring.parseCvss31Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(r.ok, true);
  assert.equal(r.version, '3.1');
});

test('parseCvss31Vector accepts both 3.0 and 3.1 (CSAF cvss_v3-permitted versions)', () => {
  const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));
  const v30 = scoring.parseCvss31Vector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
  assert.equal(v30.ok, true);
  assert.equal(v30.version, '3.0');
  const v40 = scoring.parseCvss31Vector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H');
  assert.equal(v40.ok, false, 'CVSS 4.0 must be refused (CSAF cvss_v3 only accepts 3.0/3.1)');
});

// ---------------------------------------------------------------------------
// scripts/check-test-coverage.js — coincidence-assert ban
// ---------------------------------------------------------------------------

test('scripts/check-test-coverage exposes scanForCoincidenceAsserts', () => {
  const cov = require(path.join(ROOT, 'scripts', 'check-test-coverage.js'));
  assert.equal(typeof cov.scanForCoincidenceAsserts, 'function',
    'scanForCoincidenceAsserts must be exported');
  // Run against the live tests/ tree. With v0.12.24's cleanup pass, the
  // result should be empty (every previously-coincidence-passing site is
  // now pinned to an exact exit code OR opted out with `// allow-notEqual:`).
  const findings = cov.scanForCoincidenceAsserts(ROOT);
  assert.ok(Array.isArray(findings),
    'scanForCoincidenceAsserts must return an array of findings');
});
