'use strict';

// Exports-surface coverage for the v0.12.12 additive helpers / constants.
// The diff-coverage gate (Hard Rule #15) requires every new lib export to
// have a corresponding test reference. These tests assert the shape and
// basic semantics of each export so a future rename, type-change, or
// silent removal is caught.

const test = require('node:test');
const assert = require('node:assert/strict');

const lintSkills = require('../lib/lint-skills');
const validateCveCatalog = require('../lib/validate-cve-catalog');
const prefetch = require('../lib/prefetch');
const scheduler = require('../orchestrator/scheduler');

test('lib/lint-skills exports REQUIRED_SECTIONS as a non-empty array of strings', () => {
  assert.ok(Array.isArray(lintSkills.REQUIRED_SECTIONS));
  assert.ok(lintSkills.REQUIRED_SECTIONS.length >= 1);
  for (const s of lintSkills.REQUIRED_SECTIONS) assert.equal(typeof s, 'string');
});

test('lib/lint-skills exports COUNTERMEASURE_SECTION as a string section name', () => {
  assert.equal(typeof lintSkills.COUNTERMEASURE_SECTION, 'string');
  assert.ok(lintSkills.COUNTERMEASURE_SECTION.length > 0);
});

test('lib/lint-skills exports COUNTERMEASURE_CUTOFF as an ISO-date string', () => {
  assert.equal(typeof lintSkills.COUNTERMEASURE_CUTOFF, 'string');
  assert.match(lintSkills.COUNTERMEASURE_CUTOFF, /^\d{4}-\d{2}-\d{2}$/);
});

test('lib/lint-skills exports MIN_SECTION_BODY_WORDS as a positive integer', () => {
  assert.equal(typeof lintSkills.MIN_SECTION_BODY_WORDS, 'number');
  assert.ok(Number.isInteger(lintSkills.MIN_SECTION_BODY_WORDS));
  assert.ok(lintSkills.MIN_SECTION_BODY_WORDS > 0);
});

test('lib/validate-cve-catalog exports looksLikePublicExploitSource as a function', () => {
  assert.equal(typeof validateCveCatalog.looksLikePublicExploitSource, 'function');
  // Smoke: a known public-exploit URL pattern matches; a non-exploit URL doesn't.
  assert.equal(validateCveCatalog.looksLikePublicExploitSource('https://github.com/some/exploit-poc'), true);
  assert.equal(validateCveCatalog.looksLikePublicExploitSource('https://example.com/about'), false);
});

test('lib/validate-cve-catalog exports isUsableDate as a function returning {ok, reason?}', () => {
  assert.equal(typeof validateCveCatalog.isUsableDate, 'function');
  assert.equal(validateCveCatalog.isUsableDate('2026-05-13').ok, true);
  assert.equal(validateCveCatalog.isUsableDate('1899-01-01').ok, false);
  assert.equal(validateCveCatalog.isUsableDate('2200-01-01').ok, false);
  assert.equal(validateCveCatalog.isUsableDate('not-a-date').ok, false);
  assert.equal(validateCveCatalog.isUsableDate(null).ok, false);
});

test('lib/validate-cve-catalog exports additionalChecks as a callable function', () => {
  assert.equal(typeof validateCveCatalog.additionalChecks, 'function');
  // Smoke-call the helper — exact return shape is internal; assert it doesn't throw.
  validateCveCatalog.additionalChecks('CVE-1999-0001', { name: 'x' }, { _meta: {} });
});

test('lib/validate-cve-catalog exports PUBLIC_EXPLOIT_URL_PATTERNS as an iterable of patterns', () => {
  assert.ok(Array.isArray(validateCveCatalog.PUBLIC_EXPLOIT_URL_PATTERNS));
  assert.ok(validateCveCatalog.PUBLIC_EXPLOIT_URL_PATTERNS.length >= 1);
});

test('lib/validate-cve-catalog exports STRICT_CVSS_PATTERN as a RegExp matching canonical versions', () => {
  assert.ok(validateCveCatalog.STRICT_CVSS_PATTERN instanceof RegExp);
  assert.ok(validateCveCatalog.STRICT_CVSS_PATTERN.test('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
  assert.equal(validateCveCatalog.STRICT_CVSS_PATTERN.test('CVSS:99.9/AV:N'), false);
});

test('lib/prefetch exports writeFileAtomic as a function writing files atomically', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  assert.equal(typeof prefetch._internal.writeFileAtomic, 'function');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-export-'));
  try {
    const dest = path.join(tmp, 'sample.txt');
    prefetch._internal.writeFileAtomic(dest, 'hello atomic');
    assert.equal(fs.readFileSync(dest, 'utf8'), 'hello atomic');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('orchestrator/scheduler exports TICK_MS as a positive integer not exceeding INT32 max', () => {
  assert.equal(typeof scheduler.TICK_MS, 'number');
  assert.ok(Number.isInteger(scheduler.TICK_MS));
  assert.ok(scheduler.TICK_MS > 0);
  assert.ok(scheduler.TICK_MS <= scheduler.SAFE_MAX_MS);
});
