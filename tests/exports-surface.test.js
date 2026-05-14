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
const crossRefApi = require('../lib/cross-ref-api');
const sourceGhsa = require('../lib/source-ghsa');
const sourceOsv = require('../lib/source-osv');

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

// v0.12.14 surface additions.

test('lib/cross-ref-api exports getLoadErrors as a function returning an array', () => {
  assert.equal(typeof crossRefApi.getLoadErrors, 'function');
  const errs = crossRefApi.getLoadErrors();
  assert.ok(Array.isArray(errs),
    'getLoadErrors must return an array (empty when no catalog/index parse errors)');
});

test('lib/source-ghsa exports FIELD_DROPPED_WATCH as a frozen array of field names', () => {
  assert.ok(Array.isArray(sourceGhsa.FIELD_DROPPED_WATCH));
  assert.ok(sourceGhsa.FIELD_DROPPED_WATCH.length >= 1);
  for (const f of sourceGhsa.FIELD_DROPPED_WATCH) assert.equal(typeof f, 'string');
  // Frozen so downstream consumers can't accidentally mutate the shared
  // watch list and silently change refresh-source behaviour.
  assert.ok(Object.isFrozen(sourceGhsa.FIELD_DROPPED_WATCH));
});

test('lib/source-osv exports FIELD_DROPPED_WATCH as a frozen array of field names', () => {
  assert.ok(Array.isArray(sourceOsv.FIELD_DROPPED_WATCH));
  assert.ok(sourceOsv.FIELD_DROPPED_WATCH.length >= 1);
  for (const f of sourceOsv.FIELD_DROPPED_WATCH) assert.equal(typeof f, 'string');
  assert.ok(Object.isFrozen(sourceOsv.FIELD_DROPPED_WATCH));
});

// v0.12.14 verify.js fingerprint-pin surface.

const verifyMod = require('../lib/verify');

test('lib/verify exports publicKeyFingerprint + checkExpectedFingerprint + EXPECTED_FINGERPRINT_PATH', () => {
  assert.equal(typeof verifyMod.publicKeyFingerprint, 'function');
  assert.equal(typeof verifyMod.checkExpectedFingerprint, 'function');
  assert.equal(typeof verifyMod.EXPECTED_FINGERPRINT_PATH, 'string');
  assert.ok(verifyMod.EXPECTED_FINGERPRINT_PATH.endsWith('EXPECTED_FINGERPRINT'));
});

// v0.12.14 orchestrator/event-bus.js + scheduler.js + pipeline.js additions.

const eventBus = require('../orchestrator/event-bus');
const pipelineMod = require('../orchestrator/pipeline');

test('orchestrator/event-bus exports DEFAULT_EVENT_LOG_MAX_SIZE as a positive integer', () => {
  assert.equal(typeof eventBus.DEFAULT_EVENT_LOG_MAX_SIZE, 'number');
  assert.ok(Number.isInteger(eventBus.DEFAULT_EVENT_LOG_MAX_SIZE));
  assert.ok(eventBus.DEFAULT_EVENT_LOG_MAX_SIZE > 0);
});

test('orchestrator/scheduler exports _lastFiredStorePath + _markFired internals', () => {
  assert.equal(typeof scheduler._lastFiredStorePath, 'function');
  assert.equal(typeof scheduler._markFired, 'function');
});

test('orchestrator/pipeline exports MANIFEST_CACHE_TTL_MS + _resetManifestCache', () => {
  assert.equal(typeof pipelineMod.MANIFEST_CACHE_TTL_MS, 'number');
  assert.ok(pipelineMod.MANIFEST_CACHE_TTL_MS > 0);
  assert.equal(typeof pipelineMod._resetManifestCache, 'function');
  // Smoke: resetManifestCache must not throw on a fresh process.
  pipelineMod._resetManifestCache();
});

// v0.12.14 scripts/validate-vendor-online.js exports.

const validateVendorOnline = require('../scripts/validate-vendor-online');

test('scripts/validate-vendor-online exports rawUrlForPin + fetchBuffer', () => {
  assert.equal(typeof validateVendorOnline.rawUrlForPin, 'function');
  assert.equal(typeof validateVendorOnline.fetchBuffer, 'function');
  // Smoke: rawUrlForPin produces a github raw URL string for a known shape.
  const url = validateVendorOnline.rawUrlForPin(
    'https://github.com/blamejs/blamejs.git', '1442f17758a4', 'lib/x.js'
  );
  assert.ok(typeof url === 'string' && url.includes('1442f17758a4'));
});
