"use strict";
/**
 * tests/framework-gaps-theater-test-coverage.test.js
 *
 * Hard Rule #6 coverage: every entry in data/framework-control-gaps.json
 * MUST carry a populated theater_test block that distinguishes paper
 * compliance from actual security.
 *
 * Schema (per AGENTS.md Hard Rule #6):
 *   theater_test: {
 *     claim:                 non-empty string (the audit-language sentence),
 *     test:                  non-empty string (a falsifiable check),
 *     evidence_required:     non-empty array of strings (1+ artifacts),
 *     verdict_when_failed:   exact literal "compliance-theater"
 *   }
 *
 * Per the project anti-coincidence rule: assertions test EXACT shape and
 * type, not just presence. A future regression that emits an empty array,
 * an empty string, or a typo'd verdict will fail here, not silently pass.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CATALOG_PATH = path.join(ROOT, 'data', 'framework-control-gaps.json');
const CATALOG = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));

const ENTRY_KEYS = Object.keys(CATALOG).filter((k) => k !== '_meta');

const REQUIRED_VERDICT = 'compliance-theater';

test('framework-control-gaps.json: catalog has at least 109 control-gap entries', () => {
  // Lower-bound assertion. New entries are additive and must continue to
  // satisfy the per-entry shape below; this guard catches accidental
  // truncation of the file.
  assert.ok(
    ENTRY_KEYS.length >= 109,
    `expected >= 109 entries, found ${ENTRY_KEYS.length}`
  );
});

test('framework-control-gaps.json: every entry has a populated theater_test', () => {
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const entry = CATALOG[key];
    const tt = entry.theater_test;

    if (tt === undefined || tt === null) {
      failures.push(`${key}: theater_test is missing`);
      continue;
    }

    if (typeof tt !== 'object' || Array.isArray(tt)) {
      failures.push(`${key}: theater_test is not an object`);
      continue;
    }

    // claim: non-empty string
    if (typeof tt.claim !== 'string') {
      failures.push(`${key}: theater_test.claim is not a string (got ${typeof tt.claim})`);
    } else if (tt.claim.trim().length === 0) {
      failures.push(`${key}: theater_test.claim is empty`);
    } else if (tt.claim.length < 30) {
      // Paper-compliance claims worth testing read like real audit language.
      // A 30-char minimum stops one-word stub claims from regressing in.
      failures.push(`${key}: theater_test.claim is too short (${tt.claim.length} chars)`);
    }

    // test: non-empty string with discriminating content
    if (typeof tt.test !== 'string') {
      failures.push(`${key}: theater_test.test is not a string (got ${typeof tt.test})`);
    } else if (tt.test.trim().length === 0) {
      failures.push(`${key}: theater_test.test is empty`);
    } else if (tt.test.length < 80) {
      // A falsifiability check needs enough text to describe the query
      // and the binary verdict. 80 chars is a low floor.
      failures.push(`${key}: theater_test.test is too short (${tt.test.length} chars)`);
    }

    // evidence_required: array, length >= 1, all non-empty strings
    if (!Array.isArray(tt.evidence_required)) {
      failures.push(`${key}: theater_test.evidence_required is not an array`);
    } else if (tt.evidence_required.length < 1) {
      failures.push(`${key}: theater_test.evidence_required has zero entries`);
    } else {
      for (let i = 0; i < tt.evidence_required.length; i++) {
        const item = tt.evidence_required[i];
        if (typeof item !== 'string' || item.trim().length === 0) {
          failures.push(`${key}: theater_test.evidence_required[${i}] is not a non-empty string`);
        }
      }
    }

    // verdict_when_failed: exact literal "compliance-theater"
    assert.equal(
      tt.verdict_when_failed,
      REQUIRED_VERDICT,
      `${key}: theater_test.verdict_when_failed must equal "${REQUIRED_VERDICT}", got ${JSON.stringify(tt.verdict_when_failed)}`
    );
  }

  assert.equal(
    failures.length,
    0,
    `theater_test schema failures:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test contains a falsifiability marker', () => {
  // Soft check: the test string should contain at least one of the words
  // that signal a binary verdict ("Theater verdict", "verdict if", "fail",
  // "must", "confirm"). This is not a proof of falsifiability but it
  // catches drafting accidents where the field reads like prose without
  // any pass/fail trigger.
  const verdictMarkers = /(theater verdict|verdict if|confirm|missing|absent|exceeds|fails|fail if)/i;
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    if (!verdictMarkers.test(tt.test)) {
      failures.push(`${key}: theater_test.test lacks any verdict marker`);
    }
  }
  assert.equal(
    failures.length,
    0,
    `entries without verdict markers:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test strings are not literal duplicates', () => {
  // Per AGENTS.md: distinct controls cannot share the literal same test
  // string (pattern-shaped tests are fine; copy-paste is not). Group by
  // exact-string equality and surface any group with > 1 distinct entry.
  const byTest = new Map();
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    const trimmed = tt.test.trim();
    if (!byTest.has(trimmed)) byTest.set(trimmed, []);
    byTest.get(trimmed).push(key);
  }
  const dupes = [];
  for (const [text, keys] of byTest.entries()) {
    if (keys.length > 1) {
      dupes.push(`shared by ${keys.join(', ')}: ${text.slice(0, 80)}...`);
    }
  }
  assert.equal(
    dupes.length,
    0,
    `theater_test.test strings duplicated verbatim across distinct controls:\n  - ${dupes.join('\n  - ')}`
  );
});
