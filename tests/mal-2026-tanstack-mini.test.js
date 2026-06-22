'use strict';

/**
 * tests/mal-2026-tanstack-mini.test.js
 *
 * Per-subject coverage for MAL-2026-TANSTACK-MINI. The catalog data-coherence
 * pins assert that this ecosystem-package entry carries a substantive
 * kev_scope_note explaining why an "active_exploitation: confirmed +
 * cisa_kev: false" combination is correct (CISA KEV excludes ecosystem-package
 * compromises by scope). Extracted from the kev_scope_note loop bodies.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));

const id = 'MAL-2026-TANSTACK-MINI';

test(`${id} carries a substantive kev_scope_note (ecosystem-package CVE-vs-KEV scope)`, () => {
  const entry = catalog[id];
  assert.ok(entry, `${id} must be present`);
  assert.equal(typeof entry.kev_scope_note, 'string', `${id}.kev_scope_note must be present`);
  assert.equal(entry.kev_scope_note.length >= 50, true, `${id}.kev_scope_note must be a substantive paragraph`);
});

test(`v0.12.31: ${id} kev_scope_note documents ecosystem-package CVE-vs-KEV scope`, () => {
  const entry = catalog[id];
  assert.ok(entry, `${id} must be present`);
  assert.equal(typeof entry.kev_scope_note, 'string', `${id}.kev_scope_note must be present (v0.12.31)`);
  assert.equal(entry.kev_scope_note.length >= 50, true, `${id}.kev_scope_note must be a substantive paragraph`);
});
