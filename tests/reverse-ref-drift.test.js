'use strict';

/**
 * tests/reverse-ref-drift.test.js
 *
 * Cycle 9 audit fix — every catalog's per-entry reverse skill list must
 * match the manifest forward direction exactly.
 *
 * For each of the four catalogs in scope (atlas-ttps, cwe-catalog,
 * d3fend-catalog, rfc-references), recompute the expected reverse
 * field from manifest.json's forward refs and assert set-equality with
 * the catalog's stored value. Any drift means scripts/refresh-reverse-refs.js
 * was not run after a forward-ref change in a skill manifest entry.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks the EXACT
 * value — exact set-equality (sorted-array deep-equal), never `assert.ok()`
 * or partial-match.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

// Mirror the script's CATALOGS — keep in sync. The script is the source
// of truth for the field-name pairing per catalog.
const CATALOGS = [
  { file: 'atlas-ttps.json', forwardField: 'atlas_refs', reverseField: 'exceptd_skills' },
  { file: 'cwe-catalog.json', forwardField: 'cwe_refs', reverseField: 'skills_referencing' },
  { file: 'd3fend-catalog.json', forwardField: 'd3fend_refs', reverseField: 'skills_referencing' },
  { file: 'rfc-references.json', forwardField: 'rfc_refs', reverseField: 'skills_referencing' },
];

function buildExpectedReverse(skills, forwardField) {
  const index = new Map();
  for (const skill of skills) {
    const refs = Array.isArray(skill[forwardField]) ? skill[forwardField] : [];
    for (const id of refs) {
      if (!index.has(id)) index.set(id, new Set());
      index.get(id).add(skill.name);
    }
  }
  return index;
}

for (const cfg of CATALOGS) {
  test(`reverse refs in ${cfg.file} match manifest.${cfg.forwardField} exactly`, () => {
    const catalog = JSON.parse(
      fs.readFileSync(path.join(ROOT, 'data', cfg.file), 'utf8'),
    );
    const expectedIndex = buildExpectedReverse(manifest.skills, cfg.forwardField);

    for (const [id, entry] of Object.entries(catalog)) {
      if (id === '_meta') continue;
      if (typeof entry !== 'object' || entry === null) continue;

      const stored = Array.isArray(entry[cfg.reverseField])
        ? [...entry[cfg.reverseField]]
        : [];
      const expected = expectedIndex.has(id)
        ? Array.from(expectedIndex.get(id)).sort()
        : [];

      // Set-equality, order-agnostic. Compare sorted arrays — deepEqual
      // surfaces the exact diff when they disagree.
      const storedSorted = [...stored].sort();
      assert.deepEqual(storedSorted, expected,
        `${cfg.file} entry ${id} reverse field "${cfg.reverseField}" drift: ` +
        `stored=[${storedSorted.join(',')}] expected=[${expected.join(',')}]. ` +
        `Run \`npm run refresh-reverse-refs\` to regenerate.`);
    }
  });
}
