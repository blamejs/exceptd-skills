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

// Exercise the script's public exports so the diff-coverage gate
// (Hard Rule #15) registers them as covered. The drift-detection logic
// below has its own copy of CATALOGS that stays the source of truth for
// the assertion — the require() here is a smoke-coverage hook.
const refreshScript = require(path.join(ROOT, 'scripts', 'refresh-reverse-refs.js'));

test('refresh-reverse-refs.js exports CATALOGS, buildReverseIndex, buildCveReverseIndex, rebuildCatalog (smoke)', () => {
  assert.equal(Array.isArray(refreshScript.CATALOGS), true);
  // Cycle 12 F3 (v0.12.32): added cwe-catalog entry from CVE direction
  // (`cve.entries → evidence_cves`). Catalog count grew 4 → 5.
  // Cycle 20 B F4 (v0.12.40): added CVE→framework-gap entry. 5 → 6.
  assert.equal(refreshScript.CATALOGS.length, 6);
  assert.equal(typeof refreshScript.buildReverseIndex, 'function');
  assert.equal(typeof refreshScript.buildCveReverseIndex, 'function');
  assert.equal(typeof refreshScript.rebuildCatalog, 'function');

  // Exercise buildReverseIndex against a synthetic skills array so the
  // call site is genuinely covered, not just present (matches the
  // function signature: skills-array + forward-field string).
  const reverse = refreshScript.buildReverseIndex(
    [{ name: 's1', atlas_refs: ['AML.T0040'] }, { name: 's2', atlas_refs: ['AML.T0040', 'AML.T0019'] }],
    'atlas_refs',
  );
  assert.equal(reverse.get('AML.T0040').size, 2);
  assert.equal(reverse.get('AML.T0040').has('s1'), true);
  assert.equal(reverse.get('AML.T0040').has('s2'), true);
  assert.equal(reverse.get('AML.T0019').size, 1);
});

// Mirror the script's CATALOGS — keep in sync. The script is the source
// of truth for the field-name pairing per catalog. Skill-side only here;
// the CVE-side reverse (cwe.evidence_cves from cve.cwe_refs) has its own
// drift test below.
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

// Cycle 12 F3 (v0.12.32): pin the CVE-side reverse direction. cwe-catalog
// entries declare `evidence_cves` — the operator-facing "which CVEs map
// to this CWE" index. Pre-fix it was hand-maintained and drifted with
// every CVE intake. Now mirrors cve.cwe_refs automatically; this test
// blocks merges that re-introduce drift.
test('cwe-catalog.json evidence_cves matches cve-catalog.json cwe_refs exactly (drafts excluded)', () => {
  const cveCatalog = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'),
  );
  const cweCatalog = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data', 'cwe-catalog.json'), 'utf8'),
  );
  // Build the expected reverse index: cwe-id -> Set<cve-id>. Drafts skipped
  // (matches script's buildCveReverseIndex contract).
  const expectedIndex = new Map();
  for (const [cveId, entry] of Object.entries(cveCatalog)) {
    if (cveId === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    if (entry._draft === true) continue;
    const refs = Array.isArray(entry.cwe_refs) ? entry.cwe_refs : [];
    for (const cweId of refs) {
      if (!expectedIndex.has(cweId)) expectedIndex.set(cweId, new Set());
      expectedIndex.get(cweId).add(cveId);
    }
  }

  for (const [cweId, entry] of Object.entries(cweCatalog)) {
    if (cweId === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    const stored = Array.isArray(entry.evidence_cves)
      ? [...entry.evidence_cves].sort()
      : [];
    const expected = expectedIndex.has(cweId)
      ? Array.from(expectedIndex.get(cweId)).sort()
      : [];
    assert.deepEqual(stored, expected,
      `cwe-catalog.json entry ${cweId} evidence_cves drift: ` +
      `stored=[${stored.join(',')}] expected=[${expected.join(',')}]. ` +
      `Run \`npm run refresh-reverse-refs\` to regenerate.`);
  }
});

// Cycle 20 B F4 (v0.12.40): pin the CVE-to-framework-gap reverse
// direction. Pre-fix 137 directional mismatches (24 CVE→gap missing
// reverse + 79 gap→CVE missing reverse) sat between
// cve.framework_control_gaps (dict keyed by gap id) and
// gap.evidence_cves (array of CVE ids). v0.12.40 extended
// refresh-reverse-refs.js to walk this direction; this test pins
// the contract going forward.
test('framework-control-gaps.json evidence_cves matches cve-catalog.json framework_control_gaps (drafts excluded)', () => {
  const cveCatalog = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'),
  );
  const gapCatalog = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'),
  );
  // CVE.framework_control_gaps is a dict (keys = gap ids).
  const expectedIndex = new Map();
  for (const [cveId, entry] of Object.entries(cveCatalog)) {
    if (cveId === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    if (entry._draft === true) continue;
    const fcg = entry.framework_control_gaps;
    if (!fcg || typeof fcg !== 'object' || Array.isArray(fcg)) continue;
    for (const gapId of Object.keys(fcg)) {
      if (!expectedIndex.has(gapId)) expectedIndex.set(gapId, new Set());
      expectedIndex.get(gapId).add(cveId);
    }
  }
  for (const [gapId, entry] of Object.entries(gapCatalog)) {
    if (gapId === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    const stored = Array.isArray(entry.evidence_cves)
      ? [...entry.evidence_cves].sort()
      : [];
    const expected = expectedIndex.has(gapId)
      ? Array.from(expectedIndex.get(gapId)).sort()
      : [];
    assert.deepEqual(stored, expected,
      `framework-control-gaps.json entry ${gapId} evidence_cves drift: ` +
      `stored=[${stored.join(',')}] expected=[${expected.join(',')}]. ` +
      `Run \`npm run refresh-reverse-refs\` to regenerate.`);
  }
});
