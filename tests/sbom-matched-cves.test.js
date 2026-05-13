'use strict';

/**
 * Analyze-phase CVE classification: matched_cves (evidence-correlated) vs
 * catalog_baseline_cves (scan-coverage enumeration).
 *
 * Pre-fix, analyze.matched_cves enumerated every CVE in domain.cve_refs
 * regardless of evidence. Operators running `exceptd run sbom --evidence -`
 * with EMPTY artifacts saw 6 catalog CVEs in matched_cves and incorrectly
 * read it as "I am affected by these." Post-fix, matched_cves requires a
 * correlation path — indicator hit with shared attack_ref/atlas_ref, or
 * an agent signal explicitly referencing the CVE — and the unaffiliated
 * catalog enumeration moved to catalog_baseline_cves with correlated_via=null.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { ROOT } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

// ---------------------------------------------------------------------------
// Empty-evidence case: no indicator hits, no CVE signals → matched_cves empty.

test('sbom with empty artifacts: matched_cves is empty, catalog_baseline_cves enumerates the playbook coverage', () => {
  const submission = { artifacts: {}, signal_overrides: {}, signals: {} };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true, 'run must succeed even with empty evidence');

  const matched = result.phases.analyze.matched_cves;
  const baseline = result.phases.analyze.catalog_baseline_cves;

  assert.ok(Array.isArray(matched), 'matched_cves is an array');
  assert.equal(matched.length, 0,
    'matched_cves must be empty when no evidence correlates — pre-fix this enumerated catalog CVEs as if the operator were affected');

  assert.ok(Array.isArray(baseline), 'catalog_baseline_cves is an array');
  assert.ok(baseline.length >= 1,
    'catalog_baseline_cves must enumerate the playbook\'s scan coverage; sbom has at least one cve_ref');

  // Baseline entries carry full per-CVE shape (CVE id + RWEP + KEV + ...)
  // identical to matched_cves but with correlated_via:null and a note that
  // makes the "this is scan coverage, not affected-status" semantic explicit.
  for (const entry of baseline) {
    assert.equal(entry.correlated_via, null,
      `catalog_baseline_cves entry ${entry.cve_id} must carry correlated_via=null`);
    assert.equal(typeof entry.note, 'string',
      `catalog_baseline_cves entry ${entry.cve_id} must carry a note clarifying the field is scan-coverage metadata`);
    assert.equal(typeof entry.cve_id, 'string');
    assert.equal(typeof entry.rwep, 'number');
  }

  // RWEP base falls to 0 when no evidence correlates — pre-fix it inflated
  // to the maximum catalog rwep_score, inheriting the catalog ceiling for
  // every empty-evidence run.
  assert.equal(result.phases.analyze.rwep.base, 0,
    'RWEP base must be 0 when no CVE correlates to operator evidence');
});

// ---------------------------------------------------------------------------
// Correlated-evidence case: a single indicator fires that shares an
// attack_ref with a catalog CVE → matched_cves contains that CVE.

test('sbom with indicator hit: matched_cves contains the correlated CVE with non-null correlated_via', () => {
  // tanstack-worm-payload-files (attack_ref T1195.002) is one of the sbom
  // indicators. CVE-2026-45321 (the TanStack worm CVE) carries T1195.002 in
  // its attack_refs in the catalog, so this submission must correlate.
  const submission = {
    artifacts: {},
    signal_overrides: { 'tanstack-worm-payload-files': 'hit' },
    signals: {},
  };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true);

  const matched = result.phases.analyze.matched_cves;
  assert.ok(matched.length >= 1,
    `matched_cves must contain at least one evidence-correlated CVE when a relevant indicator fires; got ${matched.length}`);

  // Every entry in matched_cves MUST have a non-empty correlated_via array.
  // Coincidence-passing regression: a runner that accidentally enumerates
  // catalog CVEs without setting correlated_via would surface as `length >= 1`
  // but every entry having correlated_via=null — explicit shape check pins
  // the correlation provenance.
  for (const entry of matched) {
    assert.ok(Array.isArray(entry.correlated_via) && entry.correlated_via.length > 0,
      `matched_cves entry ${entry.cve_id} must carry a non-empty correlated_via array — empty/null is the catalog-baseline regression class this test guards`);
    assert.ok(entry.correlated_via.every(r => typeof r === 'string' && r.length > 0),
      `correlated_via entries for ${entry.cve_id} must be non-empty strings (e.g. "indicator_hit:<id>" or "signal:<cve_id>")`);
  }

  // At least one correlation must reference the indicator we fired.
  const allReasons = matched.flatMap(c => c.correlated_via);
  assert.ok(allReasons.some(r => r === 'indicator_hit:tanstack-worm-payload-files'),
    `at least one matched_cves entry must reference the fired indicator (indicator_hit:tanstack-worm-payload-files); reasons seen: ${JSON.stringify(allReasons)}`);
});

// ---------------------------------------------------------------------------
// Correlated-evidence case: an agent signal explicitly references a CVE id.

test('sbom with direct CVE signal: matched_cves contains the CVE with signal correlation reason', () => {
  // signals['CVE-id'] === true is the explicit "operator declares affected" path.
  const submission = {
    artifacts: {},
    signal_overrides: {},
    signals: { 'CVE-2026-45321': true },
  };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true);

  const matched = result.phases.analyze.matched_cves;
  const entry = matched.find(c => c.cve_id === 'CVE-2026-45321');
  assert.ok(entry, 'CVE-2026-45321 must appear in matched_cves when the operator signals it directly');
  assert.ok(Array.isArray(entry.correlated_via) && entry.correlated_via.includes('signal:CVE-2026-45321'),
    `correlation reason must include "signal:CVE-2026-45321"; got ${JSON.stringify(entry.correlated_via)}`);
});

// ---------------------------------------------------------------------------
// Catalog baseline is independent of evidence: always populated for playbooks
// with non-empty cve_refs.

test('sbom catalog_baseline_cves is populated identically across empty-evidence and correlated-evidence runs', () => {
  const empty = runner.run('sbom', 'all-installed-packages-and-lockfiles', { artifacts: {}, signal_overrides: {}, signals: {} });
  const hit = runner.run('sbom', 'all-installed-packages-and-lockfiles', {
    artifacts: {},
    signal_overrides: { 'tanstack-worm-payload-files': 'hit' },
    signals: {},
  });
  const emptyBaseline = empty.phases.analyze.catalog_baseline_cves.map(c => c.cve_id).sort();
  const hitBaseline = hit.phases.analyze.catalog_baseline_cves.map(c => c.cve_id).sort();
  assert.deepEqual(hitBaseline, emptyBaseline,
    'catalog_baseline_cves enumeration must be stable across runs — it is scan coverage, not affected-status');
});
