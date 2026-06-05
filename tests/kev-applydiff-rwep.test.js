'use strict';

/**
 * KEV applyDiff must keep RWEP coherent with the cisa_kev flag.
 *
 * The first scheduled refresh to apply a real KEV listing wrote
 * cisa_kev: true onto an entry without touching rwep_factors or
 * rwep_score, leaving the catalog failing scoring.validate()'s sum
 * invariant (stored 45 vs computed 70 — the delta is exactly the
 * RWEP_WEIGHTS.cisa_kev contribution). The fix recomputes the factor and
 * the stored score inside the same apply, honouring whichever factor
 * shape the entry stores (Shape A boolean / Shape B post-weight).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));

function makeCatalog(entry) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-rwep-'));
  const p = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(p, JSON.stringify({ 'CVE-2099-0001': entry }, null, 2));
  return p;
}

function readCatalog(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('cisa_kev false→true adds the KEV factor and recomputes rwep_score (Shape B)', async () => {
  const p = makeCatalog({
    cisa_kev: false,
    rwep_factors: { cisa_kev: 0, poc_available: 20, active_exploitation: 20, blast_radius: 5 },
    rwep_score: 45,
  });
  const r = await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  assert.equal(r.updated, 1, 'one entry updated');
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev,
    'Shape-B factor must store the post-weight KEV contribution');
  assert.equal(e.rwep_score, 45 + scoring.RWEP_WEIGHTS.cisa_kev,
    'rwep_score must gain exactly the KEV weight — the sum invariant scoring.validate() enforces');
});

test('cisa_kev true→false removes the KEV factor and recomputes rwep_score (Shape B)', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, poc_available: 20, active_exploitation: 20, blast_radius: 5 },
    rwep_score: 45 + scoring.RWEP_WEIGHTS.cisa_kev,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped back');
  assert.equal(e.rwep_factors.cisa_kev, 0, 'Shape-B factor must zero out');
  assert.equal(e.rwep_score, 45, 'rwep_score must drop by exactly the KEV weight');
});

test('Shape-A boolean factors keep their shape and re-derive through the canonical formula', async () => {
  const factorsAfter = { cisa_kev: true, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 };
  const p = makeCatalog({
    cisa_kev: false,
    rwep_factors: { cisa_kev: false, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 },
    rwep_score: scoring.deriveRwepFromFactors({ cisa_kev: false, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 }),
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(typeof e.rwep_factors.cisa_kev, 'boolean', 'Shape-A factor must stay boolean');
  assert.equal(e.rwep_factors.cisa_kev, true, 'Shape-A factor follows the flag');
  assert.equal(e.rwep_score, scoring.deriveRwepFromFactors(factorsAfter),
    'rwep_score must match the canonical derivation of the post-flip factors');
});

test('a cisa_kev_date diff does not touch rwep_factors or rwep_score', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    cisa_kev_date: '2026-01-01',
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 10 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev_date', before: '2026-01-01', after: '2026-06-01' },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev_date, '2026-06-01', 'date applied');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev, 'factor untouched');
  assert.equal(e.rwep_score, scoring.RWEP_WEIGHTS.cisa_kev + 10, 'score untouched');
});

test('an entry without rwep_factors gets the flag but no synthesized factors', async () => {
  const p = makeCatalog({ cisa_kev: false });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped');
  assert.equal('rwep_factors' in e, false, 'must not fabricate a factors object the curator never wrote');
  assert.equal('rwep_score' in e, false, 'must not fabricate a score');
});
