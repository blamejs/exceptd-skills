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

test('a first KEV listing emits the flag AND the listing date for a null-date entry', async () => {
  // The diff producer once required a truthy local cisa_kev_date before it
  // would emit a date diff — so a first listing (local date null) flipped the
  // flag alone, and the applied tree failed strict validation (KEV-listed
  // entries must carry their listing date).
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-cache-'));
  fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
  fs.writeFileSync(
    path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'),
    JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2099-0001', dateAdded: '2026-06-01' }] })
  );
  const ctx = {
    cacheDir,
    forceStale: true,
    cveCatalog: { 'CVE-2099-0001': { cisa_kev: false, cisa_kev_date: null } },
  };
  const r = await ALL_SOURCES.kev.fetchDiff(ctx);
  const flag = r.diffs.find((d) => d.id === 'CVE-2099-0001' && d.field === 'cisa_kev');
  const date = r.diffs.find((d) => d.id === 'CVE-2099-0001' && d.field === 'cisa_kev_date');
  assert.ok(flag, 'flag diff emitted');
  assert.equal(flag.after, true, 'flag diff lists the CVE');
  assert.ok(date, 'date diff emitted despite null local date — first-listing case');
  assert.equal(date.before, null, 'before is the null local date');
  assert.equal(date.after, '2026-06-01', 'after is the upstream listing date');
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

test('a KEV de-listing (true→false) clears the now-orphaned cisa_kev_date', async () => {
  // After a CVE leaves KEV, its listing date is stale intel. The upstream
  // diff producer only emits a date diff when upstream HAS a date — a
  // de-listed CVE no longer does — so the applyDiff branch must clear the
  // date itself, or the entry ships cisa_kev:false alongside a stale date.
  const p = makeCatalog({
    cisa_kev: true,
    cisa_kev_date: '2026-01-01',
    cisa_kev_due_date: '2026-01-22',
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 10 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped to de-listed');
  assert.equal(e.cisa_kev_date, null, 'orphaned listing date cleared');
  assert.equal(e.cisa_kev_due_date, null, 'orphaned due date cleared');
  assert.equal(e.rwep_factors.cisa_kev, 0, 'KEV factor zeroed');
  assert.equal(e.rwep_score, 10, 'rwep_score drops by exactly the KEV weight');
});

test('a KEV listing (false→true) does not null a date the diff will set separately', async () => {
  // The date-clear must only fire on de-listing. A fresh listing keeps any
  // existing date untouched here; the paired cisa_kev_date diff sets it.
  const p = makeCatalog({
    cisa_kev: false,
    cisa_kev_date: null,
    rwep_factors: { cisa_kev: 0, blast_radius: 10 },
    rwep_score: 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped to listed');
  assert.equal(e.cisa_kev_date, null, 'listing-direction flip leaves the date for its own diff');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev, 'KEV factor added');
});

test('de-listing an entry that never carried a date leaves no spurious key', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 5 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 5,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped');
  assert.equal('cisa_kev_date' in e, false, 'must not introduce a date key that was never present');
  assert.equal('cisa_kev_due_date' in e, false, 'must not introduce a due-date key that was never present');
});
