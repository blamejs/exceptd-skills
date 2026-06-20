'use strict';

/**
 * Curated-data protection on the KEV de-listing path.
 *
 * When a cached CISA KEV feed no longer lists a CVE the catalog has curated as
 * cisa_kev:true, the de-listing must NOT be auto-applied if the curated entry
 * carries strong human-curated exploitation signal (active_exploitation
 * confirmed/suspected, a PoC description, or verification sources). A transient
 * or incomplete feed would otherwise silently strip confirmed-exploitation
 * intel and drop the RWEP score. This mirrors the NVD path's curated-downgrade
 * guard: never let an upstream that disagrees with curated data silently
 * regress it.
 *
 * Pinned behaviors:
 *   - A curated, strongly-signalled entry missing from the feed produces a
 *     review-only diff that applyDiff does NOT apply: after apply the entry is
 *     STILL cisa_kev:true, with rwep_factors.cisa_kev and rwep_score intact.
 *   - A genuinely weak entry (no exploitation signal) still de-lists normally.
 *   - An implausibly small feed refuses ALL de-listings wholesale, even for a
 *     weak entry — a truncated feed cannot be trusted to de-list anything.
 *   - First-listings (false->true) are unaffected by the guard.
 *
 * Offline only: the cache lives in a tmpdir; no network call occurs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { kevDiffFromCache, ALL_SOURCES } = require('../lib/refresh-external');

// Build a valid prefetch-style cache holding a KEV feed. The feed's
// vulnerabilities array is padded to `feedSize` entries (filler CVE ids) plus
// whatever explicit entries are supplied, so we can exercise both the
// plausible-feed and truncated-feed branches. readCachedJson verifies the
// payload sha256 against _index.json, so the index records the matching hash.
function writeKevCache(dir, { feedSize = 800, includeCves = [] } = {}) {
  const vulnerabilities = [];
  for (const c of includeCves) {
    vulnerabilities.push({ cveID: c.cveID, dateAdded: c.dateAdded || '2025-01-01' });
  }
  let n = vulnerabilities.length;
  while (vulnerabilities.length < feedSize) {
    n += 1;
    vulnerabilities.push({ cveID: `CVE-1999-${String(n).padStart(4, '0')}`, dateAdded: '2022-01-01' });
  }
  const feed = { catalogVersion: 'test', vulnerabilities };
  fs.mkdirSync(path.join(dir, 'kev'), { recursive: true });
  const feedPath = path.join(dir, 'kev', 'known_exploited_vulnerabilities.json');
  fs.writeFileSync(feedPath, JSON.stringify(feed, null, 2) + '\n');
  // readCachedJson recomputes sha256 over JSON.stringify(JSON.parse(fileBytes)).
  const reparsed = JSON.parse(fs.readFileSync(feedPath, 'utf8'));
  const sha256 = crypto.createHash('sha256').update(JSON.stringify(reparsed)).digest('hex');
  fs.writeFileSync(path.join(dir, '_index.json'), JSON.stringify({
    generated_at: new Date().toISOString(),
    entries: {
      'kev/known_exploited_vulnerabilities': {
        fetched_at: new Date().toISOString(), etag: null, url: 'x', sha256,
      },
    },
  }, null, 2) + '\n');
}

// A curated, strongly-signalled KEV entry shaped like the catalog norm:
// rwep_factors.cisa_kev stores the post-weight contribution (Shape B).
function curatedStrongEntry() {
  return {
    cisa_kev: true,
    cisa_kev_date: '2025-02-13',
    cisa_kev_due_date: '2025-03-06',
    active_exploitation: 'confirmed',
    verification_sources: ['vendor-advisory'],
    rwep_factors: { cisa_kev: 25 },
    rwep_score: 77,
  };
}

function makeCtx(dir, cveCatalog) {
  // applyDiff writes through ctx.cvePath under a catalog lock; point it at a
  // tmp catalog file so the real shipped catalog is never touched.
  const cvePath = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(cvePath, JSON.stringify(cveCatalog, null, 2) + '\n');
  return { cacheDir: dir, cveCatalog, cvePath, forceStale: false };
}

test('curated strongly-signalled entry missing from a plausible feed is held for review, not de-listed', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
  try {
    const cve = 'CVE-2025-1094';
    // Plausible feed (800 entries) that OMITS the curated CVE.
    writeKevCache(tmp, { feedSize: 800, includeCves: [] });
    const catalog = { [cve]: curatedStrongEntry(), _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = kevDiffFromCache(ctx);
    const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
    assert.ok(delist, 'a cisa_kev diff for the missing curated CVE must be produced');
    assert.equal(delist.after, false, 'the diff direction is a de-listing (true->false)');
    // It must be a review-only diff, not a plain applyable one.
    assert.equal(delist.review_only, true, 'a curated de-listing must be marked review_only');
    assert.equal(delist.kev_delist_review, true);

    // Apply it. The guard must hold: the entry survives intact.
    await ALL_SOURCES.kev.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
    assert.equal(after.cisa_kev, true, 'curated cisa_kev must SURVIVE the de-listing');
    assert.equal(after.rwep_factors.cisa_kev, 25, 'the KEV RWEP factor must be intact');
    assert.equal(after.rwep_score, 77, 'rwep_score must be unchanged (no 25-pt drop)');
    assert.equal(after.cisa_kev_date, '2025-02-13', 'the listing date must not be cleared');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a genuinely weak entry (no exploitation signal) still de-lists normally against a plausible feed', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
  try {
    const cve = 'CVE-2025-9999';
    writeKevCache(tmp, { feedSize: 800, includeCves: [] });
    const weak = {
      cisa_kev: true,
      cisa_kev_date: '2024-06-01',
      active_exploitation: null,
      rwep_factors: { cisa_kev: 25 },
      rwep_score: 60,
    };
    const catalog = { [cve]: weak, _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = kevDiffFromCache(ctx);
    const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
    assert.ok(delist, 'a de-listing diff must be produced for the weak entry');
    assert.notEqual(delist.review_only, true, 'a weak de-listing must NOT be review_only');

    await ALL_SOURCES.kev.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
    assert.equal(after.cisa_kev, false, 'a weak entry must de-list normally');
    assert.equal(after.rwep_factors.cisa_kev, 0, 'the KEV factor zeroes on a real de-listing');
    assert.equal(after.cisa_kev_date, null, 'the orphaned listing date is cleared on de-listing');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('an implausibly small feed refuses ALL de-listings wholesale, even for a weak entry', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
  try {
    const cve = 'CVE-2025-7777';
    // A truncated feed (50 entries) — far below a plausible CISA KEV snapshot.
    writeKevCache(tmp, { feedSize: 50, includeCves: [] });
    const weak = {
      cisa_kev: true,
      cisa_kev_date: '2024-06-01',
      active_exploitation: null,
      rwep_factors: { cisa_kev: 25 },
      rwep_score: 60,
    };
    const catalog = { [cve]: weak, _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = kevDiffFromCache(ctx);
    const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev' && d.after === false);
    assert.ok(delist, 'a de-listing diff is still produced');
    assert.equal(delist.review_only, true,
      'a truncated feed must hold even a weak de-listing for review');

    await ALL_SOURCES.kev.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
    assert.equal(after.cisa_kev, true, 'no de-listing may apply against a truncated feed');
    assert.equal(after.rwep_score, 60, 'rwep_score unchanged under the feed-shrink guard');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a first-listing (false->true) is unaffected by the de-listing guard', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
  try {
    const cve = 'CVE-2026-0001';
    // Plausible feed that DOES list the CVE; catalog has it as not-yet-listed.
    writeKevCache(tmp, { feedSize: 800, includeCves: [{ cveID: cve, dateAdded: '2026-05-01' }] });
    const entry = {
      cisa_kev: false,
      cisa_kev_date: null,
      active_exploitation: 'confirmed',
      rwep_factors: { cisa_kev: 0 },
      rwep_score: 40,
    };
    const catalog = { [cve]: entry, _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = kevDiffFromCache(ctx);
    const listing = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
    assert.ok(listing, 'a first-listing diff must be produced');
    assert.equal(listing.after, true, 'direction is a listing (false->true)');
    assert.notEqual(listing.review_only, true, 'a first-listing must apply directly, not held for review');

    await ALL_SOURCES.kev.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
    assert.equal(after.cisa_kev, true, 'the first-listing applies');
    assert.equal(after.rwep_factors.cisa_kev, 25, 'the KEV factor is credited on listing');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('RC-1: the LIVE KEV path holds a curated-exploitation de-listing for review (not just --from-cache)', async () => {
  // fetchDiff lazily requires ../sources/validators; swap it in require.cache so
  // we can drive a de-listing discrepancy without any network call.
  const validatorsPath = require.resolve('../sources/validators');
  const orig = require.cache[validatorsPath];
  require.cache[validatorsPath] = {
    id: validatorsPath, filename: validatorsPath, loaded: true, exports: {
      validateAllCves: async () => ({
        total: 1,
        results: [{
          cve_id: 'CVE-2099-0001', status: 'ok',
          discrepancies: [{ field: 'cisa_kev', local: true, fetched: false, severity: 'high' }],
        }],
      }),
    },
  };
  try {
    const kev = ALL_SOURCES['kev'];
    // Confirmed-exploitation entry → de-listing must be review_only.
    const strong = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { active_exploitation: 'confirmed', cisa_kev: true } } });
    const ds = strong.diffs.find((x) => x.field === 'cisa_kev');
    assert.ok(ds, 'a cisa_kev de-listing diff is produced');
    assert.equal(ds.review_only, true, 'a curated-exploitation de-listing must be held for review on the live path');
    // Weak entry (no exploitation signal) → de-lists normally.
    const weak = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
    const dw = weak.diffs.find((x) => x.field === 'cisa_kev');
    assert.ok(!dw.review_only, 'a weak-signal de-listing is not held for review');
  } finally {
    if (orig) require.cache[validatorsPath] = orig; else delete require.cache[validatorsPath];
  }
});
