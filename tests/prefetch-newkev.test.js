'use strict';

/**
 * Plan Task 11 — nightly prefetch also fetches NVD/EPSS for newly-KEV-listed
 * CVE ids, so a nightly KEV draft (lib/auto-discovery.js buildKevDraftEntry)
 * arrives pre-enriched instead of with null mechanical fields.
 *
 * Covers:
 *   - `newKevIds(kevFeed, cveCatalog)` — the pure helper (KEV feed minus
 *     local catalog), thoroughly, per the plan's Step 1 test plus edge cases.
 *   - `SOURCES.nvd.expand` / `SOURCES.epss.expand` — the new-KEV union,
 *     exercised directly against a synthetic `ctx` (no fs/network — the
 *     documented, cheap way to unit-test the expansion in isolation).
 *   - A real `prefetch()` run (stubbed `global.fetch`, tmp cache dir) proving
 *     the KEV-pre-fetch step actually threads `ctx.kevFeed` through to nvd's
 *     expansion and the resulting sidecar lands through the SAME write +
 *     `_index.json` path the rest of prefetch uses (the thing
 *     `lib/auto-discovery.js:readCachedJson` requires to accept it).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.resolve(__dirname, '..');
const prefetchLib = require('../lib/prefetch.js');
const { SOURCES, newKevIds, prefetch } = prefetchLib;

// ---------------------------------------------------------------------------
// newKevIds — pure helper
// ---------------------------------------------------------------------------

test('newKevIds: KEV feed minus catalog (plan Task 11 Step 1)', () => {
  const feed = { vulnerabilities: [{ cveID: 'CVE-2025-0108' }, { cveID: 'CVE-2000-0001' }] };
  const catalog = { 'CVE-2000-0001': {}, _meta: {} };
  const ids = newKevIds(feed, catalog);
  assert.deepStrictEqual(ids, ['CVE-2025-0108']);
});

test('newKevIds: filters non-CVE-shaped ids out of the feed', () => {
  const feed = {
    vulnerabilities: [
      { cveID: 'CVE-2025-0108' },
      { cveID: 'not-a-cve' },
      { cveID: 'MAL-2026-0001' },
      { cveID: '' },
      {}, // missing cveID entirely
    ],
  };
  const ids = newKevIds(feed, {});
  assert.deepStrictEqual(ids, ['CVE-2025-0108']);
});

test('newKevIds: excludes ids already present in the catalog, keeps genuinely new ones', () => {
  const feed = {
    vulnerabilities: [
      { cveID: 'CVE-2025-0001' },
      { cveID: 'CVE-2025-0002' },
      { cveID: 'CVE-2025-0003' },
    ],
  };
  const catalog = { 'CVE-2025-0001': {}, 'CVE-2025-0003': {} };
  assert.deepStrictEqual(newKevIds(feed, catalog), ['CVE-2025-0002']);
});

test('newKevIds: null/undefined kevFeed returns [] (no crash)', () => {
  assert.deepStrictEqual(newKevIds(null, { 'CVE-2020-0001': {} }), []);
  assert.deepStrictEqual(newKevIds(undefined, {}), []);
});

test('newKevIds: kevFeed with no/malformed vulnerabilities array returns [] (no crash)', () => {
  assert.deepStrictEqual(newKevIds({}, {}), []);
  assert.deepStrictEqual(newKevIds({ vulnerabilities: null }, {}), []);
});

test('newKevIds: null/undefined cveCatalog treated as empty (no crash)', () => {
  const feed = { vulnerabilities: [{ cveID: 'CVE-2025-0108' }] };
  assert.deepStrictEqual(newKevIds(feed, null), ['CVE-2025-0108']);
  assert.deepStrictEqual(newKevIds(feed, undefined), ['CVE-2025-0108']);
});

// ---------------------------------------------------------------------------
// SOURCES.nvd.expand / SOURCES.epss.expand — direct ctx exercise
// ---------------------------------------------------------------------------

test('SOURCES.nvd.expand includes a new-KEV id when ctx.kevFeed is present', () => {
  const ctx = {
    cveCatalog: { 'CVE-2000-0001': {}, _meta: {} },
    kevFeed: { vulnerabilities: [{ cveID: 'CVE-2025-0108' }, { cveID: 'CVE-2000-0001' }] },
  };
  const ids = SOURCES.nvd.expand(ctx).map((e) => e.id).sort();
  assert.deepStrictEqual(ids, ['CVE-2000-0001', 'CVE-2025-0108']);
  const newEntry = SOURCES.nvd.expand(ctx).find((e) => e.id === 'CVE-2025-0108');
  assert.match(newEntry.url, /^https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?cveId=CVE-2025-0108$/);
});

test('SOURCES.epss.expand includes a new-KEV id when ctx.kevFeed is present', () => {
  const ctx = {
    cveCatalog: { 'CVE-2000-0001': {} },
    kevFeed: { vulnerabilities: [{ cveID: 'CVE-2025-0108' }] },
  };
  const ids = SOURCES.epss.expand(ctx).map((e) => e.id).sort();
  assert.deepStrictEqual(ids, ['CVE-2000-0001', 'CVE-2025-0108']);
  const newEntry = SOURCES.epss.expand(ctx).find((e) => e.id === 'CVE-2025-0108');
  assert.match(newEntry.url, /^https:\/\/api\.first\.org\/data\/v1\/epss\?cve=CVE-2025-0108$/);
});

test('SOURCES.nvd.expand / epss.expand fall back to catalog-only when ctx.kevFeed is absent (no crash)', () => {
  const ctx = { cveCatalog: { 'CVE-2000-0001': {} } };
  assert.deepStrictEqual(SOURCES.nvd.expand(ctx).map((e) => e.id), ['CVE-2000-0001']);
  assert.deepStrictEqual(SOURCES.epss.expand(ctx).map((e) => e.id), ['CVE-2000-0001']);
});

test('SOURCES.nvd.expand does not duplicate an id already in both the catalog and the KEV feed', () => {
  const ctx = {
    cveCatalog: { 'CVE-2000-0001': {} },
    kevFeed: { vulnerabilities: [{ cveID: 'CVE-2000-0001' }] },
  };
  const ids = SOURCES.nvd.expand(ctx).map((e) => e.id);
  assert.deepStrictEqual(ids, ['CVE-2000-0001']);
});

// ---------------------------------------------------------------------------
// Integration: a real prefetch() run threads the freshly-fetched KEV feed
// into ctx before nvd/epss build their plan, and the resulting sidecars land
// through the same write + signed-_index.json path as every other entry.
// ---------------------------------------------------------------------------

function withStubbedFetch(impl, fn) {
  const orig = global.fetch;
  global.fetch = impl;
  return Promise.resolve().then(fn).finally(() => { global.fetch = orig; });
}

// prefetch.js's loadCtx() unconditionally reads the REAL (600+ entry)
// data/cve-catalog.json. Scoping a real prefetch() run to `--source kev,nvd`
// against the real catalog would still plan an nvd fetch for every real
// catalog CVE — hundreds of items throttled by the anonymous 5-req/30s NVD
// token bucket, making the test impractically slow. Swap in a tiny synthetic
// catalog for the duration of the test by intercepting fs.readFileSync calls
// for that one path only; every other read (manifest.json, rfc-references,
// keys/, .keys/) passes through unchanged.
function withTinyCveCatalog(tinyCatalog, fn) {
  const orig = fs.readFileSync;
  const catalogPath = path.join(ROOT, 'data', 'cve-catalog.json');
  fs.readFileSync = function (p, ...args) {
    if (path.resolve(String(p)) === catalogPath) return JSON.stringify(tinyCatalog);
    return orig.apply(fs, [p, ...args]);
  };
  return Promise.resolve().then(fn).finally(() => { fs.readFileSync = orig; });
}

test('prefetch(): KEV pre-fetch writes its sidecar through the standard write + signed-index path', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-newkev-kev-'));
  try {
    const kevFeed = { vulnerabilities: [{ cveID: 'CVE-2025-0108' }] };
    const result = await withStubbedFetch(
      async (url) => {
        assert.match(String(url), /known_exploited_vulnerabilities\.json$/, `unexpected fetch: ${url}`);
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          async json() { return kevFeed; },
        };
      },
      () => prefetch({ source: 'kev', cacheDir: tmp, quiet: true, maxAgeMs: 24 * 3600 * 1000 })
    );

    assert.equal(result.fetched, 1, 'the single kev entry must be fetched');
    assert.equal(result.by_source.kev.fetched, 1);
    assert.equal(result.errors, 0);

    const payloadPath = path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json');
    assert.ok(fs.existsSync(payloadPath), 'kev payload must be written to the cache dir');
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(payloadPath, 'utf8')), kevFeed);

    const idx = JSON.parse(fs.readFileSync(path.join(tmp, '_index.json'), 'utf8'));
    const meta = idx.entries['kev/known_exploited_vulnerabilities'];
    assert.ok(meta, 'kev entry must be registered in the signed _index.json, or auto-discovery.readCachedJson will refuse it');
    assert.equal(typeof meta.sha256, 'string');
    assert.equal(typeof meta.fetched_at, 'string');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch(): a CVE newly added to KEV gets an NVD sidecar in THIS run (end-to-end ordering)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-newkev-nvd-'));
  try {
    // 'CVE-2000-0001' is already in the (tiny, synthetic) local catalog;
    // 'CVE-2025-0108' is only in the KEV feed — the case this task fixes.
    const tinyCatalog = { 'CVE-2000-0001': { name: 'already curated' }, _meta: {} };
    const kevFeed = {
      vulnerabilities: [
        { cveID: 'CVE-2000-0001' },
        { cveID: 'CVE-2025-0108' },
      ],
    };
    const nvdPayload = {
      vulnerabilities: [{
        cve: {
          id: 'CVE-2025-0108',
          metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 8.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' } }] },
          descriptions: [{ lang: 'en', value: 'stub' }],
          weaknesses: [],
          references: [],
        },
      }],
    };

    const fetchedUrls = [];
    const result = await withTinyCveCatalog(tinyCatalog, () => withStubbedFetch(
      async (url) => {
        const u = String(url);
        fetchedUrls.push(u);
        if (u.includes('known_exploited_vulnerabilities.json')) {
          return { ok: true, status: 200, headers: { get: () => null }, async json() { return kevFeed; } };
        }
        if (u.includes('cveId=CVE-2000-0001')) {
          return { ok: true, status: 200, headers: { get: () => null }, async json() { return { vulnerabilities: [] }; } };
        }
        if (u.includes('cveId=CVE-2025-0108')) {
          return { ok: true, status: 200, headers: { get: () => null }, async json() { return nvdPayload; } };
        }
        throw new Error(`unexpected fetch in test: ${u}`);
      },
      () => prefetch({ source: 'kev,nvd', cacheDir: tmp, quiet: true, maxAgeMs: 24 * 3600 * 1000 })
    ));

    // Both the already-catalogued id and the newly-KEV-listed id must have
    // been fetched from NVD — the whole point of Task 11.
    assert.ok(fetchedUrls.some((u) => u.includes('cveId=CVE-2000-0001')), 'existing-catalog id must still be fetched (no regression)');
    assert.ok(fetchedUrls.some((u) => u.includes('cveId=CVE-2025-0108')), 'newly-KEV-listed id must be fetched THIS run, not deferred');

    const sidecarPath = path.join(tmp, 'nvd', 'CVE-2025-0108.json');
    assert.ok(fs.existsSync(sidecarPath), 'nvd sidecar for the newly-KEV-listed id must be written to the cache dir');
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(sidecarPath, 'utf8')), nvdPayload);

    const idx = JSON.parse(fs.readFileSync(path.join(tmp, '_index.json'), 'utf8'));
    const meta = idx.entries['nvd/CVE-2025-0108'];
    assert.ok(meta, 'the new-KEV nvd sidecar must be registered in _index.json (readCachedJson requires a matching, sha256-verified entry)');
    assert.equal(typeof meta.sha256, 'string');

    assert.equal(result.errors, 0, `no fetch errors expected; got by_source=${JSON.stringify(result.by_source)}`);
    assert.equal(result.by_source.kev.fetched, 1);
    assert.equal(result.by_source.nvd.fetched, 2, 'both the catalog id and the new-KEV id must be counted as fetched');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch(): --no-network never triggers the KEV pre-fetch (no egress, no crash)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-newkev-dryrun-'));
  try {
    let calls = 0;
    const result = await withStubbedFetch(
      async () => { calls++; throw new Error('must not fetch under --no-network'); },
      () => prefetch({ source: 'kev,nvd', cacheDir: tmp, quiet: true, noNetwork: true })
    );
    assert.equal(calls, 0, 'no-network must never call fetch, including the new KEV pre-fetch step');
    assert.equal(result.fetched, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch(): --source nvd (kev out of scope) leaves ctx.kevFeed unset — catalog-only, no crash', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-newkev-scoped-'));
  try {
    const tinyCatalog = { 'CVE-2000-0001': { name: 'x' }, _meta: {} };
    const fetchedUrls = [];
    const result = await withTinyCveCatalog(tinyCatalog, () => withStubbedFetch(
      async (url) => {
        const u = String(url);
        fetchedUrls.push(u);
        if (u.includes('known_exploited_vulnerabilities.json')) {
          throw new Error('kev must not be fetched when --source nvd excludes it');
        }
        return { ok: true, status: 200, headers: { get: () => null }, async json() { return { vulnerabilities: [] }; } };
      },
      () => prefetch({ source: 'nvd', cacheDir: tmp, quiet: true, maxAgeMs: 24 * 3600 * 1000 })
    ));
    assert.equal(fetchedUrls.length, 1, 'only the one catalog CVE should be fetched — no kev pre-fetch when kev is out of scope');
    assert.ok(fetchedUrls[0].includes('cveId=CVE-2000-0001'));
    assert.equal(result.errors, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
