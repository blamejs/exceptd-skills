'use strict';

/**
 * tests/catalog-ids.test.js
 *
 * The CVE ids the catalog tracks, own keys and aliases[], and the refresh,
 * prefetch, KEV-discovery and validate-cves paths that read upstream feeds by them.
 * A value read through an alias is held for review on the owning entry.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const { CVE_ID_RE, cveLookupTargets, trackedCveIds } = require('../lib/catalog-ids');
const { kevDiffFromCache, epssDiffFromCache, nvdDiffFromCache, ALL_SOURCES } = require('../lib/refresh-external');
const { newKevIds, SOURCES } = require('../lib/prefetch');
const { discoverNewKev } = require('../lib/auto-discovery');

const VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

function catalogWithAlias() {
  return {
    _meta: { schema_version: 'x' },
    'CVE-2099-0001': { cisa_kev: false, cvss_score: 5.0, cvss_vector: VECTOR, epss_score: 0.1, epss_percentile: 0.5, epss_date: '2026-01-01' },
    'BUG-2099-ALIASED': {
      aliases: ['CVE-2099-0002', 'GHSA-xxxx-yyyy-zzzz', 'CVE-2099-0001'],
      cisa_kev: false, cvss_score: 5.0, cvss_vector: VECTOR, epss_score: 0.1, epss_percentile: 0.5, epss_date: '2026-01-01',
    },
    'MAL-2099-NO-ALIAS': { cisa_kev: false },
  };
}

test('cveLookupTargets lists own keys, then alias CVE ids that no entry is keyed by', () => {
  const t = cveLookupTargets(catalogWithAlias());
  assert.deepEqual(t, [
    { cveId: 'CVE-2099-0001', key: 'CVE-2099-0001', alias: false },
    { cveId: 'CVE-2099-0002', key: 'BUG-2099-ALIASED', alias: true },
  ]);
});

test('cveLookupTargets skips _meta, non-CVE aliases, and an alias another entry is keyed by', () => {
  const ids = cveLookupTargets(catalogWithAlias()).map((x) => x.cveId);
  assert.ok(!ids.includes('GHSA-xxxx-yyyy-zzzz'), 'a GHSA alias is not a CVE id');
  assert.equal(ids.filter((x) => x === 'CVE-2099-0001').length, 1, 'an alias that is also a key stays with its own entry');
});

test('cveLookupTargets lists an alias two entries share once, for the first entry', () => {
  const cat = { 'BUG-A': { aliases: ['CVE-2099-0009'] }, 'BUG-B': { aliases: ['CVE-2099-0009'] } };
  assert.deepEqual(cveLookupTargets(cat), [{ cveId: 'CVE-2099-0009', key: 'BUG-A', alias: true }]);
});

test('cveLookupTargets returns [] for a missing or non-object catalog', () => {
  assert.deepEqual(cveLookupTargets(null), []);
  assert.deepEqual(cveLookupTargets('x'), []);
});

test('trackedCveIds is the set of every tracked CVE id', () => {
  assert.deepEqual([...trackedCveIds(catalogWithAlias())].sort(), ['CVE-2099-0001', 'CVE-2099-0002']);
  assert.ok(CVE_ID_RE.test('CVE-2026-1234567') && !CVE_ID_RE.test('CVE-2020-17103-REREGRESSION-2026'));
});

test('the shipped catalog tracks the YellowKey and GreenPlasma CVE ids through their entries', () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  const t = cveLookupTargets(catalog);
  const find = (id) => t.find((x) => x.cveId === id);
  assert.deepEqual(find('CVE-2026-45585'), { cveId: 'CVE-2026-45585', key: 'BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY', alias: true });
  assert.deepEqual(find('CVE-2026-45586'), { cveId: 'CVE-2026-45586', key: 'BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA', alias: true });
});

// --- refresh from cache -------------------------------------------------------

async function withCache(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-ids-'));
  try { return await fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
function writeJson(dir, sub, name, obj) {
  fs.mkdirSync(path.join(dir, sub), { recursive: true });
  fs.writeFileSync(path.join(dir, sub, `${name}.json`), JSON.stringify(obj));
}
function kevFeed(records) {
  // Pad past the plausibility floor so no diff is held for feed size.
  const vulnerabilities = [...records];
  for (let i = 0; vulnerabilities.length < 800; i++) vulnerabilities.push({ cveID: `CVE-2098-${String(10000 + i)}`, dateAdded: '2025-01-01' });
  return { vulnerabilities };
}

test('kevDiffFromCache reads an aliased CVE from the feed and holds its diffs on the owning entry', () => {
  return withCache((dir) => {
    writeJson(dir, 'kev', 'known_exploited_vulnerabilities', kevFeed([{ cveID: 'CVE-2099-0002', dateAdded: '2026-09-01', dueDate: '2026-09-22' }]));
    const ctx = { cacheDir: dir, forceStale: true, cveCatalog: catalogWithAlias() };
    const r = kevDiffFromCache(ctx);
    const mine = r.diffs.filter((d) => d.id === 'BUG-2099-ALIASED');
    assert.deepEqual(mine.map((d) => d.field).sort(), ['cisa_kev', 'cisa_kev_date', 'cisa_kev_due_date']);
    for (const d of mine) {
      assert.equal(d.review_only, true, `${d.field} read through an alias is held for review`);
      assert.equal(d.via_alias, 'CVE-2099-0002');
      assert.match(d.note, /alias of BUG-2099-ALIASED/);
    }
    assert.ok(!r.diffs.some((d) => d.id === 'CVE-2099-0002'), 'no diff names the alias as a catalog key');
    const own = r.diffs.filter((d) => d.id === 'CVE-2099-0001');
    assert.deepEqual(own, [], 'the own-key entry is not in the feed and is not KEV-listed, so it has no diff');
  });
});

test('kevDiffFromCache does not hold an own-key diff for review', () => {
  return withCache((dir) => {
    writeJson(dir, 'kev', 'known_exploited_vulnerabilities', kevFeed([{ cveID: 'CVE-2099-0001', dateAdded: '2026-09-01' }]));
    const r = kevDiffFromCache({ cacheDir: dir, forceStale: true, cveCatalog: catalogWithAlias() });
    const d = r.diffs.find((x) => x.id === 'CVE-2099-0001' && x.field === 'cisa_kev');
    assert.ok(d, 'the own-key listing is a diff');
    assert.notEqual(d.review_only, true);
    assert.equal(d.via_alias, undefined);
  });
});

test('epssDiffFromCache reads an aliased CVE, and EPSS applyDiff does not write a review-only diff', async () => {
  await withCache(async (dir) => {
    writeJson(dir, 'epss', 'CVE-2099-0002', { status: 'OK', data: [{ cve: 'CVE-2099-0002', epss: '0.9', percentile: '0.99', date: '2026-10-01' }] });
    const cveCatalog = catalogWithAlias();
    const cvePath = path.join(dir, 'cve-catalog.json');
    fs.writeFileSync(cvePath, JSON.stringify(cveCatalog, null, 2) + '\n');
    const ctx = { cacheDir: dir, forceStale: true, cveCatalog, cvePath };
    const r = epssDiffFromCache(ctx);
    const mine = r.diffs.filter((d) => d.id === 'BUG-2099-ALIASED');
    assert.deepEqual(mine.map((d) => d.field).sort(), ['epss_date', 'epss_percentile', 'epss_score']);
    assert.ok(mine.every((d) => d.review_only === true && d.via_alias === 'CVE-2099-0002'));
    await ALL_SOURCES.epss.applyDiff(ctx, r.diffs);
    const after = JSON.parse(fs.readFileSync(cvePath, 'utf8'))['BUG-2099-ALIASED'];
    assert.equal(after.epss_score, 0.1, 'a review-only EPSS diff is not applied');
  });
});

test('nvdDiffFromCache reads an aliased CVE and holds its CVSS diffs on the owning entry', () => {
  return withCache((dir) => {
    writeJson(dir, 'nvd', 'CVE-2099-0002', { vulnerabilities: [{ cve: { id: 'CVE-2099-0002', metrics: {
      cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: VECTOR } }],
    } } }] });
    const r = nvdDiffFromCache({ cacheDir: dir, forceStale: true, cveCatalog: catalogWithAlias() });
    const d = r.diffs.find((x) => x.id === 'BUG-2099-ALIASED' && x.field === 'cvss_score');
    assert.ok(d, 'the aliased CVE\'s CVSS change is a diff on the owning entry');
    assert.equal(d.after, 9.8);
    assert.equal(d.review_only, true);
    assert.equal(d.via_alias, 'CVE-2099-0002');
  });
});

// --- live validation and refresh (validateCve stubbed, no network) -------------

async function withStubbedValidateCve(stub, fn) {
  const cvPath = require.resolve('../sources/validators/cve-validator');
  const idxPath = require.resolve('../sources/validators');
  const cv = require(cvPath);
  const orig = cv.validateCve;
  const savedIdx = require.cache[idxPath];
  cv.validateCve = stub;
  delete require.cache[idxPath]; // the barrel binds validateCve when it loads
  try { return await fn(); } finally {
    cv.validateCve = orig;
    delete require.cache[idxPath];
    if (savedIdx) require.cache[idxPath] = savedIdx;
  }
}

test('validateAllCves checks an aliased CVE against its entry and reports catalog_key', async () => {
  const catalog = catalogWithAlias();
  await withStubbedValidateCve(async (id, local) => ({ cve_id: id, status: 'match', discrepancies: [], fetched: {}, local }), async () => {
    const { validateAllCves } = require('../sources/validators');
    const r = await validateAllCves(catalog);
    assert.equal(r.total, 2);
    const aliased = r.results.find((x) => x.cve_id === 'CVE-2099-0002');
    assert.equal(aliased.catalog_key, 'BUG-2099-ALIASED');
    assert.equal(aliased.local, catalog['BUG-2099-ALIASED'], 'the aliased id is compared with its entry');
    assert.equal(r.results.find((x) => x.cve_id === 'CVE-2099-0001').catalog_key, 'CVE-2099-0001');
  });
});

test('the live NVD and KEV refresh write an aliased CVE\'s diffs to its entry, held for review', async () => {
  const stub = async (id, local) => ({
    cve_id: id, status: 'drift', local, fetched: {},
    discrepancies: id === 'CVE-2099-0002'
      ? [{ field: 'cvss_score', local: 5.0, fetched: 9.8, severity: 'high' }, { field: 'cisa_kev', local: false, fetched: true, severity: 'high' }]
      : [],
  });
  await withStubbedValidateCve(stub, async () => {
    const ctx = { cveCatalog: catalogWithAlias() };
    for (const [src, field] of [['nvd', 'cvss_score'], ['kev', 'cisa_kev']]) {
      const r = await ALL_SOURCES[src].fetchDiff(ctx);
      const d = r.diffs.find((x) => x.field === field);
      assert.ok(d, `${src} reports the ${field} change`);
      assert.equal(d.id, 'BUG-2099-ALIASED', `${src} writes the diff to the owning entry`);
      assert.equal(d.review_only, true);
      assert.equal(d.via_alias, 'CVE-2099-0002');
    }
  });
});

// --- prefetch and KEV discovery ----------------------------------------------

test('prefetch treats an aliased CVE as tracked: fetched for NVD and EPSS, not new to KEV', () => {
  const cveCatalog = catalogWithAlias();
  const kev = { vulnerabilities: [{ cveID: 'CVE-2099-0002' }, { cveID: 'CVE-2099-0003' }] };
  assert.deepEqual(newKevIds(kev, cveCatalog), ['CVE-2099-0003']);
  for (const src of ['nvd', 'epss']) {
    const ids = SOURCES[src].expand({ cveCatalog, kevFeed: kev }).map((j) => j.id).sort();
    assert.deepEqual(ids, ['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0003'], `${src} fetches own, aliased and new-KEV ids`);
  }
});

test('discoverNewKev does not draft a KEV CVE that an entry lists in aliases[]', () => {
  return withCache((dir) => {
    writeJson(dir, 'kev', 'known_exploited_vulnerabilities', { vulnerabilities: [
      { cveID: 'CVE-2099-0002', dateAdded: '2026-09-01', vulnerabilityName: 'Aliased' },
      { cveID: 'CVE-2099-0003', dateAdded: '2026-09-02', vulnerabilityName: 'New' },
    ] });
    const r = discoverNewKev({ cacheDir: dir, cveCatalog: catalogWithAlias() });
    assert.deepEqual(r.diffs.map((d) => d.id), ['CVE-2099-0003']);
  });
});

// --- advisory seeding and draft adds ------------------------------------------

test('aliasOwner names the entry that lists a CVE in aliases[], and null otherwise', () => {
  const { aliasOwner } = require('../lib/catalog-ids');
  const cat = catalogWithAlias();
  assert.equal(aliasOwner(cat, 'CVE-2099-0002'), 'BUG-2099-ALIASED');
  assert.equal(aliasOwner(cat, 'CVE-2099-0001'), null, 'an own key is not an alias');
  assert.equal(aliasOwner(cat, 'CVE-2099-0404'), null);
});

test('refresh --advisory refuses to add an entry for a CVE an entry lists as an alias', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  return withCache((dir) => {
    const tmpCatalog = path.join(dir, 'cve-catalog.json');
    // The GHSA fixture answers for CVE-9999-99999, so an entry lists that id as an alias.
    const cat = { ...catalogWithAlias(), 'BUG-2099-ALIASED': { ...catalogWithAlias()['BUG-2099-ALIASED'], aliases: ['CVE-9999-99999'] } };
    fs.writeFileSync(tmpCatalog, JSON.stringify(cat, null, 2) + '\n');
    const before = fs.readFileSync(tmpCatalog, 'utf8');
    for (const extra of [[], ['--apply']]) {
      const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', ...extra, '--catalog', tmpCatalog, '--json'], {
        encoding: 'utf8', env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1' },
      });
      assert.equal(r.status, 4, `--advisory ${extra.join(' ') || '(dry run)'} exits 4 for an aliased CVE: ${r.stdout}${r.stderr}`);
      const body = JSON.parse(r.stdout);
      assert.equal(body.ok, false);
      assert.equal(body.alias_of, 'BUG-2099-ALIASED');
    }
    assert.equal(fs.readFileSync(tmpCatalog, 'utf8'), before, 'the catalog is unchanged');
  });
});

test('the KEV, GHSA and OSV sources do not add an entry for an aliased CVE', async () => {
  for (const src of ['kev', 'ghsa', 'osv']) {
    await withCache(async (dir) => {
      const cvePath = path.join(dir, 'cve-catalog.json');
      fs.writeFileSync(cvePath, JSON.stringify(catalogWithAlias(), null, 2) + '\n');
      const ctx = { cveCatalog: catalogWithAlias(), cvePath };
      const entry = { name: 'draft', _auto_imported: true };
      const diffs = src === 'kev'
        ? [{ op: 'add', id: 'CVE-2099-0002', entry }, { op: 'add', id: 'CVE-2099-0003', entry }]
        : [{ id: 'CVE-2099-0002', field: '_new_entry', after: entry }, { id: 'CVE-2099-0003', field: '_new_entry', after: entry }];
      await ALL_SOURCES[src].applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(cvePath, 'utf8'));
      assert.equal(after['CVE-2099-0002'], undefined, `${src} adds no entry for the aliased CVE`);
      assert.ok(after['CVE-2099-0003'], `${src} still adds an entry for an untracked CVE`);
    });
  }
});

// --- validate-cves --------------------------------------------------------------

test('validate-cves --offline lists an aliased CVE with * and names its entry', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'exceptd.js'), 'validate-cves', '--offline'], {
    encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^CVE-2026-45585\* +\| 30 /m);
  assert.match(r.stdout, /CVE-2026-45585 -> BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY/);
});
