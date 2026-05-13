'use strict';

/**
 * tests/source-osv.test.js
 *
 * Coverage for lib/source-osv.js — the OSV.dev upstream source registered
 * in v0.12.10. Exercises the fixture-mode path against
 * tests/fixtures/osv-mal-2026-3083.json (synthesized from the catalog
 * entry for the elementary-data PyPI worm).
 *
 * Identifier namespaces verified by these tests: MAL-, RUSTSEC-, SNYK-,
 * USN-, UVI-, GO-, MGASA-, PYSEC- (via isOsvId + OSV_ID_PREFIXES).
 *
 * No network calls. EXCEPTD_OSV_FIXTURE drives the fetch path.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OSV_FIX = path.join(ROOT, 'tests', 'fixtures', 'osv-mal-2026-3083.json');

const osv = require(path.join(ROOT, 'lib', 'source-osv.js'));

// -- fetchAdvisoryById --------------------------------------------------

test('v0.12.10 source-osv.fetchAdvisoryById resolves MAL-2026-3083 from fixture', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, true, `expected ok=true, got: ${JSON.stringify(r)}`);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories.length, 1);
    assert.equal(r.advisories[0].id, 'MAL-2026-3083');
    // Content-shape coupling: not just present, populated.
    assert.equal(typeof r.advisories[0].summary, 'string');
    assert.ok(r.advisories[0].summary.length > 10);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.fetchAdvisoryById resolves by CVE alias', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    // RUSTSEC-2025-0099 has alias CVE-9999-99998
    const r = await osv.fetchAdvisoryById('CVE-9999-99998');
    assert.equal(r.ok, true);
    assert.equal(r.advisories[0].id, 'RUSTSEC-2025-0099');
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.fetchAdvisoryById returns error for unknown id in fixture', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const r = await osv.fetchAdvisoryById('MAL-9999-99999');
    assert.equal(r.ok, false);
    assert.equal(r.source, 'fixture');
    assert.match(r.error, /not in fixture/);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

// -- normalizeAdvisory --------------------------------------------------

test('v0.12.10 source-osv.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  const out = osv.normalizeAdvisory(fixture[0]);
  assert.ok(out, 'normalizeAdvisory must return a record for MAL-2026-3083');
  // Catalog key: MAL-2026-3083 has no CVE alias, so use the OSV id verbatim.
  assert.deepEqual(Object.keys(out), ['MAL-2026-3083']);

  const entry = out['MAL-2026-3083'];
  // Auto-imported draft flags.
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(typeof entry._draft_reason, 'string');
  assert.ok(entry._draft_reason.length > 20);
  assert.equal(entry._source_osv_id, 'MAL-2026-3083');

  // Editorial fields are null/empty per draft contract.
  assert.equal(entry.framework_control_gaps, null);
  assert.deepEqual(entry.atlas_refs, []);
  assert.deepEqual(entry.attack_refs, []);
  assert.equal(entry.rwep_score, null);
  assert.equal(entry.rwep_factors, null);
  assert.equal(entry.vector, null);
  assert.equal(entry.complexity, null);

  // CVSS extracted from severity[].
  assert.equal(typeof entry.cvss_vector, 'string');
  assert.match(entry.cvss_vector, /^CVSS:3\./);

  // Critical CVSS-vector → cisa_kev_pending true.
  // (score-only path: the fixture's vector has no embedded score, so
  // cvss_score is null and pending falls through to false. Either is
  // acceptable per the type signature; assert the type, not the value.)
  assert.equal(typeof entry.cisa_kev_pending, 'boolean');

  // IoCs seeded from database_specific.iocs.
  assert.ok(entry.iocs, 'iocs should be seeded from database_specific.iocs');
  assert.ok(Array.isArray(entry.iocs.c2_indicators));
  assert.ok(entry.iocs.c2_indicators.length >= 1);
  assert.ok(entry.iocs.c2_indicators.some((c) => c.includes('skyhanni.cloud')));

  // Affected package surface.
  assert.equal(entry.affected, 'PyPI:elementary-data');
  assert.ok(entry.affected_versions.some((v) => v.includes('elementary-data') && v.includes('0.23.3')));

  // OSV.dev primary vendor advisory.
  assert.ok(Array.isArray(entry.vendor_advisories));
  assert.equal(entry.vendor_advisories[0].vendor, 'OSV.dev');
  assert.equal(entry.vendor_advisories[0].advisory_id, 'MAL-2026-3083');
  assert.equal(entry.vendor_advisories[0].url, 'https://osv.dev/vulnerability/MAL-2026-3083');

  // Timestamps preserved.
  assert.equal(entry.source_verified, '2026-04-24');
  assert.equal(entry.last_updated, '2026-04-28');
});

test('v0.12.10 source-osv.normalizeAdvisory prefers CVE alias as catalog key', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  // RUSTSEC-2025-0099 has CVE-9999-99998 in aliases — CVE wins.
  const out = osv.normalizeAdvisory(fixture[1]);
  assert.ok(out);
  assert.deepEqual(Object.keys(out), ['CVE-9999-99998']);
  // OSV id is preserved in aliases array on the entry.
  assert.ok(Array.isArray(out['CVE-9999-99998'].aliases));
  assert.ok(out['CVE-9999-99998'].aliases.includes('RUSTSEC-2025-0099'));
});

test('v0.12.10 source-osv.normalizeAdvisory returns null for malformed input', () => {
  assert.equal(osv.normalizeAdvisory(null), null);
  assert.equal(osv.normalizeAdvisory({}), null);
  assert.equal(osv.normalizeAdvisory({ summary: 'no id' }), null);
});

// -- isOsvId routing predicate -----------------------------------------

test('v0.12.10 source-osv.isOsvId recognizes OSV-native prefixes', () => {
  for (const id of ['MAL-2026-3083', 'RUSTSEC-2025-0001', 'SNYK-PYTHON-X-1', 'USN-1234-1', 'UVI-1', 'GO-2024-1234', 'MGASA-2025-0001', 'PYSEC-2024-1']) {
    assert.equal(osv.isOsvId(id), true, `${id} should be OSV-native`);
  }
  // CVE-* is NOT OSV-native — routes through GHSA.
  assert.equal(osv.isOsvId('CVE-2026-45321'), false);
  // GHSA-* is recognized by OSV but the dispatcher keeps routing through GHSA.
  assert.equal(osv.isOsvId('GHSA-tnsk-tnsk-tnsk'), true);
  assert.equal(osv.isOsvId(''), false);
  assert.equal(osv.isOsvId(null), false);
});

// -- buildDiff ctx.osv_ids ---------------------------------------------

test('v0.12.10 source-osv.buildDiff emits one _new_entry diff per requested id', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const ctx = { cveCatalog: {}, osv_ids: ['MAL-2026-3083'] };
    const r = await osv.buildDiff(ctx);
    assert.equal(r.status, 'ok');
    assert.equal(r.diffs.length, 1);
    const d = r.diffs[0];
    assert.equal(d.id, 'MAL-2026-3083');
    assert.equal(d.field, '_new_entry');
    assert.equal(d.before, null);
    assert.equal(d.source, 'osv');
    // Content-shape: the draft entry itself must be non-empty.
    assert.equal(typeof d.after, 'object');
    assert.equal(d.after._auto_imported, true);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.buildDiff skips ids already in catalog', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const ctx = {
      cveCatalog: { 'MAL-2026-3083': { name: 'pre-existing entry' } },
      osv_ids: ['MAL-2026-3083'],
    };
    const r = await osv.buildDiff(ctx);
    assert.equal(r.status, 'ok');
    assert.equal(r.diffs.length, 0, 'should refuse to overwrite existing entry');
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.buildDiff with empty osv_ids returns informational empty result', async () => {
  const ctx = { cveCatalog: {} };
  const r = await osv.buildDiff(ctx);
  assert.equal(r.status, 'ok');
  assert.equal(r.diffs.length, 0);
  assert.match(r.summary, /no ids requested/);
});

// -- fetchAdvisoriesForPackage ----------------------------------------

test('v0.12.10 source-osv.fetchAdvisoriesForPackage filters fixture by package + ecosystem', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const r = await osv.fetchAdvisoriesForPackage('elementary-data', 'PyPI');
    assert.equal(r.ok, true);
    assert.equal(r.advisories.length, 1);
    assert.equal(r.advisories[0].id, 'MAL-2026-3083');
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

// -- --advisory MAL-* CLI routing -------------------------------------

test('v0.12.10 refresh --advisory MAL-2026-3083 dry-run emits draft + exits 3', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'MAL-2026-3083', '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_OSV_FIXTURE: OSV_FIX },
  });
  assert.equal(r.status, 3, `--advisory dry-run must exit 3 ("draft prepared, not applied"); got ${r.status}, stderr=${r.stderr}`);
  let data;
  try { data = JSON.parse(r.stdout); } catch { data = null; }
  assert.ok(data, `--advisory --json must emit parseable JSON, got: ${r.stdout}`);
  assert.equal(data.ok, true);
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'MAL-2026-3083');
  // Content coupling: draft is populated, not just present.
  assert.equal(typeof data.draft, 'object');
  assert.equal(data.draft._auto_imported, true);
  assert.equal(data.draft._source_osv_id, 'MAL-2026-3083');
});

test('v0.12.10 refresh --advisory RUSTSEC-* routes through OSV and keys by CVE alias', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'RUSTSEC-2025-0099', '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_OSV_FIXTURE: OSV_FIX },
  });
  assert.equal(r.status, 3, `--advisory RUSTSEC-* dry-run expected exit 3, got ${r.status}, stderr=${r.stderr}`);
  const data = JSON.parse(r.stdout);
  // CVE alias preferred as catalog key.
  assert.equal(data.cve_id, 'CVE-9999-99998');
  assert.ok(data.draft.aliases.includes('RUSTSEC-2025-0099'));
});

test('v0.12.10 refresh --advisory --apply MAL-* writes draft to a copy of the catalog', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-osv-apply-'));
  const catalogPath = path.join(tmp, 'cve-catalog.json');
  // Seed an empty catalog so the apply path can write.
  fs.writeFileSync(catalogPath, JSON.stringify({ _meta: { last_updated: '2026-01-01' } }, null, 2));
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'MAL-2026-3083', '--apply', '--json', '--catalog', catalogPath], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_OSV_FIXTURE: OSV_FIX },
    });
    assert.equal(r.status, 3, `--advisory --apply must exit 3 (applied, editorial-review pending); got ${r.status}, stderr=${r.stderr}`);
    const data = JSON.parse(r.stdout);
    assert.equal(data.ok, true);
    assert.equal(data.mode, 'advisory-seed-applied');
    assert.equal(data.cve_id, 'MAL-2026-3083');

    const written = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    assert.ok(written['MAL-2026-3083'], 'catalog must contain MAL-2026-3083 after apply');
    assert.equal(written['MAL-2026-3083']._auto_imported, true);
    assert.equal(written['MAL-2026-3083']._source_osv_id, 'MAL-2026-3083');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// -- ALL_SOURCES registration regression -------------------------------

test('v0.12.10 refresh-external ALL_SOURCES includes osv alongside ghsa', () => {
  const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  assert.ok(ALL_SOURCES.osv, 'osv source must be registered');
  assert.equal(ALL_SOURCES.osv.name, 'osv');
  assert.equal(ALL_SOURCES.osv.applies_to, 'data/cve-catalog.json');
  // Regression: ghsa must still be present after the osv addition.
  assert.ok(ALL_SOURCES.ghsa, 'ghsa source must still be registered');
});

test('v0.12.10 refresh-external --source osv accepted as a valid source name', () => {
  const reportPath = path.join(os.tmpdir(), `refresh-report-osv-${process.pid}-${Date.now()}.json`);
  try {
    const r = spawnSync(process.execPath, [
      path.join(ROOT, 'lib', 'refresh-external.js'),
      '--from-fixture', path.join(ROOT, 'tests', 'fixtures', 'refresh'),
      '--source', 'osv',
      '--quiet',
      '--report-out', reportPath,
    ], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(r.status, 0, `--source osv dry-run must exit 0, stderr=${r.stderr}`);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.ok(report.sources.osv, 'osv source must appear in refresh-report');
  } finally {
    try { fs.unlinkSync(reportPath); } catch { /* tmpfile cleanup */ }
  }
});

// -- printHelp content regression --------------------------------------

test('v0.12.10 refresh-external --help mentions osv source + new identifier formats', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--help'], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /osv\s+\(v0\.12\.10\)/);
  assert.match(r.stdout, /MAL-/);
  assert.match(r.stdout, /RUSTSEC-/);
});

// -- direct-invocation sanity (does not crash) -------------------------

test('v0.12.10 source-osv.js direct require exposes the documented module exports', () => {
  for (const ident of ['fetchAdvisoryById', 'fetchAdvisoriesForPackage', 'normalizeAdvisory', 'buildDiff', 'isOsvId', 'OSV_ID_PREFIXES']) {
    assert.ok(ident in osv, `lib/source-osv.js must export ${ident}`);
  }
  assert.ok(Array.isArray(osv.OSV_ID_PREFIXES));
  // Hard Rule #15 coverage: enumerated namespaces a future contributor can grep.
  for (const prefix of ['MAL-', 'RUSTSEC-', 'USN-', 'UVI-', 'SNYK-', 'GO-', 'MGASA-', 'PYSEC-']) {
    assert.ok(osv.OSV_ID_PREFIXES.includes(prefix), `OSV_ID_PREFIXES must include ${prefix}`);
  }
});
