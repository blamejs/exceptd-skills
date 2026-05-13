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
  // GHSA-* is intentionally NOT OSV-native — routed through source-ghsa for
  // richer field coverage (cvss object, vulnerable_version_range, ghsa_id).
  // Verified in v0.12.11 audit: removing GHSA- from OSV_ID_PREFIXES caught
  // the misleading export.
  assert.equal(osv.isOsvId('GHSA-tnsk-tnsk-tnsk'), false);
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

// ============================================================
// v0.12.11 hardening — F1 through F8 + error-path coverage
// ============================================================

// -- F1: structured error envelope for fixture I/O ---------------------

test('v0.12.11 F1 fetchAdvisoryById returns structured error for missing fixture file', async () => {
  const missing = path.join(os.tmpdir(), `exceptd-osv-missing-${process.pid}-${Date.now()}.json`);
  process.env.EXCEPTD_OSV_FIXTURE = missing;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, false, 'must not throw; must return structured error');
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.11 F1 fetchAdvisoryById returns structured error for malformed JSON fixture', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-osv-bad-'));
  const fp = path.join(tmp, 'bad.json');
  fs.writeFileSync(fp, '{ not valid json, ;');
  process.env.EXCEPTD_OSV_FIXTURE = fp;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('v0.12.11 F1 fetchAdvisoryById returns structured error when fixture root is neither object nor array', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-osv-scalar-'));
  const fp = path.join(tmp, 'scalar.json');
  fs.writeFileSync(fp, '42');
  process.env.EXCEPTD_OSV_FIXTURE = fp;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// -- F2: uppercase id before network call ------------------------------

test('v0.12.11 F2 fetchAdvisoryById uppercases lowercase id (fixture path)', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    // OSV.dev's /v1/vulns/{id} is case-sensitive — lowercase 404s. The
    // module normalizes case at entry so the network path is also
    // case-corrected. Here we exercise the fixture path which case-folds
    // independently; the production behavior is identical (upper-case
    // before request).
    const r = await osv.fetchAdvisoryById('mal-2026-3083');
    assert.equal(r.ok, true, `lowercase id must resolve, got: ${JSON.stringify(r)}`);
    assert.equal(r.advisories[0].id, 'MAL-2026-3083');
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

// -- F3: extractCvss highest-version-wins + compute-from-vector ---------

test('v0.12.11 F3 extractCvss computes score from CVSS 3.1 vector (no embedded tail)', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  // MAL-2026-3083 carries the bare vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  // with no trailing numeric score. cvss3BaseScore must compute it.
  const { score, vector } = osv.extractCvss(fixture[0]);
  assert.equal(typeof score, 'number', 'score must be computed from vector');
  // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (canonical CVSS calculator).
  assert.ok(score >= 9.7 && score <= 9.9, `expected ~9.8, got ${score}`);
  assert.match(vector, /^CVSS:3\.1/);
});

test('v0.12.11 F3 extractCvss picks highest-version vector regardless of array order', () => {
  // V4 appears first; V3 second. V4 must win even though it's listed first.
  const rec = {
    id: 'TEST-FAKE',
    severity: [
      { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' },
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    ],
  };
  const { vector } = osv.extractCvss(rec);
  assert.match(vector, /^CVSS:4\.0/, `expected v4 vector to win, got: ${vector}`);
});

test('v0.12.11 F3 cvss3BaseScore returns null for malformed vectors', () => {
  assert.equal(osv.cvss3BaseScore('not a vector'), null);
  assert.equal(osv.cvss3BaseScore('CVSS:3.1/AV:N'), null); // incomplete
  assert.equal(osv.cvss3BaseScore(null), null);
});

// -- F4: CVE → OSV fallback when GHSA 404s -----------------------------

test('v0.12.11 F4 --advisory CVE-* falls back to OSV when GHSA 404s', async () => {
  const cveId = 'CVE-9999-99997';
  const osvRecord = {
    id: 'GO-2026-1',
    aliases: [cveId],
    summary: 'synthetic OSV-only record used by F4 fallback test',
    modified: '2026-05-13T00:00:00Z',
    published: '2026-05-12T00:00:00Z',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }],
    affected: [{ package: { ecosystem: 'Go', name: 'synthetic/pkg' }, versions: ['1.0.0'] }],
    references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/GO-2026-1' }],
  };
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  const { seedSingleAdvisory } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const origGhsa = ghsa.fetchAdvisoryById;
  const origOsv = osv.fetchAdvisoryById;
  let osvCalledWith = null;
  ghsa.fetchAdvisoryById = async () => ({ ok: false, error: 'GHSA returned HTTP 404', source: 'offline' });
  osv.fetchAdvisoryById = async (id) => {
    osvCalledWith = id;
    return { ok: true, advisories: [osvRecord], source: 'osv-api' };
  };
  // Capture stdout so the dry-run JSON doesn't pollute test output.
  const origWrite = process.stdout.write;
  let captured = '';
  process.stdout.write = (chunk) => { captured += chunk.toString(); return true; };
  const origExitCode = process.exitCode;
  try {
    await seedSingleAdvisory({ advisory: cveId, json: true, apply: false });
    process.stdout.write = origWrite;
    assert.equal(osvCalledWith, cveId, 'OSV fallback must be invoked with the same CVE id');
    const data = JSON.parse(captured.trim());
    assert.equal(data.ok, true, `expected ok=true draft from OSV fallback, got: ${captured}`);
    assert.equal(data.cve_id, cveId);
    // The OSV record carries CVE-9999-99997 in aliases, so the normalized
    // catalog key is the CVE id.
    assert.equal(data.draft._source_osv_id, 'GO-2026-1');
  } finally {
    process.stdout.write = origWrite;
    ghsa.fetchAdvisoryById = origGhsa;
    osv.fetchAdvisoryById = origOsv;
    process.exitCode = origExitCode;
  }
});

test('v0.12.11 F4 --advisory CVE-* surfaces combined error when both GHSA and OSV 404', async () => {
  const cveId = 'CVE-9999-99996';
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  const { seedSingleAdvisory } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const origGhsa = ghsa.fetchAdvisoryById;
  const origOsv = osv.fetchAdvisoryById;
  ghsa.fetchAdvisoryById = async () => ({ ok: false, error: 'GHSA returned HTTP 404', source: 'offline' });
  osv.fetchAdvisoryById = async () => ({ ok: false, error: 'OSV returned HTTP 404', source: 'offline' });
  const origWrite = process.stdout.write;
  let captured = '';
  process.stdout.write = (chunk) => { captured += chunk.toString(); return true; };
  const origExitCode = process.exitCode;
  try {
    await seedSingleAdvisory({ advisory: cveId, json: true, apply: false });
    process.stdout.write = origWrite;
    const data = JSON.parse(captured.trim());
    assert.equal(data.ok, false);
    assert.match(data.error, /not found in GHSA or OSV/);
    assert.match(data.error, /GHSA:/);
    assert.match(data.error, /OSV:/);
    assert.equal(data.routed_to, 'ghsa+osv');
  } finally {
    process.stdout.write = origWrite;
    ghsa.fetchAdvisoryById = origGhsa;
    osv.fetchAdvisoryById = origOsv;
    process.exitCode = origExitCode;
  }
});

// -- F5: epss_note on non-CVE drafts -----------------------------------

test('v0.12.11 F5 normalizeAdvisory sets epss_note on non-CVE drafts', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  // MAL-2026-3083 has no CVE alias → catalog key is MAL-* → non-CVE path.
  const out = osv.normalizeAdvisory(fixture[0]);
  const entry = out['MAL-2026-3083'];
  assert.equal(typeof entry.epss_note, 'string');
  assert.match(entry.epss_note, /non-CVE/);
  assert.ok(entry.epss_note.length > 50, 'epss_note must explain the gap');
});

test('v0.12.11 F5 normalizeAdvisory leaves epss_note null for CVE-keyed drafts', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  // RUSTSEC-2025-0099 has CVE-9999-99998 alias → catalog key is CVE-* → CVE path.
  const out = osv.normalizeAdvisory(fixture[1]);
  const entry = out['CVE-9999-99998'];
  assert.equal(entry.epss_note, null, 'CVE-keyed drafts get epss_source URL, not epss_note');
  assert.match(entry.epss_source, /first\.org/);
});

// -- F6: verification_sources dedupe -----------------------------------

test('v0.12.11 F6 normalizeAdvisory dedupes verification_sources', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  // MAL-2026-3083 fixture's references[0] is the canonical osv.dev URL —
  // would otherwise duplicate the prepended `osvUrl`.
  const out = osv.normalizeAdvisory(fixture[0]);
  const entry = out['MAL-2026-3083'];
  const osvUrl = 'https://osv.dev/vulnerability/MAL-2026-3083';
  const occurrences = entry.verification_sources.filter((u) => u === osvUrl).length;
  assert.equal(occurrences, 1, `osv.dev URL must appear exactly once, got ${occurrences}: ${JSON.stringify(entry.verification_sources)}`);
});

// -- F7: buildDiff error categorization --------------------------------

test('v0.12.11 F7 buildDiff distinguishes unreachable vs normalize-rejected', async () => {
  // Build an in-memory fixture: one valid MAL-* (counts as new diff), one
  // record with the requested id missing entirely (unreachable from
  // fixture's perspective: "not in fixture"), and one record with an empty
  // id (normalize-rejected: normalizeAdvisory returns null).
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-osv-cat-'));
  const fp = path.join(tmp, 'mixed.json');
  fs.writeFileSync(fp, JSON.stringify([
    JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'))[0], // MAL-2026-3083 — valid
    { id: '', summary: 'unusable: missing id' },     // present but normalize returns null
  ]));
  process.env.EXCEPTD_OSV_FIXTURE = fp;
  try {
    const ctx = {
      cveCatalog: {},
      osv_ids: [
        'MAL-2026-3083',     // valid → diff
        'NOT-IN-FIXTURE-XYZ', // unreachable
      ],
    };
    const r = await osv.buildDiff(ctx);
    assert.equal(r.diffs.length, 1, `expected 1 diff, got ${r.diffs.length}`);
    assert.equal(typeof r.unreachable_count, 'number');
    assert.equal(typeof r.normalize_error_count, 'number');
    assert.equal(r.unreachable_count, 1, `expected 1 unreachable, got ${r.unreachable_count}`);
    // 0 normalize errors here — the empty-id record wasn't requested in osv_ids.
    assert.equal(r.normalize_error_count, 0);
    assert.equal(r.errors, r.unreachable_count + r.normalize_error_count);
    assert.match(r.summary, /unreachable/);
    assert.match(r.summary, /normalize-rejected/);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// -- F8: OSV_ID_PREFIXES no longer contains GHSA- ----------------------

test('v0.12.11 F8 OSV_ID_PREFIXES does NOT include GHSA-', () => {
  assert.equal(osv.OSV_ID_PREFIXES.includes('GHSA-'), false,
    'GHSA- removed from OSV_ID_PREFIXES — dispatcher routes GHSA-* through source-ghsa for richer field coverage');
});

// -- Network error-path coverage (OSV_HOST_OVERRIDE) -------------------

const http = require('http');

function startStubServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, port });
    });
  });
}

test('v0.12.11 fetchAdvisoryById against 500 returns structured error', async () => {
  const { server, port } = await startStubServer((req, res) => {
    res.writeHead(500, { 'content-type': 'text/plain' });
    res.end('internal error');
  });
  process.env.OSV_HOST_OVERRIDE = `127.0.0.1:${port}`;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /HTTP 500/);
  } finally {
    delete process.env.OSV_HOST_OVERRIDE;
    await new Promise((res) => server.close(res));
  }
});

test('v0.12.11 fetchAdvisoryById against 429 returns rate-limit-flagged error', async () => {
  const { server, port } = await startStubServer((req, res) => {
    res.writeHead(429, { 'content-type': 'text/plain' });
    res.end('rate limit');
  });
  process.env.OSV_HOST_OVERRIDE = `127.0.0.1:${port}`;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, false);
    assert.match(r.error, /rate-limited|429/i);
  } finally {
    delete process.env.OSV_HOST_OVERRIDE;
    await new Promise((res) => server.close(res));
  }
});

test('v0.12.11 fetchAdvisoryById timeout returns structured error', async () => {
  // Server that accepts the connection but never responds — forces the
  // client-side timeout to fire.
  const { server, port } = await startStubServer(() => { /* never respond */ });
  process.env.OSV_HOST_OVERRIDE = `127.0.0.1:${port}`;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083', { timeoutMs: 250 });
    assert.equal(r.ok, false);
    assert.match(r.error, /timed out|timeout/i);
  } finally {
    delete process.env.OSV_HOST_OVERRIDE;
    await new Promise((res) => server.close(res));
  }
});

// -- printHelp content regression (v0.12.11) ---------------------------

test('v0.12.11 refresh-external --help mentions OSV fallback for CVE-* ids', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--help'], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /OSV\.dev/);
  assert.match(r.stdout, /falls back|fall back|fallback/i);
});
