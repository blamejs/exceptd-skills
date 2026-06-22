'use strict';

/**
 * tests/mal-2026-3083.test.js
 *
 * Per-subject coverage for MAL-2026-3083 (elementary-data PyPI worm, OSV-native
 * key). This id is the canonical OSV-source fixture exemplar
 * (tests/fixtures/osv-mal-2026-3083.json) and also a curated catalog entry.
 * Covers: the catalog-entry shape + aliases, OSV source resolution /
 * normalization / diff / id-routing, the CSAF ids[] system_name routing, the
 * OpenVEX URN namespace, the curate OSV provenance label, and the
 * regression-watcher year classifier.
 *
 * Runs under: node --test --test-concurrency=1
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const OSV_FIX = path.join(ROOT, 'tests', 'fixtures', 'osv-mal-2026-3083.json');
const osv = require(path.join(ROOT, 'lib', 'source-osv.js'));
const runner = require(path.resolve(ROOT, 'lib', 'playbook-runner.js'));
const CATALOG = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/cve-catalog.json'), 'utf8'));

const ID = 'MAL-2026-3083';

// ---------------------------------------------------------------------------
// catalog entry shape + aliases (cve-additions-v0-12-10)
// ---------------------------------------------------------------------------

test('cve-catalog v0.12.10 entry: MAL-2026-3083 present + iocs populated', () => {
  const entry = CATALOG[ID];
  assert.ok(entry, `${ID} must exist in data/cve-catalog.json`);
  assert.ok(entry.iocs && typeof entry.iocs === 'object',
    `${ID} must carry a populated iocs block (Hard Rule #14)`);
  assert.ok(Object.keys(entry.iocs).length >= 2,
    `${ID} iocs must enumerate at least 2 IoC categories`);
  assert.ok(Array.isArray(entry.aliases) && entry.aliases.length > 0,
    `${ID} (OSV-native key) must carry aliases for cross-reference`);
  assert.ok(Array.isArray(entry.verification_sources) && entry.verification_sources.length > 0,
    `${ID} must cite at least one primary-source verification URL`);
});

test('MAL-2026-3083 aliases include the Snyk advisory id', () => {
  const e = CATALOG[ID];
  assert.ok(e?.aliases?.includes('SNYK-PYTHON-ELEMENTARYDATA-16316110'),
    'MAL-2026-3083 must list SNYK-PYTHON-ELEMENTARYDATA-16316110 as an alias');
});

// ---------------------------------------------------------------------------
// OSV source resolution + normalization + diff (source-osv)
// ---------------------------------------------------------------------------

test('v0.12.10 source-osv.fetchAdvisoryById resolves MAL-2026-3083 from fixture', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const r = await osv.fetchAdvisoryById('MAL-2026-3083');
    assert.equal(r.ok, true, `expected ok=true, got: ${JSON.stringify(r)}`);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories.length, 1);
    assert.equal(r.advisories[0].id, 'MAL-2026-3083');
    assert.equal(typeof r.advisories[0].summary, 'string');
    assert.ok(r.advisories[0].summary.length > 10);
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.11 source-osv.fetchAdvisoryById uppercases a lowercase mal-2026-3083', async () => {
  process.env.EXCEPTD_OSV_FIXTURE = OSV_FIX;
  try {
    const r = await osv.fetchAdvisoryById('mal-2026-3083');
    assert.equal(r.ok, true, `lowercase id must resolve, got: ${JSON.stringify(r)}`);
    assert.equal(r.advisories[0].id, 'MAL-2026-3083');
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  const out = osv.normalizeAdvisory(fixture[0]);
  assert.ok(out, 'normalizeAdvisory must return a record for MAL-2026-3083');
  assert.deepEqual(Object.keys(out), ['MAL-2026-3083']);

  const entry = out['MAL-2026-3083'];
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(typeof entry._draft_reason, 'string');
  assert.ok(entry._draft_reason.length > 20);
  assert.equal(entry._source_osv_id, 'MAL-2026-3083');
  assert.equal(entry.framework_control_gaps, null);
  assert.deepEqual(entry.atlas_refs, []);

  assert.ok(Array.isArray(entry.vendor_advisories));
  assert.equal(entry.vendor_advisories[0].vendor, 'OSV.dev');
  assert.equal(entry.vendor_advisories[0].advisory_id, 'MAL-2026-3083');
  assert.equal(entry.vendor_advisories[0].url, 'https://osv.dev/vulnerability/MAL-2026-3083');
});

test('v0.12.11 F5 normalizeAdvisory sets epss_note on the non-CVE MAL-2026-3083 draft', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  const out = osv.normalizeAdvisory(fixture[0]);
  const entry = out['MAL-2026-3083'];
  assert.equal(typeof entry.epss_note, 'string');
  assert.match(entry.epss_note, /non-CVE/);
  assert.ok(entry.epss_note.length > 50, 'epss_note must explain the gap');
});

test('v0.12.11 F6 normalizeAdvisory dedupes verification_sources for MAL-2026-3083', () => {
  const fixture = JSON.parse(fs.readFileSync(OSV_FIX, 'utf8'));
  const out = osv.normalizeAdvisory(fixture[0]);
  const entry = out['MAL-2026-3083'];
  const osvUrl = 'https://osv.dev/vulnerability/MAL-2026-3083';
  const occurrences = entry.verification_sources.filter((u) => u === osvUrl).length;
  assert.equal(occurrences, 1, `osv.dev URL must appear exactly once, got ${occurrences}`);
});

test('v0.12.10 source-osv.isOsvId recognizes MAL-2026-3083 as OSV-native', () => {
  assert.equal(osv.isOsvId('MAL-2026-3083'), true, 'MAL-2026-3083 should be OSV-native');
});

test('v0.12.10 source-osv.buildDiff emits one _new_entry diff for MAL-2026-3083', async () => {
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
  } finally {
    delete process.env.EXCEPTD_OSV_FIXTURE;
  }
});

test('v0.12.10 source-osv.buildDiff skips MAL-2026-3083 when already in catalog', async () => {
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

test('v0.12.10 refresh --advisory MAL-2026-3083 dry-run emits draft + exits 3', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'MAL-2026-3083', '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_OSV_FIXTURE: OSV_FIX },
  });
  let data;
  try { data = JSON.parse(r.stdout); } catch { data = null; }
  assert.ok(data, `--advisory --json must emit parseable JSON, got: ${r.stdout}`);
  assert.equal(data.ok, true);
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'MAL-2026-3083');
  assert.equal(typeof data.draft, 'object');
  assert.equal(data.draft._auto_imported, true);
  assert.equal(data.draft._source_osv_id, 'MAL-2026-3083');
});

// ---------------------------------------------------------------------------
// CSAF ids[] routing (csaf-bundle-correctness)
// ---------------------------------------------------------------------------

describe('CSAF — MAL-2026-3083 emits via ids[] with system_name Malicious-Package', () => {
  const RUNNER_PATH = path.resolve(ROOT, 'lib', 'playbook-runner.js');
  const REAL_PLAYBOOK_DIR = path.resolve(ROOT, 'data', 'playbooks');
  function loadRunner() {
    delete require.cache[RUNNER_PATH];
    process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
    return require(RUNNER_PATH);
  }
  function closeWithSyntheticMatchedId(matchedId) {
    const r = loadRunner();
    const det = r.detect('kernel', 'all-catalogued-kernel-cves', { signal_overrides: { 'kver-in-affected-range': 'hit' } });
    const an = r.analyze('kernel', 'all-catalogued-kernel-cves', det, { patch_available: false, blast_radius_score: 3 });
    an.matched_cves = [{
      cve_id: matchedId, rwep: 80, cvss_score: 9.3,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cisa_kev: false, active_exploitation: 'confirmed',
      ai_discovered: false, live_patch_available: false,
      patch_available: true, vex_status: null, correlated_via: ['synthetic'],
    }];
    const v = r.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = r.close('kernel', 'all-catalogued-kernel-cves', an, v, { _bundle_formats: ['csaf-2.0'] }, { session_id: 'auditccsynthetictest' });
    return c.evidence_package.bundles_by_format['csaf-2.0'];
  }

  it('MAL-2026-3083 emits via ids[] with system_name: Malicious-Package', () => {
    const csaf = closeWithSyntheticMatchedId('MAL-2026-3083');
    const malVuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(idEntry => idEntry.text === 'MAL-2026-3083')
    );
    assert.ok(malVuln, 'MAL- id must appear under ids[]');
    assert.equal(malVuln.cve, undefined, 'MAL- id must NOT be placed under `cve`');
    const entry = malVuln.ids.find(e => e.text === 'MAL-2026-3083');
    assert.equal(entry.system_name, 'Malicious-Package');
    assert.equal(entry.text, 'MAL-2026-3083');
  });
});

// ---------------------------------------------------------------------------
// OpenVEX URN routing (openvex-urn-routing)
// ---------------------------------------------------------------------------

test('vulnIdToUrn routes MAL-2026-3083 to the urn:malicious-package: namespace', () => {
  const vulnIdToUrn = runner._vulnIdToUrn;
  assert.equal(typeof vulnIdToUrn, 'function', 'runner must export _vulnIdToUrn');
  const urn = vulnIdToUrn('MAL-2026-3083');
  assert.equal(typeof urn, 'string');
  assert.ok(urn.startsWith('urn:malicious-package:'),
    `vulnIdToUrn(MAL-2026-3083) must start with urn:malicious-package:; got ${urn}`);
  assert.ok(!urn.startsWith('urn:cve:'),
    `non-CVE id MAL-2026-3083 must NEVER route into urn:cve:; got ${urn}`);
});

// ---------------------------------------------------------------------------
// curate OSV provenance label (cve-curation)
// ---------------------------------------------------------------------------

test('autoImportedFrom labels an OSV-imported MAL-2026-3083 draft as "OSV: MAL-2026-3083"', () => {
  const { autoImportedFrom } = require(path.join(ROOT, 'lib', 'cve-curation.js'));
  assert.equal(autoImportedFrom({ _source_osv_id: 'MAL-2026-3083' }), 'OSV: MAL-2026-3083');
});

// ---------------------------------------------------------------------------
// regression-watcher year classifier (cve-regression-watcher)
// ---------------------------------------------------------------------------

test('cveYear returns null for the non-CVE shape MAL-2026-3083', () => {
  const WATCHER = require(path.join(ROOT, 'lib', 'cve-regression-watcher.js'));
  assert.equal(WATCHER.cveYear('MAL-2026-3083'), null);
});
