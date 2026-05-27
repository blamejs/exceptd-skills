'use strict';

/**
 * Citation-resolution regression suite.
 *
 * Pins the offline-first "is this CVE/RFC citation valid?" resolver so an agent
 * gets the answer from exceptd (catalog/index -> resolved cache -> opt-in single
 * network lookup) instead of re-researching each citation by hand. Every test is
 * deterministic and offline:
 *
 *   - module-level unit tests point EXCEPTD_CVE_CATALOG / EXCEPTD_RFC_INDEX at
 *     small fixtures written under tests/fixtures/ and EXCEPTD_RESOLVE_CACHE_DIR
 *     at a per-suite tempdir, so neither the network nor the real .cache/ is
 *     touched. The catalog/index paths are read at module-require time, so the
 *     env vars are set BEFORE require below.
 *   - spawned-CLI tests pass those same env overrides through cli({ env }); the
 *     subprocess re-reads them at spawn time.
 *
 * Discipline (project anti-coincidence rules): assert EXACT exit codes (never
 * notEqual(0)); pair every field-presence check with a value/type assertion;
 * never weaken a test to make it pass.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// --- fixtures: small, isolated catalog + index so nothing depends on the
//     shipped data files (which churn with every CVE/RFC intake). ------------
const FIXTURE_DIR = path.join(__dirname, 'fixtures');
const CVE_FIXTURE = path.join(FIXTURE_DIR, 'citation-cve-catalog.json');
const RFC_FIXTURE = path.join(FIXTURE_DIR, 'citation-rfc-index.json');

const CVE_FIXTURE_DATA = {
  'CVE-2030-0001': {
    cvss_score: 9.8,
    cisa_kev: true,
    name: 'FixtureVuln',
    active_exploitation: 'confirmed',
    status: 'published',
  },
};
const RFC_FIXTURE_DATA = {
  'RFC-9404': {
    title: 'JSON Meta Application Protocol (JMAP) Blob Management Extension',
    status: 'Proposed Standard',
  },
  'RFC-9661': {
    title: 'The JSON Meta Application Protocol (JMAP) for Sieve Scripts',
    status: 'Proposed Standard',
  },
};

fs.mkdirSync(FIXTURE_DIR, { recursive: true });
fs.writeFileSync(CVE_FIXTURE, JSON.stringify(CVE_FIXTURE_DATA, null, 2));
fs.writeFileSync(RFC_FIXTURE, JSON.stringify(RFC_FIXTURE_DATA, null, 2));

// Per-suite resolved-cache tempdir, cleaned up on process exit.
const CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-citation-cache-'));

process.on('exit', () => {
  try { fs.rmSync(CACHE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(CVE_FIXTURE, { force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(RFC_FIXTURE, { force: true }); } catch { /* non-fatal */ }
});

// IMPORTANT: the resolver reads EXCEPTD_CVE_CATALOG / EXCEPTD_RFC_INDEX at
// module-require time and memoizes the parsed file. Set them BEFORE require so
// the module binds to the fixtures, not the shipped data files. The cache dir
// is re-read at call time so it's safe to set here too.
process.env.EXCEPTD_CVE_CATALOG = CVE_FIXTURE;
process.env.EXCEPTD_RFC_INDEX = RFC_FIXTURE;
process.env.EXCEPTD_RESOLVE_CACHE_DIR = CACHE_DIR;

const { resolveCve, resolveRfc } = require('../lib/citation-resolve.js');
const { extractNvdStatus } = require('../sources/validators/cve-validator.js');
const ghsa = require('../lib/source-ghsa.js');
const osv = require('../lib/source-osv.js');

// Spawned-CLI harness. Each cli() call passes the fixture catalog/index as env
// overrides so the subprocess resolves against them, not the network.
const SUITE_HOME = makeSuiteHome('exceptd-citation-');
const baseCli = makeCli(SUITE_HOME);
const RESOLVER_ENV = {
  EXCEPTD_CVE_CATALOG: CVE_FIXTURE,
  EXCEPTD_RFC_INDEX: RFC_FIXTURE,
  EXCEPTD_RESOLVE_CACHE_DIR: CACHE_DIR,
};
function cli(args, opts = {}) {
  return baseCli(args, { ...opts, env: { ...RESOLVER_ENV, ...(opts.env || {}) } });
}

// ===================================================================
// 1. extractNvdStatus — surfaces NVD lifecycle + dispute tags
// ===================================================================

test('extractNvdStatus: Rejected vulnStatus + empty cveTags', () => {
  const r = extractNvdStatus({ vulnerabilities: [{ cve: { vulnStatus: 'Rejected', cveTags: [] } }] });
  assert.equal(r.vulnStatus, 'Rejected');
  assert.ok(Array.isArray(r.tags), 'tags must be an array');
  assert.equal(r.tags.length, 0);
});

test('extractNvdStatus: cveTags flatten to include "disputed"', () => {
  const r = extractNvdStatus({ vulnerabilities: [{ cve: { vulnStatus: 'Analyzed', cveTags: [{ tags: ['disputed'] }] } }] });
  assert.equal(r.vulnStatus, 'Analyzed');
  assert.ok(Array.isArray(r.tags), 'tags must be an array');
  assert.ok(r.tags.includes('disputed'), `tags should include "disputed"; got ${JSON.stringify(r.tags)}`);
});

test('extractNvdStatus: empty input -> null status + empty tags', () => {
  const r = extractNvdStatus({});
  assert.equal(r.vulnStatus, null);
  assert.ok(Array.isArray(r.tags), 'tags must be an array');
  assert.equal(r.tags.length, 0);
});

// ===================================================================
// 2. resolveCve — offline catalog / format / air-gap / cache
// ===================================================================

test('resolveCve: catalog hit returns published + catalog provenance', async () => {
  const r = await resolveCve('CVE-2030-0001');
  assert.equal(r.status, 'published');
  assert.equal(r.from, 'catalog');
  assert.equal(typeof r.cvss, 'number');
  assert.equal(r.cvss, 9.8);
  assert.equal(r.kev, true);
  assert.equal(typeof r.product, 'string');
  assert.equal(r.product, 'FixtureVuln');
});

test('resolveCve: non-canonical tail is fabricated, decided on format (no network)', async () => {
  const r = await resolveCve('CVE-2024-XXXX');
  assert.equal(r.status, 'fabricated');
  assert.equal(r.from, 'format');
  assert.equal(typeof r.reason, 'string');
  assert.ok(r.reason.length > 0, 'fabricated result must carry a reason');
});

test('resolveCve: uncatalogued + air-gap -> unknown/offline with NVD-referencing reason', async () => {
  const r = await resolveCve('CVE-2031-1234', { airGap: true });
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
  assert.equal(typeof r.reason, 'string');
  assert.match(r.reason, /air-gap|NVD/i);
});

test('resolveCve: fresh cache file is read back as a cache hit (noNetwork)', async () => {
  const id = 'CVE-2030-9999';
  const cveCacheDir = path.join(CACHE_DIR, 'cve');
  fs.mkdirSync(cveCacheDir, { recursive: true });
  const cacheFile = path.join(cveCacheDir, `${id}.json`);
  // The cache is integrity-checked: a record is only trusted if it carries a
  // matching `_digest` (sha256 over canonical bytes, keys sorted, _digest
  // excluded) AND its resolved_at is fresh. Write a valid digested record.
  const crypto = require('node:crypto');
  const rec = { id, kind: 'cve', status: 'rejected', source: 'nvd', resolved_at: new Date().toISOString() };
  const canon = {};
  for (const k of Object.keys(rec).sort()) canon[k] = rec[k];
  rec._digest = crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
  fs.writeFileSync(cacheFile, JSON.stringify(rec));
  const now = new Date();
  fs.utimesSync(cacheFile, now, now);

  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.status, 'rejected');
  assert.equal(r.from, 'cache');
  assert.equal(r.id, id);
});

// ===================================================================
// 3. resolveRfc — offline index / prefix-normalization / air-gap / format
// ===================================================================
// Uses a small tests/fixtures index (rather than the shipped
// data/rfc-references.json) so the assertions are stable across RFC intake
// churn. The two fixture entries mirror the real series' titles for 9404/9661.

test('resolveRfc: bare number resolves from the local index', async () => {
  const r = await resolveRfc('9404');
  assert.equal(r.found, true);
  assert.equal(r.from, 'index');
  assert.equal(typeof r.title, 'string');
  assert.match(r.title, /Blob Management/);
  assert.equal(typeof r.rfc_status, 'string');
  assert.ok(r.rfc_status.length > 0, 'rfc_status must be present + non-empty');
});

test('resolveRfc: "RFC 9661" (prefix + space) normalizes to the Sieve entry', async () => {
  const r = await resolveRfc('RFC 9661');
  assert.equal(r.found, true);
  assert.equal(r.from, 'index');
  assert.equal(typeof r.title, 'string');
  assert.match(r.title, /Sieve/);
});

test('resolveRfc: uncatalogued number + air-gap -> not found, offline', async () => {
  const r = await resolveRfc('9999', { airGap: true });
  assert.equal(r.found, false);
  assert.equal(r.from, 'offline');
});

test('resolveRfc: garbage input is decided on format', async () => {
  const r = await resolveRfc('not-a-number');
  assert.equal(r.from, 'format');
  assert.equal(r.found, false);
});

// ===================================================================
// 4. cve CLI end-to-end
// ===================================================================

test('cve CLI: catalog hit --json exits 0 with published envelope', () => {
  const r = cli(['cve', 'CVE-2030-0001', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'cve');
  assert.equal(body.status, 'published');
});

test('cve CLI: fabricated id trips the gate (exit 2) + FABRICATED text', () => {
  const r = cli(['cve', 'CVE-2024-XXXX']);
  assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /FABRICATED/);
});

test('cve CLI: --help exits 0 and names the verb', () => {
  const r = cli(['cve', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}`);
  assert.match(r.stdout, /exceptd cve/);
});

test('cve CLI: missing id exits 1 with ok:false envelope on stderr', () => {
  const r = cli(['cve']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'cve');
});

// ===================================================================
// 5. rfc CLI end-to-end
// ===================================================================

test('rfc CLI: --check title mismatch exits 2 with title_match:false', () => {
  const r = cli(['rfc', '9404', '--check', 'Sieve Email Filtering', '--json']);
  assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
  assert.equal(body.title_match, false);
});

test('rfc CLI: bare number exits 0 and prints the resolved title', () => {
  const r = cli(['rfc', '9404']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /Blob Management/);
});

test('rfc CLI: --help exits 0 and names the verb', () => {
  const r = cli(['rfc', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}`);
  assert.match(r.stdout, /exceptd rfc/);
});

// ===================================================================
// 6. OSV / GHSA withdrawn advisory -> status:'withdrawn' (offline, via the
//    normalizers directly — no network, no fixture-file plumbing needed since
//    normalizeAdvisory is pure over the raw advisory record).
// ===================================================================

test('GHSA normalizeAdvisory: withdrawn_at -> status:withdrawn + status_source', () => {
  const out = ghsa.normalizeAdvisory({
    cve_id: 'CVE-2030-7777',
    ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
    summary: 'Withdrawn fixture advisory',
    severity: 'high',
    withdrawn_at: '2026-01-01T00:00:00Z',
    vulnerabilities: [],
  });
  assert.ok(out && typeof out === 'object', 'normalizeAdvisory should return an object');
  const entry = out['CVE-2030-7777'];
  assert.ok(entry, 'normalized entry must be keyed by the cve_id');
  assert.equal(entry.status, 'withdrawn');
  assert.equal(typeof entry.status_source, 'string');
  assert.equal(entry.status_source, 'ghsa:withdrawn_at');
});

test('OSV normalizeAdvisory: withdrawn -> status:withdrawn + status_source', () => {
  const out = osv.normalizeAdvisory({
    id: 'CVE-2030-8888',
    summary: 'Withdrawn OSV fixture record',
    withdrawn: '2026-02-02T00:00:00Z',
    affected: [],
    references: [],
  });
  assert.ok(out && typeof out === 'object', 'normalizeAdvisory should return an object');
  const key = Object.keys(out)[0];
  assert.equal(key, 'CVE-2030-8888');
  const entry = out[key];
  assert.equal(entry.status, 'withdrawn');
  assert.equal(typeof entry.status_source, 'string');
  assert.equal(entry.status_source, 'osv:withdrawn');
});

// --- codex P1: never declare "published" when NVD itself was unreachable ----
// validateCve only returns "unreachable" when EVERY source fails; with NVD down
// but KEV/EPSS up it returns match with sources.nvd.reachable === false. The
// resolver must NOT treat that as published — it would falsely validate an
// unconfirmed (possibly nonexistent) identifier during an NVD outage.
test('resolveCve: NVD unreachable (KEV/EPSS up) -> unknown/offline, never published', async () => {
  const fakeValidate = async () => ({
    cve_id: 'CVE-2099-10001', status: 'match', discrepancies: [],
    fetched: { cvss_score: null, in_kev: false, description: null,
      sources: { nvd: { reachable: false, error: 'timeout' }, kev: { reachable: true }, epss: { reachable: true } } },
  });
  const r = await resolveCve('CVE-2099-10001', { _validateCve: fakeValidate });
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
  assert.match(r.reason, /NVD unreachable/);
});

// --- codex P2: NVD-resolved records carry product (so the product-match check
//     the CLI contract promises is possible from tool output, no manual lookup).
test('resolveCve: NVD-resolved published record includes product (description)', async () => {
  const fakeValidate = async () => ({
    cve_id: 'CVE-2099-10002', status: 'match', discrepancies: [],
    fetched: { cvss_score: 9.1, in_kev: true, nvd_vuln_status: 'Analyzed', cve_tags: [],
      description: 'Acme Widget Server before 2.0 allows remote code execution.',
      sources: { nvd: { reachable: true, found: true }, kev: { reachable: true }, epss: { reachable: true } } },
  });
  const r = await resolveCve('CVE-2099-10002', { _validateCve: fakeValidate });
  assert.equal(r.status, 'published');
  assert.equal(r.from, 'network');
  assert.equal(typeof r.product, 'string');
  assert.match(r.product, /Acme Widget Server/);
  assert.equal(r.cvss, 9.1);
});

// NVD reachable + found but vulnStatus Rejected -> rejected (not published).
test('resolveCve: NVD-reachable rejected record -> rejected', async () => {
  const fakeValidate = async () => ({
    cve_id: 'CVE-2099-10003', status: 'rejected', discrepancies: [],
    fetched: { cvss_score: null, in_kev: false, nvd_vuln_status: 'Rejected', cve_tags: [], description: null,
      sources: { nvd: { reachable: true, found: true }, kev: { reachable: true }, epss: { reachable: true } } },
  });
  const r = await resolveCve('CVE-2099-10003', { _validateCve: fakeValidate });
  assert.equal(r.status, 'rejected');
});

// --- #6: citation-hygiene --resolve flips parked verdicts (applyResolution) --
const citationHygiene = require('../lib/collectors/citation-hygiene.js');

test('applyResolution: rejected CVE flips rejected-or-disputed-cve to hit, clears needs-verification', async () => {
  const submission = {
    signal_overrides: {
      'rejected-or-disputed-cve': 'inconclusive',
      'cve-citation-needs-external-verification': 'inconclusive',
    },
    needs_verification: { cve_not_in_catalog: [{ file: 'src/x.js', citation: 'CVE-2017-9006' }], rfc_not_in_index: [] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({ status: 'rejected', from: 'network', product: null }),
    _resolveRfc: async () => ({ status: 'unknown', found: false }),
  });
  assert.equal(out.signal_overrides['rejected-or-disputed-cve'], 'hit');
  assert.equal(out.signal_overrides['cve-citation-needs-external-verification'], 'miss');
  assert.equal(out.resolution.cve[0].status, 'rejected');
  assert.equal(typeof out.artifacts['citation-resolution'].value, 'string');
});

test('applyResolution: published CVE clears needs-verification without a rejected hit', async () => {
  const submission = {
    signal_overrides: { 'cve-citation-needs-external-verification': 'inconclusive' },
    needs_verification: { cve_not_in_catalog: [{ file: 'a', citation: 'CVE-2099-12345' }], rfc_not_in_index: [] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({ status: 'published', from: 'network', product: 'Acme' }),
    _resolveRfc: async () => ({}),
  });
  assert.equal(out.signal_overrides['cve-citation-needs-external-verification'], 'miss');
  assert.notEqual(out.signal_overrides['rejected-or-disputed-cve'], 'hit');
});

test('applyResolution: an unresolvable (unknown) CVE keeps needs-verification inconclusive', async () => {
  const submission = {
    signal_overrides: { 'cve-citation-needs-external-verification': 'inconclusive' },
    needs_verification: { cve_not_in_catalog: [{ file: 'a', citation: 'CVE-2099-22222' }], rfc_not_in_index: [] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({ status: 'unknown', from: 'offline' }),
    _resolveRfc: async () => ({}),
  });
  assert.equal(out.signal_overrides['cve-citation-needs-external-verification'], 'inconclusive');
});

// --- #7: obsoleted/historic RFCs are now in the shipped index (offline) ------
test('obsoleted RFCs are present in the shipped index with obsoleted_by', () => {
  const idx = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'rfc-references.json'), 'utf8'));
  const total = Object.keys(idx).filter((k) => k !== '_meta').length;
  assert.ok(total >= 8000, `expected the index to include obsoleted RFCs (>=8000); got ${total}`);
  const httpOld = idx['RFC-2616'];
  assert.ok(httpOld && typeof httpOld === 'object', 'RFC-2616 (HTTP/1.1, obsoleted) must be in the index');
  assert.equal(httpOld._obsoleted, true);
  assert.ok(Array.isArray(httpOld.obsoleted_by) && httpOld.obsoleted_by.includes('RFC7230'),
    `RFC-2616 must carry obsoleted_by incl RFC7230; got ${JSON.stringify(httpOld.obsoleted_by)}`);
});
