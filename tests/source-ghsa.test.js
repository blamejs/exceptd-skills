'use strict';

/**
 * tests/source-ghsa.test.js
 *
 * Coverage for lib/source-ghsa.js — the GHSA upstream source. v0.12.14
 * hardening pass: regression tests for the audit findings carried by the
 * refresh-sources v0.12.13 review. Each test fails on the un-fixed code
 * and passes after the fix.
 *
 * Fixture-only — no network calls. EXCEPTD_GHSA_FIXTURE drives the fetch
 * path; in-test objects exercise normalize / build-diff helpers directly.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOT = path.join(__dirname, '..');
const GHSA_FIX = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');

const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));

// ---------------------------------------------------------------------------
// F1 (audit item 1) — non-string published_at coerces to null
// ---------------------------------------------------------------------------

test('v0.12.14 F1 normalizeAdvisory survives numeric published_at without throwing', () => {
  const adv = {
    cve_id: 'CVE-2026-99001',
    ghsa_id: 'GHSA-num-num-num',
    summary: 'numeric published_at regression',
    severity: 'medium',
    cvss: { score: 5.5, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    vulnerabilities: [],
    published_at: 1747000000000, // milliseconds since epoch — NOT a string
    html_url: 'https://github.com/advisories/GHSA-num-num-num',
    references: [],
  };
  let out;
  assert.doesNotThrow(() => { out = ghsa.normalizeAdvisory(adv); },
    'non-string published_at must not throw inside normalizeAdvisory');
  const entry = out['CVE-2026-99001'];
  assert.equal(entry.vendor_advisories[0].published_date, null,
    'non-string published_at must coerce to null, not crash on .slice()');
});

test('v0.12.14 F1 safeDateSlice rejects non-string + malformed dates', () => {
  assert.equal(ghsa.safeDateSlice(undefined), null);
  assert.equal(ghsa.safeDateSlice(null), null);
  assert.equal(ghsa.safeDateSlice(0), null);
  assert.equal(ghsa.safeDateSlice({}), null);
  assert.equal(ghsa.safeDateSlice('not-a-date'), null);
  assert.equal(ghsa.safeDateSlice('2026-05-13T00:00:00Z'), '2026-05-13');
  assert.equal(ghsa.safeDateSlice('2026-05-13'), '2026-05-13');
});

// ---------------------------------------------------------------------------
// F3 (audit item 3) — defensive iteration on vulnerabilities + references
// ---------------------------------------------------------------------------

test('v0.12.14 F3 normalizeAdvisory tolerates non-array vulnerabilities', () => {
  const adv = {
    cve_id: 'CVE-2026-99002',
    ghsa_id: 'GHSA-novuln-x-x',
    summary: 'non-array vulnerabilities regression',
    severity: 'high',
    cvss: { score: 7.0, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    vulnerabilities: null, // upstream drift: not an array
    published_at: '2026-05-13T00:00:00Z',
    references: [],
  };
  let out;
  assert.doesNotThrow(() => { out = ghsa.normalizeAdvisory(adv); },
    'null vulnerabilities must not throw inside the iteration');
  const entry = out['CVE-2026-99002'];
  assert.equal(entry.affected, null, 'no vulnerabilities → null affected');
  assert.deepEqual(entry.affected_versions, []);
});

// ---------------------------------------------------------------------------
// F12 (audit item 12) — defensive iteration on references
// ---------------------------------------------------------------------------

test('v0.12.14 F12 normalizeAdvisory tolerates non-array references', () => {
  const adv = {
    cve_id: 'CVE-2026-99003',
    ghsa_id: 'GHSA-refs-x-x',
    summary: 'non-array references regression',
    severity: 'medium',
    cvss: { score: 5.0, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    vulnerabilities: [],
    published_at: '2026-05-13T00:00:00Z',
    references: 'https://github.com/advisories/GHSA-refs-x-x', // upstream drift: string instead of array
  };
  let out;
  assert.doesNotThrow(() => { out = ghsa.normalizeAdvisory(adv); },
    'non-array references must not throw inside the spread');
  const entry = out['CVE-2026-99003'];
  assert.ok(Array.isArray(entry.verification_sources),
    'verification_sources must remain an array even when references[] is malformed');
});

// ---------------------------------------------------------------------------
// F4 (audit item 4) — cvss.score numeric coercion
// ---------------------------------------------------------------------------

test('v0.12.14 F4 normalizeAdvisory coerces string cvss.score to number', () => {
  const adv = {
    cve_id: 'CVE-2026-99004',
    ghsa_id: 'GHSA-cvss-str-x',
    summary: 'string cvss.score regression',
    severity: 'critical',
    cvss: { score: '9.8', vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    vulnerabilities: [],
    published_at: '2026-05-13T00:00:00Z',
    references: [],
  };
  const out = ghsa.normalizeAdvisory(adv);
  const entry = out['CVE-2026-99004'];
  assert.equal(typeof entry.cvss_score, 'number',
    'string upstream score must coerce to number, not propagate as string');
  assert.equal(entry.cvss_score, 9.8);
});

test('v0.12.14 F4 normalizeAdvisory yields null cvss_score for non-finite input', () => {
  const adv = {
    cve_id: 'CVE-2026-99005',
    ghsa_id: 'GHSA-cvss-nan-x',
    summary: 'non-finite cvss.score regression',
    severity: 'critical',
    cvss: { score: 'not-a-number', vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    vulnerabilities: [],
    published_at: '2026-05-13T00:00:00Z',
    references: [],
  };
  const out = ghsa.normalizeAdvisory(adv);
  const entry = out['CVE-2026-99005'];
  assert.equal(entry.cvss_score, null,
    'garbage cvss.score must produce null, not NaN');
});

// ---------------------------------------------------------------------------
// F5 (audit item 5) — fixture envelope validation
// ---------------------------------------------------------------------------

test('v0.12.14 F5 fetchAdvisories rejects fixture with root=null', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ghsa-null-'));
  const fp = path.join(tmp, 'null.json');
  fs.writeFileSync(fp, 'null');
  process.env.EXCEPTD_GHSA_FIXTURE = fp;
  try {
    const r = await ghsa.fetchAdvisories();
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
    assert.match(r.error, /invalid root shape/);
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('v0.12.14 F5 fetchAdvisories rejects fixture with root=number', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ghsa-num-'));
  const fp = path.join(tmp, 'scalar.json');
  fs.writeFileSync(fp, '42');
  process.env.EXCEPTD_GHSA_FIXTURE = fp;
  try {
    const r = await ghsa.fetchAdvisories();
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('v0.12.14 F5 fetchAdvisories rejects fixture with root=string', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ghsa-str-'));
  const fp = path.join(tmp, 'string.json');
  fs.writeFileSync(fp, '"just a string"');
  process.env.EXCEPTD_GHSA_FIXTURE = fp;
  try {
    const r = await ghsa.fetchAdvisories();
    assert.equal(r.ok, false);
    assert.equal(r.source, 'offline');
    assert.match(r.error, /fixture/);
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('v0.12.14 F5 fetchAdvisories accepts single-object fixture (back-compat)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ghsa-obj-'));
  const fp = path.join(tmp, 'one.json');
  const fixture = JSON.parse(fs.readFileSync(GHSA_FIX, 'utf8'));
  fs.writeFileSync(fp, JSON.stringify(fixture[0]));
  process.env.EXCEPTD_GHSA_FIXTURE = fp;
  try {
    const r = await ghsa.fetchAdvisories();
    assert.equal(r.ok, true);
    assert.equal(r.advisories.length, 1);
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// F6 (audit item 6) — trim ids at the entry seam
// ---------------------------------------------------------------------------

test('v0.12.14 F6 fetchAdvisoryById trims whitespace-padded id', async () => {
  process.env.EXCEPTD_GHSA_FIXTURE = GHSA_FIX;
  try {
    const r = await ghsa.fetchAdvisoryById('  CVE-2026-45321  ');
    assert.equal(r.ok, true,
      'whitespace-padded id must resolve after entry-seam trim');
    assert.equal(r.advisories[0].cve_id, 'CVE-2026-45321');
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
  }
});

test('v0.12.14 F6 fetchAdvisoryById rejects whitespace-only id', async () => {
  const r = await ghsa.fetchAdvisoryById('   ');
  assert.equal(r.ok, false);
  assert.match(r.error, /id is required/);
});

// ---------------------------------------------------------------------------
// F10 (audit item 10) — ISO-8601 + year-range date validation
// ---------------------------------------------------------------------------

test('v0.12.14 F10 safeDateSlice rejects malformed ISO prefix', () => {
  assert.equal(ghsa.safeDateSlice('05-13-2026'), null,
    'US-style date must not pass the ISO regex');
  assert.equal(ghsa.safeDateSlice('yesterday'), null);
  assert.equal(ghsa.safeDateSlice('20260513'), null,
    'compact-date form must not pass the ISO regex');
});

test('v0.12.14 F10 safeDateSlice rejects out-of-range years', () => {
  assert.equal(ghsa.safeDateSlice('0001-01-01'), null,
    'pre-1990 year must be rejected as garbage');
  assert.equal(ghsa.safeDateSlice('1980-06-15'), null,
    'years before 1990 belong to pre-CVE history; reject');
  const future = (new Date().getUTCFullYear() + 5);
  assert.equal(ghsa.safeDateSlice(`${future}-01-01`), null,
    'years far in the future are likely upstream typos; reject');
});

test('v0.12.14 F10 safeDateSlice accepts current-year + next-year boundary', () => {
  const next = (new Date().getUTCFullYear() + 1);
  assert.equal(ghsa.safeDateSlice(`${next}-12-31`), `${next}-12-31`,
    'currentYear+1 is the upper bound; must accept');
});

// ---------------------------------------------------------------------------
// F11 (audit item 11) — ghsa_only_skipped counter in buildDiff
// ---------------------------------------------------------------------------

test('v0.12.14 F11 buildDiff reports ghsa_only_skipped count', async () => {
  // Build a fixture that mixes one CVE-bearing advisory with one GHSA-only
  // advisory (no cve_id). The latter must be skipped + counted.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ghsa-skip-'));
  const fp = path.join(tmp, 'mixed.json');
  fs.writeFileSync(fp, JSON.stringify([
    JSON.parse(fs.readFileSync(GHSA_FIX, 'utf8'))[0], // has cve_id
    {
      ghsa_id: 'GHSA-orphan-x-x',
      cve_id: null, // GHSA-only — no CVE assignment yet
      summary: 'GHSA-only orphan',
      severity: 'medium',
      cvss: { score: 5.0, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' },
      vulnerabilities: [],
      published_at: '2026-05-13T00:00:00Z',
      references: [],
    },
  ]));
  process.env.EXCEPTD_GHSA_FIXTURE = fp;
  try {
    const r = await ghsa.buildDiff({ cveCatalog: {} });
    assert.equal(r.status, 'ok');
    assert.equal(typeof r.ghsa_only_skipped, 'number',
      'buildDiff summary must surface ghsa_only_skipped count');
    assert.equal(r.ghsa_only_skipped, 1,
      'one GHSA-only advisory must be counted as skipped');
    assert.match(r.summary, /ghsa_only_skipped/);
  } finally {
    delete process.env.EXCEPTD_GHSA_FIXTURE;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Module exports surface — regression guard
// ---------------------------------------------------------------------------

test('v0.12.14 source-ghsa.js exports documented surface', () => {
  for (const ident of ['fetchAdvisories', 'fetchAdvisoryById', 'normalizeAdvisory', 'buildDiff', 'safeDateSlice']) {
    assert.ok(ident in ghsa, `lib/source-ghsa.js must export ${ident}`);
  }
});

// ---------------------------------------------------------------------------
// fetchAdvisoryById / normalizeAdvisory against the shipped fixture
// ---------------------------------------------------------------------------

test('source-ghsa.fetchAdvisoryById finds CVE in fixture', async () => {
  process.env.EXCEPTD_GHSA_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  try {
    const r = await ghsa.fetchAdvisoryById('CVE-2026-45321');
    assert.equal(r.ok, true);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories[0].cve_id, 'CVE-2026-45321');
    assert.equal(r.advisories[0].severity, 'critical');
  } finally { delete process.env.EXCEPTD_GHSA_FIXTURE; }
});

test('source-ghsa.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json'), 'utf8'));
  const out = ghsa.normalizeAdvisory(fixture[0]);
  assert.ok(out);
  const entry = out['CVE-2026-45321'];
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(entry.framework_control_gaps, null, 'framework_control_gaps must be null on a draft');
  assert.equal(entry.atlas_refs.length, 0, 'editorial atlas_refs starts empty');
  assert.equal(entry.cvss_score, 9.6);
  assert.equal(entry.cisa_kev_pending, true, 'critical-severity drafts mark cisa_kev_pending');
  assert.equal(entry._source_ghsa_id, 'GHSA-tnsk-tnsk-tnsk');
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('v0.12 source-ghsa.fetchAdvisoryById finds CVE in fixture', async () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  process.env.EXCEPTD_GHSA_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  try {
    const r = await ghsa.fetchAdvisoryById('CVE-2026-45321');
    assert.equal(r.ok, true);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories[0].cve_id, 'CVE-2026-45321');
    assert.equal(r.advisories[0].severity, 'critical');
  } finally { delete process.env.EXCEPTD_GHSA_FIXTURE; }
});

test('v0.12 source-ghsa.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json'), 'utf8'));
  const out = ghsa.normalizeAdvisory(fixture[0]);
  assert.ok(out);
  const entry = out['CVE-2026-45321'];
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(entry.framework_control_gaps, null, 'framework_control_gaps must be null on a draft');
  assert.equal(entry.atlas_refs.length, 0, 'editorial atlas_refs starts empty');
  assert.equal(entry.cvss_score, 9.6);
  assert.equal(entry.cisa_kev_pending, true, 'critical-severity drafts mark cisa_kev_pending');
  assert.equal(entry._source_ghsa_id, 'GHSA-tnsk-tnsk-tnsk');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
