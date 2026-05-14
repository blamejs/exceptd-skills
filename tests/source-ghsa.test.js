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
