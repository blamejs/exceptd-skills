'use strict';

/**
 * Regression lock for a curated batch of CISA KEV vulnerabilities.
 *
 * Each entry must be a full curated catalog citizen (no _auto_imported / _draft
 * markers) carrying verified CVSS + vector, a CWE classification, cisa_kev:true,
 * confirmed active exploitation, behavioral indicators of compromise, an RWEP
 * score, and a matching zero-day lesson. Pinning the set here both documents the
 * curation and prevents a silent regression to draft state.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CATALOG = require(path.join(ROOT, 'data', 'cve-catalog.json'));
const LESSONS = require(path.join(ROOT, 'data', 'zeroday-lessons.json'));

const STRICT_CVSS = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

const BATCH = [
  'CVE-2026-42271', 'CVE-2025-27363', 'CVE-2025-30400',
  'CVE-2022-0492', 'CVE-2025-48595', 'CVE-2024-21182',
  'CVE-2026-0257', 'CVE-2026-50751', 'CVE-2026-10520',
  'CVE-2026-11645', 'CVE-2026-7473', 'CVE-2026-20245',
  'CVE-2026-35273', 'CVE-2026-28318', 'CVE-2026-45247',
  'CVE-2026-8398', 'CVE-2026-48172', 'CVE-2025-47729',
  'CVE-2024-11120', 'CVE-2024-6047',
];

for (const id of BATCH) {
  test(`${id} is fully curated (CVSS + CWE + KEV + IOCs + RWEP + lesson, not a draft)`, () => {
    const e = CATALOG[id];
    assert.ok(e, `${id} must be present in cve-catalog.json`);
    assert.notEqual(e._auto_imported, true, `${id} must not remain an auto-imported draft`);
    assert.notEqual(e._draft, true, `${id} must not remain a draft`);

    assert.equal(typeof e.cvss_score, 'number', `${id} must carry a numeric cvss_score`);
    assert.match(String(e.cvss_vector), STRICT_CVSS, `${id} cvss_vector must be a prefixed CVSS string`);
    assert.ok(Array.isArray(e.cwe_refs) && e.cwe_refs.length >= 1, `${id} must carry at least one cwe_ref`);

    assert.equal(e.cisa_kev, true, `${id} must be flagged cisa_kev`);
    assert.equal(e.active_exploitation, 'confirmed', `${id} is KEV-listed → active_exploitation confirmed`);

    // Behavioral IOCs must be populated, not an empty stub.
    assert.ok(e.iocs && typeof e.iocs === 'object' && Object.keys(e.iocs).length > 0,
      `${id} must carry a populated iocs object`);
    assert.ok(Array.isArray(e.iocs.behavioral) && e.iocs.behavioral.length >= 1,
      `${id} iocs.behavioral must list at least one indicator`);

    assert.equal(typeof e.rwep_score, 'number', `${id} must carry a numeric rwep_score`);
    assert.ok(e.rwep_factors && typeof e.rwep_factors.cisa_kev === 'number',
      `${id} rwep_factors must be present with the KEV contribution`);

    assert.ok(LESSONS[id], `${id} must have a matching entry in zeroday-lessons.json`);
  });
}

test('the curated batch is exactly 20 distinct CISA KEV CVEs', () => {
  assert.equal(new Set(BATCH).size, 20);
  for (const id of BATCH) assert.match(id, /^CVE-\d{4}-\d{4,7}$/);
});
