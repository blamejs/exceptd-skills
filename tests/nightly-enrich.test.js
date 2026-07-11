'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const ad = require('../lib/auto-discovery.js');

test('DEFAULT_CAP raised to 100', () => {
  assert.strictEqual(ad.DEFAULT_CAP, 100);
});

test('buildKevDraftEntry with nvd+epss present populates mechanical fields via cve-enrich while keeping conservative draft defaults', () => {
  const kev = {
    cveID: 'CVE-2025-0108',
    vulnerabilityName: 'Palo Alto Networks PAN-OS Authentication Bypass Vulnerability',
    vendorProject: 'Palo Alto Networks',
    product: 'PAN-OS',
    dateAdded: '2025-02-18',
    dueDate: '2025-03-11',
    shortDescription: 'PAN-OS management web interface auth bypass.',
    knownRansomwareCampaignUse: 'Unknown',
  };
  const nvdPayload = {
    vulnerabilities: [{
      cve: {
        id: 'CVE-2025-0108',
        metrics: {
          cvssMetricV31: [{
            type: 'Primary',
            cvssData: { baseScore: 8.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
          }],
        },
        descriptions: [{ lang: 'en', value: 'An authentication bypass in PAN-OS management web interface.' }],
        weaknesses: [{ description: [{ value: 'CWE-306' }] }],
      },
    }],
  };
  const epssPayload = { data: [{ cve: 'CVE-2025-0108', epss: '0.94', percentile: '0.99', date: '2026-07-11' }] };

  const entry = ad.buildKevDraftEntry(kev, nvdPayload, epssPayload);

  // Mechanical fields flowed through cve-enrich.deriveMechanicalFields — now
  // populated, not null, when NVD/EPSS cache data is present.
  assert.strictEqual(entry.cvss_score, 8.8);
  assert.strictEqual(entry.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.deepStrictEqual(entry.cwe_refs, ['CWE-306']);
  assert.strictEqual(entry.epss_score, 0.94);
  assert.strictEqual(entry.epss_percentile, 0.99);
  assert.strictEqual(entry.epss_date, '2026-07-11');
  assert.strictEqual(entry.complexity, 'low');
  assert.strictEqual(entry.cisa_kev, true);
  assert.strictEqual(entry.cisa_kev_date, '2025-02-18');
  assert.strictEqual(entry.cisa_kev_due_date, '2025-03-11');
  assert.ok(Array.isArray(entry.vendor_advisories) && entry.vendor_advisories.length >= 1);

  // Conservative pre-curation defaults must NOT be overridden by the
  // mechanical derivation — a nightly draft must not over-claim before a
  // human reviews it. deriveMechanicalFields alone would return 'confirmed'
  // for active_exploitation (a KEV listing is present); the draft builder
  // must override that back down to 'suspected'.
  assert.strictEqual(entry.active_exploitation, 'suspected');
  assert.strictEqual(entry.type, 'TBD');
  assert.strictEqual(entry.poc_available, null);
  assert.strictEqual(entry.ai_discovered, null);
  assert.strictEqual(entry._auto_imported, true);
  assert.ok(entry._auto_imported_meta && entry._auto_imported_meta.source === 'KEV discovery');

  // rwep_factors/rwep_score still come from the buildScoringInputs +
  // scoring.postWeightFactors path (unrelated to the mechanical merge).
  assert.strictEqual(typeof entry.rwep_score, 'number');
  const sum = Object.values(entry.rwep_factors).reduce((a, b) => a + b, 0);
  assert.strictEqual(sum, entry.rwep_score);
});
