'use strict';

/**
 * Regression: the LIVE (network) NVD validate path must apply the same
 * cross-version CVSS downgrade guard the cache path already has.
 *
 * NVD tags the legacy v2 metric "Primary" on pre-v3 CVEs; selecting it and
 * comparing against a curated CVSS:3.1 entry produced a cvss_score/cvss_vector
 * discrepancy that a bare `refresh --apply` (which takes the live path, not the
 * guarded cache path) wrote back — silently downgrading a curated 9.8 to NVD's
 * v2 score and rewriting the v3.1 vector to bare v2. validateCve now suppresses
 * both diffs when the upstream CVSS version is older than the curated one, while
 * a same-version re-score still surfaces.
 *
 * fetch is stubbed so this runs offline.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { validateCve, resetKevCache } = require('../sources/validators/cve-validator');

function jsonRes(obj) {
  return { ok: true, status: 200, json: async () => obj };
}

function stubFetch(nvdPayload) {
  const orig = global.fetch;
  global.fetch = async (url) => {
    const u = String(url);
    if (u.includes('nvd.nist.gov')) return jsonRes(nvdPayload);
    if (u.includes('first.org')) return jsonRes({ status: 'OK', data: [] }); // EPSS: none
    if (u.includes('known_exploited')) return jsonRes({ vulnerabilities: [] }); // KEV: empty
    throw new Error('unexpected fetch in test: ' + u);
  };
  return () => { global.fetch = orig; };
}

function nvd(metrics) {
  return {
    totalResults: 1,
    vulnerabilities: [{
      cve: {
        vulnStatus: 'Analyzed',
        cveTags: [],
        descriptions: [{ lang: 'en', value: 'test cve' }],
        metrics,
      },
    }],
  };
}

const V2_ONLY = nvd({
  cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 7.5, vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' } }],
});
const V31_RESCORE = nvd({
  cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 7.5, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L' } }],
});

// Curated to CVSS:3.1 9.8.
const CURATED = { cvss_score: 9.8, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cisa_kev: false };

test('live NVD path suppresses a v2-over-v3.1 CVSS downgrade (no discrepancy)', async () => {
  resetKevCache();
  const restore = stubFetch(V2_ONLY);
  try {
    const r = await validateCve('CVE-2014-0001', CURATED);
    const cvss = r.discrepancies.filter(d => d.field === 'cvss_score' || d.field === 'cvss_vector');
    assert.equal(cvss.length, 0, `expected zero cvss downgrade discrepancies, got: ${JSON.stringify(cvss)}`);
  } finally {
    restore();
    resetKevCache();
  }
});

test('live NVD path still reports a same-version CVSS re-score drift', async () => {
  resetKevCache();
  const restore = stubFetch(V31_RESCORE);
  try {
    const r = await validateCve('CVE-2024-9999', CURATED);
    const scoreDiff = r.discrepancies.find(d => d.field === 'cvss_score');
    assert.ok(scoreDiff, 'a same-version (v3.1) cvss_score drift must still be reported');
    assert.equal(scoreDiff.fetched, 7.5);
    assert.equal(scoreDiff.local, 9.8);
  } finally {
    restore();
    resetKevCache();
  }
});
