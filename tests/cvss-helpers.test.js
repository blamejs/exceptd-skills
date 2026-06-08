'use strict';

/**
 * lib/cvss.js — shared NVD CVSS metric-selection + vector-normalization.
 *
 * These helpers exist because NVD tags the legacy CVSS v2 metric as "Primary"
 * on pre-v3 CVEs while a modern v3.1 re-score rides as "Secondary", and emits
 * the v2 vector with no "CVSS:2.0/" prefix. Selecting by type alone (and
 * writing the bare vector) downgraded curated v3.1 catalog entries to v2 and
 * produced vectors that validate-cve-catalog --strict rejects.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { cvssVersionOf, normalizeCvssVector, selectNvdCvss } = require('../lib/cvss');

// Mirrors validate-cve-catalog.js STRICT_CVSS_PATTERN — every normalized
// vector must satisfy it.
const STRICT = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

test('cvssVersionOf returns a comparable version for every recognized form', () => {
  assert.equal(cvssVersionOf('AV:N/AC:M/Au:N/C:C/I:C/A:C'), 2.0, 'bare v2 base vector -> 2.0');
  assert.equal(cvssVersionOf('CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C'), 2.0);
  assert.equal(cvssVersionOf('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 3.0);
  assert.equal(cvssVersionOf('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 3.1);
  assert.equal(cvssVersionOf('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), 4.0);
  // Ordering is numeric so the downgrade comparison works.
  assert.ok(cvssVersionOf('CVSS:3.1/x') > cvssVersionOf('CVSS:3.0/x'));
  assert.ok(cvssVersionOf('CVSS:4.0/x') > cvssVersionOf('CVSS:3.1/x'));
  assert.ok(cvssVersionOf('CVSS:2.0/x') < cvssVersionOf('CVSS:3.0/x'));
});

test('cvssVersionOf returns null for unrecognized / empty input (treated as "do not block")', () => {
  assert.equal(cvssVersionOf('not-a-vector'), null);
  assert.equal(cvssVersionOf(''), null);
  assert.equal(cvssVersionOf(null), null);
  assert.equal(cvssVersionOf(undefined), null);
  assert.equal(cvssVersionOf('CVSS:9.9/AV:N'), null, 'an unknown CVSS version is not a recognized prefix');
});

test('normalizeCvssVector prefixes a bare v2 vector and leaves prefixed vectors untouched', () => {
  assert.equal(
    normalizeCvssVector('AV:N/AC:M/Au:N/C:C/I:C/A:C'),
    'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:C',
  );
  const v31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  assert.equal(normalizeCvssVector(v31), v31);
  assert.equal(
    normalizeCvssVector('CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C'),
    'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C',
  );
  // The output of a recognized vector is always strict-validator-legal — this
  // is the property that keeps the apply from ever writing a rejectable vector.
  assert.ok(STRICT.test(normalizeCvssVector('AV:N/AC:M/Au:N/C:C/I:C/A:C')));
  assert.ok(STRICT.test(normalizeCvssVector(v31)));
});

test('selectNvdCvss prefers the newest version and Primary within it (CVE-2008-4250 shape)', () => {
  // Real NVD shape for legacy CVEs: v3.1 rides as Secondary, v2 as Primary.
  const metrics = {
    cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
    cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }],
  };
  const up = selectNvdCvss(metrics);
  assert.equal(up.version, 3.1, 'must pick the v3.1 metric, not the v2 Primary');
  assert.equal(up.baseScore, 9.8);
  assert.equal(up.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('selectNvdCvss prefers Primary within the chosen version, else the first entry', () => {
  // Both buckets carry a Primary; the newer version still wins.
  const both = {
    cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 7.5, vectorString: 'CVSS:3.1/AV:N' } }],
    cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 9.0, vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' } }],
  };
  assert.equal(selectNvdCvss(both).baseScore, 7.5);

  // The newest bucket has only a Secondary — fall back to it, never to a
  // lower-version Primary.
  const secondaryOnly = {
    cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 7.0, vectorString: 'CVSS:3.1/AV:N' } }],
    cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 9.0, vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' } }],
  };
  assert.equal(selectNvdCvss(secondaryOnly).baseScore, 7.0);
});

test('selectNvdCvss prefers a CVSS 4.0 metric when present', () => {
  const metrics = {
    cvssMetricV40: [{ type: 'Primary', cvssData: { version: '4.0', baseScore: 9.3, vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' } }],
    cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 8.8, vectorString: 'CVSS:3.1/AV:N' } }],
  };
  const up = selectNvdCvss(metrics);
  assert.equal(up.version, 4.0);
  assert.equal(up.baseScore, 9.3);
});

test('selectNvdCvss normalizes a bare v2 vector and returns null when no metric present', () => {
  const v2 = { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }] };
  const up = selectNvdCvss(v2);
  assert.equal(up.vector, 'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C', 'bare v2 vector normalized to canonical prefix');
  assert.ok(STRICT.test(up.vector));

  assert.equal(selectNvdCvss({}), null);
  assert.equal(selectNvdCvss(null), null);
  assert.equal(selectNvdCvss({ cvssMetricV31: [] }), null, 'empty buckets -> null');
});
