'use strict';

/**
 * tests/package-confidence.test.js
 *
 * Pins the Package-Confidence Score (PCS): the scoring helper, the additive
 * package_confidence field on package-class catalog entries, and — the
 * load-bearing invariant — that PCS NEVER perturbs RWEP (it lives outside the
 * RWEP factor set, so every annotated entry's rwep_score still equals
 * sum(rwep_factors)). Also pins the Shai-Hulud lightning/PyPI enrichment.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const scoring = require(path.join(__dirname, '..', 'lib', 'scoring.js'));
const CAT = require(path.join(__dirname, '..', 'data', 'cve-catalog.json'));
const { resolveCve } = require(path.join(__dirname, '..', 'lib', 'citation-resolve.js'));
const PCS_ENTRIES = [
  'MAL-2026-MOIKA-DEPCONFUSION', 'MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM',
  'CVE-2022-23812', 'MAL-2026-SHAI-HULUD-OSS', 'MAL-2026-NODE-IPC-STEALER',
];

test('packageConfidence() = mean of present sub-signals, skips absent, clamps, null on empty', () => {
  assert.equal(scoring.packageConfidence({ maintainer: 5, quality: 10, behavioral: 5, provenance: 0 }), 5);
  assert.equal(scoring.packageConfidence({ maintainer: 25, quality: 60, behavioral: 10, provenance: 30 }), 31);
  // absent sub-signals are skipped, not treated as 0
  assert.equal(scoring.packageConfidence({ provenance: 80 }), 80);
  assert.equal(scoring.packageConfidence({ maintainer: 40, quality: 60 }), 50);
  // clamp + degenerate input
  assert.equal(scoring.packageConfidence({ quality: 250 }), 100);
  assert.equal(scoring.packageConfidence({}), null);
  assert.equal(scoring.packageConfidence(null), null);
  assert.equal(scoring.packageConfidence({ maintainer: 'x' }), null);
});

test('packageConfidence is NOT part of the RWEP factor set (cannot feed the sum)', () => {
  // The RWEP recognised-factor keys must not include any PCS dimension, so PCS
  // can never leak into deriveRwepFromFactors / validate.
  for (const dim of ['maintainer', 'quality', 'behavioral', 'provenance', 'package_confidence']) {
    assert.ok(!scoring.RECOGNISED_FACTOR_KEYS.has(dim), `${dim} must not be an RWEP factor key`);
  }
});

test('package-class entries carry a valid trust-polarity PCS that matches its inputs', () => {
  for (const key of PCS_ENTRIES) {
    const e = CAT[key];
    assert.ok(e, `${key} must exist`);
    const pc = e.package_confidence;
    assert.ok(pc, `${key} must carry package_confidence`);
    assert.equal(pc.polarity, 'trust', 'polarity const guards against summing with RWEP');
    assert.ok(Number.isInteger(pc.score) && pc.score >= 0 && pc.score <= 100, 'score is an integer in [0,100]');
    assert.equal(pc.score, scoring.packageConfidence(pc.inputs), `${key} score must equal packageConfidence(inputs)`);
  }
});

test('PCS does not perturb RWEP — every annotated entry still has rwep_score == sum(rwep_factors)', () => {
  for (const key of PCS_ENTRIES) {
    const e = CAT[key];
    const sum = Object.values(e.rwep_factors).reduce((a, b) => a + b, 0);
    assert.equal(e.rwep_score, sum, `${key}: PCS must not change the RWEP sum invariant`);
  }
});

test('polarity is enum-enforced by the actual validator (risk rejected, trust accepted)', () => {
  // codex P2: the inline validator implements `enum` but NOT `const`, so the
  // guard must be `enum: ["trust"]`, and the validator must actually reject an
  // inverse-polarity PCS that would be confused with RWEP.
  const schema = require(path.join(__dirname, '..', 'lib', 'schemas', 'cve-catalog.schema.json'));
  const pcSchema = schema.properties.package_confidence;
  assert.deepEqual(pcSchema.properties.polarity, { enum: ['trust'] }, 'polarity must be enum (validator handles enum, not const)');
  const { validate } = require(path.join(__dirname, '..', 'lib', 'validate-cve-catalog.js'));
  const bad = validate({ score: 5, polarity: 'risk' }, pcSchema, 'pc', 'pc');
  assert.ok(bad.length > 0, "polarity 'risk' must be rejected by the validator");
  const good = validate({ score: 5, polarity: 'trust' }, pcSchema, 'pc', 'pc');
  assert.equal(good.length, 0, "polarity 'trust' must validate");
});

test('resolveCve resolves a folded-in CVE alias to its campaign entry offline', async () => {
  // codex P2: CVE-2026-44484 is catalogued only as an alias of the Shai-Hulud
  // wave; it must still resolve offline, or `exceptd cve CVE-2026-44484` reports
  // unknown for an incident the catalog actually covers.
  const r = await resolveCve('CVE-2026-44484', { airGap: true });
  assert.equal(r.from, 'catalog-alias', 'must resolve via the alias index, not fall through to offline/unknown');
  assert.equal(r.aliased_to, 'MAL-2026-SHAI-HULUD-OSS');
  // Exact pin (anti-coincidence): the alias inherits the campaign entry's
  // status — "published" via the e.status || "published" default — NOT "unknown".
  assert.equal(r.status, 'published', 'a catalogued-by-alias id resolves with the campaign status, not offline/unknown');
});

test('Shai-Hulud entry covers the PyPI lightning sub-incident', () => {
  const sh = CAT['MAL-2026-SHAI-HULUD-OSS'];
  assert.ok(Array.isArray(sh.aliases) && sh.aliases.includes('CVE-2026-44484'),
    'lightning PyPI compromise (CVE-2026-44484) recorded as an alias of this wave');
  assert.ok(sh.affected_versions.some((v) => /lightning/i.test(v) && /2\.6\.2/.test(v)),
    'affected_versions must name lightning 2.6.2/2.6.3');
  assert.ok(sh.iocs && Array.isArray(sh.iocs.pypi_lightning_subincident),
    'iocs must carry the lightning sub-incident block (Bun-runtime infostealer)');
  assert.ok(sh.verification_sources.some((u) => /MAL-2026-3201/.test(u)),
    'verification_sources must cite the OSV lightning record');
});
