'use strict';

/**
 * Regression: the NVD apply must not downgrade a curated higher-version CVSS
 * to NVD's legacy v2 metric.
 *
 * NVD tags the v2 metric "Primary" on pre-v3 CVEs (a v3.1 re-score rides as
 * "Secondary") and emits the v2 vector with no "CVSS:2.0/" prefix. The old
 * selection (`[...V31,...V30,...V2].find(type==='Primary')`) therefore picked
 * the v2 Primary and rewrote a curated "CVSS:3.1/..." vector to the bare v2
 * form — which validate-cve-catalog --strict rejects, failing the refresh
 * validation gate (15 legacy CVEs in run 27130985594). It also downgraded the
 * curated cvss_score (e.g. 9.8 -> 10) silently, since a numeric v2 score is
 * schema-valid.
 *
 * nvdDiffFromCache now selects the newest CVSS version (Primary within it),
 * normalizes a bare v2 vector, and suppresses BOTH the score and vector diff
 * whenever the upstream metric is an older CVSS version than the curated one.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { nvdDiffFromCache } = require('../lib/refresh-external');

// Strict prefix the validation gate enforces.
const STRICT = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

function writeNvdCache(cacheDir, id, payload) {
  fs.mkdirSync(path.join(cacheDir, 'nvd'), { recursive: true });
  fs.writeFileSync(path.join(cacheDir, 'nvd', `${id}.json`), JSON.stringify(payload, null, 2) + '\n');
  const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  const idxPath = path.join(cacheDir, '_index.json');
  let idx;
  try { idx = JSON.parse(fs.readFileSync(idxPath, 'utf8')); } catch { idx = { entries: {} }; }
  idx.entries[`nvd/${id}`] = { sha256: sha, fetched_at: new Date().toISOString(), url: 'test' };
  fs.writeFileSync(idxPath, JSON.stringify(idx, null, 2) + '\n');
}

function nvdPayload(buckets) {
  return { vulnerabilities: [{ cve: { metrics: buckets } }] };
}

function run(localEntry, buckets) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nvd-downgrade-'));
  try {
    const id = 'CVE-2008-4250';
    writeNvdCache(tmp, id, nvdPayload(buckets));
    const ctx = { cacheDir: tmp, cveCatalog: { [id]: localEntry }, forceStale: false };
    return { id, ...nvdDiffFromCache(ctx) };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

test('nvdDiffFromCache is exported for direct testing', () => {
  assert.equal(typeof nvdDiffFromCache, 'function');
});

test('v2-Primary + v3.1-Secondary against a curated v3.1 entry emits NO diff (the shipped-bug repro)', () => {
  const r = run(
    { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8 },
    {
      cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
      cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }],
    },
  );
  assert.equal(r.errors, 0);
  assert.equal(r.diffs.filter((d) => d.field === 'cvss_vector').length, 0, 'must not rewrite the curated v3.1 vector to bare v2');
  assert.equal(r.diffs.filter((d) => d.field === 'cvss_score').length, 0, 'must not downgrade the curated v3.1 score to the v2 score');
  assert.deepEqual(r.diffs, []);
});

test('downgrade-guard: v2-only upstream against a curated v3.1 entry emits NOTHING (vector AND score)', () => {
  // NVD never re-scored this CVE to v3.x; the catalog was curated to v3.1.
  const r = run(
    { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8 },
    { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 5.0, vectorString: 'AV:N/AC:L/Au:N/C:P/I:N/A:N' } }] },
  );
  assert.deepEqual(r.diffs, [], 'a strictly-older upstream version must suppress both the score and vector diff');
});

test('legitimate upgrade: local v3.0, upstream v3.1 still emits a diff (guard blocks only downgrades)', () => {
  const r = run(
    { cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.0 },
    { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
  );
  const vec = r.diffs.find((d) => d.field === 'cvss_vector');
  const score = r.diffs.find((d) => d.field === 'cvss_score');
  assert.ok(vec, 'a genuine newer-version upstream must still produce a vector diff');
  assert.equal(vec.after, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.ok(score, 'and the accompanying score move');
  assert.equal(score.after, 9.8);
});

test('same-version score drift on a curated entry is surfaced but held for review (not a downgrade)', () => {
  // Catalog score hand-adjusted to 9.3 vs NVD v3.1 9.8 — a legitimate same-
  // version drift the refresh surfaces. The default catalog entry is
  // curator-owned (no _auto_imported flag), so the drift is held for review
  // rather than auto-applied (the curator accepts an NVD re-score deliberately).
  const r = run(
    { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.3 },
    { cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
  );
  assert.equal(r.diffs.filter((d) => d.field === 'cvss_vector').length, 0, 'vectors match -> no vector diff');
  const score = r.diffs.find((d) => d.field === 'cvss_score');
  assert.ok(score && score.after === 9.8, 'same-version score drift is surfaced');
  assert.equal(score.review_only, true, 'a curator-owned entry holds the drift for review, not auto-applied');
});

test('same-version score drift on a raw auto-imported entry applies (not curator-owned)', () => {
  // An _auto_imported draft is not yet curated — NVD is its source of truth,
  // so a same-version re-score applies directly (no review_only).
  const r = run(
    { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.3, _auto_imported: true },
    { cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
  );
  const score = r.diffs.find((d) => d.field === 'cvss_score');
  assert.ok(score && score.after === 9.8, 'a raw entry surfaces the same-version drift');
  assert.notEqual(score.review_only, true, 'a raw auto-imported entry applies the NVD re-score directly');
});

test('bare v2 upstream against a curated v2.0 entry: normalized, no spurious diff, validator-legal', () => {
  const r = run(
    { cvss_vector: 'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C', cvss_score: 10 },
    { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }] },
  );
  assert.deepEqual(r.diffs, [], 'normalizing the bare upstream vector to CVSS:2.0/ avoids a prefix-only churn diff');
});

test('any vector this apply would write is strict-validator-legal', () => {
  // A v2-only CVE whose catalog entry is (legitimately) still v2 — the apply
  // should normalize to a prefixed vector if it ever writes one.
  const r = run(
    { cvss_vector: 'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:P', cvss_score: 5.0 },
    { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 7.5, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }] },
  );
  for (const d of r.diffs.filter((x) => x.field === 'cvss_vector')) {
    assert.ok(STRICT.test(d.after), `apply must never write a vector that fails --strict: ${d.after}`);
  }
});
