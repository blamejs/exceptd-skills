'use strict';

/**
 * Curated-data protection on the NVD CVSS path.
 *
 * The version-downgrade guard already suppresses a v3.x->v2 regression. This
 * additionally keeps a SAME-version NVD re-score (e.g. a maintainer-pinned 10.0
 * dropping to NVD's 9.8) from silently overwriting a curated value. A catalog
 * entry is curator-owned unless it carries `_auto_imported: true`.
 *
 * Pinned behaviors:
 *   - A curator-owned entry's NVD CVSS re-score is surfaced in the report as a
 *     review_only diff that applyDiff does NOT apply: after apply the curated
 *     cvss_score and cvss_vector are unchanged.
 *   - A raw `_auto_imported: true` draft is NOT curator-owned, so NVD is its
 *     source of truth and the same-version re-score applies directly.
 *
 * Offline only: the NVD cache lives in a tmpdir; no network call occurs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { nvdDiffFromCache, ALL_SOURCES } = require('../lib/refresh-external');

const CURATED_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'; // score 10.0
const NVD_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';      // score 9.8 (same version)

function writeNvdCache(cacheDir, id, baseScore, vectorString) {
  fs.mkdirSync(path.join(cacheDir, 'nvd'), { recursive: true });
  const payload = {
    vulnerabilities: [{ cve: { metrics: {
      cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore, vectorString } }],
    } } }],
  };
  fs.writeFileSync(path.join(cacheDir, 'nvd', `${id}.json`), JSON.stringify(payload, null, 2) + '\n');
  const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  const idxPath = path.join(cacheDir, '_index.json');
  const idx = fs.existsSync(idxPath) ? JSON.parse(fs.readFileSync(idxPath, 'utf8')) : { entries: {} };
  idx.entries[`nvd/${id}`] = { sha256: sha, fetched_at: new Date().toISOString(), url: 'test' };
  fs.writeFileSync(idxPath, JSON.stringify(idx, null, 2) + '\n');
}

function makeCtx(dir, cveCatalog) {
  const cvePath = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(cvePath, JSON.stringify(cveCatalog, null, 2) + '\n');
  return { cacheDir: dir, cveCatalog, cvePath, forceStale: false };
}

test('a curator-owned CVSS re-score is surfaced for review and NOT applied', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cvss-prot-'));
  try {
    const id = 'CVE-2025-31324';
    writeNvdCache(tmp, id, 9.8, NVD_VECTOR);
    // Curator-owned: no _auto_imported flag (the live-catalog norm).
    const catalog = { [id]: { cvss_score: 10, cvss_vector: CURATED_VECTOR, _auto_imported: false }, _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = nvdDiffFromCache(ctx);
    const score = diffs.find((d) => d.id === id && d.field === 'cvss_score');
    const vector = diffs.find((d) => d.id === id && d.field === 'cvss_vector');
    assert.ok(score, 'the NVD score delta must be surfaced in the report');
    assert.equal(score.after, 9.8);
    assert.equal(score.review_only, true, 'a curator-owned score re-score must be review_only');
    assert.equal(score.cvss_review, true);
    assert.ok(vector, 'the NVD vector delta must be surfaced too');
    assert.equal(vector.review_only, true, 'the vector re-score is review_only as well');

    await ALL_SOURCES.nvd.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[id];
    assert.equal(after.cvss_score, 10, 'curated cvss_score must SURVIVE (not lowered to 9.8)');
    assert.equal(after.cvss_vector, CURATED_VECTOR, 'curated cvss_vector must be preserved');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a raw _auto_imported draft applies the NVD CVSS re-score directly', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cvss-prot-'));
  try {
    const id = 'CVE-2026-99999';
    writeNvdCache(tmp, id, 9.8, NVD_VECTOR);
    const catalog = { [id]: { cvss_score: 10, cvss_vector: CURATED_VECTOR, _auto_imported: true }, _meta: {} };
    const ctx = makeCtx(tmp, catalog);

    const { diffs } = nvdDiffFromCache(ctx);
    const score = diffs.find((d) => d.id === id && d.field === 'cvss_score');
    assert.ok(score, 'a raw entry still surfaces the delta');
    assert.notEqual(score.review_only, true, 'a raw auto-imported draft is not review_only');

    await ALL_SOURCES.nvd.applyDiff(ctx, diffs);
    const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[id];
    assert.equal(after.cvss_score, 9.8, 'a raw draft applies the NVD re-score');
    assert.equal(after.cvss_vector, NVD_VECTOR, 'a raw draft applies the NVD vector');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
