'use strict';

/**
 * Auto-discovery reads per-CVE NVD/EPSS cache files and writes their CVSS /
 * CWE / EPSS values into auto-imported catalog drafts. Those reads must be
 * integrity-checked against the signed _index.json the rest of the cache
 * consume path verifies — otherwise an attacker who drops a forged sidecar
 * for a newly-DISCOVERED CVE (one not in the local catalog, so never
 * prefetched and never indexed) between prefetch and refresh gets forged
 * mechanical fields written into the catalog with zero verification.
 *
 * Discovery cannot throw (it returns drafts), so the fail-closed behavior is
 * to drop the unverified payload: the draft keeps its null mechanical fields,
 * the same fallback used when no sidecar exists at all.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const { discoverNewKev } = require(path.join(ROOT, 'lib', 'auto-discovery.js'));

// The sha256 prefetch records is over JSON.stringify(payload) (unindented).
function indexSha(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  // On-disk bytes are pretty-printed; the integrity check re-stringifies the
  // parsed object, so the on-disk formatting is independent of the hash.
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

// A discovered (not-in-catalog) KEV CVE plus its KEV feed entry indexed.
function buildDiscoveryCache(prefix, { nvdPayload, nvdIndexed, tamperNvd }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const NEW_CVE = 'CVE-2099-40001';
  const kevFeed = { vulnerabilities: [{ cveID: NEW_CVE, dateAdded: '2099-01-01', vulnerabilityName: 'Discovered Bug' }] };
  writeJson(path.join(dir, 'kev', 'known_exploited_vulnerabilities.json'), kevFeed);

  const entries = {
    'kev/known_exploited_vulnerabilities': { sha256: indexSha(kevFeed) },
  };

  if (nvdPayload) {
    writeJson(path.join(dir, 'nvd', `${NEW_CVE}.json`), nvdPayload);
    if (nvdIndexed) {
      // Record the honest hash, then optionally rewrite the on-disk payload
      // so the recorded hash no longer matches (a payload tamper).
      entries[`nvd/${NEW_CVE}`] = { sha256: indexSha(nvdPayload) };
      if (tamperNvd) {
        const tampered = JSON.parse(JSON.stringify(nvdPayload));
        tampered.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore = 1.0;
        writeJson(path.join(dir, 'nvd', `${NEW_CVE}.json`), tampered);
      }
    }
    // nvdIndexed=false leaves the sidecar on disk with NO index entry — the
    // drop-alongside-a-signed-cache vector.
  }

  writeJson(path.join(dir, '_index.json'), { entries });
  return { dir, NEW_CVE };
}

const NVD_PAYLOAD = {
  vulnerabilities: [{
    cve: {
      descriptions: [{ lang: 'en', value: 'real description' }],
      metrics: {
        cvssMetricV31: [{
          type: 'Primary',
          cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        }],
      },
      weaknesses: [{ description: [{ value: 'CWE-787' }] }],
    },
  }],
};

test('discovered draft does NOT absorb a tampered NVD sidecar (sha256 mismatch)', () => {
  const { dir, NEW_CVE } = buildDiscoveryCache('exceptd-disc-tamper-', {
    nvdPayload: NVD_PAYLOAD, nvdIndexed: true, tamperNvd: true,
  });
  try {
    const ctx = { cacheDir: dir, cveCatalog: {} };
    const r = discoverNewKev(ctx);
    assert.equal(r.diffs.length, 1, 'the discovered CVE still produces a draft');
    const entry = r.diffs[0].entry;
    assert.equal(r.diffs[0].id, NEW_CVE);
    // The tampered baseScore (1.0) must NOT land; the draft keeps null CVSS.
    assert.equal(entry.cvss_score, null, 'tampered CVSS must be refused');
    assert.equal(entry.cvss_vector, null, 'tampered vector must be refused');
    assert.deepEqual(entry.cwe_refs, [], 'tampered CWE refs must be refused');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovered draft does NOT absorb an NVD sidecar with no _index.json entry', () => {
  const { dir, NEW_CVE } = buildDiscoveryCache('exceptd-disc-unindexed-', {
    nvdPayload: NVD_PAYLOAD, nvdIndexed: false,
  });
  try {
    const ctx = { cacheDir: dir, cveCatalog: {} };
    const r = discoverNewKev(ctx);
    assert.equal(r.diffs.length, 1);
    const entry = r.diffs[0].entry;
    assert.equal(r.diffs[0].id, NEW_CVE);
    assert.equal(entry.cvss_score, null, 'unindexed CVSS must be refused');
    assert.equal(entry.cvss_vector, null, 'unindexed vector must be refused');
    assert.deepEqual(entry.cwe_refs, [], 'unindexed CWE refs must be refused');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovered draft DOES absorb a correctly-indexed, untampered NVD sidecar', () => {
  // The integrity check must not refuse legitimate, verifiable values.
  const { dir, NEW_CVE } = buildDiscoveryCache('exceptd-disc-clean-', {
    nvdPayload: NVD_PAYLOAD, nvdIndexed: true, tamperNvd: false,
  });
  try {
    const ctx = { cacheDir: dir, cveCatalog: {} };
    const r = discoverNewKev(ctx);
    assert.equal(r.diffs.length, 1);
    const entry = r.diffs[0].entry;
    assert.equal(r.diffs[0].id, NEW_CVE);
    assert.equal(entry.cvss_score, 9.8, 'verified CVSS is populated');
    assert.equal(entry.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    assert.deepEqual(entry.cwe_refs, ['CWE-787']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
