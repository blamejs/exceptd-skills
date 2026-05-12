'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  discoverNewKev,
  buildKevDraftEntry,
  getProjectRfcGroups,
  SEED_RFC_GROUPS,
  DEFAULT_CAP,
} = require('../lib/auto-discovery');

function loadLocalCves() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'cve-catalog.json'), 'utf8'));
}

test('SEED_RFC_GROUPS covers core security/compliance WGs', () => {
  // Smoke: seed should include WGs relevant to the project's main
  // coverage areas — crypto/PKI, identity/auth, supply chain, DNS
  // security, AND production-framework concerns (workload identity,
  // audit-grade time sync, constrained-env auth, CT, CBOR).
  const required = [
    // Transport / crypto / PKI
    'tls', 'cfrg', 'lamps', 'ipsecme',
    // Identity / auth / workload identity / constrained auth
    'oauth', 'gnap', 'jose', 'cose', 'cbor', 'scim', 'acme', 'wimse', 'ace',
    // Supply chain + attestation + transparency
    'scitt', 'rats', 'suit', 'teep', 'trans',
    // DNS security + DANE
    'dnsop', 'dprive', 'dance',
    // Threat intel + ops
    'mile', 'opsawg', 'opsec',
    // Messaging + IoT + time + schema
    'mls', 'core', 'ntp', 'jsonschema',
  ];
  for (const wg of required) {
    assert.ok(SEED_RFC_GROUPS.includes(wg), `seed should include "${wg}" WG (relevant to project)`);
  }
  // Sanity: enough breadth to actually catch new RFCs without being too noisy
  assert.ok(SEED_RFC_GROUPS.length >= 40, `seed should be >= 40 WGs (broader project coverage); got ${SEED_RFC_GROUPS.length}`);
  assert.ok(SEED_RFC_GROUPS.length <= 80, `seed should not exceed ~80 WGs (noisy); got ${SEED_RFC_GROUPS.length}`);
});

test('getProjectRfcGroups returns seed set when no cache and no rfc-references entries', () => {
  const ctx = { rfcCatalog: { _meta: {} }, cacheDir: null };
  const groups = getProjectRfcGroups(ctx);
  for (const wg of SEED_RFC_GROUPS) assert.ok(groups.has(wg), `missing seed WG ${wg}`);
});

test('buildKevDraftEntry produces a complete schema entry from minimal KEV input', () => {
  const kev = {
    cveID: 'CVE-2026-99999',
    vulnerabilityName: 'Acme Widget Remote Code Execution',
    vendorProject: 'Acme',
    product: 'Widget',
    dateAdded: '2026-05-12',
    dueDate: '2026-06-02',
    shortDescription: 'A buffer overflow in Acme Widget allows remote unauthenticated RCE.',
    knownRansomwareCampaignUse: 'Unknown',
  };
  const entry = buildKevDraftEntry(kev, null, null);

  // Required schema fields populated
  assert.equal(entry.cisa_kev, true);
  assert.equal(entry.cisa_kev_date, '2026-05-12');
  assert.equal(entry.cisa_kev_due_date, '2026-06-02');
  assert.equal(entry.active_exploitation, 'suspected');
  assert.ok(entry.affected.includes('Acme'));
  assert.ok(typeof entry.rwep_score === 'number');
  assert.ok(entry.rwep_score >= 25, 'KEV-listed entry should score at least 25 (the KEV weight)');
  assert.ok(Array.isArray(entry.atlas_refs));
  assert.ok(Array.isArray(entry.attack_refs));

  // Auto-imported annotation present + curation list populated
  assert.ok(entry._auto_imported, '_auto_imported block required');
  assert.equal(entry._auto_imported.source, 'KEV discovery');
  assert.ok(Array.isArray(entry._auto_imported.curation_needed));
  assert.ok(entry._auto_imported.curation_needed.length >= 5,
    'curation_needed should enumerate the analytical fields a human still must fill');
});

test('buildKevDraftEntry pulls CVSS from NVD payload when present', () => {
  const kev = { cveID: 'CVE-2026-88888', vulnerabilityName: 'X' };
  const nvdPayload = {
    vulnerabilities: [{
      cve: {
        metrics: {
          cvssMetricV31: [{
            type: 'Primary',
            cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
          }],
        },
        descriptions: [{ lang: 'en', value: 'Test description' }],
        weaknesses: [{ description: [{ value: 'CWE-787' }] }],
      },
    }],
  };
  const entry = buildKevDraftEntry(kev, nvdPayload, null);
  assert.equal(entry.cvss_score, 9.8);
  assert.equal(entry.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.deepEqual(entry.cwe_refs, ['CWE-787']);
});

test('buildKevDraftEntry pulls EPSS score when payload provided', () => {
  const kev = { cveID: 'CVE-2026-77777' };
  const epssPayload = { data: [{ cve: 'CVE-2026-77777', epss: '0.91', percentile: '0.98', date: '2026-05-12' }] };
  const entry = buildKevDraftEntry(kev, null, epssPayload);
  assert.equal(entry.epss_score, 0.91);
  assert.equal(entry.epss_percentile, 0.98);
  assert.equal(entry.epss_date, '2026-05-12');
});

test('discoverNewKev returns empty when cache missing', () => {
  const ctx = { cveCatalog: loadLocalCves(), cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), 'kev-disc-')) };
  try {
    const result = discoverNewKev(ctx);
    assert.equal(result.diffs.length, 0);
    assert.equal(result.errors, 1);
    assert.match(result.summary, /no cached feed/);
  } finally {
    fs.rmSync(ctx.cacheDir, { recursive: true, force: true });
  }
});

test('discoverNewKev finds CVEs in KEV feed but not in local catalog', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-disc-'));
  try {
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify({
      vulnerabilities: [
        // Already in local catalog — should be skipped
        { cveID: 'CVE-2026-31431', dateAdded: '2026-03-15', vulnerabilityName: 'Copy Fail' },
        // New — should be picked up
        { cveID: 'CVE-2026-99001', dateAdded: '2026-05-12', vulnerabilityName: 'New Bug 1', vendorProject: 'Acme', product: 'Widget' },
        { cveID: 'CVE-2026-99002', dateAdded: '2026-05-11', vulnerabilityName: 'New Bug 2' },
      ],
    }));
    const ctx = { cveCatalog: loadLocalCves(), cacheDir: tmp };
    const result = discoverNewKev(ctx);
    assert.equal(result.diffs.length, 2);
    for (const d of result.diffs) {
      assert.equal(d.op, 'add');
      assert.equal(d.target, 'cveCatalog');
      assert.ok(d.entry._auto_imported);
      assert.ok(d.entry.cisa_kev === true);
    }
    // Most recent first
    assert.equal(result.diffs[0].id, 'CVE-2026-99001');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('discoverNewKev caps at DEFAULT_CAP and reports spilled count', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-disc-'));
  try {
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    // 25 brand-new entries
    const vulnerabilities = Array.from({ length: 25 }, (_, i) => ({
      cveID: `CVE-2026-9${String(1000 + i).padStart(4, '0')}`,
      dateAdded: `2026-05-${String((i % 28) + 1).padStart(2, '0')}`,
      vulnerabilityName: `Synthetic ${i}`,
    }));
    fs.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify({ vulnerabilities }));
    const ctx = { cveCatalog: loadLocalCves(), cacheDir: tmp };
    const result = discoverNewKev(ctx, DEFAULT_CAP);
    assert.equal(result.diffs.length, DEFAULT_CAP);
    assert.equal(result.spilled, 5);
    assert.match(result.summary, /spilled past cap/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('buildKevDraftEntry rwep_score is bounded 0..100', () => {
  const entry = buildKevDraftEntry({ cveID: 'CVE-2026-12345' }, null, null);
  assert.ok(entry.rwep_score >= 0 && entry.rwep_score <= 100, `rwep_score out of bounds: ${entry.rwep_score}`);
});
