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

  // v0.12.15 (audit M P1-D): _auto_imported must be the literal boolean
  // `true` so lib/validate-cve-catalog.js's strict draft check
  // (`entry._auto_imported === true`) recognises it as a draft and
  // applies WARNING severity instead of hard-error for missing fields.
  // Provenance (source + imported_at + curation_needed) moved to a
  // sibling `_auto_imported_meta` object.
  assert.equal(entry._auto_imported, true, '_auto_imported must be boolean true for strict-validator draft recognition');
  assert.ok(entry._auto_imported_meta, '_auto_imported_meta provenance block required');
  assert.equal(entry._auto_imported_meta.source, 'KEV discovery');
  assert.ok(Array.isArray(entry._auto_imported_meta.curation_needed));
  assert.ok(entry._auto_imported_meta.curation_needed.length >= 5,
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

test('audit X P1 — buildKevDraftEntry rwep_factors uses schema-required post-weight numeric shape', () => {
  // The CVE catalog JSON schema requires `rwep_factors` to have:
  //   cisa_kev, poc_available, ai_factor, active_exploitation, blast_radius,
  //   patch_available, live_patch_available, reboot_required — all NUMBERS.
  // Pre-fix the auto-discovery builder stored the SHAPE-A boolean +
  // string-ladder bag, which the strict catalog validator (loaded by
  // curate-apply gate) rejected as malformed. Result: KEV-discovered drafts
  // were permanently unpromotable.
  const entry = buildKevDraftEntry({ cveID: 'CVE-2026-55555', vulnerabilityName: 'X' }, null, null);
  const f = entry.rwep_factors;
  // Schema-required keys present and numeric.
  const required = ['cisa_kev', 'poc_available', 'ai_factor', 'active_exploitation',
    'blast_radius', 'patch_available', 'live_patch_available', 'reboot_required'];
  for (const k of required) {
    assert.ok(k in f, `rwep_factors missing required key ${k}`);
    assert.equal(typeof f[k], 'number', `rwep_factors.${k} must be a number, got ${typeof f[k]}`);
    assert.ok(Number.isFinite(f[k]), `rwep_factors.${k} must be finite`);
  }
  // Shape A keys (ai_assisted_weapon, ai_discovered) must NOT pollute the
  // schema-required object — they live in the buildScoringInputs internal
  // bag, not the persisted rwep_factors.
  assert.ok(!('ai_assisted_weapon' in f), 'rwep_factors must not carry SHAPE-A key ai_assisted_weapon');
  assert.ok(!('ai_discovered' in f), 'rwep_factors must not carry SHAPE-A key ai_discovered');
  // Sum of post-weight contributions must reproduce the stored rwep_score
  // (within rounding tolerance) since blast_radius weight=30 mirrors the
  // raw cap — see scoring.js header comment.
  const sum = Object.values(f).reduce((s, v) => s + v, 0);
  assert.ok(Math.abs(sum - entry.rwep_score) <= 1,
    `rwep_factors sum ${sum} must reproduce rwep_score ${entry.rwep_score} (post-weight invariant)`);
});

test('audit X P1 — buildKevDraftEntry rwep_factors numeric values match expected weights', () => {
  // Defaults from buildScoringInputs: cisa_kev=true, poc_available=true,
  // ai=false, active_exploitation='suspected' (0.5 multiplier),
  // blast_radius=15, no patch, no live-patch, reboot_required=true.
  // Expected post-weight contributions (per scoring.RWEP_WEIGHTS):
  //   cisa_kev: 25, poc_available: 20, ai_factor: 0,
  //   active_exploitation: 20 * 0.5 = 10, blast_radius: 15,
  //   patch_available: 0, live_patch_available: 0, reboot_required: 5.
  const entry = buildKevDraftEntry({ cveID: 'CVE-2026-55556' }, null, null);
  const f = entry.rwep_factors;
  assert.equal(f.cisa_kev, 25);
  assert.equal(f.poc_available, 20);
  assert.equal(f.ai_factor, 0);
  assert.equal(f.active_exploitation, 10);
  assert.equal(f.blast_radius, 15);
  assert.equal(f.patch_available, 0);
  assert.equal(f.live_patch_available, 0);
  assert.equal(f.reboot_required, 5);
});

test('audit X P1 — buildKevDraftEntry source_verified is a YYYY-MM-DD string (KEV listing is the verification)', () => {
  // Pre-fix source_verified was null, which (a) violated the strict-catalog
  // schema's `^\d{4}-\d{2}-\d{2}$` pattern and (b) left operators no signal
  // that the KEV listing had in fact authoritatively confirmed the CVE id.
  // Now: stamp with TODAY because the KEV listing IS the verification
  // source for the auto-import.
  const entry = buildKevDraftEntry({ cveID: 'CVE-2026-55557' }, null, null);
  assert.equal(typeof entry.source_verified, 'string',
    'source_verified must be a YYYY-MM-DD string for strict-schema compliance');
  assert.match(entry.source_verified, /^\d{4}-\d{2}-\d{2}$/,
    `source_verified must match YYYY-MM-DD; got ${JSON.stringify(entry.source_verified)}`);
});

test('audit X P1 — buildKevDraftEntry validates against the schema-required active_exploitation enum', () => {
  // active_exploitation is a string on the entry (top-level), not on
  // rwep_factors — the schema enum is { confirmed, suspected, none, unknown }.
  const entry = buildKevDraftEntry({ cveID: 'CVE-2026-55558' }, null, null);
  const allowed = new Set(['confirmed', 'suspected', 'none', 'unknown']);
  assert.ok(allowed.has(entry.active_exploitation),
    `active_exploitation must be one of ${[...allowed].join(', ')}; got ${entry.active_exploitation}`);
});
