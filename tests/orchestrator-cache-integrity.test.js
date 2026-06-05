'use strict';

/**
 * validate-cves --from-cache must verify each cached upstream payload against
 * the sha256 recorded in the prefetch _index.json before trusting it. A cache
 * file rewritten after prefetch (forging matching CVSS/KEV values to mask
 * drift) must be refused so the drift signal cannot be silently suppressed.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');
const VALIDATORS = path.join(ROOT, 'sources', 'validators', 'index.js');

// sha256 over JSON.stringify(payload) — the exact fingerprint lib/prefetch.js
// records at fetch time, which the consumer re-derives by parse + re-stringify.
function recordedSha(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

// Write a payload to <cacheDir>/<source>/<id>.json the way prefetch does
// (indented + trailing newline) and return the sha256 of its canonical form.
function writeCacheFile(cacheDir, source, id, payload) {
  const dir = path.join(cacheDir, source);
  fs.mkdirSync(dir, { recursive: true });
  const safe = id.replace(/[^A-Za-z0-9._-]/g, '_');
  fs.writeFileSync(path.join(dir, `${safe}.json`), JSON.stringify(payload, null, 2) + '\n');
  return recordedSha(payload);
}

// Build a preload that replaces the live validator with an instant stub, so a
// full-catalog run never touches the network and finishes fast. Cache misses
// then surface as 'unreachable' instead of real upstream lookups.
function stubValidatorsPreload(tmp) {
  const p = path.join(tmp, 'stub-validators.js');
  fs.writeFileSync(p, [
    "'use strict';",
    'const Module = require("module");',
    `const target = ${JSON.stringify(VALIDATORS)};`,
    'const orig = Module._load;',
    'Module._load = function (request, parent, isMain) {',
    '  let resolved = request;',
    '  try { resolved = Module._resolveFilename(request, parent, isMain); } catch { /* keep */ }',
    '  if (resolved === target) {',
    '    return {',
    '      validateCve: async (id, local) => ({ cve_id: id, status: "unreachable", discrepancies: [], fetched: { sources: { nvd: null, kev: null, epss: null } }, local }),',
    '      validateAllCves: async () => ({ results: [], by_status: {}, total: 0 }),',
    '    };',
    '  }',
    '  return orig.apply(this, arguments);',
    '};',
    '',
  ].join('\n'));
  return p;
}

test('validate-cves --from-cache refuses a cache payload whose sha256 mismatches the index', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cve-cache-tamper-'));
  try {
    const cacheDir = path.join(tmp, 'upstream');
    const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
    const cveId = Object.keys(catalog).find((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));

    // A KEV feed that forges this CVE as present, plus a clean NVD payload.
    const kevPayload = { vulnerabilities: [{ cveID: cveId, dateAdded: '2099-01-01' }] };
    const nvdPayload = { vulnerabilities: [{ cve: { metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 1.0, vectorString: 'CVSS:3.1/AV:N' } }] } } }] };

    // Write both; record the CLEAN sha for NVD but a DELIBERATELY WRONG sha for
    // KEV — simulating a post-prefetch on-disk rewrite of the KEV feed.
    const nvdSha = writeCacheFile(cacheDir, 'nvd', cveId, nvdPayload);
    writeCacheFile(cacheDir, 'kev', 'known_exploited_vulnerabilities', kevPayload);

    const index = {
      entries: {
        [`nvd/${cveId}`]: { sha256: nvdSha, fetched_at: new Date().toISOString() },
        ['kev/known_exploited_vulnerabilities']: { sha256: 'deadbeef'.repeat(8), fetched_at: new Date().toISOString() },
      },
    };
    fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify(index, null, 2) + '\n');

    const preload = stubValidatorsPreload(tmp);
    const r = spawnSync(process.execPath, ['--require', preload, ORCH, 'validate-cves', '--from-cache', cacheDir, '--no-fail'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_SUPPRESS_DEPRECATION: '1' },
      timeout: 60000,
    });

    // The tampered KEV file must be flagged and refused.
    assert.match(r.stderr, /cache integrity: sha256 mismatch for kev\/known_exploited_vulnerabilities/);
    // The clean NVD entry must NOT be flagged for that CVE.
    assert.ok(!new RegExp(`sha256 mismatch for nvd/${cveId}`).test(r.stderr), 'clean NVD entry must verify');
    // --no-fail keeps the exit code at success; the contract under test is the
    // refusal of tampered data, not the drift exit branch.
    assert.equal(r.status, 0, `expected exit 0 with --no-fail; got ${r.status} stderr=${r.stderr}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('validate-cves --from-cache trusts a payload whose sha256 matches the index', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cve-cache-clean-'));
  try {
    const cacheDir = path.join(tmp, 'upstream');
    const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
    const cveId = Object.keys(catalog).find((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));

    // A clean NVD payload whose recorded sha matches its on-disk content. The
    // baseScore differs from the catalog so a trusted read yields visible drift
    // (proving the value was actually consumed, not silently dropped).
    const nvdPayload = { vulnerabilities: [{ cve: { metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 0.5, vectorString: 'CVSS:3.1/AV:L' } }] } } }] };
    const nvdSha = writeCacheFile(cacheDir, 'nvd', cveId, nvdPayload);
    const index = { entries: { [`nvd/${cveId}`]: { sha256: nvdSha, fetched_at: new Date().toISOString() } } };
    fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify(index, null, 2) + '\n');

    const preload = stubValidatorsPreload(tmp);
    const r = spawnSync(process.execPath, ['--require', preload, ORCH, 'validate-cves', '--from-cache', cacheDir, '--no-fail'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_SUPPRESS_DEPRECATION: '1' },
      timeout: 60000,
    });

    // No integrity warning for the clean entry.
    assert.ok(!/cache integrity/.test(r.stderr), `clean cache must not warn; stderr=${r.stderr}`);
    // The trusted NVD value (0.5) drives a drift row for that CVE in the table.
    assert.match(r.stdout, new RegExp(`${cveId}[^\\n]*0\\.5 DRIFT`));
    assert.equal(r.status, 0, `expected exit 0 with --no-fail; got ${r.status} stderr=${r.stderr}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('validate-cves --from-cache refuses a cache payload absent from the index', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cve-cache-noindex-'));
  try {
    const cacheDir = path.join(tmp, 'upstream');
    const kevPayload = { vulnerabilities: [] };
    writeCacheFile(cacheDir, 'kev', 'known_exploited_vulnerabilities', kevPayload);
    // _index.json present but with NO entry for the KEV feed.
    fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify({ entries: {} }, null, 2) + '\n');

    const preload = stubValidatorsPreload(tmp);
    const r = spawnSync(process.execPath, ['--require', preload, ORCH, 'validate-cves', '--from-cache', cacheDir, '--no-fail'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_SUPPRESS_DEPRECATION: '1' },
      timeout: 60000,
    });

    assert.match(r.stderr, /cache integrity: no recorded sha256 for kev\/known_exploited_vulnerabilities/);
    assert.equal(r.status, 0, `expected exit 0 with --no-fail; got ${r.status} stderr=${r.stderr}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
