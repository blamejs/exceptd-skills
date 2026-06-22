"use strict";


// ---- routed from orchestrator-cache-integrity ----
require("node:test").describe("orchestrator-cache-integrity", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
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
});


// ---- routed from orchestrator-envelope ----
require("node:test").describe("orchestrator-envelope", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Every orchestrator error surface must emit the structured ok:false envelope
 * when a JSON consumer is downstream — including the framework-gap catalog-read
 * failure and the top-level fatal handler, which previously printed plain text.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');

const baseEnv = () => ({
  ...process.env,
  EXCEPTD_SUPPRESS_DEPRECATION: '1',
});

// framework-gap's catalog-read catch must honor --json. Drive main() with
// fs.readFileSync forced to throw for the catalog files, so the real catch
// path runs without touching the shipped data/ tree.
test('framework-gap catalog-read failure emits ok:false JSON under --json', () => {
  const script = `
    const fs = require('fs');
    const orig = fs.readFileSync;
    fs.readFileSync = function (p, ...rest) {
      if (typeof p === 'string' && /framework-control-gaps\\.json$|cve-catalog\\.json$/.test(p)) {
        const e = new Error('forced read failure');
        e.code = 'EIO';
        throw e;
      }
      return orig.call(this, p, ...rest);
    };
    process.argv = [process.argv[0], ${JSON.stringify(ORCH)}, 'framework-gap', 'NIST-800-53', 'CVE-2026-31431', '--json'];
    const orch = require(${JSON.stringify(ORCH)});
    orch.main().then(() => { process.exitCode = process.exitCode || 0; });
  `;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: baseEnv() });
  assert.equal(r.status, 1, `expected GENERIC_FAILURE exit 1; got ${r.status} stderr=${r.stderr}`);
  // Envelope lands on stdout (where the verb's other --json error paths write).
  const parsed = JSON.parse(r.stdout.trim());
  assert.equal(parsed.ok, false);
  assert.equal(parsed.verb, 'framework-gap');
  assert.equal(typeof parsed.error, 'string');
  assert.match(parsed.error, /cannot read catalog/);
});

// Without --json the same path stays human-readable on stderr.
test('framework-gap catalog-read failure stays plain text without --json', () => {
  const script = `
    const fs = require('fs');
    const orig = fs.readFileSync;
    fs.readFileSync = function (p, ...rest) {
      if (typeof p === 'string' && /framework-control-gaps\\.json$|cve-catalog\\.json$/.test(p)) {
        throw new Error('forced read failure');
      }
      return orig.call(this, p, ...rest);
    };
    process.argv = [process.argv[0], ${JSON.stringify(ORCH)}, 'framework-gap', 'NIST-800-53', 'CVE-2026-31431'];
    require(${JSON.stringify(ORCH)}).main();
  `;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: baseEnv() });
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  assert.match(r.stderr, /\[framework-gap\] cannot read catalog/);
  assert.equal(r.stdout.trim(), '', 'human path must not emit JSON on stdout');
});

// The top-level fatal handler must emit a parseable ok:false envelope on
// stderr, not the legacy plain-text "[orchestrator] Fatal:" line.
test('orchestrator fatal handler emits ok:false JSON envelope on stderr', () => {
  // Patch the scanner so scan() throws an uncaught error that escapes runScan
  // and reaches main().catch(). require.main === module here (direct spawn),
  // so the fatal handler fires.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-fatal-'));
  const preloadPath = path.join(tmp, 'preload.js');
  const scannerPath = path.join(ROOT, 'orchestrator', 'scanner.js');
  fs.writeFileSync(preloadPath, [
    "'use strict';",
    "const Module = require('module');",
    `const scannerPath = ${JSON.stringify(scannerPath)};`,
    'const orig = Module._load;',
    'Module._load = function (request, parent, isMain) {',
    '  let resolved = request;',
    '  try { resolved = Module._resolveFilename(request, parent, isMain); } catch { /* keep request */ }',
    '  if (resolved === scannerPath) {',
    "    return { scan: () => { throw new Error('synthetic scan failure'); }, scanDomain: () => {}, sanitizeConfig: (x) => x };",
    '  }',
    '  return orig.apply(this, arguments);',
    '};',
    '',
  ].join('\n'));

  try {
    const r = spawnSync(process.execPath, ['--require', preloadPath, ORCH, 'scan', '--json'], {
      encoding: 'utf8',
      env: baseEnv(),
    });
    assert.equal(r.status, 1, `expected exit 1 on fatal; got ${r.status} stderr=${r.stderr}`);
    // The last stderr line is the fatal envelope; parse it.
    const lines = r.stderr.trim().split(/\r?\n/).filter(Boolean);
    const last = lines[lines.length - 1];
    const parsed = JSON.parse(last);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.verb, 'scan');
    assert.equal(typeof parsed.error, 'string');
    assert.match(parsed.error, /synthetic scan failure/);
    // The legacy plain-text marker must be gone.
    assert.ok(!r.stderr.includes('[orchestrator] Fatal:'), 'plain-text fatal marker must not appear');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});


// ---- routed from orchestrator-redaction ----
require("node:test").describe("orchestrator-redaction", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * sanitizeConfig must scrub credentials from scanner findings at any nesting
 * depth before they reach stdout. MCP server configs place real secrets inside
 * `env` and `headers` sub-objects, so a top-level-only sweep leaks them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { sanitizeConfig } = require('../orchestrator/scanner');

test('sanitizeConfig redacts secret-named keys nested inside env and headers', () => {
  const out = sanitizeConfig({
    command: 'npx',
    args: ['-y', 'some-mcp-server'],
    env: {
      OPENAI_API_KEY: 'sk-proj-LEAKEDsecret0001',
      AUTH_TOKEN: 'bearer-LEAKEDsecret0002',
      PATH: '/usr/bin',
    },
    headers: {
      Authorization: 'Bearer LEAKEDsecret0003headervalue',
      Accept: 'application/json',
    },
  });

  // Secret-named keys redacted regardless of depth.
  assert.equal(out.env.OPENAI_API_KEY, '[REDACTED]');
  assert.equal(out.env.AUTH_TOKEN, '[REDACTED]');
  assert.equal(out.headers.Authorization, '[REDACTED]');

  // Benign values preserved so the finding stays useful.
  assert.equal(out.command, 'npx');
  assert.deepEqual(out.args, ['-y', 'some-mcp-server']);
  assert.equal(out.env.PATH, '/usr/bin');
  assert.equal(out.headers.Accept, 'application/json');

  // No secret substring survives anywhere in the serialized output.
  const serialized = JSON.stringify(out);
  for (const leak of ['sk-proj-LEAKED', 'bearer-LEAKED', 'LEAKEDsecret0003']) {
    assert.ok(!serialized.includes(leak), `leaked credential survived redaction: ${leak}`);
  }
});

test('sanitizeConfig redacts top-level secret keys (existing behavior preserved)', () => {
  const out = sanitizeConfig({ apiKey: 'top-secret-value', password: 'hunter2', name: 'demo' });
  assert.equal(out.apiKey, '[REDACTED]');
  assert.equal(out.password, '[REDACTED]');
  assert.equal(out.name, 'demo');
});

test('sanitizeConfig redacts credential-shaped values under benign key names', () => {
  // A secret can appear positionally (e.g. args: ['--token', 'sk-...']) where
  // the surrounding key name gives no hint.
  const out = sanitizeConfig({
    args: ['--header', 'Bearer abcdEFGH1234567890token'],
    nested: { positional: 'sk-proj-anotherLeakedKey99' },
  });
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes('Bearer abcdEFGH'), 'bearer value must be redacted by shape');
  assert.ok(!serialized.includes('sk-proj-anotherLeaked'), 'sk- value must be redacted by shape');
});

test('sanitizeConfig redacts secrets inside arrays of objects', () => {
  const out = sanitizeConfig({
    servers: [
      { name: 'a', env: { API_KEY: 'sk-deepArrayLeak001' } },
      { name: 'b', secret: 'do-not-emit' },
    ],
  });
  assert.equal(out.servers[0].env.API_KEY, '[REDACTED]');
  assert.equal(out.servers[1].secret, '[REDACTED]');
  assert.equal(out.servers[0].name, 'a');
  assert.equal(out.servers[1].name, 'b');
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes('sk-deepArrayLeak'), 'array-nested key must be redacted');
  assert.ok(!serialized.includes('do-not-emit'), 'array-nested secret value must be redacted');
});

test('sanitizeConfig tolerates cycles without throwing', () => {
  const a = { token: 'sk-cycleLeak0001', child: {} };
  a.child.parent = a;
  const out = sanitizeConfig(a);
  assert.equal(out.token, '[REDACTED]');
  assert.equal(out.child.parent, '[CIRCULAR]');
});

test('sanitizeConfig passes non-object inputs through unchanged when benign', () => {
  assert.equal(sanitizeConfig('plain-string'), 'plain-string');
  assert.equal(sanitizeConfig(42), 42);
  assert.equal(sanitizeConfig(null), null);
});
});
