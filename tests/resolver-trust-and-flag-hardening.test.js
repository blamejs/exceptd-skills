'use strict';

/**
 * Resolver-trust + flag-hardening regression suite.
 *
 * Pins three independently-exploitable contracts so they can't silently
 * regress:
 *
 *   1. Resolved-cache integrity (lib/citation-resolve.js). A resolved record is
 *      only trusted when it carries a sha256 `_digest` over its own canonical
 *      bytes AND its embedded `resolved_at` is inside the freshness window.
 *      A poisoned/tampered/stale/future-dated file cannot launder a verdict —
 *      it reads back as a cache miss and the resolver falls through to
 *      offline/unknown. This is the security headline: an operator-writable
 *      cache directory can never turn a rejected/fabricated citation into a
 *      "published" one.
 *
 *   2. Unknown-flag rejection on the cve/rfc resolvers. A swallowed `--josn`
 *      would emit human text into a pipe that asked for JSON and defeat a CI
 *      gate, so an unrecognized flag is a hard exit 1 with an ok:false envelope.
 *
 *   3. Evidence-shape / --max-rwep / --format guards on run + ci. `null`, an
 *      array, or a scalar parse as valid JSON but are not a submission; a
 *      non-numeric or negative cap would degenerate the gate; `--format`
 *      explicitly overrides `--json`.
 *
 * Plus the applyResolution RFC-flip contract (a cited RFC number that resolves
 * to nothing is a bad citation; an obsoleted-but-real RFC is not).
 *
 * Discipline (project anti-coincidence rules): assert EXACT exit codes (never
 * notEqual(0)); pair every field-presence check with a value/type assertion;
 * never weaken a test to make it pass. Every test is deterministic and offline:
 * cache tests inject a per-suite EXCEPTD_RESOLVE_CACHE_DIR and a tiny catalog
 * fixture WITHOUT the test ids (so the resolver reaches the cache path), and
 * pass { noNetwork: true } so no network is touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// --- isolated resolved-cache dir + a tiny catalog fixture that deliberately
//     does NOT contain the ids these tests resolve, so resolveCve falls past
//     the catalog branch into the cache branch. Both env vars are set BEFORE
//     require('../lib/citation-resolve.js') — the catalog path is read +
//     memoized at module-require time; the cache dir is read at call time but
//     is set here too to be safe. --------------------------------------------
const CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-cache-'));
const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-fixture-'));
const CVE_FIXTURE = path.join(FIXTURE_DIR, 'cve-catalog.json');

// A catalog hit for the CLI fixture-id test, but NONE of the cache-integrity
// test ids, so those reach the cache path rather than short-circuiting here.
const CVE_FIXTURE_DATA = {
  'CVE-2030-0001': {
    cvss_score: 9.8,
    cisa_kev: true,
    name: 'FixtureVuln',
    status: 'published',
  },
};
fs.writeFileSync(CVE_FIXTURE, JSON.stringify(CVE_FIXTURE_DATA, null, 2));

process.on('exit', () => {
  try { fs.rmSync(CACHE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(FIXTURE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
});

process.env.EXCEPTD_CVE_CATALOG = CVE_FIXTURE;
process.env.EXCEPTD_RESOLVE_CACHE_DIR = CACHE_DIR;

const { resolveCve } = require('../lib/citation-resolve.js');
const citationHygiene = require('../lib/collectors/citation-hygiene.js');

// Spawned-CLI harness. Pass the fixture catalog + isolated cache dir as env
// overrides so subprocesses resolve offline against them, not the network.
const SUITE_HOME = makeSuiteHome('exceptd-resolver-trust-');
const baseCli = makeCli(SUITE_HOME);
const RESOLVER_ENV = {
  EXCEPTD_CVE_CATALOG: CVE_FIXTURE,
  EXCEPTD_RESOLVE_CACHE_DIR: CACHE_DIR,
};
function cli(args, opts = {}) {
  return baseCli(args, { ...opts, env: { ...RESOLVER_ENV, ...(opts.env || {}) } });
}

// --- digest helper: replicate lib/citation-resolve.js recordDigest exactly so
//     a test can write a VALID (trusted) cache record. sha256 over the record's
//     canonical JSON: keys sorted, `_digest` excluded. ------------------------
function recordDigest(rec) {
  const canon = {};
  for (const k of Object.keys(rec).sort()) {
    if (k === '_digest') continue;
    canon[k] = rec[k];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}
function writeRawCveCache(id, rec) {
  const dir = path.join(CACHE_DIR, 'cve');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(rec));
  return path.join(dir, `${id}.json`);
}
function writeDigestedCveCache(id, rec) {
  const signed = { ...rec };
  signed._digest = recordDigest(signed);
  return writeRawCveCache(id, signed);
}

// ===================================================================
// 1. Resolved-cache integrity
// ===================================================================

test('cache integrity: a valid digested record (fresh, rejected) reads back as a cache hit', async () => {
  const id = 'CVE-2099-30001';
  writeDigestedCveCache(id, {
    id, kind: 'cve', status: 'rejected', source: 'nvd',
    resolved_at: new Date().toISOString(),
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.status, 'rejected');
  assert.equal(r.from, 'cache');
  assert.equal(r.id, id);
});

test('cache integrity: a POISONED record (status published, NO _digest) cannot launder a verdict', async () => {
  // Headline: an attacker who can write the cache dir drops a well-formed
  // "published" verdict with no digest. It must be rejected — never published,
  // never a cache hit.
  const id = 'CVE-2099-30002';
  writeRawCveCache(id, {
    id, kind: 'cve', status: 'published', source: 'nvd',
    resolved_at: new Date().toISOString(),
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.notEqual(r.status, 'published'); // allow-notEqual: security refusal-pin — a poisoned/tampered record must NEVER surface as published; exact verdict pinned below
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
});

test('cache integrity: a record with a WRONG _digest is rejected (poisoning signal)', async () => {
  const id = 'CVE-2099-30003';
  writeRawCveCache(id, {
    id, kind: 'cve', status: 'published', source: 'nvd',
    resolved_at: new Date().toISOString(),
    _digest: 'deadbeef'.repeat(8), // 64 hex chars, but not the real digest
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
});

test('cache integrity: TAMPERED record (valid digest, then status flipped) is rejected on mismatch', async () => {
  const id = 'CVE-2099-30004';
  const file = writeDigestedCveCache(id, {
    id, kind: 'cve', status: 'rejected', source: 'nvd',
    resolved_at: new Date().toISOString(),
  });
  // Rewrite the file flipping status to 'published' but keeping the OLD digest.
  const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
  rec.status = 'published';
  fs.writeFileSync(file, JSON.stringify(rec)); // digest now stale w.r.t. content
  const r = await resolveCve(id, { noNetwork: true });
  assert.notEqual(r.status, 'published'); // allow-notEqual: security refusal-pin — a poisoned/tampered record must NEVER surface as published; exact verdict pinned below
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
});

test('cache integrity: STALE record (valid digest, resolved_at 8 days ago) is rejected on freshness', async () => {
  const id = 'CVE-2099-30005';
  writeDigestedCveCache(id, {
    id, kind: 'cve', status: 'rejected', source: 'nvd',
    resolved_at: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
});

test('cache integrity: FUTURE-DATED record (valid digest, resolved_at +1h) is rejected', async () => {
  const id = 'CVE-2099-30006';
  writeDigestedCveCache(id, {
    id, kind: 'cve', status: 'rejected', source: 'nvd',
    resolved_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.status, 'unknown');
  assert.equal(r.from, 'offline');
});

test('cache integrity: the internal _digest field is never surfaced on a cache hit', async () => {
  const id = 'CVE-2099-30007';
  writeDigestedCveCache(id, {
    id, kind: 'cve', status: 'rejected', source: 'nvd',
    resolved_at: new Date().toISOString(),
  });
  const r = await resolveCve(id, { noNetwork: true });
  assert.equal(r.from, 'cache');
  assert.equal('_digest' in r, false);
});

// ===================================================================
// 2. cve / rfc unknown-flag rejection (spawned CLIs)
// ===================================================================

test('cve CLI: unknown flag --josn exits 1 with ok:false + unknown_flags', () => {
  const r = cli(['cve', 'CVE-2025-0001', '--josn', '--air-gap']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'cve');
  assert.ok(Array.isArray(body.unknown_flags), 'unknown_flags must be an array');
  assert.ok(body.unknown_flags.includes('--josn'),
    `unknown_flags should include "--josn"; got ${JSON.stringify(body.unknown_flags)}`);
});

test('rfc CLI: unknown flag --notaflag exits 1 with ok:false + unknown_flags', () => {
  const r = cli(['rfc', '9404', '--notaflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'rfc');
  assert.ok(Array.isArray(body.unknown_flags), 'unknown_flags must be an array');
  assert.ok(body.unknown_flags.includes('--notaflag'),
    `unknown_flags should include "--notaflag"; got ${JSON.stringify(body.unknown_flags)}`);
});

test('cve CLI: known flags --air-gap --json on a catalog hit exit 0 with published envelope', () => {
  // Fixture id IS in the catalog, status published -> exit 0 (not the rejected/
  // fabricated/nonexistent/withdrawn exit-2 path).
  const r = cli(['cve', 'CVE-2030-0001', '--air-gap', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'cve');
  assert.equal(body.status, 'published');
});

// ===================================================================
// 3. run evidence-shape guard
// ===================================================================

for (const bad of [
  { label: 'null', input: 'null' },
  { label: 'array', input: '[]' },
  { label: 'string', input: '"astring"' },
  { label: 'number', input: '123' },
]) {
  test(`run CLI: --evidence - with ${bad.label} exits 1 with "evidence must be a JSON object"`, () => {
    const r = cli(['run', 'secrets', '--evidence', '-'], { input: bad.input });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stderr.trim());
    assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.match(body.error, /evidence must be a JSON object/);
  });
}

test('run CLI: --evidence - with an empty object {} runs (exit 0, not the shape error)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
});

// ===================================================================
// 4. applyResolution RFC flip
// ===================================================================

test('applyResolution: a nonexistent RFC citation flips rfc-number-title-mismatch to hit', async () => {
  const submission = {
    signal_overrides: {},
    needs_verification: { cve_not_in_catalog: [], rfc_not_in_index: [{ file: 'x', citation: 'RFC 88888' }] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({}),
    _resolveRfc: async () => ({ status: 'nonexistent', found: false }),
  });
  assert.equal(out.signal_overrides['rfc-number-title-mismatch'], 'hit');
});

test('applyResolution: an obsoleted-but-real RFC does NOT flip rfc-number-title-mismatch to hit', async () => {
  const submission = {
    signal_overrides: {},
    needs_verification: { cve_not_in_catalog: [], rfc_not_in_index: [{ file: 'x', citation: 'RFC 88888' }] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({}),
    _resolveRfc: async () => ({ status: 'obsoleted-or-historic', found: true }),
  });
  assert.notEqual(out.signal_overrides['rfc-number-title-mismatch'], 'hit');
});

// ===================================================================
// 5. ci --max-rwep validation
// ===================================================================

test('ci CLI: --max-rwep abc exits 1 with "non-negative number"', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', 'abc']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /non-negative number/);
});

test('ci CLI: --max-rwep -5 (negative) exits 1 with "non-negative number"', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', '-5']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /non-negative number/);
});

test('ci CLI: --max-rwep 70 (valid) runs — not the validation error', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', '70']);
  // A clean no-evidence ci run with a valid cap PASSes the gate (exit 0); the
  // point of this assertion is that the cap was accepted, not the exact verdict.
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'ci');
});

// ===================================================================
// 6. --format overrides --json (note on stderr, markdown on stdout)
// ===================================================================

test('run CLI: --format markdown overrides --json — stdout is markdown, stderr carries the note', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json', '--format', 'markdown'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.equal(r.stdout.trimStart()[0], '#',
    `stdout should be a markdown document (starts with '#'); got: ${r.stdout.slice(0, 80)}`);
  assert.match(r.stderr, /overrides --json/);
});

// ===================================================================
// 7. help lists the cve / rfc / collect verbs
// ===================================================================

test('help: top-level help lists the cve, rfc and collect verbs', () => {
  const r = cli(['help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /^  cve /m);
  assert.match(r.stdout, /^  rfc /m);
  assert.match(r.stdout, /^  collect /m);
});
