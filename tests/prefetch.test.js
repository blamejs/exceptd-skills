'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

test('prefetch --no-network --quiet reports a plan without writing the cache', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--cache-dir', tmp, '--quiet'],
      { encoding: 'utf8' }
    );
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    // Dry-run must not have written any payload to the cache.
    const entries = fs.readdirSync(tmp);
    assert.deepEqual(entries, [], `cache dir should be empty after --no-network; got: ${entries.join(',')}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch --no-network --source <name> respects the source filter', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--source', 'kev', '--cache-dir', tmp],
      { encoding: 'utf8' }
    );
    assert.equal(r.status, 0);
    assert.match(r.stdout, /\[kev\]/);
    assert.doesNotMatch(r.stdout, /\[nvd\]/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch SOURCES has exactly the five expected sources', () => {
  const { SOURCES } = require('../lib/prefetch');
  assert.deepEqual(Object.keys(SOURCES).sort(), ['epss', 'kev', 'nvd', 'pins', 'rfc']);
});

test('prefetch readCached returns null on miss and on stale entries past --max-age', () => {
  const { readCached } = require('../lib/prefetch');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    // No cache at all → null.
    assert.equal(readCached(tmp, 'kev', 'whatever'), null);
    // Write a synthetic entry that's "60 seconds old", then test maxAgeMs.
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify({ vulnerabilities: [] }));
    const olderIso = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({
      generated_at: olderIso,
      entries: {
        'kev/known_exploited_vulnerabilities': { fetched_at: olderIso, etag: null, url: 'x', sha256: 'x' },
      },
    }));
    // 24h default is plenty fresh.
    const fresh = readCached(tmp, 'kev', 'known_exploited_vulnerabilities');
    assert.ok(fresh && fresh.data);
    // 30s threshold → stale.
    const stale = readCached(tmp, 'kev', 'known_exploited_vulnerabilities', { maxAgeMs: 30_000 });
    assert.equal(stale, null);
    // allowStale opt-in returns the entry anyway.
    const forced = readCached(tmp, 'kev', 'known_exploited_vulnerabilities', { maxAgeMs: 30_000, allowStale: true });
    assert.ok(forced && forced.data);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch refuses unknown --source values', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--source', 'made-up'],
    { encoding: 'utf8' }
  );
  assert.equal(r.status, 2, 'unknown --source must exit 2 (flag-validation rejection in prefetch parseArgs)');
  assert.match(r.stderr || '', /unknown source/);
});

// Regression: every entry in the `pins` registry must resolve to a real
// GitHub Releases endpoint. Previously `d3fend__d3fend-data__releases`
// and `mitre__cwe__releases` were 404 on every refresh (their upstream
// projects don't publish via GitHub Releases), surfacing as "2 error(s)"
// in the prefetch summary on a clean install. Pin every id we ship to
// the two MITRE repos that actually have a Releases feed.
test('prefetch pins source contains only repos that publish GitHub Releases', () => {
  const { SOURCES } = require('../lib/prefetch');
  const entries = SOURCES.pins.expand();
  const ids = entries.map((e) => e.id).sort();
  assert.deepEqual(
    ids,
    ['mitre-atlas__atlas-data__releases', 'mitre-attack__attack-stix-data__releases'],
    `pins registry must contain only repos with a real GitHub Releases feed (D3FEND distributes via d3fend-ontology without tagged releases; CWE ships XML from cwe.mitre.org, not GitHub). Got: ${ids.join(',')}`
  );
  // Every URL must target api.github.com/repos/<org>/<repo>/releases —
  // any other shape means we re-introduced the 404 class of bug.
  for (const e of entries) {
    assert.match(e.url, /^https:\/\/api\.github\.com\/repos\/[^/]+\/[^/]+\/releases\?/,
      `pins entry "${e.id}" must point at a GitHub Releases endpoint; got ${e.url}`);
  }
});

// Regression: the libuv `UV_HANDLE_CLOSING` assertion on Windows + Node 25.
// Pre-fix, `node lib/prefetch.js` (or the `refresh --no-network` route
// through bin/exceptd.js) emitted the summary line and then crashed with
// `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file
// src\win\async.c, line 76` and exited 3221226505. The post-fix contract
// is: clean exit code 0 when every source is fresh / dry-run completed,
// no assertion line on stderr. We assert BOTH — checking exit alone would
// have missed the regression on the platforms where the assertion fires
// but the parent shell still reports 0 (which happened when stdout was
// piped).
// v0.12.12 C2 — concurrent prefetch index-merge regression test.
//
// Pre-fix: each prefetch run did `loadIndex → mutate-in-memory → saveIndex`
// at end. Two concurrent runs against the same cache dir both loaded the
// index at start, accumulated their entries in their own in-memory copies,
// then wrote at the end — the second writer overwrote the first run's
// sibling entries.
//
// Post-fix: every per-entry success updates _index.json under a sidecar
// lockfile, merging with whatever the on-disk index currently has. The
// final saveIndex() does the same merge.
//
// The test uses the prefetch API directly rather than spawning subprocesses
// — `withIndexLock` is exercised on the in-process path too, and we don't
// need real network to validate the locking contract. We simulate two
// runs by directly invoking `withIndexLock` from two interleaved
// promises with overlapping writes; the merged result must contain both
// runs' entries.
test('prefetch _index.json: concurrent writers preserve all entries (5x)', async () => {
  // Re-require the module so we get a fresh handle; the helper isn't
  // exported, so we test the contract via two parallel saveIndex-equivalent
  // mutations through the public `prefetch` flow's lock layer. The simplest
  // shape is a direct functional probe of the lock by importing the module
  // and using its readCached + loadIndex round-trip after a synthetic
  // pair of parallel writers.
  for (let trial = 0; trial < 5; trial++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `pf-race-${trial}-`));
    try {
      // Each "writer" emulates a prefetch run by repeatedly mutating the
      // _index.json: it writes 20 entries, racing against a sibling that
      // writes a different 20 entries. Pre-fix this produced a 20-entry
      // result; post-fix it produces a 40-entry result.
      const writer = (prefix) => new Promise((resolve, reject) => {
        const cp = require('child_process').fork(
          path.join(ROOT, 'tests', '_helpers', 'concurrent-prefetch-index-writer.js'),
          [tmp, prefix, '20'],
          { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }
        );
        let err = '';
        cp.stderr.on('data', (b) => { err += b; });
        cp.on('close', (code) => code === 0 ? resolve() : reject(new Error(`writer ${prefix} exited ${code}: ${err}`)));
      });
      await Promise.all([writer('A'), writer('B')]);
      const idxPath = path.join(tmp, '_index.json');
      assert.ok(fs.existsSync(idxPath), `trial ${trial}: _index.json must exist after concurrent writes`);
      const idx = JSON.parse(fs.readFileSync(idxPath, 'utf8'));
      const keys = Object.keys(idx.entries);
      const aCount = keys.filter((k) => k.startsWith('test/A-')).length;
      const bCount = keys.filter((k) => k.startsWith('test/B-')).length;
      assert.equal(aCount, 20, `trial ${trial}: writer A wrote 20 entries, ${aCount} survived in merged index`);
      assert.equal(bCount, 20, `trial ${trial}: writer B wrote 20 entries, ${bCount} survived in merged index`);
      // Field-present + populated: every entry must have a fetched_at
      // timestamp, confirming the on-disk JSON wasn't truncated.
      for (const k of keys) {
        assert.ok(idx.entries[k].fetched_at, `trial ${trial}: entry ${k} missing fetched_at`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
});

test('prefetch exits cleanly with no libuv assertion (Win + Node 25 regression)', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--quiet'],
    { encoding: 'utf8' }
  );
  assert.equal(r.status, 0,
    `prefetch --no-network --quiet must exit 0 — got status=${r.status}, stderr=${JSON.stringify(r.stderr)}`);
  assert.doesNotMatch(r.stderr || '', /Assertion failed/,
    `stderr must not contain the libuv UV_HANDLE_CLOSING assertion line — got ${JSON.stringify(r.stderr)}`);
  assert.doesNotMatch(r.stderr || '', /UV_HANDLE_CLOSING/,
    `stderr must not contain UV_HANDLE_CLOSING — got ${JSON.stringify(r.stderr)}`);
});

// ===========================================================================
// Source: cli-flag-and-envelope-hardening.test.js — prefetch unknown-flag
// rejection (F3). Offline via --no-network; the rejection fires before any
// fetch. Uses the shared cli() harness against bin/exceptd.js.
// ===========================================================================
{
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const pfCli = makeCli(makeSuiteHome('exceptd-flag-envelope-'));

  test('F3: prefetch --badflag -> ok:false exit 2', () => {
    const r = pfCli(['prefetch', '--badflag', '--no-network'], { timeout: 20000 });
    assert.equal(r.status, 2);
    const body = tryJson(r.stderr.trim());
    assert.ok(body, 'must emit a parseable JSON envelope on stderr');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'prefetch');
    assert.deepEqual(body.unknown_flags, ['--badflag']);
    assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--source'));
  });

  test('F3: prefetch --no-network --source kev still runs (dry-run), exit 0', () => {
    const r = pfCli(['prefetch', '--no-network', '--source', 'kev'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /prefetch summary:/);
  });
}


// ---- routed from prefetch-index-fingerprint-pin ----
require("node:test").describe("prefetch-index-fingerprint-pin", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * The --from-cache trust gate verifies _index.json.sig with verifyIndexSignature.
 * Every other signature-verifying ingest site cross-checks the live public key
 * against keys/EXPECTED_FINGERPRINT before crypto.verify, so a host-local
 * keys/public.pem swap paired with an attacker-signed _index.json.sig cannot
 * authenticate against the attacker's own key. verifyIndexSignature must apply
 * the same pin.
 *
 * The happy path is asserted end-to-end (sign with the real key, verify against
 * the real pin -> valid). The mismatch path is asserted against the exact
 * building blocks verifyIndexSignature now consumes — checkExpectedFingerprint
 * over publicKeyFingerprint, with an attacker key and a pin file the attacker
 * cannot satisfy — proving the gate refuses a swapped key.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const prefetch = require(path.join(ROOT, 'lib', 'prefetch.js'));
const { publicKeyFingerprint, checkExpectedFingerprint } = require(path.join(ROOT, 'lib', 'verify.js'));

test('verifyIndexSignature returns valid when the real key matches the real pin', () => {
  // The signing key on the working tree matches keys/EXPECTED_FINGERPRINT, so
  // a freshly-signed index must verify — confirming the new pin check passes
  // legitimate caches through rather than blocking them.
  if (!fs.existsSync(path.join(ROOT, '.keys', 'private.pem'))) {
    return; // no signing key available in this environment; nothing to assert
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-ok-'));
  try {
    fs.writeFileSync(
      path.join(dir, '_index.json'),
      JSON.stringify({ entries: { 'kev/x': { sha256: 'abc' } } }, null, 2) + '\n',
    );
    const s = prefetch.signIndex(dir);
    assert.equal(s.signed, true, 'index signed with the real key');
    const v = prefetch.verifyIndexSignature(dir);
    assert.equal(v.status, 'valid', `expected valid; got ${JSON.stringify(v)}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the pin gate refuses a swapped public key (attacker-signed index would not authenticate)', () => {
  // Generate an attacker keypair and a pin file naming a DIFFERENT (legitimate)
  // fingerprint. The pin check verifyIndexSignature performs is exactly this:
  // checkExpectedFingerprint(publicKeyFingerprint(<live public.pem>)).
  const attacker = crypto.generateKeyPairSync('ed25519');
  const legit = crypto.generateKeyPairSync('ed25519');
  const attackerPem = attacker.publicKey.export({ type: 'spki', format: 'pem' });
  const legitFp = publicKeyFingerprint(legit.publicKey.export({ type: 'spki', format: 'pem' }));

  const pinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-mismatch-'));
  try {
    const pinPath = path.join(pinDir, 'EXPECTED_FINGERPRINT');
    fs.writeFileSync(pinPath, legitFp.sha256 + '\n');

    const result = checkExpectedFingerprint(publicKeyFingerprint(attackerPem), pinPath);
    assert.equal(result.status, 'mismatch', 'swapped key must mismatch the pin');
    assert.equal(result.expected, legitFp.sha256);
    assert.notEqual(result.actual, legitFp.sha256);
    // Without KEYS_ROTATED=1 the rotation override stays false, so
    // verifyIndexSignature returns status:"invalid" on this branch.
    assert.equal(result.rotationOverride, process.env.KEYS_ROTATED === '1');
  } finally {
    fs.rmSync(pinDir, { recursive: true, force: true });
  }
});

test('the pin gate matches when the live fingerprint equals the pin', () => {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  const fp = publicKeyFingerprint(pem);
  const pinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pf-pin-match-'));
  try {
    const pinPath = path.join(pinDir, 'EXPECTED_FINGERPRINT');
    fs.writeFileSync(pinPath, fp.sha256 + '\n');
    const result = checkExpectedFingerprint(publicKeyFingerprint(pem), pinPath);
    assert.equal(result.status, 'match');
  } finally {
    fs.rmSync(pinDir, { recursive: true, force: true });
  }
});
});


// ---- routed from prefetch-max-errors ----
require("node:test").describe("prefetch-max-errors", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Regression: prefetch's warm-cache use must tolerate a few transient per-entry
 * fetch errors without failing the whole refresh.
 *
 * prefetch fans out hundreds (daily) to ~9.7k (Monday) per-CVE/per-RFC fetches
 * against rate-limited public APIs. The errors counter is incremented only
 * after the job queue exhausts its retries, but even so a handful of transient
 * misses per run is expected. Previously `process.exitCode = errors > 0 ? 1 : 0`
 * meant a single transient miss exited 1, and the warm-cache workflow step
 * (bash -e) failed the entire External Data Refresh before the dry-run/apply
 * ever read the cache. `--max-errors <N|N%>` is the tolerance; the default 0
 * preserves the strict any-error-exits-1 contract for a manual operator.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { exitCodeForResult, parseErrorThreshold, formatSummary, parseArgs } = require('../lib/prefetch');

function result(fetched, errors, by_source) {
  return { fetched, skipped_fresh: 0, errors, by_source: by_source || {} };
}

test('exitCodeForResult: default budget 0 keeps the strict manual-operator contract (any error -> 1)', () => {
  assert.equal(exitCodeForResult(result(850, 1), { maxErrors: 0 }), 1);
  // No opts at all must equal the old `errors > 0 ? 1 : 0`.
  assert.equal(exitCodeForResult(result(9737, 1)), 1);
  assert.equal(exitCodeForResult(result(9737, 0)), 0);
});

test('exitCodeForResult: zero errors is always exit 0', () => {
  assert.equal(exitCodeForResult(result(9737, 0), { maxErrors: 0 }), 0);
  assert.equal(exitCodeForResult(result(851, 0), { maxErrors: '50%' }), 0);
});

test('exitCodeForResult: the diagnosed transient runs (1/2/23 errors) pass under the warm-cache tolerance', () => {
  // The exact error counts from the failing refresh runs.
  assert.equal(exitCodeForResult(result(9737, 1), { maxErrors: 50 }), 0, 'Monday full sweep, 1 error');
  assert.equal(exitCodeForResult(result(851, 2), { maxErrors: 50 }), 0, '06-07 daily, 2 errors');
  assert.equal(exitCodeForResult(result(830, 23), { maxErrors: 50 }), 0, '06-06 daily, 23 errors');
});

test('exitCodeForResult: absolute budget is inclusive at the boundary, strict above it', () => {
  assert.equal(exitCodeForResult(result(100, 50), { maxErrors: 50 }), 0, '50 <= 50 passes');
  assert.equal(exitCodeForResult(result(100, 51), { maxErrors: 50 }), 1, '51 > 50 fails');
});

test('exitCodeForResult: a systemic outage still fails over a percentage budget', () => {
  // planned = fetched + skipped_fresh + errors. 50% of 853 -> floor 426.
  assert.equal(exitCodeForResult(result(427, 426), { maxErrors: '50%' }), 0, '426 == floor(0.5*853) passes');
  assert.equal(exitCodeForResult(result(426, 427), { maxErrors: '50%' }), 1, '427 > floor(0.5*853) fails');
  assert.equal(exitCodeForResult(result(353, 500), { maxErrors: '50%' }), 1, 'half-dead upstream fails');
});

test('a source that is entirely unreachable fails regardless of the global budget', () => {
  // A complete KEV outage: 1 planned, 0 landed, 1 error — well under the
  // budget, but the refresh would finish having silently skipped KEV.
  const deadKev = {
    fetched: 800, skipped_fresh: 0, errors: 1,
    by_source: { kev: { fetched: 0, skipped_fresh: 0, errors: 1 }, nvd: { fetched: 800, skipped_fresh: 0, errors: 0 } },
  };
  assert.equal(exitCodeForResult(deadKev, { maxErrors: 50 }), 1, 'a fully-dead feed must fail even under budget');

  // A partially-degraded source (some entries landed) stays tolerated.
  const partial = {
    fetched: 417, skipped_fresh: 0, errors: 23,
    by_source: { nvd: { fetched: 417, skipped_fresh: 0, errors: 23 } },
  };
  assert.equal(exitCodeForResult(partial, { maxErrors: 50 }), 0);

  // An all-fresh source (cache hit, nothing fetched, no errors) does not trip it.
  const allFresh = {
    fetched: 0, skipped_fresh: 440, errors: 0,
    by_source: { nvd: { fetched: 0, skipped_fresh: 440, errors: 0 } },
  };
  assert.equal(exitCodeForResult(allFresh, { maxErrors: 50 }), 0);
});

test('parseErrorThreshold + parseArgs accept integer and percentage; default is 0', () => {
  assert.equal(parseErrorThreshold('50'), 50);
  assert.equal(parseErrorThreshold('5%'), '5%');
  assert.equal(parseArgs(['node', 'prefetch.js']).maxErrors, 0);
  assert.equal(parseArgs(['node', 'prefetch.js', '--max-errors', '50']).maxErrors, 50);
  assert.equal(parseArgs(['node', 'prefetch.js', '--max-errors=5%']).maxErrors, '5%');
});

test('parseErrorThreshold throws on a malformed value (drives exit 2 in main)', () => {
  assert.throws(() => parseErrorThreshold('abc'));
  assert.throws(() => parseErrorThreshold('50%%'));
  assert.throws(() => parseErrorThreshold('-5'));
  // parseArgs records the error rather than throwing, so main() can refuse.
  assert.ok(parseArgs(['node', 'prefetch.js', '--max-errors', 'abc'])._argError);
});

test('a malformed --max-errors exits 2 (usage error), not 1 or a silent unbounded tolerance', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--max-errors', 'abc'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr || r.stdout || '', /invalid --max-errors/);
});

test('formatSummary names the per-source error counts so a --quiet log is actionable', () => {
  const line = formatSummary(result(830, 23, { nvd: { errors: 20 }, epss: { errors: 3 }, kev: { errors: 0 } }), {});
  assert.match(line, /23 error\(s\)/);
  assert.match(line, /nvd=20/);
  assert.match(line, /epss=3/);
  assert.doesNotMatch(line, /kev=/, 'sources with zero errors are omitted from the breakdown');
  // No breakdown bracket when there are no errors.
  assert.doesNotMatch(formatSummary(result(853, 0, { nvd: { errors: 0 } }), {}), /\[/);
});

test('the refresh workflow warm-cache step carries the --max-errors tolerance', () => {
  const yaml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.match(
    yaml,
    /node lib\/prefetch\.js --quiet --max-errors 50\b/,
    'the warm-cache prefetch invocation must pass --max-errors so a transient per-entry miss no longer fails the whole refresh',
  );
});
});


// ---- routed from prefetch-retry-status-field ----
require("node:test").describe("prefetch-retry-status-field", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
// Regression: prefetch's timedFetch must tag HTTP failures with the field the
// vendored retry classifier actually reads (err.statusCode), so a transient
// 429/5xx from a KEV/NVD/EPSS/OSV source routes through the job-queue backoff
// instead of being dropped on the first hiccup. Earlier it set only err.status,
// which vendor/blamejs/retry.js isRetryable never inspects — every retryable
// HTTP status was misclassified non-retryable and the fetch failed after one
// attempt with no backoff.

const test = require('node:test');
const assert = require('node:assert/strict');

const prefetch = require('../lib/prefetch');
const { timedFetch } = prefetch._internal;
const { JobQueue } = require('../lib/job-queue');
const { isRetryable } = require('../vendor/blamejs/retry');

function withStubbedFetch(impl, fn) {
  const orig = global.fetch;
  global.fetch = impl;
  return Promise.resolve()
    .then(fn)
    .finally(() => { global.fetch = orig; });
}

test('timedFetch tags HTTP failures with statusCode the vendored classifier reads', async () => {
  let thrown;
  await withStubbedFetch(
    async () => ({ ok: false, status: 503, headers: { get: () => null }, json: async () => ({}) }),
    async () => {
      try {
        await timedFetch('https://example.test/kev.json');
        assert.fail('expected timedFetch to throw on a 503');
      } catch (err) {
        thrown = err;
      }
    }
  );
  // Exact field + value the classifier keys off, and the classifier verdict.
  assert.equal(thrown.statusCode, 503);
  assert.equal(typeof thrown.statusCode, 'number');
  assert.equal(isRetryable(thrown), true, 'a 503 from timedFetch must classify retryable');
});

test('a transient 503 from timedFetch is retried through the job-queue backoff', async () => {
  const q = new JobQueue({
    sources: { kev: { concurrency: 1 } },
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2, jitterFactor: 0 },
  });
  let calls = 0;
  await withStubbedFetch(
    async () => {
      calls++;
      if (calls <= 2) {
        return { ok: false, status: 503, headers: { get: () => null }, json: async () => ({}) };
      }
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ ok: true }) };
    },
    async () => {
      const res = await q.add({
        source: 'kev',
        run: () => timedFetch('https://example.test/kev.json'),
        meta: { id: 'x' },
      });
      assert.deepEqual(res.json, { ok: true });
    }
  );
  await q.drain();
  const s = q.stats().kev;
  assert.equal(calls, 3, 'timedFetch must be called maxAttempts times for two 503s then a 200');
  assert.equal(s.retried, 2, 'job-queue must record two retries');
  assert.equal(s.completed, 1);
  assert.equal(s.failed, 0);
});

test('a permanent 404 from timedFetch is NOT retried', async () => {
  const q = new JobQueue({
    sources: { kev: { concurrency: 1 } },
    retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2, jitterFactor: 0 },
  });
  let calls = 0;
  await withStubbedFetch(
    async () => {
      calls++;
      return { ok: false, status: 404, headers: { get: () => null }, json: async () => ({}) };
    },
    async () => {
      await assert.rejects(
        q.add({ source: 'kev', run: () => timedFetch('https://example.test/missing.json'), meta: { id: 'y' } }),
        /HTTP 404/
      );
    }
  );
  await q.drain();
  assert.equal(calls, 1, 'a 404 must fail on the first attempt with no retry');
  assert.equal(q.stats().kev.retried, 0);
});
});
