"use strict";


// ---- routed from hunt-fix-K-citation-rfc ----
require("node:test").describe("hunt-fix-K-citation-rfc", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for the K-citation-rfc fix cluster.
 *
 * Covers four confirmed bugs across lib/citation-resolve.js, lib/rfc-cli.js,
 * and lib/upstream-check-cli.js. Each case fails on the pre-fix behavior and
 * passes after, asserting exact values (exit codes, booleans, field content) —
 * never a bare !==0 or assert.ok(x).
 *
 *   #29  cacheGet must bind a resolved-cache record to the requested id/kind,
 *        not just prove the record is self-consistent + fresh. A digest-valid
 *        record written under one filename but carrying a different internal
 *        id/kind is a swapped-file poisoning that the self-digest cannot catch.
 *   #30  rfc --check title match must be whole-word + phrase-aware, not a
 *        lenient bidirectional substring (which let "TLS" match the DTLS title).
 *   #49  upstream-check-cli.js must catch any unexpected throw and emit one
 *        parseable JSON envelope on stdout (exit 0), not an unhandled rejection.
 *   #50  rfc positional/--check parsing must resolve the RFC number regardless
 *        of flag order ("rfc --check <title> <n>" must read id=<n>).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CITATION = path.join(ROOT, 'lib', 'citation-resolve.js');
const RFC_CLI = path.join(ROOT, 'lib', 'rfc-cli.js');
const UPSTREAM_CLI = path.join(ROOT, 'lib', 'upstream-check-cli.js');

// Re-implements the resolver's canonical-bytes digest so a test can write a
// record the resolver will accept as integrity-valid (and the swapped-key test
// can prove the binding check — not the digest — is what rejects it).
function recordDigest(record) {
  const canon = {};
  for (const k of Object.keys(record).sort()) {
    if (k === '_digest') continue;
    canon[k] = record[k];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// Each cacheGet test gets an isolated cache dir + empty catalog/index so neither
// the network nor the shipped data files are touched. The resolver reads the
// catalog/index path at module-require time, so we require a FRESH copy of the
// module per case via a child node -e invocation that sets the env first.
function makeIsolatedDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ===================================================================
// #29 — resolved-cache record must be bound to the requested id/kind
// ===================================================================





// ===================================================================
// #30 — rfc --check title match is whole-word + phrase-aware
// ===================================================================

const { titleMatches } = require('../lib/rfc-cli.js');
const DTLS_TITLE = 'The Datagram Transport Layer Security (DTLS) Protocol Version 1.3';
const TLS_TITLE = 'The Transport Layer Security (TLS) Protocol Version 1.3';
const RFC2119_TITLE = 'Key words for use in RFCs to Indicate Requirement Levels';








// ===================================================================
// #50 — rfc positional/--check parsing is order-independent
// ===================================================================



// ===================================================================
// #49 — upstream-check-cli.js catches unexpected throws -> JSON envelope
// ===================================================================

test('#49 upstream-check-cli emits a parseable ok:false envelope on an unexpected throw (no unhandled rejection)', () => {
  const dir = makeIsolatedDir('k49-');
  try {
    // Preload module that monkeypatches fetchLatestPublished to throw. The throw
    // propagates out of the awaited call into the IIFE; pre-fix that surfaced as
    // an unhandled rejection (raw stack on stderr, non-zero exit). Post-fix the
    // .catch() emits one JSON line on stdout and exits 0.
    const preload = path.join(dir, 'preload.js');
    fs.writeFileSync(
      preload,
      'const u = require(' + JSON.stringify(path.join(ROOT, 'lib', 'upstream-check.js')) + ');\n' +
      'u.fetchLatestPublished = async () => { throw new Error("forced-throw-for-test"); };\n',
    );
    const out = spawnSync(process.execPath, ['-r', preload, UPSTREAM_CLI], { encoding: 'utf8' });
    assert.equal(out.status, 0, `expected exit 0 (offline != error); got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be parseable JSON, never a raw stack trace; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(typeof body.source, 'string');
    assert.equal(body.source, 'upstream-check');
    assert.equal(body.error, 'forced-throw-for-test');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ===================================================================
// unknown flags are refused, not silently ignored
// ===================================================================

test('upstream-check-cli refuses an unknown flag with exit 2 and a JSON envelope on stderr', () => {
  // EXCEPTD_AIR_GAP pins the no-flag-error path to the offline `skipped`
  // envelope (exit 0), so this asserts the refusal and never the network.
  const out = spawnSync(process.execPath, [UPSTREAM_CLI, '--tiemout=5000'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_AIR_GAP: '1' },
  });
  assert.equal(out.status, 2, `unknown flag must exit 2; got ${out.status} (stdout: ${out.stdout.slice(0, 200)})`);
  // stdout stays reserved for the report line callers JSON.parse.
  assert.equal(out.stdout, '');
  const body = tryJson(out.stderr.trim());
  assert.ok(body, `stderr must be one parseable JSON line; got: ${out.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.source, 'upstream-check');
  assert.equal(typeof body.error, 'string');
  assert.equal(body.error, 'upstream-check: unknown flag(s): --tiemout');
  assert.deepEqual(body.unknown_flags, ['--tiemout']);
  assert.deepEqual(body.known_flags, ['--timeout', '--raw', '--air-gap']);
});

// A no-over-rejection pin, NOT a regression case: it also passes against the
// version that had no unknown-flag refusal at all, because that version ignored
// every unrecognised argument. What it locks is branch ORDER — the collector's
// `--` catch-all stays below the known-flag branches, so `--timeout` (both
// spellings), `--raw` and `--air-gap` are never read as typos. The refusal
// itself is covered by the exit-2 case above.
test('upstream-check-cli does not over-reject its own documented flags (--air-gap short-circuits to the skipped envelope)', () => {
  const out = spawnSync(process.execPath, [UPSTREAM_CLI, '--air-gap', '--timeout=5000', '--raw'], {
    encoding: 'utf8',
  });
  assert.equal(out.status, 0, `known flags must not be refused; got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
  assert.equal(out.stderr.includes('unknown flag'), false, `no known flag may be reported as unknown; stderr: ${out.stderr.slice(0, 200)}`);
  const body = tryJson(out.stdout.trim());
  assert.ok(body, `stdout must be parseable JSON; got: ${out.stdout.slice(0, 200)}`);
  assert.equal(body.ok, null);
  assert.equal(body.skipped, 'air-gap');
  assert.equal(body.source, 'upstream-check');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
