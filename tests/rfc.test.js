'use strict';

/**
 * Subject suite for the `exceptd rfc` CLI verb (and the lib/rfc-cli.js
 * resolver it dispatches to). Every test drives the CLI / resolver as a
 * subprocess and asserts the documented exit code + ok-derived envelope.
 *
 * Discipline: exact exit-code assertions; field-presence paired with
 * field-content; all writes confined to os.tmpdir().
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// ===================================================================
// Source: cli-flag-and-envelope-hardening.test.js — `rfc` verb envelope
// (ok derived from the resolved status). Offline via --air-gap.
// ===================================================================
describe('cli-flag-and-envelope-hardening.test.js', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-flag-envelope-');
  const cli = makeCli(SUITE_HOME);

  test('F2: rfc --check title MISMATCH -> ok:false exit 2', () => {
    const r = cli(['rfc', '2119', '--check', 'wrong title', '--json', '--air-gap']);
    assert.equal(r.status, 2);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'rfc');
    assert.equal(body.title_match, false);
  });

  test('F2: rfc --check title MATCH -> ok:true exit 0', () => {
    const r = cli(['rfc', '2119', '--check', 'Key words for use in RFCs', '--json', '--air-gap']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, true);
    assert.equal(body.title_match, true);
  });
});

// ===================================================================
// Source: cli-error-envelopes.test.js — the rfc resolver (lib/rfc-cli.js)
// must turn a corrupt index into the single-line {ok:false,verb,error}
// envelope, never a raw V8 stack trace.
// ===================================================================
describe('cli-error-envelopes.test.js', () => {
  const ROOT = path.join(__dirname, '..');
  const RFC_CLI = path.join(ROOT, 'lib', 'rfc-cli.js');

  function run(script, args, env) {
    return spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1', EXCEPTD_RAW_JSON: '1', ...env },
    });
  }

  test("rfc resolver emits {ok:false,verb:'rfc',error} + exit 1 on a corrupt index (no raw crash)", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rfc-badidx-'));
    try {
      const bad = path.join(tmp, 'rfc-references.json');
      fs.writeFileSync(bad, '{ not json either');
      const r = run(RFC_CLI, ['9404', '--json', '--air-gap'], { EXCEPTD_RFC_INDEX: bad });
      assert.equal(r.status, 1);
      assert.equal(r.stdout.trim(), '', 'no partial result must reach stdout on failure');
      const err = tryJson(r.stderr.trim());
      assert.ok(err, `stderr must be a parseable single-line envelope; got ${r.stderr.slice(0, 200)}`);
      assert.equal(err.ok, false);
      assert.equal(err.verb, 'rfc');
      assert.equal(typeof err.error, 'string');
      assert.ok(err.error.length > 0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});


// ---- routed from resolver-trust-and-flag-hardening ----
require("node:test").describe("resolver-trust-and-flag-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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








// ===================================================================
// 2. cve / rfc unknown-flag rejection (spawned CLIs)
// ===================================================================




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


// ===================================================================
// 4. applyResolution RFC flip
// ===================================================================



// ===================================================================
// 5. ci --max-rwep validation
// ===================================================================




// ===================================================================
// 6. --format overrides --json (note on stderr, markdown on stdout)
// ===================================================================


// ===================================================================
// 7. help lists the cve / rfc / collect verbs
// ===================================================================

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
