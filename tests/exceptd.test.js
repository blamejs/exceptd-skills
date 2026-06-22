"use strict";


// ---- routed from help-verb-attest-list-deprecation ----
require("node:test").describe("help-verb-attest-list-deprecation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/help-verb-attest-list-deprecation.test.js
 *
 * Cycle 11 P2/P3 fixes (v0.12.32):
 *
 *   F4 — `exceptd help <verb>` now routes through printPlaybookVerbHelp()
 *        so operators get verb-specific help regardless of whether they
 *        type `exceptd help run` or `exceptd run --help`. Pre-fix it
 *        dropped the verb argument and printed the top-level help.
 *
 *   F5 — `attest list` empty-state human renderer surfaces `roots_evaluated`
 *        showing every candidate root + whether it existed (`[scanned-empty]`
 *        vs `[not-present]`). Pre-fix it said `(no attestations under )`
 *        with an empty path list when no roots existed at all. JSON output
 *        also carries a structured `roots_evaluated[]` array.
 *
 *   F7 — Legacy-verb deprecation banner now persists suppression across
 *        invocations via an OS-tempdir marker keyed by exceptd version.
 *        Pre-fix the env-var guard reset on every fresh node process so
 *        operators saw the same banner on every `exceptd plan` invocation.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (status code, string presence/absence, array shape).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// F4 ------------------------------------------------------------------------



// F5 ------------------------------------------------------------------------



// F7 v0.13.0 update --------------------------------------------------------
//
// v0.13.0 honored the long-advertised legacy-verb removal. The pre-v0.13
// deprecation-banner mechanism (soft banner + tempdir marker for once-per-
// version display) was replaced by a hard refusal with a replacement hint.
// The two prior F7 tests asserted banner+suppress semantics; both are
// replaced with refusal-shape assertions below.

test('F4: `exceptd help run` returns verb-specific help (not top-level)', () => {
  const r = cli(['help', 'run']);
  assert.equal(r.status, 0);
  // Verb-specific help opens with the verb name + a brief tagline.
  assert.equal(/^run \[playbook\]/m.test(r.stdout), true,
    `expected verb-specific help opening; got: ${r.stdout.slice(0, 200)}`);
  // Verb-specific help (not top-level) — must mention the phase chain
  // for the run verb specifically.
  assert.equal(/detect → analyze/.test(r.stdout), true,
    'verb-specific help for run should mention the phase chain');
  // Must NOT be the top-level help (which opens with "exceptd CLI" /
  // "VERBS" / similar section banners).
  assert.equal(/^VERBS$|^exceptd CLI/m.test(r.stdout), false,
    'verb-specific help should NOT be the top-level help banner');
});

test('F4: `exceptd help <unknown>` falls through to top-level help with stderr note', () => {
  const r = cli(['help', 'definitely-not-a-real-verb-zzz']);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /no verb-specific help for "definitely-not-a-real-verb-zzz"/);
  // Top-level help banner is reachable in stdout.
  assert.equal(r.stdout.length > 200, true, 'top-level help should have substantial content');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#18 unknown command returns JSON error', () => {
  const r = cli(['nope-not-a-verb']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'nope-not-a-verb');
  // The hint is the recovery path: an unknown-verb error that just says
  // "unknown command" without pointing at `exceptd help` leaves operators
  // stranded, especially in CI where there's no terminal to retry in.
  assert.equal(typeof err.hint, 'string', 'hint must be a string operators can follow');
  assert.match(err.hint, /exceptd help/,
    'hint must point operators at `exceptd help` so a typo never dead-ends');
});

test('#130 exceptd path copy is not a silent no-op', () => {
  const r = cli(['path', 'copy']);
  // Behavior: prints path on stdout AND either confirms clipboard write on
  // stderr (when a tool is available) OR warns about missing tool on stderr.
  // The silent no-op is the bug.
  assert.equal(r.status, 0);
  assert.ok(r.stdout.trim().length > 0, 'path on stdout');
  // Pre-strengthening: matched only the "[exceptd path]" prefix, which
  // would accept ANY message after it (including "[exceptd path] gibberish"
  // or an empty bracket). Pin one of the two exact branches operators
  // actually rely on for diagnosing whether the clipboard write happened.
  // Two branches the CLI emits: success path is `[exceptd path] copied to clipboard: <path>`
  // (no `copy:` infix), degraded path is `[exceptd path] copy: no clipboard tool available (tried: ...)`
  // (with `copy:` infix because the verb name disambiguates the warning from the success path).
  assert.match(r.stderr, /\[exceptd path\] (copied to clipboard|copy: no clipboard tool available)/,
    'stderr must emit one of the two specific status messages — "copied to clipboard" (success) or "copy: no clipboard tool available" (degraded). Neither branch can be silent; a missing/altered message is the regression.');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from playbook-schema-validation ----
require("node:test").describe("playbook-schema-validation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression tests for the v0.12.20 audit S+T+U+Z P1 fixes.
 *
 *   S P1-A — Array attestation must NOT bypass the FP-check gate.
 *   S P1-B — `signals.detection_classification: 'detected'` override must be
 *            refused when ANY indicator was downgraded due to unattested FP
 *            checks; a runtime_error documents the refusal.
 *   U REG-1 — `signal_overrides_invalid` errors pushed by normalizeSubmission
 *            must reach analyze.runtime_errors[] (F20 contract).
 *   T P1-1 — withCatalogLock / withIndexLock must reclaim a lockfile whose
 *            PID is dead (ESRCH) without waiting STALE_LOCK_MS.
 *   T P1-2 — persistAttestation --force-overwrite must serialize concurrent
 *            writers so the prior_evidence_hash chain does not lose
 *            intermediate writers.
 *   T P1-3 — prefetch must NOT leave a payload on disk with no index entry
 *            when withIndexLock fails.
 *   T P1-4 — scheduleEvery must throw RangeError on 0 / negative / NaN /
 *            Infinity intervals.
 *
 * Concurrency tests use real subprocess invocation + race contention.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync, fork } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const RUNNER_PATH = path.resolve(ROOT, 'lib', 'playbook-runner.js');

// --- helpers --------------------------------------------------------------

function freshRunner(playbookDir) {
  if (playbookDir) process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  else delete process.env.EXCEPTD_PLAYBOOK_DIR;
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-stuz-${label}-`));
}

function writePlaybook(dir, id, body) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body, null, 2));
}

function synthPlaybook(overrides = {}) {
  const base = {
    _meta: {
      id: 'synth',
      version: '0.1.0',
      last_threat_review: '2026-05-14',
      threat_currency_score: 95,
      changelog: [{ version: '0.1.0', date: '2026-05-14', summary: 'synthetic test playbook' }],
      owner: '@blamejs/test',
      air_gap_mode: false,
      preconditions: [],
      mutex: [],
      feeds_into: [],
    },
    domain: {
      name: 'synth domain', attack_class: 'kernel-lpe',
      atlas_refs: [], attack_refs: [], cve_refs: [], cwe_refs: [], d3fend_refs: [],
      frameworks_in_scope: ['nist-800-53'],
    },
    phases: {
      govern: { jurisdiction_obligations: [], theater_fingerprints: [], framework_context: {}, skill_preload: [] },
      direct: { threat_context: 'x', rwep_threshold: { escalate: 90, monitor: 70, close: 30 }, framework_lag_declaration: 'x', skill_chain: [], token_budget: {} },
      look: { artifacts: [], collection_scope: {}, environment_assumptions: [], fallback_if_unavailable: [] },
      detect: { indicators: [], false_positive_profile: [], minimum_signal: { detected: 'x', inconclusive: 'x', not_detected: 'x' } },
      analyze: { rwep_inputs: [], blast_radius_model: { scope_question: '?', scoring_rubric: [] }, compliance_theater_check: null, framework_gap_mapping: [], escalation_criteria: [] },
      validate: { remediation_paths: [], validation_tests: [], residual_risk_statement: null, evidence_requirements: [], regression_trigger: [] },
      close: { evidence_package: null, learning_loop: { enabled: false }, notification_actions: [], exception_generation: null, regression_schedule: null },
    },
    directives: [{ id: 'default', title: 'default directive', applies_to: { always: true } }],
  };
  return deepMerge(base, overrides);
}

function deepMerge(a, b) {
  if (b === null || b === undefined) return a;
  if (Array.isArray(b)) return b;
  if (typeof b !== 'object') return b;
  const out = { ...a };
  for (const k of Object.keys(b)) {
    if (k in out && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k]) && b[k] && typeof b[k] === 'object' && !Array.isArray(b[k])) {
      out[k] = deepMerge(out[k], b[k]);
    } else {
      out[k] = b[k];
    }
  }
  return out;
}

// =========================================================================
// S P1-A — Array attestation bypasses FP-check gate
// =========================================================================


// =========================================================================
// S P1-B — `detection_classification: 'detected'` override cannot bypass FP downgrade
// =========================================================================



// =========================================================================
// U REG-1 — signal_overrides_invalid must reach analyze.runtime_errors[]
// =========================================================================


// =========================================================================
// T P1-1 — PID-liveness check on stale lockfiles
// =========================================================================


// =========================================================================
// T P1-2 — persistAttestation force-overwrite serializes concurrent writers
// =========================================================================


// =========================================================================
// T P1-3 — prefetch must NOT orphan a payload on lock failure
// =========================================================================


// =========================================================================
// T P1-4 — scheduleEvery lower-bound guard
// =========================================================================

test('T P1-2: concurrent --force-overwrite writers preserve prior_evidence_hash chain', async () => {
  // Real subprocess race: N children each call persistAttestation with
  // --force-overwrite against the same session-id. Without the lock, the
  // read of `prior` is racy and the final attestation's prior_evidence_hash
  // would point to whatever happened to be on disk at one writer's read
  // moment — losing intermediates. With the lock, every overwrite reads
  // the on-disk prior INSIDE the critical section, so the chain is
  // contiguous: the final attestation's prior_evidence_hash matches some
  // prior writer's evidence_hash.
  const root = tmpDir('t-p1-2');
  try {
    const sessionId = 'race-' + crypto.randomBytes(4).toString('hex');
    const dir = path.join(root, sessionId);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, 'attestation.json');
    // Seed an initial attestation so every concurrent writer hits the
    // force-overwrite path.
    fs.writeFileSync(filePath, JSON.stringify({
      session_id: sessionId,
      playbook_id: 'synth',
      directive_id: 'default',
      evidence_hash: 'seed-hash',
      operator: null,
      operator_consent: null,
      submission: {},
      run_opts: { airGap: false, forceStale: false, mode: 'test' },
      captured_at: new Date(Date.now() - 1000).toISOString(),
      prior_evidence_hash: null,
      prior_captured_at: null,
    }, null, 2));

    const helperPath = path.join(__dirname, '_helpers', 'concurrent-attestation-writer.js');
    const N = 4;
    const children = [];
    for (let i = 0; i < N; i++) {
      children.push(new Promise((resolve, reject) => {
        const cp = fork(helperPath, [root, sessionId, String(i)], {
          stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
          env: { ...process.env, EXCEPTD_ATTESTATION_ROOT: root },
        });
        let out = '';
        let err = '';
        cp.stdout.on('data', (b) => { out += b; });
        cp.stderr.on('data', (b) => { err += b; });
        cp.on('close', (code) => {
          if (code === 0) resolve({ out, err });
          else reject(new Error(`writer ${i} exited ${code}: ${err}`));
        });
      }));
    }
    const results = await Promise.all(children);
    // Every writer must report ok:true.
    for (const r of results) {
      const parsed = JSON.parse(r.out);
      assert.equal(parsed.ok, true, `writer must report ok:true; got ${JSON.stringify(parsed)}`);
    }
    // The final on-disk attestation must:
    //   1. Exist with valid JSON.
    //   2. Have a non-null prior_evidence_hash (forceOverwrite always
    //      captures the prior).
    //   3. The prior_evidence_hash must equal SOME writer's reported
    //      evidence_hash OR the seed-hash — i.e. it traces back to a real
    //      prior writer, not a corrupted read.
    const final = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    assert.ok(final.evidence_hash, 'final attestation must have evidence_hash');
    assert.ok(final.prior_evidence_hash, 'final attestation must record prior_evidence_hash');
    const reportedHashes = new Set(['seed-hash']);
    for (const r of results) reportedHashes.add(JSON.parse(r.out).evidence_hash);
    assert.ok(reportedHashes.has(final.prior_evidence_hash),
      `final.prior_evidence_hash (${final.prior_evidence_hash}) must trace to a real writer; reported hashes: ${[...reportedHashes].join(',')}`);
    // No orphan .lock left behind.
    assert.equal(fs.existsSync(filePath + '.lock'), false,
      'attestation .lock must be released after every writer');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
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

test('help: top-level help lists the cve, rfc and collect verbs', () => {
  const r = cli(['help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /^  cve /m);
  assert.match(r.stdout, /^  rfc /m);
  assert.match(r.stdout, /^  collect /m);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from round4-derivation-lint-attest ----
require("node:test").describe("round4-derivation-lint-attest", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Round-4 correctness regressions:
 *   - diffSignalOverrides must deep-compare (signal_overrides hold object
 *     `*__fp_checks` values; a reference-strict !== reports false drift)
 *   - the skill-section linter must not count headings inside fenced code
 *     blocks, and must not let a deeper heading (H3+) satisfy a top-level
 *     required-section (H2) requirement
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const cli = require(path.resolve(__dirname, '..', 'bin', 'exceptd.js'));
const lint = require(path.resolve(__dirname, '..', 'lib', 'lint-skills.js'));

const diffSignalOverrides = cli._diffSignalOverrides;
const findMissingSections = lint.findMissingSections;




const REQUIRED = ['Threat Context', 'Compliance Theater Check'];

test('diffSignalOverrides reports object-valued overrides with identical content as unchanged', () => {
  // Two distinct object references with byte-identical content (the
  // `<id>__fp_checks` shape) must NOT be flagged as changed.
  const a = { 'x__fp_checks': { vendor_advisory: true, poc_seen: false } };
  const b = { 'x__fp_checks': { poc_seen: false, vendor_advisory: true } }; // key order swapped
  const r = diffSignalOverrides(a, b);
  assert.equal(r.changed.length, 0, 'identical FP-check content must not be "changed"');
  assert.equal(r.unchanged_count, 1);
});

test('diffSignalOverrides still detects a real content change in an object override', () => {
  const a = { 'x__fp_checks': { vendor_advisory: true } };
  const b = { 'x__fp_checks': { vendor_advisory: false } };
  const r = diffSignalOverrides(a, b);
  assert.equal(r.changed.length, 1);
  assert.equal(r.changed[0].id, 'x__fp_checks');
});

test('diffSignalOverrides detects added / removed overrides', () => {
  const r = diffSignalOverrides({ a: 1 }, { a: 1, b: 2 });
  assert.equal(r.changed.length, 1, 'b is present on only one side -> changed');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
