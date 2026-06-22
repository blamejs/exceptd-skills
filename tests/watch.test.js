"use strict";


// ---- routed from engine-hardening-and-help ----
require("node:test").describe("engine-hardening-and-help", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for an engine-hardening + UX cluster:
 *
 *   Deeply-nested evidence overflowed the stack (canonicalStringify recursion
 *     runs on every run via evidence_hash) with an opaque "internal error";
 *     it is now rejected at a bounded depth with an actionable message.
 *   --strict-preconditions missed a false skip_phase precondition (verdict
 *     skipped, exit 0) — a CI gate silently passed. It now fails (exit 1).
 *   A signal_overrides value that doesn't canonicalize (e.g. "maybe") was
 *     silently dropped; it now surfaces a runtime_error.
 *   A not_detected/clean classification override that would bury a
 *     DETERMINISTIC hit is refused (substituted inconclusive) and no longer
 *     reported as classification_override_applied. A probabilistic hit's
 *     confirm-benign override is still honored.
 *   run --all swallowed a mid-batch session-id collision (exit 0); it now
 *     surfaces exit 7 like the single-run path.
 *   watch --help started the blocking daemon (hung the terminal); collect
 *     --help had no content. Both now print usage.
 *
 * Discipline: exact exit codes; value + type assertions.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-enginehard-"));

test("watch --help prints usage and exits 0 (does not start the blocking daemon)", () => {
  const r = cli(["watch", "--help"], { timeout: 8000 });
  assert.equal(r.status, 0, "watch --help must exit 0, not hang");
  assert.match(r.stdout, /forward-watch daemon/i, "must describe the daemon");
  assert.match(r.stdout, /watchlist/, "must point at watchlist for the one-shot aggregator");
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

test('#62 watch verb is registered', () => {
  // watch is a long-running orchestrator subprocess; we just verify the
  // CLI doesn't reject it as unknown. spawn with short timeout so the test
  // doesn't hang on the event-loop.
  const r = spawnSync(process.execPath, [CLI, 'watch'], {
    encoding: 'utf8', timeout: 1500,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.doesNotMatch(r.stderr, /unknown command/,
    'watch must be registered, not fall through to the unknown-verb branch');
  // Two-sided contract:
  //  (a) the subprocess didn't exit on its own — spawn timeout killed it,
  //      so signal is SIGTERM (or status is null on platforms that report
  //      timeouts via status). A clean exit-0 from `watch` would mean the
  //      orchestrator never reached its event loop, which is the regression
  //      worth catching — pre-strengthening only `doesNotMatch unknown
  //      command` accepted that case silently.
  //  (b) the orchestrator wrote its startup banner to stdout before being
  //      killed, proving the verb actually dispatched (not just got past
  //      the unknown-verb gate via some lazy lookup).
  assert.ok(r.signal === 'SIGTERM' || r.status === null,
    `watch must still be running when the spawn timeout fires (got status=${r.status}, signal=${r.signal})`);
  assert.match(r.stdout, /\[orchestrator\] Starting event watcher/,
    'watch must reach the orchestrator-startup banner — proves dispatch happened, not just that the verb was recognized');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from z-watch-lock-and-watcher-stamps ----
require("node:test").describe("z-watch-lock-and-watcher-stamps", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Two narrow contracts:
 *
 *   1. `exceptd watch` reports lock contention with the EX_TEMPFAIL exit (75)
 *      even when the contention surfaces on the stale-reclaim path. After the
 *      watcher judges a lock stale and unlinks it, another reclaimer can win
 *      the create race; the resulting O_EXCL EEXIST is contention ("retry
 *      later"), not a generic failure (1).
 *
 *   2. cve-regression-watcher stamps `generated_at` from the same injectable
 *      clock that derives the threshold year, so both date-derived report
 *      fields share one instant rather than diverging from a module-load
 *      timestamp.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');
const WATCHER = require(path.join(ROOT, 'lib', 'cve-regression-watcher.js'));

test('watch reports lock contention (75) when the stale-reclaim create loses a race', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'z-watch-reclaim-'));
  try {
    // Place a DIRECTORY at the lock path. This deterministically reproduces
    // the reclaim-race interleaving: the first O_EXCL create sees EEXIST, the
    // staleness probe's read fails (so the lock is judged stale), the unlink
    // of the still-present name is swallowed, and the reclaim O_EXCL create
    // sees EEXIST again — the exact shape of "another reclaimer won the race
    // between our unlink and our re-create".
    const lockPath = path.join(home, 'watch.lock');
    fs.mkdirSync(lockPath);

    const r = spawnSync(process.execPath, [ORCH, 'watch'], {
      encoding: 'utf8',
      timeout: 8000,
      env: {
        ...process.env,
        EXCEPTD_HOME: home,
        EXCEPTD_SUPPRESS_DEPRECATION: '1',
      },
    });

    assert.equal(
      r.status,
      75,
      `reclaim-race contention must exit EX_TEMPFAIL 75, not GENERIC_FAILURE 1; got ${r.status} stderr=${r.stderr}`,
    );
    assert.match(r.stderr, /cannot start watch/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
