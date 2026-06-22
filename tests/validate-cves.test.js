'use strict';

/**
 * Subject suite for the `exceptd validate-cves` CLI verb.
 *
 * Unknown flags are rejected fast, BEFORE any network work (a typo'd flag
 * previously fell through to the default live-network path and hung).
 * --offline still produces the offline view.
 *
 * Offline-only: --offline guarantees no real network egress; the
 * unknown-flag rejection fires before the fetch. Bounded timeouts prove no
 * hang.
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// ===================================================================
// Source: cli-flag-and-envelope-hardening.test.js
// ===================================================================
describe('cli-flag-and-envelope-hardening.test.js', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-flag-envelope-');
  const cli = makeCli(SUITE_HOME);

  test('F1: validate-cves --badflag rejects fast with ok:false exit 1 (no network)', () => {
    const r = cli(['validate-cves', '--badflag'], { timeout: 15000 });
    assert.equal(r.status, 1);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'validate-cves');
    assert.deepEqual(body.unknown_flags, ['--badflag']);
    assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--offline'));
  });

  test('F1: validate-cves --offline still produces the offline view, exit 0', () => {
    const r = cli(['validate-cves', '--offline'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /offline mode — no network calls made/);
  });
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

test('#17 validate-cves does not crash with MODULE_NOT_FOUND', () => {
  const r = cli(['validate-cves', '--offline', '--no-fail']);
  assert.doesNotMatch(r.stderr + r.stdout, /Cannot find module.*sources\/validators/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
