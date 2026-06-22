'use strict';

/**
 * Subject coverage for the `report` CLI verb (bin/exceptd.js cmdRecipes-
 * adjacent report dispatch + orchestrator report): the executive markdown
 * flavor header, --json output for non-csaf formats (technical / executive),
 * and the --help default-format documentation.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');
  const { ROOT } = require('./_helpers/cli');

  test('report executive emits markdown with self-describing flavor header', () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'executive'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
      timeout: 30000,
    });
    assert.equal(r.status, 0, 'report executive must exit 0');
    assert.match(r.stdout, /# exceptd Executive Report/,
      'header must self-describe the report flavor as executive');
    assert.match(r.stdout, /flavor=executive/,
      'HTML comment provenance must carry flavor=executive');
    assert.match(r.stdout, /## Executive Summary/,
      'body must include the Executive Summary section');
    assert.match(r.stdout, /Total scan findings:/,
      'body must include a Total scan findings line (content, not just header)');
  });
});

// ===========================================================================
test.describe('cli-selector-flag-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-selector-fix-report-');
  const cli = makeCli(SUITE_HOME);

  test('report --json (no format) emits parseable JSON, not a format error', () => {
    const r = cli(['report', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && typeof body === 'object', 'stdout must parse as JSON');
    assert.equal(body.ok, true);
    assert.equal(body.verb, 'report');
    assert.equal(body.format, 'technical');
  });

  test('report executive --json emits JSON for a non-csaf format (not Markdown)', () => {
    const r = cli(['report', 'executive', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && typeof body === 'object', 'stdout must parse as JSON, not render Markdown');
    assert.equal(body.format, 'executive');
    assert.ok(body.summary && typeof body.summary === 'object');
  });
});

// ===========================================================================
test.describe('usability-fixes', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-usability-report-');
  const cli = makeCli(home);

  test('report --help states the default output format (Markdown), not just --json', () => {
    const r = cli(['report', '--help']);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.match(out, /Markdown/i, 'report --help must state the Markdown default so operators do not pipe Markdown into a JSON tool');
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

test('#98 report garbage returns JSON error exit 1 (v0.13 exit-code class)', () => {
  // v0.13.0: usage errors exit 1 (GENERIC_FAILURE), not 2 (DETECTED_ESCALATE).
  // Exit 2 in the canonical CLI contract means "verb ran and detected an
  // escalation-worthy finding" — unknown-format is a usage error, not a
  // detected finding. Envelope harmonization also routes ok:false to stdout.
  const r = cli(['report', 'garbage']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const err = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.equal(err.verb, 'report');
  assert.match(err.error, /not in accepted set/);
  assert.ok(Array.isArray(err.accepted_formats));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
