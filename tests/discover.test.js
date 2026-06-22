'use strict';

/**
 * Subject coverage for the `discover` CLI verb (bin/exceptd.js cmdDiscover):
 * the happy-path context + recommended_playbooks output, the --scan-only
 * legacy embed, the output envelope shape, the bundle-flag irrelevant refusal,
 * and the --cwd help documentation.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-discover-');
  const cli = makeCli(SUITE_HOME);

  test('discover happy path emits context + recommended_playbooks[]', () => {
    const r = cli(['discover', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(data, 'discover output must be JSON');
    assert.equal(data.verb, 'discover');
    assert.ok(data.context && typeof data.context.cwd === 'string',
      'context.cwd must be present and a string');
    assert.ok(Array.isArray(data.recommended_playbooks),
      'recommended_playbooks must be an array');
    assert.ok(data.recommended_playbooks.length > 0,
      'recommended_playbooks must include at least the cross-cutting framework entry');
    const ids = data.recommended_playbooks.map(p => p.id);
    assert.ok(ids.includes('framework'),
      'framework playbook must always be recommended (cross-cutting)');
  });

  test('discover --scan-only embeds legacy_scan and emits no routed_to', () => {
    const r = cli(['discover', '--scan-only', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(data, 'discover --scan-only must emit JSON');
    assert.ok('legacy_scan' in data, 'legacy_scan field must be present under --scan-only');
    assert.ok(!('routed_to' in data),
      '--scan-only must NOT dispatch (no routed_to field); routing requires discover without --scan-only');
  });
});

// ===========================================================================
test.describe('cli-output-envelope-shape-v0_12_39', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  test('discover envelope: exact top-level key set + context sub-keys', () => {
    const r = cli(['discover', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body, `discover must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    const expected = ['context', 'next_steps', 'ok', 'recommended_playbooks', 'verb'];
    assert.deepEqual(Object.keys(body).sort(), expected);
    assert.equal(body.verb, 'discover');
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.next_steps));
    assert.ok(Array.isArray(body.recommended_playbooks));

    const expectedContextKeys = ['cwd', 'detected_files', 'git_remote', 'host_distro', 'host_platform'];
    assert.deepEqual(Object.keys(body.context).sort(), expectedContextKeys);
    assert.equal(typeof body.context.cwd, 'string');
    assert.equal(typeof body.context.host_platform, 'string');
    assert.ok(Array.isArray(body.context.detected_files));

    for (const p of body.recommended_playbooks) {
      assert.equal(typeof p.id, 'string');
      assert.equal(typeof p.reason, 'string');
    }
  });
});

// ===========================================================================
test.describe('cli-subverb-dispatch', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-audit-nn-discover-');
  const cli = makeCli(SUITE_HOME);

  test('NN P1-1: discover --csaf-status final → refused on a non-bundle verb', () => {
    const r = cli(['discover', '--csaf-status', 'interim', '--json']);
    assert.equal(r.status, 1,
      'discover --csaf-status must exit EXACTLY 1; got status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.equal(err.error_class, 'irrelevant-flag');
    assert.equal(err.verb, 'discover');
  });
});

// ===========================================================================
test.describe('reconciliation-deep-fixes', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-deep-discover-');
  const cli = makeCli(home);

  test('discover --help documents --cwd (accepted + typo-suggestible but was undocumented)', () => {
    const out = (cli(['discover', '--help']).stdout || '') + (cli(['discover', '--help']).stderr || '');
    assert.match(out, /--cwd/, 'discover --help must document --cwd');
  });
});


// ---- routed from audit-usability-fixes ----
require("node:test").describe("audit-usability-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================









// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================


// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================


// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================




// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================




// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================


// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================


// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('unknown flag on discover hard-fails with structured envelope', () => {
  const r = cli(['discover', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
  assert.ok(Array.isArray(body.unknown_flags), 'unknown_flags must be an array');
  assert.ok(body.unknown_flags.length > 0, 'unknown_flags must be non-empty');
  assert.ok(Array.isArray(body.known_flags), 'known_flags must be an array');
  assert.ok(body.known_flags.length > 0, 'known_flags must be non-empty');
});

test('unknown flag typo gets a did_you_mean suggestion', () => {
  const r = cli(['discover', '--scop', 'code']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.ok(Array.isArray(body.unknown_flags) && body.unknown_flags.length > 0,
    'unknown_flags must be a non-empty array');
  assert.ok(Array.isArray(body.unknown_flags[0].did_you_mean),
    'did_you_mean must be an array');
  assert.ok(body.unknown_flags[0].did_you_mean.includes('--scope'),
    `did_you_mean must suggest --scope; got ${JSON.stringify(body.unknown_flags[0].did_you_mean)}`);
});

test('known flags still work: discover --scope code (exit 0)', () => {
  const r = cli(['discover', '--scope', 'code']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
});

test('known flags still work: discover --json (exit 0, parseable stdout)', () => {
  const r = cli(['discover', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `discover --json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from blamejs-scan-fixes ----
require("node:test").describe("blamejs-scan-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/blamejs-scan-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const containersCollector = require('../lib/collectors/containers.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('discover recommends containers for a subdir Dockerfile / compose variant (not just a root exact-name file)', () => {
  const cli = makeCli(makeSuiteHome());
  // A subdir Dockerfile + a compose variant — neither is a root-level
  // exact-name Dockerfile/docker-compose.yml, so the old root-only probes
  // missed them and discover never recommended the containers playbook.
  const fx = mkfx();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const ids = ((tryJson(cli(['discover', '--cwd', fx, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.ok(ids.includes('containers'), 'discover recommends containers for a subdir Dockerfile + compose variant');
  // A tree with no container config must NOT recommend containers.
  const empty = mkfx();
  fs.writeFileSync(path.join(empty, 'README.md'), '# nothing container-ish here\n');
  const ids2 = ((tryJson(cli(['discover', '--cwd', empty, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.equal(ids2.includes('containers'), false, 'no container config means no containers recommendation');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
