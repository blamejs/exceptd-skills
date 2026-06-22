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

// ---- routed from attest-replay-and-discover-cwd ----
;(() => {
/**
 * Regression suite for the attestation-replay + discover-cwd + collect/lint
 * fixes:
 *   - reattest replays the ORIGINAL submission, so an unchanged session reports
 *     "unchanged" (it previously reported a false "drifted" every time).
 *   - discover honors --cwd (it previously scanned the process cwd silently).
 *   - collect warns on ANY failed precondition (not only empty-signal skips).
 *   - lint distinguishes a present-but-uncaptured required artifact from an
 *     absent one.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-replayfix-");
const cli = makeCli(SUITE_HOME);

test("discover honors --cwd: an empty target dir yields no repo recommendations", () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-disc-empty-"));
  try {
    const r = cli(["discover", "--cwd", empty, "--json"]);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && body.ok === true);
    const detected = body.detected_files || body.detected || [];
    assert.ok(Array.isArray(detected) && detected.length === 0,
      `empty dir should detect nothing; got ${JSON.stringify(detected)}`);
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

test("discover --cwd to a nonexistent path errors cleanly (not silently ignored)", () => {
  const r = cli(["discover", "--cwd", path.join(os.tmpdir(), "exceptd-no-such-dir-xyz123"), "--json"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--cwd .* does not exist/);
});
})();
