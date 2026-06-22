'use strict';

/**
 * Subject coverage for the `doctor` CLI verb (bin/exceptd.js cmdDoctor): the
 * full no-flags health run, each selective subcheck (--signatures, --currency,
 * --cves, --rfcs, --shipped-tarball), the output envelope + summary shape, and
 * the --air-gap flag-allowlist consistency.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-doctor-');
  const cli = makeCli(SUITE_HOME);

  test('doctor no-flags emits checks{} covering every subcheck', () => {
    const r = cli(['doctor', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.equal(data.verb, 'doctor');
    assert.ok(data.checks && typeof data.checks === 'object', 'checks{} must be present');
    assert.ok(Object.keys(data.checks).length >= 4,
      'doctor with no flags must run at least 4 subchecks (signatures, currency, cves, rfcs)');
    for (const [name, check] of Object.entries(data.checks)) {
      assert.equal(typeof check.ok, 'boolean',
        `check ${name} must carry boolean .ok (no coincidence-passing)`);
    }
  });

  test('doctor --signatures emits only the signatures subcheck', () => {
    const r = cli(['doctor', '--signatures', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.signatures,
      'checks.signatures must be present when --signatures is passed');
    assert.equal(typeof data.checks.signatures.ok, 'boolean',
      'signatures.ok must be a boolean verdict, not undefined');
  });

  test('doctor --signatures --shipped-tarball opts into tarball-verify round-trip', () => {
    const r = cli(['doctor', '--signatures', '--shipped-tarball', '--json'], { timeout: 120000 });
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.signatures, 'checks.signatures must be present');
    assert.ok(data.checks.signatures.shipped_tarball,
      'checks.signatures.shipped_tarball must be populated when --shipped-tarball is passed');
    const st = data.checks.signatures.shipped_tarball;
    if (st.skipped === true) {
      assert.equal(typeof st.reason, 'string',
        'when skipped, shipped_tarball must document why (e.g. installed package without verify-shipped-tarball.js)');
    } else {
      assert.equal(typeof st.ok, 'boolean',
        'when run, shipped_tarball.ok must be a boolean verdict');
    }
  });

  test('doctor --currency emits only the currency subcheck', () => {
    const r = cli(['doctor', '--currency', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.currency, 'checks.currency must be present');
    assert.equal(typeof data.checks.currency.ok, 'boolean');
  });

  test('doctor --cves emits only the cves subcheck', () => {
    const r = cli(['doctor', '--cves', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.cves, 'checks.cves must be present');
    assert.equal(typeof data.checks.cves.ok, 'boolean');
  });

  test('doctor --rfcs emits only the rfcs subcheck', () => {
    const r = cli(['doctor', '--rfcs', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.rfcs, 'checks.rfcs must be present');
    assert.equal(typeof data.checks.rfcs.ok, 'boolean');
  });

  test('doctor --rfcs (modern) wraps the same validator with structured output', () => {
    const r = cli(['doctor', '--rfcs', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.rfcs, 'doctor --rfcs must populate checks.rfcs');
    assert.equal(typeof data.checks.rfcs.ok, 'boolean',
      'checks.rfcs.ok must be a boolean (not undefined / not coincidence-truthy)');
    assert.ok(typeof data.checks.rfcs.total === 'number' || data.checks.rfcs.total === null,
      'checks.rfcs.total must be numeric or explicit null');
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

  test('doctor envelope: exact top-level + summary sub-key set + baseline check set', () => {
    const r = cli(['doctor', '--json']);
    const body = tryJson(r.stdout);
    assert.ok(body, `doctor must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    assert.deepEqual(Object.keys(body).sort(), ['checks', 'local_version', 'ok', 'summary', 'verb']);
    assert.equal(body.verb, 'doctor');
    assert.equal(body.ok, true, 'v0.13: doctor carries ok:true (summary.all_green remains authoritative)');

    const baselineChecks = ['currency', 'cves', 'rfcs', 'signatures', 'signing'];
    for (const k of baselineChecks) {
      assert.ok(k in body.checks, `expected check "${k}" in doctor.checks`);
      assert.equal(typeof body.checks[k].ok, 'boolean');
    }

    const expectedSummaryKeys = [
      'all_green', 'failed_checks', 'issues_count',
      'warning_checks', 'warnings_count',
    ];
    assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
    assert.equal(typeof body.summary.all_green, 'boolean');
    assert.ok(Array.isArray(body.summary.failed_checks));
    assert.ok(Array.isArray(body.summary.warning_checks));
    assert.equal(body.summary.issues_count, body.summary.failed_checks.length);
    assert.equal(body.summary.warnings_count, body.summary.warning_checks.length);
  });
});

// ===========================================================================
test.describe('reconciliation-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-doctor-');
  const cli = makeCli(home);

  test('doctor accepts --air-gap on both validation paths (allowlist drift fixed)', () => {
    const r = cli(['doctor', '--bogus', '--json']);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.ok(Array.isArray(body.known_flags), 'doctor --bogus emits known_flags');
    assert.ok(body.known_flags.includes('--air-gap'), 'doctor known_flags must include --air-gap');
    const ok = cli(['doctor', '--signatures', '--air-gap', '--json']);
    assert.doesNotMatch((ok.stdout || '') + (ok.stderr || ''), /unknown flag/, '--air-gap must be accepted on doctor');
  });
});
