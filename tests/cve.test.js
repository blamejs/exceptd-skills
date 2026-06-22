'use strict';

/**
 * Subject suite for the `exceptd cve` CLI verb (and the lib/cve-cli.js
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
// Source: cli-flag-and-envelope-hardening.test.js — `cve` verb envelope
// (ok derived from the resolved status, not inverted). Offline via
// --air-gap so there is no network egress.
// ===================================================================
describe('cli-flag-and-envelope-hardening.test.js', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-flag-envelope-');
  const cli = makeCli(SUITE_HOME);

  test('F2: cve fabricated id → ok:false exit 2', () => {
    const r = cli(['cve', 'NOT-A-CVE', '--json', '--air-gap']);
    assert.equal(r.status, 2);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, false, 'a non-zero exit must carry ok:false');
    assert.equal(body.verb, 'cve');
    assert.equal(body.status, 'fabricated');
  });

  test('F2: cve published catalog entry → ok:true exit 0', () => {
    const r = cli(['cve', 'CVE-2026-31431', '--json', '--air-gap']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, true);
    assert.equal(body.status, 'published');
  });
});

// ===================================================================
// Source: cli-error-envelopes.test.js — the cve resolver (lib/cve-cli.js)
// must turn a corrupt catalog into the single-line {ok:false,verb,error}
// envelope, never a raw V8 stack trace.
// ===================================================================
describe('cli-error-envelopes.test.js', () => {
  const ROOT = path.join(__dirname, '..');
  const CVE_CLI = path.join(ROOT, 'lib', 'cve-cli.js');

  function run(script, args, env) {
    return spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1', EXCEPTD_RAW_JSON: '1', ...env },
    });
  }

  test("cve resolver emits {ok:false,verb:'cve',error} + exit 1 on a corrupt catalog (no raw crash)", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cve-badcat-'));
    try {
      const bad = path.join(tmp, 'cve-catalog.json');
      fs.writeFileSync(bad, '{ this is not valid json');
      // --air-gap keeps the resolver offline so the only failure is the catalog read.
      const r = run(CVE_CLI, ['CVE-2024-0001', '--json', '--air-gap'], { EXCEPTD_CVE_CATALOG: bad });
      assert.equal(r.status, 1);
      assert.equal(r.stdout.trim(), '', 'no partial result must reach stdout on failure');
      const err = tryJson(r.stderr.trim());
      assert.ok(err, `stderr must be a parseable single-line envelope; got ${r.stderr.slice(0, 200)}`);
      assert.equal(err.ok, false);
      assert.equal(err.verb, 'cve');
      assert.equal(typeof err.error, 'string');
      assert.ok(err.error.length > 0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
