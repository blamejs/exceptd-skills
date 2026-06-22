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
