'use strict';

/**
 * Subject suite for the `exceptd validate-rfcs` CLI verb.
 *
 * Unknown flags are rejected fast, BEFORE any network work (a typo'd flag
 * previously fell through to the default live-network path and hung).
 * --offline / --air-gap still produce the offline view.
 *
 * Offline-only: --air-gap / --offline guarantee no real network egress;
 * the unknown-flag rejection fires before the fetch, so these tests neither
 * reach nor depend on the network. Bounded timeouts prove no hang.
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

  test('F1: validate-rfcs --badflag rejects fast with ok:false exit 1 (no network)', () => {
    const r = cli(['validate-rfcs', '--badflag'], { timeout: 15000 });
    assert.equal(r.status, 1, 'unknown flag must exit 1, not hang on the network');
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'validate-rfcs');
    assert.deepEqual(body.unknown_flags, ['--badflag']);
    assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--offline'),
      'known_flags must list the accepted flags');
  });

  test('F1: validate-rfcs --offline still produces the offline view, exit 0', () => {
    const r = cli(['validate-rfcs', '--offline'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /Offline view only|skipped \(offline\)/);
  });

  test('F1: validate-rfcs --air-gap is treated as offline (no egress), exit 0', () => {
    const r = cli(['validate-rfcs', '--air-gap'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /Offline view only|skipped \(offline\)/);
  });
});
