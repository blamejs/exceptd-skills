'use strict';

/**
 * Subject suite for the `exceptd watchlist` orchestrator-passthrough verb.
 *
 * A --json success carries top-level ok:true; an unknown flag is rejected
 * (exit 1) instead of being silently swallowed.
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

  function lastJsonLine(stdout) {
    const lines = stdout.trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const parsed = tryJson(lines[i]);
      if (parsed) return parsed;
    }
    return null;
  }

  test('F4: watchlist --json carries top-level ok:true, exit 0', () => {
    const r = cli(['watchlist', '--json'], { timeout: 20000 });
    assert.equal(r.status, 0);
    const body = lastJsonLine(r.stdout);
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, true);
  });

  test('F4: watchlist --badflag -> ok:false exit 1', () => {
    const r = cli(['watchlist', '--badflag'], { timeout: 20000 });
    assert.equal(r.status, 1);
    const body = tryJson(r.stdout.trim());
    assert.ok(body);
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'watchlist');
    assert.deepEqual(body.unknown_flags, ['--badflag']);
  });
});
