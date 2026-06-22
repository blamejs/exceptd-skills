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
