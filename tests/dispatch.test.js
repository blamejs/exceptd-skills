'use strict';

/**
 * Subject suite for the `exceptd dispatch` orchestrator-passthrough verb.
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

  test('F4: dispatch --json carries top-level ok:true, exit 0', () => {
    const r = cli(['dispatch', '--json'], { timeout: 20000 });
    assert.equal(r.status, 0);
    const body = lastJsonLine(r.stdout);
    assert.ok(body, 'must emit a parseable JSON envelope');
    assert.equal(body.ok, true);
  });

  test('F4: dispatch --badflag -> ok:false exit 1', () => {
    const r = cli(['dispatch', '--badflag'], { timeout: 20000 });
    assert.equal(r.status, 1);
    const body = tryJson(r.stdout.trim());
    assert.ok(body);
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'dispatch');
  });
});

// ---- routed from cli-flag-and-envelope-hardening ----
;(() => {
/**
 * Regression coverage for a CLI flag-handling + envelope-shape pass.
 *
 * Findings closed here:
 *
 *   1. validate-rfcs / validate-cves rejected unknown flags BEFORE any
 *      network work (a typo'd flag previously fell through to the default
 *      live-network path and hung). --offline / --air-gap still produce the
 *      offline view.
 *   2. cve / rfc derive `ok` from the resolved status: a non-zero (exit 2)
 *      failure carries ok:false; a published / matching resolution stays
 *      ok:true exit 0. Previously ok:true was hardcoded alongside exit 2.
 *   3. refresh / prefetch reject unknown flags (exit 2) instead of silently
 *      swallowing them (exit 0).
 *   4. orchestrator passthrough verbs (scan / dispatch / currency / watchlist)
 *      reject unknown flags AND carry top-level ok:true on --json success.
 *   5. framework-gap / skill missing-arg paths honor --json (emit ok:false
 *      JSON, exit 1); skill no longer treats --json as the skill name.
 *
 * Every assertion checks the EXACT exit code and the EXACT ok value + field
 * shape — never `notEqual(0)` / bare `assert.ok(field)`.
 *
 * Offline-only: --air-gap / --offline guarantee no real network egress. The
 * finding-1 unknown-flag tests rely on the rejection firing BEFORE the fetch,
 * so they neither reach nor depend on the network.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-flag-envelope-');
const cli = makeCli(SUITE_HOME);

// ---------------------------------------------------------------------------
// Finding 1 — validate-rfcs / validate-cves unknown-flag rejection (fast,
// pre-network). Bounded timeout proves no hang on a live fetch.
// ---------------------------------------------------------------------------






// ---------------------------------------------------------------------------
// Finding 2 — cve / rfc envelope ok derived from status (not inverted).
// ---------------------------------------------------------------------------





// ---------------------------------------------------------------------------
// Finding 3 — refresh / prefetch unknown-flag rejection.
// ---------------------------------------------------------------------------





// ---------------------------------------------------------------------------
// Finding 4 — orchestrator passthrough verbs: unknown-flag rejection +
// top-level ok:true on --json success. (currency emits a scheduler log line
// before the envelope; the JSON envelope is the LAST stdout line.)
// ---------------------------------------------------------------------------

function lastJsonLine(stdout) {
  const lines = stdout.trim().split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const parsed = tryJson(lines[i]);
    if (parsed) return parsed;
  }
  return null;
}









// ---------------------------------------------------------------------------
// Finding 5 — framework-gap / skill missing-arg paths honor --json; skill
// no longer treats --json as args[0].
// ---------------------------------------------------------------------------

test('F4: dispatch --badflag → ok:false exit 1', () => {
  const r = cli(['dispatch', '--badflag'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'dispatch');
});
})();
