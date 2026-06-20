'use strict';

/**
 * Regression: the watchlist --org-scan per-pattern GitHub fetch must retry a
 * transient failure (5xx / reset / timeout) with backoff instead of dropping
 * the pattern on the first hiccup, and must surface a pattern that exhausted
 * its retries so an operator can tell a dropped query from a clean no-match.
 *
 * Before the fix the loop did a single-shot `await fetch(...)` wrapped in a
 * bare `catch { ... }`; a flaky 502 on one pattern silently yielded zero
 * matches for it with the envelope still reading `ok:true` / `rate_limited:false`
 * — the false-negative-on-transient class NEW-CTRL-052 exists to defend against.
 *
 * fetch is stubbed in the subprocess via a --require preload
 * (tests/fixtures/org-scan-fetch-stub.js) so this runs offline and
 * deterministically. Spawning rather than calling in-process avoids a
 * collision between the verb's stdout writes and the node:test TAP stream.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
// Spawn the orchestrator directly: bin/exceptd.js re-spawns the watchlist
// verb as its own subprocess, which would not inherit a --require preload.
// The orchestrator is the documented subprocess entry point for the verb.
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');
const STUB = path.join(__dirname, 'fixtures', 'org-scan-fetch-stub.js');

function run(stubMode) {
  const r = spawnSync(process.execPath, ['--require', STUB, ORCH, 'watchlist', '--org-scan', '--org', 'victim-org', '--json'], {
    encoding: 'utf8',
    cwd: ROOT,
    timeout: 30000,
    env: { ...process.env, ORG_SCAN_STUB: stubMode, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  let body = null;
  for (const line of r.stdout.split('\n').filter(Boolean)) {
    try { body = JSON.parse(line); } catch { /* keep scanning */ }
  }
  // The stub prints ATTEMPTS:<n> per flaky-query call to stderr; the last
  // one is the total attempt count for that pattern.
  const attemptLines = r.stderr.split('\n').filter((l) => l.startsWith('ATTEMPTS:'));
  const attempts = attemptLines.length ? Number(attemptLines[attemptLines.length - 1].slice('ATTEMPTS:'.length)) : 0;
  return { r, body, attempts };
}

test('org-scan: a transient 502 is retried and the pattern recovers (no silent drop)', () => {
  const { body, attempts } = run('transient-recover');
  assert.ok(body, 'expected a JSON envelope');
  assert.equal(body.mode, 'org-scan');
  // The flaky pattern was retried (3 attempts) instead of dropped on attempt 1.
  assert.equal(attempts, 3, `expected 3 attempts on the flaky pattern, got ${attempts}`);
  // The recovered match is present.
  assert.ok(
    body.matches.some((m) => m.repo === 'attacker/shai-hulud-clone'),
    "the retried pattern's match must be present after recovery",
  );
  // Clean recovery — nothing errored, envelope is ok.
  assert.deepEqual(body.errored_patterns, [], 'no patterns should be marked errored after recovery');
  assert.equal(body.ok, true);
  assert.equal(body.rate_limited, false);
});

test('org-scan: a pattern that exhausts retries is surfaced as errored, not a clean zero', () => {
  const { body, attempts } = run('transient-exhaust');
  assert.ok(body, 'expected a JSON envelope');
  // maxAttempts:3 — three tries before giving up on the flaky pattern.
  assert.equal(attempts, 3, `expected 3 attempts before giving up, got ${attempts}`);
  // The dropped pattern is OBSERVABLE — not silently absent.
  assert.ok(Array.isArray(body.errored_patterns), 'errored_patterns must be present');
  assert.equal(body.errored_patterns.length, 1, 'exactly one pattern exhausted its retries');
  assert.equal(body.errored_patterns[0].pattern_id, 'shai-hulud-classic');
  assert.equal(typeof body.errored_patterns[0].error, 'string');
  // A transient drop is NOT a rate-limit and is NOT a clean scan.
  assert.equal(body.rate_limited, false, 'a 502 is not a rate-limit');
  assert.equal(body.ok, false, 'an errored pattern must make the envelope ok:false');
});

test('org-scan: a 429 still maps to rate_limited (not retried as a transient)', () => {
  const { body, attempts } = run('rate-limit');
  assert.ok(body, 'expected a JSON envelope');
  // 429 is the documented rate-limit signal — short-circuited, not retried 3x.
  assert.equal(attempts, 1, `429 must not be retried as a transient; got ${attempts} attempts`);
  assert.equal(body.rate_limited, true);
  assert.deepEqual(body.errored_patterns, [], '429 surfaces as rate_limited, not errored');
  assert.equal(body.ok, false, 'rate-limited scan is incomplete -> ok:false');
});
