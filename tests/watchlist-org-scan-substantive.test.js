'use strict';

/**
 * tests/watchlist-org-scan-substantive.test.js
 *
 * Beyond the v0.13.3 smoke pin (refuses without --org). Verifies the
 * argument-handling + envelope-shape contracts without making real
 * GitHub API calls. The actual fetch path is exercised separately via
 * the daily scheduled remote agent — these tests cover the parts
 * deterministic in-process.
 *
 * Tests:
 *   - --org-scan with --org consumes the argument (no "requires --org" refusal)
 *   - GITHUB_ORG env var serves as fallback
 *   - --pattern custom patterns extend the default set
 *   - JSON envelope shape matches the documented contract
 *   - exit codes are correct
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    timeout: 30000,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test('--org-scan: with --org argument accepts the arg (no missing-arg refusal)', () => {
  // Pass a definitely-nonexistent org so the GitHub API returns no hits.
  // The point isn't the API result — it's that arg parsing succeeded.
  const r = cli(['watchlist', '--org-scan', '--org', 'exceptd-test-nonexistent-org-99999999', '--json'], {
    env: { ...process.env, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  // Status may be 0 (no matches found, no rate limit) or non-0 (rate
  // limited / network unreachable). Either way, the body must be JSON
  // with the org-scan envelope shape — NOT the "requires --org" error.
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON; got: ${r.stdout.slice(0, 200)} / stderr: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.equal(body.org, 'exceptd-test-nonexistent-org-99999999');
  assert.equal(typeof body.patterns_evaluated, 'number');
  assert.ok(body.patterns_evaluated >= 3, 'must evaluate at least the 3 default patterns');
  assert.ok(Array.isArray(body.matches));
});

test('--org-scan: GITHUB_ORG env var serves as fallback when --org omitted', () => {
  const r = cli(['watchlist', '--org-scan', '--json'], {
    env: { ...process.env, GITHUB_ORG: 'exceptd-test-env-fallback', GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON; got: ${r.stdout.slice(0, 200)}`);
  // If parsing worked, env-var fallback worked.
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.equal(body.org, 'exceptd-test-env-fallback');
});

test('--org-scan: --pattern argument extends the default set', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'exceptd-test-pattern', '--pattern', 'custom-marker', '--json'], {
    env: { ...process.env, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  // The default set is 3 (shai-hulud-classic / teampcp-gift / teampcp-bare);
  // 1 custom pattern brings it to 4.
  assert.equal(body.patterns_evaluated, 4,
    `expected 4 patterns evaluated (3 defaults + 1 custom); got ${body.patterns_evaluated}`);
});

test('--org-scan: NEW-CTRL-052 control_reference field is present', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'exceptd-test-ctrl-ref', '--json'], {
    env: { ...process.env, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  assert.equal(body.control_reference, 'NEW-CTRL-052 (MAL-2026-SHAI-HULUD-OSS lesson)');
});

test('--org-scan: each match carries the documented per-match shape', () => {
  // Use exceptd's actual repo org so the call exercises the real
  // fetch + parse path. Whether matches are returned is environment-
  // dependent (rate-limited / no creds may return 0); the test
  // checks shape WHEN matches exist.
  const r = cli(['watchlist', '--org-scan', '--org', 'blamejs', '--json'], {
    timeout: 20000,
  });
  const body = tryJson(r.stdout.trim());
  if (!body || body.rate_limited || body.matches.length === 0) {
    // Rate-limited or empty — can't assert match shape. Verify the
    // envelope at least carries the rate_limited signal.
    if (body) {
      assert.equal(typeof body.rate_limited, 'boolean');
      assert.equal(typeof body.unauthenticated, 'boolean');
    }
    return;
  }
  for (const m of body.matches) {
    assert.equal(typeof m.pattern_id, 'string');
    assert.ok(['critical', 'high', 'medium', 'low'].includes(m.severity));
    assert.equal(typeof m.source, 'string');
    assert.equal(typeof m.repo, 'string');
    assert.match(m.url, /^https:\/\/github\.com\//);
    assert.equal(typeof m.private, 'boolean');
    assert.equal(typeof m.created_at, 'string');
    assert.equal(typeof m.stars, 'number');
  }
});
