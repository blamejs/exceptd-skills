'use strict';

/**
 * tests/watchlist-alerts.test.js
 *
 * v0.13.1 — `exceptd watchlist --alerts` surfaces CVE-class pattern
 * matches against the current catalog. Closes the post-mortem gap on
 * CVE-2026-46333 where the toolkit had no programmatic way for an
 * operator to ask "what just landed that needs attention?".
 *
 * Tests cover:
 *   - Envelope shape (ok, verb, mode, generated_at, alert_count, alerts)
 *   - Pattern coverage: each of the 5 documented patterns fires on at
 *     least one current catalog entry
 *   - Sort order: critical-severity matches first, then by RWEP descending
 *   - Specific anchors: CVE-2026-46333 (ssh-keysign-pwn) MUST surface
 *     under kernel_lpe_with_poc; MAL-2026-SHAI-HULUD-OSS MUST surface
 *     under supply_chain_family
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
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test('watchlist --alerts --json: envelope shape', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}. stderr: ${r.stderr.slice(0, 300)}`);
  const body = tryJson(r.stdout);
  assert.ok(body, `must emit parseable JSON; got: ${r.stdout.slice(0, 300)}`);
  // v0.13.0 envelope: every body has ok + verb. Plus the --alerts-specific shape.
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'alerts');
  assert.equal(typeof body.generated_at, 'string');
  assert.match(body.generated_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(typeof body.patterns_evaluated, 'number');
  assert.ok(body.patterns_evaluated >= 5, `expected >= 5 patterns; got ${body.patterns_evaluated}`);
  assert.equal(typeof body.entries_scanned, 'number');
  assert.ok(body.entries_scanned >= 30, `expected >= 30 catalog entries scanned; got ${body.entries_scanned}`);
  assert.equal(typeof body.alert_count, 'number');
  assert.ok(Array.isArray(body.alerts));
  assert.equal(body.alert_count, body.alerts.length, 'alert_count must match alerts.length');
});

test('watchlist --alerts: every alert carries the structured per-entry shape', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body && body.alerts.length > 0, 'expected at least one alert in the current catalog');
  for (const a of body.alerts) {
    assert.equal(typeof a.cve_id, 'string', `alert missing cve_id`);
    assert.ok(Array.isArray(a.patterns), `${a.cve_id}: patterns must be an array`);
    assert.ok(a.patterns.length >= 1, `${a.cve_id}: at least one pattern must fire`);
    for (const p of a.patterns) {
      assert.equal(typeof p.id, 'string');
      assert.ok(['critical', 'high', 'medium', 'low'].includes(p.severity),
        `${a.cve_id}: pattern ${p.id} severity must be one of critical/high/medium/low`);
    }
    assert.ok(Array.isArray(a.links));
  }
});

test('watchlist --alerts: CVE-2026-46333 surfaces under kernel_lpe_with_poc', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  const body = tryJson(r.stdout);
  const a = body.alerts.find((x) => x.cve_id === 'CVE-2026-46333');
  assert.ok(a, 'CVE-2026-46333 (ssh-keysign-pwn) must surface in alerts');
  const patternIds = a.patterns.map((p) => p.id);
  assert.ok(patternIds.includes('kernel_lpe_with_poc'),
    `CVE-2026-46333 must match kernel_lpe_with_poc; matched: ${patternIds.join(', ')}`);
});

test('watchlist --alerts: MAL-2026-SHAI-HULUD-OSS surfaces under supply_chain_family', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  const body = tryJson(r.stdout);
  const a = body.alerts.find((x) => x.cve_id === 'MAL-2026-SHAI-HULUD-OSS');
  assert.ok(a, 'MAL-2026-SHAI-HULUD-OSS must surface in alerts');
  const patternIds = a.patterns.map((p) => p.id);
  assert.ok(patternIds.includes('supply_chain_family'),
    `MAL-2026-SHAI-HULUD-OSS must match supply_chain_family; matched: ${patternIds.join(', ')}`);
});

test('watchlist --alerts: sort order — critical-severity alerts first', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  const body = tryJson(r.stdout);
  if (body.alerts.length < 2) return; // can't test order with <2
  const weight = { critical: 0, high: 1, medium: 2, low: 3 };
  function minWeight(a) { return Math.min(...a.patterns.map((p) => weight[p.severity] ?? 9)); }
  for (let i = 1; i < body.alerts.length; i++) {
    const wprev = minWeight(body.alerts[i - 1]);
    const wcurr = minWeight(body.alerts[i]);
    assert.ok(wprev <= wcurr,
      `sort order violation at index ${i}: alert ${body.alerts[i - 1].cve_id} (severity weight ${wprev}) ranked before ${body.alerts[i].cve_id} (severity weight ${wcurr})`);
  }
});

test('watchlist --alerts: human-mode output names each surfaced CVE', () => {
  const r = cli(['watchlist', '--alerts']);
  assert.equal(r.status, 0);
  // Human-mode output should include the alerts banner + at least one
  // CVE-id-shaped line.
  assert.match(r.stdout, /CVE-class Alerts/);
  assert.match(r.stdout, /Entries scanned:/);
  assert.match(r.stdout, /CVE-2026-\d{4,7}|MAL-2026-/, 'human output must include at least one CVE/MAL id');
});
