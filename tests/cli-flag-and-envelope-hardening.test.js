'use strict';

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

test('F1: validate-cves --offline still produces the offline view, exit 0', () => {
  const r = cli(['validate-cves', '--offline'], { timeout: 20000 });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /offline mode — no network calls made/);
});

// ---------------------------------------------------------------------------
// Finding 2 — cve / rfc envelope ok derived from status (not inverted).
// ---------------------------------------------------------------------------

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

test('F2: rfc --check title MISMATCH → ok:false exit 2', () => {
  const r = cli(['rfc', '2119', '--check', 'wrong title', '--json', '--air-gap']);
  assert.equal(r.status, 2);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'rfc');
  assert.equal(body.title_match, false);
});

test('F2: rfc --check title MATCH → ok:true exit 0', () => {
  const r = cli(['rfc', '2119', '--check', 'Key words for use in RFCs', '--json', '--air-gap']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, true);
  assert.equal(body.title_match, true);
});

// ---------------------------------------------------------------------------
// Finding 3 — refresh / prefetch unknown-flag rejection.
// ---------------------------------------------------------------------------

test('F3: refresh --badflag → ok:false exit 2 (not silently swallowed)', () => {
  const r = cli(['refresh', '--badflag', '--air-gap'], { timeout: 20000 });
  assert.equal(r.status, 2, 'refresh usage error exits 2 per its own scheme');
  const body = tryJson(r.stderr.trim());
  assert.ok(body, 'must emit a parseable JSON envelope on stderr');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'refresh');
  assert.deepEqual(body.unknown_flags, ['--badflag']);
  assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--source'));
});

test('F3: refresh --source kev --air-gap still runs (dry-run), exit 0', () => {
  const r = cli(['refresh', '--source', 'kev', '--air-gap'], { timeout: 20000 });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /air-gap mode: kev skipped|dry-run/);
});

test('F3: prefetch --badflag → ok:false exit 2', () => {
  const r = cli(['prefetch', '--badflag', '--no-network'], { timeout: 20000 });
  assert.equal(r.status, 2);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, 'must emit a parseable JSON envelope on stderr');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'prefetch');
  assert.deepEqual(body.unknown_flags, ['--badflag']);
  assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--source'));
});

test('F3: prefetch --no-network --source kev still runs (dry-run), exit 0', () => {
  const r = cli(['prefetch', '--no-network', '--source', 'kev'], { timeout: 20000 });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /prefetch summary:/);
});

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

test('F4: scan --json carries top-level ok:true, exit 0', () => {
  const r = cli(['scan', '--json'], { timeout: 20000 });
  assert.equal(r.status, 0);
  const body = lastJsonLine(r.stdout);
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, true);
});

test('F4: scan --badflag → ok:false exit 1', () => {
  const r = cli(['scan', '--badflag'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'scan');
  assert.deepEqual(body.unknown_flags, ['--badflag']);
});

test('F4: dispatch --json carries top-level ok:true, exit 0', () => {
  const r = cli(['dispatch', '--json'], { timeout: 20000 });
  assert.equal(r.status, 0);
  const body = lastJsonLine(r.stdout);
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, true);
});

test('F4: dispatch --badflag → ok:false exit 1', () => {
  const r = cli(['dispatch', '--badflag'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'dispatch');
});

test('F4: currency --json carries top-level ok:true, exit 0', () => {
  const r = cli(['currency', '--json'], { timeout: 20000 });
  assert.equal(r.status, 0);
  const body = lastJsonLine(r.stdout);
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, true);
  assert.ok(Array.isArray(body.currency_report), 'currency_report must be present');
});

test('F4: currency --badflag → ok:false exit 1', () => {
  const r = cli(['currency', '--badflag'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = lastJsonLine(r.stdout);
  assert.ok(body);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'currency');
});

test('F4: watchlist --json carries top-level ok:true, exit 0', () => {
  const r = cli(['watchlist', '--json'], { timeout: 20000 });
  assert.equal(r.status, 0);
  const body = lastJsonLine(r.stdout);
  assert.ok(body, 'must emit a parseable JSON envelope');
  assert.equal(body.ok, true);
});

test('F4: watchlist --badflag → ok:false exit 1', () => {
  const r = cli(['watchlist', '--badflag'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'watchlist');
  assert.deepEqual(body.unknown_flags, ['--badflag']);
});

// ---------------------------------------------------------------------------
// Finding 5 — framework-gap / skill missing-arg paths honor --json; skill
// no longer treats --json as args[0].
// ---------------------------------------------------------------------------

test('F5: framework-gap --json missing-arg → ok:false JSON exit 1', () => {
  const r = cli(['framework-gap', '--json'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'must emit a parseable JSON envelope on stdout');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'framework-gap');
  assert.equal(typeof body.error, 'string');
  assert.ok(body.error.length > 0);
});

test('F5: skill --json missing-arg → ok:false JSON exit 1 (not "Skill not found: --json")', () => {
  const r = cli(['skill', '--json'], { timeout: 20000 });
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'must emit a parseable JSON envelope on stdout');
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'skill');
  assert.equal(typeof body.error, 'string');
  assert.doesNotMatch(body.error, /Skill not found: --json/,
    '--json must not be treated as the skill name');
});

test('F5: skill <real-skill> still resolves with --json filtered from positionals, exit 0', () => {
  const r = cli(['skill', 'kernel-lpe-triage', '--json'], { timeout: 20000 });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Skill: kernel-lpe-triage/);
});
