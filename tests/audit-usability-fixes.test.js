'use strict';

/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================

test('unknown flag on discover hard-fails with structured envelope', () => {
  const r = cli(['discover', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
  assert.ok(Array.isArray(body.unknown_flags), 'unknown_flags must be an array');
  assert.ok(body.unknown_flags.length > 0, 'unknown_flags must be non-empty');
  assert.ok(Array.isArray(body.known_flags), 'known_flags must be an array');
  assert.ok(body.known_flags.length > 0, 'known_flags must be non-empty');
});

test('unknown flag on ci hard-fails (exit 1)', () => {
  const r = cli(['ci', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});

test('unknown flag on ask hard-fails (exit 1)', () => {
  const r = cli(['ask', 'x', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});

test('unknown flag typo gets a did_you_mean suggestion', () => {
  const r = cli(['discover', '--scop', 'code']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.ok(Array.isArray(body.unknown_flags) && body.unknown_flags.length > 0,
    'unknown_flags must be a non-empty array');
  assert.ok(Array.isArray(body.unknown_flags[0].did_you_mean),
    'did_you_mean must be an array');
  assert.ok(body.unknown_flags[0].did_you_mean.includes('--scope'),
    `did_you_mean must suggest --scope; got ${JSON.stringify(body.unknown_flags[0].did_you_mean)}`);
});

test('cross-verb flag yields the tailored "irrelevant" message, not unknown-flag (--csaf-status)', () => {
  // --csaf-status is a real flag on run/ci/ingest but irrelevant on brief.
  // The refusal must say so explicitly rather than collapse into the generic
  // unknown-flag path — that's the whole point of the tailored message.
  const r = cli(['brief', 'secrets', '--csaf-status', 'final']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /irrelevant/);
  assert.doesNotMatch(body.error, /unknown flag/);
});

test('cross-verb flag yields the tailored "irrelevant" message, not unknown-flag (--ack)', () => {
  const r = cli(['brief', 'secrets', '--ack']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /irrelevant/);
  assert.doesNotMatch(body.error, /unknown flag/);
});

test('known flags still work: discover --scope code (exit 0)', () => {
  const r = cli(['discover', '--scope', 'code']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
});

test('known flags still work: discover --json (exit 0, parseable stdout)', () => {
  const r = cli(['discover', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `discover --json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
});

// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================

test('run --format json emits the full run result, not a stub', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'json'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `run --format json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body.phases, 'object');
  assert.ok(body.phases !== null, 'phases must not be null');
  assert.equal(body.playbook_id, 'secrets');
  assert.ok(Object.keys(body).length > 5,
    `full result must carry more than 5 top-level keys; got ${Object.keys(body).length}`);
});

// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================

test('multiple --format values: first format to stdout, note to stderr', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'sarif', '--format', 'openvex'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout must parse as JSON; got: ${r.stdout.slice(0, 200)}`);
  // First format wins on stdout → SARIF carries a $schema.
  assert.equal(typeof body['$schema'], 'string');
  assert.match(body['$schema'], /sarif/);
  assert.match(r.stderr, /--format values given|bundles_by_format/);
});

// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================

test('sarif bundle: no top-level ok, carries spec marker', () => {
  // crypto gates on a Linux-platform precondition; satisfy it so the run
  // proceeds to emit a bundle regardless of the test host's OS.
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'sarif'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `sarif stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(body.version, '2.1.0');
  assert.ok(Array.isArray(body.runs), 'sarif must carry a runs array');
});

test('csaf-2.0 bundle: no top-level ok, carries document object', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'csaf-2.0'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `csaf stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body.document, 'object');
  assert.ok(body.document !== null, 'csaf document must not be null');
});

test('openvex bundle: no top-level ok, carries @context string', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'openvex'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `openvex stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body['@context'], 'string');
});

// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================

test('skill --help shows usage, not "Skill not found"', () => {
  const r = cli(['skill', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /exceptd skill <name>/);
  assert.doesNotMatch(r.stdout, /Skill not found/);
});

test('framework-gap --help shows usage', () => {
  const r = cli(['framework-gap', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /framework-gap </);
});

test('refresh --help keeps its own detailed help (not swallowed by --help interception)', () => {
  const r = cli(['refresh', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /check-advisories/);
});

// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================

test('collect emits JSON when piped (non-TTY), not human prose', () => {
  const r = cli(['collect', 'secrets']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `collect stdout must parse as JSON when piped; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body.playbook_id, 'string');
  assert.equal(body.verb, 'collect');
});

// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================

test('refresh parseArgs: --check-advisories is report-only and source-scoped', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const a = parseArgs(['node', 'x', '--check-advisories']);
  assert.equal(a.source, 'advisories');
  assert.equal(a.apply, false);
  assert.equal(a.checkAdvisories, true);
  // --apply must NOT flip a check-advisories run to write mode, regardless of order.
  const b = parseArgs(['node', 'x', '--check-advisories', '--apply']);
  assert.equal(b.apply, false);
});

// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('attest list --limit on an empty isolated root: deterministic envelope', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-cwd-'));
  try {
    const r = cli(['attest', 'list', '--limit', '3', '--json'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome },
    });
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
    assert.equal(body.count, 0);
    assert.equal(body.shown, 0);
    assert.equal(body.limit, 3);
    assert.ok(Array.isArray(body.attestations), 'attestations must be an array');
    assert.equal(body.attestations.length, 0, 'empty root yields zero attestations');
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

test('attest list --limit rejects a non-integer value (exit 1)', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-cwd-'));
  try {
    const r = cli(['attest', 'list', '--limit', 'abc'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome },
    });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
    assert.match(r.stderr, /non-negative integer/);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});
