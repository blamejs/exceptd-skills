'use strict';

/**
 * tests/cli-output-envelope-shape-v0_12_39.test.js
 *
 * Cycle 13 P3 F3 + cycle 19 B follow-up (v0.12.39): pin the EXACT top-level
 * JSON envelope shape for the 6 verbs whose envelope was not yet bound:
 * `brief --all`, `ci`, `discover`, `doctor`, `watchlist`, `run` (both
 * single-playbook and multi-playbook variants). The v0.12.33 envelope
 * test (`cli-output-envelope-shape.test.js`) covered `attest list`,
 * `attest verify`, and `version`. v0.12.39 closes the rest.
 *
 * A contributor adding / removing a top-level field on any of these
 * verbs must now update this contract — that's the entire point.
 *
 * Several intentional inconsistencies (documented per cycle 19 B
 * audit) are pinned by absence:
 *   - `brief --all` and `watchlist` do NOT emit a `verb` field (every
 *     other verb does). Pinned so accidental "added verb field" land
 *     as an intentional change in v0.13.
 *   - `ci` and `doctor` do NOT emit a top-level `ok` field. They
 *     signal pass/fail through `summary.verdict` and `summary.all_green`
 *     respectively. Pinned so the v0.11.13 emit() contract doesn't
 *     accidentally grow into them.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * key set (deepEqual) or specific scalar value.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// brief --all -------------------------------------------------------------

test('brief --all envelope: exact top-level key set', () => {
  const r = cli(['brief', '--all']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `brief --all must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  // Pre-cycle-19-B-audit shape: 8 top-level keys, NO `verb` field.
  // The verb-field absence is a transitional inconsistency with the rest
  // of the CLI; flagged for the v0.13 envelope-harmonization pass.
  const expected = [
    'contract', 'exceptd_owns', 'generated_at', 'grouped_by_scope',
    'host_ai_owns', 'playbooks', 'scope_summary', 'session_id',
  ];
  assert.deepEqual(Object.keys(body).sort(), expected);
  // Per cycle 19 B doc: pin absence of `verb` for the transition.
  assert.equal(body.verb, undefined,
    'brief --all does NOT emit a verb field today; if you added one, update this test + flag for v0.13 harmonization');
  assert.match(body.contract, /seven-phase: govern → direct → look → detect → analyze → validate → close/);
  assert.match(body.session_id, /^[0-9a-f]{16}$/);
  assert.match(body.generated_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(Array.isArray(body.host_ai_owns));
  assert.ok(Array.isArray(body.exceptd_owns));
  assert.ok(Array.isArray(body.playbooks));
});

// ci ----------------------------------------------------------------------

test('ci --required <pb> envelope: exact top-level key set + summary sub-key set', () => {
  const r = cli(['ci', '--required', 'cred-stores']);
  // Status may be 4 (BLOCKED) without preconditions verified; that's fine
  // for the envelope-shape test — we only care about the JSON shape.
  const body = tryJson(r.stdout);
  assert.ok(body, `ci must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  const expected = ['playbooks_run', 'results', 'session_id', 'summary', 'verb'];
  assert.deepEqual(Object.keys(body).sort(), expected);
  assert.equal(body.verb, 'ci');
  assert.equal(body.ok, undefined,
    'ci does NOT emit top-level ok — pass/fail flows through summary.verdict');
  assert.ok(Array.isArray(body.playbooks_run));
  assert.ok(Array.isArray(body.results));

  // summary sub-key set (13 keys per cycle 19 B audit).
  const expectedSummaryKeys = [
    'blocked', 'clock_started_reasons', 'detected', 'fail_reasons',
    'framework_gap_count', 'framework_gap_rollup', 'inconclusive',
    'jurisdiction_clock_rollup', 'jurisdiction_clocks_started',
    'max_rwep_observed', 'not_detected', 'total', 'verdict',
  ];
  assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
  assert.equal(typeof body.summary.verdict, 'string');
  assert.equal(typeof body.summary.total, 'number');
  assert.equal(typeof body.summary.max_rwep_observed, 'number');
});

// discover ----------------------------------------------------------------

test('discover envelope: exact top-level key set + context sub-keys', () => {
  const r = cli(['discover', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `discover must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  const expected = ['context', 'next_steps', 'recommended_playbooks', 'verb'];
  assert.deepEqual(Object.keys(body).sort(), expected);
  assert.equal(body.verb, 'discover');
  assert.ok(Array.isArray(body.next_steps));
  assert.ok(Array.isArray(body.recommended_playbooks));

  const expectedContextKeys = ['cwd', 'detected_files', 'git_remote', 'host_distro', 'host_platform'];
  assert.deepEqual(Object.keys(body.context).sort(), expectedContextKeys);
  assert.equal(typeof body.context.cwd, 'string');
  assert.equal(typeof body.context.host_platform, 'string');
  assert.ok(Array.isArray(body.context.detected_files));

  for (const p of body.recommended_playbooks) {
    assert.equal(typeof p.id, 'string');
    assert.equal(typeof p.reason, 'string');
  }
});

// doctor ------------------------------------------------------------------

test('doctor envelope: exact top-level + summary sub-key set + baseline check set', () => {
  const r = cli(['doctor', '--json']);
  // doctor exit may be 1 if signing key absent; envelope shape unchanged.
  const body = tryJson(r.stdout);
  assert.ok(body, `doctor must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(), ['checks', 'summary', 'verb']);
  assert.equal(body.verb, 'doctor');
  assert.equal(body.ok, undefined,
    'doctor does NOT emit top-level ok — pass/fail flows through summary.all_green');

  // Baseline 5 checks always present (registry conditional on --registry-key).
  const baselineChecks = ['currency', 'cves', 'rfcs', 'signatures', 'signing'];
  for (const k of baselineChecks) {
    assert.ok(k in body.checks, `expected check "${k}" in doctor.checks`);
    assert.equal(typeof body.checks[k].ok, 'boolean');
  }

  const expectedSummaryKeys = [
    'all_green', 'failed_checks', 'issues_count',
    'warning_checks', 'warnings_count',
  ];
  assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
  assert.equal(typeof body.summary.all_green, 'boolean');
  assert.ok(Array.isArray(body.summary.failed_checks));
  assert.ok(Array.isArray(body.summary.warning_checks));
  assert.equal(body.summary.issues_count, body.summary.failed_checks.length);
  assert.equal(body.summary.warnings_count, body.summary.warning_checks.length);
});

// watchlist ---------------------------------------------------------------

test('watchlist (default by-item mode) envelope: exact top-level key set', () => {
  const r = cli(['watchlist', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `watchlist must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(),
    ['by_item', 'generated_at', 'mode', 'parse_errors', 'skills_scanned']);
  assert.equal(body.mode, 'by-item');
  assert.equal(typeof body.skills_scanned, 'number');
  assert.equal(typeof body.parse_errors, 'number');
  assert.match(body.generated_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(typeof body.by_item, 'object');
  assert.equal(body.verb, undefined,
    'watchlist does NOT emit a verb field today (transitional with brief --all); flag for v0.13 harmonization');
});

test('watchlist --by-skill envelope: by_skill key replaces by_item', () => {
  const r = cli(['watchlist', '--by-skill', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `watchlist --by-skill must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(),
    ['by_skill', 'generated_at', 'mode', 'parse_errors', 'skills_scanned']);
  assert.equal(body.mode, 'by-skill');
  assert.equal(body.by_item, undefined,
    'by-skill mode must NOT carry by_item; mutually exclusive');
});

// run (single-playbook, success path) -------------------------------------

test('run <pb> --evidence envelope (single-playbook success): exact top-level key set', () => {
  // Positive-detect kernel run — the canonical "attestation persisted"
  // shape. Same evidence shape the cycle 14 / 16 sanity checks use.
  const evidence = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
    signal_overrides: { 'kver-in-affected-range': 'hit' },
  });
  // Use --attestation-root to a tmpdir so the test doesn't leak into
  // the real ~/.exceptd/. Pattern matches v0.12.38 attestation-mode test.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-run-'));
  try {
    const r = cli(['run', 'kernel', '--evidence', '-', '--json',
      '--attestation-root', path.join(tmpHome, 'attestations')], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);
    const body = tryJson(r.stdout);
    assert.ok(body, `run kernel must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    const expected = [
      'ack', 'directive_id', 'evidence_hash', 'ok', 'phases',
      'playbook_id', 'precondition_check_source', 'preflight_issues',
      'session_id', 'submission_digest',
    ];
    assert.deepEqual(Object.keys(body).sort(), expected);
    assert.equal(body.ok, true);
    assert.equal(body.playbook_id, 'kernel');
    assert.equal(typeof body.directive_id, 'string');
    assert.match(body.session_id, /^[0-9a-f-]+$/);
    assert.match(body.evidence_hash, /^[0-9a-f]+$/);
    assert.match(body.submission_digest, /^[0-9a-f]+$/);
    assert.ok(Array.isArray(body.preflight_issues));
    assert.equal(typeof body.phases, 'object');
    assert.equal(typeof body.ack, 'boolean');
    // Conditional fields absent on a fresh non-collision run:
    assert.equal(body.prior_session_id, undefined);
    assert.equal(body.overwrote_at, undefined);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

// Error-case envelope shared shape ----------------------------------------

test('shared error envelope (run unknown playbook): exact required field set', () => {
  const r = cli(['run', 'this-playbook-does-not-exist']);
  assert.equal(r.status, 1, `unknown playbook must exit 1; got ${r.status}`);
  const err = tryJson(r.stderr);
  assert.ok(err, `error stderr must be JSON; got: ${r.stderr.slice(0, 200)}`);
  // Required fields per cycle 19 B audit:
  assert.equal(err.ok, false);
  assert.equal(typeof err.error, 'string');
  // verb-specific additions tolerated (wanted/type/hint/etc); only
  // assert the minimum shape every error MUST carry.
});
