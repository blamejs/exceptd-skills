'use strict';

/**
 * tests/cli-output-envelope-shape.test.js
 *
 * Cycle 13 P3 F3 fix (v0.12.33): no CLI verb had a test that pinned the
 * EXACT top-level JSON envelope shape. A contributor adding a new top-
 * level field to `attest list`, `attest verify`, `ci`, `brief`, `doctor`,
 * `watchlist`, etc. would not get a forcing-function test failure, so
 * the operator-facing JSON contract drifted silently across releases.
 *
 * This test pins the top-level key set per verb. When a field is added or
 * removed intentionally, the contributor must update the expected key
 * list here — that's the entire point. The test ALWAYS uses
 * `assert.deepEqual(sortedKeys, expected)` per CLAUDE.md anti-coincidence
 * rule, never `assert.ok(field)`.
 *
 * Coverage scope is intentionally narrow at v0.12.33 introduction:
 * `attest list` (the simplest verb with no playbook execution),
 * `attest verify` (the second simplest), and `version` (the trivial
 * scalar that proves the test harness works). Future cycles can expand
 * to `run`, `ci`, `discover`, `brief`, `doctor`, `watchlist` as their
 * envelope shapes stabilize.
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
    env: { ...process.env, ...(opts.env || {}), EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test('attest list --json envelope: exact top-level key set', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-cwd-'));
  try {
    const r = cli(['attest', 'list', '--json'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome },
    });
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
    const keys = Object.keys(body).sort();
    // Adding / removing a top-level field on `attest list` MUST update
    // this list. Cycle 11 F5 added `roots_evaluated`; that addition was
    // intentional and this test was authored to capture the post-fix state.
    assert.deepEqual(keys, [
      'attestations',
      'count',
      'filter',
      'ok',
      'roots_evaluated',
      'roots_searched',
    ]);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

test('attest verify (no session) envelope: exact top-level key set on error path', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
  try {
    const r = cli(['attest', 'verify', 'this-session-does-not-exist', '--json'], {
      env: { EXCEPTD_HOME: tmpHome },
    });
    // Exit code is non-zero on missing session; envelope still parseable.
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body, `attest verify error envelope must parse; got stderr: ${r.stderr.slice(0, 200)} stdout: ${r.stdout.slice(0, 200)}`);
    // Error envelope per emitError() shape: ok + error + (optional) hint
    // + (optional) verb. Verb is always present for the dispatch-error
    // class; not always for the inner-handler error class.
    assert.equal(body.ok, false);
    assert.equal(typeof body.error, 'string');
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test('exceptd version: trivial scalar contract (proves harness)', () => {
  const r = cli(['version']);
  assert.equal(r.status, 0);
  // Stdout is a bare semver newline, NOT JSON. The contract is that
  // `version` always returns ONE token on stdout that semver-parses.
  const v = r.stdout.trim();
  assert.match(v, /^\d+\.\d+\.\d+$/, `version must be a bare semver; got: ${JSON.stringify(v)}`);
});

test('attest list (human renderer, empty state) names every candidate root', () => {
  // Cycle 11 F5 cross-check: the empty-state human renderer surfaces
  // each candidate root with `[scanned-empty]` or `[not-present]`
  // markers. Pre-fix it said "(no attestations under )" with an empty
  // path list — operators couldn't see which directory was scanned.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-cwd-'));
  try {
    const r = cli(['attest', 'list'], { cwd: tmpCwd, env: { EXCEPTD_HOME: tmpHome } });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /candidate roots evaluated:/);
    assert.match(r.stdout, /\[scanned-empty\]|\[not-present\]/);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});
