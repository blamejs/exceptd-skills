'use strict';

/**
 * tests/help-verb-attest-list-deprecation.test.js
 *
 * Cycle 11 P2/P3 fixes (v0.12.32):
 *
 *   F4 — `exceptd help <verb>` now routes through printPlaybookVerbHelp()
 *        so operators get verb-specific help regardless of whether they
 *        type `exceptd help run` or `exceptd run --help`. Pre-fix it
 *        dropped the verb argument and printed the top-level help.
 *
 *   F5 — `attest list` empty-state human renderer surfaces `roots_evaluated`
 *        showing every candidate root + whether it existed (`[scanned-empty]`
 *        vs `[not-present]`). Pre-fix it said `(no attestations under )`
 *        with an empty path list when no roots existed at all. JSON output
 *        also carries a structured `roots_evaluated[]` array.
 *
 *   F7 — Legacy-verb deprecation banner now persists suppression across
 *        invocations via an OS-tempdir marker keyed by exceptd version.
 *        Pre-fix the env-var guard reset on every fresh node process so
 *        operators saw the same banner on every `exceptd plan` invocation.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * value (status code, string presence/absence, array shape).
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
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// F4 ------------------------------------------------------------------------

test('F4: `exceptd help run` returns verb-specific help (not top-level)', () => {
  const r = cli(['help', 'run']);
  assert.equal(r.status, 0);
  // Verb-specific help opens with the verb name + a brief tagline.
  assert.equal(/^run \[playbook\]/m.test(r.stdout), true,
    `expected verb-specific help opening; got: ${r.stdout.slice(0, 200)}`);
  // Verb-specific help (not top-level) — must mention the phase chain
  // for the run verb specifically.
  assert.equal(/detect → analyze/.test(r.stdout), true,
    'verb-specific help for run should mention the phase chain');
  // Must NOT be the top-level help (which opens with "exceptd CLI" /
  // "VERBS" / similar section banners).
  assert.equal(/^VERBS$|^exceptd CLI/m.test(r.stdout), false,
    'verb-specific help should NOT be the top-level help banner');
});

test('F4: `exceptd help <unknown>` falls through to top-level help with stderr note', () => {
  const r = cli(['help', 'definitely-not-a-real-verb-zzz']);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /no verb-specific help for "definitely-not-a-real-verb-zzz"/);
  // Top-level help banner is reachable in stdout.
  assert.equal(r.stdout.length > 200, true, 'top-level help should have substantial content');
});

// F5 ------------------------------------------------------------------------

test('F5: `attest list --json` carries roots_evaluated[] with per-root exists flag', () => {
  // Force a synthetic EXCEPTD_HOME so the test is deterministic regardless
  // of what's on the host. Run in a tempdir so the cwd-relative
  // `.exceptd/attestations/` path is also empty.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-cwd-'));
  try {
    const r = cli(['attest', 'list', '--json'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, true);
    assert.equal(body.count, 0);
    assert.equal(Array.isArray(body.roots_evaluated), true);
    assert.equal(body.roots_evaluated.length >= 1, true);
    for (const r of body.roots_evaluated) {
      assert.equal(typeof r.root, 'string');
      assert.equal(typeof r.exists, 'boolean');
    }
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

test('F5: `attest list` empty-state human output names each candidate root', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-cwd-'));
  try {
    const r = cli(['attest', 'list'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 0);
    // Pre-fix output: "  (no attestations under )" — empty path.
    // Post-fix output: candidate roots block with [scanned-empty] / [not-present] markers.
    assert.match(r.stdout, /candidate roots evaluated:/);
    assert.match(r.stdout, /\[scanned-empty\]|\[not-present\]/);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

// F7 ------------------------------------------------------------------------

test('F7: legacy-verb deprecation banner shows once, then is suppressed by tempdir marker', () => {
  const pkg = require(path.join(ROOT, 'package.json'));
  const marker = path.join(os.tmpdir(), `exceptd-deprecation-shown-v${pkg.version}`);
  // Reset to ensure a clean test run.
  try { fs.unlinkSync(marker); } catch {}
  try {
    // First invocation: banner must fire on stderr.
    const r1 = cli(['plan'], { env: { EXCEPTD_DEPRECATION_SHOWN: '' } });
    assert.equal(r1.status, 0);
    assert.match(r1.stderr, /DEPRECATION.*plan.*is a v0\.10\.x verb/);
    assert.equal(fs.existsSync(marker), true, 'marker file must be created after first banner');
    // Second invocation: marker present, banner suppressed.
    const r2 = cli(['plan'], { env: { EXCEPTD_DEPRECATION_SHOWN: '' } });
    assert.equal(r2.status, 0);
    assert.equal(r2.stderr.includes('DEPRECATION'), false,
      `second invocation must NOT emit the deprecation banner; got stderr: ${r2.stderr.slice(0, 200)}`);
  } finally {
    try { fs.unlinkSync(marker); } catch {}
  }
});

test('F7: explicit EXCEPTD_DEPRECATION_SHOWN=1 suppresses even the first display', () => {
  const pkg = require(path.join(ROOT, 'package.json'));
  const marker = path.join(os.tmpdir(), `exceptd-deprecation-shown-v${pkg.version}`);
  try { fs.unlinkSync(marker); } catch {}
  try {
    const r = cli(['plan'], { env: { EXCEPTD_DEPRECATION_SHOWN: '1' } });
    assert.equal(r.status, 0);
    assert.equal(r.stderr.includes('DEPRECATION'), false);
  } finally {
    try { fs.unlinkSync(marker); } catch {}
  }
});
