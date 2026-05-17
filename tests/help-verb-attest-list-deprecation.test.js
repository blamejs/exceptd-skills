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

// F7 v0.13.0 update --------------------------------------------------------
//
// v0.13.0 honored the long-advertised legacy-verb removal. The pre-v0.13
// deprecation-banner mechanism (soft banner + tempdir marker for once-per-
// version display) was replaced by a hard refusal with a replacement hint.
// The two prior F7 tests asserted banner+suppress semantics; both are
// replaced with refusal-shape assertions below.

test('F7: removed legacy verbs (plan/govern/direct/look/ingest) are refused with replacement hint', () => {
  // Exhaustive across the 5 removed verbs so a regression that re-routes
  // one of them silently is caught. (reattest and list-attestations are
  // preserved as canonical short-form routings — they remain operationally
  // useful and v0.13 does not remove them.)
  const removedPairs = [
    ['plan', 'brief --all'],
    ['govern', 'brief <pb> --phase govern'],
    ['direct', 'brief <pb> --phase direct'],
    ['look', 'brief <pb> --phase look'],
    ['ingest', 'run'],
  ];
  for (const [removed, replacement] of removedPairs) {
    const r = cli([removed]);
    assert.equal(r.status, 1, `${removed}: expected exit 1; got ${r.status}`);
    const body = JSON.parse(r.stderr.trim());
    assert.equal(body.ok, false, `${removed}: body must be ok:false`);
    assert.equal(body.verb, removed, `${removed}: body.verb must echo input`);
    assert.equal(body.removed_in, '0.13.0', `${removed}: removed_in must be "0.13.0"`);
    assert.equal(body.replacement, replacement,
      `${removed}: replacement must be "${replacement}"; got "${body.replacement}"`);
    assert.match(body.error, new RegExp(`'${removed}' was removed in v0\\.13\\.0\\. Use .exceptd ${replacement.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&')}.`),
      `${removed}: error string must point at the replacement command`);
  }
});

test('F7: removal refusal carries deprecation_history field for operator audit', () => {
  const r = cli(['plan']);
  const body = JSON.parse(r.stderr.trim());
  assert.equal(typeof body.deprecation_history, 'string');
  assert.match(body.deprecation_history, /v0\.11\.0/);
  assert.match(body.deprecation_history, /v0\.13\.0/);
});
