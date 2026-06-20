'use strict';

/**
 * Regression: `attest prune` must dedup its search roots by CANONICAL path,
 * not by raw string. The two roots it walks are the resolved attestation root
 * and the legacy `<cwd>/.exceptd/attestations` root. When both resolve to the
 * SAME directory via different path strings — e.g. a relative `EXCEPTD_HOME`
 * like `.exceptd` (whose root joins to the relative `.exceptd/attestations`,
 * pointing at the same dir as the absolute cwd literal) — a plain Set over the
 * raw strings keeps both. Every session under that dir was then scanned twice:
 * `scanned`/`kept`/`pruned_count` were inflated and each prunable session was
 * listed twice in the preview's `pruned[]`.
 *
 * The fix canonicalizes each root (realpathSync, falling back to path.resolve
 * for a not-yet-created dir) before dedup, so the same directory reached by
 * two strings collapses to one search — while two genuinely distinct dirs are
 * still both scanned.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const { CLI, tryJson } = require('./_helpers/cli');

// This test deliberately controls the spawned process's cwd and sets a
// RELATIVE EXCEPTD_HOME, so it spawns directly rather than via the shared
// makeCli() helper (which pins EXCEPTD_HOME to an absolute suite dir and has
// no cwd override).
function prune(cwd, env) {
  return spawnSync(
    process.execPath,
    [CLI, 'attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json'],
    {
      encoding: 'utf8',
      cwd,
      env: {
        ...process.env,
        EXCEPTD_DEPRECATION_SHOWN: '1',
        EXCEPTD_UNSIGNED_WARNED: '1',
        EXCEPTD_RAW_JSON: '1',
        EXCEPTD_LOCK_DIR: path.join(cwd, '_locks'),
        ...env,
      },
      timeout: 30000,
    },
  );
}

function stageSession(rootDir, sid, capturedAt) {
  const sdir = path.join(rootDir, sid);
  fs.mkdirSync(sdir, { recursive: true });
  fs.writeFileSync(
    path.join(sdir, 'attestation.json'),
    JSON.stringify({ session_id: sid, captured_at: capturedAt, kind: 'attestation' }),
  );
}

test('same dir reached via relative EXCEPTD_HOME + cwd literal is scanned ONCE, not twice', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-prune-dedup-'));
  try {
    // <cwd>/.exceptd/attestations holds one old session. With EXCEPTD_HOME set
    // to the RELATIVE string `.exceptd`, the resolved root is
    // `.exceptd/attestations` — same directory, different string from the
    // absolute `<cwd>/.exceptd/attestations` literal.
    stageSession(path.join(cwd, '.exceptd', 'attestations'), 'sess-AAA', '2020-01-01T00:00:00Z');

    const r = prune(cwd, { EXCEPTD_HOME: '.exceptd' });
    assert.equal(r.status, 0, r.stderr);
    const body = tryJson(r.stdout);
    assert.ok(body && Array.isArray(body.pruned), 'output carries pruned[]');

    // Exact counts: one session => scanned 1, pruned_count 1 (pre-fix: 2 / 2).
    assert.equal(body.scanned, 1, 'one session must be scanned exactly once');
    assert.equal(body.pruned_count, 1, 'pruned_count must count the session once');

    const ids = body.pruned.map((p) => p.session_id);
    assert.deepEqual(ids, ['sess-AAA'], 'session listed exactly once (no duplicate)');
    assert.equal(new Set(ids).size, ids.length, 'no duplicate session_id in pruned[]');

    // The two same-dir roots collapse to one canonical entry.
    assert.equal(body.roots_searched.length, 1, 'same-dir roots collapse to one');
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('two genuinely distinct roots are BOTH still scanned (dedup must not over-collapse)', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-prune-distinct-'));
  try {
    // Distinct dirs: an absolute EXCEPTD_HOME elsewhere + the cwd literal.
    stageSession(path.join(cwd, '.exceptd', 'attestations'), 'sess-CWD', '2020-01-01T00:00:00Z');
    const homeAbs = path.join(cwd, 'fakehome');
    stageSession(path.join(homeAbs, 'attestations'), 'sess-HOME', '2020-01-01T00:00:00Z');

    const r = prune(cwd, { EXCEPTD_HOME: homeAbs });
    assert.equal(r.status, 0, r.stderr);
    const body = tryJson(r.stdout);

    assert.equal(body.scanned, 2, 'both distinct-dir sessions scanned');
    assert.equal(body.roots_searched.length, 2, 'two distinct roots remain two');
    const ids = body.pruned.map((p) => p.session_id).sort();
    assert.deepEqual(ids, ['sess-CWD', 'sess-HOME'], 'each distinct-root session listed once');
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
