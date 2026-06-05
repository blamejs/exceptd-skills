'use strict';

/**
 * Two narrow contracts:
 *
 *   1. `exceptd watch` reports lock contention with the EX_TEMPFAIL exit (75)
 *      even when the contention surfaces on the stale-reclaim path. After the
 *      watcher judges a lock stale and unlinks it, another reclaimer can win
 *      the create race; the resulting O_EXCL EEXIST is contention ("retry
 *      later"), not a generic failure (1).
 *
 *   2. cve-regression-watcher stamps `generated_at` from the same injectable
 *      clock that derives the threshold year, so both date-derived report
 *      fields share one instant rather than diverging from a module-load
 *      timestamp.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');
const WATCHER = require(path.join(ROOT, 'lib', 'cve-regression-watcher.js'));

test('watch reports lock contention (75) when the stale-reclaim create loses a race', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'z-watch-reclaim-'));
  try {
    // Place a DIRECTORY at the lock path. This deterministically reproduces
    // the reclaim-race interleaving: the first O_EXCL create sees EEXIST, the
    // staleness probe's read fails (so the lock is judged stale), the unlink
    // of the still-present name is swallowed, and the reclaim O_EXCL create
    // sees EEXIST again — the exact shape of "another reclaimer won the race
    // between our unlink and our re-create".
    const lockPath = path.join(home, 'watch.lock');
    fs.mkdirSync(lockPath);

    const r = spawnSync(process.execPath, [ORCH, 'watch'], {
      encoding: 'utf8',
      timeout: 8000,
      env: {
        ...process.env,
        EXCEPTD_HOME: home,
        EXCEPTD_SUPPRESS_DEPRECATION: '1',
      },
    });

    assert.equal(
      r.status,
      75,
      `reclaim-race contention must exit EX_TEMPFAIL 75, not GENERIC_FAILURE 1; got ${r.status} stderr=${r.stderr}`,
    );
    assert.match(r.stderr, /cannot start watch/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('cve-regression-watcher stamps generated_at from the injected clock, matching the threshold year', () => {
  const now = new Date('2024-07-09T00:00:00Z');
  const report = WATCHER.findRegressionCandidates([], {}, { now });

  // Presence + content: generated_at must be the injected date, not the real
  // (module-load / call-time) date.
  assert.equal(typeof report.generated_at, 'string');
  assert.equal(
    report.generated_at,
    '2024-07-09',
    'generated_at must derive from opts.now, not a module-load timestamp',
  );
  // Both date-derived fields share one clock: threshold = injectedYear - 2.
  assert.equal(report.historical_id_threshold_year, 2022);
  assert.equal(
    String(report.historical_id_threshold_year),
    report.generated_at.slice(0, 4) - 2 + '',
    'generated_at year and threshold year must come from the same injected instant',
  );
});

test('cve-regression-watcher falls back to call-time now (not a stale module constant) when no clock is injected', () => {
  const today = new Date().toISOString().slice(0, 10);
  const report = WATCHER.findRegressionCandidates([], {}, {});
  assert.equal(typeof report.generated_at, 'string');
  assert.equal(
    report.generated_at,
    today,
    'with no injected clock, generated_at must be the call-time date',
  );
});
