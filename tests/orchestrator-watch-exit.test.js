'use strict';

/**
 * `exceptd watch` exits with the sysexits EX_TEMPFAIL code (75) when the watch
 * lock is already held. The orchestrator reads this from the canonical
 * exit-code table when it carries a WATCH_LOCK_CONTENTION constant and falls
 * back to the literal otherwise, so the value stays stable either way.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');

test('watch refuses with exit 75 when the lock is held by a live PID', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-watch-exit-'));
  try {
    // Forge a lockfile pointing at this (alive) process so the second watcher
    // sees contention and refuses immediately.
    const lockPath = path.join(home, 'watch.lock');
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }));

    const r = spawnSync(process.execPath, [ORCH, 'watch'], {
      encoding: 'utf8',
      timeout: 8000,
      env: {
        ...process.env,
        EXCEPTD_HOME: home,
        EXCEPTD_SUPPRESS_DEPRECATION: '1',
      },
    });

    assert.equal(r.status, 75, `expected EX_TEMPFAIL exit 75; got ${r.status} stderr=${r.stderr}`);
    assert.match(r.stderr, /cannot start watch/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('exit-code table either omits 75 (literal fallback) or documents it consistently', () => {
  // Guard against a future divergence: if the canonical table grows a
  // WATCH_LOCK_CONTENTION constant, it must equal the literal the watch path
  // still falls back to.
  const { EXIT_CODES } = require('../lib/exit-codes');
  if (Object.prototype.hasOwnProperty.call(EXIT_CODES, 'WATCH_LOCK_CONTENTION')) {
    assert.equal(EXIT_CODES.WATCH_LOCK_CONTENTION, 75, 'canonical constant must match the watch exit literal');
  } else {
    assert.equal(EXIT_CODES.WATCH_LOCK_CONTENTION, undefined);
  }
});
