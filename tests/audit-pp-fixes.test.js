'use strict';

/**
 * tests/audit-pp-fixes.test.js
 *
 * Regression coverage for the PP audit batch:
 *
 *   PP P1-1  acquireLock recovers from a same-PID stale lockfile (orphan from
 *            a prior run() within this process that crashed without releasing).
 *            Same-PID + fresh mtime still returns null (legitimate reentrancy).
 *   PP P1-2  persistAttestation lock-contention exit code is 8, distinct from
 *            the generic exit 1 that emit() applies to every other ok:false
 *            body. Body carries lock_contention:true AND exit_code:8.
 *
 * Per CLAUDE.md: each assertion checks the EXACT value the fix produces. No
 * assert.notEqual(0) / assert.ok(field) coincidence-passers.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const playbookRunner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

function makeLockDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pb-pp-locks-'));
  process.env.EXCEPTD_LOCK_DIR = dir;
  return dir;
}

// ============================================================================
// PP P1-1 — same-PID stale-lockfile reclaim
// ============================================================================

test('PP P1-1: acquireLock reclaims a same-PID lockfile whose mtime is older than STALE_LOCK_MS', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-pp-self-stale-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  // Pre-populate the lockfile with OUR pid — simulates an orphan from a
  // prior run() that crashed without releasing.
  fs.writeFileSync(
    lockFile,
    JSON.stringify({ pid: process.pid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2),
  );
  // Backdate mtime past STALE_LOCK_MS (30s). Use 60s to comfortably clear.
  const sixtySecondsAgo = (Date.now() - 60_000) / 1000;
  fs.utimesSync(lockFile, sixtySecondsAgo, sixtySecondsAgo);

  const result = playbookRunner._acquireLock(playbookId);
  assert.equal(
    result,
    lockFile,
    'acquireLock must reclaim a same-PID lockfile whose mtime is older than STALE_LOCK_MS',
  );

  // Lockfile should now reflect a fresh hold by us: mtime within the last second.
  const stat = fs.statSync(lockFile);
  assert.equal(
    Date.now() - stat.mtimeMs < 5_000,
    true,
    'reclaimed lockfile must have a freshly-rewritten mtime (within 5s)',
  );
  playbookRunner._releaseLock(result);
});

test('PP P1-1: acquireLock returns null for same-PID lockfile with fresh mtime (legitimate reentrancy block)', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-pp-self-fresh-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  // Pre-populate with our pid + fresh mtime (now). This is the legitimate
  // reentrancy case: another acquireLock() call within this process already
  // holds the lock, and we must NOT reclaim it.
  fs.writeFileSync(
    lockFile,
    JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2),
  );
  // Read mtime before the acquireLock call so we can confirm it was not touched.
  const mtimeBefore = fs.statSync(lockFile).mtimeMs;

  const result = playbookRunner._acquireLock(playbookId);
  assert.equal(
    result,
    null,
    'acquireLock must return null when the same-PID lockfile is fresh (reentrancy must be blocked)',
  );
  // Lockfile contents must be unchanged — we didn't reclaim.
  const reread = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  assert.equal(reread.pid, process.pid);
  // mtime not rewritten.
  const mtimeAfter = fs.statSync(lockFile).mtimeMs;
  assert.equal(
    mtimeAfter,
    mtimeBefore,
    'fresh same-PID lockfile mtime must NOT be rewritten by a failed acquire',
  );
  // Cleanup — we created it directly.
  try { fs.unlinkSync(lockFile); } catch {}
});

test('PP P1-1: acquireLockDiagnostic returns reclaimed_self_stale_pid: true for stale same-PID orphan', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-pp-diag-self-stale-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  fs.writeFileSync(
    lockFile,
    JSON.stringify({ pid: process.pid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2),
  );
  const sixtySecondsAgo = (Date.now() - 60_000) / 1000;
  fs.utimesSync(lockFile, sixtySecondsAgo, sixtySecondsAgo);

  const diag = playbookRunner._acquireLockDiagnostic(playbookId);
  assert.equal(diag.ok, true, 'diagnostic must succeed when reclaiming same-PID stale orphan');
  assert.equal(diag.path, lockFile);
  assert.equal(
    diag.reclaimed_self_stale_pid,
    true,
    'diagnostic must flag reclaimed_self_stale_pid:true when the prior holder was our own dead self',
  );
  assert.equal(
    typeof diag.prior_mtime_ms,
    'number',
    'diagnostic must report the prior mtime for audit visibility',
  );
  playbookRunner._releaseLock(diag.path);
});

test('PP P1-1: acquireLockDiagnostic returns held_by_self for fresh same-PID lockfile', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-pp-diag-self-fresh-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  fs.writeFileSync(
    lockFile,
    JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2),
  );

  const diag = playbookRunner._acquireLockDiagnostic(playbookId);
  assert.equal(diag.ok, false);
  assert.equal(
    diag.reason,
    'held_by_self',
    'fresh same-PID lockfile must be diagnosed as held_by_self (reentrancy), not held_by_live_pid or reclaim_failed',
  );
  assert.equal(diag.holder_pid, process.pid);
  assert.equal(diag.lock_path, lockFile);
  try { fs.unlinkSync(lockFile); } catch {}
});

// ============================================================================
// PP P1-2 — persistAttestation LOCK_CONTENTION exit code 8
// ============================================================================

test('PP P1-2: persistAttestation lock contention sets process.exitCode = 8 and body.exit_code = 8', () => {
  // Reset the exitCode at test entry so we observe a clean transition.
  const priorExitCode = process.exitCode;
  process.exitCode = 0;

  const bin = require(path.join(ROOT, 'bin', 'exceptd.js'));
  assert.equal(typeof bin.persistAttestation, 'function', 'persistAttestation must be exported for testability');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-p1-2-attest-'));
  const sessionId = 'pp-p1-2-' + process.pid + '-' + Date.now().toString(36);
  const sessionDir = path.join(tmpRoot, sessionId);
  fs.mkdirSync(sessionDir, { recursive: true });
  const slotPath = path.join(sessionDir, 'attestation.json');
  // Pre-populate the slot so persistAttestation hits the EEXIST/force-overwrite branch.
  fs.writeFileSync(slotPath, JSON.stringify({ session_id: sessionId, prior: true }, null, 2));
  // Pre-create the .lock file with a PID that is BOTH alive AND different
  // from process.pid (so the stale-PID reclaim path does not fire) AND
  // freshly mtime'd (so the stale-mtime fallback does not fire). The PPID
  // satisfies all three conditions in any normal node test run.
  const lockPath = slotPath + '.lock';
  const livePid = process.ppid && process.ppid !== process.pid ? process.ppid : null;
  if (livePid === null) {
    // Can't reliably create a live-but-not-self holder; skip this case.
    process.exitCode = priorExitCode;
    return;
  }
  let isAlive = false;
  try { process.kill(livePid, 0); isAlive = true; } catch {}
  if (!isAlive) {
    process.exitCode = priorExitCode;
    return;
  }
  fs.writeFileSync(lockPath, String(livePid));

  const result = bin.persistAttestation({
    sessionId,
    playbookId: 'pp-test',
    directiveId: 'default',
    evidenceHash: 'pp-evidence-hash',
    operator: null,
    operatorConsent: null,
    submission: { test: 'pp-p1-2' },
    runOpts: { airGap: false, forceStale: false, mode: 'test', attestationRoot: tmpRoot },
    forceOverwrite: true,
    filename: 'attestation.json',
  });

  // EXACT assertions — no notEqual(0) or ok(field) coincidence-passers.
  assert.equal(result.ok, false, 'lock-contention result must be ok:false');
  assert.equal(result.lock_contention, true, 'body must carry lock_contention:true');
  assert.equal(result.exit_code, 8, 'body must carry exit_code:8 for downstream visibility');
  assert.equal(
    typeof result.error,
    'string',
    'lock-contention result must carry a human error string',
  );
  assert.equal(
    result.error.startsWith('LOCK_CONTENTION:'),
    true,
    'error string must be prefixed with LOCK_CONTENTION: for grep-ability',
  );
  assert.equal(
    process.exitCode,
    8,
    'process.exitCode must be set to 8 at the lock-contention return site, BEFORE emit() runs',
  );

  // Clean up so a parallel test doesn't see stale state. Also reset
  // process.exitCode so this test doesn't leak a failure code into the
  // test runner's final exit status.
  try { fs.unlinkSync(lockPath); } catch {}
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
  process.exitCode = priorExitCode;
});

test('PP P1-2: emit() preserves an already-set non-zero exitCode (load-bearing for PP P1-2)', () => {
  // This is the contract PP P1-2 relies on: emit()'s ok:false → exitCode=1
  // mapping is gated on `!process.exitCode`, so a caller that pinned 8 before
  // emit() runs must survive the trip through ok:false auto-mapping. Pin the
  // contract here so a future emit() change can't silently revert it.
  const priorExitCode = process.exitCode;
  process.exitCode = 0;

  const bin = require(path.join(ROOT, 'bin', 'exceptd.js'));
  // emit is not exported; grep the source instead — this is a structural
  // assertion not a runtime call. Tests for runtime behavior are handled by
  // the PP P1-2 test above.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Match the exact guarding clause that makes the contract hold.
  assert.equal(
    /if\s*\(\s*obj\s*&&\s*obj\.ok\s*===\s*false\s*&&\s*!process\.exitCode\s*\)/.test(src),
    true,
    "emit() must gate its ok:false → exitCode=1 mapping on !process.exitCode so a pre-set 8 survives",
  );
  // And persistAttestation must set exitCode BEFORE returning.
  assert.equal(
    /process\.exitCode\s*=\s*8;\s*\n\s*return\s*\{\s*\n\s*ok:\s*false,/.test(src),
    true,
    "persistAttestation lock-contention site must set process.exitCode = 8 BEFORE the return",
  );
  void bin; // touch require'd module so it isn't dead-code-eliminated
  process.exitCode = priorExitCode;
});
