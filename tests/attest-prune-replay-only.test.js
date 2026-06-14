'use strict';

/**
 * Regression: `attest prune` must be able to GC a session that holds ONLY
 * replay records (its attestation was removed). Such a session has no
 * captured_at anywhere; pre-fix it was undateable and unconditionally kept, so
 * the store grew without bound. Prune now falls back to the newest
 * `replayed_at` so the session can still age out past the cutoff.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-prune-replay-');
const cli = makeCli(SUITE_HOME);

function stageReplayOnly(sid, replayedAt) {
  const sdir = path.join(SUITE_HOME, 'attestations', sid);
  fs.mkdirSync(sdir, { recursive: true });
  fs.writeFileSync(
    path.join(sdir, 'replay-secrets.json'),
    JSON.stringify({ kind: 'replay', replayed_at: replayedAt }),
  );
}

test('a replay-only session older than the cutoff is eligible for prune (dated by replayed_at)', () => {
  stageReplayOnly('replayonly-old', '2020-03-01T00:00:00.000Z');
  const r = cli(['attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body && Array.isArray(body.pruned), 'output carries a pruned[] array');
  const hit = body.pruned.find((p) => p.session_id === 'replayonly-old');
  assert.ok(hit, 'replay-only session must be eligible for prune (was kept forever pre-fix)');
  assert.equal(hit.replayed_at, '2020-03-01T00:00:00.000Z', 'reports the fallback date used');
});

test('a replay-only session newer than the cutoff is kept', () => {
  stageReplayOnly('replayonly-recent', '2030-01-01T00:00:00.000Z');
  const r = cli(['attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(
    !body.pruned.find((p) => p.session_id === 'replayonly-recent'),
    'a future-dated replay-only session must not be pruned',
  );
});
