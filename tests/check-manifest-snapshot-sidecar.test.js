'use strict';

/**
 * Regression for the manifest-snapshot integrity sidecar.
 *
 * The sha256 sidecar (manifest-snapshot.sha256) is the only thing that
 * catches a hand-edit of manifest-snapshot.json that bypassed
 * refresh-manifest-snapshot.js — e.g. a lockstep edit of manifest.json +
 * the baseline to hide a removed skill/trigger from the surface diff.
 * Deleting the sidecar must NOT downgrade that hard failure to a silent
 * warn-and-continue: the snapshot and its sidecar ship as a pair
 * (package.json `files`) and refresh always writes both, so a present
 * snapshot WITHOUT its sidecar is the integrity-evasion shape, not a
 * benign legacy state.
 *
 * Asserts EXACT outcomes (ok boolean + subprocess exit code), not just
 * "non-zero" — a coincidence-passing test is worse than none.
 *
 * Shadow-tree pattern: copy snapshot + sidecar + script into a tempdir,
 * mutate, run the exported function and the real CLI subprocess.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts', 'check-manifest-snapshot.js');
const { checkSnapshotIntegrity } = require(SCRIPT);

const SNAPSHOT = path.join(ROOT, 'manifest-snapshot.json');

// Build a minimal shadow tree containing only what the integrity check
// needs: <tmp>/manifest-snapshot.json (+ optional sidecar). The exported
// checkSnapshotIntegrity(root) reads relative to the passed root, so we
// never touch the real working tree.
function shadow({ withSidecar }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-sidecar-'));
  const snapBytes = fs.readFileSync(SNAPSHOT);
  fs.writeFileSync(path.join(tmp, 'manifest-snapshot.json'), snapBytes);
  if (withSidecar) {
    const sha = crypto.createHash('sha256').update(snapBytes).digest('hex');
    fs.writeFileSync(
      path.join(tmp, 'manifest-snapshot.sha256'),
      sha + '  manifest-snapshot.json\n'
    );
  }
  return tmp;
}

test('checkSnapshotIntegrity: snapshot present + matching sidecar => ok', () => {
  const tmp = shadow({ withSidecar: true });
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, true, 'matching snapshot+sidecar must pass');
    assert.equal(r.error, null);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: snapshot present + sidecar ABSENT => FAIL (not skip)', () => {
  const tmp = shadow({ withSidecar: false });
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, false, 'a missing sidecar next to a present snapshot must fail');
    assert.match(
      r.error,
      /manifest-snapshot\.sha256 missing/,
      `error must name the missing sidecar; got ${JSON.stringify(r.error)}`
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: snapshot present + tampered sidecar => FAIL', () => {
  const tmp = shadow({ withSidecar: true });
  try {
    // Corrupt the recorded hash so it no longer matches the snapshot bytes.
    fs.writeFileSync(
      path.join(tmp, 'manifest-snapshot.sha256'),
      'deadbeef'.repeat(8) + '  manifest-snapshot.json\n'
    );
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, false, 'a hash mismatch must fail');
    assert.match(r.error, /integrity check FAILED/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: no snapshot at all => ok (baseline-read handles it)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-none-'));
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, true, 'no snapshot => integrity check has nothing to anchor; ok');
    assert.equal(r.error, null);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// End-to-end through the real CLI: the surface-narrowing bypass must not
// pass with the sidecar deleted. Build a full shadow (script + snapshot,
// no sidecar) and assert the process exits 1 — the EXACT blocking code.
test('CLI: snapshot present + sidecar absent exits 1 (surface-narrowing bypass blocked)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-cli-'));
  try {
    fs.mkdirSync(path.join(tmp, 'scripts'), { recursive: true });
    fs.copyFileSync(SCRIPT, path.join(tmp, 'scripts', 'check-manifest-snapshot.js'));
    // manifest.json + snapshot kept in lockstep so the surface diff is
    // clean; only the sidecar is missing. Pre-fix this printed
    // "surface unchanged" and exited 0.
    fs.copyFileSync(path.join(ROOT, 'manifest.json'), path.join(tmp, 'manifest.json'));
    fs.copyFileSync(SNAPSHOT, path.join(tmp, 'manifest-snapshot.json'));
    // deliberately NOT copying manifest-snapshot.sha256

    const r = spawnSync(process.execPath, [path.join(tmp, 'scripts', 'check-manifest-snapshot.js')], {
      encoding: 'utf8',
    });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status}\nstdout=${r.stdout}\nstderr=${r.stderr}`);
    assert.match(
      r.stderr,
      /manifest-snapshot\.sha256 missing/,
      'must explain the missing sidecar on stderr'
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
