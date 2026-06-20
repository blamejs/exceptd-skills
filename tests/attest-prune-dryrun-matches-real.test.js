"use strict";

/**
 * Regression: `attest prune --dry-run` is a preview of the real run. The
 * sessions it lists as [would-delete] must be exactly the sessions a real run
 * removes from disk, and `pruned_count` must be a post-condition (sessions
 * actually deleted) — never a candidacy tally.
 *
 * Pre-fix, the realpath root-confinement gate lived entirely inside
 * `if (!dryRun)`, so dry-run pushed every dated-old session onto pruned[] with
 * no deletability check, and a real run that swallowed a confinement failure /
 * realpathSync throw / rmSync throw had ALREADY counted the session. That made
 * dry-run over-promise and pruned_count over-report. The gate is now evaluated
 * in both modes, and a real run records a session as pruned only after rmSync
 * succeeds.
 *
 * Two cases:
 *  - cross-platform: on a normal store, dry-run's [would-delete] set equals the
 *    set the real run removes from disk, and pruned_count == dirs removed.
 *  - POSIX-only: a session whose dir cannot be removed (parent dir made
 *    non-writable so rmSync throws EACCES) must be ABSENT from dry-run's
 *    pruned[] and must NOT be counted by the real run. Skipped on win32, where
 *    rmSync({force:true}) ignores POSIX permission bits (the same host-skip
 *    shape the crypto linux-platform precondition test uses).
 *
 * Discipline: exact counts; the dry-run set is compared against the set of dirs
 * the real run actually removes from disk, not against itself.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { makeCli, tryJson } = require("./_helpers/cli");

function freshHome(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Stage a datable attestation session under <home>/attestations/<sid>.
function stage(home, sid, capturedAt) {
  const sdir = path.join(home, "attestations", sid);
  fs.mkdirSync(sdir, { recursive: true });
  fs.writeFileSync(
    path.join(sdir, "attestation.json"),
    JSON.stringify({ kind: "attestation", captured_at: capturedAt }),
  );
  return sdir;
}

function sessionDirs(home) {
  const root = path.join(home, "attestations");
  try {
    return new Set(
      fs.readdirSync(root, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name),
    );
  } catch {
    return new Set();
  }
}

const OLD = "2020-01-01T00:00:00.000Z"; // older than cutoff -> prune
const NEW = "2030-01-01T00:00:00.000Z"; // newer than cutoff -> keep
const CUTOFF = "2026-01-01";

test("dry-run [would-delete] set equals the set a real run removes from disk", () => {
  // --- dry-run home ---
  const dryHome = freshHome("exceptd-prune-dry-");
  stage(dryHome, "old-a", OLD);
  stage(dryHome, "old-b", OLD);
  stage(dryHome, "keep-c", NEW);
  const before = sessionDirs(dryHome);

  const dryCli = makeCli(dryHome);
  const dry = dryCli(["attest", "prune", "--all-older-than", CUTOFF, "--dry-run", "--json"], { env: { EXCEPTD_HOME: dryHome } });
  assert.equal(dry.status, 0, `dry-run exit: ${dry.stderr.slice(0, 200)}`);
  const dryBody = tryJson(dry.stdout);
  assert.ok(dryBody && Array.isArray(dryBody.pruned), "dry-run output carries pruned[]");
  const dryPruned = new Set(dryBody.pruned.map((p) => p.session_id));
  // dry-run must not touch disk.
  assert.deepEqual(sessionDirs(dryHome), before, "dry-run must not delete any session");

  // --- real-run home (identical staging) ---
  const realHome = freshHome("exceptd-prune-real-");
  stage(realHome, "old-a", OLD);
  stage(realHome, "old-b", OLD);
  stage(realHome, "keep-c", NEW);
  const beforeReal = sessionDirs(realHome);

  const realCli = makeCli(realHome);
  const real = realCli(["attest", "prune", "--all-older-than", CUTOFF, "--json"], { env: { EXCEPTD_HOME: realHome } });
  assert.equal(real.status, 0, `real exit: ${real.stderr.slice(0, 200)}`);
  const realBody = tryJson(real.stdout);
  assert.ok(realBody && Array.isArray(realBody.pruned), "real output carries pruned[]");

  const afterReal = sessionDirs(realHome);
  const actuallyRemoved = new Set([...beforeReal].filter((s) => !afterReal.has(s)));

  // Contract 1: the dry-run preview equals what the real run removes from disk.
  assert.deepEqual(
    [...dryPruned].sort(),
    [...actuallyRemoved].sort(),
    "dry-run [would-delete] set must equal the set the real run actually removes",
  );
  // Contract 2: pruned_count is a post-condition — exactly the dirs removed.
  assert.equal(
    realBody.pruned_count,
    actuallyRemoved.size,
    "pruned_count must equal the number of sessions actually removed from disk",
  );

  // Sanity on the staged set: the two old sessions go, the future one stays.
  assert.deepEqual([...actuallyRemoved].sort(), ["old-a", "old-b"], "both old sessions removed");
  assert.ok(afterReal.has("keep-c"), "the future-dated session is kept");
  assert.equal(realBody.kept, 1, "exactly one session kept");
});

test("an undeletable old session is neither previewed nor counted (POSIX)", { skip: process.platform === "win32" ? "rmSync({force}) ignores POSIX perms on win32" : false }, () => {
  // Stage two old sessions; make one un-removable by clearing write+execute on
  // its parent dir so fs.rmSync(realDir) throws EACCES. Pre-fix this session is
  // shown as [would-delete] in dry-run and counted in pruned_count even though
  // the real run leaves it on disk. Post-fix it is excluded from both.
  const home = freshHome("exceptd-prune-locked-");
  const root = path.join(home, "attestations");
  stage(home, "deletable", OLD);
  const lockedSess = stage(home, "locked", OLD);

  // Make rmSync(lockedSess) fail: remove write perm on the PARENT (root) so the
  // entry can't be unlinked, but keep read+execute so readdir/scan still works.
  const origMode = fs.statSync(root).mode;
  fs.chmodSync(root, 0o555); // r-xr-xr-x: listable, traversable, NOT writable
  try {
    const cli = makeCli(home);
    const dry = cli(["attest", "prune", "--all-older-than", CUTOFF, "--dry-run", "--json"], { env: { EXCEPTD_HOME: home } });
    assert.equal(dry.status, 0);
    const dryBody = tryJson(dry.stdout);
    const dryIds = new Set((dryBody.pruned || []).map((p) => p.session_id));

    // The locked session cannot be deleted by a real run, so the dry-run preview
    // must NOT list it. (Pre-fix it was listed — the gate was absent in dry-run.)
    assert.ok(!dryIds.has("locked"), "dry-run must not preview an undeletable session");

    const real = cli(["attest", "prune", "--all-older-than", CUTOFF, "--json"], { env: { EXCEPTD_HOME: home } });
    assert.equal(real.status, 0);
    const realBody = tryJson(real.stdout);
    const realIds = new Set((realBody.pruned || []).map((p) => p.session_id));

    // Confirm the lock actually prevented removal (the test's premise holds).
    assert.ok(fs.existsSync(lockedSess), "locked session is still on disk after the real run");
    // pruned_count is a post-condition: only the deletable session counts.
    assert.ok(!realIds.has("locked"), "real run must not record an undeleted session as pruned");
    assert.equal(realBody.pruned_count, 1, "exactly the one deletable session is counted");
  } finally {
    fs.chmodSync(root, origMode); // restore so the suite tempdir cleanup can rm it
  }
});
