"use strict";

/**
 * tests/collector-walk-symlink-cycle.test.js
 *
 * Guards the shared cwd-tree walker (lib/collectors/scan-excludes.js
 * walkTree), which realpaths only directories and symlinks — never regular
 * files — for its symlink-cycle `seen` set. This test pins the two
 * properties that reduction must never break:
 *
 *   (a) A symlink CYCLE (a directory symlink pointing back at an ancestor)
 *       is handled safely: the walk terminates, returns a finite file list,
 *       and never throws. A regression that dropped directory realpath would
 *       loop forever / overflow the stack here.
 *   (b) A planted secret in a DEEP directory is still discovered. A
 *       regression that broke traversal (e.g. realpath-on-files removal
 *       skipping the file emit) would lose the deep hit.
 *
 * No wall-clock assertion — timing is flaky across CI hosts. Gross
 * slowdowns are already guarded by the redos-whitespace-line suite.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const { walkTree } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Real-shaped GitHub PAT — the AWS doc example key is demoted by the
// collector, so use a token literal that genuinely fires.
const SECRET = 'const token = "ghp_' + "A".repeat(36) + '";\n';

// Create a directory symlink, returning false if the platform refuses
// (Windows without the privilege). Tests that depend on a symlink skip
// themselves rather than fail on such hosts.
function trySymlinkDir(target, linkPath) {
  try {
    fs.symlinkSync(target, linkPath, "dir");
    return true;
  } catch {
    return false;
  }
}

test("(a) walkTree terminates on a directory symlink cycle without throwing", () => {
  const tmp = mkTmp("walk-cycle-");
  try {
    // a/b/c real directory chain with a file at the bottom.
    const a = path.join(tmp, "a");
    const b = path.join(a, "b");
    const c = path.join(b, "c");
    fs.mkdirSync(c, { recursive: true });
    fs.writeFileSync(path.join(c, "leaf.txt"), "leaf\n");

    // Cycle: a/b/c/loop -> a  (points back at an ancestor).
    const made = trySymlinkDir(a, path.join(c, "loop"));
    if (!made) {
      // Platform refuses directory symlinks — nothing to assert here.
      return;
    }

    let files;
    assert.doesNotThrow(() => {
      files = walkTree(tmp, { maxDepth: 8 });
    }, "walkTree must not throw / loop forever on a symlink cycle");

    // Finite, and the real leaf file is present exactly once.
    assert.ok(Array.isArray(files), "walkTree returns an array");
    const leaves = files.filter((f) => f.name === "leaf.txt");
    assert.equal(leaves.length, 1, "the real leaf file is emitted exactly once despite the cycle");
    // The directory symlink itself is never traversed nor emitted as a file.
    assert.equal(files.some((f) => f.name === "loop"), false, "the directory symlink is not emitted as a file");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(b) a planted secret in a deep directory is still discovered", () => {
  const tmp = mkTmp("walk-deep-secret-");
  try {
    // Deep nest within the secrets collector's depth budget (<= 6).
    const deep = path.join(tmp, "src", "app", "config", "env");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, "creds.js"), SECRET);

    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(
      r.signal_overrides["github-personal-access-token"],
      "hit",
      "a GitHub PAT planted in a deep directory must still flip the indicator to hit",
    );
    const blob = JSON.stringify(r.artifacts);
    assert.equal(/creds\.js/.test(blob), true, "the deep secret-carrier file appears in the evidence");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c) walkTree skips a directory symlink cycle yet still finds a secret beyond it", () => {
  // Combined: a cycle near the root must not prevent discovery of a real
  // secret in a sibling deep directory.
  const tmp = mkTmp("walk-cycle-secret-");
  try {
    const loopHost = path.join(tmp, "loophost");
    fs.mkdirSync(loopHost, { recursive: true });
    const made = trySymlinkDir(tmp, path.join(loopHost, "back")); // back -> root: cycle

    const deep = path.join(tmp, "lib", "secrets");
    fs.mkdirSync(deep, { recursive: true });
    // Use a non-.env carrier: a .env file is legitimately recorded in TWO
    // artifact categories (general scan + env-file carrier), which would make
    // a raw filename-occurrence count 2 even with no symlink at all. A .js
    // carrier is recorded once, so an occurrence count > 1 genuinely indicates
    // the cycle re-walked the file via a second path.
    fs.writeFileSync(path.join(deep, "leak_carrier.js"), 'const t = "ghp_' + "B".repeat(36) + '";\n');

    let r;
    assert.doesNotThrow(() => {
      r = secretsCollector.collect({ cwd: tmp });
    }, "collect must terminate even with a root-pointing symlink cycle present");

    // Whether or not the platform created the symlink, the real secret fires.
    assert.equal(
      r.signal_overrides["github-personal-access-token"],
      "hit",
      "the real secret beyond the cycle is still discovered",
    );
    if (!made) return; // symlink not created — cycle-specific check skipped
    // The cycle did not duplicate the carrier into a second walked path.
    const occurrences = (JSON.stringify(r.artifacts).match(/leak_carrier\.js/g) || []).length;
    assert.equal(occurrences, 1, "the secret carrier is counted once, not duplicated via the cycle");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});
