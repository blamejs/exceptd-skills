"use strict";

/**
 * tests/collector-scan-excludes.test.js
 *
 * Pins the shared directory-walk exclusion policy used by every
 * code-scope collector (lib/collectors/scan-excludes.js):
 *
 *   - `.claude` (agent/editor scratch) is in the default exclude set,
 *     so collectors never descend into it.
 *   - isLinkedWorktreeDir() distinguishes a linked git worktree (its
 *     `.git` is a gitdir-pointer FILE) from a real repo root (its
 *     `.git` is a DIRECTORY).
 *   - A collector walk skips a `.claude/worktrees/<id>/` repo copy so
 *     duplicated source files don't inflate hit counts.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const {
  DEFAULT_CODE_EXCLUDES,
  codeExcludeSet,
  isLinkedWorktreeDir,
} = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("(a) .claude is in the shared default code-scope exclude set", () => {
  assert.ok(DEFAULT_CODE_EXCLUDES.includes(".claude"),
    ".claude must be excluded so agent/editor scratch is never walked");
  // codeExcludeSet() must carry the default forward and merge extras.
  const set = codeExcludeSet(["my-extra"]);
  assert.ok(set.has(".claude"), "codeExcludeSet() must retain .claude");
  assert.ok(set.has("node_modules"), "codeExcludeSet() must retain shared defaults");
  assert.ok(set.has("my-extra"), "codeExcludeSet(extra) must merge collector-specific extras");
});

test("(b) isLinkedWorktreeDir: true for a .git-FILE dir, false for a .git-DIR", () => {
  const tmp = mkTmp("scan-excl-wt-");
  try {
    // Linked worktree: `.git` is a gitdir-pointer FILE.
    const linked = path.join(tmp, "linked");
    fs.mkdirSync(linked);
    fs.writeFileSync(path.join(linked, ".git"), "gitdir: /somewhere/.git/worktrees/x\n");
    assert.equal(isLinkedWorktreeDir(linked), true,
      "a directory whose .git is a FILE is a linked worktree");

    // Normal repo root: `.git` is a DIRECTORY.
    const repo = path.join(tmp, "repo");
    fs.mkdirSync(repo);
    fs.mkdirSync(path.join(repo, ".git"));
    assert.equal(isLinkedWorktreeDir(repo), false,
      "a directory whose .git is a DIRECTORY is a normal repo root, not a linked worktree");

    // No .git at all: not a worktree.
    const plain = path.join(tmp, "plain");
    fs.mkdirSync(plain);
    assert.equal(isLinkedWorktreeDir(plain), false,
      "a directory with no .git entry is not a linked worktree");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c) collector walk skips a .claude/worktrees copy (no duplicate hits)", () => {
  const tmp = mkTmp("scan-excl-claude-");
  try {
    // Host-tree source carrying a recognisable secret. Use a real-shaped
    // GitHub PAT, not the AWS doc example key (which the collector demotes).
    const src = 'const token = "ghp_' + "A".repeat(36) + '";\n';
    fs.writeFileSync(path.join(tmp, "keys.js"), src);

    // Full repo copy under .claude/worktrees/<id>/ with a gitfile.
    const wt = path.join(tmp, ".claude", "worktrees", "x");
    fs.mkdirSync(wt, { recursive: true });
    fs.writeFileSync(path.join(wt, "keys.js"), src);
    fs.writeFileSync(path.join(wt, ".git"), "gitdir: /elsewhere/.git/worktrees/x\n");

    const r = secretsCollector.collect({ cwd: tmp });
    const blob = JSON.stringify(r.artifacts);
    assert.equal(/worktrees/.test(blob), false,
      ".claude/worktrees copy must not appear in the secrets scan evidence");
    // The single host-tree keys.js is the only carrier counted.
    assert.equal((blob.match(/keys\.js/g) || []).length, 1,
      "only the host-tree keys.js should be counted, not the worktree duplicate");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c2) worktree guard skips a linked worktree even outside an excluded dir name", () => {
  // Proves the guard is independent of the `.claude` name exclusion:
  // a linked worktree under any directory name is skipped, while a
  // normal nested repo (real `.git` directory) is still walked.
  // Real-shaped GitHub PAT (not the demoted AWS doc example key).
  const src = 'const token = "ghp_' + "A".repeat(36) + '";\n';

  // Linked worktree under a non-excluded dir name -> skipped.
  const a = mkTmp("scan-excl-linked-");
  try {
    fs.writeFileSync(path.join(a, "keys.js"), src);
    const wt = path.join(a, "wtcopy");
    fs.mkdirSync(wt);
    fs.writeFileSync(path.join(wt, "keys.js"), src);
    fs.writeFileSync(path.join(wt, ".git"), "gitdir: /elsewhere\n");
    const ra = secretsCollector.collect({ cwd: a });
    assert.equal(/wtcopy/.test(JSON.stringify(ra.artifacts)), false,
      "a linked worktree (gitfile) must be skipped regardless of its directory name");
  } finally {
    try { fs.rmSync(a, { recursive: true, force: true }); } catch {}
  }

  // Normal nested repo (real .git directory) under the same name -> walked.
  const b = mkTmp("scan-excl-repo-");
  try {
    fs.writeFileSync(path.join(b, "keys.js"), src);
    const nested = path.join(b, "wtcopy");
    fs.mkdirSync(nested);
    fs.writeFileSync(path.join(nested, "keys.js"), src);
    fs.mkdirSync(path.join(nested, ".git"));
    const rb = secretsCollector.collect({ cwd: b });
    assert.equal(/wtcopy/.test(JSON.stringify(rb.artifacts)), true,
      "a normal nested repo (real .git directory) must still be walked");
  } finally {
    try { fs.rmSync(b, { recursive: true, force: true }); } catch {}
  }
});
