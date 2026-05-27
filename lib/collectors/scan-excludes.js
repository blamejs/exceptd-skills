"use strict";

/**
 * lib/collectors/scan-excludes.js
 *
 * Shared directory-walk exclusion policy for every code-scope collector.
 *
 * Before this existed, each collector hard-coded its own exclude Set. None
 * skipped agent/editor worktree copies (`.claude/worktrees/`), so a tree
 * holding N detached worktrees scanned each one as a full repo — inflating
 * hit counts to N+1 duplicates of the same source and forcing manual dedup.
 *
 * Two layers:
 *   1. NAME exclusions — directory basenames never worth descending into
 *      (dependency caches, build output, VCS metadata, agent scratch).
 *   2. A LINKED-WORKTREE predicate — a directory that is itself a git
 *      worktree distinct from the scan root. A `git worktree add` target
 *      carries a `.git` *file* (a gitdir pointer) rather than a `.git`
 *      directory; agent tools frequently stamp full repo copies under
 *      `.claude/worktrees/`. Skipping these keeps a scan to the one tree
 *      the operator actually pointed at.
 *
 * Collectors apply both: spread DEFAULT_CODE_EXCLUDES into their exclude
 * Set, and call isLinkedWorktreeDir(fullPath) before descending into a
 * subdirectory.
 */

const fs = require("node:fs");
const path = require("node:path");

// Directory basenames excluded from every code-scope walk. Superset of the
// per-collector lists that predated this module, plus agent/editor scratch
// (`.claude`) and additional dependency/build caches that only ever hold
// generated or third-party content.
const DEFAULT_CODE_EXCLUDES = Object.freeze([
  // VCS + agent/editor scratch
  ".git", ".hg", ".svn", ".claude", ".idea", ".vscode",
  // dependency trees / package caches
  "node_modules", ".pnpm-store", "bower_components",
  ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
  ".tox", ".gradle", ".m2",
  // build output
  "dist", "build", "out", "target", "coverage",
  ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache",
]);

/**
 * Build an exclude Set for a collector. Pass any collector-specific extra
 * basenames; they are merged with the shared defaults.
 *
 * @param {Iterable<string>} [extra] additional basenames to exclude
 * @returns {Set<string>}
 */
function codeExcludeSet(extra = []) {
  return new Set([...DEFAULT_CODE_EXCLUDES, ...extra]);
}

/**
 * True when `dir` is a git worktree linked to a repository elsewhere — i.e.
 * its `.git` entry is a file (a `gitdir: …` pointer) rather than a directory.
 * These are detached copies created by `git worktree add` (commonly under
 * `.claude/worktrees/<id>/`); descending into them rescans unrelated repo
 * state. A normal repo root has a `.git` *directory* and is NOT skipped.
 *
 * Cheap and synchronous: one lstat. Returns false on any error so a walk
 * never aborts on a permission/race issue.
 *
 * @param {string} dir absolute path to a candidate directory
 * @returns {boolean}
 */
function isLinkedWorktreeDir(dir) {
  try {
    const gitPath = path.join(dir, ".git");
    const st = fs.lstatSync(gitPath);
    return st.isFile();
  } catch {
    return false;
  }
}

module.exports = {
  DEFAULT_CODE_EXCLUDES,
  codeExcludeSet,
  isLinkedWorktreeDir,
};
