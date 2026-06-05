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

/**
 * Shared cwd-tree walker for every code-scope collector. Returns one entry
 * per regular file as `{ full, rel, name }` — the exact shape the four
 * collectors (secrets / crypto-codebase / containers / citation-hygiene)
 * built with their own near-identical local walkers.
 *
 * Behavior preserved from those walkers:
 *   - Directory basenames in `excludes` are never descended into.
 *   - A linked git worktree (its `.git` is a gitdir-pointer FILE) is never
 *     descended into (isLinkedWorktreeDir).
 *   - Recursion follows ONLY real directories (`entry.isDirectory()`).
 *     Symlinks are never traversed and symlink targets are never emitted
 *     as files — matching the old behavior where a Dirent for a symlink is
 *     neither isDirectory() nor isFile(), so it fell through both branches.
 *   - Depth is capped at `maxDepth`.
 *
 * Performance: `fs.realpathSync` is called ONLY on directories and symlinks
 * (the only entries that can introduce a traversal cycle), never on regular
 * files. The old walkers realpath'd every file entry, which on a large repo
 * dominated walk time. A regular file cannot create a directory cycle, so
 * dropping its realpath preserves cycle protection exactly while removing
 * the per-file syscall. The symlink-cycle `seen` set still guards every
 * directory and symlink by canonical path.
 *
 * @param {string} root absolute scan root
 * @param {object} [opts]
 * @param {number} [opts.maxDepth] max recursion depth (collector-specific)
 * @param {Set<string>} [opts.excludes] directory basenames to skip
 * @returns {Array<{full:string, rel:string, name:string}>}
 */
function walkTree(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? 6;
  const excludes = opts.excludes ?? codeExcludeSet();
  const out = [];
  const seen = new Set();

  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
      if (excludes.has(entry.name)) continue;
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Cycle guard: canonicalize directories (and symlinks below) so a
        // symlinked or bind-mounted loop is visited at most once. realpath
        // here is bounded by directory count, not file count.
        let real;
        try { real = fs.realpathSync(full); } catch { continue; }
        if (seen.has(real)) continue;
        seen.add(real);
        // Never descend into a linked git worktree (its `.git` is a gitdir
        // pointer file) — agent tooling stamps full repo copies under
        // `.claude/worktrees/<id>/`; walking them rescans the same source
        // as the host tree and multiplies every hit.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
      } else if (entry.isSymbolicLink()) {
        // A symlink Dirent is neither isDirectory() nor isFile(). The old
        // walkers realpath'd it (adding the target to `seen`) and then
        // emitted nothing, because neither branch matched. Preserve that:
        // canonicalize for the cycle guard, never emit, never traverse.
        try { fs.realpathSync(full); } catch { /* dangling link — ignore */ }
      } else if (entry.isFile()) {
        // Regular files cannot introduce a directory cycle, so no realpath /
        // `seen` check is needed. This is the hot path — it runs once per
        // file in the tree and is now syscall-free beyond the parent
        // readdir.
        // Emit forward-slash rel paths on every platform so artifact
        // summaries match the SARIF evidence_locations (which normalize the
        // same way) — on Windows path.relative returns backslash separators.
        out.push({ full, rel: path.relative(root, full).split(path.sep).join("/"), name: entry.name });
      }
    }
  }
  walk(root, 0);
  return out;
}

// Per-indicator cap so a flood of identical findings can't bloat a SARIF
// upload. 50 locations per result is well within GitHub code-scanning's
// rendering budget while still showing the operator where every distinct
// finding lives.
const MAX_EVIDENCE_LOCATIONS_PER_INDICATOR = 50;

/**
 * Turn a collector's per-indicator file hits into the `evidence_locations`
 * entry the runner threads onto a firing indicator for SARIF
 * `results[].locations`. Each hit contributes a `{ uri, startLine? }` where
 * `uri` is the repo-relative file path the collector already recorded and
 * `startLine` is included only when a real (non-placeholder) line number is
 * present — many collectors store `line: 0` to mean "file-level, no line",
 * which omits the region so SARIF points at the file rather than line 0.
 *
 * Identical `{ uri, startLine }` entries are de-duplicated and the list is
 * capped at MAX_EVIDENCE_LOCATIONS_PER_INDICATOR.
 *
 * @param {Array<object>} hits  entries with a `rel` or `file` repo-relative
 *                              path and an optional `line` number
 * @returns {Array<{uri:string,startLine?:number}>}
 */
function buildEvidenceLocations(hits) {
  if (!Array.isArray(hits) || hits.length === 0) return [];
  const out = [];
  const seen = new Set();
  for (const h of hits) {
    if (!h || typeof h !== "object") continue;
    const raw = h.rel != null ? h.rel : h.file;
    if (typeof raw !== "string" || raw.trim() === "") continue;
    const uri = raw.replace(/\\/g, "/");
    const line = Number(h.line);
    const hasLine = Number.isInteger(line) && line > 0;
    const key = hasLine ? `${uri}\u0000${line}` : uri;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(hasLine ? { uri, startLine: line } : { uri });
    if (out.length >= MAX_EVIDENCE_LOCATIONS_PER_INDICATOR) break;
  }
  return out;
}

/**
 * Convert a byte/char offset into a file's text to a 1-based line number.
 * Content-regex collectors record the offset of a match (`m.index`) but not
 * a line, which left `buildEvidenceLocations` emitting a file-level location
 * with no region. Pairing the offset with this helper lets SARIF point at the
 * exact line.
 *
 * Returns 1 for offset 0 / a non-finite offset (file-level fallback at the
 * first line). Counts `\n` occurrences before the offset; `\r\n` is handled
 * because the `\n` is what increments the line.
 *
 * @param {string} content the file text the offset indexes into
 * @param {number} offset  0-based offset of the match within `content`
 * @returns {number} 1-based line number
 */
function lineFromOffset(content, offset) {
  if (typeof content !== "string") return 1;
  const idx = Number(offset);
  if (!Number.isFinite(idx) || idx <= 0) return 1;
  const upto = idx > content.length ? content.length : idx;
  let line = 1;
  for (let i = 0; i < upto; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

module.exports = {
  DEFAULT_CODE_EXCLUDES,
  codeExcludeSet,
  isLinkedWorktreeDir,
  walkTree,
  buildEvidenceLocations,
  lineFromOffset,
  MAX_EVIDENCE_LOCATIONS_PER_INDICATOR,
};
