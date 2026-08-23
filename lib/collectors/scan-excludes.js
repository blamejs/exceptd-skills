"use strict";

/**
 * Shared directory-walk exclusion policy for every code-scope collector: a set of
 * directory basenames never worth descending into, and a predicate for linked git
 * worktrees, which rescan the host tree's source and multiply every hit.
 * Collectors spread DEFAULT_CODE_EXCLUDES into their exclude Set and call
 * isLinkedWorktreeDir(fullPath) before descending.
 */

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_CODE_EXCLUDES = Object.freeze([
  ".git", ".hg", ".svn", ".claude", ".idea", ".vscode",
  "node_modules", ".pnpm-store", "bower_components",
  ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
  ".tox", ".gradle", ".m2",
  "dist", "build", "out", "target", "coverage",
  ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache",
]);

function codeExcludeSet(extra = []) {
  return new Set([...DEFAULT_CODE_EXCLUDES, ...extra]);
}

/**
 * True when `dir` is a git worktree linked elsewhere — its `.git` entry is a file
 * (a `gitdir: …` pointer), where a normal repo root has a `.git` *directory* and
 * is NOT skipped. Returns false on any error, so a walk never aborts on a race.
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
 * Shared cwd-tree walker for every code-scope collector. Returns one entry per
 * regular file as `{ full, rel, name }`, `rel` forward-slashed on every platform.
 * Directory basenames in `excludes` and linked git worktrees are never descended
 * into, recursion follows only real directories — a symlink is neither traversed
 * nor emitted — and depth is capped at `maxDepth`.
 *
 * `opts.truncations`, when an array, is an out-param: one `{ rel, depth }` per
 * directory pruned for exceeding the cap. The return value is the file array.
 */
function walkTree(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? 6;
  const excludes = opts.excludes ?? codeExcludeSet();
  const truncations = Array.isArray(opts.truncations) ? opts.truncations : null;
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
        // Cycle guard: canonicalize so a symlinked or bind-mounted loop is
        // visited at most once.
        let real;
        try { real = fs.realpathSync(full); } catch { continue; }
        if (seen.has(real)) continue;
        seen.add(real);
        if (isLinkedWorktreeDir(full)) continue;
        // Checked before descending, so the pruned directory can be recorded.
        if (depth + 1 > maxDepth) {
          if (truncations) {
            truncations.push({
              rel: path.relative(root, full).split(path.sep).join("/"),
              depth: depth + 1,
            });
          }
          continue;
        }
        walk(full, depth + 1);
      } else if (entry.isSymbolicLink()) {
        // A symlink Dirent is neither isDirectory() nor isFile(): never emitted.
        try { fs.realpathSync(full); } catch { /* dangling link — ignore */ }
      } else if (entry.isFile()) {
        // A regular file cannot introduce a directory cycle, so no realpath /
        // `seen` check. Windows path.relative returns backslashes, so rel is
        // normalized to match SARIF locations.
        out.push({ full, rel: path.relative(root, full).split(path.sep).join("/"), name: entry.name });
      }
    }
  }
  walk(root, 0);
  return out;
}

// Per-indicator cap: 50 sits well inside GitHub code-scanning's rendering budget.
const MAX_EVIDENCE_LOCATIONS_PER_INDICATOR = 50;

/**
 * Turns a collector's per-indicator file hits into `evidence_locations` for SARIF
 * `results[].locations`. Each hit yields `{ uri, startLine? }` from its `rel` (or
 * `file`) repo-relative path; `startLine` is emitted only above zero, because
 * collectors store `line: 0` to mean "file-level, no line". Identical entries
 * de-duplicate; the list caps at MAX_EVIDENCE_LOCATIONS_PER_INDICATOR.
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
 * Converts a 0-based offset into `content` to a 1-based line number, so a
 * content-regex collector can pair a match's `m.index` with a SARIF region.
 * Returns 1 for offset 0 or a non-finite offset. Counts `\n`, covering `\r\n`.
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
