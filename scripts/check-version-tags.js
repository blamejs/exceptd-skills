#!/usr/bin/env node
"use strict";

/**
 * scripts/check-version-tags.js
 *
 * Refuses NEW version-stamped comments / filenames in the tracked
 * source tree. The authoritative version surfaces are:
 *
 *   1. package.json / manifest.json `"version"` field
 *   2. CHANGELOG.md `## X.Y.Z` headings
 *   3. git tags
 *   4. CLI `version` verb output (reads from package.json)
 *
 * Anywhere else, `// v0.13.22` / `Pre-v0.13.22` / `*-v0_13_22.test.js`
 * is phase residue — operators don't have the roadmap, version tags
 * rot the moment the next release lands, and `git clone` ships every
 * comment to operators along with the code.
 *
 * The check uses a baseline snapshot (`tests/.version-tag-baseline.
 * json`) capturing current violation counts per file. Future scans
 * compare against the baseline:
 *
 *   - Filename violations beyond baseline → fail.
 *   - Comment violations beyond baseline (in any file)        → fail.
 *   - Violations strictly within baseline                     → ok.
 *   - Violations below baseline (drift reduced)               → ok +
 *     suggestion to refresh the baseline.
 *
 * Refresh: `node scripts/check-version-tags.js --update-baseline`.
 *
 * Wired into `npm run predeploy` as a gate.
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const BASELINE_PATH = path.join(ROOT, "tests", ".version-tag-baseline.json");

// Directories we do not walk at all.
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".keys", ".cache", ".scratch",
  "data", "vendor", ".husky",
]);

// File extensions we scan for comment violations.
const SCAN_EXTS = new Set([".js", ".cjs", ".mjs", ".md"]);

// Paths that the project intentionally version-stamps:
//   - CHANGELOG headings are how operators navigate the file
//   - package.json / manifest.json carry the canonical version field
//   - manifest-snapshot.json + sbom.cdx.json contain version-pinned
//     metadata (the SBOM IS a version-stamped manifest)
//   - lib/version-pins.js is a version-constant lookup table
//   - This checker itself documents what it forbids
//   - .git-blame-ignore-revs carries commit hashes, not version tags,
//     but is conventional config the user maintains
const COMMENT_EXEMPT = new Set([
  "package.json",
  "manifest.json",
  "manifest-snapshot.json",
  "sbom.cdx.json",
  "CHANGELOG.md",
  "lib/version-pins.js",
  "scripts/check-version-tags.js",
  // The release-notes-extract gate test asserts version-based CHANGELOG
  // extraction + the shorter-vs-longer prefix-collision guard, so its fixtures
  // MUST embed real `## X.Y.Z` headings (e.g. 0.15.5 vs 0.15.50) — load-bearing
  // test data, not sprinkled release tags.
  "tests/check-changelog-extract.test.js",
]);

// Git-ignored files (a contributor's local-only working docs, scratch) are
// never scanned — the gate enforces on the would-be-shipped surface, with no
// need to name individual local-only files. Untracked-but-NOT-ignored files
// ARE still scanned: a new file a contributor is about to commit is exactly
// what the gate must catch. Computed via `git check-ignore` over the walked set.
function gitIgnoredSet(relPaths) {
  if (!relPaths.length) return new Set();
  try {
    const out = execFileSync("git", ["check-ignore", "--stdin"], {
      cwd: ROOT, input: relPaths.join("\n"), encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
    });
    return new Set(out.split(/\r?\n/).filter(Boolean));
  } catch (e) {
    // `git check-ignore --stdin` exits 1 when NO path is ignored (not an
    // error); any paths it did match are on stdout. Absent that, none ignored.
    const out = e && e.stdout ? String(e.stdout) : "";
    return new Set(out.split(/\r?\n/).filter(Boolean));
  }
}

// Pattern: project version like `v0.13.22` or bare `0.13.22`. Matches
// our pre-1.0 release range. External package versions like ATLAS
// `v5.6.0` or CycloneDX `1.6` don't match because the major is 0.
const VERSION_TAG_RE = /\bv?0\.\d+\.\d+\b/;

// Phase residue patterns — broader than just version tags.
const PHASE_RESIDUE_RES = [
  /\bcycle\s+\d+\b/i,        // "cycle 13 P3 F3"
  /\bphase\s+\d+(\.\d+)+\b/i,// "phase 9.11k"
  /\bPre-v?0\.\d+\.\d+\b/i,  // "Pre-0.13.22"
];

// Filename pattern. `-v0_13_22.test.js` style.
const FILENAME_VERSION_RE = /-v\d+_\d+_\d+\.test\.\w+$/;

function walk(dir, results = []) {
  for (const name of fs.readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = path.join(dir, name);
    const rel = path.relative(ROOT, full).replace(/\\/g, "/");
    let stat;
    try { stat = fs.statSync(full); }
    catch { continue; }
    if (stat.isDirectory()) {
      walk(full, results);
    } else if (stat.isFile()) {
      results.push(rel);
    }
  }
  return results;
}

function countCommentViolations(rel) {
  if (COMMENT_EXEMPT.has(rel)) return 0;
  const ext = path.extname(rel);
  if (!SCAN_EXTS.has(ext)) return 0;
  let text;
  try { text = fs.readFileSync(path.join(ROOT, rel), "utf8"); }
  catch { return 0; }
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    if (VERSION_TAG_RE.test(line)) { count++; continue; }
    for (const re of PHASE_RESIDUE_RES) {
      if (re.test(line)) { count++; break; }
    }
  }
  return count;
}

function scanCurrent() {
  const files = walk(ROOT);
  const ignored = gitIgnoredSet(files);
  const byFile = {};
  const filenameViolations = [];
  for (const rel of files) {
    // Skip git-ignored, local-only files (a contributor's private working notes
    // that `git clone` never ships). Untracked-but-not-ignored files are still
    // scanned — a new file about to be committed is what the gate guards.
    if (ignored.has(rel)) continue;
    if (FILENAME_VERSION_RE.test(rel)) filenameViolations.push(rel);
    const n = countCommentViolations(rel);
    if (n > 0) byFile[rel] = n;
  }
  return { byFile, filenameViolations };
}

function readBaseline() {
  if (!fs.existsSync(BASELINE_PATH)) {
    return { byFile: {}, filenameViolations: [], _missing: true };
  }
  try {
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
  } catch (e) {
    console.error(`[check-version-tags] baseline at ${path.relative(ROOT, BASELINE_PATH)} is malformed: ${e.message}`);
    process.exitCode = 2;
    return null;
  }
}

function writeBaseline(current) {
  const body = {
    note: "Snapshot of pre-existing version-tag drift. The check-version-tags gate fails when these counts go UP. Refresh after an organic cleanup with `node scripts/check-version-tags.js --update-baseline`.",
    recorded_at: new Date().toISOString().split("T")[0],
    byFile: current.byFile,
    filenameViolations: current.filenameViolations,
  };
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(body, null, 2) + "\n");
  console.log(`[check-version-tags] wrote baseline to ${path.relative(ROOT, BASELINE_PATH)}`);
  console.log(`  ${Object.keys(current.byFile).length} file(s) with comment violations`);
  console.log(`  ${current.filenameViolations.length} filename violation(s)`);
}

function main() {
  const wantUpdate = process.argv.includes("--update-baseline");
  const current = scanCurrent();

  if (wantUpdate) {
    writeBaseline(current);
    process.exitCode = 0;
    return;
  }

  const baseline = readBaseline();
  if (!baseline) return;

  if (baseline._missing) {
    console.error(`[check-version-tags] baseline missing at ${path.relative(ROOT, BASELINE_PATH)}.`);
    console.error("Run `node scripts/check-version-tags.js --update-baseline` to capture the current state.");
    process.exitCode = 2;
    return;
  }

  const regressions = [];

  // Filename regressions: any new filename matching the pattern that
  // wasn't in the baseline.
  for (const rel of current.filenameViolations) {
    if (!baseline.filenameViolations.includes(rel)) {
      regressions.push({
        kind: "filename",
        path: rel,
        reason: "new test filename carries a version tag — rename to describe the surface it pins, not the release",
      });
    }
  }

  // Comment regressions: per-file count grew.
  for (const [rel, n] of Object.entries(current.byFile)) {
    const prior = baseline.byFile[rel] || 0;
    if (n > prior) {
      regressions.push({
        kind: "comment",
        path: rel,
        baseline: prior,
        actual: n,
        reason: `comment-level version-tag count grew from ${prior} to ${n} — describe the WHY of the current code, not the release that introduced it`,
      });
    }
  }

  // Files newly added to the violation set (not in baseline at all).
  for (const rel of Object.keys(current.byFile)) {
    if (!(rel in baseline.byFile)) {
      const n = current.byFile[rel];
      // Skip if already captured as a count regression above.
      if (regressions.some(r => r.path === rel)) continue;
      regressions.push({
        kind: "comment",
        path: rel,
        baseline: 0,
        actual: n,
        reason: `new file carries ${n} version-tag comment(s) — describe the WHY of the current code, not the release that introduced it`,
      });
    }
  }

  if (regressions.length === 0) {
    const totalFiles = Object.keys(current.byFile).length;
    const totalFilenames = current.filenameViolations.length;
    console.log(`[check-version-tags] ok — no new version tags. (${totalFiles} file(s) within baseline, ${totalFilenames} legacy filename(s).)`);
    process.exitCode = 0;
    return;
  }

  console.error(`[check-version-tags] FAIL — ${regressions.length} new version-tag regression(s).`);
  console.error("");
  for (const r of regressions) {
    if (r.kind === "filename") {
      console.error(`  ${r.path}`);
      console.error(`    → ${r.reason}`);
    } else {
      console.error(`  ${r.path}  (${r.baseline} → ${r.actual})`);
      console.error(`    → ${r.reason}`);
    }
  }
  console.error("");
  console.error("Authoritative version surfaces (mentions are LOAD-BEARING here):");
  console.error("  package.json / manifest.json `version` field");
  console.error("  CHANGELOG.md `## X.Y.Z` headings (body should describe behavior, not compare versions)");
  console.error("  git tags");
  console.error("");
  console.error("Fix anywhere else:");
  console.error("  - Rename test files to describe the surface (no `-v0_X_Y` suffix).");
  console.error("  - Rewrite comments to describe the WHY of the current code, not the release.");
  console.error("  - In CHANGELOG bodies, use 'Previously' / 'Now' phrasing, not 'Pre-X.Y.Z'.");
  console.error("");
  console.error("If a violation is legitimate (e.g. a deprecation timeline that needs a specific version), add the");
  console.error("file path to COMMENT_EXEMPT in scripts/check-version-tags.js with a justifying comment.");

  process.exitCode = 1;
}

if (require.main === module) main();

