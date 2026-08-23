#!/usr/bin/env node
"use strict";

/**
 * Predeploy gate refusing new version-stamped lines and filenames in the tracked
 * source tree. Whole lines, not just comments: a stamp in a data literal or a
 * help string is residue too, and a load-bearing one is exempted by path in
 * COMMENT_EXEMPT rather than by narrowing the scan. Counts must not rise above
 * tests/.version-tag-baseline.json; refresh it with `--update-baseline`.
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const BASELINE_PATH = path.join(ROOT, "tests", ".version-tag-baseline.json");

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".keys", ".cache", ".scratch",
  "data", "vendor", ".husky",
]);

const SCAN_EXTS = new Set([".js", ".cjs", ".mjs", ".md"]);

// Paths where a version reference is load-bearing.
const COMMENT_EXEMPT = new Set([
  "package.json",
  "manifest.json",
  "manifest-snapshot.json",
  "sbom.cdx.json",
  "CHANGELOG.md",
  "lib/version-pins.js",
  "scripts/check-version-tags.js",
  // Fixtures embed real `## X.Y.Z` headings, including a prefix collision.
  "tests/check-changelog-extract.test.js",
  // Allowlists the exact versions of tags with no published release.
  "scripts/check-changelog-extract.js",
  // Version comparison is the subject: real X.Y.Z transitions under test.
  "scripts/check-version-bump.js",
  "tests/version-bump-cadence.test.js",
  // The detector's own boundary cases appear literally as the inputs under test.
  "tests/check-version-tags.test.js",
]);

// The ignored subset of `relPaths`, or null when git cannot answer. "No path
// matched" and "the question could not be asked" must not collapse into the same
// empty set, which would reclassify every local-only file as shipped surface.
function gitIgnoredSet(relPaths) {
  if (!relPaths.length) return new Set();
  try {
    const out = execFileSync("git", ["check-ignore", "--stdin"], {
      cwd: ROOT, input: relPaths.join("\n"), encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return new Set(out.split(/\r?\n/).filter(Boolean));
  } catch (e) {
    // Exit 1 with no stderr is git's "no path matched" — a real answer, not a failure.
    const status = e && typeof e.status === "number" ? e.status : null;
    const stderr = e && e.stderr ? String(e.stderr).trim() : "";
    const out = e && e.stdout ? String(e.stdout) : "";
    if (status === 1 && !stderr) return new Set(out.split(/\r?\n/).filter(Boolean));
    return null;
  }
}

// A pre-1.0 project version, `v0.13.22` or bare; a non-0.x external version such
// as CycloneDX `1.6` misses. The lookarounds keep the stamp out of a wider number
// or a dotted run like `127.0.0.1`, whose tail would otherwise register.
const VERSION_TAG_RE = /(?<![\d.])v?0\.\d+\.\d+(?!\d)(?!\.\d)/;

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

function countLineViolations(rel) {
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
  // Without git, local-only files are indistinguishable from tracked ones.
  if (ignored === null) return { byFile: {}, filenameViolations: [], surfaceUnknown: true };
  const byFile = {};
  const filenameViolations = [];
  for (const rel of files) {
    if (ignored.has(rel)) continue;
    if (FILENAME_VERSION_RE.test(rel)) filenameViolations.push(rel);
    const n = countLineViolations(rel);
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

  if (current.surfaceUnknown) {
    // A baseline written from this scan would bake in the wrong surface. In
    // automation this fails rather than skips: predeploy guards publishing.
    const inAutomation = process.env.CI === "true" || !!process.env.GITHUB_ACTIONS;
    if (inAutomation) {
      console.error("[check-version-tags] FAIL — no git repository available, so the shipped");
      console.error("  surface cannot be determined. In automation this is a failure, not a skip:");
      console.error("  this gate runs inside predeploy, which guards publishing. Ensure the job");
      console.error("  checks out git metadata (actions/checkout provides it by default).");
      process.exitCode = 2;
      return;
    }
    console.error("[check-version-tags] SKIPPED — no git repository available, so the shipped");
    console.error("  surface cannot be determined. This is not a pass; run it where git metadata");
    console.error("  is present. In CI the same condition fails instead.");
    process.exitCode = 0;
    return;
  }

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

  for (const rel of current.filenameViolations) {
    if (!baseline.filenameViolations.includes(rel)) {
      regressions.push({
        kind: "filename",
        path: rel,
        reason: "new test filename carries a version tag — rename to describe the surface it pins, not the release",
      });
    }
  }

  for (const [rel, n] of Object.entries(current.byFile)) {
    const prior = baseline.byFile[rel] || 0;
    if (n > prior) {
      regressions.push({
        kind: "comment",
        path: rel,
        baseline: prior,
        actual: n,
        reason: `version-tag line count grew from ${prior} to ${n} (counts stamps in comments, strings, and data) — describe the WHY of the current code, not the release that introduced it`,
      });
    }
  }

  for (const rel of Object.keys(current.byFile)) {
    if (!(rel in baseline.byFile)) {
      const n = current.byFile[rel];
      if (regressions.some(r => r.path === rel)) continue;
      regressions.push({
        kind: "comment",
        path: rel,
        baseline: 0,
        actual: n,
        reason: `new file carries ${n} version-tag line(s) (counts stamps in comments, strings, and data) — describe the WHY of the current code, not the release that introduced it`,
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

module.exports = {
  VERSION_TAG_RE,
  PHASE_RESIDUE_RES,
  FILENAME_VERSION_RE,
  countLineViolations,
  scanCurrent,
};

if (require.main === module) main();

