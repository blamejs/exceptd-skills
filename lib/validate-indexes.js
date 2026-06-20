"use strict";
/**
 * lib/validate-indexes.js
 *
 * Predeploy gate. Confirms that `data/_indexes/*.json` is current
 * against the canonical sources (manifest.json + every data/*.json
 * minus _indexes/* + every skill body).
 *
 * Strategy:
 *   1. Load `data/_indexes/_meta.json` for the source SHA-256 table.
 *   2. Re-hash every listed source file.
 *   3. Fail if any hash diverges (the indexes are stale).
 *   4. Fail if a new source file exists that's not in the index (the
 *      index doesn't reflect current state).
 *   5. Fail if source_hashes is empty (build-indexes never ran).
 *   6. Fail if any data/*.json or listed source is a symlink.
 *
 * Exit 0 on success, 1 on staleness.
 *
 * Run as: node lib/validate-indexes.js
 * Or as predeploy gate via scripts/predeploy.js.
 *
 * Re-build with: npm run build-indexes
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const IDX_DIR = ABS("data/_indexes");
const META = path.join(IDX_DIR, "_meta.json");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Confirm every derived index OUTPUT exists, is a real file, and parses as
 * JSON. Returns an array of human-readable issue strings (empty = all good).
 * Source-hash drift alone does NOT catch a deleted/truncated/corrupted output,
 * so this runs in addition to the source-hash comparison.
 */
function verifyOutputs(idxDir, outputs) {
  const issues = [];
  // O_NOFOLLOW + a single descriptor: the open atomically refuses a symlinked
  // index path (ELOOP) and every subsequent stat/read rides the same fd, so
  // there is no existsSync->lstat->readFileSync TOCTOU on the path. Where
  // O_NOFOLLOW is unavailable the flag degrades to 0 (plain open).
  const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
  for (const file of outputs) {
    const abs = path.join(idxDir, file);
    let fd;
    try {
      fd = fs.openSync(abs, fs.constants.O_RDONLY | O_NOFOLLOW);
    } catch (e) {
      if (e.code === "ELOOP") {
        issues.push(`derived index file is a symbolic link: data/_indexes/${file}`);
      } else if (e.code === "ENOENT") {
        issues.push(`derived index file missing: data/_indexes/${file} — run npm run build-indexes`);
      } else {
        issues.push(`derived index file unreadable: data/_indexes/${file} (${e.message})`);
      }
      continue;
    }
    try {
      // readFileSync(fd) loops read() to EOF — a single readSync may return
      // fewer than st.size bytes (short read on a network/FUSE-backed fd),
      // leaving the tail NUL-filled and truncating the JSON. Reading via the
      // open fd keeps the open→fstat ordering TOCTOU-free.
      JSON.parse(fs.readFileSync(fd, "utf8"));
    } catch (e) {
      issues.push(`derived index file does not parse: data/_indexes/${file} (${e.message})`);
    } finally {
      fs.closeSync(fd);
    }
  }
  return issues;
}

function main() {
  if (!fs.existsSync(META)) {
    console.error("[validate-indexes] data/_indexes/_meta.json missing — run `npm run build-indexes`.");
    // v0.11.13 pattern: exitCode + return so async stdout/stderr writes drain.
    process.exitCode = 1;
    return;
  }

  const meta = JSON.parse(fs.readFileSync(META, "utf8"));
  const recorded = meta.source_hashes || {};

  // reject an empty source_hashes table outright. The previous
  // gate would silently pass when source_hashes was {} (or missing entirely)
  // because the for-loop body never executed; the resulting "0 sources" pass
  // banner falsely advertised the indexes as current. An empty source-hash
  // table means build-indexes was never run, or was run against an empty
  // repo, and the index files themselves are not trustworthy.
  if (Object.keys(recorded).length === 0) {
    console.error(
      "[validate-indexes] data/_indexes/_meta.json source_hashes is empty — " +
      "this means build-indexes did not populate the index. " +
      "Regenerate with: npm run build-indexes"
    );
    process.exitCode = 1;
    return;
  }

  // Discover the current canonical source set.
  const manifest = JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"));
  const liveSources = new Set();
  liveSources.add("manifest.json");
  // README.md is consumed by the stale-content index builder (badge-count
  // drift), so build-indexes hashes it as a source. Keep this validator's
  // source set in sync — otherwise the hashed README looks like a removed
  // file here. (Mirrors liveSourceSet() in scripts/build-indexes.js.)
  if (fs.existsSync(ABS("README.md"))) liveSources.add("README.md");
  // use lstat to detect symlinks. A symlinked .json under data/
  // would be hashed via the followed target, allowing a malicious checkout
  // (or a misconfigured filesystem) to swap data origin without tripping the
  // gate. Reject symlinks outright.
  for (const f of fs.readdirSync(ABS("data"))) {
    if (!f.endsWith(".json")) continue;
    const abs = ABS("data/" + f);
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) {
      console.error(
        `[validate-indexes] data/${f} is a symbolic link — refusing to follow. ` +
        `Replace with the real file or remove the entry.`
      );
      process.exitCode = 1;
      return;
    }
    liveSources.add("data/" + f);
  }
  for (const s of manifest.skills) liveSources.add(s.path);

  const drift = [];
  const missing = [];
  const recordedKeys = new Set(Object.keys(recorded));

  for (const p of liveSources) {
    if (!recordedKeys.has(p)) {
      missing.push(`new source not in index: ${p}`);
      continue;
    }
    const abs = ABS(p);
    // F16 — also check listed-but-symlinked sources. lstatSync on a missing
    // file throws; mirror the existsSync semantics by guarding it.
    if (fs.existsSync(abs)) {
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink()) {
        missing.push(`source ${p} is a symbolic link — refusing to follow`);
        continue;
      }
    }
    const live = sha256(fs.readFileSync(abs));
    if (live !== recorded[p]) {
      drift.push(`hash drift: ${p} (recorded ${recorded[p].slice(0, 12)}…, live ${live.slice(0, 12)}…)`);
    }
  }
  for (const p of recordedKeys) {
    if (!liveSources.has(p)) {
      missing.push(`stale source in index (file removed): ${p}`);
    }
  }

  // Verify the derived index OUTPUTS themselves exist and parse. Source-hash
  // drift alone does not catch a deleted/truncated/corrupted OUTPUT: a clean
  // source tree with a missing index file would otherwise pass as "current".
  // _meta.outputs is the canonical list build-indexes records; an absent list
  // FAILS (rather than silently skipping the check) so an old _meta can't pass.
  // Absent `outputs` list (an older build that predates this field) is itself a
  // staleness condition — fold it into the unified STALE report rather than
  // early-returning, so a concurrent source-hash drift still surfaces too.
  const outputs = Array.isArray(meta.outputs) ? meta.outputs : null;
  if (!outputs || outputs.length === 0) {
    missing.push(
      "data/_indexes/_meta.json has no `outputs` list — rebuild with " +
      "`npm run build-indexes` so derived-index integrity can be confirmed"
    );
  } else {
    for (const issue of verifyOutputs(IDX_DIR, outputs)) missing.push(issue);
  }

  const issues = [...drift, ...missing];
  if (issues.length === 0) {
    console.log(`[validate-indexes] indexes current — ${recordedKeys.size} sources hashed at ${meta.generated_at}.`);
    return;
  }

  console.error("[validate-indexes] indexes STALE:");
  for (const i of issues) console.error("  • " + i);
  console.error("[validate-indexes] regenerate with: npm run build-indexes");
  process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { main, verifyOutputs };
