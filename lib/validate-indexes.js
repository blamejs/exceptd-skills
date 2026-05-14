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

function main() {
  if (!fs.existsSync(META)) {
    console.error("[validate-indexes] data/_indexes/_meta.json missing — run `npm run build-indexes`.");
    // v0.11.13 pattern: exitCode + return so async stdout/stderr writes drain.
    process.exitCode = 1;
    return;
  }

  const meta = JSON.parse(fs.readFileSync(META, "utf8"));
  const recorded = meta.source_hashes || {};

  // Audit G F1 — reject an empty source_hashes table outright. The previous
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
  // Audit G F16 — use lstat to detect symlinks. A symlinked .json under data/
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

module.exports = { main };
