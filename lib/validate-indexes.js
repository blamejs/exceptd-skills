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

if (!fs.existsSync(META)) {
  console.error("[validate-indexes] data/_indexes/_meta.json missing — run `npm run build-indexes`.");
  process.exit(1);
}

const meta = JSON.parse(fs.readFileSync(META, "utf8"));
const recorded = meta.source_hashes || {};

// Discover the current canonical source set.
const manifest = JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"));
const liveSources = new Set();
liveSources.add("manifest.json");
for (const f of fs.readdirSync(ABS("data"))) {
  if (f.endsWith(".json")) liveSources.add("data/" + f);
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
  const live = sha256(fs.readFileSync(ABS(p)));
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
  process.exit(0);
}

console.error("[validate-indexes] indexes STALE:");
for (const i of issues) console.error("  • " + i);
console.error("[validate-indexes] regenerate with: npm run build-indexes");
process.exit(1);
