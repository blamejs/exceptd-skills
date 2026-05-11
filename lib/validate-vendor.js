"use strict";
/**
 * lib/validate-vendor.js
 *
 * Predeploy gate. Confirms every file recorded in `vendor/blamejs/_PROVENANCE.json`
 * has the same SHA-256 on disk as the manifest claims. Silent hand-edits
 * to a vendored copy fail the build.
 *
 * Also confirms vendor/blamejs/LICENSE matches the recorded license hash so
 * a license-text change is detected as a separate event from a code change.
 *
 * Exit codes:
 *   0 — vendor tree in sync with provenance
 *   1 — at least one file drift / missing
 *
 * Re-vendor with: copy upstream, apply strip rules, refresh hashes in
 * _PROVENANCE.json, re-run this gate.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const PROV = path.join(ROOT, "vendor", "blamejs", "_PROVENANCE.json");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function main() {
  if (!fs.existsSync(PROV)) {
    console.error("[validate-vendor] vendor/blamejs/_PROVENANCE.json missing.");
    process.exit(1);
  }
  const prov = JSON.parse(fs.readFileSync(PROV, "utf8"));
  const issues = [];

  // License file.
  if (prov.license_file && prov.license_sha256) {
    const p = path.join(ROOT, "vendor", "blamejs", prov.license_file);
    if (!fs.existsSync(p)) {
      issues.push(`missing license file: ${prov.license_file}`);
    } else {
      const live = sha256(fs.readFileSync(p));
      if (live !== prov.license_sha256) {
        issues.push(`LICENSE drift: recorded ${prov.license_sha256.slice(0, 12)}…, live ${live.slice(0, 12)}…`);
      }
    }
  }

  // Each vendored file.
  for (const [name, info] of Object.entries(prov.files || {})) {
    const p = path.join(ROOT, info.vendored_path);
    if (!fs.existsSync(p)) {
      issues.push(`missing vendored file: ${info.vendored_path}`);
      continue;
    }
    const live = sha256(fs.readFileSync(p));
    if (live !== info.vendored_sha256) {
      issues.push(`drift in ${info.vendored_path}: recorded ${info.vendored_sha256.slice(0, 12)}…, live ${live.slice(0, 12)}…`);
    }
    // Smoke-check the vendored module loads.
    try {
      require(p);
    } catch (err) {
      issues.push(`load error in ${info.vendored_path}: ${err.message}`);
    }
  }

  if (issues.length === 0) {
    const fileCount = Object.keys(prov.files || {}).length;
    console.log(`[validate-vendor] vendor tree current — ${fileCount} file(s) validated against pin ${prov.pinned_commit?.slice(0, 12) || "?"}.`);
    process.exit(0);
  }

  console.error("[validate-vendor] vendor tree DRIFT:");
  for (const i of issues) console.error("  • " + i);
  console.error("[validate-vendor] re-vendor instructions: vendor/blamejs/README.md");
  process.exit(1);
}

if (require.main === module) main();

module.exports = { main };
