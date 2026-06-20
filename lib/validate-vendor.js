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
const { safeExit } = require("./exit-codes");

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

  // On-disk inventory cross-check (BJS-04): the loop above is one-directional
  // (manifest → disk). A .js file PRESENT in vendor/blamejs/ but ABSENT from
  // _PROVENANCE.json would ship in the tarball and be require()'d by lib code
  // while NOTHING verifies its integrity — an unregistered or smuggled-in
  // vendored module. Flag every on-disk .js that the manifest does not record.
  const registered = new Set(
    Object.values(prov.files || {}).map((info) => path.basename(info.vendored_path))
  );
  const vendorDir = path.join(ROOT, "vendor", "blamejs");
  try {
    for (const f of fs.readdirSync(vendorDir)) {
      if (!f.endsWith(".js")) continue;
      if (!registered.has(f)) {
        issues.push(`unregistered vendored file: vendor/blamejs/${f} is on disk but absent from _PROVENANCE.json — its integrity is not verified`);
      }
    }
  } catch (err) {
    issues.push(`cannot read vendor/blamejs/ for the inventory cross-check: ${err.message}`);
  }

  if (issues.length === 0) {
    const fileCount = Object.keys(prov.files || {}).length;
    console.log(`[validate-vendor] vendor tree current — ${fileCount} file(s) validated against pin ${prov.pinned_commit?.slice(0, 12) || "?"}.`);
    safeExit(0);
    return;
  }

  console.error("[validate-vendor] vendor tree DRIFT:");
  for (const i of issues) console.error("  • " + i);
  console.error("[validate-vendor] re-vendor instructions: vendor/blamejs/README.md");
  safeExit(1);
  return;
}

if (require.main === module) main();

module.exports = { main };
