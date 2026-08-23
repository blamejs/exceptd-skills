"use strict";
/**
 * Predeploy gate: every file recorded in `vendor/blamejs/_PROVENANCE.json` must
 * carry the same SHA-256 on disk, and vendor/blamejs/LICENSE must match its
 * recorded hash. Exits 0 when the tree is in sync, 1 on any drift.
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

  // A recorded license_file with NO license_sha256 is an unverifiable integrity
  // claim, not a skip: stripping the hash must not disable this check.
  if (prov.license_file) {
    if (!prov.license_sha256) {
      issues.push(`license_file recorded (${prov.license_file}) without license_sha256 — integrity unverifiable`);
    } else {
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
  }

  for (const [name, info] of Object.entries(prov.files || {})) {
    const p = path.join(ROOT, info.vendored_path);
    if (!fs.existsSync(p)) {
      issues.push(`missing vendored file: ${info.vendored_path}`);
      continue;
    }
    // An entry recorded without vendored_sha256 is an unverifiable integrity
    // claim — report it rather than crash on `undefined.slice()`.
    if (!info.vendored_sha256) {
      issues.push(`${info.vendored_path} recorded without vendored_sha256 — integrity unverifiable`);
      continue;
    }
    const live = sha256(fs.readFileSync(p));
    if (live !== info.vendored_sha256) {
      issues.push(`drift in ${info.vendored_path}: recorded ${info.vendored_sha256.slice(0, 12)}…, live ${live.slice(0, 12)}…`);
    }
    // The vendored_sha256 compare above is self-attesting: it proves the file
    // matches its OWN recorded hash, never that the bytes match blamejs@<pin>.
    // With no strip rules the vendored bytes ARE the upstream bytes, so a
    // divergence from upstream_sha256_at_pin is a forged pin claim, provable
    // offline. The fetching check is scripts/validate-vendor-online.js.
    const stripped = Array.isArray(info.stripped) ? info.stripped : [];
    if (stripped.length === 0) {
      if (!info.upstream_sha256_at_pin) {
        issues.push(`${info.vendored_path} has no strip rules but records no upstream_sha256_at_pin — upstream pin claim unverifiable`);
      } else if (info.upstream_sha256_at_pin !== info.vendored_sha256) {
        issues.push(
          `${info.vendored_path} records no strip rules, so its upstream_sha256_at_pin must equal vendored_sha256, ` +
            `but upstream_sha256_at_pin is ${String(info.upstream_sha256_at_pin).slice(0, 12)}… vs vendored ${info.vendored_sha256.slice(0, 12)}… — forged or inconsistent upstream pin`
        );
      }
    }
    // Smoke-check the vendored module loads.
    try {
      require(p);
    } catch (err) {
      issues.push(`load error in ${info.vendored_path}: ${err.message}`);
    }
  }

  // The loop above is one-directional (manifest → disk): a module on disk but
  // absent from _PROVENANCE.json ships with nothing verifying its integrity.
  // Node executes `.js`, `.cjs` and `.mjs` alike, so a renamed extension must not
  // slip the sweep; `.json` stays out because `_PROVENANCE.json` IS the manifest.
  const LOADABLE_MODULE = /\.(c|m)?js$/;
  const registered = new Set(
    Object.values(prov.files || {}).map((info) => path.basename(info.vendored_path))
  );
  const vendorDir = path.join(ROOT, "vendor", "blamejs");
  try {
    for (const f of fs.readdirSync(vendorDir)) {
      if (!LOADABLE_MODULE.test(f)) continue;
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
