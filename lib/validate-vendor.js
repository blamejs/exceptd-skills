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

  // License file. A recorded license_file with NO license_sha256 is an
  // unverifiable integrity claim, not a skip: stripping the hash from the
  // manifest must not silently disable the LICENSE-text check (the
  // absent-field-fails-open class). Only a manifest that records no
  // license_file at all is exempt.
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

  // Each vendored file.
  for (const [name, info] of Object.entries(prov.files || {})) {
    const p = path.join(ROOT, info.vendored_path);
    if (!fs.existsSync(p)) {
      issues.push(`missing vendored file: ${info.vendored_path}`);
      continue;
    }
    // A files[] entry recorded without vendored_sha256 is an unverifiable
    // integrity claim — surface it as a clean issue rather than crashing on
    // `undefined.slice()` while formatting a drift message (the absent-field
    // class, symmetric with the license path above).
    if (!info.vendored_sha256) {
      issues.push(`${info.vendored_path} recorded without vendored_sha256 — integrity unverifiable`);
      continue;
    }
    const live = sha256(fs.readFileSync(p));
    if (live !== info.vendored_sha256) {
      issues.push(`drift in ${info.vendored_path}: recorded ${info.vendored_sha256.slice(0, 12)}…, live ${live.slice(0, 12)}…`);
    }
    // Offline upstream-pin cross-check. The vendored_sha256 compare above is
    // self-attesting — it only proves the file matches its OWN recorded hash,
    // never that the bytes match blamejs@<pin> upstream. The full upstream
    // verification (scripts/validate-vendor-online.js) needs the network and
    // is not a predeploy gate, so a hand-edited upstream_sha256_at_pin
    // advertising a pin that never existed otherwise passes every
    // automatically-run gate.
    //
    // For a file recorded with NO strip rules, the vendored bytes are
    // byte-identical to upstream by definition, so upstream_sha256_at_pin MUST
    // equal vendored_sha256. A divergence is a forged or internally
    // inconsistent pin claim, and it is provable OFFLINE — no fetch required.
    // This closes the upstream side of the integrity check for every
    // unmodified vendored file (the common case) inside the existing gate.
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
