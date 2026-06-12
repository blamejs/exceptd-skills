"use strict";
/**
 * scripts/check-sbom-currency.js
 *
 * Predeploy gate: assert sbom.cdx.json is current against the live skill +
 * catalog counts. Drift means an SBOM regen was forgotten — operators
 * downloading the tarball would see counts that disagree with the actual
 * manifest.json and data/*.json contents.
 *
 * Anchors to ROOT in this order of preference:
 *   1. `--root <dir>` on argv (testability — staged tempdir layouts).
 *   2. `EXCEPTD_ROOT` environment variable.
 *   3. `path.join(__dirname, '..')` — the running script's parent dir.
 *
 * Exit 0 on current SBOM, 1 on any drift (catalog count, skill count, or
 * CycloneDX-format mismatch).
 *
 * No external dependencies. Node 24 stdlib only.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function resolveRoot(argv) {
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--root" && argv[i + 1]) return path.resolve(argv[i + 1]);
    if (argv[i].startsWith("--root=")) return path.resolve(argv[i].slice("--root=".length));
  }
  if (process.env.EXCEPTD_ROOT) return path.resolve(process.env.EXCEPTD_ROOT);
  return path.join(__dirname, "..");
}

// Entry count for a data/*.json catalog: keys minus the _meta sentinel. The
// catalogs are objects keyed by entry id (CVE-…, CWE-…, T…, AML.T…, D3-…,
// RFC-…) with a single _meta block, so the live entry total is the key count
// excluding _meta.
function catalogEntryCount(dataDir, file) {
  const p = path.join(dataDir, file);
  // A --root pointed at a partial tree (no such catalog file) skips that
  // token's check rather than crashing — catalog PRESENCE is asserted by
  // the cardinality check above and the per-component hash check below,
  // not by the description parser.
  if (!fs.existsSync(p)) return null;
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  if (Array.isArray(j)) return j.length;
  if (j && typeof j === "object") {
    return Object.keys(j).filter((k) => k !== "_meta").length;
  }
  return 0;
}

// The description string embeds per-catalog ENTRY counts as free text, e.g.
// "11 catalogs (439 CVEs / 177 CWEs / 805 ATT&CK + ICS / 170 ATLAS /
// 468 D3FEND / 8888 RFCs)". Each token maps to one data/*.json catalog whose
// live entry count must match. `label` is the regex-escaped text that follows
// the number in the description.
const DESCRIPTION_ENTRY_TOKENS = [
  { file: "cve-catalog.json", label: "CVEs" },
  { file: "cwe-catalog.json", label: "CWEs" },
  { file: "attack-techniques.json", label: "ATT&CK \\+ ICS" },
  { file: "atlas-ttps.json", label: "ATLAS" },
  { file: "d3fend-catalog.json", label: "D3FEND" },
  { file: "rfc-references.json", label: "RFCs" },
];

function checkSbomCurrency(root) {
  const sbomPath = path.join(root, "sbom.cdx.json");
  const manifestPath = path.join(root, "manifest.json");
  const dataDir = path.join(root, "data");

  if (!fs.existsSync(sbomPath)) {
    return {
      ok: false,
      errors: ["sbom.cdx.json not found — run `npm run refresh-sbom`."],
    };
  }
  const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const liveCatalogs = fs
    .readdirSync(dataDir)
    .filter((f) => f.endsWith(".json")).length;
  const liveSkills = Array.isArray(manifest.skills) ? manifest.skills.length : 0;
  const props = Object.fromEntries(
    ((sbom.metadata && sbom.metadata.properties) || []).map((p) => [p.name, p.value])
  );
  const sbomCatalogs = Number(props["exceptd:catalog:count"]);
  const sbomSkills = Number(props["exceptd:skill:count"]);
  const errors = [];
  if (sbomCatalogs !== liveCatalogs) {
    errors.push(`SBOM catalog count ${sbomCatalogs} != live ${liveCatalogs}`);
  }
  if (sbomSkills !== liveSkills) {
    errors.push(`SBOM skill count ${sbomSkills} != live ${liveSkills}`);
  }
  if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.6") {
    errors.push("SBOM is not CycloneDX 1.6");
  }

  // The SBOM ships per-catalog entry counts and a skill count embedded as free
  // text in metadata.component.description (propagated verbatim from
  // package.json). The numeric properties above only cover catalog/skill
  // CARDINALITY (file count + skill count), so a catalog's entry total can
  // drift past the count baked into the description while the dedicated SBOM
  // gate still passes. Parse each token out of the description and assert it
  // against the live entry count so a stale published-SBOM description fails
  // the gate.
  const description =
    (sbom.metadata && sbom.metadata.component && sbom.metadata.component.description) || "";
  for (const { file, label } of DESCRIPTION_ENTRY_TOKENS) {
    const live = catalogEntryCount(dataDir, file);
    if (live === null) continue;
    const m = description.match(new RegExp("(\\d+)\\s+" + label + "\\b"));
    if (!m) {
      errors.push(
        `SBOM description is missing the "${file.replace(/\.json$/, "")}" entry-count token (${label}) — regenerate via \`npm run refresh-sbom\``
      );
      continue;
    }
    const stated = Number(m[1]);
    if (stated !== live) {
      errors.push(
        `SBOM description entry count for ${label} is ${stated} but live ${file} has ${live} — description is stale; update package.json.description and \`npm run refresh-sbom\``
      );
    }
  }
  // The skill count is embedded in the same description string ("N skills").
  const skillMatch = description.match(/(\d+)\s+skills\b/);
  if (!skillMatch) {
    errors.push(
      "SBOM description is missing the skill-count token (N skills) — regenerate via `npm run refresh-sbom`"
    );
  } else if (Number(skillMatch[1]) !== liveSkills) {
    errors.push(
      `SBOM description skill count is ${Number(skillMatch[1])} but live manifest has ${liveSkills} skills — description is stale; update package.json.description and \`npm run refresh-sbom\``
    );
  }

  // The "N catalogs" and "N jurisdictions" free-text counts in the same
  // description string were never validated — only the per-catalog entry tokens
  // and the skill count were. Pin them to the live values so a stale
  // description (e.g. after an auto-refresh changed a count) fails the gate.
  const catalogMatch = description.match(/(\d+)\s+catalogs?\b/i);
  if (catalogMatch && Number(catalogMatch[1]) !== liveCatalogs) {
    errors.push(
      `SBOM description catalog count is ${Number(catalogMatch[1])} but live data/ has ${liveCatalogs} catalogs — description is stale; update package.json.description and \`npm run refresh-sbom\``
    );
  }
  const liveJurisdictions = (() => {
    try {
      const gf = JSON.parse(fs.readFileSync(path.join(dataDir, "global-frameworks.json"), "utf8"));
      // Non-underscore top-level keys — the canonical jurisdiction count the
      // README badge and catalog-summaries use.
      return Object.keys(gf).filter((k) => !k.startsWith("_")).length;
    } catch {
      return null;
    }
  })();
  const jurisdictionMatch = description.match(/(\d+)\s+jurisdictions?\b/i);
  if (liveJurisdictions !== null && jurisdictionMatch && Number(jurisdictionMatch[1]) !== liveJurisdictions) {
    errors.push(
      `SBOM description jurisdiction count is ${Number(jurisdictionMatch[1])} but live global-frameworks.json has ${liveJurisdictions} — description is stale; update package.json.description and \`npm run refresh-sbom\``
    );
  }

  // Component-level cross-check (defense-in-depth). In normal operation
  // refresh-sbom emits NO per-skill "skill:" components — skill drift is caught
  // by the file:skills/<name>/skill.md and file:manifest.json content hashes in
  // the file: component pass below (a bumped or renamed skill changes those
  // bytes). This branch is therefore not exercised by a clean SBOM, but it is
  // retained as a tamper guard: a forged or buggy SBOM that injected a skill
  // component with a stale version (or a skill name no longer in the manifest)
  // is still caught here. Vendor components are validated against
  // vendor/blamejs/_PROVENANCE.json.
  const components = Array.isArray(sbom.components) ? sbom.components : [];
  const skillByName = new Map(
    (manifest.skills || []).map((s) => [s.name, s])
  );
  const provPath = path.join(root, "vendor", "blamejs", "_PROVENANCE.json");
  let vendorProv = null;
  if (fs.existsSync(provPath)) {
    try { vendorProv = JSON.parse(fs.readFileSync(provPath, "utf8")); } catch { /* leave null */ }
  }
  for (const comp of components) {
    const bomRef = typeof comp["bom-ref"] === "string" ? comp["bom-ref"] : "";
    const name = comp.name;
    const version = comp.version;
    if (bomRef.startsWith("skill:") || skillByName.has(name)) {
      const skillName = bomRef.startsWith("skill:")
        ? bomRef.slice("skill:".length)
        : name;
      const live = skillByName.get(skillName);
      if (!live) {
        errors.push(
          `SBOM component "${name}" (bom-ref ${bomRef}) is not in manifest.skills — skill renamed or removed without SBOM refresh`
        );
        continue;
      }
      if (live.version && version && String(live.version) !== String(version)) {
        errors.push(
          `SBOM component "${name}" version ${version} != manifest.skills version ${live.version} — bump without SBOM refresh`
        );
      }
    } else if (bomRef.startsWith("vendor:")) {
      if (vendorProv && vendorProv.pinned_commit) {
        const expected = vendorProv.pinned_commit.slice(0, 12);
        if (version && String(version) !== expected) {
          errors.push(
            `SBOM vendor component "${name}" version ${version} != _PROVENANCE.json pinned_commit ${expected}`
          );
        }
      }
    }
  }

  // v0.13.9: per-file SHA-256 integrity check. For every CycloneDX
  // component whose bom-ref begins with "file:", confirm the recorded
  // SHA-256 hash matches the live bytes on disk. Catches the class of
  // release-ordering bug where sbom.cdx.json was regenerated BEFORE the
  // final sign-all pass — the recorded manifest.json hash drifted from
  // the signed-and-committed bytes, but the count-based check above
  // could not see it. Codex P2 flag on PR #48 surfaced one instance;
  // this gate makes it unreachable.
  let fileComponentsChecked = 0;
  const rootResolved = path.resolve(root);
  for (const comp of components) {
    const bomRef = typeof comp["bom-ref"] === "string" ? comp["bom-ref"] : "";
    if (!bomRef.startsWith("file:")) continue;
    const relPath = bomRef.slice("file:".length);
    // Codex P2 on PR #49: refuse bom-ref entries that escape the repo
    // root. The earlier implementation trusted `relPath` verbatim, so a
    // tampered or carelessly-edited sbom.cdx.json with `file:../outside`
    // would read + hash a path OUTSIDE the checkout — the gate would
    // either report "exists, hash matches" (silently weakening the
    // integrity guarantee) or "does not exist" without ever flagging the
    // attempted escape. Refuse early.
    if (relPath.includes("..") || path.isAbsolute(relPath)) {
      errors.push(
        `SBOM file component "${relPath}" rejected: path must be repo-relative without ".." segments (path-traversal guard)`
      );
      continue;
    }
    const absPath = path.resolve(rootResolved, relPath);
    // Defense-in-depth: even if the textual check above passed, the
    // resolved path must still live under the root. Symlinks or future
    // changes to the textual filter would surface here.
    const rel = path.relative(rootResolved, absPath);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      errors.push(
        `SBOM file component "${relPath}" resolved outside repo root (${absPath}) — refused (path-traversal guard)`
      );
      continue;
    }
    if (!fs.existsSync(absPath)) {
      errors.push(
        `SBOM file component "${relPath}" recorded but file does not exist on disk`
      );
      continue;
    }
    // v0.13.12: verify SHA-256 AND SHA3-512 when present. SHA-256 is
    // the universal-tool contract (CycloneDX 1.6 default, Anchore /
    // Trivy / Dependency-Track / GitHub Dependency Graph). SHA3-512
    // is the SHA-3 family hedge, matching the existing key-fingerprint
    // pattern (lib/verify.js). Both must agree with the live bytes;
    // a mismatch on either fires the same drift error. A missing
    // SHA-256 is a hard error (the universal contract is the floor);
    // a missing SHA3-512 surfaces as a downgrade-attack warning so an
    // operator who intentionally strips the second hash from an
    // SBOM (post-quantum posture relaxation) sees it in the gate
    // output, not in the JSON downstream.
    const sha256Entry = (comp.hashes || []).find((h) => h && h.alg === "SHA-256");
    const sha3Entry = (comp.hashes || []).find((h) => h && h.alg === "SHA3-512");
    if (!sha256Entry || typeof sha256Entry.content !== "string") {
      errors.push(
        `SBOM file component "${relPath}" lacks a SHA-256 hash entry`
      );
      continue;
    }
    const fileBytes = fs.readFileSync(absPath);
    const liveSha256 = crypto.createHash("sha256").update(fileBytes).digest("hex");
    if (liveSha256 !== sha256Entry.content) {
      errors.push(
        `SBOM file component "${relPath}" SHA-256 drift: recorded ${sha256Entry.content.slice(0, 12)}…, live ${liveSha256.slice(0, 12)}… — re-sign skills (\`node $(exceptd path)/lib/sign.js sign-all\` from a contributor checkout) and then \`npm run refresh-sbom\`, in that order (sbom must regenerate AFTER the final sign).`,
      );
    }
    // Codex P1 on PR #52: the dual-hash contract requires SHA3-512 to be
    // PRESENT, not just verified when present. An attacker (or a careless
    // sbom-generator regression) that strips the SHA3-512 column would
    // silently pass the gate under an `if (sha3Entry)` guard, defeating
    // the downgrade defense the dual-hash design is supposed to provide.
    // Refuse absence as a hard error.
    if (!sha3Entry || typeof sha3Entry.content !== "string") {
      errors.push(
        `SBOM file component "${relPath}" lacks a SHA3-512 hash entry — the dual-hash contract (SHA-256 + SHA3-512) requires both algorithms on every file: component. Regenerate via \`npm run refresh-sbom\` (v0.13.12+).`
      );
    } else {
      const liveSha3 = crypto.createHash("sha3-512").update(fileBytes).digest("hex");
      if (liveSha3 !== sha3Entry.content) {
        errors.push(
          `SBOM file component "${relPath}" SHA3-512 drift: recorded ${sha3Entry.content.slice(0, 12)}…, live ${liveSha3.slice(0, 12)}… — same remediation as SHA-256 drift (re-sign then refresh-sbom).`,
        );
      }
    }
    fileComponentsChecked++;
  }

  // Completeness + bundle-digest integrity. The per-file pass above verifies
  // every RECORDED file: component, but never checked that every SHIPPED file
  // (the package.json.files expansion) actually HAS a component — a
  // newly-shipped file would ship unhashed and silent. And the aggregate
  // bundle digest in metadata.component.hashes[] was never recomputed. Reuse
  // refresh-sbom's exact allowlist expansion + digest so the gate can't drift
  // from the generator.
  try {
    const { expandAllowlist, bundleDigest } = require("./refresh-sbom");
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const expected = expandAllowlist(pkg.files || []);
    const fileComps = components.filter(
      (c) => typeof c["bom-ref"] === "string" && c["bom-ref"].startsWith("file:")
    );
    const fileCompNames = new Set(fileComps.map((c) => c.name));
    for (const rel of expected) {
      if (!fileCompNames.has(rel)) {
        errors.push(
          `Shipped file "${rel}" (package.json.files) has no file: component in the SBOM — run \`npm run refresh-sbom\``
        );
      }
    }
    // Recompute the aggregate bundle digest from the file: components' recorded
    // SHA-256 hashes and compare to metadata.component.hashes[] (the per-file
    // pass already tied each recorded hash to live bytes).
    const compHashes = (sbom.metadata && sbom.metadata.component && sbom.metadata.component.hashes) || [];
    const recorded = (compHashes.find((h) => h && h.alg === "SHA-256") || {}).content;
    if (recorded && fileComps.length) {
      const recomputed = bundleDigest(fileComps);
      if (recomputed !== recorded) {
        errors.push(
          `SBOM bundle digest mismatch: metadata.component.hashes SHA-256 ${String(recorded).slice(0, 12)}… != recomputed ${recomputed.slice(0, 12)}… from file: components — run \`npm run refresh-sbom\``
        );
      }
    }
  } catch (e) {
    errors.push(`SBOM completeness/bundle-digest check failed: ${e.message}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    skills: sbomSkills,
    catalogs: sbomCatalogs,
    components_validated: components.length,
    file_components_hash_checked: fileComponentsChecked,
  };
}

function main() {
  const root = resolveRoot(process.argv);
  const result = checkSbomCurrency(root);
  if (!result.ok) {
    for (const e of result.errors) process.stderr.write(e + "\n");
    process.stderr.write("Run `npm run refresh-sbom` to regenerate sbom.cdx.json.\n");
    // v0.11.13 pattern: set exitCode + return so buffered stdout/stderr
    // writes drain before the event loop exits. process.exit() can
    // truncate piped output (CI log capture, JSON consumers).
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `SBOM current — ${result.skills} skills, ${result.catalogs} catalogs, ` +
    `${result.components_validated} components validated, ` +
    `${result.file_components_hash_checked} file-hash entries verified.\n`
  );
}

module.exports = { checkSbomCurrency, resolveRoot, DESCRIPTION_ENTRY_TOKENS, catalogEntryCount };

if (require.main === module) main();
