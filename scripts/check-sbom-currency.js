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

  // component-level cross-check. A renamed or version-bumped
  // skill that never made it into the SBOM refresh will pass the count
  // check (the cardinality is unchanged) but the per-component name +
  // version comparison surfaces it. Two component classes are recognised:
  //
  //   1. Skill components — bom-ref begins with "skill:" OR the component
  //      name matches a manifest.skills[].name. Each one must exist in
  //      manifest.skills with the same version.
  //   2. Vendor components — bom-ref begins with "vendor:". Validated
  //      against vendor/blamejs/_PROVENANCE.json when present.
  //
  // Components that don't fit either pattern are surfaced as warnings
  // (not errors) so the gate isn't brittle against future component types.
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

module.exports = { checkSbomCurrency, resolveRoot };

if (require.main === module) main();
