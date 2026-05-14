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

  return {
    ok: errors.length === 0,
    errors,
    skills: sbomSkills,
    catalogs: sbomCatalogs,
    components_validated: components.length,
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
    `${result.components_validated} components validated.\n`
  );
}

module.exports = { checkSbomCurrency, resolveRoot };

if (require.main === module) main();
