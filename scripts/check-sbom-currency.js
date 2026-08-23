"use strict";
/**
 * Predeploy gate: sbom.cdx.json must be current against the live skill and
 * catalog counts, the recorded file hashes and the shipped-file set — drift
 * means the tarball ships an SBOM that disagrees with its own contents.
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

// Live entry total for a data/*.json catalog, or null when the file is absent so
// a `--root` pointed at a partial tree skips that token instead of crashing.
function catalogEntryCount(dataDir, file) {
  const p = path.join(dataDir, file);
  if (!fs.existsSync(p)) return null;
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  if (Array.isArray(j)) return j.length;
  if (j && typeof j === "object") {
    return Object.keys(j).filter((k) => k !== "_meta").length;
  }
  return 0;
}

// Mirrors scripts/refresh-sbom.js SELF_EXCLUDED + DERIVABLE_PREFIXES: the
// completeness check must apply the SAME exclusions or it demands a component
// the generator never emits.
const SBOM_SELF_EXCLUDED = new Set(["sbom.cdx.json"]);
const SBOM_DERIVABLE_PREFIXES = ["data/_indexes/"];
// Mirrors refresh-sbom's ALWAYS_SHIPPED: npm adds package.json to every tarball
// without it appearing in `files`, so a component is expected for it.
const SBOM_ALWAYS_SHIPPED = ["package.json", "sources/README.md"];

function sbomIsDerivable(rel) {
  return SBOM_DERIVABLE_PREFIXES.some(
    (p) => rel === p.replace(/\/$/, "") || rel.startsWith(p)
  );
}

// Mirrors refresh-sbom's walkFiles, walking whatever absolute dir it is handed.
function walkFilesAbs(absDir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(absDir, { withFileTypes: true }); }
  catch { return out; }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFilesAbs(abs));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

// The shipped-file set that must each have a file: component, computed against
// the TARGET tree. refresh-sbom's expandAllowlist is bound to its own REPO_ROOT,
// so it would validate the source repo's file list against the target SBOM.
function expandAllowlistAt(allowlist, root) {
  const abs = [];
  for (const entry of [...allowlist, ...SBOM_ALWAYS_SHIPPED]) {
    const full = path.join(root, entry);
    let stat;
    try { stat = fs.statSync(full); }
    catch { continue; } // tolerate a stale entry; presence checks elsewhere flag
    if (stat.isDirectory()) abs.push(...walkFilesAbs(full));
    else if (stat.isFile()) abs.push(full);
  }
  const rel = Array.from(
    new Set(abs.map((a) => path.relative(root, a).split(path.sep).join("/")))
  )
    .filter((r) => !SBOM_SELF_EXCLUDED.has(r))
    .filter((r) => !sbomIsDerivable(r))
    .sort();
  return rel;
}

// The description embeds per-catalog ENTRY counts as free text ("… 177 CWEs /
// 805 ATT&CK + ICS …"). `label` is the regex-escaped text after the number.
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

  // The numeric properties above cover only CARDINALITY, so an entry total can
  // drift in the description while those still agree.
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

  const catalogMatch = description.match(/(\d+)\s+catalogs?\b/i);
  if (!catalogMatch) {
    // Absence fails CLOSED: a reworded description must not skip the check.
    errors.push(
      "SBOM description is missing the catalog-count token (N catalogs) — regenerate via `npm run refresh-sbom`"
    );
  } else if (Number(catalogMatch[1]) !== liveCatalogs) {
    errors.push(
      `SBOM description catalog count is ${Number(catalogMatch[1])} but live data/ has ${liveCatalogs} catalogs — description is stale; update package.json.description and \`npm run refresh-sbom\``
    );
  }
  const liveJurisdictions = (() => {
    try {
      const gf = JSON.parse(fs.readFileSync(path.join(dataDir, "global-frameworks.json"), "utf8"));
      // Non-underscore top-level keys — the count the README badge reports.
      return Object.keys(gf).filter((k) => !k.startsWith("_")).length;
    } catch {
      return null;
    }
  })();
  const jurisdictionMatch = description.match(/(\d+)\s+jurisdictions?\b/i);
  // A partial `--root` tree without global-frameworks.json skips the check. Where
  // the source IS present the token is the SBOM's only jurisdiction assertion —
  // no structured property carries it — so a dropped token fails CLOSED.
  if (liveJurisdictions !== null) {
    if (!jurisdictionMatch) {
      errors.push(
        "SBOM description is missing the jurisdiction-count token (N jurisdictions) — regenerate via `npm run refresh-sbom`"
      );
    } else if (Number(jurisdictionMatch[1]) !== liveJurisdictions) {
      errors.push(
        `SBOM description jurisdiction count is ${Number(jurisdictionMatch[1])} but live global-frameworks.json has ${liveJurisdictions} — description is stale; update package.json.description and \`npm run refresh-sbom\``
      );
    }
  }

  // A clean SBOM carries no "skill:" components — skill drift shows up in the
  // file: hashes. This branch is the tamper guard for a forged SBOM that injects
  // one with a stale version.
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

  // Every "file:" component's recorded hash must match the live bytes. This is
  // what catches an SBOM regenerated BEFORE the final sign-all, where the
  // recorded manifest.json hash drifts from the signed-and-committed bytes.
  let fileComponentsChecked = 0;
  const rootResolved = path.resolve(root);
  for (const comp of components) {
    const bomRef = typeof comp["bom-ref"] === "string" ? comp["bom-ref"] : "";
    if (!bomRef.startsWith("file:")) continue;
    const relPath = bomRef.slice("file:".length);
    // A `file:../outside` bom-ref would otherwise hash a path outside the
    // checkout and report "exists, hash matches" — never the escape.
    if (relPath.includes("..") || path.isAbsolute(relPath)) {
      errors.push(
        `SBOM file component "${relPath}" rejected: path must be repo-relative without ".." segments (path-traversal guard)`
      );
      continue;
    }
    const absPath = path.resolve(rootResolved, relPath);
    // The resolved path must also land under root — a symlink, or a loosening of
    // the textual filter above, surfaces here.
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
    // SHA-256 is the universal-tool contract (CycloneDX 1.6 default, read by
    // Anchore / Trivy / Dependency-Track); SHA3-512 is the SHA-3 family hedge.
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
    // Absence is a hard error, never an `if (sha3Entry)` guard: stripping the
    // SHA3-512 column would otherwise pass and defeat the downgrade defense.
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

  // Completeness plus the aggregate bundle digest. The per-file pass verifies
  // every RECORDED component, so without this a newly-shipped file carrying no
  // component would go unhashed and silent.
  try {
    // bundleDigest reads only the file: component objects, so it is
    // root-agnostic; the allowlist expansion is not, hence expandAllowlistAt.
    const { bundleDigest } = require("./refresh-sbom");
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const expected = expandAllowlistAt(pkg.files || [], root);
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
    // Recomputed from the recorded per-file SHA-256s, already tied to live bytes.
    const compHashes = (sbom.metadata && sbom.metadata.component && sbom.metadata.component.hashes) || [];
    const recorded = (compHashes.find((h) => h && h.alg === "SHA-256") || {}).content;
    if (fileComps.length) {
      // The bundle-as-a-whole anchor: absence fails rather than skipping.
      if (!recorded) {
        errors.push(
          "SBOM metadata.component.hashes lacks a SHA-256 bundle digest — the aggregate verification anchor is missing; run `npm run refresh-sbom`"
        );
      } else {
        const recomputed = bundleDigest(fileComps);
        if (recomputed !== recorded) {
          errors.push(
            `SBOM bundle digest mismatch: metadata.component.hashes SHA-256 ${String(recorded).slice(0, 12)}… != recomputed ${recomputed.slice(0, 12)}… from file: components — run \`npm run refresh-sbom\``
          );
        }
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
    // process.exitCode, not process.exit() — the exit can truncate a piped write.
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `SBOM current — ${result.skills} skills, ${result.catalogs} catalogs, ` +
    `${result.components_validated} components validated, ` +
    `${result.file_components_hash_checked} file-hash entries verified.\n`
  );
}

module.exports = { checkSbomCurrency, resolveRoot, DESCRIPTION_ENTRY_TOKENS, catalogEntryCount, expandAllowlistAt };

if (require.main === module) main();
