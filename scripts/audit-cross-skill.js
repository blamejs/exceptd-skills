"use strict";
/**
 * scripts/audit-cross-skill.js
 *
 * Comprehensive cross-skill accuracy / bug audit. Run after any
 * skill add / rename / dispatch-rewire. Surfaces:
 *
 *   - manifest paths that don't exist on disk
 *   - skill directories on disk with no manifest entry
 *   - frontmatter `name` drift from manifest `name`
 *   - skills missing from the researcher dispatch table
 *   - skills missing from AGENTS.md Quick Skill Reference
 *   - version drift between package.json / manifest.json / CHANGELOG.md
 *   - manifest-snapshot.json drift from manifest.json
 *   - sbom.cdx.json drift from live skill / catalog counts
 *   - broken ref: any cwe_refs / d3fend_refs / framework_gaps / atlas_refs /
 *     rfc_refs / dlp_refs that doesn't resolve in its catalog
 *   - RFC catalog reverse-references that drift from manifest forward-refs
 *   - skill-update-loop "Affected skills" blocks referencing nonexistent skills
 *   - stale references to renamed skills in any tracked file
 *   - trigger collisions between skills (informational)
 *   - README badge count drift
 *
 * Exit non-zero on any finding (excluding trigger collisions which are informational).
 *
 * Usage: node scripts/audit-cross-skill.js
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);

const issues = [];
const note = (s) => issues.push(s);

const manifest = JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"));
const skills = manifest.skills;
const skillNames = new Set(skills.map((s) => s.name));

// 1. Manifest paths exist
for (const s of skills) {
  if (!fs.existsSync(ABS(s.path))) {
    note(`MANIFEST PATH MISSING: ${s.name} → ${s.path}`);
  }
}

// 2. Disk skill dirs have manifest entries
const skillDirs = fs
  .readdirSync(ABS("skills"))
  .filter((d) => fs.existsSync(ABS(`skills/${d}/skill.md`)));
for (const d of skillDirs) {
  if (!skillNames.has(d)) note(`ORPHAN SKILL FILE: skills/${d}/skill.md has no manifest entry`);
}

// 3. Frontmatter name == manifest name
for (const s of skills) {
  const c = fs.readFileSync(ABS(s.path), "utf8");
  const m = c.match(/^name:\s*(\S+)/m);
  if (m && m[1] !== s.name) {
    note(`NAME DRIFT: manifest "${s.name}" vs frontmatter "${m[1]}" in ${s.path}`);
  }
}

// 4. Researcher dispatch covers every non-researcher skill
const researcher = fs.readFileSync(ABS("skills/researcher/skill.md"), "utf8");
const missingDispatch = [];
for (const n of skillNames) {
  if (n === "researcher") continue;
  if (!researcher.includes("`" + n + "`")) missingDispatch.push(n);
}
if (missingDispatch.length) {
  note(`RESEARCHER DISPATCH GAPS: ${missingDispatch.join(", ")}`);
}

// 5. AGENTS.md Quick Skill Reference lists every skill
const agents = fs.readFileSync(ABS("AGENTS.md"), "utf8");
const missingAgents = [];
for (const n of skillNames) {
  if (!agents.includes("| " + n + " |") && !agents.includes("|" + n + "|")) {
    missingAgents.push(n);
  }
}
if (missingAgents.length) {
  note(`AGENTS.md QUICK REF GAPS: ${missingAgents.join(", ")}`);
}

// 6. Version triple agreement
const pkg = JSON.parse(fs.readFileSync(ABS("package.json"), "utf8"));
const cl = fs.readFileSync(ABS("CHANGELOG.md"), "utf8");
const clTop = cl.match(/^## (\d+\.\d+\.\d+)/m);
if (clTop && clTop[1] !== pkg.version) {
  note(`VERSION DRIFT: package.json ${pkg.version} vs CHANGELOG top ${clTop[1]}`);
}
if (manifest.version !== pkg.version) {
  note(`VERSION DRIFT: manifest.json ${manifest.version} vs package.json ${pkg.version}`);
}

// 7. Manifest snapshot matches manifest
const snap = JSON.parse(fs.readFileSync(ABS("manifest-snapshot.json"), "utf8"));
if (snap.skill_count !== skills.length) {
  note(`SNAPSHOT DRIFT: snapshot ${snap.skill_count} vs manifest ${skills.length}`);
}
const snapNames = new Set(snap.skills.map((s) => s.name));
for (const n of skillNames) if (!snapNames.has(n)) note(`SNAPSHOT MISSING: ${n}`);
for (const n of snapNames) if (!skillNames.has(n)) note(`SNAPSHOT STALE: snapshot has "${n}" not in manifest`);

// 8. SBOM counts
const sbom = JSON.parse(fs.readFileSync(ABS("sbom.cdx.json"), "utf8"));
const sbomProps = Object.fromEntries(
  (sbom.metadata.properties || []).map((p) => [p.name, p.value])
);
const sbomSkills = Number(sbomProps["exceptd:skill:count"]);
if (sbomSkills !== skills.length) {
  note(`SBOM SKILL COUNT DRIFT: sbom ${sbomSkills} vs live ${skills.length}`);
}
const liveCatalogs = fs.readdirSync(ABS("data")).filter((f) => f.endsWith(".json")).length;
const sbomCatalogs = Number(sbomProps["exceptd:catalog:count"]);
if (sbomCatalogs !== liveCatalogs) {
  note(`SBOM CATALOG COUNT DRIFT: sbom ${sbomCatalogs} vs live ${liveCatalogs}`);
}

// 9. Catalog ref resolution
function catKeys(p) {
  return new Set(
    Object.keys(JSON.parse(fs.readFileSync(ABS(p), "utf8"))).filter(
      (k) => !k.startsWith("_")
    )
  );
}
const cweK = catKeys("data/cwe-catalog.json");
const d3K = catKeys("data/d3fend-catalog.json");
const fwK = catKeys("data/framework-control-gaps.json");
const atlasK = catKeys("data/atlas-ttps.json");
const rfcK = catKeys("data/rfc-references.json");
const dlpK = catKeys("data/dlp-controls.json");
for (const s of skills) {
  for (const r of s.cwe_refs || []) if (!cweK.has(r)) note(`BAD CWE_REF: ${s.name} cites "${r}" not in cwe-catalog`);
  for (const r of s.d3fend_refs || []) if (!d3K.has(r)) note(`BAD D3FEND_REF: ${s.name} cites "${r}" not in d3fend-catalog`);
  for (const r of s.framework_gaps || []) if (!fwK.has(r)) note(`BAD FRAMEWORK_GAP: ${s.name} cites "${r}" not in framework-control-gaps`);
  for (const r of s.atlas_refs || []) if (!atlasK.has(r)) note(`BAD ATLAS_REF: ${s.name} cites "${r}" not in atlas-ttps`);
  for (const r of s.rfc_refs || []) if (!rfcK.has(r)) note(`BAD RFC_REF: ${s.name} cites "${r}" not in rfc-references`);
  for (const r of s.dlp_refs || []) if (!dlpK.has(r)) note(`BAD DLP_REF: ${s.name} cites "${r}" not in dlp-controls`);
}

// 10. RFC catalog reverse-refs symmetric with manifest forward-refs
const rfcs = JSON.parse(fs.readFileSync(ABS("data/rfc-references.json"), "utf8"));
const forwardRfc = {};
for (const s of skills) {
  for (const r of s.rfc_refs || []) (forwardRfc[r] = forwardRfc[r] || []).push(s.name);
}
for (const [rfcId, names] of Object.entries(forwardRfc)) {
  const rev = new Set(rfcs[rfcId]?.skills_referencing || []);
  for (const n of names) {
    if (!rev.has(n)) note(`RFC REVERSE-REF MISSING: ${rfcId}.skills_referencing should include "${n}"`);
  }
}
for (const rfcId of Object.keys(rfcs).filter((k) => !k.startsWith("_"))) {
  for (const n of rfcs[rfcId].skills_referencing || []) {
    if (!skillNames.has(n)) {
      note(`RFC STALE REVERSE-REF: ${rfcId} lists "${n}" not in manifest`);
    } else {
      const s = skills.find((x) => x.name === n);
      if (!(s.rfc_refs || []).includes(rfcId)) {
        note(`RFC ASYMMETRIC: ${rfcId}.skills_referencing has "${n}" but skill rfc_refs doesn't include ${rfcId}`);
      }
    }
  }
}

// 11. skill-update-loop Affected-skills blocks reference real skill names
const sul = fs.readFileSync(ABS("skills/skill-update-loop/skill.md"), "utf8");
const sulBlocks = [...sul.matchAll(/\*\*Affected skills.*?\*\*\s*([^\n]+)/g)];
for (const m of sulBlocks) {
  const tokens = m[1].split(/[,;]/).map((s) => s.trim().replace(/[.()`*]/g, ""));
  for (const tok of tokens) {
    const first = tok.split(/\s/)[0];
    if (!first) continue;
    if (!/^[a-z][a-z0-9-]+$/.test(first)) continue;
    if (skillNames.has(first)) continue;
    if (["other", "any", "none", "skill", "existing", "and", "or", "the", "a", "an"].includes(first)) continue;
    note(`SKILL-UPDATE-LOOP unknown affected-skill ref: "${first}"`);
  }
}

// 12. Stale renamed-skill references
const staleTokens = ["age-gates-minor-safeguarding", "minor-safeguarding"];
const trackedDocs = [
  "AGENTS.md", "CHANGELOG.md", "README.md",
  "CONTEXT.md", "ARCHITECTURE.md", "MAINTAINERS.md",
  "manifest.json", "manifest-snapshot.json",
];
for (const f of trackedDocs) {
  if (!fs.existsSync(ABS(f))) continue;
  const body = fs.readFileSync(ABS(f), "utf8");
  for (const tok of staleTokens) {
    if (body.includes(tok)) {
      // CHANGELOG legitimately records the rename in the 0.5.4 entry.
      if (f === "CHANGELOG.md") continue;
      note(`STALE RENAME REF in ${f}: contains "${tok}"`);
    }
  }
}
for (const s of skills) {
  const body = fs.readFileSync(ABS(s.path), "utf8");
  for (const tok of staleTokens) {
    if (body.includes(tok)) note(`STALE RENAME REF in ${s.path}: contains "${tok}"`);
  }
}

// 13. Trigger collisions (informational; not necessarily bugs)
const triggerOwners = {};
for (const s of skills) {
  for (const t of s.triggers || []) {
    const k = String(t).toLowerCase().trim();
    (triggerOwners[k] = triggerOwners[k] || []).push(s.name);
  }
}
const collisions = Object.entries(triggerOwners).filter(([, v]) => v.length > 1);

// 14. README badges
const readme = fs.readFileSync(ABS("README.md"), "utf8");
const badgeMatch = readme.match(/skills-(\d+)-/);
if (badgeMatch && Number(badgeMatch[1]) !== skills.length) {
  note(`README BADGE DRIFT: shows skills-${badgeMatch[1]}- but manifest has ${skills.length}`);
}
const jurBadge = readme.match(/jurisdictions-(\d+)-/);
const liveJurs = (() => {
  const g = JSON.parse(fs.readFileSync(ABS("data/global-frameworks.json"), "utf8"));
  return Object.keys(g).filter((k) => !k.startsWith("_") && k !== "GLOBAL").length;
})();
if (jurBadge && Number(jurBadge[1]) !== liveJurs) {
  note(`README BADGE DRIFT: shows jurisdictions-${jurBadge[1]}- but live count is ${liveJurs}`);
}

// 15. Researcher count claim
const cntClaim = researcher.match(/(\d+)\s+specialized skills downstream/);
if (cntClaim) {
  const claimed = Number(cntClaim[1]);
  const actual = skills.length - 1; // minus researcher itself
  if (claimed !== actual) {
    note(`RESEARCHER COUNT CLAIM: says ${claimed} downstream but actual is ${actual}`);
  }
}

// Output
console.log("\n=== CROSS-SKILL AUDIT ===");
console.log(`Skills: ${skills.length}`);
console.log(`Catalogs: ${liveCatalogs}`);
console.log(`Trigger collisions: ${collisions.length} (informational)`);
for (const [t, owners] of collisions) {
  console.log(`  "${t}" → ${owners.join(", ")}`);
}
console.log(`\n=== ISSUES (${issues.length}) ===`);
if (issues.length === 0) {
  console.log("zero issues");
} else {
  for (const i of issues) console.log("  • " + i);
}
process.exit(issues.length === 0 ? 0 : 1);
