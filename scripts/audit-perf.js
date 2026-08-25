"use strict";
/**
 * scripts/audit-perf.js — micro-benchmarks the hot paths a skill, orchestrator
 * or audit exercises, to decide what is worth pre-computing into a seeded index.
 *
 * Usage: node scripts/audit-perf.js
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);

function bench(label, fn, iters = 1) {
  const start = process.hrtime.bigint();
  let result;
  for (let i = 0; i < iters; i++) result = fn();
  const ns = Number(process.hrtime.bigint() - start);
  const ms = (ns / 1e6 / iters).toFixed(3);
  console.log(`  ${ms.padStart(10)} ms  ${label}`);
  return result;
}

console.log("\n=== exceptd hot-path performance ===\n");
console.log("Operation                                            Time");
console.log("-".repeat(70));

const manifest = bench("load manifest.json (parse)", () =>
  JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"))
);
const skills = manifest.skills;

const catalogs = [
  "cve-catalog.json",
  "atlas-ttps.json",
  "framework-control-gaps.json",
  "global-frameworks.json",
  "cwe-catalog.json",
  "d3fend-catalog.json",
  "rfc-references.json",
  "dlp-controls.json",
  "zeroday-lessons.json",
  "exploit-availability.json",
];
const catalogObjs = bench(`load all ${catalogs.length} data catalogs`, () => {
  const out = {};
  for (const c of catalogs) out[c] = JSON.parse(fs.readFileSync(ABS("data/" + c), "utf8"));
  return out;
});

bench(`read all ${skills.length} skill.md bodies`, () => {
  for (const s of skills) fs.readFileSync(ABS(s.path), "utf8");
});

// The linter's expensive operation.
function parseFm(text) {
  if (!text.startsWith("---")) return null;
  const end = text.indexOf("\n---", 3);
  if (end < 0) return null;
  const fm = text.slice(3, end).replace(/^\r?\n/, "");
  const r = {};
  const lines = fm.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const L = lines[i];
    if (!L.trim() || L.trimStart().startsWith("#")) { i++; continue; }
    const m = L.match(/^([A-Za-z_]+):\s*(.*)$/);
    if (!m) { i++; continue; }
    const k = m[1], rest = m[2].trim();
    if (rest === "" || rest === undefined) {
      const items = []; i++;
      while (i < lines.length && /^\s+-\s+/.test(lines[i])) {
        items.push(lines[i].match(/^\s+-\s+(.*)$/)[1].trim()); i++;
      }
      r[k] = items; continue;
    }
    if (rest === "[]") { r[k] = []; i++; continue; }
    r[k] = rest; i++;
  }
  return r;
}
bench(`parse all ${skills.length} skill frontmatters`, () => {
  for (const s of skills) parseFm(fs.readFileSync(ABS(s.path), "utf8"));
});

// The lookup the dispatcher performs.
const flatTriggers = [];
for (const s of skills) for (const t of s.triggers || []) flatTriggers.push([t.toLowerCase(), s.name]);
bench("trigger string-match against all skills (single query)", () => {
  const q = "ai red team";
  return flatTriggers.filter(([t]) => t.includes(q) || q.includes(t));
});

bench("xref: which skills cite CWE-79? (linear scan)", () => {
  const refSet = "CWE-79";
  return skills.filter((s) => (s.cwe_refs || []).includes(refSet)).map((s) => s.name);
});

// CVE entry → its CWE refs → the skills citing any of them → their ATLAS refs
// and framework gaps. An unknown id resolves to no entry and yields empty sets,
// which is what makes this a measurement of the lookup rather than of the corpus.
function multiHopChain(catalog, allSkills, cveId) {
  const entry = catalog[cveId];
  if (!entry) return { cwes: [], atlases: [], fws: [], citing: [] };
  // The seed stays fixed while the skills are scanned: a skill qualifies by
  // citing one of the CVE's OWN weaknesses, never one another skill dragged in.
  const seed = new Set(entry.cwe_refs || []);
  const cwes = new Set(seed);
  const atlases = new Set(entry.atlas_refs || []);
  const fws = new Set(Object.keys(entry.framework_control_gaps || {}));
  const citing = [];
  for (const s of allSkills) {
    if (!(s.cwe_refs || []).some((c) => seed.has(c))) continue;
    citing.push(s.name);
    for (const c of s.cwe_refs || []) cwes.add(c);
    for (const a of s.atlas_refs || []) atlases.add(a);
    for (const f of s.framework_gaps || []) fws.add(f);
  }
  return { cwes: [...cwes], atlases: [...atlases], fws: [...fws], citing };
}
// Seeded from a CVE whose weaknesses several skills actually cite, so the row
// times a join that unions real skill refs instead of terminating at the seed.
const CHAIN_CVE_ID = "CVE-2026-46817";
bench(`multi-hop chain: ${CHAIN_CVE_ID} → CWE → ATLAS → frameworks`, () =>
  multiHopChain(catalogObjs["cve-catalog.json"], skills, CHAIN_CVE_ID)
);

bench(`watchlist aggregator (full scan, ${skills.length} skills)`, () => {
  const watch = new Set();
  for (const s of skills) {
    const fm = parseFm(fs.readFileSync(ABS(s.path), "utf8"));
    if (fm && Array.isArray(fm.forward_watch)) for (const w of fm.forward_watch) watch.add(w);
  }
  return watch.size;
});

bench("full cross-skill audit script (subprocess overhead included)", () => {
  // Simulated: load the manifest, catalogs and skill files, walk every refset.
  for (const s of skills) {
    fs.readFileSync(ABS(s.path), "utf8");
    for (const f of s.cwe_refs || []) { /* lookup */ }
    for (const f of s.d3fend_refs || []) { /* lookup */ }
    for (const f of s.framework_gaps || []) { /* lookup */ }
    for (const f of s.atlas_refs || []) { /* lookup */ }
    for (const f of s.rfc_refs || []) { /* lookup */ }
  }
});

console.log("");
console.log("=== Sizes ===");
const totalBytes = (paths) => paths.reduce((t, p) => t + fs.statSync(ABS(p)).size, 0);
console.log(`  manifest.json:                    ${fs.statSync(ABS("manifest.json")).size.toLocaleString()} bytes`);
console.log(`  manifest-snapshot.json:           ${fs.statSync(ABS("manifest-snapshot.json")).size.toLocaleString()} bytes`);
console.log(`  data/*.json (${catalogs.length} files):              ${totalBytes(catalogs.map(c => "data/" + c)).toLocaleString()} bytes`);
console.log(`  skills/*/skill.md (${skills.length} files):           ${totalBytes(skills.map(s => s.path)).toLocaleString()} bytes`);

console.log("\n=== Recommendation surfaces (manual review) ===");
console.log("  - Anything slower than 50 ms in the hot path = candidate for pre-computed index");
console.log("  - Anything called >1×/operation = candidate for cached + invalidated index");
console.log("  - JSON files >100 KB = candidate for streaming or partial load if hot-path indexed");
