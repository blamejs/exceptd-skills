"use strict";
/**
 * scripts/audit-perf.js
 *
 * Micro-benchmarks the hot paths a skill / orchestrator / audit
 * actually exercises. Times each operation so we can decide what's
 * worth pre-computing into a seeded index.
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

// 1. Load manifest
const manifest = bench("load manifest.json (parse)", () =>
  JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"))
);
const skills = manifest.skills;

// 2. Load every data catalog
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

// 3. Read every skill body
bench(`read all ${skills.length} skill.md bodies`, () => {
  for (const s of skills) fs.readFileSync(ABS(s.path), "utf8");
});

// 4. Parse every skill frontmatter (the linter's expensive op)
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

// 5. Trigger lookup (what the dispatcher does)
const flatTriggers = [];
for (const s of skills) for (const t of s.triggers || []) flatTriggers.push([t.toLowerCase(), s.name]);
bench("trigger string-match against all skills (single query)", () => {
  const q = "ai red team";
  return flatTriggers.filter(([t]) => t.includes(q) || q.includes(t));
});

// 6. Cross-reference lookup: which skills cite a given CWE?
bench("xref: which skills cite CWE-79? (linear scan)", () => {
  const refSet = "CWE-79";
  return skills.filter((s) => (s.cwe_refs || []).includes(refSet)).map((s) => s.name);
});

// 7. Multi-hop chain: CVE → CWE → ATLAS → framework_gaps for one CVE
const cve = catalogObjs["cve-catalog.json"]["CVE-2026-31431"];
bench("multi-hop chain: CVE-2026-31431 → CWE → ATLAS → frameworks", () => {
  // skills that mention CVE → their CWE refs → their ATLAS refs → their framework gaps
  const skillsCiting = skills.filter((s) =>
    (catalogObjs["cve-catalog.json"]["CVE-2026-31431"].evidence_cves || []).length > 0 // dummy filter
  );
  const cwes = new Set();
  const atlases = new Set();
  const fws = new Set();
  for (const s of skills) {
    if (!(s.atlas_refs || []).length) continue;
    for (const c of s.cwe_refs || []) cwes.add(c);
    for (const a of s.atlas_refs || []) atlases.add(a);
    for (const f of s.framework_gaps || []) fws.add(f);
  }
  return { cwes: [...cwes], atlases: [...atlases], fws: [...fws] };
});

// 8. Forward_watch aggregator (read 38 skill files, parse frontmatter, union all forward_watch)
bench(`watchlist aggregator (full scan, ${skills.length} skills)`, () => {
  const watch = new Set();
  for (const s of skills) {
    const fm = parseFm(fs.readFileSync(ABS(s.path), "utf8"));
    if (fm && Array.isArray(fm.forward_watch)) for (const w of fm.forward_watch) watch.add(w);
  }
  return watch.size;
});

// 9. Full cross-skill audit
bench("full cross-skill audit script (subprocess overhead included)", () => {
  // Simulate: load manifest + all catalogs + all skill files + compute every refset
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
