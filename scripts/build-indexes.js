"use strict";
/**
 * scripts/build-indexes.js
 *
 * Produces pre-computed indexes under `data/_indexes/` so AI consumers
 * and downstream tooling don't have to scan all 38 skills + 10 catalogs
 * to answer routine cross-reference questions.
 *
 *   data/_indexes/xref.json          — for each catalog entry, the list
 *                                       of skills that cite it. Inverted
 *                                       index over cwe_refs, d3fend_refs,
 *                                       framework_gaps, atlas_refs,
 *                                       attack_refs, rfc_refs, dlp_refs.
 *
 *   data/_indexes/trigger-table.json — flat trigger string → [skills].
 *                                       Replaces the linear scan the
 *                                       dispatcher currently performs.
 *
 *   data/_indexes/chains.json        — pre-computed cross-walks. For each
 *                                       CVE: CWE → ATT&CK → ATLAS →
 *                                       framework_gaps → D3FEND chain via
 *                                       the skills that reference it.
 *
 *   data/_indexes/jurisdiction-map.json — jurisdiction code → list of
 *                                         skills that mention it in body
 *                                         + body excerpt (1 line).
 *
 *   data/_indexes/handoff-dag.json   — skill → set of skills it mentions
 *                                       in body (out-edges of the
 *                                       cross-skill DAG audit-cross-
 *                                       skill.js already computes).
 *
 *   data/_indexes/_meta.json         — SHA-256 of every source file
 *                                       (manifest.json + every catalog +
 *                                       every skill body) at generation
 *                                       time. Predeploy gate compares to
 *                                       detect staleness.
 *
 * The indexes are derived data — never edit them by hand. Re-run this
 * script after any catalog / manifest / skill body change. The
 * `npm run build-indexes` script is the canonical invocation.
 *
 * The `_meta.json` source-hash check is what the predeploy gate uses:
 * if a source file changed after the indexes were last built, the gate
 * fails and the developer must re-run this script.
 *
 * Index file naming convention: leading underscore marks them as derived
 * (mirroring the `_meta` convention in catalog files), so anyone scanning
 * `data/` for "primary data" filters them out.
 *
 * Node 24 stdlib only — zero npm deps.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const IDX = ABS("data/_indexes");

if (!fs.existsSync(IDX)) fs.mkdirSync(IDX, { recursive: true });

const manifest = JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"));
const skills = manifest.skills;
const skillNames = new Set(skills.map((s) => s.name));

// Source hash helper for the staleness check.
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// --- xref.json: inverted index ------------------------------------------
const xref = {
  cwe_refs: {},
  d3fend_refs: {},
  framework_gaps: {},
  atlas_refs: {},
  attack_refs: {},
  rfc_refs: {},
  dlp_refs: {},
};
for (const s of skills) {
  for (const field of Object.keys(xref)) {
    for (const v of s[field] || []) {
      (xref[field][v] = xref[field][v] || []).push(s.name);
    }
  }
}
// Sort the skill arrays for stable output.
for (const field of Object.keys(xref)) {
  for (const k of Object.keys(xref[field])) xref[field][k].sort();
}
const xrefStats = {};
for (const field of Object.keys(xref)) xrefStats[field] = Object.keys(xref[field]).length;

// --- trigger-table.json: flat dispatch index ----------------------------
const triggerTable = {};
for (const s of skills) {
  for (const t of s.triggers || []) {
    const k = String(t).toLowerCase().trim();
    (triggerTable[k] = triggerTable[k] || []).push(s.name);
  }
}
for (const k of Object.keys(triggerTable)) triggerTable[k].sort();

// --- chains.json: pre-computed cross-walks ------------------------------
// For each CVE in the catalog, walk through the skills that reference it
// (directly or via evidence_cves on a framework_gap) and gather every
// catalog dimension. This gives an AI consumer a single-file picture of
// "what does the project know about this CVE?"
const cveCatalog = JSON.parse(fs.readFileSync(ABS("data/cve-catalog.json"), "utf8"));
const frameworkGaps = JSON.parse(fs.readFileSync(ABS("data/framework-control-gaps.json"), "utf8"));
const atlasTtps = JSON.parse(fs.readFileSync(ABS("data/atlas-ttps.json"), "utf8"));
const cweCatalog = JSON.parse(fs.readFileSync(ABS("data/cwe-catalog.json"), "utf8"));
const d3Catalog = JSON.parse(fs.readFileSync(ABS("data/d3fend-catalog.json"), "utf8"));

const chains = {};
for (const cveId of Object.keys(cveCatalog).filter((k) => !k.startsWith("_"))) {
  const cve = cveCatalog[cveId];
  const referencingSkills = skills
    .filter((s) => {
      for (const fg of s.framework_gaps || []) {
        const evd = (frameworkGaps[fg] || {}).evidence_cves || [];
        if (evd.includes(cveId)) return true;
      }
      return false;
    })
    .map((s) => s.name);

  // Union of every catalog dimension that those skills cite.
  const accum = {
    cwe_refs: new Set(), atlas_refs: new Set(), attack_refs: new Set(),
    framework_gaps: new Set(), d3fend_refs: new Set(), rfc_refs: new Set(),
  };
  for (const name of referencingSkills) {
    const s = skills.find((x) => x.name === name);
    for (const field of Object.keys(accum)) {
      for (const v of s[field] || []) accum[field].add(v);
    }
  }

  // Hydrate referenced entries with their own catalog data for the AI consumer.
  const hydrated = {
    cwes: [...accum.cwe_refs].map((c) => ({
      id: c,
      name: cweCatalog[c]?.name,
      category: cweCatalog[c]?.category,
    })),
    atlas: [...accum.atlas_refs].map((a) => ({
      id: a,
      name: atlasTtps[a]?.name,
      tactic: atlasTtps[a]?.tactic,
    })),
    d3fend: [...accum.d3fend_refs].map((d) => ({
      id: d,
      name: d3Catalog[d]?.name,
      tactic: d3Catalog[d]?.tactic,
    })),
    framework_gaps: [...accum.framework_gaps].map((f) => ({
      id: f,
      framework: frameworkGaps[f]?.framework,
      control_name: frameworkGaps[f]?.control_name,
    })),
    attack_refs: [...accum.attack_refs].sort(),
    rfc_refs: [...accum.rfc_refs].sort(),
  };

  chains[cveId] = {
    name: cve.name,
    rwep: cve.rwep_score,
    cvss: cve.cvss_score,
    cisa_kev: cve.cisa_kev,
    epss_score: cve.epss_score,
    epss_percentile: cve.epss_percentile,
    referencing_skills: referencingSkills,
    chain: hydrated,
  };
}

// --- jurisdiction-map.json ----------------------------------------------
const globalFrameworks = JSON.parse(fs.readFileSync(ABS("data/global-frameworks.json"), "utf8"));
const jurisdictionCodes = Object.keys(globalFrameworks).filter(
  (k) => !k.startsWith("_") && k !== "GLOBAL"
);
const jurisdictionPatterns = jurisdictionCodes.map((c) => {
  // Build a match pattern: jurisdiction code OR primary name.
  // The keys are like "EU", "UK", "AU", "JP", "IL", "CH", "HK", "TW",
  // "ID", "VN", "BR", "CN", "ZA", "AE", "SA", "NZ", "KR", "CL", "SG",
  // "IN", "CA", "US_NYDFS", "US_CALIFORNIA", "EU_DE_BSI",
  // "EU_FR_ANSSI", "EU_ES_AEPD", "EU_IT_AgID_ACN", "EU_ENISA",
  // "NO", "MX", "AR", "TR", "TH", "PH".
  return c;
});
const jurisdictionMap = {};
for (const code of jurisdictionCodes) {
  jurisdictionMap[code] = { skills: [], example_excerpts: {} };
}
// Naive scan: read each skill body once and look for jurisdiction code
// OR a few high-signal regulator names.
const NAME_TO_CODE = {
  "GDPR": "EU", "NIS2": "EU", "DORA": "EU", "EU AI Act": "EU", "ENISA": "EU",
  "NCSC": "UK", "Children's Code": "UK", "Online Safety Act": "UK",
  "ISM": "AU", "Essential 8": "AU", "APRA": "AU", "eSafety": "AU",
  "MAS TRM": "SG", "CSA Singapore": "SG",
  "APPI": "JP", "FISC": "JP", "NISC": "JP",
  "DPDPA": "IN", "CERT-In": "IN", "SEBI": "IN",
  "OSFI": "CA", "Quebec Law 25": "CA", "PIPEDA": "CA",
  "LGPD": "BR", "ANPD": "BR",
  "PIPL": "CN", "CAC": "CN", "DSL": "CN", "CSL": "CN",
  "POPIA": "ZA",
  "UAE PDPL": "AE",
  "KSA PDPL": "SA", "SAMA": "SA",
  "Privacy Act 2020": "NZ",
  "PIPA": "KR",
  "INCD": "IL", "BoI Directive 361": "IL",
  "FADP": "CH", "FINMA": "CH",
  "PDPO": "HK", "HKMA": "HK",
  "CSMA": "TW",
  "UU PDP": "ID", "BSSN": "ID",
  "Vietnam Cybersecurity Law": "VN",
  "NYDFS": "US_NYDFS", "23 NYCRR 500": "US_NYDFS",
  "CCPA": "US_CALIFORNIA", "CPRA": "US_CALIFORNIA", "CPPA": "US_CALIFORNIA",
  "BSI": "EU_DE_BSI", "IT-Grundschutz": "EU_DE_BSI",
  "ANSSI": "EU_FR_ANSSI",
  "AEPD": "EU_ES_AEPD",
  "AgID": "EU_IT_AgID_ACN", "ACN": "EU_IT_AgID_ACN",
  "NSM": "NO",
  "LFPDPPP": "MX", "INAI": "MX",
  "AAIP": "AR",
  "KVKK": "TR",
  "PDPA Thailand": "TH",
  "DPA Philippines": "PH",
};
for (const s of skills) {
  const body = fs.readFileSync(ABS(s.path), "utf8");
  for (const code of jurisdictionCodes) {
    // Match the code with word boundaries, or "US_*" with the underscore.
    const codeRe = code.includes("_")
      ? new RegExp("\\b" + code + "\\b")
      : new RegExp("\\b" + code + "\\b");
    if (codeRe.test(body)) {
      if (!jurisdictionMap[code].skills.includes(s.name)) {
        jurisdictionMap[code].skills.push(s.name);
      }
    }
  }
  // Also check the regulator names.
  for (const [name, code] of Object.entries(NAME_TO_CODE)) {
    if (body.includes(name)) {
      if (!jurisdictionMap[code].skills.includes(s.name)) {
        jurisdictionMap[code].skills.push(s.name);
      }
    }
  }
}
for (const code of jurisdictionCodes) {
  jurisdictionMap[code].skills.sort();
  jurisdictionMap[code].skill_count = jurisdictionMap[code].skills.length;
}

// --- handoff-dag.json ---------------------------------------------------
const handoffDag = { nodes: [], edges: {} };
for (const s of skills) handoffDag.edges[s.name] = [];
for (const s of skills) {
  const body = fs.readFileSync(ABS(s.path), "utf8");
  for (const other of skillNames) {
    if (other === s.name) continue;
    if (body.includes("`" + other + "`")) handoffDag.edges[s.name].push(other);
  }
  handoffDag.edges[s.name].sort();
}
handoffDag.nodes = [...skillNames].sort();
// Compute in-degree / out-degree for diagnostics.
const inDeg = {}, outDeg = {};
for (const n of handoffDag.nodes) { inDeg[n] = 0; outDeg[n] = 0; }
for (const [from, tos] of Object.entries(handoffDag.edges)) {
  outDeg[from] = tos.length;
  for (const to of tos) inDeg[to] = (inDeg[to] || 0) + 1;
}
handoffDag.in_degree = inDeg;
handoffDag.out_degree = outDeg;

// --- _meta.json: source hashes ------------------------------------------
const sourceFiles = [
  "manifest.json",
  ...catalogList(),
  ...skills.map((s) => s.path),
];
function catalogList() {
  return fs.readdirSync(ABS("data")).filter((f) => f.endsWith(".json")).map((f) => "data/" + f);
}
const sourceHashes = {};
for (const p of sourceFiles) {
  sourceHashes[p] = sha256(fs.readFileSync(ABS(p)));
}

const meta = {
  schema_version: "1.0.0",
  generated_at: new Date().toISOString(),
  generator: "scripts/build-indexes.js",
  source_count: sourceFiles.length,
  source_hashes: sourceHashes,
  skill_count: skills.length,
  catalog_count: catalogList().length,
  index_stats: {
    xref_entries: xrefStats,
    trigger_table_entries: Object.keys(triggerTable).length,
    chains_entries: Object.keys(chains).length,
    jurisdictions_indexed: jurisdictionCodes.length,
    handoff_dag_nodes: handoffDag.nodes.length,
  },
  invalidation_note: "If any source file in source_hashes has a different SHA-256 than recorded here, the indexes are stale. Re-run `npm run build-indexes`.",
};

// --- write ---
function writeJson(name, obj) {
  const out = "// Auto-generated by scripts/build-indexes.js — do not hand-edit. Re-run `npm run build-indexes` after any source change.\n" +
              JSON.stringify(obj, null, 2) + "\n";
  // Strip the JS-style comment for valid JSON.
  fs.writeFileSync(path.join(IDX, name), JSON.stringify(obj, null, 2) + "\n", "utf8");
}
writeJson("xref.json", xref);
writeJson("trigger-table.json", triggerTable);
writeJson("chains.json", chains);
writeJson("jurisdiction-map.json", jurisdictionMap);
writeJson("handoff-dag.json", handoffDag);
writeJson("_meta.json", meta);

console.log(`[build-indexes] wrote 6 files to data/_indexes/`);
console.log(`  xref.json — inverted index over ${Object.values(xrefStats).reduce((a, b) => a + b, 0)} catalog entries across 7 fields`);
console.log(`  trigger-table.json — ${Object.keys(triggerTable).length} unique triggers`);
console.log(`  chains.json — ${Object.keys(chains).length} CVE chains`);
console.log(`  jurisdiction-map.json — ${jurisdictionCodes.length} jurisdictions indexed`);
console.log(`  handoff-dag.json — ${handoffDag.nodes.length} nodes, ${Object.values(handoffDag.edges).reduce((a, b) => a + b.length, 0)} edges`);
console.log(`  _meta.json — ${Object.keys(sourceHashes).length} source-file hashes for staleness detection`);
