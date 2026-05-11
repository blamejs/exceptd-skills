"use strict";
/**
 * scripts/build-indexes.js
 *
 * Produces pre-computed indexes under `data/_indexes/` so AI consumers
 * and downstream tooling don't have to scan all 38 skills + 10 catalogs
 * to answer routine cross-reference questions.
 *
 * Tier 1 indexes (introduced v0.6.0):
 *   xref.json              — inverted index over cwe / d3fend / framework_gap /
 *                            atlas / attack / rfc / dlp citations.
 *   trigger-table.json     — flat trigger → [skills].
 *   chains.json            — pre-computed cross-walks per CVE and (v0.7.0) per CWE.
 *   jurisdiction-map.json  — jurisdiction → skills that reference it.
 *   handoff-dag.json       — skill → skills it references in body (cross-skill DAG).
 *   _meta.json             — SHA-256 of every source file for staleness detection.
 *
 * Tier 1 additions (v0.7.0 — AI-consumer ergonomics):
 *   summary-cards.json     — per-skill 100-word abstract for researcher dispatch.
 *   section-offsets.json   — per-skill byte/line offsets of every H2 section.
 *   token-budget.json      — approximate token cost per skill + per section.
 *
 * Tier 2 additions (v0.7.0 — operational dispatch):
 *   recipes.json           — curated multi-skill recipes for common use cases.
 *   jurisdiction-clocks.json — normalized jurisdiction × obligation × hours matrix.
 *   did-ladders.json       — canonical defense-in-depth ladders per attack class.
 *   theater-fingerprints.json — structured compliance-theater pattern records.
 *
 * Tier 3 additions (v0.7.0 — diagnostic / maintenance):
 *   currency.json          — pre-computed skill currency snapshot.
 *   frequency.json         — citation-count tables per catalog field.
 *   activity-feed.json     — "what changed when" feed across skills + catalogs.
 *   catalog-summaries.json — compact per-catalog summary cards.
 *
 * Tier 4 additions (v0.7.0 — accuracy artifact):
 *   stale-content.json     — persisted snapshot of stale-content findings.
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

// --- Catalog loads (shared across multiple builders) --------------------
const cveCatalog = JSON.parse(fs.readFileSync(ABS("data/cve-catalog.json"), "utf8"));
const frameworkGaps = JSON.parse(fs.readFileSync(ABS("data/framework-control-gaps.json"), "utf8"));
const atlasTtps = JSON.parse(fs.readFileSync(ABS("data/atlas-ttps.json"), "utf8"));
const cweCatalog = JSON.parse(fs.readFileSync(ABS("data/cwe-catalog.json"), "utf8"));
const d3Catalog = JSON.parse(fs.readFileSync(ABS("data/d3fend-catalog.json"), "utf8"));
const rfcCatalog = JSON.parse(fs.readFileSync(ABS("data/rfc-references.json"), "utf8"));
const dlpCatalog = JSON.parse(fs.readFileSync(ABS("data/dlp-controls.json"), "utf8"));
const globalFrameworks = JSON.parse(fs.readFileSync(ABS("data/global-frameworks.json"), "utf8"));

function catalogList() {
  return fs.readdirSync(ABS("data")).filter((f) => f.endsWith(".json")).map((f) => "data/" + f);
}

// --- chains.json: pre-computed cross-walks (CVE-keyed) ------------------
const chains = {
  _meta: {
    schema_version: "1.1.0",
    note: "Pre-computed cross-walks keyed by CVE-id and (v0.7.0+) CWE-id. CVE chains hydrate: skills citing the CVE via framework gaps, plus union of catalog dimensions. CWE chains hydrate: skills citing the CWE directly, plus related CVEs via skill graph traversal.",
    entry_types: ["CVE", "CWE"],
  },
};

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

  const hydrated = {
    cwes: [...accum.cwe_refs].sort().map((c) => ({
      id: c,
      name: cweCatalog[c]?.name,
      category: cweCatalog[c]?.category,
    })),
    atlas: [...accum.atlas_refs].sort().map((a) => ({
      id: a,
      name: atlasTtps[a]?.name,
      tactic: atlasTtps[a]?.tactic,
    })),
    d3fend: [...accum.d3fend_refs].sort().map((d) => ({
      id: d,
      name: d3Catalog[d]?.name,
      tactic: d3Catalog[d]?.tactic,
    })),
    framework_gaps: [...accum.framework_gaps].sort().map((f) => ({
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

// CWE chains (v0.7.0 addition)
const { buildCweChains } = require("./builders/cwe-chains");
const cweChains = buildCweChains({
  skills,
  cweCatalog,
  atlasTtps,
  cveCatalog,
  frameworkGaps,
  d3fendCatalog: d3Catalog,
  rfcCatalog,
});
for (const [k, v] of Object.entries(cweChains)) chains[k] = v;

// --- jurisdiction-map.json ----------------------------------------------
const jurisdictionCodes = Object.keys(globalFrameworks).filter(
  (k) => !k.startsWith("_") && k !== "GLOBAL"
);
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
const jurisdictionMap = {};
for (const code of jurisdictionCodes) {
  jurisdictionMap[code] = { skills: [], example_excerpts: {} };
}
for (const s of skills) {
  const body = fs.readFileSync(ABS(s.path), "utf8");
  for (const code of jurisdictionCodes) {
    const codeRe = new RegExp("\\b" + code + "\\b");
    if (codeRe.test(body)) {
      if (!jurisdictionMap[code].skills.includes(s.name)) {
        jurisdictionMap[code].skills.push(s.name);
      }
    }
  }
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
const inDeg = {}, outDeg = {};
for (const n of handoffDag.nodes) { inDeg[n] = 0; outDeg[n] = 0; }
for (const [from, tos] of Object.entries(handoffDag.edges)) {
  outDeg[from] = tos.length;
  for (const to of tos) inDeg[to] = (inDeg[to] || 0) + 1;
}
handoffDag.in_degree = inDeg;
handoffDag.out_degree = outDeg;

// --- v0.7.0 tier 1: summary-cards, section-offsets, token-budget --------
const { buildSummaryCards } = require("./builders/summary-cards");
const { buildSectionOffsets } = require("./builders/section-offsets");
const { buildTokenBudget } = require("./builders/token-budget");

const summaryCards = buildSummaryCards({ root: ROOT, manifest, skills });
const sectionOffsets = buildSectionOffsets({ root: ROOT, skills });
const tokenBudget = buildTokenBudget({ root: ROOT, skills, sectionOffsets });

// --- v0.7.0 tier 2: recipes, jurisdiction-clocks, did-ladders, theater --
const { buildRecipes } = require("./builders/recipes");
const { buildJurisdictionClocks } = require("./builders/jurisdiction-clocks");
const { buildDidLadders } = require("./builders/did-ladders");
const { buildTheaterFingerprints } = require("./builders/theater-fingerprints");

const recipes = buildRecipes({ skills });
const jurisdictionClocks = buildJurisdictionClocks({ globalFrameworks });
const didLadders = buildDidLadders({ skills, d3fendCatalog: d3Catalog });
const theaterFingerprints = buildTheaterFingerprints({ root: ROOT });

// --- v0.7.0 tier 3: currency, frequency, activity-feed, catalog-summaries
const { buildCurrency } = require("./builders/currency");
const { buildFrequency } = require("./builders/frequency");
const { buildActivityFeed } = require("./builders/activity-feed");
const { buildCatalogSummaries } = require("./builders/catalog-summaries");

const currency = buildCurrency({ root: ROOT, manifest, skills });
const frequency = buildFrequency({
  skills,
  catalogs: {
    cwe: cweCatalog,
    atlas: atlasTtps,
    d3fend: d3Catalog,
    frameworkGaps,
    rfc: rfcCatalog,
    dlp: dlpCatalog,
  },
});
const catalogFiles = catalogList();
const activityFeed = buildActivityFeed({ root: ROOT, manifest, skills, catalogFiles });
const catalogSummaries = buildCatalogSummaries({ root: ROOT, catalogFiles });

// --- v0.7.0 tier 4: stale-content snapshot ------------------------------
const { buildStaleContent } = require("./builders/stale-content");
const staleContent = buildStaleContent({ root: ROOT, manifest, skills, catalogFiles });

// --- write helpers ------------------------------------------------------
function writeJson(name, obj) {
  fs.writeFileSync(path.join(IDX, name), JSON.stringify(obj, null, 2) + "\n", "utf8");
}

writeJson("xref.json", xref);
writeJson("trigger-table.json", triggerTable);
writeJson("chains.json", chains);
writeJson("jurisdiction-map.json", jurisdictionMap);
writeJson("handoff-dag.json", handoffDag);
writeJson("summary-cards.json", summaryCards);
writeJson("section-offsets.json", sectionOffsets);
writeJson("token-budget.json", tokenBudget);
writeJson("recipes.json", recipes);
writeJson("jurisdiction-clocks.json", jurisdictionClocks);
writeJson("did-ladders.json", didLadders);
writeJson("theater-fingerprints.json", theaterFingerprints);
writeJson("currency.json", currency);
writeJson("frequency.json", frequency);
writeJson("activity-feed.json", activityFeed);
writeJson("catalog-summaries.json", catalogSummaries);
writeJson("stale-content.json", staleContent);

// --- _meta.json: source hashes (last, after all outputs persisted) ------
const sourceFiles = [
  "manifest.json",
  ...catalogList(),
  ...skills.map((s) => s.path),
];
const sourceHashes = {};
for (const p of sourceFiles) {
  sourceHashes[p] = sha256(fs.readFileSync(ABS(p)));
}

const cveChainCount = Object.keys(chains).filter((k) => k.startsWith("CVE-")).length;
const cweChainCount = Object.keys(chains).filter((k) => k.startsWith("CWE-")).length;

const meta = {
  schema_version: "1.1.0",
  generated_at: new Date().toISOString(),
  generator: "scripts/build-indexes.js",
  source_count: sourceFiles.length,
  source_hashes: sourceHashes,
  skill_count: skills.length,
  catalog_count: catalogFiles.length,
  index_stats: {
    xref_entries: xrefStats,
    trigger_table_entries: Object.keys(triggerTable).length,
    chains_cve_entries: cveChainCount,
    chains_cwe_entries: cweChainCount,
    jurisdictions_indexed: jurisdictionCodes.length,
    handoff_dag_nodes: handoffDag.nodes.length,
    summary_cards: Object.keys(summaryCards.skills).length,
    section_offsets_skills: Object.keys(sectionOffsets.skills).length,
    token_budget_total_approx: tokenBudget._meta.total_approx_tokens,
    recipes: recipes.recipes.length,
    jurisdiction_clocks: Object.keys(jurisdictionClocks.by_jurisdiction).length,
    did_ladders: didLadders.ladders.length,
    theater_fingerprints: Object.keys(theaterFingerprints.patterns).length,
    currency_action_required: currency.summary.action_required,
    frequency_fields: Object.keys(frequency.counts).length,
    activity_feed_events: activityFeed.events.length,
    catalog_summaries: Object.keys(catalogSummaries.catalogs).length,
    stale_content_findings: staleContent._meta.finding_count,
  },
  invalidation_note: "If any source file in source_hashes has a different SHA-256 than recorded here, the indexes are stale. Re-run `npm run build-indexes`.",
};
writeJson("_meta.json", meta);

// --- summary -----------------------------------------------------------
console.log(`[build-indexes] wrote 17 files to data/_indexes/`);
console.log(`  xref.json — inverted index over ${Object.values(xrefStats).reduce((a, b) => a + b, 0)} catalog entries across 7 fields`);
console.log(`  trigger-table.json — ${Object.keys(triggerTable).length} unique triggers`);
console.log(`  chains.json — ${cveChainCount} CVE + ${cweChainCount} CWE chains`);
console.log(`  jurisdiction-map.json — ${jurisdictionCodes.length} jurisdictions indexed`);
console.log(`  handoff-dag.json — ${handoffDag.nodes.length} nodes, ${Object.values(handoffDag.edges).reduce((a, b) => a + b.length, 0)} edges`);
console.log(`  summary-cards.json — ${Object.keys(summaryCards.skills).length} per-skill abstracts`);
console.log(`  section-offsets.json — ${Object.keys(sectionOffsets.skills).length} skills with H2 offsets`);
console.log(`  token-budget.json — ${tokenBudget._meta.total_approx_tokens.toLocaleString()} approx tokens across all skills`);
console.log(`  recipes.json — ${recipes.recipes.length} curated skill sequences`);
console.log(`  jurisdiction-clocks.json — ${Object.keys(jurisdictionClocks.by_jurisdiction).length} jurisdictions with obligation timings`);
console.log(`  did-ladders.json — ${didLadders.ladders.length} attack-class ladders`);
console.log(`  theater-fingerprints.json — ${Object.keys(theaterFingerprints.patterns).length} compliance theater patterns`);
console.log(`  currency.json — ${currency.summary.action_required} skills need action`);
console.log(`  frequency.json — ${Object.keys(frequency.counts).length} citation-count tables`);
console.log(`  activity-feed.json — ${activityFeed.events.length} events`);
console.log(`  catalog-summaries.json — ${Object.keys(catalogSummaries.catalogs).length} catalog cards`);
console.log(`  stale-content.json — ${staleContent._meta.finding_count} findings (${staleContent._meta.by_severity.high} high, ${staleContent._meta.by_severity.medium} medium, ${staleContent._meta.by_severity.low} low)`);
console.log(`  _meta.json — ${Object.keys(sourceHashes).length} source-file hashes for staleness detection`);
