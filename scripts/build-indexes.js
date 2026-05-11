"use strict";
/**
 * scripts/build-indexes.js
 *
 * Produces pre-computed indexes under `data/_indexes/` so AI consumers
 * and downstream tooling don't have to scan all 38 skills + 10 catalogs
 * to answer routine cross-reference questions.
 *
 * Outputs (17 total):
 *   xref.json                — inverted index over cwe/d3fend/framework_gap/
 *                              atlas/attack/rfc/dlp citations
 *   trigger-table.json       — flat trigger → [skills]
 *   chains.json              — pre-computed cross-walks per CVE and per CWE
 *   jurisdiction-map.json    — jurisdiction → skills that reference it
 *   handoff-dag.json         — cross-skill mention graph
 *   summary-cards.json       — per-skill 100-word abstract
 *   section-offsets.json     — per-skill byte/line offsets of every H2
 *   token-budget.json        — approximate token cost per skill + section
 *   recipes.json             — curated multi-skill recipes
 *   jurisdiction-clocks.json — normalized obligation × hours matrix
 *   did-ladders.json         — canonical defense-in-depth ladders
 *   theater-fingerprints.json — structured compliance-theater pattern records
 *   currency.json            — pre-computed skill currency snapshot
 *   frequency.json           — citation-count tables per catalog field
 *   activity-feed.json       — "what changed when" feed
 *   catalog-summaries.json   — compact per-catalog summary cards
 *   stale-content.json       — persisted stale-content findings
 *   _meta.json               — SHA-256 of every source file for staleness
 *
 * Flags:
 *   (default)              build all outputs
 *   --only <names>         build only the comma-separated outputs (and
 *                          anything they depend on)
 *   --changed              build only outputs whose declared deps changed
 *                          since the last _meta.json snapshot. Safe in CI:
 *                          identical inputs always produce identical outputs.
 *   --parallel             run independent builders concurrently via
 *                          Promise.all (I/O concurrency, no worker threads).
 *                          For CPU-bound fan-out, callers can compose with
 *                          lib/worker-pool.js directly.
 *   --quiet                suppress per-output log lines
 *
 * Re-build conditions:
 *   _meta.json records sha256 of every source file. validate-indexes
 *   (predeploy gate) re-hashes those and fails if any source changed
 *   after the last build. --changed reads that same table to decide what
 *   to rebuild.
 *
 * Index file naming convention: leading underscore marks them as derived
 * (mirroring `_meta` in catalog files), so anyone scanning `data/` for
 * primary data filters them out.
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

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function writeJson(name, obj) {
  fs.writeFileSync(path.join(IDX, name), JSON.stringify(obj, null, 2) + "\n", "utf8");
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function parseArgs(argv) {
  const out = { only: null, changed: false, parallel: false, quiet: false, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--only") out.only = argv[++i];
    else if (a.startsWith("--only=")) out.only = a.slice("--only=".length);
    else if (a === "--changed") out.changed = true;
    else if (a === "--parallel") out.parallel = true;
    else if (a === "--quiet") out.quiet = true;
    else if (a === "--help" || a === "-h") out.help = true;
  }
  return out;
}

function printHelp() {
  console.log(`build-indexes — produce data/_indexes/*.json from canonical sources.

Flags:
  (default)             build all 17 outputs
  --only <names>        comma-separated subset (xref,chains,recipes,...)
  --changed             rebuild only outputs whose declared dependencies
                        changed since the last _meta.json (CI-safe).
  --parallel            run independent builders concurrently via Promise.all.
  --quiet               suppress per-output log lines.

Examples:
  npm run build-indexes
  node scripts/build-indexes.js --only summary-cards,section-offsets
  node scripts/build-indexes.js --changed --parallel
`);
}

// --- Source loading (shared in-memory snapshot) -------------------------

function loadSources() {
  const manifest = readJson(ABS("manifest.json"));
  const skills = manifest.skills;
  const skillNames = new Set(skills.map((s) => s.name));
  const catalogFiles = fs.readdirSync(ABS("data")).filter((f) => f.endsWith(".json")).map((f) => "data/" + f);

  // Per-skill body cache so multiple builders don't re-read the same file.
  const skillBodies = {};
  for (const s of skills) skillBodies[s.name] = fs.readFileSync(ABS(s.path), "utf8");

  const ctx = {
    root: ROOT,
    manifest,
    skills,
    skillNames,
    skillBodies,
    catalogFiles,
    cveCatalog: readJson(ABS("data/cve-catalog.json")),
    frameworkGaps: readJson(ABS("data/framework-control-gaps.json")),
    atlasTtps: readJson(ABS("data/atlas-ttps.json")),
    cweCatalog: readJson(ABS("data/cwe-catalog.json")),
    d3Catalog: readJson(ABS("data/d3fend-catalog.json")),
    rfcCatalog: readJson(ABS("data/rfc-references.json")),
    dlpCatalog: readJson(ABS("data/dlp-controls.json")),
    globalFrameworks: readJson(ABS("data/global-frameworks.json")),
  };
  return ctx;
}

// --- Outputs registry ---------------------------------------------------
// Each entry: { name, file, deps, build, dependsOn?: [name, ...] }
//   deps: list of source-file pattern functions. A pattern is a function that
//         returns true if a given relative path counts as a dep for this
//         output. The --changed planner walks every changed source and
//         flags every output whose deps match.
//   dependsOn: names of other outputs that must be built first (used by
//              chains.json which composes CVE + CWE halves, and
//              token-budget.json which consumes section-offsets).

function isAnySkillBody(p) { return p.startsWith("skills/") && p.endsWith("/skill.md"); }
function isManifest(p) { return p === "manifest.json"; }
function isCatalog(name) { return (p) => p === `data/${name}.json`; }
function isAnyCatalog(p) { return p.startsWith("data/") && p.endsWith(".json") && !p.includes("/_indexes/"); }

const OUTPUTS = [
  {
    name: "xref",
    file: "xref.json",
    deps: [isManifest],
    build: (ctx) => {
      const xref = {
        cwe_refs: {}, d3fend_refs: {}, framework_gaps: {},
        atlas_refs: {}, attack_refs: {}, rfc_refs: {}, dlp_refs: {},
      };
      for (const s of ctx.skills) {
        for (const field of Object.keys(xref)) {
          for (const v of s[field] || []) (xref[field][v] = xref[field][v] || []).push(s.name);
        }
      }
      for (const field of Object.keys(xref)) {
        for (const k of Object.keys(xref[field])) xref[field][k].sort();
      }
      const stats = {};
      for (const field of Object.keys(xref)) stats[field] = Object.keys(xref[field]).length;
      ctx._xrefStats = stats;
      return xref;
    },
  },

  {
    name: "trigger-table",
    file: "trigger-table.json",
    deps: [isManifest],
    build: (ctx) => {
      const t = {};
      for (const s of ctx.skills) {
        for (const tr of s.triggers || []) {
          const k = String(tr).toLowerCase().trim();
          (t[k] = t[k] || []).push(s.name);
        }
      }
      for (const k of Object.keys(t)) t[k].sort();
      return t;
    },
  },

  {
    name: "jurisdiction-map",
    file: "jurisdiction-map.json",
    deps: [isManifest, isCatalog("global-frameworks"), isAnySkillBody],
    build: (ctx) => {
      const codes = Object.keys(ctx.globalFrameworks).filter((k) => !k.startsWith("_") && k !== "GLOBAL");
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
        "POPIA": "ZA", "UAE PDPL": "AE",
        "KSA PDPL": "SA", "SAMA": "SA",
        "Privacy Act 2020": "NZ", "PIPA": "KR",
        "INCD": "IL", "BoI Directive 361": "IL",
        "FADP": "CH", "FINMA": "CH",
        "PDPO": "HK", "HKMA": "HK", "CSMA": "TW",
        "UU PDP": "ID", "BSSN": "ID",
        "Vietnam Cybersecurity Law": "VN",
        "NYDFS": "US_NYDFS", "23 NYCRR 500": "US_NYDFS",
        "CCPA": "US_CALIFORNIA", "CPRA": "US_CALIFORNIA", "CPPA": "US_CALIFORNIA",
        "BSI": "EU_DE_BSI", "IT-Grundschutz": "EU_DE_BSI",
        "ANSSI": "EU_FR_ANSSI", "AEPD": "EU_ES_AEPD",
        "AgID": "EU_IT_AgID_ACN", "ACN": "EU_IT_AgID_ACN",
        "NSM": "NO",
        "LFPDPPP": "MX", "INAI": "MX", "AAIP": "AR",
        "KVKK": "TR", "PDPA Thailand": "TH", "DPA Philippines": "PH",
      };
      const out = {};
      for (const code of codes) out[code] = { skills: [], example_excerpts: {} };
      for (const s of ctx.skills) {
        const body = ctx.skillBodies[s.name];
        for (const code of codes) {
          const re = new RegExp("\\b" + code + "\\b");
          if (re.test(body) && !out[code].skills.includes(s.name)) out[code].skills.push(s.name);
        }
        for (const [name, code] of Object.entries(NAME_TO_CODE)) {
          if (body.includes(name) && !out[code].skills.includes(s.name)) out[code].skills.push(s.name);
        }
      }
      for (const code of codes) {
        out[code].skills.sort();
        out[code].skill_count = out[code].skills.length;
      }
      ctx._jurisdictionCount = codes.length;
      return out;
    },
  },

  {
    name: "handoff-dag",
    file: "handoff-dag.json",
    deps: [isManifest, isAnySkillBody],
    build: (ctx) => {
      const edges = {}, nodes = [...ctx.skillNames].sort();
      for (const s of ctx.skills) edges[s.name] = [];
      for (const s of ctx.skills) {
        const body = ctx.skillBodies[s.name];
        for (const other of ctx.skillNames) {
          if (other === s.name) continue;
          if (body.includes("`" + other + "`")) edges[s.name].push(other);
        }
        edges[s.name].sort();
      }
      const inDeg = {}, outDeg = {};
      for (const n of nodes) { inDeg[n] = 0; outDeg[n] = 0; }
      for (const [from, tos] of Object.entries(edges)) {
        outDeg[from] = tos.length;
        for (const to of tos) inDeg[to] = (inDeg[to] || 0) + 1;
      }
      return { nodes, edges, in_degree: inDeg, out_degree: outDeg };
    },
  },

  {
    name: "chains",
    file: "chains.json",
    deps: [
      isManifest,
      isCatalog("cve-catalog"),
      isCatalog("cwe-catalog"),
      isCatalog("framework-control-gaps"),
      isCatalog("atlas-ttps"),
      isCatalog("d3fend-catalog"),
      isCatalog("rfc-references"),
    ],
    build: (ctx) => {
      const { buildCweChains } = require("./builders/cwe-chains");
      const chains = {
        _meta: {
          schema_version: "1.1.0",
          note: "Pre-computed cross-walks keyed by CVE-id and (v0.7.0+) CWE-id.",
          entry_types: ["CVE", "CWE"],
        },
      };
      // CVE half
      for (const cveId of Object.keys(ctx.cveCatalog).filter((k) => !k.startsWith("_"))) {
        const cve = ctx.cveCatalog[cveId];
        const referencingSkills = ctx.skills
          .filter((s) => {
            for (const fg of s.framework_gaps || []) {
              const evd = (ctx.frameworkGaps[fg] || {}).evidence_cves || [];
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
          const s = ctx.skills.find((x) => x.name === name);
          for (const field of Object.keys(accum)) {
            for (const v of s[field] || []) accum[field].add(v);
          }
        }
        const hydrated = {
          cwes: [...accum.cwe_refs].sort().map((c) => ({ id: c, name: ctx.cweCatalog[c]?.name, category: ctx.cweCatalog[c]?.category })),
          atlas: [...accum.atlas_refs].sort().map((a) => ({ id: a, name: ctx.atlasTtps[a]?.name, tactic: ctx.atlasTtps[a]?.tactic })),
          d3fend: [...accum.d3fend_refs].sort().map((d) => ({ id: d, name: ctx.d3Catalog[d]?.name, tactic: ctx.d3Catalog[d]?.tactic })),
          framework_gaps: [...accum.framework_gaps].sort().map((f) => ({ id: f, framework: ctx.frameworkGaps[f]?.framework, control_name: ctx.frameworkGaps[f]?.control_name })),
          attack_refs: [...accum.attack_refs].sort(),
          rfc_refs: [...accum.rfc_refs].sort(),
        };
        chains[cveId] = {
          name: cve.name, rwep: cve.rwep_score, cvss: cve.cvss_score,
          cisa_kev: cve.cisa_kev, epss_score: cve.epss_score, epss_percentile: cve.epss_percentile,
          referencing_skills: referencingSkills, chain: hydrated,
        };
      }
      // CWE half (delegated to builder)
      const cweChains = buildCweChains({
        skills: ctx.skills, cweCatalog: ctx.cweCatalog, atlasTtps: ctx.atlasTtps,
        cveCatalog: ctx.cveCatalog, frameworkGaps: ctx.frameworkGaps,
        d3fendCatalog: ctx.d3Catalog, rfcCatalog: ctx.rfcCatalog,
      });
      for (const [k, v] of Object.entries(cweChains)) chains[k] = v;
      return chains;
    },
  },

  {
    name: "summary-cards",
    file: "summary-cards.json",
    deps: [isManifest, isAnySkillBody],
    build: (ctx) => {
      const { buildSummaryCards } = require("./builders/summary-cards");
      return buildSummaryCards({ root: ctx.root, manifest: ctx.manifest, skills: ctx.skills });
    },
  },

  {
    name: "section-offsets",
    file: "section-offsets.json",
    deps: [isManifest, isAnySkillBody],
    build: (ctx) => {
      const { buildSectionOffsets } = require("./builders/section-offsets");
      return buildSectionOffsets({ root: ctx.root, skills: ctx.skills });
    },
  },

  {
    name: "token-budget",
    file: "token-budget.json",
    deps: [isManifest, isAnySkillBody],
    dependsOn: ["section-offsets"],   // needs the produced index
    build: (ctx) => {
      const { buildTokenBudget } = require("./builders/token-budget");
      // section-offsets output is already on disk (built first by the
      // dependency planner). Read it back for the token splitter.
      const sectionOffsets = readJson(path.join(IDX, "section-offsets.json"));
      return buildTokenBudget({ root: ctx.root, skills: ctx.skills, sectionOffsets });
    },
  },

  {
    name: "recipes",
    file: "recipes.json",
    deps: [isManifest],
    build: (ctx) => {
      const { buildRecipes } = require("./builders/recipes");
      return buildRecipes({ skills: ctx.skills });
    },
  },

  {
    name: "jurisdiction-clocks",
    file: "jurisdiction-clocks.json",
    deps: [isCatalog("global-frameworks")],
    build: (ctx) => {
      const { buildJurisdictionClocks } = require("./builders/jurisdiction-clocks");
      return buildJurisdictionClocks({ globalFrameworks: ctx.globalFrameworks });
    },
  },

  {
    name: "did-ladders",
    file: "did-ladders.json",
    deps: [isManifest, isCatalog("d3fend-catalog")],
    build: (ctx) => {
      const { buildDidLadders } = require("./builders/did-ladders");
      return buildDidLadders({ skills: ctx.skills, d3fendCatalog: ctx.d3Catalog });
    },
  },

  {
    name: "theater-fingerprints",
    file: "theater-fingerprints.json",
    deps: [(p) => p === "skills/compliance-theater/skill.md"],
    build: (ctx) => {
      const { buildTheaterFingerprints } = require("./builders/theater-fingerprints");
      return buildTheaterFingerprints({ root: ctx.root });
    },
  },

  {
    name: "currency",
    file: "currency.json",
    deps: [isManifest, isAnySkillBody],
    build: (ctx) => {
      const { buildCurrency } = require("./builders/currency");
      return buildCurrency({ root: ctx.root, manifest: ctx.manifest, skills: ctx.skills });
    },
  },

  {
    name: "frequency",
    file: "frequency.json",
    deps: [isManifest, isAnyCatalog],
    build: (ctx) => {
      const { buildFrequency } = require("./builders/frequency");
      return buildFrequency({
        skills: ctx.skills,
        catalogs: {
          cwe: ctx.cweCatalog, atlas: ctx.atlasTtps, d3fend: ctx.d3Catalog,
          frameworkGaps: ctx.frameworkGaps, rfc: ctx.rfcCatalog, dlp: ctx.dlpCatalog,
        },
      });
    },
  },

  {
    name: "activity-feed",
    file: "activity-feed.json",
    deps: [isManifest, isAnyCatalog],
    build: (ctx) => {
      const { buildActivityFeed } = require("./builders/activity-feed");
      return buildActivityFeed({ root: ctx.root, manifest: ctx.manifest, skills: ctx.skills, catalogFiles: ctx.catalogFiles });
    },
  },

  {
    name: "catalog-summaries",
    file: "catalog-summaries.json",
    deps: [isAnyCatalog],
    build: (ctx) => {
      const { buildCatalogSummaries } = require("./builders/catalog-summaries");
      return buildCatalogSummaries({ root: ctx.root, catalogFiles: ctx.catalogFiles });
    },
  },

  {
    name: "stale-content",
    file: "stale-content.json",
    deps: [isManifest, isAnySkillBody, isAnyCatalog],
    build: (ctx) => {
      const { buildStaleContent } = require("./builders/stale-content");
      return buildStaleContent({ root: ctx.root, manifest: ctx.manifest, skills: ctx.skills, catalogFiles: ctx.catalogFiles });
    },
  },
];

// --- Plan + run --------------------------------------------------------

function loadPriorMeta() {
  const p = path.join(IDX, "_meta.json");
  if (!fs.existsSync(p)) return null;
  try { return readJson(p); } catch { return null; }
}

function liveSourceSet(ctx) {
  const out = new Set();
  out.add("manifest.json");
  for (const c of ctx.catalogFiles) out.add(c);
  for (const s of ctx.skills) out.add(s.path);
  return out;
}

function changedSources(ctx, priorMeta) {
  // Returns the array of source paths whose sha256 differs from prior, OR
  // every source if there's no prior meta. Also accounts for new + removed
  // source files (which always force a rebuild).
  if (!priorMeta || !priorMeta.source_hashes) {
    return [...liveSourceSet(ctx)];
  }
  const live = liveSourceSet(ctx);
  const recorded = new Set(Object.keys(priorMeta.source_hashes));
  const changed = [];
  for (const p of live) {
    const h = sha256(fs.readFileSync(ABS(p)));
    if (priorMeta.source_hashes[p] !== h) changed.push(p);
  }
  // Any source that disappeared since last build counts as a change.
  for (const p of recorded) if (!live.has(p)) changed.push(p);
  return changed;
}

function outputsAffectedBy(changedPaths) {
  const affected = new Set();
  for (const o of OUTPUTS) {
    for (const dep of o.deps) {
      if (changedPaths.some(dep)) { affected.add(o.name); break; }
    }
  }
  return affected;
}

function withDependencyClosure(names) {
  // Pull in any dependsOn entries (e.g. token-budget needs section-offsets).
  const closure = new Set(names);
  let added = true;
  while (added) {
    added = false;
    for (const o of OUTPUTS) {
      if (!closure.has(o.name)) continue;
      for (const dep of o.dependsOn || []) {
        if (!closure.has(dep)) {
          closure.add(dep);
          added = true;
        }
      }
    }
  }
  return closure;
}

function topoOrder(names) {
  const want = new Set(names);
  const order = [];
  const visited = new Set();
  function visit(name) {
    if (visited.has(name)) return;
    visited.add(name);
    const out = OUTPUTS.find((x) => x.name === name);
    for (const dep of (out?.dependsOn || [])) if (want.has(dep)) visit(dep);
    order.push(name);
  }
  for (const o of OUTPUTS) if (want.has(o.name)) visit(o.name);
  return order;
}

async function runBuilders(ctx, names, opts) {
  // Build the dependency-respecting execution plan, then dispatch.
  const order = topoOrder(names);
  const log = (s) => opts.quiet || console.log(s);

  // Group by levels — outputs with no produced-output deps go first, then
  // outputs depending on those, etc. This is the parallelization unit.
  const remaining = new Set(order);
  const levels = [];
  while (remaining.size > 0) {
    const level = [];
    for (const n of remaining) {
      const o = OUTPUTS.find((x) => x.name === n);
      const blockers = (o.dependsOn || []).filter((d) => remaining.has(d));
      if (blockers.length === 0) level.push(n);
    }
    if (level.length === 0) {
      throw new Error("build-indexes: dependency cycle detected — please check OUTPUTS.dependsOn");
    }
    levels.push(level);
    for (const n of level) remaining.delete(n);
  }

  const results = {};
  for (const level of levels) {
    const runOne = async (name) => {
      const o = OUTPUTS.find((x) => x.name === name);
      const t0 = Date.now();
      const payload = await o.build(ctx);
      writeJson(o.file, payload);
      results[name] = payload;
      const ms = Date.now() - t0;
      log(`  ✓ ${o.file} (${ms}ms)`);
    };
    if (opts.parallel) {
      await Promise.all(level.map(runOne));
    } else {
      for (const n of level) await runOne(n);
    }
  }

  return results;
}

function writeMeta(ctx, results) {
  const sourceFiles = [...liveSourceSet(ctx)];
  const sourceHashes = {};
  for (const p of sourceFiles) sourceHashes[p] = sha256(fs.readFileSync(ABS(p)));

  // Stats are computed from in-memory results when available, else from disk
  // (covers --only / --changed runs that didn't rebuild every output).
  function readBack(name) {
    if (results[name]) return results[name];
    const o = OUTPUTS.find((x) => x.name === name);
    if (!o) return null;
    const p = path.join(IDX, o.file);
    if (!fs.existsSync(p)) return null;
    try { return readJson(p); } catch { return null; }
  }

  const xref = readBack("xref") || {};
  const trigger = readBack("trigger-table") || {};
  const chains = readBack("chains") || {};
  const handoff = readBack("handoff-dag") || { nodes: [], edges: {} };
  const summaryCards = readBack("summary-cards") || { skills: {} };
  const sectionOffsets = readBack("section-offsets") || { skills: {} };
  const tokenBudget = readBack("token-budget") || { _meta: {} };
  const recipes = readBack("recipes") || { recipes: [] };
  const jurisdictionClocks = readBack("jurisdiction-clocks") || { by_jurisdiction: {} };
  const didLadders = readBack("did-ladders") || { ladders: [] };
  const theater = readBack("theater-fingerprints") || { patterns: {} };
  const currency = readBack("currency") || { summary: {} };
  const frequency = readBack("frequency") || { counts: {} };
  const activity = readBack("activity-feed") || { events: [] };
  const catSummaries = readBack("catalog-summaries") || { catalogs: {} };
  const stale = readBack("stale-content") || { _meta: { finding_count: 0, by_severity: {} } };

  const cveChainCount = Object.keys(chains).filter((k) => k.startsWith("CVE-")).length;
  const cweChainCount = Object.keys(chains).filter((k) => k.startsWith("CWE-")).length;
  const xrefStats = {};
  for (const field of Object.keys(xref)) xrefStats[field] = Object.keys(xref[field]).length;

  const meta = {
    schema_version: "1.1.0",
    generated_at: new Date().toISOString(),
    generator: "scripts/build-indexes.js",
    source_count: sourceFiles.length,
    source_hashes: sourceHashes,
    skill_count: ctx.skills.length,
    catalog_count: ctx.catalogFiles.length,
    index_stats: {
      xref_entries: xrefStats,
      trigger_table_entries: Object.keys(trigger).length,
      chains_cve_entries: cveChainCount,
      chains_cwe_entries: cweChainCount,
      jurisdictions_indexed: Object.keys(jurisdictionClocks.by_jurisdiction || {}).length || Object.keys(readBack("jurisdiction-map") || {}).length,
      handoff_dag_nodes: handoff.nodes?.length || 0,
      summary_cards: Object.keys(summaryCards.skills || {}).length,
      section_offsets_skills: Object.keys(sectionOffsets.skills || {}).length,
      token_budget_total_approx: tokenBudget._meta?.total_approx_tokens || 0,
      recipes: (recipes.recipes || []).length,
      jurisdiction_clocks: Object.keys(jurisdictionClocks.by_jurisdiction || {}).length,
      did_ladders: (didLadders.ladders || []).length,
      theater_fingerprints: Object.keys(theater.patterns || {}).length,
      currency_action_required: currency.summary?.action_required || 0,
      frequency_fields: Object.keys(frequency.counts || {}).length,
      activity_feed_events: (activity.events || []).length,
      catalog_summaries: Object.keys(catSummaries.catalogs || {}).length,
      stale_content_findings: stale._meta?.finding_count || 0,
    },
    invalidation_note: "If any source file in source_hashes has a different SHA-256 than recorded here, the indexes are stale. Re-run `npm run build-indexes`.",
  };
  writeJson("_meta.json", meta);
  return meta;
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  const ctx = loadSources();
  const log = (s) => opts.quiet || console.log(s);

  // Decide which outputs to build.
  let chosen;
  if (opts.only) {
    const wanted = opts.only.split(",").map((s) => s.trim()).filter(Boolean);
    for (const n of wanted) {
      if (!OUTPUTS.find((o) => o.name === n)) {
        console.error(`build-indexes: unknown output "${n}". Valid: ${OUTPUTS.map((o) => o.name).join(", ")}`);
        process.exit(2);
      }
    }
    chosen = withDependencyClosure(wanted);
  } else if (opts.changed) {
    const prior = loadPriorMeta();
    const changed = changedSources(ctx, prior);
    log(`changed sources: ${changed.length}`);
    const affected = outputsAffectedBy(changed);
    chosen = withDependencyClosure(affected);
    if (chosen.size === 0) {
      log("build-indexes: no outputs need rebuilding (sources unchanged)");
      // Still rewrite _meta.json with the same hashes — preserves freshness
      // semantics for the predeploy gate even when nothing else changed.
      writeMeta(ctx, {});
      return;
    }
  } else {
    chosen = new Set(OUTPUTS.map((o) => o.name));
  }

  log(`build-indexes — ${chosen.size} output(s) ${opts.parallel ? "in parallel" : "sequential"}${opts.changed ? " (--changed)" : ""}${opts.only ? ` (--only ${opts.only})` : ""}`);

  const results = await runBuilders(ctx, chosen, opts);
  writeMeta(ctx, results);

  log(`build-indexes — done`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`build-indexes: fatal: ${err && err.stack ? err.stack : err}`);
    process.exit(1);
  });
}

module.exports = { OUTPUTS, loadSources, runBuilders, writeMeta };
