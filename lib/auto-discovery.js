"use strict";
/**
 * Discovers new upstream catalog entries (CISA KEV, IETF RFCs) as `op:"add"`
 * diffs for refresh-external.js's auto-PR; items past `cap` spill to the next run.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { scoreCustom, postWeightFactors } = require("./scoring");
const { selectNvdCvss } = require("./cvss");
const { deriveMechanicalFields } = require("./cve-enrich");

// Single source of truth for a fresh KEV draft's score and its stored
// rwep_factors, which must reproduce each other. The defaults read KEV conservatively.
function buildScoringInputs(kevEntry /*, nvdPayload */) {
  void kevEntry;
  return {
    cisa_kev: true,
    poc_available: true,
    ai_assisted_weapon: false,
    ai_discovered: false,
    active_exploitation: "suspected",
    blast_radius: 15,
    patch_available: false,
    live_patch_available: false,
    reboot_required: true,
  };
}

// cve-catalog.schema.json requires `rwep_factors` in the post-weight numeric
// shape, not the boolean + string-ladder shape scoreCustom consumes;
// `scoring.postWeightFactors` is the one converter.

/**
 * Severity of a KEV-discovered diff. A KEV listing itself means active
 * exploitation, so "low" and "medium" never apply.
 */
function deriveKevSeverity(kevEntry) {
  const ransomware = String(kevEntry?.knownRansomwareCampaignUse || "").toLowerCase() === "known";
  if (ransomware) return "critical";
  const due = kevEntry?.dueDate;
  if (typeof due === "string" && /^\d{4}-\d{2}-\d{2}/.test(due)) {
    const dueMs = Date.parse(due);
    if (Number.isFinite(dueMs)) {
      const deltaMs = dueMs - Date.now();
      if (deltaMs <= 7 * 86_400_000) return "critical";
    }
  }
  return "high";
}

const TODAY = new Date().toISOString().slice(0, 10);
const TIMEOUT_MS = 10_000;
const USER_AGENT = "exceptd-security/auto-discovery (+https://exceptd.com)";
const DEFAULT_CAP = 100;

// IETF Datatracker codes → the status strings data/rfc-references.json stores.
const RFC_STATUS_MAP = {
  std: "Internet Standard",
  ps:  "Proposed Standard",
  ds:  "Draft Standard",
  bcp: "Best Current Practice",
  inf: "Informational",
  exp: "Experimental",
  his: "Historic",
  unkn: "Unknown",
};

// Reads a per-source cache payload, verified against the signed _index.json.
// Anything unverifiable returns null — the only fail-closed action available to
// a function that returns drafts, not errors. A missing index ENTRY returns null
// too (the inject-alongside-a-signed-cache vector); an absent _index.json is left
// to loadCtx's --from-cache signature gate.
function readCachedJson(cacheDir, source, id) {
  if (!cacheDir) return null;
  const safe = String(id).replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(cacheDir, source, `${safe}.json`);
  if (!fs.existsSync(p)) return null;
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }

  const indexPath = path.join(cacheDir, "_index.json");
  if (!fs.existsSync(indexPath)) return parsed;
  let idx;
  try { idx = JSON.parse(fs.readFileSync(indexPath, "utf8")); } catch { return null; }
  const meta = idx && idx.entries && idx.entries[`${source}/${id}`];
  if (!meta || typeof meta.sha256 !== "string") return null;
  // The recorded sha256 is over JSON.stringify of the parsed payload
  // (unindented), so re-stringify rather than hashing the file bytes.
  const actual = crypto.createHash("sha256").update(JSON.stringify(parsed)).digest("hex");
  if (actual !== meta.sha256) return null;
  return parsed;
}

function extractNvdMetrics(payload, id) {
  // Resolve by id, not by position: a cache entry keyed under `id` that holds
  // another CVE's response would otherwise attribute its CVSS and CWE here.
  const cves = (payload?.vulnerabilities || []).map((v) => v?.cve).filter(Boolean);
  const vuln = id
    ? cves.find((c) => c.id && String(c.id).toUpperCase() === String(id).toUpperCase())
    : cves[0];
  if (!vuln) return null;
  // Newest CVSS version, Primary within it, with a bare v2 vector normalized
  // to its canonical prefix — the strict catalog validator rejects unprefixed.
  const up = selectNvdCvss(vuln.metrics);
  return {
    cvss_score: up ? up.baseScore : null,
    cvss_vector: up ? up.vector : null,
    description: (vuln.descriptions || []).find((d) => d.lang === "en")?.value || null,
    cwe_refs: ((vuln.weaknesses || [])
      .flatMap((w) => (w.description || []))
      .map((d) => d.value)
      .filter((v) => /^CWE-\d+$/.test(v))
    ),
    // The tags are load-bearing: cve-enrich keeps only "Vendor Advisory" links,
    // so an empty result correctly trips the no-advisory curation-gap detector.
    references: (vuln.references || []).map((r) => ({ url: r.url, tags: r.tags || [] })),
  };
}

function extractEpss(payload, id) {
  const data = Array.isArray(payload?.data) ? payload.data : [];
  // Match the requested id only — a `|| data[0]` fallback writes another CVE's
  // score here. The one exception is a single-row, cve-less payload.
  let row = data.find((r) => r?.cve === id);
  if (!row && data.length === 1 && data[0]?.cve == null) row = data[0];
  if (!row) return null;
  return {
    score: row.epss != null ? Number(row.epss) : null,
    percentile: row.percentile != null ? Number(row.percentile) : null,
    date: typeof row.date === "string" ? row.date : null,
  };
}

/**
 * Draft catalog entry from one KEV record plus cached NVD 2.0 and EPSS payloads,
 * either of which may be null. Analytical fields stay null.
 */
function buildKevDraftEntry(kevEntry, nvdPayload, epssPayload) {
  const id = String(kevEntry.cveID);
  const nvd = nvdPayload ? extractNvdMetrics(nvdPayload, id) : null;
  const epss = epssPayload ? extractEpss(epssPayload, id) : null;

  // One input object feeds both, so the stored factors sum exactly to rwep_score.
  const scoringInputs = buildScoringInputs(kevEntry, nvdPayload);
  const rwep_factors = postWeightFactors(scoringInputs);
  const rwep_score = scoreCustom(scoringInputs);

  const product = [kevEntry.vendorProject, kevEntry.product]
    .filter(Boolean)
    .join(" ");

  // deriveMechanicalFields is shared with `--curate-batch`, so the nightly path
  // and the batch tool cannot drift. What follows is that module's `facts` shape.
  const facts = {
    id,
    nvd_desc: nvd && nvd.description,
    cvss: nvd && nvd.cvss_score != null
      ? { version: "3.1", base_score: nvd.cvss_score, vector: nvd.cvss_vector, severity: null }
      : null,
    cwe_nvd: (nvd && nvd.cwe_refs) || [],
    references: (nvd && nvd.references) || [],
    kev: {
      name: kevEntry.vulnerabilityName,
      vendor: kevEntry.vendorProject,
      product: kevEntry.product,
      dateAdded: kevEntry.dateAdded,
      dueDate: kevEntry.dueDate,
      ransomware: kevEntry.knownRansomwareCampaignUse,
      shortDescription: kevEntry.shortDescription,
    },
    epss: epss && { score: epss.score, percentile: epss.percentile, date: epss.date },
  };
  const mech = deriveMechanicalFields(facts, TODAY);

  return {
    ...mech,
    type: "TBD",
    poc_available: null,
    poc_description: null,
    ai_discovered: null,
    ai_discovery_notes: null,
    ai_assisted_weaponization: null,
    // Overrides deriveMechanicalFields' 'confirmed': a draft must not claim
    // confirmed exploitation before a human has reviewed it.
    active_exploitation: "suspected",
    affected: product || "See vendor advisory",
    affected_versions: [],
    complexity_notes: null,
    patch_available: null,
    patch_required_reboot: null,
    live_patch_available: null,
    live_patch_tools: [],
    live_patch_notes: null,
    framework_control_gaps: {},
    atlas_refs: [],
    attack_refs: [],
    rwep_score,
    rwep_factors,
    last_verified: TODAY,
    // Boolean `true`, not an object: lib/validate-cve-catalog.js recognizes a
    // draft by strict `=== true`. Provenance goes in `_auto_imported_meta`.
    _auto_imported: true,
    _auto_imported_meta: {
      source: "KEV discovery",
      imported_at: TODAY,
      curation_needed: [
        "type (LPE/RCE/SSRF/etc.)",
        "poc_available + poc_description (link to public PoC if any)",
        "ai_discovered + ai_assisted_weaponization classification",
        "active_exploitation upgrade from 'suspected' to 'confirmed' once a campaign is documented",
        "framework_control_gaps mapping (NIST/ISO/PCI/SOC 2 controls this defeats)",
        "atlas_refs + attack_refs categorization",
        "complexity_notes (complexity auto-derived from CVSS AC when NVD data present)",
        "patch_available + live_patch_available + live_patch_tools",
        "blast_radius numeric in rwep_factors (currently default 15)",
        "RWEP score recompute after the above land",
      ],
    },
  };
}

/**
 * KEV entries upstream that are absent from local cve-catalog.json, as
 * { id, op:"add", entry, severity } diffs capped at `cap`; overflow is `spilled`.
 */
function discoverNewKev(ctx, cap = DEFAULT_CAP) {
  const feed = readCachedJson(ctx.cacheDir, "kev", "known_exploited_vulnerabilities");
  if (!feed || !Array.isArray(feed.vulnerabilities)) {
    return { diffs: [], errors: 1, spilled: 0, summary: "KEV discovery: no cached feed" };
  }

  const localCves = new Set(
    Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k))
  );

  // Newest dateAdded first, so the cap clips the oldest additions.
  const candidates = feed.vulnerabilities
    .filter((v) => v && v.cveID && !localCves.has(String(v.cveID)))
    .sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));

  const total = candidates.length;
  const picks = candidates.slice(0, cap);
  const spilled = Math.max(0, total - picks.length);

  const diffs = picks.map((kev) => {
    const id = String(kev.cveID);
    const nvd = readCachedJson(ctx.cacheDir, "nvd", id);
    const epss = readCachedJson(ctx.cacheDir, "epss", id);
    const entry = buildKevDraftEntry(kev, nvd, epss);
    return {
      id,
      op: "add",
      target: "cveCatalog",
      entry,
      severity: deriveKevSeverity(kev),
      meta: {
        date_added: kev.dateAdded || null,
        vendor: kev.vendorProject || null,
        product: kev.product || null,
      },
    };
  });

  return {
    diffs,
    errors: 0,
    spilled,
    summary: total === 0
      ? "KEV discovery: no new entries"
      : `KEV discovery: ${diffs.length} new entries${spilled > 0 ? ` (+${spilled} spilled past cap)` : ""}`,
  };
}

async function fetchDatatracker(url, ctx) {
  // A structured `ok:false` the caller tells apart from a payload, so an air-gap
  // refusal reports as a skip rather than a fetch error.
  if ((ctx && ctx.airGap === true) || process.env.EXCEPTD_AIR_GAP === "1") {
    return { ok: false, error: "air-gap-blocked", source: "datatracker" };
  }
  // Transient failures (429/5xx, ECONNRESET/ETIMEDOUT) back off with jitter.
  // Discovery never throws, so an exhausted budget collapses to null.
  const { withRetry } = require("../vendor/blamejs/retry.js");
  const once = async () => {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: ac.signal,
        headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
      });
      if (!res.ok) {
        const e = new Error(`HTTP ${res.status} from ${url}`);
        e.statusCode = res.status; // let withRetry's classifier retry 429/5xx
        throw e;
      }
      return await res.json();
    } finally {
      clearTimeout(t);
    }
  };
  try {
    return await withRetry(once, { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 2000, jitterFactor: 0.5 });
  } catch {
    return null;
  }
}

/**
 * Seed WGs, unioned with those on project-cited RFCs: without the seed,
 * discovery stays blind to a WG until one of its RFCs is added by hand.
 */
const SEED_RFC_GROUPS = [
  // Transport / crypto / PKI
  "tls", "uta", "cfrg", "lamps", "ipsecme",
  // HTTP / web / QUIC / API
  "httpbis", "quic", "ohai", "privacypass", "httpapi", "core",
  // Identity / auth / SSO / cert mgmt / workload identity / constrained auth
  "oauth", "gnap", "jose", "cose", "cbor", "kitten", "emu",
  "secevent", "scim", "acme", "wimse", "ace",
  // DNS security + privacy + DNS-based auth
  "dnsop", "dprive", "add", "dance",
  // Supply chain + attestation + transparency + firmware/TEE
  "scitt", "rats", "suit", "teep", "trans",
  // Threat intel + security automation + operational telemetry
  "mile", "sacm", "i2nsf", "opsawg", "opsec",
  // Messaging + E2E + media
  "mls", "moq", "sframe",
  // Network / IoT mgmt + audit-grade time sync
  "anima", "drip", "iotops", "netconf", "netmod", "ntp",
  // Data / schema / policy serialization
  "jsonschema",
];

function getProjectRfcGroups(ctx) {
  const groups = new Set();
  const ids = Object.keys(ctx.rfcCatalog).filter((k) => !k.startsWith("_"));
  for (const id of ids) {
    let docName;
    if (id.startsWith("RFC-")) docName = `rfc${id.slice(4)}`;
    else if (id.startsWith("DRAFT-")) docName = `draft-${id.slice(6).toLowerCase()}`;
    if (!docName) continue;
    const payload = readCachedJson(ctx.cacheDir, "rfc", docName);
    const obj = payload?.objects?.[0];
    const acronym = obj?.group?.acronym || (typeof obj?.group === "string" ? extractAcronymFromGroupUri(obj.group) : null);
    if (acronym) groups.add(String(acronym).toLowerCase());
  }
  for (const g of SEED_RFC_GROUPS) groups.add(g);
  return groups;
}

function extractAcronymFromGroupUri(uri) {
  // A Datatracker group URI (/api/v1/group/group/12345/) carries no acronym —
  // it is only in the doc object's full record. Null means live-fetch later.
  void uri;
  return null;
}

/**
 * Recent RFCs in project-relevant working groups that are not already in
 * data/rfc-references.json. Queries Datatracker live, one call per WG.
 * @param {object} opts  { cap = DEFAULT_CAP, sinceDays = 180 }
 */
async function discoverNewRfcs(ctx, opts = {}) {
  // --air-gap refuses the egress outright; --from-cache alone still queries
  // live, since the scheduled refresh runs on a networked host.
  if ((ctx && ctx.airGap === true) || process.env.EXCEPTD_AIR_GAP === "1") {
    return { diffs: [], errors: 0, spilled: 0, summary: "RFC discovery: skipped under air-gap (no live Datatracker query)" };
  }
  const cap = opts.cap ?? DEFAULT_CAP;
  const sinceDays = opts.sinceDays ?? 180;
  const cutoff = new Date(Date.now() - sinceDays * 86_400_000).toISOString().slice(0, 10);

  const groups = [...getProjectRfcGroups(ctx)];
  if (groups.length === 0) {
    return { diffs: [], errors: 0, spilled: 0, summary: "RFC discovery: no project WGs derived" };
  }

  const localIds = new Set(Object.keys(ctx.rfcCatalog).filter((k) => !k.startsWith("_")));

  let candidates = [];
  let errors = 0;

  for (const wg of groups) {
    const url =
      `https://datatracker.ietf.org/api/v1/doc/document/` +
      `?type=rfc&group__acronym=${encodeURIComponent(wg)}` +
      `&time__gt=${cutoff}&order_by=-time&limit=20&format=json`;
    const payload = await fetchDatatracker(url, ctx);
    // An air-gap refusal is a skip, not an `errors++` fault, and every later
    // fetch refuses identically — leave the WG loop on the first one.
    if (payload && payload.ok === false && payload.error === "air-gap-blocked") {
      return {
        diffs: [],
        errors: 0,
        spilled: 0,
        summary: "RFC discovery: skipped (air-gap mode)",
        skipped: "air-gap",
      };
    }
    if (!payload || !Array.isArray(payload.objects)) {
      errors++;
      continue;
    }
    for (const obj of payload.objects) {
      const docName = String(obj.name || "");
      const m = docName.match(/^rfc(\d+)$/i);
      if (!m) continue;
      const number = Number(m[1]);
      const localKey = `RFC-${number}`;
      if (localIds.has(localKey)) continue;
      candidates.push({ obj, number, localKey, wg });
    }
  }

  // An RFC can list several groups; keep the first WG match.
  const seen = new Set();
  candidates = candidates.filter((c) => {
    if (seen.has(c.localKey)) return false;
    seen.add(c.localKey);
    return true;
  });

  // Newest published first, so the cap clips the oldest.
  candidates.sort((a, b) => String(b.obj.time || "").localeCompare(String(a.obj.time || "")));

  const total = candidates.length;
  const picks = candidates.slice(0, cap);
  const spilled = Math.max(0, total - picks.length);

  const diffs = picks.map(({ obj, number, localKey, wg }) => {
    const status = RFC_STATUS_MAP[obj.std_level] || "Unknown";
    const entry = {
      number,
      title: String(obj.title || `RFC ${number}`),
      status,
      published: typeof obj.time === "string" ? obj.time.slice(0, 7) : null,
      tracker: `https://www.rfc-editor.org/info/rfc${number}`,
      relevance: `AUTO-IMPORTED from IETF ${wg.toUpperCase()} working group. Project already cites other RFCs in this WG — this candidate surfaced via the auto-discovery filter and needs a curated relevance statement before merge.`,
      lag_notes: null,
      skills_referencing: [],
      errata_count: null,
      last_verified: TODAY,
      // Boolean `true` for strict-validator draft recognition.
      _auto_imported: true,
      _auto_imported_meta: {
        source: `RFC discovery (IETF ${wg} working group)`,
        imported_at: TODAY,
        curation_needed: [
          "relevance — project-specific framing of how this RFC matters for mid-2026 threats",
          "lag_notes — what gaps remain or where the RFC falls short",
          "skills_referencing — list of skills that should cite this RFC",
          `errata_count — populate from <rfc-editor.org/errata/rfc${number}>`,
        ],
      },
    };
    return {
      id: localKey,
      op: "add",
      target: "rfcCatalog",
      entry,
      severity: "low",
      meta: { wg, published: entry.published, title: entry.title },
    };
  });

  return {
    diffs,
    errors,
    spilled,
    summary: total === 0
      ? "RFC discovery: no new entries in project WGs"
      : `RFC discovery: ${diffs.length} new entries${spilled > 0 ? ` (+${spilled} spilled past cap)` : ""} across ${groups.length} WG(s)`,
  };
}

module.exports = {
  discoverNewKev,
  discoverNewRfcs,
  buildKevDraftEntry,
  getProjectRfcGroups,
  deriveKevSeverity,
  SEED_RFC_GROUPS,
  DEFAULT_CAP,
};
