"use strict";
/**
 * lib/auto-discovery.js
 *
 * Discovers NEW catalog entries upstream and builds draft entries for
 * `refresh-external.js` to include as `op:"add"` diffs in its auto-PR.
 *
 * Sources covered:
 *   - KEV: every CVE in the CISA KEV feed that's not in local
 *     data/cve-catalog.json. NVD + EPSS data is pulled from the same
 *     prefetch cache the drift-check uses; missing cache entries fall
 *     through to a draft with null mechanical fields.
 *   - RFC: every recent IETF RFC published in a working group the
 *     project's existing rfc-references.json already cites. Queried
 *     live against Datatracker (small N — typically 1-5 RFCs per
 *     month across all project-relevant WGs).
 *
 * Each draft entry carries an `_auto_imported` block with the source,
 * import date, and a `curation_needed` list of analytical fields a
 * human still needs to fill (framework_control_gaps, atlas_refs,
 * attack_refs, type classification, etc.). `validate-cve-catalog.js`
 * is tolerant of this annotation; the audit / stale-content index
 * surfaces uncurated entries so they don't sit indefinitely.
 *
 * Both discovery functions accept a `cap` (default 20) so a burst
 * upstream addition doesn't generate an unreviewable PR. Items past
 * the cap spill to the next run.
 */

const fs = require("fs");
const path = require("path");
const { scoreCustom } = require("./scoring");

const TODAY = new Date().toISOString().slice(0, 10);
const TIMEOUT_MS = 10_000;
const USER_AGENT = "exceptd-security/auto-discovery (+https://exceptd.com)";
const DEFAULT_CAP = 20;

// IETF Datatracker codes → human-readable status strings used in
// data/rfc-references.json.
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

function readCachedJson(cacheDir, source, id) {
  if (!cacheDir) return null;
  const safe = String(id).replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(cacheDir, source, `${safe}.json`);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

function extractNvdMetrics(payload) {
  const vuln = payload?.vulnerabilities?.[0]?.cve;
  if (!vuln) return null;
  const m = vuln.metrics || {};
  const ordered = [
    ...(m.cvssMetricV31 || []),
    ...(m.cvssMetricV30 || []),
    ...(m.cvssMetricV2 || []),
  ];
  const primary = ordered.find((x) => x.type === "Primary") || ordered[0];
  return {
    cvss_score: typeof primary?.cvssData?.baseScore === "number" ? primary.cvssData.baseScore : null,
    cvss_vector: primary?.cvssData?.vectorString || null,
    description: (vuln.descriptions || []).find((d) => d.lang === "en")?.value || null,
    cwe_refs: ((vuln.weaknesses || [])
      .flatMap((w) => (w.description || []))
      .map((d) => d.value)
      .filter((v) => /^CWE-\d+$/.test(v))
    ),
  };
}

function extractEpss(payload, id) {
  const data = Array.isArray(payload?.data) ? payload.data : [];
  const row = data.find((r) => r?.cve === id) || data[0];
  if (!row) return null;
  return {
    score: row.epss != null ? Number(row.epss) : null,
    percentile: row.percentile != null ? Number(row.percentile) : null,
    date: typeof row.date === "string" ? row.date : null,
  };
}

// --- KEV discovery -----------------------------------------------------

/**
 * Build a draft CVE catalog entry from a KEV record + optional cached
 * NVD/EPSS payloads. Required-schema fields are populated where
 * mechanically derivable; analytical fields are nulled and listed in
 * `_auto_imported.curation_needed`.
 *
 * @param {object} kevEntry  Single vulnerability from CISA KEV feed
 * @param {object|null} nvdPayload  Cached NVD 2.0 response (or null)
 * @param {object|null} epssPayload  Cached EPSS response (or null)
 */
function buildKevDraftEntry(kevEntry, nvdPayload, epssPayload) {
  const id = String(kevEntry.cveID);
  const nvd = nvdPayload ? extractNvdMetrics(nvdPayload) : null;
  const epss = epssPayload ? extractEpss(epssPayload, id) : null;

  const knownRansomware =
    String(kevEntry.knownRansomwareCampaignUse || "").toLowerCase() === "known";

  // Compute initial RWEP. KEV → +25, suspected exploitation → +10.
  // Unknown PoC/AI flags default to false (conservative — we don't
  // claim more than we know). Blast radius defaults to 15 (mid-range)
  // since we can't infer it from KEV metadata alone.
  const rwep_factors = {
    cisa_kev: true,
    poc_available: null,                  // unknown — curation needed
    ai_assisted_weapon: null,
    ai_discovered: null,
    active_exploitation: "suspected",     // KEV listing implies exploitation
    blast_radius: 15,
    patch_available: null,
    live_patch_available: null,
    reboot_required: null,
  };
  // scoreCustom() treats null fields as false, which under-counts the
  // score. Pass concrete defaults for unknowns: poc_available=true is
  // the conservative assumption for KEV entries (CISA generally only
  // adds entries with documented exploitation), and reboot_required=
  // true biases toward urgency.
  const rwep_score = scoreCustom({
    cisa_kev: true,
    poc_available: true,
    ai_assisted_weapon: false,
    ai_discovered: false,
    active_exploitation: "suspected",
    blast_radius: 15,
    patch_available: false,
    live_patch_available: false,
    reboot_required: true,
  });

  const product = [kevEntry.vendorProject, kevEntry.product]
    .filter(Boolean)
    .join(" ");

  return {
    name: String(kevEntry.vulnerabilityName || "TBD — verify against vendor advisory"),
    type: "TBD",
    cvss_score: nvd?.cvss_score ?? null,
    cvss_vector: nvd?.cvss_vector ?? null,
    cisa_kev: true,
    cisa_kev_date: kevEntry.dateAdded || null,
    cisa_kev_due_date: kevEntry.dueDate || null,
    poc_available: null,
    poc_description: null,
    ai_discovered: null,
    ai_discovery_notes: null,
    ai_assisted_weaponization: null,
    active_exploitation: "suspected",
    affected: product || "See vendor advisory",
    affected_versions: [],
    vector: nvd?.description || kevEntry.shortDescription || "TBD",
    complexity: null,
    complexity_notes: null,
    patch_available: null,
    patch_required_reboot: null,
    live_patch_available: null,
    live_patch_tools: [],
    live_patch_notes: null,
    framework_control_gaps: {},
    atlas_refs: [],
    attack_refs: [],
    cwe_refs: nvd?.cwe_refs || [],
    known_ransomware_use: knownRansomware,
    epss_score: epss?.score ?? null,
    epss_percentile: epss?.percentile ?? null,
    epss_date: epss?.date ?? null,
    rwep_score,
    rwep_factors,
    verification_sources: [
      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      kevEntry.notes ? String(kevEntry.notes) : null,
    ].filter(Boolean),
    source_verified: false,
    last_updated: TODAY,
    last_verified: TODAY,
    _auto_imported: {
      source: "KEV discovery",
      imported_at: TODAY,
      curation_needed: [
        "type (LPE/RCE/SSRF/etc.)",
        "poc_available + poc_description (link to public PoC if any)",
        "ai_discovered + ai_assisted_weaponization classification",
        "active_exploitation upgrade from 'suspected' to 'confirmed' once a campaign is documented",
        "framework_control_gaps mapping (NIST/ISO/PCI/SOC 2 controls this defeats)",
        "atlas_refs + attack_refs categorization",
        "complexity assessment + complexity_notes",
        "patch_available + live_patch_available + live_patch_tools",
        "blast_radius numeric in rwep_factors (currently default 15)",
        "RWEP score recompute after the above land",
        "source_verified once a project maintainer has confirmed the upstream",
      ],
    },
  };
}

/**
 * Find KEV entries upstream that are not in local cve-catalog.json.
 * Returns an array of { id, op:"add", entry, severity } diffs capped
 * at `cap` items. Spill past the cap is logged on the diff object's
 * `_spilled` count so the PR body can mention it.
 */
function discoverNewKev(ctx, cap = DEFAULT_CAP) {
  const feed = readCachedJson(ctx.cacheDir, "kev", "known_exploited_vulnerabilities");
  if (!feed || !Array.isArray(feed.vulnerabilities)) {
    return { diffs: [], errors: 1, spilled: 0, summary: "KEV discovery: no cached feed" };
  }

  const localCves = new Set(
    Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k))
  );

  // Sort by dateAdded descending so the most recent additions are kept
  // when the cap clips the list.
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
      severity: "high",
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

// --- RFC discovery -----------------------------------------------------

async function fetchDatatracker(url) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Derive the set of IETF working-group acronyms the project already
 * cares about. Reads each entry in data/rfc-references.json, looks up
 * its Datatracker doc in the prefetch cache, extracts the group
 * acronym, returns the union.
 *
 * Two layers in the result:
 *
 *   1. DYNAMICALLY DERIVED — every WG that appears on a project-cited
 *      RFC's Datatracker record. Grows organically as catalog grows.
 *
 *   2. SEEDED — a curated baseline of IETF WGs that publish RFCs
 *      directly relevant to the project's mid-2026 threat model and
 *      compliance frameworks, even when the catalog doesn't yet cite
 *      one of their RFCs. Without this, RFC discovery would be blind
 *      to e.g. SCITT (supply chain) until a SCITT RFC was already
 *      manually added — defeating the point of discovery.
 *
 * SEED groups by project area:
 *
 *   Transport / crypto / PKI:
 *     tls, uta, cfrg, lamps, ipsecme
 *   HTTP / web / QUIC / API:
 *     httpbis, quic, ohai, privacypass, httpapi, core
 *   Identity / auth / SSO / cert mgmt / workload identity / constrained-env auth:
 *     oauth, gnap, jose, cose, cbor, kitten, emu, secevent, scim,
 *     acme, wimse, ace
 *   DNS security + privacy + DNS-based auth:
 *     dnsop, dprive, add, dance
 *   Supply chain + attestation + transparency + firmware/TEE:
 *     scitt, rats, suit, teep, trans
 *   Threat intel + security automation + operational telemetry:
 *     mile, sacm, i2nsf, opsawg, opsec
 *   Messaging + E2E + media:
 *     mls, moq, sframe
 *   Network / IoT mgmt + audit-grade time sync:
 *     anima, drip, iotops, netconf, netmod, ntp
 *   Data / schema / policy serialization:
 *     jsonschema
 *
 * Database protocols themselves (Postgres wire, MongoDB wire, etc.)
 * aren't IETF-standardized, so there's no "database" WG. The security
 * infrastructure databases USE — TLS for connections (tls/uta/lamps),
 * SASL/Kerberos auth (kitten/emu), workload identity (wimse), field
 * encryption (cose/cfrg/cbor), audit-trail time (ntp), cert validation
 * (lamps/dance/trans), and access-control sync (scim/oauth) — is all
 * already covered by the WGs above. jsonschema covers the DB+API+policy
 * schema validation layer.
 *
 * Reasoning for additions over the v0.9.2 seed:
 *   - wimse (Workload Identity in Multi-System Environments): federal
 *     zero-trust mandates + cloud-native workload identity are core to
 *     identity-assurance + sector-federal-government skills.
 *   - gnap (Grant Negotiation): OAuth successor; identity-assurance
 *     skill will eventually cite this.
 *   - ace + core: auth + REST for constrained environments — OT/ICS
 *     and IoT supply chain.
 *   - cbor: foundation for COSE, attestation tokens, SCITT receipts.
 *     Touches MCP trust + supply-chain integrity + RATS attestation.
 *   - trans (Certificate Transparency): compliance evidence for cert
 *     issuance; cross-cuts identity + framework-gap analysis.
 *   - ntp: audit trails need monotonic time. Required for the audit
 *     skills + breach-notification clocks (DORA, NYDFS, NIS2).
 *   - opsawg + opsec: operational security guidance and telemetry.
 *     Touches incident-response + threat-model-currency.
 *   - dance: DANE Authentication for Named Entities Enhancements —
 *     adds DNS-anchored TLS trust (complements lamps PKI).
 *   - netmod: NETCONF YANG models, often security-relevant for OT/ICS
 *     and network-segmentation policy.
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
  // Data / schema / policy serialization (DB validation, API schemas,
  // security-policy contract languages)
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
  // Always union the seed list — dynamic derivation covers the WGs we
  // already cite; the seed covers WGs we SHOULD watch for our skill
  // coverage even if no RFC from that WG is in the catalog yet.
  for (const g of SEED_RFC_GROUPS) groups.add(g);
  return groups;
}

function extractAcronymFromGroupUri(uri) {
  // Group URIs from Datatracker look like /api/v1/group/group/12345/.
  // Group acronym is in the doc object's full record but not in the URI.
  // Returning null means we have to live-fetch later.
  void uri;
  return null;
}

/**
 * Find recent RFCs published in any project-relevant working group
 * that aren't already in data/rfc-references.json. Queries Datatracker
 * live (small N — runs once per refresh, ~9 WG queries).
 *
 * @param {object} ctx
 * @param {object} opts  { cap?: number, sinceDays?: number }
 */
async function discoverNewRfcs(ctx, opts = {}) {
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
    // Datatracker filter: RFCs in this WG, time > cutoff. Ordered by time descending.
    const url =
      `https://datatracker.ietf.org/api/v1/doc/document/` +
      `?type=rfc&group__acronym=${encodeURIComponent(wg)}` +
      `&time__gt=${cutoff}&order_by=-time&limit=20&format=json`;
    const payload = await fetchDatatracker(url);
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

  // Dedupe across overlapping WG membership (an RFC can list multiple
  // groups). Keep the first occurrence (alphabetically first WG match).
  const seen = new Set();
  candidates = candidates.filter((c) => {
    if (seen.has(c.localKey)) return false;
    seen.add(c.localKey);
    return true;
  });

  // Sort by published time descending so we keep the most recent under the cap.
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
      _auto_imported: {
        source: `RFC discovery (IETF ${wg} working group)`,
        imported_at: TODAY,
        curation_needed: [
          "relevance — project-specific framing of how this RFC matters for mid-2026 threats",
          "lag_notes — what gaps remain or where the RFC falls short",
          "skills_referencing — list of skills that should cite this RFC",
          "errata_count — populate from <rfc-editor.org/errata/rfc${number}>",
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
  SEED_RFC_GROUPS,
  DEFAULT_CAP,
};
