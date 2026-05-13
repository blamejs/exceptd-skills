"use strict";

/**
 * lib/source-osv.js
 *
 * OSV.dev fetcher. OSV aggregates OSSF Malicious Packages (MAL-*), Snyk
 * (SNYK-*), GitHub Advisory Database (GHSA-*), RustSec (RUSTSEC-*),
 * Mageia (MGASA-*), Go Vuln DB (GO-*), Ubuntu USN (USN-*), and several
 * other ecosystems into a single unauthenticated API.
 *
 * Endpoints:
 *   GET  https://api.osv.dev/v1/vulns/{id}
 *     Fetch by OSV id. CVE-* is NOT a primary key — CVE numbers live
 *     under `aliases` on records whose primary id is GHSA-*, MAL-*, etc.
 *   POST https://api.osv.dev/v1/query
 *     Body { "package": { "name": "...", "ecosystem": "..." }
 *          [,"version": "..."] }
 *     Lists vulns for a package (optionally filtered to a version).
 *
 * Why this matters: MAL-* (OSSF Malicious Packages) is the canonical
 * namespace for package-compromise events that don't have a CVE yet.
 * The elementary-data PyPI worm (MAL-2026-3083) is the catalog's
 * reference example of that class.
 *
 * Returns drafts — every imported entry carries `_auto_imported: true`
 * + `_draft: true` so the strict catalog validator treats them as
 * warnings, not errors. Editorial fields (framework_control_gaps,
 * atlas_refs, attack_refs, rwep_factors) remain null until a human or
 * AI assistant fills them in via the cve-curation skill / seven-phase
 * playbook flow.
 *
 * Honors EXCEPTD_OSV_FIXTURE env var for offline testing — value is a
 * path to a JSON file containing either a single OSV record or an
 * array of OSV records. Matches the GHSA fixture pattern.
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const https = require("https");
const fs = require("fs");

const OSV_HOST = "api.osv.dev";
const REQUEST_TIMEOUT_MS = 10000;
const USER_AGENT = "exceptd-security/source-osv (+https://exceptd.com)";

// Identifier namespaces OSV uses as PRIMARY keys (i.e. that route through
// this module rather than GHSA's CVE-search path). Keep this list in sync
// with the dispatcher in lib/refresh-external.js — adding a new prefix
// here is not enough; the dispatcher's --advisory regex must also accept it.
const OSV_ID_PREFIXES = [
  "MAL-",     // OSSF Malicious Packages
  "GHSA-",    // GitHub Security Advisories (OSV import)
  "SNYK-",    // Snyk
  "RUSTSEC-", // RustSec
  "GO-",      // Go vuln DB
  "USN-",     // Ubuntu Security Notices
  "UVI-",     // Ubuntu (alternate prefix used in some OSV mirrors)
  "MGASA-",   // Mageia
  "OSV-",     // OSV-internal
  "PYSEC-",   // Python Security
  "DLA-",     // Debian LTS
  "DSA-",     // Debian Security
  "DTSA-",    // Debian Testing Security
  "BIT-",     // Bitnami
  "ALAS-",    // Amazon Linux
  "ALSA-",    // AlmaLinux
  "RHSA-",    // Red Hat
  "RLSA-",    // Rocky Linux
  "SUSE-",    // SUSE
  "OPENSUSE-", // openSUSE
];

/**
 * Return true when `id` looks like an OSV-native primary key (i.e. NOT a
 * CVE-* identifier). CVE-* identifiers continue to route through the GHSA
 * source because GHSA carries richer field coverage for CVE-keyed records.
 */
function isOsvId(id) {
  if (!id || typeof id !== "string") return false;
  const up = id.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(up)) return false;
  return OSV_ID_PREFIXES.some((p) => up.startsWith(p));
}

/**
 * Low-level HTTPS GET against OSV. Resolves to { ok, record|error, source }.
 */
function osvGet(path, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const req = https.get({
      host: OSV_HOST,
      path,
      headers: {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
      },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ ok: false, error: `OSV returned HTTP ${res.statusCode}`, source: "offline" });
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          resolve({ ok: true, record: body, source: "osv-api" });
        } catch (e) {
          resolve({ ok: false, error: `parse: ${e.message}`, source: "offline" });
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ ok: false, error: e.message, source: "offline" }));
  });
}

/**
 * Low-level HTTPS POST against OSV. Body is JSON-stringified.
 */
function osvPost(path, body, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const req = https.request({
      host: OSV_HOST,
      path,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": payload.length,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
      },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ ok: false, error: `OSV returned HTTP ${res.statusCode}`, source: "offline" });
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          resolve({ ok: true, record: parsed, source: "osv-api" });
        } catch (e) {
          resolve({ ok: false, error: `parse: ${e.message}`, source: "offline" });
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ ok: false, error: e.message, source: "offline" }));
    req.write(payload);
    req.end();
  });
}

/**
 * Read EXCEPTD_OSV_FIXTURE and return an array of OSV records. Accepts
 * either a single object or an array on disk.
 */
function readFixture() {
  const fp = process.env.EXCEPTD_OSV_FIXTURE;
  if (!fp) return null;
  const raw = JSON.parse(fs.readFileSync(fp, "utf8"));
  return Array.isArray(raw) ? raw : [raw];
}

/**
 * Fetch a single OSV record by id (MAL-*, GHSA-*, SNYK-*, RUSTSEC-*, etc.).
 *
 * Returns shape matches source-ghsa.fetchAdvisoryById:
 *   { ok: true,  advisories: [<osv_record>], source: "osv-api" | "fixture" }
 *   { ok: false, error, source: "offline" | "fixture" }
 */
async function fetchAdvisoryById(id, opts = {}) {
  if (!id || typeof id !== "string") {
    return { ok: false, error: "id is required (MAL-*, GHSA-*, SNYK-*, etc.)", source: "offline" };
  }
  const fixture = readFixture();
  if (fixture) {
    const want = id.toUpperCase();
    const match = fixture.find((rec) => {
      const recId = (rec && rec.id) ? String(rec.id).toUpperCase() : null;
      if (recId === want) return true;
      const aliases = Array.isArray(rec?.aliases) ? rec.aliases.map((a) => String(a).toUpperCase()) : [];
      return aliases.includes(want);
    });
    if (!match) return { ok: false, error: `${id} not in fixture`, source: "fixture" };
    return { ok: true, advisories: [match], source: "fixture" };
  }
  const result = await osvGet(`/v1/vulns/${encodeURIComponent(id)}`, opts.timeoutMs);
  if (!result.ok) return result;
  return { ok: true, advisories: [result.record], source: "osv-api" };
}

/**
 * List advisories for a package, optionally filtered to a specific version.
 * v0.12.10 ships the network path; bulk-import callers are a v0.13 follow-up.
 */
async function fetchAdvisoriesForPackage(name, ecosystem, version, opts = {}) {
  if (!name || !ecosystem) {
    return { ok: false, error: "name and ecosystem are required", source: "offline" };
  }
  const fixture = readFixture();
  if (fixture) {
    // Best-effort fixture filtering: match any record whose `affected[]`
    // contains the requested package + ecosystem (+ version when set).
    const matches = fixture.filter((rec) => {
      const affected = Array.isArray(rec?.affected) ? rec.affected : [];
      return affected.some((a) => {
        const pkg = a?.package || {};
        if ((pkg.name || "").toLowerCase() !== name.toLowerCase()) return false;
        if ((pkg.ecosystem || "").toLowerCase() !== ecosystem.toLowerCase()) return false;
        if (!version) return true;
        const versions = Array.isArray(a.versions) ? a.versions : [];
        return versions.includes(version);
      });
    });
    return { ok: true, advisories: matches, source: "fixture" };
  }
  const body = { package: { name, ecosystem } };
  if (version) body.version = version;
  const r = await osvPost("/v1/query", body, opts.timeoutMs);
  if (!r.ok) return r;
  const vulns = Array.isArray(r.record?.vulns) ? r.record.vulns : [];
  return { ok: true, advisories: vulns, source: "osv-api" };
}

/**
 * Pick the catalog key for an OSV record. If `aliases` contains a CVE-*
 * value, prefer that (preserving the existing CVE-keyed convention).
 * Otherwise return the OSV id verbatim — MAL-*, SNYK-*, RUSTSEC-*, etc.
 */
function pickCatalogKey(rec) {
  if (!rec || !rec.id) return null;
  const aliases = Array.isArray(rec.aliases) ? rec.aliases : [];
  const cve = aliases.find((a) => /^CVE-\d{4}-\d+$/i.test(String(a)));
  return cve ? String(cve).toUpperCase() : String(rec.id);
}

/**
 * Pull a numeric CVSS score out of an OSV severity[] entry (CVSS v3 / v4
 * vector strings start with "CVSS:3.x/" or "CVSS:4.0/"). Returns null if
 * no parseable score is present.
 */
function extractCvss(rec) {
  const sev = Array.isArray(rec?.severity) ? rec.severity : [];
  let score = null;
  let vector = null;
  for (const s of sev) {
    if (typeof s?.score !== "string") continue;
    const v = s.score.trim();
    // Bare numeric score
    const num = parseFloat(v);
    if (!Number.isNaN(num) && num >= 0 && num <= 10 && !v.includes("/")) {
      if (score == null) score = num;
      continue;
    }
    // CVSS vector — accept the highest-version vector we see.
    if (/^CVSS:[34]/.test(v)) {
      vector = v;
      // Try to parse the score out of the trailing fragment if encoded
      // as "CVSS:3.1/AV:.../9.3" — most OSV records don't embed it here,
      // but some Snyk-imported records do.
      const m = v.match(/\/(\d+(?:\.\d+)?)$/);
      if (m && score == null) {
        const candidate = parseFloat(m[1]);
        if (candidate >= 0 && candidate <= 10) score = candidate;
      }
    }
  }
  return { score, vector };
}

/**
 * Coarse package-ecosystem inference for the catalog `type` field. Mirrors
 * the same heuristic used by source-ghsa.
 */
function inferType(rec) {
  const ecos = new Set();
  for (const a of (rec?.affected || [])) {
    if (a?.package?.ecosystem) ecos.add(String(a.package.ecosystem).toLowerCase());
  }
  if (ecos.has("pypi") || ecos.has("pip")) return "supply-chain-pypi";
  if (ecos.has("npm")) return "supply-chain-npm";
  if (ecos.has("maven")) return "supply-chain-maven";
  if (ecos.has("rubygems")) return "supply-chain-gem";
  if (ecos.has("crates.io") || ecos.has("cargo")) return "supply-chain-rust";
  if (ecos.has("go")) return "supply-chain-go";
  if (ecos.has("nuget")) return "supply-chain-nuget";
  if (ecos.has("packagist")) return "supply-chain-composer";
  return "supply-chain-other";
}

/**
 * Normalize an OSV record into the exceptd catalog draft shape. Returns
 * `{ [catalogKey]: <draft-entry> }` so callers can spread it into the
 * catalog object directly. Returns null if the record is unusable.
 *
 * Editorial fields (framework_control_gaps, atlas_refs, attack_refs,
 * rwep_factors) are left null — the seven-phase playbook flow or a human
 * reviewer fills these in. `_auto_imported: true` + `_draft: true` flags
 * mark the entry for the strict catalog validator (warn, not error).
 */
function normalizeAdvisory(rec) {
  if (!rec || !rec.id) return null;
  const catalogKey = pickCatalogKey(rec);
  if (!catalogKey) return null;

  const aliases = Array.isArray(rec.aliases) ? rec.aliases.slice() : [];
  // If the catalog key came from aliases (CVE-*), put the OSV id back into
  // the aliases array so it stays discoverable.
  if (catalogKey !== rec.id && !aliases.includes(rec.id)) aliases.push(rec.id);

  const { score, vector } = extractCvss(rec);

  const affectedPackages = [];
  const affectedVersions = [];
  for (const a of (rec.affected || [])) {
    const pkg = a?.package || {};
    if (pkg.name && pkg.ecosystem) {
      affectedPackages.push(`${pkg.ecosystem}:${pkg.name}`);
    }
    const versions = Array.isArray(a.versions) ? a.versions : [];
    for (const v of versions) {
      affectedVersions.push(`${pkg.name || "?"} == ${v}`);
    }
    // Range bounds: surface "introduced/fixed" pairs as a textual range.
    const ranges = Array.isArray(a.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r.events) ? r.events : [];
      const intro = events.find((e) => e.introduced)?.introduced;
      const fixed = events.find((e) => e.fixed)?.fixed;
      if (intro || fixed) {
        affectedVersions.push(`${pkg.name || "?"} >= ${intro || "0"}` + (fixed ? `, < ${fixed}` : ""));
      }
    }
  }

  // IoC seeding from database_specific.iocs if present (some Snyk + StepSec
  // imported records carry this). Domains + URLs land in c2_indicators so
  // an operator scanning a repo has something to grep for immediately.
  const dsIocs = rec?.database_specific?.iocs || null;
  let iocs = null;
  if (dsIocs && (Array.isArray(dsIocs.domains) || Array.isArray(dsIocs.urls))) {
    const c2 = [];
    if (Array.isArray(dsIocs.domains)) c2.push(...dsIocs.domains.map((d) => `domain: ${d}`));
    if (Array.isArray(dsIocs.urls)) c2.push(...dsIocs.urls.map((u) => `url: ${u}`));
    iocs = { c2_indicators: c2 };
  }

  // Reference URLs — OSV `references` is `[{ type, url }, ...]`.
  const refUrls = [];
  for (const r of (rec.references || [])) {
    if (r && typeof r.url === "string") refUrls.push(r.url);
  }

  // Severity wording from CVSS / qualitative hint.
  const severityWord = score != null && score >= 9.0 ? "critical"
    : score != null && score >= 7.0 ? "high"
    : score != null && score >= 4.0 ? "medium"
    : score != null ? "low"
    : null;

  const pending = severityWord === "critical" || (score != null && score >= 9.0);

  const today = new Date().toISOString().slice(0, 10);
  const published = (rec.published || "").slice(0, 10) || null;
  const modified = (rec.modified || "").slice(0, 10) || null;

  // OSV.dev canonical advisory URL — used as the primary vendor advisory.
  const osvUrl = `https://osv.dev/vulnerability/${encodeURIComponent(rec.id)}`;

  return {
    [catalogKey]: {
      name: rec.summary || rec.id,
      type: inferType(rec),
      cvss_score: score,
      cvss_vector: vector,
      cisa_kev: false,
      cisa_kev_date: null,
      cisa_kev_pending: pending,
      cisa_kev_pending_reason: pending
        ? `OSV severity critical (CVSS ${score}). KEV listing typically follows for critical advisories with confirmed exploitation; verify before publish.`
        : null,
      poc_available: null,
      poc_description: null,
      ai_discovered: null,
      ai_assisted_weaponization: null,
      active_exploitation: severityWord === "critical" ? "suspected" : "unknown",
      affected: affectedPackages.join(", ") || null,
      affected_versions: affectedVersions,
      vector: null,
      complexity: null,
      patch_available: null,
      patch_required_reboot: false,
      live_patch_available: null,
      live_patch_tools: [],
      framework_control_gaps: null,
      atlas_refs: [],
      attack_refs: [],
      rwep_score: null,
      rwep_factors: null,
      rwep_notes: "Auto-imported from OSV.dev. RWEP factors require editorial review before this entry passes the strict catalog gate.",
      epss_score: null,
      epss_percentile: null,
      epss_date: null,
      epss_source: /^CVE-/i.test(catalogKey)
        ? `https://api.first.org/data/v1/epss?cve=${catalogKey}`
        : null,
      source_verified: published || today,
      verification_sources: [
        osvUrl,
        ...(/^CVE-/i.test(catalogKey) ? [`https://nvd.nist.gov/vuln/detail/${catalogKey}`] : []),
        ...refUrls.slice(0, 10),
      ],
      vendor_advisories: [
        {
          vendor: "OSV.dev",
          advisory_id: rec.id,
          url: osvUrl,
          severity: severityWord,
          published_date: published,
        },
      ],
      iocs,
      aliases,
      _auto_imported: true,
      _draft: true,
      _draft_reason: "Imported from OSV.dev on " + today + ". Editorial fields (framework_control_gaps, atlas_refs, attack_refs, iocs, vector, complexity, rwep_factors) require human review. Run `exceptd run sbom --evidence -` against an affected repo to gather IoCs; consult MITRE ATLAS + ATT&CK catalogs for refs.",
      _source_osv_id: rec.id,
      _source_published_at: rec.published || null,
      last_updated: modified || today,
    },
  };
}

/**
 * Build a refresh diff for the refresh-external orchestrator. v0.12.10
 * supports targeted seeding: when `ctx.osv_ids` is populated, fetch each
 * id and emit one `_new_entry` diff per record that isn't already in the
 * local catalog. The broader package-watchlist path (bulk import from
 * a watched-packages list) is deferred to v0.13.
 */
async function buildDiff(ctx) {
  const ids = Array.isArray(ctx?.osv_ids) ? ctx.osv_ids : [];
  if (ids.length === 0) {
    return {
      status: "ok",
      diffs: [],
      errors: 0,
      summary: "OSV: no ids requested (set ctx.osv_ids to seed a draft, or pass --advisory <MAL-...> for one-shot import).",
    };
  }
  const existingKeys = new Set(Object.keys(ctx.cveCatalog || {}));
  const diffs = [];
  let errors = 0;
  for (const id of ids) {
    const r = await fetchAdvisoryById(id);
    if (!r.ok) { errors++; continue; }
    const rec = r.advisories[0];
    if (!rec) { errors++; continue; }
    const normalized = normalizeAdvisory(rec);
    if (!normalized) { errors++; continue; }
    const key = Object.keys(normalized)[0];
    if (existingKeys.has(key)) continue;
    diffs.push({
      id: key,
      field: "_new_entry",
      before: null,
      after: normalized[key],
      severity: normalized[key].cvss_score != null && normalized[key].cvss_score >= 9.0 ? "critical" : null,
      source: "osv",
    });
  }
  return {
    status: errors === 0 ? "ok" : errors === ids.length ? "unreachable" : "partial",
    diffs,
    errors,
    summary: `OSV fetched ${ids.length} id(s); ${diffs.length} new entry diff(s), ${errors} failure(s).`,
  };
}

module.exports = {
  fetchAdvisoryById,
  fetchAdvisoriesForPackage,
  normalizeAdvisory,
  buildDiff,
  isOsvId,
  OSV_ID_PREFIXES,
};
