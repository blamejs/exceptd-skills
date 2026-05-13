"use strict";

/**
 * lib/source-ghsa.js
 *
 * GitHub Advisory Database fetcher. The GHSA covers npm, PyPI, RubyGems,
 * Maven, NuGet, Go, Composer, Swift, Erlang, Pub, and Rust ecosystems in
 * one feed and is updated within hours of disclosure — much faster than
 * NVD (~10 days) or KEV (variable, often days).
 *
 * Endpoint: GET https://api.github.com/advisories
 *   - Unauthenticated: 60 req/hr (sufficient for nightly refresh)
 *   - Authenticated:   5000 req/hr (set GITHUB_TOKEN env var)
 *
 * Returns drafts — every imported entry carries `_auto_imported: true`
 * + `_draft: true` so the strict catalog validator treats them as
 * warnings, not errors. Editorial fields (framework_control_gaps,
 * iocs, atlas_refs) are left null until a human or AI assistant
 * fills them in via the seven-phase playbook flow.
 *
 * Honors EXCEPTD_GHSA_FIXTURE env var for offline testing — value is a
 * path to a JSON array matching the api.github.com/advisories shape.
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const https = require("https");
const fs = require("fs");

const GHSA_HOST = "api.github.com";
const GHSA_PATH = "/advisories?per_page=50&type=reviewed&sort=published&direction=desc";
const REQUEST_TIMEOUT_MS = 10000;
const USER_AGENT = "exceptd-security/source-ghsa (+https://exceptd.com)";

/**
 * Fetch a page of advisories (default: latest 50).
 *
 * Returns:
 *   { ok: true,  advisories: [...], source: "github-api" | "fixture", rate_limit?: { remaining, reset } }
 *   { ok: false, error, source: "offline" }
 */
async function fetchAdvisories({ timeoutMs = REQUEST_TIMEOUT_MS, path = GHSA_PATH, token = null } = {}) {
  if (process.env.EXCEPTD_GHSA_FIXTURE) {
    try {
      const arr = JSON.parse(fs.readFileSync(process.env.EXCEPTD_GHSA_FIXTURE, "utf8"));
      return { ok: true, advisories: Array.isArray(arr) ? arr : [arr], source: "fixture" };
    } catch (e) {
      return { ok: false, error: `fixture: ${e.message}`, source: "offline" };
    }
  }

  return new Promise((resolve) => {
    const headers = {
      "Accept": "application/vnd.github+json",
      "User-Agent": USER_AGENT,
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (token || process.env.GITHUB_TOKEN) {
      headers.Authorization = `Bearer ${token || process.env.GITHUB_TOKEN}`;
    }
    const req = https.get({
      host: GHSA_HOST,
      path,
      headers,
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ ok: false, error: `GHSA returned HTTP ${res.statusCode}`, source: "offline" });
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const advisories = Array.isArray(body) ? body : (body ? [body] : []);
          resolve({
            ok: true,
            advisories,
            source: "github-api",
            rate_limit: {
              remaining: parseInt(res.headers["x-ratelimit-remaining"], 10) || null,
              reset: parseInt(res.headers["x-ratelimit-reset"], 10) || null,
            },
          });
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
 * Fetch a single advisory by ID — accepts CVE-* or GHSA-* identifiers.
 *
 * GHSA-IDs hit /advisories/<ghsa-id> directly. CVE-IDs require a search
 * since the API is keyed by GHSA. We fall back to a query-string search.
 */
async function fetchAdvisoryById(id, opts = {}) {
  if (!id || typeof id !== "string") {
    return { ok: false, error: "id is required (CVE-* or GHSA-*)", source: "offline" };
  }
  if (process.env.EXCEPTD_GHSA_FIXTURE) {
    const r = await fetchAdvisories(opts);
    if (!r.ok) return r;
    const match = r.advisories.find(a =>
      (a.ghsa_id && a.ghsa_id.toUpperCase() === id.toUpperCase()) ||
      (a.cve_id && a.cve_id.toUpperCase() === id.toUpperCase())
    );
    if (!match) return { ok: false, error: `${id} not in fixture`, source: "fixture" };
    return { ok: true, advisories: [match], source: "fixture" };
  }
  if (/^GHSA-/i.test(id)) {
    return fetchAdvisories({ ...opts, path: `/advisories/${id.toLowerCase()}` });
  }
  if (/^CVE-\d{4}-\d+$/i.test(id)) {
    return fetchAdvisories({ ...opts, path: `/advisories?cve_id=${encodeURIComponent(id.toUpperCase())}` });
  }
  return { ok: false, error: `unrecognized id format (expected CVE-YYYY-NNNN or GHSA-*): ${id}`, source: "offline" };
}

/**
 * Normalize a GHSA advisory object to the exceptd catalog draft shape.
 * Fields the GHSA carries authoritatively: cve_id, ghsa_id, summary,
 * severity, cvss, vulnerabilities (package + version range), published_at,
 * references. Editorial fields (framework_control_gaps, iocs, atlas_refs,
 * attack_refs, rwep_factors) are LEFT NULL — drafts. The seven-phase
 * playbook flow OR a human reviewer fills these in.
 *
 * Returns null if the advisory lacks a CVE ID (we don't import GHSA-only
 * advisories into the CVE catalog — they belong in a separate GHSA index
 * which is a v0.13 design).
 */
function normalizeAdvisory(adv) {
  if (!adv || !adv.cve_id) return null;

  const ecosystems = new Set();
  const affected = [];
  const ecosystemPackages = [];
  for (const v of (adv.vulnerabilities || [])) {
    if (v?.package?.ecosystem) ecosystems.add(v.package.ecosystem);
    if (v?.package?.name) {
      ecosystemPackages.push(`${v.package.ecosystem || "?"}:${v.package.name}`);
      if (v.vulnerable_version_range) {
        affected.push(`${v.package.name} ${v.vulnerable_version_range}`);
      }
    }
  }

  const cvssScore = adv.cvss?.score ?? null;
  const cvssVector = adv.cvss?.vector_string || null;
  const severity = (adv.severity || "").toLowerCase();
  // Derive a coarse type from package ecosystem when nothing better available.
  const inferredType = ecosystems.has("npm") ? "supply-chain-npm"
    : ecosystems.has("pip") ? "supply-chain-pypi"
    : ecosystems.has("maven") ? "supply-chain-maven"
    : ecosystems.has("rubygems") ? "supply-chain-gem"
    : "supply-chain-other";

  return {
    [adv.cve_id]: {
      name: adv.summary || adv.cve_id,
      type: inferredType,
      cvss_score: cvssScore,
      cvss_vector: cvssVector,
      cisa_kev: false,
      cisa_kev_date: null,
      cisa_kev_pending: severity === "critical",
      cisa_kev_pending_reason: severity === "critical"
        ? `GHSA severity critical (CVSS ${cvssScore}). KEV listing typically follows for critical advisories with confirmed exploitation; verify before publish.`
        : null,
      poc_available: null,
      poc_description: null,
      ai_discovered: null,
      ai_assisted_weaponization: null,
      active_exploitation: severity === "critical" ? "suspected" : "unknown",
      affected: ecosystemPackages.join(", ") || null,
      affected_versions: affected,
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
      rwep_notes: "Auto-imported from GHSA. RWEP factors require editorial review before this entry passes the strict catalog gate.",
      epss_score: null,
      epss_percentile: null,
      epss_date: null,
      epss_source: adv.cve_id ? `https://api.first.org/data/v1/epss?cve=${adv.cve_id}` : null,
      source_verified: new Date().toISOString().slice(0, 10),
      verification_sources: [
        ...(adv.html_url ? [adv.html_url] : []),
        ...(adv.cve_id ? [`https://nvd.nist.gov/vuln/detail/${adv.cve_id}`] : []),
        ...(adv.references || []).slice(0, 10),
      ],
      vendor_advisories: [
        {
          vendor: "GitHub Security Advisories",
          advisory_id: adv.ghsa_id || null,
          url: adv.html_url || `https://github.com/advisories?query=${encodeURIComponent(adv.cve_id)}`,
          severity: severity || null,
          published_date: (adv.published_at || "").slice(0, 10) || null,
        },
      ],
      iocs: null,
      _auto_imported: true,
      _draft: true,
      _draft_reason: "Imported from GHSA on " + new Date().toISOString().slice(0, 10) + ". Editorial fields (framework_control_gaps, atlas_refs, attack_refs, iocs, vector, complexity, rwep_factors) require human review. Run `exceptd run sbom --evidence -` against an affected repo to gather IoCs; consult MITRE ATLAS + ATT&CK catalogs for refs.",
      _source_ghsa_id: adv.ghsa_id || null,
      _source_published_at: adv.published_at || null,
      last_updated: new Date().toISOString().slice(0, 10),
    },
  };
}

/**
 * Build a refresh diff for the existing refresh-external orchestrator.
 * Compares the latest 50 advisories' CVE IDs against the local catalog;
 * any CVE ID not in the catalog becomes an "add" diff.
 */
async function buildDiff(ctx) {
  const result = await fetchAdvisories({});
  if (!result.ok) {
    return { status: "unreachable", diffs: [], errors: 1, summary: `GHSA fetch failed: ${result.error}` };
  }
  const existing = new Set(Object.keys(ctx.cveCatalog || {}).filter(k => /^CVE-/.test(k)));
  const diffs = [];
  for (const adv of result.advisories) {
    if (!adv.cve_id) continue;
    if (existing.has(adv.cve_id)) continue;
    const normalized = normalizeAdvisory(adv);
    if (!normalized) continue;
    diffs.push({
      id: adv.cve_id,
      field: "_new_entry",
      before: null,
      after: normalized[adv.cve_id],
      severity: adv.severity || null,
      source: "ghsa",
    });
  }
  return {
    status: "ok",
    diffs,
    errors: 0,
    summary: `GHSA returned ${result.advisories.length} reviewed advisories; ${diffs.length} new CVE ID(s) not yet in local catalog.`,
    rate_limit: result.rate_limit || null,
  };
}

module.exports = { fetchAdvisories, fetchAdvisoryById, normalizeAdvisory, buildDiff };
