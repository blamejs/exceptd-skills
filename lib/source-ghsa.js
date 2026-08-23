"use strict";

/**
 * GitHub Advisory Database fetcher — GET https://api.github.com/advisories,
 * rate-limited to 60 req/hr unauthenticated and 5000 with GITHUB_TOKEN set.
 * EXCEPTD_GHSA_FIXTURE points at a JSON file of the same shape for offline runs.
 * Everything imported is a draft: entries carry `_auto_imported` + `_draft`, so
 * the strict validator warns rather than errors and editorial fields stay null.
 */

const https = require("https");
const fs = require("fs");
const { withRetry } = require("../vendor/blamejs/retry.js");

const GHSA_HOST = "api.github.com";
const GHSA_PATH = "/advisories?per_page=50&type=reviewed&sort=published&direction=desc";
const REQUEST_TIMEOUT_MS = 10000;
const USER_AGENT = "exceptd-security/source-ghsa (+https://exceptd.com)";

// Caps the streamed response so anything impersonating api.github.com cannot push
// unbounded bytes into RAM. Symmetric with getJsonOnce in lib/refresh-network.js.
function ghsaResponseCapBytes() {
  const env = parseInt(process.env.EXCEPTD_GHSA_RESPONSE_CAP_BYTES, 10);
  return Number.isFinite(env) && env > 0 ? env : 16 * 1024 * 1024;
}

/** Fields buildDiff watches going null while upstream still has the entry; mirrors lib/source-osv.js. */
const FIELD_DROPPED_WATCH = Object.freeze([
  // Only upstream-populated fields: normalize nulls the editorial ones on every
  // import, so watching them reports a regression on each re-import.
  "cvss_score",
  "cisa_kev_pending",
]);

/**
 * True when air-gap mode is requested; a source must then fall through to a
 * fixture or return the structured `air-gap: no fixture available` error.
 */
function isAirGap(opts) {
  if (opts && opts.airGap) return true;
  if (process.env.EXCEPTD_AIR_GAP === "1") return true;
  return false;
}

/**
 * Read EXCEPTD_GHSA_FIXTURE. Null when unset, `{ ok: true, advisories, source }`
 * on success, `{ ok: false, error, source }` on any failure — including a
 * non-object root, which would otherwise pass as an empty advisory list.
 */
function readFixture() {
  const fp = process.env.EXCEPTD_GHSA_FIXTURE;
  if (!fp) return null;
  let raw;
  try {
    raw = fs.readFileSync(fp, "utf8");
  } catch (e) {
    return { ok: false, error: `fixture: ${e.message}`, source: "offline" };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: `fixture: ${e.message}`, source: "offline" };
  }
  if (parsed == null || typeof parsed !== "object") {
    return { ok: false, error: `fixture: invalid root shape (got ${typeof parsed}); expected GHSA advisory object or array`, source: "offline" };
  }
  return { ok: true, advisories: Array.isArray(parsed) ? parsed : [parsed], source: "fixture" };
}

/**
 * One HTTPS GET against api.github.com. Rejects on retryable conditions so
 * withRetry's classifier picks them up, resolves an envelope on permanent ones.
 */
function ghsaRequestOnce({ path, headers, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const req = https.get({
      host: GHSA_HOST,
      path,
      headers,
      timeout: timeoutMs,
    }, (res) => {
      const status = res.statusCode;
      if (status === 429 || status === 503 ||
          (status >= 500 && status <= 599) ||
          status === 408 || status === 425) {
        res.resume();
        const err = new Error(`GHSA returned HTTP ${status}`);
        err.statusCode = status;
        const ra = res.headers["retry-after"];
        if (ra) {
          const secs = parseInt(ra, 10);
          if (Number.isFinite(secs)) err.retryAfterMs = secs * 1000;
        }
        return reject(err);
      }
      if (status !== 200) {
        res.resume();
        return resolve({ ok: false, error: `GHSA returned HTTP ${status}`, source: "offline" });
      }
      const chunks = [];
      let total = 0;
      const cap = ghsaResponseCapBytes();
      let capped = false;
      res.on("data", (c) => {
        total += c.length;
        if (total > cap) {
          capped = true;
          req.destroy(new Error(`GHSA response exceeds ${cap}-byte cap during streaming download`));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => {
        // The cap already routed through req.on("error"); resolving here settles twice.
        if (capped) return;
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
    req.on("timeout", () => {
      const err = new Error("timeout");
      err.code = "ETIMEDOUT";
      req.destroy(err);
    });
    req.on("error", (e) => {
      if (e && e.code && /^(ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|EPIPE|EAGAIN|ENOTFOUND|ENETUNREACH)$/.test(e.code)) {
        return reject(e);
      }
      resolve({ ok: false, error: e.message, source: "offline" });
    });
  });
}

/**
 * Fetch a page of advisories, backing off through withRetry on transient
 * failures. `{ ok: true, advisories, source: "github-api" | "fixture",
 * rate_limit? }` or `{ ok: false, error, source: "offline" }`.
 */
async function fetchAdvisories({ timeoutMs = REQUEST_TIMEOUT_MS, path = GHSA_PATH, token = null, airGap = false } = {}) {
  const fixture = readFixture();
  if (fixture) return fixture;
  if (isAirGap({ airGap })) {
    return { ok: false, error: "air-gap: no fixture available (set EXCEPTD_GHSA_FIXTURE)", source: "offline" };
  }
  const headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token || process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${token || process.env.GITHUB_TOKEN}`;
  }
  try {
    return await withRetry(() => ghsaRequestOnce({ path, headers, timeoutMs }), {
      maxAttempts: 3,
      baseDelayMs: 100,
      maxDelayMs: 2000,
      jitterFactor: 0.5,
    });
  } catch (e) {
    const status = typeof e?.statusCode === "number" ? e.statusCode : null;
    const error = status
      ? `GHSA returned HTTP ${status}`
      : `GHSA request failed: ${e.message || e}`;
    return { ok: false, error, status, source: "offline" };
  }
}

/**
 * Fetch a single advisory by CVE-* or GHSA-* id. A GHSA id addresses
 * /advisories/<ghsa-id>; the API is keyed by GHSA, so a CVE id goes via search.
 */
async function fetchAdvisoryById(id, opts = {}) {
  if (!id || typeof id !== "string") {
    return { ok: false, error: "id is required (CVE-* or GHSA-*)", source: "offline" };
  }
  id = id.trim();
  if (!id) {
    return { ok: false, error: "id is required (CVE-* or GHSA-*)", source: "offline" };
  }
  if (process.env.EXCEPTD_GHSA_FIXTURE) {
    const r = await fetchAdvisories(opts);
    if (!r.ok) return r;
    const want = id.toUpperCase();
    const match = r.advisories.find(a =>
      (a.ghsa_id && String(a.ghsa_id).toUpperCase() === want) ||
      (a.cve_id && String(a.cve_id).toUpperCase() === want)
    );
    if (!match) return { ok: false, error: `${id} not in fixture`, source: "fixture" };
    return { ok: true, advisories: [match], source: "fixture" };
  }
  // The full GHSA token shape, not a `/^GHSA-/` prefix: `GHSA-aaaa/../../meta`
  // would otherwise reach `/advisories/` as path-control segments.
  if (/^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i.test(id)) {
    return fetchAdvisories({ ...opts, path: `/advisories/${encodeURIComponent(id.toLowerCase())}` });
  }
  if (/^CVE-\d{4}-\d+$/i.test(id)) {
    return fetchAdvisories({ ...opts, path: `/advisories?cve_id=${encodeURIComponent(id.toUpperCase())}` });
  }
  // The accepted set mirrors seedSingleAdvisory in lib/refresh-external.js.
  return { ok: false, error: `unrecognized id format: ${id}. Expected one of: CVE-YYYY-NNNN, GHSA-* (routed through source-ghsa); MAL-* / SNYK-* / RUSTSEC-* / USN-* / PYSEC-* / GO-* / MGASA-* / UVI- (routed through source-osv).`, source: "offline" };
}

/**
 * The YYYY-MM-DD head of an upstream timestamp, or null — a non-string, a
 * non-ISO prefix or a year outside [1990, next year] all yield null.
 */
function safeDateSlice(value) {
  if (typeof value !== "string") return null;
  const head = value.slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(head)) return null;
  const year = parseInt(head.slice(0, 4), 10);
  const now = new Date().getUTCFullYear();
  if (!Number.isFinite(year) || year < 1990 || year > now + 1) return null;
  return head;
}

/**
 * Normalize a GHSA advisory into the catalog draft shape. Only what GHSA carries
 * authoritatively is populated; editorial fields stay null for a curator. Null
 * for an advisory with no CVE id — a GHSA-only advisory is not a CVE entry.
 */
function normalizeAdvisory(adv) {
  if (!adv || !adv.cve_id) return null;

  const ecosystems = new Set();
  const affected = [];
  const ecosystemPackages = [];
  const vulnList = Array.isArray(adv.vulnerabilities) ? adv.vulnerabilities : [];
  for (const v of vulnList) {
    if (v?.package?.ecosystem) ecosystems.add(v.package.ecosystem);
    if (v?.package?.name) {
      ecosystemPackages.push(`${v.package.ecosystem || "?"}:${v.package.name}`);
      if (v.vulnerable_version_range) {
        affected.push(`${v.package.name} ${v.vulnerable_version_range}`);
      }
    }
  }

  // cvss.score arrives as a string often enough to need coercion + a finite check.
  let cvssScore = null;
  if (adv.cvss != null && adv.cvss.score !== undefined && adv.cvss.score !== null) {
    const n = Number(adv.cvss.score);
    cvssScore = Number.isFinite(n) ? n : null;
  }
  const cvssVector = adv.cvss?.vector_string || null;
  const severity = (adv.severity || "").toLowerCase();
  // Derive a coarse type from package ecosystem when nothing better available.
  const inferredType = ecosystems.has("npm") ? "supply-chain-npm"
    : ecosystems.has("pip") ? "supply-chain-pypi"
    : ecosystems.has("maven") ? "supply-chain-maven"
    : ecosystems.has("rubygems") ? "supply-chain-gem"
    : "supply-chain-other";

  const publishedDate = safeDateSlice(adv.published_at);

  const refList = Array.isArray(adv.references) ? adv.references : [];

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
        ...refList.slice(0, 10),
      ],
      vendor_advisories: [
        {
          vendor: "GitHub Security Advisories",
          advisory_id: adv.ghsa_id || null,
          url: adv.html_url || `https://github.com/advisories?query=${encodeURIComponent(adv.cve_id)}`,
          severity: severity || null,
          published_date: publishedDate,
        },
      ],
      iocs: null,
      _auto_imported: true,
      _draft: true,
      _draft_reason: "Imported from GHSA on " + new Date().toISOString().slice(0, 10) + ". Editorial fields (framework_control_gaps, atlas_refs, attack_refs, iocs, vector, complexity, rwep_factors) require human review. Run `exceptd run sbom --evidence -` against an affected repo to gather IoCs; consult MITRE ATLAS + ATT&CK catalogs for refs.",
      _source_ghsa_id: adv.ghsa_id || null,
      _source_published_at: adv.published_at || null,
      // `withdrawn_at` marks a retracted advisory; carried as status, not imported live.
      ...(adv.withdrawn_at ? { status: "withdrawn", status_source: "ghsa:withdrawn_at", status_verified: new Date().toISOString().slice(0, 10) } : {}),
      last_updated: new Date().toISOString().slice(0, 10),
    },
  };
}

/**
 * Build a refresh diff for the refresh-external orchestrator. A CVE id absent
 * from the local catalog becomes a `_new_entry` diff; one already present whose
 * FIELD_DROPPED_WATCH value has gone null becomes a `field_dropped` diff.
 */
async function buildDiff(ctx) {
  const result = await fetchAdvisories({ airGap: ctx?.airGap });
  if (!result.ok) {
    return { status: "unreachable", diffs: [], errors: 1, summary: `GHSA fetch failed: ${result.error}` };
  }
  const cveCatalog = ctx.cveCatalog || {};
  const existing = new Set(Object.keys(cveCatalog).filter(k => /^CVE-/.test(k)));
  const diffs = [];
  let ghsaOnlySkipped = 0;
  for (const adv of result.advisories) {
    if (!adv.cve_id) { ghsaOnlySkipped++; continue; }
    const normalized = normalizeAdvisory(adv);
    if (!normalized) continue;
    if (existing.has(adv.cve_id)) {
      const before = cveCatalog[adv.cve_id] || {};
      const after = normalized[adv.cve_id];
      for (const field of FIELD_DROPPED_WATCH) {
        const had = before[field];
        const has = after[field];
        const wasPopulated = had !== null && had !== undefined && had !== "" && had !== false;
        const isNowEmpty = has === null || has === undefined;
        if (wasPopulated && isNowEmpty) {
          diffs.push({
            id: adv.cve_id,
            field,
            before: had,
            after: null,
            severity: null,
            source: "ghsa",
            variant: "field_dropped",
          });
        }
      }
      continue;
    }
    diffs.push({
      id: adv.cve_id,
      field: "_new_entry",
      before: null,
      after: normalized[adv.cve_id],
      severity: adv.severity || null,
      source: "ghsa",
    });
  }
  // diffs holds both kinds; count separately so a field_dropped is not a new CVE.
  const newCount = diffs.filter((d) => d.field === "_new_entry").length;
  const droppedCount = diffs.filter((d) => d.variant === "field_dropped").length;
  return {
    status: "ok",
    diffs,
    errors: 0,
    ghsa_only_skipped: ghsaOnlySkipped,
    summary: `GHSA returned ${result.advisories.length} reviewed advisories; ${newCount} new CVE ID(s) not yet in local catalog, ${droppedCount} field-dropped regression(s), ${ghsaOnlySkipped} ghsa_only_skipped.`,
    rate_limit: result.rate_limit || null,
  };
}

module.exports = {
  fetchAdvisories,
  fetchAdvisoryById,
  normalizeAdvisory,
  buildDiff,
  FIELD_DROPPED_WATCH,
  safeDateSlice,
};
