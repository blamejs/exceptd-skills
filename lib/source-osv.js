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

// OSV_HOST_OVERRIDE lets tests redirect the network call to a local HTTP
// server bound on 127.0.0.1:<port>. The override accepts either a bare
// `host:port` string or a full `http://host:port` URL. When set, the
// underlying request switches from `https` to `http` so the test server
// doesn't need a TLS cert. Production callers never set this.
const OSV_HOST = "api.osv.dev";
const REQUEST_TIMEOUT_MS = 10000;
const USER_AGENT = "exceptd-security/source-osv (+https://exceptd.com)";

// Identifier namespaces OSV uses as PRIMARY keys. GHSA-* is intentionally
// NOT in this list — `seedSingleAdvisory` in lib/refresh-external.js routes
// CVE-* and GHSA-* through `source-ghsa` because GHSA carries richer field
// coverage (cvss object, vulnerable_version_range string, ghsa_id linkage)
// than OSV's import of the same advisories. Keep this list in sync with the
// dispatcher in lib/refresh-external.js — adding a new prefix here is not
// enough; the dispatcher's --advisory regex must also accept it.
const OSV_ID_PREFIXES = [
  "MAL-",     // OSSF Malicious Packages
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
 * CVE-* identifier and NOT a GHSA-* identifier). Both CVE-* and GHSA-*
 * route through `source-ghsa` for richer field coverage.
 */
function isOsvId(id) {
  if (!id || typeof id !== "string") return false;
  const up = id.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(up)) return false;
  if (up.startsWith("GHSA-")) return false;
  return OSV_ID_PREFIXES.some((p) => up.startsWith(p));
}

/**
 * Resolve the OSV transport target. When OSV_HOST_OVERRIDE is set the
 * request switches to plain HTTP on the override host:port so test
 * harnesses can stand up a local server without TLS. Production omits the
 * override entirely and lands on api.osv.dev over HTTPS.
 */
function osvTransport() {
  const override = process.env.OSV_HOST_OVERRIDE;
  if (!override) return { mod: https, host: OSV_HOST, port: 443 };
  // Accept either "host:port" or a full URL.
  let raw = override.trim();
  if (/^https?:\/\//i.test(raw)) {
    const u = new URL(raw);
    return { mod: require("http"), host: u.hostname, port: parseInt(u.port, 10) || 80 };
  }
  const [h, p] = raw.split(":");
  return { mod: require("http"), host: h || "127.0.0.1", port: parseInt(p, 10) || 80 };
}

/**
 * Low-level GET against OSV. Resolves to { ok, record|error, source }.
 * Honors OSV_HOST_OVERRIDE for offline tests.
 */
function osvGet(reqPath, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const { mod, host, port } = osvTransport();
    const req = mod.get({
      host,
      port,
      path: reqPath,
      headers: {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
      },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        const status = res.statusCode;
        const error = status === 429
          ? `OSV rate-limited (HTTP 429)`
          : `OSV returned HTTP ${status}`;
        return resolve({ ok: false, error, status, source: "offline" });
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
    req.on("timeout", () => req.destroy(new Error("OSV request timed out")));
    req.on("error", (e) => resolve({ ok: false, error: e.message, source: "offline" }));
  });
}

/**
 * Low-level POST against OSV. Body is JSON-stringified.
 */
function osvPost(reqPath, body, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const { mod, host, port } = osvTransport();
    const req = mod.request({
      host,
      port,
      path: reqPath,
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
        const status = res.statusCode;
        const error = status === 429
          ? `OSV rate-limited (HTTP 429)`
          : `OSV returned HTTP ${status}`;
        return resolve({ ok: false, error, status, source: "offline" });
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
    req.on("timeout", () => req.destroy(new Error("OSV request timed out")));
    req.on("error", (e) => resolve({ ok: false, error: e.message, source: "offline" }));
    req.write(payload);
    req.end();
  });
}

/**
 * Read EXCEPTD_OSV_FIXTURE and return a structured envelope. Matches the
 * GHSA-source convention: on any failure (missing file, malformed JSON,
 * root not object/array) return `{ ok: false, error, source: "offline" }`
 * rather than throw — operators on the CLI surface get a structured error
 * instead of a Node stack trace.
 *
 * Returns:
 *   null                                          when env var is unset
 *   { ok: true, advisories: [...], source }       on success
 *   { ok: false, error, source: "offline" }       on any failure
 */
function readFixture() {
  const fp = process.env.EXCEPTD_OSV_FIXTURE;
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
  if (parsed == null || (typeof parsed !== "object")) {
    return { ok: false, error: `fixture: root must be an OSV record object or array (got ${typeof parsed})`, source: "offline" };
  }
  return { ok: true, advisories: Array.isArray(parsed) ? parsed : [parsed], source: "fixture" };
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
    return { ok: false, error: "id is required (MAL-*, SNYK-*, RUSTSEC-*, etc.)", source: "offline" };
  }
  // OSV.dev's /v1/vulns/{id} is case-sensitive — `mal-2026-3083` 404s while
  // `MAL-2026-3083` resolves. Uppercase at entry so operators piping
  // lowercase ids from grep/jq don't get a surprising 404 from the network
  // path. Fixture lookup already case-folds, so this normalization is a
  // no-op there but harmless.
  id = id.toUpperCase();
  const fixture = readFixture();
  if (fixture) {
    if (!fixture.ok) return fixture; // F1: structured error envelope
    const want = id;
    const match = fixture.advisories.find((rec) => {
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
    if (!fixture.ok) return fixture; // F1: structured error envelope
    // Best-effort fixture filtering: match any record whose `affected[]`
    // contains the requested package + ecosystem (+ version when set).
    const matches = fixture.advisories.filter((rec) => {
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
 * CVSS 3.1 base-score computation from a vector string. Implements Table 6
 * of the FIRST CVSS 3.1 specification. Used when an OSV record carries a
 * vector but no embedded numeric score (the common case for MAL-* records).
 * Returns null on malformed input.
 *
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */
function cvss3BaseScore(vector) {
  if (typeof vector !== "string") return null;
  const m = vector.match(/^CVSS:3\.\d\/(.+)$/);
  if (!m) return null;
  const parts = m[1].split("/");
  const metrics = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (!k || !v) return null;
    metrics[k] = v;
  }
  // Required metrics — bail if any are missing.
  for (const k of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    if (!metrics[k]) return null;
  }
  const AV_W = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC_W = { L: 0.77, H: 0.44 };
  const UI_W = { N: 0.85, R: 0.62 };
  const CIA_W = { H: 0.56, L: 0.22, N: 0 };
  // PR weights depend on Scope.
  const PR_W_U = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_W_C = { N: 0.85, L: 0.68, H: 0.5 };
  const scope = metrics.S;
  if (scope !== "U" && scope !== "C") return null;
  const av = AV_W[metrics.AV];
  const ac = AC_W[metrics.AC];
  const ui = UI_W[metrics.UI];
  const pr = (scope === "C" ? PR_W_C : PR_W_U)[metrics.PR];
  const c = CIA_W[metrics.C];
  const i = CIA_W[metrics.I];
  const a = CIA_W[metrics.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x == null)) return null;
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  let impact;
  if (scope === "U") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }
  if (impact <= 0) return 0.0;
  const exploitability = 8.22 * av * ac * pr * ui;
  let base;
  if (scope === "U") {
    base = Math.min(impact + exploitability, 10);
  } else {
    base = Math.min(1.08 * (impact + exploitability), 10);
  }
  // roundUp1: round up to one decimal (CVSS 3.1 §7.1).
  const rounded = Math.ceil(base * 10) / 10;
  if (!Number.isFinite(rounded) || rounded < 0 || rounded > 10) return null;
  return rounded;
}

/**
 * Pull a numeric CVSS score + vector out of an OSV severity[] entry. CVSS
 * vectors start with "CVSS:3.x/" or "CVSS:4.0/". When multiple vectors are
 * present (e.g. both V3 and V4), the highest version wins regardless of
 * array order. When the OSV record has no embedded numeric tail, the score
 * is computed from the vector itself via cvss3BaseScore(). Returns null
 * components when nothing parseable is present.
 */
function extractCvss(rec) {
  const sev = Array.isArray(rec?.severity) ? rec.severity : [];
  let score = null;
  let bestVector = null;
  let bestVersion = 0;
  for (const s of sev) {
    if (typeof s?.score !== "string") continue;
    const v = s.score.trim();
    // Bare numeric score (no vector prefix).
    const num = parseFloat(v);
    if (!Number.isNaN(num) && num >= 0 && num <= 10 && !v.includes("/")) {
      if (score == null) score = num;
      continue;
    }
    const m = v.match(/^CVSS:(\d+\.\d+)/);
    if (!m) continue;
    const ver = parseFloat(m[1]);
    if (ver > bestVersion) {
      bestVersion = ver;
      bestVector = v;
    }
  }
  // If we picked a vector, try to read an embedded score from the trailing
  // fragment (some Snyk records carry it as ".../9.3"). Otherwise compute
  // it from the vector for CVSS 3.x. CVSS 4.0 base-score derivation is
  // intentionally not implemented here — that's a v0.13 follow-up.
  if (bestVector && score == null) {
    const tail = bestVector.match(/\/(\d+(?:\.\d+)?)$/);
    if (tail) {
      const candidate = parseFloat(tail[1]);
      if (candidate >= 0 && candidate <= 10) score = candidate;
    }
    if (score == null && /^CVSS:3\./.test(bestVector)) {
      const computed = cvss3BaseScore(bestVector);
      if (computed != null) score = computed;
    }
  }
  return { score, vector: bestVector };
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

  // F6: dedupe verification_sources. OSV records frequently carry the
  // canonical osv.dev URL in references[] as well, which would otherwise
  // produce a duplicate alongside the prepended `osvUrl`.
  const verification_sources = Array.from(new Set([
    osvUrl,
    ...(/^CVE-/i.test(catalogKey) ? [`https://nvd.nist.gov/vuln/detail/${catalogKey}`] : []),
    ...refUrls.slice(0, 10),
  ]));

  // F5: EPSS coverage does not extend to non-CVE identifiers. Surface this
  // explicitly so curators know to re-query if MITRE later assigns a CVE
  // id to the entry. Wording mirrors the MAL-2026-3083 catalog entry.
  const isCveKey = /^CVE-/i.test(catalogKey);
  const epss_note = isCveKey
    ? null
    : "EPSS coverage does not extend to non-CVE identifiers. FIRST EPSS API only indexes CVE keys; MAL-* / SNYK-* / GHSA-* / RUSTSEC-* / etc. return no data. Re-query and populate epss_score when MITRE assigns a CVE id and the entry is renamed.";

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
      epss_note,
      epss_source: isCveKey
        ? `https://api.first.org/data/v1/epss?cve=${catalogKey}`
        : null,
      source_verified: published || today,
      verification_sources,
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
      unreachable_count: 0,
      normalize_error_count: 0,
      summary: "OSV: no ids requested (set ctx.osv_ids to seed a draft, or pass --advisory <MAL-...> for one-shot import).",
    };
  }
  const existingKeys = new Set(Object.keys(ctx.cveCatalog || {}));
  const diffs = [];
  // F7: distinguish unreachable (fetch failed, network or 5xx) from
  // normalize-rejected (record fetched but normalization produced null).
  // Operators triaging a refresh-report want to know whether to chase a
  // network outage or a malformed upstream record.
  let unreachable = 0;
  let normalizeErrors = 0;
  for (const id of ids) {
    const r = await fetchAdvisoryById(id);
    if (!r.ok) { unreachable++; continue; }
    const rec = r.advisories[0];
    if (!rec) { unreachable++; continue; }
    const normalized = normalizeAdvisory(rec);
    if (!normalized) { normalizeErrors++; continue; }
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
  const errors = unreachable + normalizeErrors;
  return {
    status: errors === 0 ? "ok" : errors === ids.length ? "unreachable" : "partial",
    diffs,
    errors,
    unreachable_count: unreachable,
    normalize_error_count: normalizeErrors,
    summary: `OSV fetched ${ids.length} id(s); ${diffs.length} new entry diff(s), ${unreachable} unreachable, ${normalizeErrors} normalize-rejected.`,
  };
}

module.exports = {
  fetchAdvisoryById,
  fetchAdvisoriesForPackage,
  normalizeAdvisory,
  buildDiff,
  isOsvId,
  extractCvss,
  cvss3BaseScore,
  OSV_ID_PREFIXES,
};
