"use strict";

/**
 * lib/citation-resolve.js
 *
 * Answers "is this CVE/RFC citation valid?" so an agent gets the answer FROM
 * exceptd instead of researching each citation against NVD / the IETF
 * datatracker by hand. Offline-first:
 *
 *   CVE: local catalog -> resolved cache -> (opt-in) one NVD lookup, cached.
 *   RFC: local index    -> resolved cache -> (opt-in) one datatracker lookup.
 *
 * The resolved cache lives at .cache/upstream/resolved/<kind>/<id>.json with a
 * 7-day TTL. The FIRST agent to resolve an uncatalogued id pays one network
 * call and writes the cache; sibling agents (and later offline runs) read it —
 * turning N agents x M citations of redundant lookups into one lookup per id.
 *
 * Network is opt-out: --air-gap / EXCEPTD_AIR_GAP=1 / { noNetwork:true } make
 * resolution offline-only (catalog + cache), returning status "unknown" with a
 * reason rather than reaching out. Network-resolved records are transient
 * (cache only) and are never written into the signed catalog.
 */

const fs = require("node:fs");
const path = require("node:path");

const PKG_ROOT = path.join(__dirname, "..");
const CVE_CATALOG = process.env.EXCEPTD_CVE_CATALOG || path.join(PKG_ROOT, "data", "cve-catalog.json");
const RFC_INDEX = process.env.EXCEPTD_RFC_INDEX || path.join(PKG_ROOT, "data", "rfc-references.json");
const RESOLVE_CACHE_DIR = process.env.EXCEPTD_RESOLVE_CACHE_DIR || path.join(PKG_ROOT, ".cache", "upstream", "resolved");
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // matches the prefetch freshness window

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const RFC_RE = /^(?:RFC[-\s]?)?(\d+)$/i;

let _cve = null;
let _rfc = null;
function cveCatalog() {
  if (!_cve) _cve = JSON.parse(fs.readFileSync(CVE_CATALOG, "utf8"));
  return _cve;
}
function rfcIndex() {
  if (!_rfc) _rfc = JSON.parse(fs.readFileSync(RFC_INDEX, "utf8"));
  return _rfc;
}

// --- resolved-id cache (atomic JSON files, TTL-bounded, best-effort) ---
function cachePath(kind, id) {
  // Read the env at call time so tests can isolate the cache per-case.
  const dir = process.env.EXCEPTD_RESOLVE_CACHE_DIR || RESOLVE_CACHE_DIR;
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(dir, kind, `${safe}.json`);
}
function cacheGet(kind, id) {
  try {
    const p = cachePath(kind, id);
    const st = fs.statSync(p);
    if (Date.now() - st.mtimeMs > CACHE_TTL_MS) return null;
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch { return null; }
}
function cachePut(kind, id, record) {
  try {
    const p = cachePath(kind, id);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const tmp = `${p}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(record));
    fs.renameSync(tmp, p); // atomic — concurrent agents can't read a half-written file
  } catch { /* cache is an optimization, never fatal */ }
}

function isAirGap(opts) {
  return !!(opts && opts.airGap) || process.env.EXCEPTD_AIR_GAP === "1";
}

/**
 * Resolve a CVE citation. Returns { id, kind:"cve", status, from, ... }.
 * status: published | rejected | disputed | fabricated | nonexistent | unknown
 * from:   format | catalog | cache | network | offline | error
 */
async function resolveCve(id, opts = {}) {
  const cveId = String(id || "").toUpperCase();
  const base = { id: cveId, kind: "cve" };

  if (!CVE_RE.test(cveId)) {
    return { ...base, status: "fabricated", from: "format",
      reason: "not the canonical CVE-YYYY-NNNN form — a non-numeric tail is a fabricated identifier" };
  }

  // 1. curated catalog (offline, authoritative for the ids it covers)
  const entry = cveCatalog()[cveId];
  if (entry && typeof entry === "object") {
    return {
      ...base,
      status: entry.status || "published",
      cvss: entry.cvss_score ?? null,
      kev: entry.cisa_kev ?? null,
      product: entry.name || entry.type || null,
      exploitation: entry.active_exploitation ?? null,
      from: "catalog",
    };
  }

  // 2. resolved cache (offline, warmed by a prior agent's lookup)
  const cached = cacheGet("cve", cveId);
  if (cached) return { ...cached, from: "cache" };

  // 3. offline / air-gap: cannot resolve uncatalogued ids without network
  if (isAirGap(opts)) {
    return { ...base, status: "unknown", from: "offline",
      reason: "air-gap: not in local catalog and no cached resolution — verify against NVD when online" };
  }
  if (opts.noNetwork) {
    return { ...base, status: "unknown", from: "offline",
      reason: "not in local catalog and no cached resolution (network disabled)" };
  }

  // 4. resolve once via NVD, then cache for sibling agents
  let validateCve;
  try { ({ validateCve } = require("../sources/validators/cve-validator.js")); }
  catch { return { ...base, status: "unknown", from: "error", reason: "cve validator unavailable" }; }
  let v;
  try { v = await validateCve(cveId, {}); }
  catch (e) { return { ...base, status: "unknown", from: "error", reason: e.message }; }

  if (v.status === "unreachable") {
    return { ...base, status: "unknown", from: "offline", reason: "NVD unreachable — retry online" };
  }
  let status;
  if (v.status === "rejected") status = "rejected";
  else if (v.status === "missing") status = "nonexistent";
  else if ((v.fetched?.cve_tags || []).some(t => /disputed/i.test(t)) || /disputed/i.test(v.fetched?.nvd_vuln_status || "")) status = "disputed";
  else status = "published";

  const record = {
    id: cveId, kind: "cve", status,
    cvss: v.fetched?.cvss_score ?? null,
    kev: v.fetched?.in_kev ?? null,
    nvd_vuln_status: v.fetched?.nvd_vuln_status ?? null,
    cve_tags: v.fetched?.cve_tags || [],
    source: "nvd",
    resolved_at: new Date().toISOString(),
  };
  cachePut("cve", cveId, record);
  return { ...record, from: "network" };
}

/**
 * Resolve an RFC citation. Returns { id, kind:"rfc", number, title, rfc_status,
 * found, from, ... }. The local index covers the whole current RFC series, so
 * number->title resolution is fully offline. Obsoleted/historic RFCs are
 * excluded from the index, so a not-found number is either obsoleted or
 * nonexistent; the optional network step disambiguates.
 */
async function resolveRfc(id, opts = {}) {
  const raw = String(id || "").trim();
  const m = raw.match(RFC_RE);
  const base = { id: raw, kind: "rfc" };
  if (!m) {
    return { ...base, found: false, status: "unknown", from: "format",
      reason: "not an RFC number — expected `RFC <n>` or a bare number" };
  }
  const num = Number(m[1]);
  const key = `RFC-${num}`;

  // 1. local index (offline, whole current series)
  const entry = rfcIndex()[key];
  if (entry && typeof entry === "object") {
    return {
      ...base, number: num, found: true,
      title: entry.title || null,
      rfc_status: entry.status || null,
      published: entry.published || null,
      obsoleted_by: entry.obsoleted_by || null,
      from: "index",
    };
  }

  // 2. resolved cache
  const cached = cacheGet("rfc", String(num));
  if (cached) return { ...cached, from: "cache" };

  // 3. offline: report the ambiguity rather than guessing
  if (isAirGap(opts) || opts.noNetwork) {
    return { ...base, number: num, found: false, status: "unknown", from: "offline",
      reason: "not in the local RFC index — likely obsoleted/historic (excluded from the index) or nonexistent; verify at datatracker.ietf.org when online" };
  }

  // 4. disambiguate obsoleted vs nonexistent via the datatracker, once + cached
  let validateRfc;
  try { ({ validateRfc } = require("../sources/validators/rfc-validator.js")); }
  catch { return { ...base, number: num, found: false, status: "unknown", from: "error", reason: "rfc validator unavailable" }; }
  let v;
  try { v = await validateRfc(key, {}); }
  catch (e) { return { ...base, number: num, found: false, status: "unknown", from: "error", reason: e.message }; }
  if (v.status === "unreachable") {
    return { ...base, number: num, found: false, status: "unknown", from: "offline", reason: "datatracker unreachable — retry online" };
  }
  const record = v.status === "missing"
    ? { id: raw, kind: "rfc", number: num, found: false, status: "nonexistent", source: "datatracker", resolved_at: new Date().toISOString() }
    : { id: raw, kind: "rfc", number: num, found: true, status: "obsoleted-or-historic",
        title: v.fetched?.title || null, source: "datatracker", resolved_at: new Date().toISOString(),
        note: "resolves at the datatracker but is absent from the local index (obsoleted/historic RFCs are excluded)" };
  cachePut("rfc", String(num), record);
  return { ...record, from: "network" };
}

module.exports = { resolveCve, resolveRfc };
