"use strict";

/**
 * Answers "is this CVE/RFC citation valid?" offline-first: local catalog or
 * index, then the resolved cache, then one opt-in network lookup. --air-gap /
 * EXCEPTD_AIR_GAP=1 / { noNetwork:true } make it offline-only, returning status
 * "unknown". Network-resolved records live in the cache only and never enter
 * the signed catalog.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

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

// The resolved-id cache feeds security verdicts, so a record is trusted only when
// its `_digest` matches and its own `resolved_at` is inside the freshness window —
// an in-place edit cannot launder a rejected citation into "published".
function cachePath(kind, id) {
  // Read the env at call time so tests can isolate the cache per-case.
  const dir = process.env.EXCEPTD_RESOLVE_CACHE_DIR || RESOLVE_CACHE_DIR;
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(dir, kind, `${safe}.json`);
}
// sha256 over canonical bytes (sorted keys, `_digest` excluded); covers `resolved_at`.
function recordDigest(record) {
  const canon = {};
  for (const k of Object.keys(record).sort()) {
    if (k === "_digest") continue;
    canon[k] = record[k];
  }
  return crypto.createHash("sha256").update(JSON.stringify(canon)).digest("hex");
}
function cacheGet(kind, id) {
  try {
    const p = cachePath(kind, id);
    const record = JSON.parse(fs.readFileSync(p, "utf8"));
    if (!record || typeof record !== "object") return null;
    if (typeof record._digest !== "string" || record._digest !== recordDigest(record)) return null;
    // resolved_at, not file mtime which `touch` resets; a future-dated record is poisoning.
    const ts = Date.parse(record.resolved_at || "");
    if (!Number.isFinite(ts)) return null;
    const age = Date.now() - ts;
    if (age < -60_000 || age > CACHE_TTL_MS) return null;
    // The digest proves self-consistency, not that this is the record FOR this
    // id/kind — a valid record filed under another name must not be served.
    if (record.kind !== kind) return null;
    if (kind === "cve") {
      if (typeof record.id !== "string" || record.id.toUpperCase() !== String(id).toUpperCase()) return null;
    } else if (kind === "rfc") {
      if (Number(record.number) !== Number(id)) return null;
    }
    delete record._digest; // internal integrity field — never surface it
    return record;
  } catch { return null; }
}
function cachePut(kind, id, record) {
  try {
    const p = cachePath(kind, id);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const signed = { ...record };
    signed._digest = recordDigest(signed);
    // Random suffix, not just pid: an in-process fan-out would race the same tmp path.
    const tmp = `${p}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(signed));
    fs.renameSync(tmp, p); // atomic — concurrent readers never see a half-written file
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
  // Trim before the format test so a whitespace-only id is malformed, not fed to CVE_RE.
  const cveId = String(id || "").trim().toUpperCase();
  const base = { id: cveId, kind: "cve" };

  if (!CVE_RE.test(cveId)) {
    return { ...base, status: "fabricated", from: "format",
      reason: "not the canonical CVE-YYYY-NNNN form (4-digit year + 4-or-more-digit sequence) — a malformed identifier" };
  }

  // 1. curated catalog (offline, authoritative for the ids it covers)
  const catalog = cveCatalog();
  const entry = catalog[cveId];
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

  // 1b. alias lookup — a catalogued-by-alias id must resolve offline too.
  for (const k of Object.keys(catalog)) {
    if (k === "_meta") continue;
    const e = catalog[k];
    if (e && Array.isArray(e.aliases) && e.aliases.includes(cveId)) {
      return {
        ...base,
        status: e.status || "published",
        cvss: e.cvss_score ?? null,
        kev: e.cisa_kev ?? null,
        product: e.name || e.type || null,
        exploitation: e.active_exploitation ?? null,
        from: "catalog-alias",
        aliased_to: k,
      };
    }
  }

  // 2. resolved cache (offline, warmed by a prior agent's lookup)
  const cached = cacheGet("cve", cveId);
  if (cached) return { ...cached, from: "cache" };

  if (isAirGap(opts)) {
    return { ...base, status: "unknown", from: "offline",
      reason: "air-gap: not in local catalog and no cached resolution — verify against NVD when online" };
  }
  if (opts.noNetwork) {
    return { ...base, status: "unknown", from: "offline",
      reason: "not in local catalog and no cached resolution (network disabled)" };
  }

  // Resolve once via NVD, then cache. opts._validateCve is a test seam.
  let validateCve = opts._validateCve;
  if (!validateCve) {
    try { ({ validateCve } = require("../sources/validators/cve-validator.js")); }
    catch { return { ...base, status: "unknown", from: "error", reason: "cve validator unavailable" }; }
  }
  let v;
  try { v = await validateCve(cveId, {}); }
  catch (e) { return { ...base, status: "unknown", from: "error", reason: e.message }; }

  if (v.status === "unreachable") {
    return { ...base, status: "unknown", from: "offline", reason: "NVD unreachable — retry online" };
  }
  // "unreachable" means EVERY source failed, so an NVD outage with KEV/EPSS still
  // answering slips through. NVD is the existence authority: never publish on KEV alone.
  const nvd = v.fetched && v.fetched.sources && v.fetched.sources.nvd;
  if (!nvd || nvd.reachable !== true) {
    return { ...base, status: "unknown", from: "offline",
      reason: "NVD unreachable — CVE existence/status unconfirmed; retry online" };
  }
  let status;
  if (v.status === "rejected") status = "rejected";
  else if (v.status === "missing" || nvd.found !== true) status = "nonexistent";
  else if ((v.fetched?.cve_tags || []).some(t => /disputed/i.test(t)) || /disputed/i.test(v.fetched?.nvd_vuln_status || "")) status = "disputed";
  else status = "published";

  const record = {
    id: cveId, kind: "cve", status,
    cvss: v.fetched?.cvss_score ?? null,
    kev: v.fetched?.in_kev ?? null,
    // The NVD description carries the product/scope a citation must match.
    product: v.fetched?.description ?? null,
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
 * found, from, ... }. A number absent from the local index is almost certainly
 * nonexistent; the optional network step confirms.
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

  // 1. local index (offline)
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

  const cached = cacheGet("rfc", String(num));
  if (cached) return { ...cached, from: "cache" };

  // 3. offline: report the ambiguity rather than guessing
  if (isAirGap(opts) || opts.noNetwork) {
    return { ...base, number: num, found: false, status: "unknown", from: "offline",
      reason: "not in the local RFC index (which includes obsoleted/historic RFCs) — most likely a nonexistent number; confirm at datatracker.ietf.org when online" };
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
