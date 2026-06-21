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

// --- resolved-id cache (atomic JSON files, TTL-bounded, integrity-checked) ---
//
// The cache feeds security verdicts (and, via citation-hygiene --resolve,
// attestations), so a record is only trusted if it carries a matching content
// digest AND its own `resolved_at` is within the freshness window. A file an
// attacker (or a corrupt/half-written process) edits in place without
// recomputing `_digest` is rejected as a cache-miss — it can never launder a
// rejected/fabricated citation into "published". This is the resolved-cache
// analogue of the prefetch cache's sha256+signature model; full maintainer
// signing isn't possible operator-side (no private key), so the digest binds
// the record to itself and makes tampering detectable.
function cachePath(kind, id) {
  // Read the env at call time so tests can isolate the cache per-case.
  const dir = process.env.EXCEPTD_RESOLVE_CACHE_DIR || RESOLVE_CACHE_DIR;
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(dir, kind, `${safe}.json`);
}
// sha256 over the record's canonical bytes (sorted keys, `_digest` excluded).
// `resolved_at` IS covered, so the staleness clock can't be rewritten apart
// from the verdict.
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
    // Integrity: a record without a matching digest is tampered/corrupt → miss.
    if (typeof record._digest !== "string" || record._digest !== recordDigest(record)) return null;
    // Freshness keyed on the record's own resolved_at (not file mtime, which a
    // `touch` can reset). Reject future-dated records as a poisoning signal,
    // mirroring the prefetch cache's future-date guard.
    const ts = Date.parse(record.resolved_at || "");
    if (!Number.isFinite(ts)) return null;
    const age = Date.now() - ts;
    if (age < -60_000 || age > CACHE_TTL_MS) return null;
    // Bind the record to the requested key — a digest proves self-consistency,
    // not that this is the record FOR the looked-up id/kind. A digest-valid
    // record written under one filename but carrying a different internal
    // id/kind would otherwise be served for the wrong lookup (a swapped-file
    // poisoning that the self-digest cannot catch). Mismatch → cache miss.
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
    // Random suffix (not just pid) so two cachePut calls for the same id in one
    // process — a Promise.all fan-out or worker threads sharing a pid — don't
    // race the same tmp path. Matches lib/prefetch.js writeFileAtomic.
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
  // Trim before the format test — matches resolveRfc — so a whitespace-only
  // identifier is "fabricated/malformed" (empty form) rather than a literal
  // whitespace string fed straight into CVE_RE.
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

  // 1b. alias lookup — an id may be carried as an alias of a curated entry
  //     (e.g. a CVE for a sub-incident folded into a campaign-level MAL-* key).
  //     Catalogued-by-alias must resolve offline too, or `exceptd cve <alias>`
  //     would report unknown for an incident the catalog actually covers.
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

  // 3. offline / air-gap: cannot resolve uncatalogued ids without network
  if (isAirGap(opts)) {
    return { ...base, status: "unknown", from: "offline",
      reason: "air-gap: not in local catalog and no cached resolution — verify against NVD when online" };
  }
  if (opts.noNetwork) {
    return { ...base, status: "unknown", from: "offline",
      reason: "not in local catalog and no cached resolution (network disabled)" };
  }

  // 4. resolve once via NVD, then cache for sibling agents.
  // opts._validateCve is a test seam (inject a fake validator); production uses
  // the real NVD-backed validator.
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
  // NVD is the authority for a CVE's existence and lifecycle. validateCve only
  // returns "unreachable" when EVERY source fails — if NVD is down but KEV/EPSS
  // answer, it returns match/drift with sources.nvd.reachable === false. Do NOT
  // declare "published" on KEV/EPSS alone during an NVD outage; that would
  // falsely validate an unconfirmed (or nonexistent) identifier.
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
    // NVD English description — carries the product/scope a citation must match,
    // so an agent can confirm status=published applies to the right product
    // without a second manual NVD lookup.
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
 * found, from, ... }. The local index covers the whole RFC series — current
 * AND obsoleted/historic (the latter carry `_obsoleted` + `obsoleted_by`) — so
 * number->title resolution, including "is this RFC superseded?", is fully
 * offline. A number absent from the index is almost certainly nonexistent (or
 * an UNKNOWN-status placeholder); the optional network step confirms.
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
