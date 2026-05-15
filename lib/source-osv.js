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
const { withRetry } = require("../vendor/blamejs/retry.js");

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
 * Set of OSV draft fields the field-dropped detector watches. When a
 * previously-populated value goes to null on a refresh, surface it as a
 * `field_dropped` diff so curators can investigate the upstream regression
 * rather than silently losing signal. Keep this set small + intentional —
 * fields here MUST be ones the editorial review process can re-source.
 */
const FIELD_DROPPED_WATCH = Object.freeze([
  "cvss_score",
  "cisa_kev_pending",
  "active_exploitation",
  "ai_discovered",
  "poc_available",
]);

/**
 * Return true when `id` looks like an OSV-native primary key (i.e. NOT a
 * CVE-* identifier and NOT a GHSA-* identifier). Both CVE-* and GHSA-*
 * route through `source-ghsa` for richer field coverage.
 */
function isOsvId(id) {
  if (!id || typeof id !== "string") return false;
  // F8 (finding 8): trim trailing/leading whitespace so operators pasting
  // ids from clipboards / multi-line files don't see a surprising routing
  // miss. Empty after trim → not an OSV id.
  const trimmed = id.trim();
  if (!trimmed) return false;
  const up = trimmed.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(up)) return false;
  if (up.startsWith("GHSA-")) return false;
  return OSV_ID_PREFIXES.some((p) => up.startsWith(p));
}

/**
 * Return true when the runtime context requests air-gap mode. Sources MUST
 * refuse network calls when this is set — fall through to fixture or return
 * a structured `air-gap: no fixture available` error so the operator sees
 * an explicit refusal, not a silent network attempt.
 */
function isAirGap(opts) {
  if (opts && opts.airGap) return true;
  if (process.env.EXCEPTD_AIR_GAP === "1") return true;
  return false;
}

/**
 * Resolve the OSV transport target. When OSV_HOST_OVERRIDE is set the
 * request switches to plain HTTP on the override host:port so test
 * harnesses can stand up a local server without TLS. Production omits the
 * override entirely and lands on api.osv.dev over HTTPS.
 *
 * Finding 13: validate the override aggressively. Garbage env values
 * (random binary, embedded NUL, port > 65535) previously slipped through
 * into the http.request options and produced opaque ENOTFOUND / EADDRINUSE
 * errors far from the source. Reject with a structured error here instead.
 */
function osvTransport() {
  const override = process.env.OSV_HOST_OVERRIDE;
  if (!override) return { mod: https, host: OSV_HOST, port: 443 };
  const raw = String(override).trim();
  const HOST_RE = /^[a-z0-9.-]+$/i;
  let host;
  let port;
  if (/^https?:\/\//i.test(raw)) {
    let u;
    try { u = new URL(raw); }
    catch (e) {
      return { error: `OSV_HOST_OVERRIDE: invalid URL: ${e.message}` };
    }
    host = u.hostname;
    port = parseInt(u.port, 10);
    if (!port) port = u.protocol === "https:" ? 443 : 80;
  } else {
    const [h, p] = raw.split(":");
    host = h;
    port = parseInt(p, 10) || 80;
  }
  if (!host || !HOST_RE.test(host)) {
    return { error: `OSV_HOST_OVERRIDE: invalid host '${host || ""}'; must match /^[a-z0-9.-]+$/i` };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: `OSV_HOST_OVERRIDE: invalid port '${port}'; must be 1..65535` };
  }
  return { mod: require("http"), host, port };
}

/**
 * Make one OSV request (HEAD/GET/POST). Throws on retryable conditions
 * (HTTP 429/503/5xx + ECONNRESET/ETIMEDOUT family) and resolves to a
 * structured `{ok:false}` envelope on permanent conditions (4xx other than
 * 408/425/429). The thrown errors carry `statusCode` so withRetry's default
 * classifier recognizes them as retryable.
 */
function osvRequestOnce({ method, reqPath, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const t = osvTransport();
    if (t.error) {
      // Surface the validation error structurally; no retry.
      return resolve({ ok: false, error: t.error, source: "offline" });
    }
    const { mod, host, port } = t;
    const headers = {
      "Accept": "application/json",
      "User-Agent": USER_AGENT,
    };
    let payload = null;
    if (method === "POST" && body) {
      payload = Buffer.from(JSON.stringify(body), "utf8");
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = payload.length;
    }
    const opts = { host, port, path: reqPath, method, headers, timeout: timeoutMs };
    const req = mod.request(opts, (res) => {
      const status = res.statusCode;
      // 401/404 (and other 4xx aside from 408/425/429) are permanent.
      // 429/503 + 5xx are retryable. Honor Retry-After when present.
      const retryAfterRaw = res.headers["retry-after"];
      if (status === 429 || status === 503 || (status >= 500 && status <= 599) ||
          status === 408 || status === 425) {
        res.resume();
        const err = new Error(`OSV returned HTTP ${status}`);
        err.statusCode = status;
        // Surface Retry-After (seconds or HTTP-date). The retry caller
        // doesn't currently consume this directly — withRetry's backoff is
        // its own schedule — but exposing it lets future schedulers honor
        // server-advertised delay.
        if (retryAfterRaw) {
          const secs = parseInt(retryAfterRaw, 10);
          if (Number.isFinite(secs)) err.retryAfterMs = secs * 1000;
        }
        return reject(err);
      }
      if (status !== 200) {
        res.resume();
        const error = `OSV returned HTTP ${status}`;
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
    req.on("timeout", () => {
      const err = new Error("OSV request timed out");
      err.code = "ETIMEDOUT";
      req.destroy(err);
    });
    req.on("error", (e) => {
      // Retryable network errors propagate up to withRetry; non-retryable
      // resolve as structured offline.
      if (e && e.code && /^(ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|EPIPE|EAGAIN|ENOTFOUND|ENETUNREACH)$/.test(e.code)) {
        return reject(e);
      }
      resolve({ ok: false, error: e.message, source: "offline" });
    });
    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Low-level GET against OSV. Resolves to { ok, record|error, source }.
 * Honors OSV_HOST_OVERRIDE for offline tests. Wraps the request in
 * withRetry so 429/503/5xx + transient net errors back off automatically.
 */
async function osvGet(reqPath, timeoutMs = REQUEST_TIMEOUT_MS) {
  try {
    return await withRetry(() => osvRequestOnce({ method: "GET", reqPath, timeoutMs }), {
      maxAttempts: 3,
      baseDelayMs: 100,
      maxDelayMs: 2000,
      jitterFactor: 0.5,
    });
  } catch (e) {
    // After exhaustion of retries, return a structured envelope rather
    // than letting the throw escape into the caller's promise chain.
    const status = typeof e?.statusCode === "number" ? e.statusCode : null;
    const error = status === 429
      ? `OSV rate-limited (HTTP 429)`
      : status
        ? `OSV returned HTTP ${status}`
        : `OSV request failed: ${e.message || e}`;
    return { ok: false, error, status, source: "offline" };
  }
}

/**
 * Low-level POST against OSV. Body is JSON-stringified. Same retry policy
 * as osvGet — 429/503/5xx + transient net errors back off automatically.
 */
async function osvPost(reqPath, body, timeoutMs = REQUEST_TIMEOUT_MS) {
  try {
    return await withRetry(() => osvRequestOnce({ method: "POST", reqPath, body, timeoutMs }), {
      maxAttempts: 3,
      baseDelayMs: 100,
      maxDelayMs: 2000,
      jitterFactor: 0.5,
    });
  } catch (e) {
    const status = typeof e?.statusCode === "number" ? e.statusCode : null;
    const error = status === 429
      ? `OSV rate-limited (HTTP 429)`
      : status
        ? `OSV returned HTTP ${status}`
        : `OSV request failed: ${e.message || e}`;
    return { ok: false, error, status, source: "offline" };
  }
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
  // `MAL-2026-3083` resolves. Uppercase + trim at entry so operators piping
  // lowercase ids from grep/jq don't get a surprising 404 from the network
  // path. Fixture lookup already case-folds, so this normalization is a
  // no-op there but harmless.
  id = id.trim().toUpperCase();
  if (!id) {
    return { ok: false, error: "id is required (MAL-*, SNYK-*, RUSTSEC-*, etc.)", source: "offline" };
  }
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
  // Finding 7: air-gap mode hard-refuses network calls. Operators running
  // `exceptd refresh --air-gap` without a fixture get a structured refusal,
  // not an outbound DNS query.
  if (isAirGap(opts)) {
    return { ok: false, error: "air-gap: no fixture available (set EXCEPTD_OSV_FIXTURE)", source: "offline" };
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
  // Finding 7: air-gap refusal applies to the package query path too.
  if (isAirGap(opts)) {
    return { ok: false, error: "air-gap: no fixture available (set EXCEPTD_OSV_FIXTURE)", source: "offline" };
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
 *
 * Finding 14: the non-CVE branch must String-coerce + uppercase so a
 * record with `id: 12345` (numeric) or `id: "mal-2026-3083"` (lowercase)
 * doesn't produce a catalog key that diverges from the canonical
 * uppercase-prefix convention. The CVE branch already upper-cases via
 * `String(cve).toUpperCase()`.
 */
function pickCatalogKey(rec) {
  if (!rec || rec.id == null) return null;
  const aliases = Array.isArray(rec.aliases) ? rec.aliases : [];
  const cve = aliases.find((a) => /^CVE-\d{4}-\d+$/i.test(String(a)));
  if (cve) return String(cve).toUpperCase();
  return String(rec.id).toUpperCase();
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
  // roundUp1 per CVSS 3.1 §7.1: round up to one decimal place. The spec
  // uses an integer-arithmetic formulation (Math.ceil(input * 100000) /
  // 10000 / 10) to avoid floating-point off-by-ones (e.g. 5.55 -> 5.6,
  // not 5.5 if naive `Math.ceil(base * 10) / 10` is applied to a value
  // that lands at 5.5499999... after IEEE 754 rounding). Finding 11.
  const rounded = Math.ceil(base * 100000) / 1000000 < 0
    ? null
    : (Math.ceil(base * 100000) / 100000); // intermediate at 5 decimals
  if (rounded == null) return null;
  // Now round-up to 1 decimal from the high-precision intermediate.
  const out = Math.ceil(rounded * 10 - 1e-9) / 10;
  if (!Number.isFinite(out) || out < 0 || out > 10) return null;
  return Math.round(out * 10) / 10; // strip trailing fp noise
}

/**
 * Pull a numeric CVSS score + vector out of an OSV severity[] entry. CVSS
 * vectors start with "CVSS:3.x/" or "CVSS:4.0/". When multiple vectors are
 * present (e.g. both V3 and V4), the highest version wins — UNLESS the v4
 * vector cannot be scored (this module does not implement CVSS 4.0
 * derivation yet), in which case fall back to the highest computable
 * version below v4 so we don't silently lose a v3 9.8 (Finding 10).
 * Returns null components when nothing parseable is present.
 *
 * Finding 19: when `s.score` is an object (some Snyk records embed
 * `{ value: "CVSS:3.1/..." }`), accept `s.score.value` as the string
 * source rather than silently producing null.
 */
function extractCvss(rec) {
  const sev = Array.isArray(rec?.severity) ? rec.severity : [];
  let score = null;
  // Collect all parseable vectors keyed by major version so we can fall
  // back from v4 -> v3 if v4 fails to compute.
  const vectorsByVersion = new Map(); // version (number) -> vector string
  let bareScore = null;
  for (const s of sev) {
    if (s == null) continue;
    let raw = null;
    if (typeof s.score === "string") raw = s.score;
    else if (typeof s.score === "object" && s.score && typeof s.score.value === "string") {
      raw = s.score.value; // Finding 19
    }
    if (raw == null) continue;
    const v = raw.trim();
    // Bare numeric score (no vector prefix).
    const num = parseFloat(v);
    if (!Number.isNaN(num) && num >= 0 && num <= 10 && !v.includes("/")) {
      if (bareScore == null) bareScore = num;
      continue;
    }
    const m = v.match(/^CVSS:(\d+\.\d+)/);
    if (!m) continue;
    const ver = parseFloat(m[1]);
    // Keep the highest score within each major version.
    const prev = vectorsByVersion.get(ver);
    if (!prev) vectorsByVersion.set(ver, v);
  }
  // Try versions in descending order. CVSS 4.0 derivation is not yet
  // implemented here — if v4 was the highest but can't be computed, walk
  // down to v3.x. Only return null when ALL versions fail.
  const versions = Array.from(vectorsByVersion.keys()).sort((a, b) => b - a);
  let bestVector = null;
  for (const ver of versions) {
    const candidate = vectorsByVersion.get(ver);
    if (!candidate) continue;
    bestVector = candidate;
    const tail = candidate.match(/\/(\d+(?:\.\d+)?)$/);
    if (tail) {
      const t = parseFloat(tail[1]);
      if (t >= 0 && t <= 10) { score = t; break; }
    }
    if (/^CVSS:3\./.test(candidate)) {
      const computed = cvss3BaseScore(candidate);
      if (computed != null) { score = computed; break; }
    }
    // v4 has no in-module computer — keep walking down to the next
    // version. The bestVector tracker holds whatever was tried last;
    // overwrite it with the next computable on the loop iteration.
  }
  // If we landed on an uncomputable v4 vector but a lower-version vector
  // was usable, prefer the lower-version one's vector string so callers
  // don't get a v4 vector + null score combo when v3 was available.
  if (score == null && versions.length > 0) {
    for (const ver of versions) {
      if (ver >= 4) continue;
      const candidate = vectorsByVersion.get(ver);
      if (candidate) { bestVector = candidate; break; }
    }
  }
  // F10 fix: if score is still null but we have a v4 vector + a bare
  // score that came from a v3-only severity entry, prefer the v3 vector
  // string when one exists. (Handles the case described in the audit:
  // v4 is the highest version but uncomputable; a v3 vector with 9.8
  // sits alongside. Without this fallback we lose the 9.8.)
  if (score == null && bareScore != null) score = bareScore;
  return { score, vector: bestVector };
}

/**
 * Coarse package-ecosystem inference for the catalog `type` field. Mirrors
 * the same heuristic used by source-ghsa.
 */
function inferType(rec) {
  const ecos = new Set();
  const affected = Array.isArray(rec?.affected) ? rec.affected : [];
  for (const a of affected) {
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
 * Validate + slice a published/modified timestamp string. Findings 2 + 17:
 *  - typeof guard so non-string inputs (number, object, undefined) become
 *    null instead of throwing on .slice().
 *  - ISO-prefix regex + year sanity bound so garbage like "yesterday" or
 *    "0001-01-01" doesn't pollute downstream surfaces.
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
  if (!rec || rec.id == null) return null;
  // Trim id so trailing whitespace doesn't bleed into pickCatalogKey + key.
  if (typeof rec.id === "string") rec = { ...rec, id: rec.id.trim() };
  if (!rec.id) return null;
  const catalogKey = pickCatalogKey(rec);
  if (!catalogKey) return null;

  const aliases = Array.isArray(rec.aliases) ? rec.aliases.slice() : [];
  // If the catalog key came from aliases (CVE-*), put the OSV id back into
  // the aliases array so it stays discoverable.
  if (catalogKey !== rec.id && !aliases.includes(rec.id)) aliases.push(rec.id);

  const { score, vector } = extractCvss(rec);

  const affectedPackages = [];
  const affectedVersions = [];
  // Finding 3: rec.affected might not be an array — guard before iterating.
  const affectedList = Array.isArray(rec.affected) ? rec.affected : [];
  for (const a of affectedList) {
    const pkg = a?.package || {};
    if (pkg.name && pkg.ecosystem) {
      affectedPackages.push(`${pkg.ecosystem}:${pkg.name}`);
    }
    const versions = Array.isArray(a.versions) ? a.versions : [];
    for (const v of versions) {
      affectedVersions.push(`${pkg.name || "?"} == ${v}`);
    }
    // Finding 16: walk events sequentially. OSV emits a stream of
    // introduced/fixed/last_affected events; the historical implementation
    // collected the FIRST `introduced` + FIRST `fixed` per range and
    // emitted one range, losing re-introduction cycles (an introduced ->
    // fixed -> introduced -> fixed sequence collapsed to one range).
    // Sequential pairing produces ONE entry per (introduced, fixed |
    // last-known-vulnerable) pair instead.
    const ranges = Array.isArray(a.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r.events) ? r.events : [];
      let openIntro = null;
      let lastKnownVulnerable = null;
      for (const e of events) {
        if (!e || typeof e !== "object") continue;
        if (typeof e.introduced === "string") {
          // Flush any prior open pair with whatever upper bound we have.
          if (openIntro != null) {
            const upper = lastKnownVulnerable ? `, <= ${lastKnownVulnerable}` : "";
            affectedVersions.push(`${pkg.name || "?"} >= ${openIntro}${upper}`);
            lastKnownVulnerable = null;
          }
          openIntro = e.introduced;
        } else if (typeof e.fixed === "string") {
          if (openIntro != null) {
            affectedVersions.push(`${pkg.name || "?"} >= ${openIntro}, < ${e.fixed}`);
            openIntro = null;
            lastKnownVulnerable = null;
          } else {
            // Defensive: fixed-without-introduced — emit a fixed-only marker.
            affectedVersions.push(`${pkg.name || "?"} < ${e.fixed}`);
          }
        } else if (typeof e.last_affected === "string") {
          lastKnownVulnerable = e.last_affected;
        }
      }
      // Trailing open range — no `fixed` ever observed. Emit as
      // `>= introduced` (optionally with last_known_vulnerable upper).
      if (openIntro != null) {
        const upper = lastKnownVulnerable ? `, <= ${lastKnownVulnerable}` : "";
        affectedVersions.push(`${pkg.name || "?"} >= ${openIntro}${upper}`);
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
  // Finding 20: guard non-array references silently truncating to [].
  const refUrls = [];
  const refList = Array.isArray(rec.references) ? rec.references : [];
  for (const r of refList) {
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
  // Finding 2 + 17: type-safe + format-validated date slicing.
  const published = safeDateSlice(rec.published);
  const modified = safeDateSlice(rec.modified);

  // OSV.dev canonical advisory URL — used as the primary vendor advisory.
  const osvUrl = `https://osv.dev/vulnerability/${encodeURIComponent(rec.id)}`;

  // Dedupe verification_sources. OSV records frequently carry the
  // canonical osv.dev URL in references[] as well, which would otherwise
  // produce a duplicate alongside the prepended `osvUrl`.
  const verification_sources = Array.from(new Set([
    osvUrl,
    ...(/^CVE-/i.test(catalogKey) ? [`https://nvd.nist.gov/vuln/detail/${catalogKey}`] : []),
    ...refUrls.slice(0, 10),
  ]));

  // EPSS coverage does not extend to non-CVE identifiers. Surface this
  // explicitly so curators know to re-query if MITRE later assigns a CVE
  // id to the entry.
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
 * local catalog. Finding 9: when the record already exists and a watched
 * field has dropped from populated -> null, emit a `field_dropped` diff
 * so curators see the upstream regression instead of silently absorbing it.
 */
async function buildDiff(ctx) {
  // Finding 8: trim ids defensively at the entry seam.
  const rawIds = Array.isArray(ctx?.osv_ids) ? ctx.osv_ids : [];
  const ids = rawIds.map((x) => (typeof x === "string" ? x.trim() : "")).filter(Boolean);
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
  const cveCatalog = ctx.cveCatalog || {};
  const existingKeys = new Set(Object.keys(cveCatalog));
  const diffs = [];
  // Distinguish unreachable (fetch failed, network or 5xx) from
  // normalize-rejected (record fetched but normalization produced null).
  // Operators triaging a refresh-report want to know whether to chase a
  // network outage or a malformed upstream record.
  let unreachable = 0;
  let normalizeErrors = 0;
  // Ids that ARE in the catalog but skipped because of overlap
  // are not "errors"; surface them so the summary doesn't read as silently
  // dropping work. Particularly useful when a curator dispatches the same
  // batch twice and wonders why nothing happened.
  let ghsaOnlySkipped = 0;
  for (const id of ids) {
    const r = await fetchAdvisoryById(id, { airGap: ctx.airGap });
    if (!r.ok) { unreachable++; continue; }
    const rec = r.advisories[0];
    if (!rec) { unreachable++; continue; }
    const normalized = normalizeAdvisory(rec);
    if (!normalized) { normalizeErrors++; continue; }
    const key = Object.keys(normalized)[0];
    if (existingKeys.has(key)) {
      // Finding 9: field-dropped detection. Compare watched fields between
      // the existing local entry and the freshly-normalized one. Emit a
      // `field_dropped` diff per regression rather than a `_new_entry`.
      const before = cveCatalog[key] || {};
      const after = normalized[key];
      let dropped = false;
      for (const field of FIELD_DROPPED_WATCH) {
        const had = before[field];
        const has = after[field];
        const wasPopulated = had !== null && had !== undefined && had !== "" && had !== false;
        const isNowEmpty = has === null || has === undefined;
        if (wasPopulated && isNowEmpty) {
          diffs.push({
            id: key,
            field,
            before: had,
            after: null,
            severity: null,
            source: "osv",
            variant: "field_dropped",
          });
          dropped = true;
        }
      }
      if (!dropped) ghsaOnlySkipped++;
      continue;
    }
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
  const summary = `OSV fetched ${ids.length} id(s); ${diffs.length} new entry diff(s), ${unreachable} unreachable, ${normalizeErrors} normalize-rejected, ${ghsaOnlySkipped} ghsa_only_skipped.`;
  return {
    status: errors === 0 ? "ok" : errors === ids.length ? "unreachable" : "partial",
    diffs,
    errors,
    unreachable_count: unreachable,
    normalize_error_count: normalizeErrors,
    ghsa_only_skipped: ghsaOnlySkipped,
    summary,
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
  FIELD_DROPPED_WATCH,
  safeDateSlice,
};
