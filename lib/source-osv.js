"use strict";

/**
 * OSV.dev fetcher. CVE-* is NOT a primary key there — CVE numbers live under
 * `aliases` on records whose id is GHSA-*, MAL-*, etc.; MAL-* is the canonical
 * namespace for a package compromise with no CVE. Every imported entry is a
 * draft (`_auto_imported` + `_draft`), so the strict validator warns rather than
 * errors and editorial fields stay null. EXCEPTD_OSV_FIXTURE points at a JSON
 * file of one record or an array of them, for offline runs.
 */

const https = require("https");
const fs = require("fs");
const { withRetry } = require("../vendor/blamejs/retry.js");

// Production endpoint; OSV_HOST_OVERRIDE substitutes host/port/transport — see osvTransport().
const OSV_HOST = "api.osv.dev";
const REQUEST_TIMEOUT_MS = 10000;
const USER_AGENT = "exceptd-security/source-osv (+https://exceptd.com)";

// Caps the streamed response so a hostile endpoint cannot stream unbounded bytes
// into RAM. Symmetric with the JSON cap getJsonOnce enforces in lib/refresh-network.js.
function osvResponseCapBytes() {
  const env = parseInt(process.env.EXCEPTD_OSV_RESPONSE_CAP_BYTES, 10);
  return Number.isFinite(env) && env > 0 ? env : 16 * 1024 * 1024;
}

// Identifier namespaces OSV uses as PRIMARY keys. GHSA-* is deliberately absent:
// seedSingleAdvisory in lib/refresh-external.js routes CVE-* and GHSA-* through
// `source-ghsa`. Adding a prefix here also needs that dispatcher's --advisory regex.
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
 * Draft fields the field-dropped detector watches. Keep the set small — a field
 * here MUST be one the editorial review process can re-source.
 */
const FIELD_DROPPED_WATCH = Object.freeze([
  // Only upstream-populated fields: normalize nulls the editorial ones on every
  // import, so watching them flags a false regression on each re-import.
  "cvss_score",
  "cisa_kev_pending",
]);

/** True when `id` is an OSV-native primary key; CVE-* and GHSA-* route to `source-ghsa`. */
function isOsvId(id) {
  if (!id || typeof id !== "string") return false;
  // Trimmed first, so a pasted id doesn't miss the routing.
  const trimmed = id.trim();
  if (!trimmed) return false;
  const up = trimmed.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(up)) return false;
  if (up.startsWith("GHSA-")) return false;
  return OSV_ID_PREFIXES.some((p) => up.startsWith(p));
}

/**
 * True when the runtime context requests air-gap mode. Sources MUST refuse the
 * network then — a fixture, or a structured `air-gap` error; never a silent attempt.
 */
function isAirGap(opts) {
  if (opts && opts.airGap) return true;
  if (process.env.EXCEPTD_AIR_GAP === "1") return true;
  return false;
}

/**
 * Resolve the OSV transport target. OSV_HOST_OVERRIDE switches the request to
 * plain HTTP on the override host:port; production lands on api.osv.dev over
 * HTTPS. The override is validated here, not left to surface as an ENOTFOUND.
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
 * One OSV request. THROWS on retryable conditions (429/503/5xx, 408/425, the
 * ECONNRESET/ETIMEDOUT family) and RESOLVES a structured `{ok:false}` envelope on
 * permanent ones. A thrown error carries `statusCode` for withRetry's classifier.
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
      const retryAfterRaw = res.headers["retry-after"];
      if (status === 429 || status === 503 || (status >= 500 && status <= 599) ||
          status === 408 || status === 425) {
        res.resume();
        const err = new Error(`OSV returned HTTP ${status}`);
        err.statusCode = status;
        // Retry-After is exposed for a scheduler; withRetry runs its own backoff.
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
      let total = 0;
      const cap = osvResponseCapBytes();
      let capped = false;
      res.on("data", (c) => {
        total += c.length;
        if (total > cap) {
          capped = true;
          req.destroy(new Error(`OSV response exceeds ${cap}-byte cap during streaming download`));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => {
        // The cap already routed through req.on("error"); resolving here settles twice.
        if (capped) return;
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
      // Retryable network errors propagate to withRetry; the rest resolve offline.
      if (e && e.code && /^(ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|EPIPE|EAGAIN|ENOTFOUND|ENETUNREACH)$/.test(e.code)) {
        return reject(e);
      }
      resolve({ ok: false, error: e.message, source: "offline" });
    });
    if (payload) req.write(payload);
    req.end();
  });
}

/** GET against OSV → { ok, record|error, source }; withRetry backs off 429/503/5xx. */
async function osvGet(reqPath, timeoutMs = REQUEST_TIMEOUT_MS) {
  try {
    return await withRetry(() => osvRequestOnce({ method: "GET", reqPath, timeoutMs }), {
      maxAttempts: 3,
      baseDelayMs: 100,
      maxDelayMs: 2000,
      jitterFactor: 0.5,
    });
  } catch (e) {
    // Once retries are exhausted, return an envelope; never let the throw escape.
    const status = typeof e?.statusCode === "number" ? e.statusCode : null;
    const error = status === 429
      ? `OSV rate-limited (HTTP 429)`
      : status
        ? `OSV returned HTTP ${status}`
        : `OSV request failed: ${e.message || e}`;
    return { ok: false, error, status, source: "offline" };
  }
}

/** POST against OSV; the body is JSON-stringified. Same retry policy as osvGet. */
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
 * Read EXCEPTD_OSV_FIXTURE. Null when unset, `{ ok: true, advisories, source }`
 * on success, `{ ok: false, error, source: "offline" }` on any failure — missing
 * file, malformed JSON, root neither object nor array. Never throws.
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
 * Fetch one OSV record by id. Return shape matches source-ghsa.fetchAdvisoryById:
 *   { ok: true,  advisories: [<osv_record>], source: "osv-api" | "fixture" }
 *   { ok: false, error, source: "offline" | "fixture" }
 */
async function fetchAdvisoryById(id, opts = {}) {
  if (!id || typeof id !== "string") {
    return { ok: false, error: "id is required (MAL-*, SNYK-*, RUSTSEC-*, etc.)", source: "offline" };
  }
  // /v1/vulns/{id} is case-sensitive — `mal-2026-3083` 404s where `MAL-2026-3083`
  // resolves — so uppercase and trim at entry.
  id = id.trim().toUpperCase();
  if (!id) {
    return { ok: false, error: "id is required (MAL-*, SNYK-*, RUSTSEC-*, etc.)", source: "offline" };
  }
  const fixture = readFixture();
  if (fixture) {
    if (!fixture.ok) return fixture;
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
  // Air-gap hard-refuses: no fixture means a structured refusal, not a DNS query.
  if (isAirGap(opts)) {
    return { ok: false, error: "air-gap: no fixture available (set EXCEPTD_OSV_FIXTURE)", source: "offline" };
  }
  const result = await osvGet(`/v1/vulns/${encodeURIComponent(id)}`, opts.timeoutMs);
  if (!result.ok) return result;
  return { ok: true, advisories: [result.record], source: "osv-api" };
}

/** List advisories for a package, optionally filtered to one version. */
async function fetchAdvisoriesForPackage(name, ecosystem, version, opts = {}) {
  if (!name || !ecosystem) {
    return { ok: false, error: "name and ecosystem are required", source: "offline" };
  }
  const fixture = readFixture();
  if (fixture) {
    if (!fixture.ok) return fixture;
    // Best-effort: match on `affected[]` package + ecosystem, and version when given.
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
  // The air-gap refusal applies to the package-query path too.
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
 * Catalog key for an OSV record: a CVE-* alias when present, preserving the
 * CVE-keyed convention, else the OSV id. Both branches String-coerce and
 * uppercase, so a numeric or lowercase id cannot diverge from the convention.
 */
function pickCatalogKey(rec) {
  if (!rec || rec.id == null) return null;
  const aliases = Array.isArray(rec.aliases) ? rec.aliases : [];
  const cve = aliases.find((a) => /^CVE-\d{4}-\d+$/i.test(String(a)));
  if (cve) return String(cve).toUpperCase();
  return String(rec.id).toUpperCase();
}

/**
 * CVSS 3.1 base score from a vector string, per Table 6 of the FIRST CVSS 3.1
 * specification (https://www.first.org/cvss/v3.1/specification-document). Used
 * when a record carries a vector but no numeric score. Null on malformed input.
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
  // roundUp1 per CVSS 3.1 §7.1. The spec's integer formulation avoids the IEEE-754
  // off-by-one where Math.ceil(base * 10) / 10 turns 5.5499999… into 5.5, not 5.6.
  const rounded = Math.ceil(base * 100000) / 1000000 < 0
    ? null
    : (Math.ceil(base * 100000) / 100000); // intermediate at 5 decimals
  if (rounded == null) return null;
  const out = Math.ceil(rounded * 10 - 1e-9) / 10;
  if (!Number.isFinite(out) || out < 0 || out > 10) return null;
  return Math.round(out * 10) / 10; // strip trailing fp noise
}

/**
 * Pull a numeric CVSS score + vector out of an OSV severity[] entry. The highest
 * version wins UNLESS it cannot be scored — CVSS 4.0 derivation is not implemented
 * — in which case the highest computable version below it is used, so a v3 9.8 is
 * not silently lost. `s.score` may be a string or an object carrying `.value`.
 */
function extractCvss(rec) {
  const sev = Array.isArray(rec?.severity) ? rec.severity : [];
  let score = null;
  const vectorsByVersion = new Map(); // version (number) -> vector string
  let bareScore = null;
  // Score for one vector: its trailing /N.N when present, else the derived CVSS 3.x
  // base score, else null. Keeps the HIGHEST-scoring vector per major version.
  const vectorScore = (vec) => {
    const tail = vec.match(/\/(\d+(?:\.\d+)?)$/);
    if (tail) { const t = parseFloat(tail[1]); if (t >= 0 && t <= 10) return t; }
    if (/^CVSS:3\./.test(vec)) { const c = cvss3BaseScore(vec); if (c != null) return c; }
    return null;
  };
  for (const s of sev) {
    if (s == null) continue;
    let raw = null;
    if (typeof s.score === "string") raw = s.score;
    else if (typeof s.score === "object" && s.score && typeof s.score.value === "string") {
      raw = s.score.value;
    }
    if (raw == null) continue;
    const v = raw.trim();
    // Bare numeric score (no vector prefix).
    const num = parseFloat(v);
    if (!Number.isNaN(num) && num >= 0 && num <= 10 && !v.includes("/")) {
      // HIGHEST-wins, not first-wins: several same-version entries arrive in no
      // guaranteed order, and first-wins downgrades a 9.8 critical to a 5.3.
      if (bareScore == null || num > bareScore) bareScore = num;
      continue;
    }
    const m = v.match(/^CVSS:(\d+\.\d+)/);
    if (!m) continue;
    const ver = parseFloat(m[1]);
    // Same within each major version: compare computed scores, not array order.
    const prev = vectorsByVersion.get(ver);
    if (!prev || (vectorScore(v) ?? -1) > (vectorScore(prev) ?? -1)) vectorsByVersion.set(ver, v);
  }
  // Descending; score stays null only when every version fails.
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
    // v4 has no in-module computer — keep walking down.
  }
  // Prefer a lower-version vector when the highest was uncomputable, so no v4-with-null.
  if (score == null && versions.length > 0) {
    for (const ver of versions) {
      if (ver >= 4) continue;
      const candidate = vectorsByVersion.get(ver);
      if (candidate) { bestVector = candidate; break; }
    }
  }
  // Last resort: a bare numeric score, when no vector was computable.
  if (score == null && bareScore != null) score = bareScore;
  return { score, vector: bestVector };
}

/** Coarse package-ecosystem inference for the catalog `type`. Mirrors source-ghsa. */
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
 * Validate and slice a published/modified timestamp; a non-string, a non-ISO
 * prefix or a year outside [1990, next year] all yield null rather than throwing.
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
 * Normalize an OSV record into the catalog draft shape, as
 * `{ [catalogKey]: <draft-entry> }` so a caller can spread it into the catalog.
 * Null when the record is unusable. Editorial fields are left null, and
 * `_auto_imported` + `_draft` mark the entry warn-not-error for the validator.
 */
function normalizeAdvisory(rec) {
  if (!rec || rec.id == null) return null;
  // Trim id so trailing whitespace doesn't bleed into pickCatalogKey + key.
  if (typeof rec.id === "string") rec = { ...rec, id: rec.id.trim() };
  if (!rec.id) return null;
  const catalogKey = pickCatalogKey(rec);
  if (!catalogKey) return null;

  const aliases = Array.isArray(rec.aliases) ? rec.aliases.slice() : [];
  // When the key came from aliases (CVE-*), the OSV id goes back into aliases.
  if (catalogKey !== rec.id && !aliases.includes(rec.id)) aliases.push(rec.id);

  const { score, vector } = extractCvss(rec);

  const affectedPackages = [];
  const affectedVersions = [];
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
    // Events are walked sequentially, one entry per (introduced, fixed |
    // last-known-vulnerable) pair. Pairing the FIRST introduced with the FIRST fixed
    // collapses an introduced → fixed → introduced cycle and loses the re-introduction.
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
      // Trailing open range — no `fixed` was ever observed.
      if (openIntro != null) {
        const upper = lastKnownVulnerable ? `, <= ${lastKnownVulnerable}` : "";
        affectedVersions.push(`${pkg.name || "?"} >= ${openIntro}${upper}`);
      }
    }
  }

  // IoC seeding from database_specific.iocs; domains and URLs land in c2_indicators
  // so an operator has something to grep for immediately.
  const dsIocs = rec?.database_specific?.iocs || null;
  let iocs = null;
  if (dsIocs && (Array.isArray(dsIocs.domains) || Array.isArray(dsIocs.urls))) {
    const c2 = [];
    if (Array.isArray(dsIocs.domains)) c2.push(...dsIocs.domains.map((d) => `domain: ${d}`));
    if (Array.isArray(dsIocs.urls)) c2.push(...dsIocs.urls.map((u) => `url: ${u}`));
    iocs = { c2_indicators: c2 };
  }

  // OSV `references` is `[{ type, url }, ...]`.
  const refUrls = [];
  const refList = Array.isArray(rec.references) ? rec.references : [];
  for (const r of refList) {
    if (r && typeof r.url === "string") refUrls.push(r.url);
  }

  const severityWord = score != null && score >= 9.0 ? "critical"
    : score != null && score >= 7.0 ? "high"
    : score != null && score >= 4.0 ? "medium"
    : score != null ? "low"
    : null;

  const pending = severityWord === "critical" || (score != null && score >= 9.0);

  const today = new Date().toISOString().slice(0, 10);
  const published = safeDateSlice(rec.published);
  const modified = safeDateSlice(rec.modified);

  // The canonical osv.dev URL, used as the primary vendor advisory.
  const osvUrl = `https://osv.dev/vulnerability/${encodeURIComponent(rec.id)}`;

  // Deduped: references[] often carries the canonical osv.dev URL as well.
  const verification_sources = Array.from(new Set([
    osvUrl,
    ...(/^CVE-/i.test(catalogKey) ? [`https://nvd.nist.gov/vuln/detail/${catalogKey}`] : []),
    ...refUrls.slice(0, 10),
  ]));

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
      // A retracted record carries a top-level `withdrawn` timestamp; surfaced as
      // structured status so a citation check flags it instead of importing it live.
      ...(rec.withdrawn ? { status: "withdrawn", status_source: "osv:withdrawn", status_verified: today } : {}),
      last_updated: modified || today,
    },
  };
}

/**
 * Build a refresh diff for the refresh-external orchestrator. With `ctx.osv_ids`
 * populated, each id is fetched and emitted as a `_new_entry` diff unless its key
 * is already in the local catalog — in which case a watched field that dropped to
 * null emits a `field_dropped` diff instead.
 */
async function buildDiff(ctx) {
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
  // Unreachable (fetch failed) and normalize-rejected (fetched, normalized to null)
  // are counted apart, so triage knows a network outage from a malformed record.
  let unreachable = 0;
  let normalizeErrors = 0;
  // An id already in the catalog is skipped, not an error; counting it keeps a
  // re-dispatched batch from reading as silently dropped work.
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
  // diffs holds both kinds; count separately so a field_dropped is not a new entry.
  const newCount = diffs.filter((d) => d.field === "_new_entry").length;
  const droppedCount = diffs.filter((d) => d.variant === "field_dropped").length;
  const summary = `OSV fetched ${ids.length} id(s); ${newCount} new entry diff(s), ${droppedCount} field-dropped regression(s), ${unreachable} unreachable, ${normalizeErrors} normalize-rejected, ${ghsaOnlySkipped} ghsa_only_skipped.`;
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
