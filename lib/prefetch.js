"use strict";
/**
 * Warms a local cache (`.cache/upstream/`, gitignored) of every upstream
 * artifact this project queries.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { JobQueue, isRetryable } = require("./job-queue");

const ROOT = path.join(__dirname, "..");
const DEFAULT_CACHE = path.join(ROOT, ".cache", "upstream");
const REQUEST_TIMEOUT_MS = 10_000;
const USER_AGENT = "exceptd-security/prefetch (+https://exceptd.com)";

// CVE ids the KEV feed lists that are NOT yet in the local catalog; a null
// `kevFeed` yields [].
function newKevIds(kevFeed, cveCatalog) {
  const have = new Set(Object.keys(cveCatalog || {}));
  const vulns = Array.isArray(kevFeed && kevFeed.vulnerabilities) ? kevFeed.vulnerabilities : [];
  return vulns
    .map((v) => v.cveID)
    .filter((id) => /^CVE-\d{4}-\d{4,7}$/.test(id) && !have.has(id));
}

const SOURCES = {
  kev: {
    description: "CISA Known Exploited Vulnerabilities (single feed)",
    rate: { tokens: 6, windowMs: 60_000 },     // very gentle
    concurrency: 1,
    expand: () => [{ id: "known_exploited_vulnerabilities", url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" }],
  },
  nvd: {
    description: "NIST NVD 2.0 per-CVE responses",
    rate: { tokens: 5, windowMs: 30_000 },     // anon budget; NVD_API_KEY lifts to 50
    rate_with_key: { tokens: 50, windowMs: 30_000 },
    concurrency: 4,
    // The catalog unioned with any newly-KEV-listed id.
    expand: (ctx) => {
      const ids = new Set(Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k)));
      for (const id of newKevIds(ctx.kevFeed, ctx.cveCatalog)) ids.add(id);
      return [...ids].map((id) => ({ id, url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}` }));
    },
  },
  epss: {
    description: "FIRST.org EPSS per-CVE responses",
    rate: { tokens: 30, windowMs: 60_000 },
    concurrency: 4,
    // Same new-KEV union as nvd above.
    expand: (ctx) => {
      const ids = new Set(Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k)));
      for (const id of newKevIds(ctx.kevFeed, ctx.cveCatalog)) ids.add(id);
      return [...ids].map((id) => ({ id, url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}` }));
    },
  },
  rfc: {
    description: "IETF Datatracker per-RFC/doc records",
    rate: { tokens: 30, windowMs: 60_000 },
    concurrency: 4,
    expand: (ctx) => Object.keys(ctx.rfcCatalog)
      .filter((k) => !k.startsWith("_"))
      .map((id) => {
        let docName;
        if (id.startsWith("RFC-")) docName = `rfc${id.slice(4)}`;
        else if (id.startsWith("DRAFT-")) docName = `draft-${id.slice(6).toLowerCase()}`;
        return docName ? { id: docName, url: `https://datatracker.ietf.org/api/v1/doc/document/?name=${encodeURIComponent(docName)}&format=json` } : null;
      })
      .filter(Boolean),
  },
  pins: {
    description: "MITRE GitHub releases for ATLAS / ATT&CK pin checks",
    rate: { tokens: 30, windowMs: 60 * 60_000 },   // anon: 60/h, leave headroom
    rate_with_key: { tokens: 500, windowMs: 60 * 60_000 },
    concurrency: 2,
    // D3FEND and CWE publish no GitHub Releases, so an entry for either 404s on
    // every refresh; lib/upstream-check.js tracks their pin currency instead.
    expand: () => [
      { id: "mitre-atlas__atlas-data__releases", url: "https://api.github.com/repos/mitre-atlas/atlas-data/releases?per_page=5" },
      { id: "mitre-attack__attack-stix-data__releases", url: "https://api.github.com/repos/mitre-attack/attack-stix-data/releases?per_page=5" },
    ],
  },
};

// Refresh-orchestrator sources with nothing to warm (live id lookup only), so
// scoping a warm to one reports that rather than "unknown source".
const LIVE_ONLY_REFRESH_SOURCES = new Set(["ghsa", "osv", "advisories", "cve-regression-watcher"]);

function parseArgs(argv) {
  const out = { maxAgeMs: 24 * 3600 * 1000, source: null, force: false, noNetwork: false, cacheDir: DEFAULT_CACHE, quiet: false, help: false, maxErrors: 0 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--force") out.force = true;
    else if (a === "--no-network" || a === "--dry-run" || a === "--air-gap") out.noNetwork = true;
    else if (a === "--quiet") out.quiet = true;
    else if (a === "--help" || a === "-h") out.help = true;
    // A trailing value-flag is a usage error, never a default: an undefined
    // --max-age means "everything is stale" and a bare --source means all.
    else if (a === "--source") { const v = takesValue(argv, ++i); if (v === undefined) out._argError = "prefetch: --source requires a value"; else out.source = v; }
    else if (a.startsWith("--source=")) out.source = a.slice("--source=".length);
    else if (a === "--max-age") { const v = takesValue(argv, ++i); if (v === undefined) out._argError = "prefetch: --max-age requires a value"; else out.maxAgeMs = parseDuration(v); }
    else if (a.startsWith("--max-age=")) out.maxAgeMs = parseDuration(a.slice("--max-age=".length));
    else if (a === "--cache-dir") { const v = takesValue(argv, ++i); if (v === undefined) out._argError = "prefetch: --cache-dir requires a value"; else out.cacheDir = path.resolve(v); }
    else if (a.startsWith("--cache-dir=")) out.cacheDir = path.resolve(a.slice("--cache-dir=".length));
    else if (a === "--max-errors") { try { out.maxErrors = parseErrorThreshold(argv[++i]); } catch (e) { out._argError = e.message; } }
    else if (a.startsWith("--max-errors=")) { try { out.maxErrors = parseErrorThreshold(a.slice("--max-errors=".length)); } catch (e) { out._argError = e.message; } }
    // Any remaining --flag is a typo; main() refuses before any network work.
    else if (typeof a === "string" && a.startsWith("--")) {
      const base = a.indexOf("=") === -1 ? a : a.slice(0, a.indexOf("="));
      (out._unknownFlags || (out._unknownFlags = [])).push(base);
    }
  }
  // A supplied-but-empty --source would warm ALL sources and a comma-only value
  // none, both reporting success. Omitting the flag still warms everything.
  if (!out._argError && out.source != null) {
    const names = String(out.source).split(",").map((s) => s.trim()).filter(Boolean);
    if (names.length === 0) {
      out._argError = "prefetch: --source given but resolved to no source names (empty or comma-only value)";
    }
  }
  // EXCEPTD_AIR_GAP=1 is --no-network: no live fetch is planned under air-gap.
  if (process.env.EXCEPTD_AIR_GAP === "1") out.noNetwork = true;
  return out;
}

// The value token a space-separated flag expects, or `undefined` when the flag
// trails or the next token is itself a --flag. Callers turn that into an error.
function takesValue(argv, i) {
  const v = argv[i];
  if (v === undefined) return undefined;
  if (typeof v === "string" && v.startsWith("--")) return undefined;
  return v;
}

function parseDuration(s) {
  if (!s) return 0;
  const m = String(s).match(/^(\d+)\s*([smhd])?$/);
  if (!m) throw new Error(`prefetch: invalid duration "${s}"`);
  const n = Number(m[1]);
  const unit = (m[2] || "h").toLowerCase();
  const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit];
  return n * mult;
}

// Returns an absolute integer budget or a "<N>%" marker; throws on anything
// else, so a typo cannot degrade into an unbounded tolerance.
function parseErrorThreshold(s) {
  const str = String(s == null ? "" : s).trim();
  const m = str.match(/^(\d+)(%?)$/);
  if (!m) throw new Error(`prefetch: invalid --max-errors "${s}" (expected an integer or a percentage like "50" or "5%")`);
  return m[2] === "%" ? `${m[1]}%` : Number(m[1]);
}

// Total entries a run planned to fetch (fetched + skipped-fresh + errored).
function plannedCount(result) {
  if (!result) return 0;
  return (result.fetched || 0) + (result.skipped_fresh || 0) + (result.errors || 0);
}

// Resolves a --max-errors value into an absolute count against the planned total.
function errorBudget(maxErrors, planned) {
  if (maxErrors == null) return 0;
  if (typeof maxErrors === "number") return Number.isFinite(maxErrors) ? maxErrors : 0;
  const m = String(maxErrors).match(/^(\d+)%$/);
  if (m) return Math.floor((Number(m[1]) / 100) * (planned || 0));
  const n = Number(maxErrors);
  return Number.isFinite(n) ? n : 0;
}

// prefetch's 0-vs-1 exit code, counted only after the queue exhausts retries.
// Hard errors (data faults) count against `opts.maxErrors`; transient ones
// (the upstream throttling us) never fail a run on their own. Fatal errors
// exit 2 from main().
function exitCodeForResult(result, opts = {}) {
  const errors = (result && result.errors) || 0;
  if (errors === 0) return 0;
  // A source with errors but nothing fetched and nothing fresh is unreachable:
  // that fails regardless of budget or error class.
  const bySource = (result && result.by_source) || {};
  for (const s of Object.values(bySource)) {
    if (s && (s.errors || 0) > 0 && (s.fetched || 0) === 0 && (s.skipped_fresh || 0) === 0) {
      return 1;
    }
  }
  // Only hard errors gate against the budget. A result built without the split
  // (errors_hard undefined) treats every error as hard.
  const hardErrors = (result && result.errors_hard != null) ? result.errors_hard : errors;
  const budget = errorBudget(opts.maxErrors, plannedCount(result));
  return hardErrors > budget ? 1 : 0;
}

// One-line run summary; names per-source counts when a run has errors.
function formatSummary(result, opts = {}) {
  let line = `prefetch summary: ${result.fetched} fetched, ${result.skipped_fresh} fresh, ${result.errors} error(s)`;
  if (result.errors > 0 && result.by_source) {
    const parts = Object.entries(result.by_source)
      .filter(([, s]) => s && s.errors > 0)
      .map(([name, s]) => `${name}=${s.errors}`);
    if (parts.length) line += ` [${parts.join(", ")}]`;
  }
  // The transient/hard split; only hard errors gate exit 1.
  if (result.errors > 0 && result.errors_transient != null && result.errors_hard != null) {
    line += ` (${result.errors_transient} transient/throttled, ${result.errors_hard} hard)`;
  }
  if (opts.noNetwork) line += " (dry-run)";
  return line;
}

function printHelp() {
  console.log(`prefetch — warm a local cache of every upstream artifact this project consumes.

Sources:
  kev      CISA Known Exploited Vulnerabilities
  nvd      NIST NVD 2.0 per-CVE
  epss     FIRST EPSS per-CVE
  rfc      IETF Datatracker per-RFC
  pins     MITRE GitHub releases (ATLAS / ATT&CK)

Options:
  --max-age <dur>     skip entries fresher than this (e.g. 12h, 1d). Default: 24h.
  --source kev,nvd    scope by comma-separated source list.
  --force             ignore freshness; re-fetch every entry.
  --no-network        report-only; list what would be fetched.
  --cache-dir <path>  override cache root (default .cache/upstream).
  --quiet             suppress per-entry log lines.
  --max-errors <n|n%> tolerate up to n (or n% of planned) HARD per-entry fetch
                      errors before exit 1. Default: 0 (any hard error exits 1).
                      Transient errors (rate-limit / timeout / 5xx that
                      exhausted retries) never fail the run on their own — they
                      are surfaced in the summary and retried on the next run.
                      A fully-dead source still exits 1 regardless of budget.

Use NVD_API_KEY / GITHUB_TOKEN env vars to lift rate limits.

Outputs:
  <cache-dir>/_index.json                — per-entry metadata
  <cache-dir>/<source>/<id>.json         — raw upstream payloads
`);
}

async function timedFetch(url, headers = {}) {
  const ac = new AbortController();
  let timedOut = false;
  const t = setTimeout(() => { timedOut = true; ac.abort(); }, REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "application/json", ...headers },
    });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      // vendor/blamejs/retry.js isRetryable keys off err.statusCode, so a
      // 429/5xx reaches the backoff; err.status is for callers that message.
      err.statusCode = res.status;
      err.status = res.status;
      throw err;
    }
    const etag = res.headers.get("etag") || null;
    const lastModified = res.headers.get("last-modified") || null;
    const json = await res.json();
    return { json, etag, lastModified };
  } catch (e) {
    // An AbortError carries no statusCode and so would not be retried;
    // re-marking a timeout as ETIMEDOUT keeps the queue backing off.
    if (timedOut || (e && (e.name === "AbortError" || e.code === "ABORT_ERR"))) {
      const te = new Error(`request timed out after ${REQUEST_TIMEOUT_MS}ms`);
      te.code = "ETIMEDOUT";
      throw te;
    }
    throw e;
  } finally {
    clearTimeout(t);
  }
}

function loadIndex(cacheDir) {
  const p = path.join(cacheDir, "_index.json");
  if (!fs.existsSync(p)) return { entries: {}, generated_at: null };
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return { entries: {}, generated_at: null };
  }
}

// tmp + rename, so a reader sees either file whole. The `.tmp.<pid>.<rand>`
// sibling keeps the rename same-volume, which is what makes it atomic.
function writeFileAtomic(p, body) {
  const tmpPath = `${p}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 10)}`;
  fs.writeFileSync(tmpPath, body);
  try {
    fs.renameSync(tmpPath, p);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch {}
    throw err;
  }
}

// Lockfile-gated read-modify-write for _index.json; unlocked, two concurrent
// runs lose one's entries. A lockfile older than 30s is reclaimed as orphaned.
async function withIndexLock(cacheDir, mutator) {
  if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
  const lockPath = path.join(cacheDir, "_index.json.lock");
  const indexPath = path.join(cacheDir, "_index.json");
  const MAX_RETRIES = 50;
  const STALE_LOCK_MS = 30_000;
  let acquired = false;
  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      fs.writeFileSync(lockPath, String(process.pid), { flag: "wx" });
      acquired = true;
      break;
    } catch (e) {
      // EEXIST is "lock held" on POSIX; the same race surfaces as EPERM on
      // Windows, a sharing violation while the holder is mid-unlink.
      if (e.code !== "EEXIST" && e.code !== "EPERM") throw e;
      // PID liveness, mirroring withCatalogLock in lib/refresh-external.js:
      // ESRCH means the holder is dead, EPERM means alive under another user.
      let reclaimedByPid = false;
      try {
        const raw = fs.readFileSync(lockPath, "utf8").trim();
        const pid = Number.parseInt(raw, 10);
        if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
          try {
            process.kill(pid, 0);
          } catch (probeErr) {
            if (probeErr && probeErr.code === "ESRCH") {
              try { fs.unlinkSync(lockPath); reclaimedByPid = true; } catch {}
            }
          }
        }
      } catch {}
      if (reclaimedByPid) continue;
      try {
        const stat = fs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > STALE_LOCK_MS) {
          try { fs.unlinkSync(lockPath); } catch {}
          continue;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 50 + Math.random() * 150));
    }
  }
  if (!acquired) {
    throw new Error(`withIndexLock: could not acquire ${lockPath} after ${MAX_RETRIES} attempts`);
  }
  try {
    // Re-read inside the lock: a copy loaded before acquisition is stale.
    let current;
    if (fs.existsSync(indexPath)) {
      try { current = JSON.parse(fs.readFileSync(indexPath, "utf8")); }
      catch { current = { entries: {}, generated_at: null }; }
    } else {
      current = { entries: {}, generated_at: null };
    }
    const mutated = await mutator(current);
    const toWrite = mutated === undefined ? current : mutated;
    writeFileAtomic(indexPath, JSON.stringify(toWrite, null, 2) + "\n");
    return toWrite;
  } finally {
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

// Merges `idx.entries` into the on-disk index under the lock, so a concurrent
// run's writes survive the caller's possibly-stale in-memory snapshot.
async function saveIndex(cacheDir, idx) {
  await withIndexLock(cacheDir, (current) => {
    const mergedEntries = { ...current.entries, ...idx.entries };
    return {
      entries: mergedEntries,
      generated_at: idx.generated_at || current.generated_at,
    };
  });
}

// Canonical bytes for _index.json signing, mirroring canonicalManifestBytes in
// lib/sign.js: deep-sorted keys, no formatting to drift against, and
// `index_signature` excluded. verifyIndexSignature below must match any change.
function canonicalizeIndex(value) {
  if (Array.isArray(value)) return value.map(canonicalizeIndex);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeIndex(value[key]);
    }
    return out;
  }
  return value;
}
function canonicalIndexBytes(idx) {
  const clone = Object.assign({}, idx);
  delete clone.index_signature;
  return Buffer.from(JSON.stringify(canonicalizeIndex(clone)), "utf8");
}

// Signs _index.json with .keys/private.pem into the sidecar `_index.json.sig`.
// With no private key present it warns and returns { signed: false }.
function signIndex(cacheDir) {
  const privPath = path.join(ROOT, ".keys", "private.pem");
  if (!fs.existsSync(privPath)) {
    console.warn(
      `[prefetch] WARN: .keys/private.pem absent — _index.json written unsigned. ` +
      `Downstream consumers reading this cache via --from-cache will refuse it ` +
      `unless they pass --force-stale.`
    );
    return { signed: false };
  }
  const indexPath = path.join(cacheDir, "_index.json");
  if (!fs.existsSync(indexPath)) return { signed: false };
  const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  const bytes = canonicalIndexBytes(idx);
  const privKey = crypto.createPrivateKey(fs.readFileSync(privPath, "utf8"));
  const sig = crypto.sign(null, bytes, privKey);
  const sidecar = {
    algorithm: "Ed25519",
    signature_base64: sig.toString("base64"),
    signed_at: new Date().toISOString(),
  };
  writeFileAtomic(path.join(cacheDir, "_index.json.sig"), JSON.stringify(sidecar, null, 2) + "\n");
  return { signed: true };
}

// Returns { status: "valid" | "missing" | "invalid", reason? } for _index.json
// against its sidecar and keys/public.pem. Callers set policy.
function verifyIndexSignature(cacheDir) {
  const indexPath = path.join(cacheDir, "_index.json");
  const sigPath = path.join(cacheDir, "_index.json.sig");
  if (!fs.existsSync(indexPath)) return { status: "missing", reason: "_index.json not present" };
  if (!fs.existsSync(sigPath)) return { status: "missing", reason: "_index.json.sig not present (cache was prefetched without a signing key)" };
  let sidecar;
  try { sidecar = JSON.parse(fs.readFileSync(sigPath, "utf8")); }
  catch (e) { return { status: "invalid", reason: `_index.json.sig parse: ${e.message}` }; }
  if (!sidecar || sidecar.algorithm !== "Ed25519" || typeof sidecar.signature_base64 !== "string") {
    return { status: "invalid", reason: "_index.json.sig missing algorithm or signature_base64" };
  }
  const pubPath = path.join(ROOT, "keys", "public.pem");
  if (!fs.existsSync(pubPath)) return { status: "invalid", reason: "keys/public.pem absent — cannot verify cache signature" };
  const pubPem = fs.readFileSync(pubPath, "utf8");
  // The pin is checked BEFORE crypto.verify: a swapped host-local public.pem
  // paired with an attacker-signed sidecar verifies against the attacker's own
  // key. KEYS_ROTATED=1 permits a legitimate rotation.
  try {
    const { publicKeyFingerprint, checkExpectedFingerprint } = require("./verify.js");
    const pinResult = checkExpectedFingerprint(publicKeyFingerprint(pubPem));
    if (pinResult.status === "mismatch" && !pinResult.rotationOverride) {
      return {
        status: "invalid",
        reason: `fingerprint-mismatch: live=${pinResult.actual} pin=${pinResult.expected} — keys/public.pem does not match keys/EXPECTED_FINGERPRINT. If this is an intentional rotation, set KEYS_ROTATED=1 and update the pin.`,
      };
    }
  } catch {
    // verify.js unavailable (partial install): the signature check below runs
    // unpinned rather than refusing here.
  }
  const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  const bytes = canonicalIndexBytes(idx);
  const pubKey = crypto.createPublicKey(pubPem);
  let sigBytes;
  try { sigBytes = Buffer.from(sidecar.signature_base64, "base64"); }
  catch (e) { return { status: "invalid", reason: `signature_base64 decode: ${e.message}` }; }
  let ok = false;
  try { ok = crypto.verify(null, bytes, pubKey, sigBytes); }
  catch (e) { return { status: "invalid", reason: `crypto.verify threw: ${e.message}` }; }
  return ok ? { status: "valid" } : { status: "invalid", reason: "Ed25519 signature did not verify against keys/public.pem" };
}

function entryKey(source, id) {
  return `${source}/${id}`;
}

function entryPath(cacheDir, source, id) {
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(cacheDir, source, `${safe}.json`);
}

function isFresh(idx, source, id, maxAgeMs) {
  const e = idx.entries[entryKey(source, id)];
  if (!e) return false;
  if (!e.fetched_at) return false;
  const ageMs = Date.now() - new Date(e.fetched_at).getTime();
  // A non-finite or negative age is untrustworthy provenance — an unparseable
  // or future-dated fetched_at — so re-fetch. readCached's guard must match.
  if (!Number.isFinite(ageMs) || ageMs < 0) return false;
  return ageMs < maxAgeMs;
}

function authHeadersForSource(source) {
  if (source === "nvd" && process.env.NVD_API_KEY) return { apiKey: process.env.NVD_API_KEY };
  // `pins` is the registered source name; `github` is accepted too, so
  // GITHUB_TOKEN reaches the header whichever spelling an operator uses.
  if ((source === "pins" || source === "github") && process.env.GITHUB_TOKEN) {
    return { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` };
  }
  return {};
}

async function prefetch(options = {}) {
  const opts = { maxAgeMs: 24 * 3600 * 1000, source: null, force: false, noNetwork: false, cacheDir: DEFAULT_CACHE, quiet: false, ...options };
  // Bound here, at the function that issues the fetches, so a direct
  // prefetch({...}) call bypassing parseArgs still cannot egress under air-gap.
  if (process.env.EXCEPTD_AIR_GAP === "1" || opts.airGap) opts.noNetwork = true;
  const ctx = loadCtx();
  // An omitted --source warms every source; a supplied-but-empty one throws.
  const sourceSupplied = opts.source != null;
  const chosen = sourceSupplied
    ? opts.source.split(",").map((s) => s.trim()).filter(Boolean)
    : Object.keys(SOURCES);
  if (sourceSupplied && chosen.length === 0) {
    throw new Error('prefetch: --source given but resolved to no source names (empty or comma-only value)');
  }
  for (const n of chosen) {
    if (!SOURCES[n]) {
      if (LIVE_ONLY_REFRESH_SOURCES.has(n)) {
        throw new Error(`prefetch: source "${n}" has no prefetch cache layer (live id lookup only); prefetchable sources: ${Object.keys(SOURCES).join(",")}`);
      }
      throw new Error(`prefetch: unknown source "${n}"; prefetchable sources: ${Object.keys(SOURCES).join(",")}`);
    }
  }

  // Per-source budgets; NVD and GitHub lift theirs when an env key is present.
  const sources = {};
  for (const n of chosen) {
    const cfg = SOURCES[n];
    const rate = (n === "nvd" && process.env.NVD_API_KEY && cfg.rate_with_key)
      || (n === "pins" && process.env.GITHUB_TOKEN && cfg.rate_with_key)
      || cfg.rate
      || null;
    sources[n] = { concurrency: cfg.concurrency, ...(rate ? { rate } : {}) };
  }
  const queue = new JobQueue({ sources });

  const idx = loadIndex(opts.cacheDir);
  if (!fs.existsSync(opts.cacheDir)) fs.mkdirSync(opts.cacheDir, { recursive: true });

  const log = (s) => opts.quiet || console.log(s);
  const result = { fetched: 0, skipped_fresh: 0, errors: 0, errors_transient: 0, errors_hard: 0, by_source: {} };
  for (const s of chosen) result.by_source[s] = { fetched: 0, skipped_fresh: 0, errors: 0, errors_transient: 0, errors_hard: 0 };

  // Fetch (or fresh-skip) one plan item, writing the payload and its index
  // entry under lock. Returns the parsed body when `needData` is true, null
  // otherwise and on error — a fresh-skip pays an extra cache read to honour it.
  async function fetchEntry(item, { needData = false } = {}) {
    if (item.fresh) {
      result.skipped_fresh++;
      result.by_source[item.source].skipped_fresh++;
      if (!needData) return null;
      const cached = readCached(opts.cacheDir, item.source, item.id, { maxAgeMs: opts.maxAgeMs });
      return cached ? cached.data : null;
    }
    const headers = authHeadersForSource(item.source);
    // NVD takes its key in a custom header.
    const reqHeaders = item.source === "nvd" && headers.apiKey ? { apiKey: headers.apiKey } : (item.source === "pins" ? headers : {});
    try {
      const res = await queue.add({
        source: item.source,
        priority: priorityFor(item.source),
        run: () => timedFetch(item.url, reqHeaders),
        meta: { id: item.id },
      });
      const targetPath = entryPath(opts.cacheDir, item.source, item.id);
      const dir = path.dirname(targetPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const body = JSON.stringify(res.json, null, 2) + "\n";
      // Stage → lock → rename+index → release. Staging before the lock means a
      // lock timeout discards the payload rather than orphaning it outside the
      // index, where `readCached` could never see it.
      const tmpPath = `${targetPath}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 10)}`;
      fs.writeFileSync(tmpPath, body);
      const meta = {
        fetched_at: new Date().toISOString(),
        etag: res.etag,
        last_modified: res.lastModified,
        url: item.url,
        sha256: crypto.createHash("sha256").update(JSON.stringify(res.json)).digest("hex"),
      };
      try {
        // The rename is inside the lock: payload and index entry land as a pair.
        await withIndexLock(opts.cacheDir, (current) => {
          try {
            fs.renameSync(tmpPath, targetPath);
          } catch (renameErr) {
            // Throwing aborts the lock's write step; the outer catch counts it.
            throw renameErr;
          }
          current.entries[entryKey(item.source, item.id)] = meta;
          return current;
        });
        // In-memory mirror so a later in-run freshness check sees this entry.
        idx.entries[entryKey(item.source, item.id)] = meta;
      } catch (lockErr) {
        // Lock or rename failure: unlink the staged tmp so no orphan is left.
        try { fs.unlinkSync(tmpPath); } catch {}
        throw lockErr;
      }
      result.fetched++;
      result.by_source[item.source].fetched++;
      log(`  [${item.source}] ${item.id} — ok`);
      return needData ? res.json : null;
    } catch (err) {
      result.errors++;
      result.by_source[item.source].errors++;
      // Transient iff the queue's own isRetryable classifier says so.
      const transient = isRetryable(err);
      if (transient) {
        result.errors_transient++;
        result.by_source[item.source].errors_transient++;
      } else {
        result.errors_hard++;
        result.by_source[item.source].errors_hard++;
      }
      // stderr unconditionally: --quiet suppresses success chatter, not
      // diagnostics.
      console.error(`  [${item.source}] ${item.id} — ${transient ? "transient" : "hard"} error: ${err.message}`);
      return null;
    }
  }

  // KEV resolves BEFORE nvd/epss build their expansion lists, so a CVE added
  // today gets its sidecar warmed in THIS run. Skipped when kev is out of scope
  // or the network is off; ctx.kevFeed then stays unset.
  let kevPrefetched = false;
  if (chosen.includes("kev") && !opts.noNetwork) {
    const [kevEntry] = SOURCES.kev.expand();
    if (kevEntry) {
      const fresh = !opts.force && isFresh(idx, "kev", kevEntry.id, opts.maxAgeMs);
      const data = await fetchEntry({ source: "kev", id: kevEntry.id, url: kevEntry.url, fresh }, { needData: true });
      if (data) ctx.kevFeed = data;
      kevPrefetched = true;
    }
  }

  const plan = [];
  for (const sourceName of chosen) {
    if (sourceName === "kev" && kevPrefetched) continue; // already resolved above
    const cfg = SOURCES[sourceName];
    const entries = cfg.expand(ctx);
    for (const e of entries) {
      const fresh = !opts.force && isFresh(idx, sourceName, e.id, opts.maxAgeMs);
      plan.push({ source: sourceName, id: e.id, url: e.url, fresh });
    }
  }

  const totalItems = plan.length + (kevPrefetched ? 1 : 0);
  log(`\nprefetch — ${opts.noNetwork ? "DRY-RUN" : "fetching"} ${totalItems} item(s) across ${chosen.length} source(s)`);
  log(`Cache dir: ${path.relative(ROOT, opts.cacheDir)}`);
  log(`Max age:   ${(opts.maxAgeMs / 3_600_000).toFixed(1)}h${opts.force ? "  (forced)" : ""}`);

  if (opts.noNetwork) {
    for (const item of plan) {
      const tag = item.fresh ? "FRESH (skip)" : "STALE (would fetch)";
      log(`  [${item.source}] ${item.id} — ${tag}`);
      if (item.fresh) {
        result.skipped_fresh++;
        result.by_source[item.source].skipped_fresh++;
      }
    }
    // Unconditional: --quiet drops per-entry chatter, not the run's outcome.
    const stale = plan.length - result.skipped_fresh;
    console.log(`prefetch summary: 0 fetched, ${result.skipped_fresh} fresh, ${stale} would-fetch (dry-run)`);
    return result;
  }

  const jobPromises = plan.map((item) => fetchEntry(item));

  await Promise.all(jobPromises);
  await queue.drain();
  // Stamps generated_at on the CURRENT on-disk index and nothing else:
  // re-merging the start-of-run `idx` snapshot would resurrect entries a
  // concurrent run pruned.
  await withIndexLock(opts.cacheDir, (current) => {
    current.generated_at = new Date().toISOString();
    return current;
  });

  try {
    signIndex(opts.cacheDir);
  } catch (err) {
    console.warn(`[prefetch] WARN: _index.json signing failed: ${err && err.message}; cache left unsigned.`);
  }

  console.log(formatSummary(result, { noNetwork: opts.noNetwork }));
  return result;
}

function priorityFor(source) {
  // KEV is operationally most urgent; pins are least.
  return { kev: 10, nvd: 8, epss: 6, rfc: 4, pins: 2 }[source] || 0;
}

function loadCtx() {
  return {
    manifest: JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8")),
    cveCatalog: JSON.parse(fs.readFileSync(path.join(ROOT, "data/cve-catalog.json"), "utf8")),
    rfcCatalog: JSON.parse(fs.readFileSync(path.join(ROOT, "data/rfc-references.json"), "utf8")),
  };
}

// Returns { data, age_ms, meta } for a cached entry, or null when it is absent
// or stale. Defaults: 24h freshness, allowStale=false.
function readCached(cacheDir, source, id, opts = {}) {
  const maxAgeMs = opts.maxAgeMs ?? 24 * 3600 * 1000;
  const idx = loadIndex(cacheDir);
  const meta = idx.entries[entryKey(source, id)];
  if (!meta) return null;
  // `NaN > maxAgeMs` is false, so an unparseable fetched_at would read as
  // fresh. A non-finite age is no provenance: refuse unless allowStale.
  const ageMs = meta.fetched_at ? Date.now() - new Date(meta.fetched_at).getTime() : NaN;
  // A future-dated fetched_at is refused even under allowStale.
  if (Number.isFinite(ageMs) && ageMs < 0) return null;
  if (!opts.allowStale) {
    if (!meta.fetched_at || !Number.isFinite(ageMs)) return null;
    if (ageMs > maxAgeMs) return null;
  }
  const p = entryPath(cacheDir, source, id);
  if (!fs.existsSync(p)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(p, "utf8"));
    return { data, age_ms: Number.isFinite(ageMs) ? ageMs : null, meta };
  } catch {
    return null;
  }
}

// --flag base names prefetch accepts; drives the unknown-flag error message.
const PREFETCH_KNOWN_FLAGS = Object.freeze([
  "--force", "--no-network", "--dry-run", "--air-gap", "--quiet", "--help", "-h",
  "--source", "--max-age", "--cache-dir", "--max-errors",
]);

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    printHelp();
    return;
  }

  // Usage errors exit 2 rather than run with an unintended scope or tolerance.
  if (opts._argError) {
    process.stderr.write(JSON.stringify({
      ok: false,
      verb: "prefetch",
      error: opts._argError,
    }) + "\n");
    process.exitCode = 2;
    return;
  }

  // Unknown flags are rejected before any network work: a swallowed typo like
  // `--max-aeg 12h` would otherwise fall through to a full-cache fetch.
  if (Array.isArray(opts._unknownFlags) && opts._unknownFlags.length > 0) {
    const uniq = [...new Set(opts._unknownFlags)];
    process.stderr.write(JSON.stringify({
      ok: false,
      verb: "prefetch",
      error: `prefetch: unknown flag(s): ${uniq.join(", ")}`,
      unknown_flags: uniq,
      known_flags: PREFETCH_KNOWN_FLAGS,
    }) + "\n");
    process.exitCode = 2;
    return;
  }
  // `process.exitCode` + return, never process.exit(): exiting while undici's
  // pool and the AbortController listeners tear down trips a libuv assertion
  // on Windows.
  try {
    const result = await prefetch(opts);
    process.exitCode = exitCodeForResult(result, opts);
  } catch (err) {
    console.error(`prefetch: fatal: ${err.message}`);
    process.exitCode = 2;
  }
}

if (require.main === module) main();

module.exports = {
  prefetch,
  readCached,
  parseArgs,
  parseErrorThreshold,
  exitCodeForResult,
  formatSummary,
  SOURCES,
  DEFAULT_CACHE,
  newKevIds,
  // Exported for lib/refresh-external.js, which verifies the sidecar before
  // trusting any --from-cache entry.
  signIndex,
  verifyIndexSignature,
  canonicalIndexBytes,
  // Test-only access; not operator-facing API.
  _internal: { withIndexLock, writeFileAtomic, loadIndex, saveIndex, timedFetch },
};
