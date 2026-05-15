"use strict";
/**
 * lib/prefetch.js
 *
 * Pre-downloads every upstream artifact the project queries (CISA KEV,
 * NIST NVD per-CVE, FIRST EPSS per-CVE, IETF Datatracker per-RFC, MITRE
 * GitHub releases) into a local cache directory. Operators behind an air
 * gap can run this once on a connected host and ship `.cache/upstream/`
 * across the boundary. CI runs use it as a warm cache so each refresh job
 * doesn't re-pay full network latency.
 *
 * Cache layout (`.cache/upstream/` by default — gitignored):
 *
 *   _index.json                                       — per-entry fetch metadata
 *   kev/known_exploited_vulnerabilities.json          — full KEV feed
 *   nvd/<cve-id>.json                                 — NVD 2.0 per-CVE response
 *   epss/<cve-id>.json                                — EPSS per-CVE response
 *   rfc/<doc-name>.json                               — IETF Datatracker doc record
 *   pins/<owner>__<repo>__releases.json               — MITRE GitHub releases listing
 *
 * The registered source names in SOURCES below are `rfc` and `pins`.
 * `--source ietf` or `--source github` would hit "unknown source"
 * because no such key exists. The names below are the canonical ones
 * consumed by --source filtering.
 *
 * Usage:
 *   node lib/prefetch.js                  # fetch everything not fresh
 *   node lib/prefetch.js --max-age 12h    # re-fetch entries older than 12h
 *   node lib/prefetch.js --source kev,nvd # scope by source
 *   node lib/prefetch.js --force          # ignore freshness, refetch all
 *   node lib/prefetch.js --no-network     # report-only: list what would be fetched
 *
 * Every fetch routes through lib/job-queue.js so per-source rate budgets
 * (NVD 5 req/30s anon, GitHub 60/h anon, etc.) are respected.
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { JobQueue } = require("./job-queue");

const ROOT = path.join(__dirname, "..");
const DEFAULT_CACHE = path.join(ROOT, ".cache", "upstream");
const REQUEST_TIMEOUT_MS = 10_000;
const USER_AGENT = "exceptd-security/prefetch (+https://exceptd.com)";

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
    expand: (ctx) => Object.keys(ctx.cveCatalog)
      .filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k))
      .map((id) => ({ id, url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}` })),
  },
  epss: {
    description: "FIRST.org EPSS per-CVE responses",
    rate: { tokens: 30, windowMs: 60_000 },
    concurrency: 4,
    expand: (ctx) => Object.keys(ctx.cveCatalog)
      .filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k))
      .map((id) => ({ id, url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}` })),
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
    // D3FEND and CWE were previously listed here but neither project
    // publishes via GitHub Releases — D3FEND distributes the ontology
    // from d3fend/d3fend-ontology without tagged releases, and CWE
    // ships its catalog as XML/JSON downloads from cwe.mitre.org rather
    // than a GitHub repo. The old api.github.com URLs (mitre/cwe and
    // d3fend/d3fend-data) returned HTTP 404 on every refresh, surfacing
    // as "2 error(s)" in the prefetch summary. Pin currency for those
    // two frameworks is tracked via lib/upstream-check.js against
    // cwe.mitre.org and d3fend.mitre.org respectively; the prefetch
    // registry only contains sources that actually have a GitHub
    // Releases feed to poll.
    expand: () => [
      { id: "mitre-atlas__atlas-data__releases", url: "https://api.github.com/repos/mitre-atlas/atlas-data/releases?per_page=5" },
      { id: "mitre-attack__attack-stix-data__releases", url: "https://api.github.com/repos/mitre-attack/attack-stix-data/releases?per_page=5" },
    ],
  },
};

function parseArgs(argv) {
  const out = { maxAgeMs: 24 * 3600 * 1000, source: null, force: false, noNetwork: false, cacheDir: DEFAULT_CACHE, quiet: false, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--force") out.force = true;
    else if (a === "--no-network" || a === "--dry-run") out.noNetwork = true;
    else if (a === "--quiet") out.quiet = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--source") out.source = argv[++i];
    else if (a.startsWith("--source=")) out.source = a.slice("--source=".length);
    else if (a === "--max-age") out.maxAgeMs = parseDuration(argv[++i]);
    else if (a.startsWith("--max-age=")) out.maxAgeMs = parseDuration(a.slice("--max-age=".length));
    else if (a === "--cache-dir") out.cacheDir = path.resolve(argv[++i]);
    else if (a.startsWith("--cache-dir=")) out.cacheDir = path.resolve(a.slice("--cache-dir=".length));
  }
  return out;
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

Use NVD_API_KEY / GITHUB_TOKEN env vars to lift rate limits.

Outputs:
  <cache-dir>/_index.json                — per-entry metadata
  <cache-dir>/<source>/<id>.json         — raw upstream payloads
`);
}

async function timedFetch(url, headers = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "application/json", ...headers },
    });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    const etag = res.headers.get("etag") || null;
    const lastModified = res.headers.get("last-modified") || null;
    const json = await res.json();
    return { json, etag, lastModified };
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

// v0.12.12 C4: atomic write helper — tmp + rename. Concurrent readers either
// see the prior file in full or the new file in full, never a half-written
// buffer. fs.renameSync is atomic on POSIX and on Windows for same-volume
// renames; a `.tmp.<pid>.<rand>` sibling to the destination is always
// same-volume.
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

// v0.12.12 C2: lockfile-gated read-modify-write for _index.json. Two
// concurrent prefetch runs against the same cache dir previously raced —
// each loaded the index at start, mutated its in-memory copy as entries
// fetched, then wrote at the end. The second writer overwrote the first,
// silently dropping any entries the first run wrote.
//
// Stale-lock recovery: if a holder crashes without unlinking, the lockfile
// persists. After backoff, if the lockfile's mtime is older than 30s we
// treat it as orphaned and unlink it before retrying.
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
      // EEXIST is the POSIX signal another process holds the lock. On
      // Windows the same race surfaces as EPERM (a sharing-violation
      // raised when the other process is mid-unlink). Treat both as
      // "lock held, back off" rather than a fatal error.
      if (e.code !== "EEXIST" && e.code !== "EPERM") throw e;
      // PID-liveness check. Same pattern as withCatalogLock in
      // lib/refresh-external.js — read the lockfile's PID, probe with
      // process.kill(pid, 0); ESRCH → holder dead, reclaim immediately;
      // EPERM → holder alive (different user), keep waiting. The mtime
      // fallback below covers malformed / unreadable lockfiles.
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
    // Always re-read the current on-disk index inside the lock. Stale
    // in-memory copies from before acquisition are the entire bug class.
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

// Back-compat: existing callers used saveIndex(cacheDir, idx). The thin
// wrapper merges entries under the lock so a concurrent run's writes are
// preserved (rather than blindly overwriting them with the caller's
// possibly-stale in-memory `idx`).
async function saveIndex(cacheDir, idx) {
  await withIndexLock(cacheDir, (current) => {
    const mergedEntries = { ...current.entries, ...idx.entries };
    return {
      entries: mergedEntries,
      generated_at: idx.generated_at || current.generated_at,
    };
  });
}

// Canonical bytes for _index.json signing. Mirrors the manifest-signing
// contract (lib/sign.js + lib/verify.js canonicalManifestBytes): deep-sort
// keys, JSON.stringify with no formatting overhead the verifier can drift
// against. Any change here must be mirrored in verifyIndexSignature() below.
// The signature covers the index AS PERSISTED — `index_signature` is
// excluded from the canonical bytes (the signature cannot sign itself).
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

// Sign _index.json with the Ed25519 private key (.keys/private.pem). The
// signature is written as a sidecar `_index.json.sig` containing
// { algorithm: "Ed25519", signature_base64, signed_at }. readCachedJson /
// loadCtx --from-cache verify this against keys/public.pem.
//
// Behavior on missing private key: emit a warning and return; the cache is
// left unsigned. Operators on connected hosts where prefetch runs without
// the maintainer keypair will see this warning. The verify side treats a
// missing sidecar as "unsigned cache" and refuses unless --force-stale.
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

// Verify _index.json against its sidecar signature using keys/public.pem.
// Returns { status: "valid" | "missing" | "invalid", reason? }. Callers
// decide policy: typically refuse unless --force-stale on "missing" /
// "invalid".
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
  const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  const bytes = canonicalIndexBytes(idx);
  const pubKey = crypto.createPublicKey(fs.readFileSync(pubPath, "utf8"));
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
  // Sanitize id for filesystem.
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(cacheDir, source, `${safe}.json`);
}

function isFresh(idx, source, id, maxAgeMs) {
  const e = idx.entries[entryKey(source, id)];
  if (!e) return false;
  if (!e.fetched_at) return false;
  return Date.now() - new Date(e.fetched_at).getTime() < maxAgeMs;
}

function authHeadersForSource(source) {
  if (source === "nvd" && process.env.NVD_API_KEY) return { apiKey: process.env.NVD_API_KEY };
  // The registered source name for MITRE GitHub releases is `pins`
  // (see SOURCES above). Accept both `pins` and `github` so GITHUB_TOKEN
  // reaches the per-request Authorization header regardless of which
  // spelling the operator's automation uses; without this, anonymous
  // rate-limited fetches happen even when a token is configured. Be
  // forgiving of
  // the historical naming and the registered name.
  if ((source === "pins" || source === "github") && process.env.GITHUB_TOKEN) {
    return { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` };
  }
  return {};
}

async function prefetch(options = {}) {
  const opts = { maxAgeMs: 24 * 3600 * 1000, source: null, force: false, noNetwork: false, cacheDir: DEFAULT_CACHE, quiet: false, ...options };
  const ctx = loadCtx();
  const chosen = opts.source
    ? opts.source.split(",").map((s) => s.trim()).filter(Boolean)
    : Object.keys(SOURCES);
  for (const n of chosen) {
    if (!SOURCES[n]) throw new Error(`prefetch: unknown source "${n}"`);
  }

  // Build the queue with per-source budgets. NVD / GitHub upgrade if env-key
  // is present.
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

  const plan = [];
  for (const sourceName of chosen) {
    const cfg = SOURCES[sourceName];
    const entries = cfg.expand(ctx);
    for (const e of entries) {
      const fresh = !opts.force && isFresh(idx, sourceName, e.id, opts.maxAgeMs);
      plan.push({ source: sourceName, id: e.id, url: e.url, fresh });
    }
  }

  const log = (s) => opts.quiet || console.log(s);
  log(`\nprefetch — ${opts.noNetwork ? "DRY-RUN" : "fetching"} ${plan.length} item(s) across ${chosen.length} source(s)`);
  log(`Cache dir: ${path.relative(ROOT, opts.cacheDir)}`);
  log(`Max age:   ${(opts.maxAgeMs / 3_600_000).toFixed(1)}h${opts.force ? "  (forced)" : ""}`);

  const result = { fetched: 0, skipped_fresh: 0, errors: 0, by_source: {} };
  for (const s of chosen) result.by_source[s] = { fetched: 0, skipped_fresh: 0, errors: 0 };

  if (opts.noNetwork) {
    for (const item of plan) {
      const tag = item.fresh ? "FRESH (skip)" : "STALE (would fetch)";
      log(`  [${item.source}] ${item.id} — ${tag}`);
      if (item.fresh) {
        result.skipped_fresh++;
        result.by_source[item.source].skipped_fresh++;
      }
    }
    // Unconditional one-line summary (--quiet preserved on per-entry chatter
    // but operator still needs confirmation the dry-run completed).
    const stale = plan.length - result.skipped_fresh;
    console.log(`prefetch summary: 0 fetched, ${result.skipped_fresh} fresh, ${stale} would-fetch (dry-run)`);
    return result;
  }

  const jobPromises = plan.map((item) => {
    if (item.fresh) {
      result.skipped_fresh++;
      result.by_source[item.source].skipped_fresh++;
      return Promise.resolve();
    }
    const headers = authHeadersForSource(item.source);
    // NVD takes its key in a custom header.
    const reqHeaders = item.source === "nvd" && headers.apiKey ? { apiKey: headers.apiKey } : (item.source === "pins" ? headers : {});
    return queue
      .add({
        source: item.source,
        priority: priorityFor(item.source),
        run: () => timedFetch(item.url, reqHeaders),
        meta: { id: item.id },
      })
      .then(async (res) => {
        const targetPath = entryPath(opts.cacheDir, item.source, item.id);
        const dir = path.dirname(targetPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const body = JSON.stringify(res.json, null, 2) + "\n";
        // Stage the payload to a same-volume tmp file BEFORE attempting
        // to acquire the index lock. If withIndexLock fails (timeout
        // after MAX_RETRIES), the partially-completed download must be
        // discarded — not left on disk as an orphan payload with no
        // index entry. Air-gap operators feed off `readCached`, which
        // consults the index; an unindexed payload silently becomes junk
        // taking cache space. Pattern: stage → lock → rename+index →
        // release. The rename is atomic same-volume; if it fails inside
        // the lock we clean up the tmp file. If we never reach the rename
        // (lock acquisition throws), the tmp file is unlinked in the
        // catch block below.
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
          // v0.12.12 C2: persist this entry's metadata to _index.json under
          // lock immediately, merging with whatever the on-disk index has
          // (another concurrent prefetch may have written sibling entries).
          // Inside the lock we also rename the staged tmp → final path so
          // a concurrent reader sees the new payload + new index entry as
          // an atomic pair.
          await withIndexLock(opts.cacheDir, (current) => {
            try {
              fs.renameSync(tmpPath, targetPath);
            } catch (renameErr) {
              // Surface as a failure to mutator: throwing here aborts the
              // lock's write step. We re-throw to the outer catch which
              // will increment errors.
              throw renameErr;
            }
            current.entries[entryKey(item.source, item.id)] = meta;
            return current;
          });
          // Mirror the entry into the in-memory idx for callers that read
          // it later in this run (e.g. the final saveIndex merge).
          idx.entries[entryKey(item.source, item.id)] = meta;
        } catch (lockErr) {
          // Lock failure OR rename-inside-lock failure — unlink the staged
          // tmp so the cache directory does not accumulate orphans.
          try { fs.unlinkSync(tmpPath); } catch {}
          throw lockErr;
        }
        result.fetched++;
        result.by_source[item.source].fetched++;
        log(`  [${item.source}] ${item.id} — ok`);
      })
      .catch((err) => {
        result.errors++;
        result.by_source[item.source].errors++;
        log(`  [${item.source}] ${item.id} — error: ${err.message}`);
      });
  });

  await Promise.all(jobPromises);
  await queue.drain();
  idx.generated_at = new Date().toISOString();
  // v0.12.12 C2: saveIndex now merges under lock with whatever is on disk
  // (another concurrent prefetch's entries). Without the merge, a sibling
  // run's writes would be silently overwritten here at the end of our run.
  await saveIndex(opts.cacheDir, idx);

  // Sign the freshly-written _index.json with the Ed25519 private key
  // (.keys/private.pem). The signature is a sidecar `_index.json.sig`;
  // consumers reading via --from-cache verify it against keys/public.pem
  // before trusting any entry. If the private key is absent (typical on
  // operator-side prefetch runs where the maintainer keypair isn't
  // present), signIndex() warns-and-returns and the cache is left
  // unsigned — downstream verify will then refuse it without --force-stale.
  try {
    signIndex(opts.cacheDir);
  } catch (err) {
    console.warn(`[prefetch] WARN: _index.json signing failed: ${err && err.message}; cache left unsigned.`);
  }

  // Final summary is unconditional — --quiet suppresses per-entry chatter
  // (the noisy part) but the operator still needs one line confirming success.
  // Without this, --quiet + --no-network was zero output even on dry-run
  // success, leaving operators unsure if the command had run at all.
  console.log(`prefetch summary: ${result.fetched} fetched, ${result.skipped_fresh} fresh, ${result.errors} error(s)${opts.noNetwork ? " (dry-run)" : ""}`);
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

// --- Cache-read helpers (consumed by validate-cves / validate-rfcs / refresh)

/**
 * Read a cached entry, returning `null` if absent or stale.
 *
 * @param {string} cacheDir  cache root
 * @param {string} source    "kev" | "nvd" | "epss" | "ietf" | "github"
 * @param {string} id        entry id (CVE-id, doc-name, etc.)
 * @param {object} opts      { maxAgeMs?: number; allowStale?: boolean }
 *                           defaults: 24h fresh, allowStale=false
 * @returns {{ data: object, age_ms: number, meta: object } | null}
 */
function readCached(cacheDir, source, id, opts = {}) {
  const maxAgeMs = opts.maxAgeMs ?? 24 * 3600 * 1000;
  const idx = loadIndex(cacheDir);
  const meta = idx.entries[entryKey(source, id)];
  if (!meta) return null;
  // When `fetched_at` is missing / non-string / unparseable,
  // `new Date(undefined).getTime()` is NaN and `NaN > maxAgeMs` is false,
  // so the cached entry would have been returned as if fresh. Treat any
  // non-finite age as "no provenance, refuse" unless the caller explicitly
  // opted into allowStale.
  const ageMs = meta.fetched_at ? Date.now() - new Date(meta.fetched_at).getTime() : NaN;
  // Future-dated `fetched_at` (ageMs < 0) is a poisoning signal: either the
  // host clock jumped backwards mid-fetch, or an attacker rewrote the index
  // to inflate apparent freshness past the maxAge gate. Either way the
  // entry's provenance is no longer trustworthy. Treat as missing — refuse
  // even when allowStale is set, because allowStale loosens the upper bound,
  // not the lower one.
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

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    printHelp();
    return;
  }
  // Why process.exitCode and not process.exit():
  // On Windows + Node 25 (libuv), calling process.exit() synchronously
  // while in-flight fetch / AbortController teardown is still mid-close
  // produced `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING),
  // file src\win\async.c, line 76` followed by exit 3221226505
  // (STATUS_STACK_BUFFER_OVERRUN). The summary line had already
  // flushed, so operators saw the crash *after* their summary —
  // contractually correct but visibly noisy. Letting the event loop
  // drain naturally — via exitCode + return — lets undici's connection
  // pool and the AbortController signal listeners finish teardown
  // before the process exits, eliminating the assertion. Same pattern
  // documented in CLAUDE.md for v0.11.11's `ci` #100 regression.
  try {
    const result = await prefetch(opts);
    process.exitCode = result.errors > 0 ? 1 : 0;
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
  SOURCES,
  DEFAULT_CACHE,
  // Ed25519 _index.json signing + verification. Exported so
  // lib/refresh-external.js (which consumes --from-cache) can verify the
  // sidecar before trusting any cached entry, and so test harnesses can
  // exercise the signing path without running the full prefetch pipeline.
  signIndex,
  verifyIndexSignature,
  canonicalIndexBytes,
  // v0.12.12 C2: exported for the concurrent-writer regression test.
  // Not part of the operator-facing API — internal contract for tests
  // that need to exercise the lockfile path without spawning the full
  // prefetch network pipeline.
  _internal: { withIndexLock, writeFileAtomic, loadIndex, saveIndex },
};
