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
 *   ietf/<doc-name>.json                              — IETF Datatracker doc record
 *   github/<owner>__<repo>__releases.json             — releases listing
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
  ietf     IETF Datatracker per-RFC
  github   MITRE GitHub releases (ATLAS / ATT&CK / D3FEND / CWE)

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

function saveIndex(cacheDir, idx) {
  if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, "_index.json"), JSON.stringify(idx, null, 2) + "\n", "utf8");
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
  if (source === "github" && process.env.GITHUB_TOKEN) return { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` };
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
      .then((res) => {
        const dir = path.dirname(entryPath(opts.cacheDir, item.source, item.id));
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(entryPath(opts.cacheDir, item.source, item.id), JSON.stringify(res.json, null, 2) + "\n", "utf8");
        idx.entries[entryKey(item.source, item.id)] = {
          fetched_at: new Date().toISOString(),
          etag: res.etag,
          last_modified: res.lastModified,
          url: item.url,
          sha256: crypto.createHash("sha256").update(JSON.stringify(res.json)).digest("hex"),
        };
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
  saveIndex(opts.cacheDir, idx);

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
  const ageMs = Date.now() - new Date(meta.fetched_at).getTime();
  if (!opts.allowStale && ageMs > maxAgeMs) return null;
  const p = entryPath(cacheDir, source, id);
  if (!fs.existsSync(p)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(p, "utf8"));
    return { data, age_ms: ageMs, meta };
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

module.exports = { prefetch, readCached, parseArgs, SOURCES, DEFAULT_CACHE };
