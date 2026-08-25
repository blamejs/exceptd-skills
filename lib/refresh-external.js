"use strict";
/**
 * External-data refresh orchestrator: reports upstream drift (dry-run, the
 * default) or upserts it into the local catalog (--apply).
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { selectNvdCvss, cvssVersionOf } = require("./cvss");
const { renderEpssNote } = require("./cve-enrich");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const TODAY = new Date().toISOString().slice(0, 10);

// Every write site in this file resolves the catalog path through here, so a
// --catalog / EXCEPTD_CVE_CATALOG redirect holds across all of them.
function resolveCatalogPath(opts) {
  if (opts && opts.catalog) return path.resolve(opts.catalog);
  if (process.env.EXCEPTD_CVE_CATALOG) return path.resolve(process.env.EXCEPTD_CVE_CATALOG);
  return ABS("data/cve-catalog.json");
}

function parseArgs(argv) {
  const out = {
    apply: false,
    source: null,        // comma-separated list or null = all
    fromFixture: null,   // path to fixture dir
    fromCache: null,     // path to .cache/upstream dir (or default if --from-cache passed bare)
    swarm: false,        // fan-out sources across worker threads
    advisory: null,      // single-advisory seed (CVE-* or GHSA-*)
    help: false,
    quiet: false,
    json: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--apply") out.apply = true;
    else if (a === "--quiet") out.quiet = true;
    else if (a === "--swarm") out.swarm = true;
    else if (a === "--json") out.json = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--advisory") { out.advisory = argv[++i]; }
    else if (a.startsWith("--advisory=")) { out.advisory = a.slice("--advisory=".length); }
    else if (a === "--check-advisories") { out.source = "advisories"; out.apply = false; out.checkAdvisories = true; }
    else if (a === "--catalog") { out.catalog = argv[++i]; }
    else if (a.startsWith("--catalog=")) { out.catalog = a.slice("--catalog=".length); }
    else if (a === "--from-cache") {
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) { out.fromCache = next; i++; }
      else out.fromCache = ".cache/upstream";
    }
    else if (a.startsWith("--from-cache=")) out.fromCache = a.slice("--from-cache=".length);
    else if (a === "--source") out.source = argv[++i];
    else if (a.startsWith("--source=")) out.source = a.slice("--source=".length);
    else if (a === "--from-fixture") out.fromFixture = argv[++i];
    else if (a.startsWith("--from-fixture=")) out.fromFixture = a.slice("--from-fixture=".length);
    else if (a === "--report-out") out.reportOut = argv[++i];
    else if (a.startsWith("--report-out=")) out.reportOut = a.slice("--report-out=".length);
    else if (a === "--air-gap") out.airGap = true;
    // Bypasses the cache freshness and signature refusals.
    else if (a === "--force-stale") out.forceStale = true;
    else if (a === "--drift-only") out.driftOnly = true;
    // Cache operations; main() delegates them to lib/prefetch.js.
    else if (a === "--no-network") { out.noNetwork = true; }
    else if (a === "--prefetch") { out.prefetch = true; }
    // bin-translated aliases, accepted so the unknown-flag guard below spares them.
    else if (
      a === "--indexes-only" ||
      a === "--network" || a === "--curate" || a === "--force-stale-acked"
    ) { /* accepted, no-op at this layer */ }
    // Any remaining --flag is a typo: recorded here, refused in main().
    else if (typeof a === "string" && a.startsWith("--")) {
      const base = a.indexOf("=") === -1 ? a : a.slice(0, a.indexOf("="));
      (out._unknownFlags || (out._unknownFlags = [])).push(base);
    }
  }
  if (process.env.EXCEPTD_FORCE_STALE === "1") out.forceStale = true;
  // Report-only is intrinsic to the advisory poll regardless of flag order —
  // a trailing --apply must not turn it into a catalog mutation.
  if (out.checkAdvisories) out.apply = false;
  return out;
}

function printHelp() {
  console.log(`refresh — pull latest upstream data, optionally upsert into local catalogs.

Default behavior is to actually fetch from the network in dry-run mode and write
refresh-report.json. Use --apply to upsert findings into local catalogs.

Modes:
  (default)          fetch all sources from network, dry-run, write refresh-report.json
  --apply            apply diffs and rebuild indexes (default also fetches; combine)
  --network          fetch the latest signed catalog snapshot from the
                     maintainer's npm-published tarball, verify every skill
                     signature against the local public.pem, swap data/ in
                     place. Same trust anchor as \`npm update -g\`, only the
                     data slice changes — useful when you want fresher
                     intel without re-resolving CLI/lib code.
  --prefetch         populate the cache for offline use. Equivalent to
                     \`exceptd prefetch\`.
  --no-network       report-only: list what would be fetched, WITHOUT writing
                     the cache (the dry-run opposite of --prefetch).
  --from-cache [<p>] read from prefetch cache (default .cache/upstream).
                     Combine with --apply to upsert against cached data. New-RFC
                     discovery still queries IETF Datatracker live; add --air-gap
                     for a fully offline run. Cache must be pre-populated via --prefetch.
  --source kev,epss  scope to a comma-separated list (kev|epss|nvd|rfc|pins|ghsa|osv)
  --drift-only       reconcile the entries the catalog already holds; skip
                     auto-discovery of new ones. Discovered entries arrive as
                     drafts that still need curation, so this is the flag for
                     correcting stale fields on shipped entries without pulling
                     that work into the same change.
  --check-advisories poll primary-source advisory feeds (Qualys TRU, RHSA, USN,
                     ZDI, kernel.org, oss-security, vendor research blogs) and
                     report newly-seen CVE IDs ahead of NVD enrichment.
                     Report-only — emits diffs[]; never mutates the catalog.
                     Triage the output and seed promising IDs with
                     \`exceptd refresh --advisory <id> --apply\`.
  --from-fixture <p> use frozen fixture payloads (tests use this path)
  --indexes-only     rebuild data/_indexes/ only; no network. Equivalent to
                     \`exceptd refresh --indexes-only\`.
  --swarm            fan out sources across worker threads. Best with --from-cache.
  --advisory <id>    (v0.12.0) seed a single catalog entry from an advisory ID.
                     CVE-* and GHSA-* route through the GitHub Advisory
                     Database. When GHSA returns 404 for a CVE-* id
                     (CNAs / OSV mirrors operate on different cadences) the
                     dispatcher falls back to OSV.dev's /v1/vulns/{id}
                     before failing (v0.12.11). MAL-*, SNYK-*, RUSTSEC-*,
                     USN-*, UVI-*, GO-*, MGASA-*, PYSEC-*, and other
                     OSV-native namespaces route through OSV.dev (v0.12.10).
                     Writes a DRAFT to data/cve-catalog.json marked with
                     _auto_imported: true.
                     Editorial fields (framework_control_gaps, iocs,
                     atlas_refs, attack_refs) remain null pending review via:
                       exceptd run cve-curation --advisory <id>
                     Examples:
                       exceptd refresh --advisory CVE-2026-45321
                       exceptd refresh --advisory GHSA-xxxx-xxxx-xxxx --apply
                       exceptd refresh --advisory MAL-2026-3083
                       exceptd refresh --advisory RUSTSEC-2025-0001
  --curate <CVE-ID>  emit editorial questions + ranked candidates
                     (ATLAS/ATT&CK/CWE/framework gaps) for a draft entry.
                     With --answers <path> the operator-supplied answers
                     are validated, applied to the catalog entry, and the
                     draft is promoted out of _auto_imported / _draft once
                     every required schema field is populated. Atomic write;
                     concurrent --apply runs against the same catalog are
                     safe. --apply is an alias for "--answers implies write".
                     Examples:
                       exceptd refresh --curate CVE-2026-45321
                       exceptd refresh --curate CVE-2026-45321 --answers a.json --apply

Sources (default = all):
  kev   CISA Known Exploited Vulnerabilities
  epss  FIRST EPSS exploit-prediction scores
  nvd   NIST NVD per-CVE feed
  rfc   IETF Datatracker per-RFC
  pins  Upstream version-pin drift (MITRE ATLAS/ATT&CK/D3FEND/CWE) — report only
  ghsa  (v0.12.0) GitHub Advisory Database — npm/PyPI/Maven/etc. Lands new CVE
        IDs as DRAFTS (_auto_imported: true); catalog validator treats drafts
        as warnings, not errors. Editorial review still required.
  osv   (v0.12.10) OSV.dev aggregator — OSSF Malicious Packages (MAL-*) + Snyk
        + GHSA + RustSec + Mageia + Go Vuln DB + Ubuntu USN. Unauthenticated.
        Use --advisory MAL-* / RUSTSEC-* / SNYK-* / USN-* to seed a single
        draft. One advisory ID per invocation; there is no bulk or
        package-watchlist import.

Air-gap workflow:
  1. On a connected host:   \`exceptd refresh --prefetch\`
  2. Copy .cache/upstream/ across the boundary
  3. On the offline host:   \`exceptd refresh --from-cache --apply\`

Outputs:
  refresh-report.json (gitignored) — per-source status + every diff

Exit codes (refresh's own scheme — distinct from the seven-phase verbs):
  0  applied (or a clean dry-run with no diffs to surface)
  1  apply-mode downstream gate failed (build-indexes, or a per-source error)
  2  error (unknown --source, unreadable fixture, invalid --advisory id, air-gap refusal)
  3  draft produced, editorial review pending (a successful --advisory seed —
     NOT a failure; run --advisory <id> --apply to land it, or curate first)
  4  network/source unreachable OR cache precondition refused (unsigned/stale/tampered/unindexed cache)
Note: exit 3 here means "review needed", which differs from \`exceptd run\`'s
exit 3 ("ran but no evidence"). Script \`refresh --advisory\` on the body's
\`ok\` field, not on \`$? == 0\`.

This module never auto-applies version-pin bumps — those require audit per
AGENTS.md Hard Rule #12 and are surfaced as report-only findings.
`);
}

/**
 * Every source module exposes:
 *   fetchDiff(ctx, opts) -> { status: "ok" | "unreachable" | "partial",
 *                             diffs: [{ id, field, before, after, severity? }],
 *                             errors, summary }
 *   applyDiff(ctx, diffs) -> { updated, errors }, having written the catalog
 */

const { discoverNewKev, discoverNewRfcs } = require("./auto-discovery");

const KEV_SOURCE = {
  name: "kev",
  description: "CISA Known Exploited Vulnerabilities",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.kev) return synthesizeFromFixture(ctx, "kev");
    if (ctx.cacheDir) return kevDiffWithDiscoveryFromCache(ctx);
    const { validateAllCves } = require("../sources/validators");
    const report = await validateAllCves(ctx.cveCatalog, { concurrency: 4 });
    const diffs = [];
    let errors = 0;
    // A feed that parses but sits far below a real CISA snapshot must not be
    // trusted to de-list curated entries. With no size available, the per-entry
    // curated-signal guard is the fallback.
    let liveFeedSize = null;
    for (const r of report.results) {
      const n = r && r.fetched && r.fetched.sources && r.fetched.sources.kev
        && r.fetched.sources.kev.total_entries;
      if (typeof n === "number") { liveFeedSize = n; break; }
    }
    const feedComplete = liveFeedSize === null || liveFeedSize >= KEV_FEED_MIN_PLAUSIBLE;
    for (const r of report.results) {
      if (r.status === "unreachable") errors++;
      for (const d of r.discrepancies || []) {
        if (KEV_RECONCILED_FIELDS.has(d.field)) {
          const diff = { id: r.cve_id, field: d.field, before: d.local, after: d.fetched, severity: d.severity };
          // A designation REMOVED against an implausibly small feed is the feed
          // failing to say something, not upstream saying it is gone.
          if (d.field === "known_ransomware_use" && d.local === true && d.fetched === false && !feedComplete) {
            diff.review_only = true;
            diff.note = `Ransomware designation removal held for review: live feed returned only ${liveFeedSize} entries (< ${KEV_FEED_MIN_PLAUSIBLE}), likely incomplete.`;
          }
          // A de-listing is review-only — applyDiff skips those — when the entry
          // carries curated exploitation signal or the feed is implausibly small.
          if (d.field === "cisa_kev" && d.local === true && d.fetched === false &&
              (!feedComplete || hasCuratedExploitSignal(ctx.cveCatalog && ctx.cveCatalog[r.cve_id]))) {
            diff.review_only = true;
            diff.kev_delist_review = true;
            diff.note = !feedComplete
              ? `KEV de-listing held for review: live feed returned only ${liveFeedSize} entries (< ${KEV_FEED_MIN_PLAUSIBLE}), likely incomplete. Confirm against a complete CISA KEV snapshot before de-listing ${r.cve_id}.`
              : `KEV de-listing held for review: ${r.cve_id} carries curated exploitation signal; confirm a genuine CISA removal before downgrading.`;
          }
          diffs.push(diff);
        }
      }
    }
    return {
      status: errors === 0 ? "ok" : errors === report.results.length ? "unreachable" : "partial",
      diffs,
      errors,
      summary: `${diffs.length} KEV diffs; ${errors} unreachable / ${report.total} total`,
    };
  },
  async applyDiff(ctx, diffs) {
    let updated = 0;
    let added = 0;
    const errors = [];
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    await withCatalogLock(catalogPath, (catalog) => {
      for (const d of diffs) {
        if (d.op === "add") {
          if (catalog[d.id]) continue;
          catalog[d.id] = d.entry;
          added++;
          continue;
        }
        if (!catalog[d.id]) {
          errors.push(`KEV: no local entry for ${d.id}`);
          continue;
        }
        // review_only keeps the flag, factor, score and dates intact until a
        // maintainer confirms a genuine CISA removal.
        if (d.review_only) continue;
        catalog[d.id][d.field] = d.after;
        // The catalog invariant is rwep_score === Σ rwep_factors, so a cisa_kev
        // flip must rewrite the factor and the score with it.
        if (d.field === "cisa_kev") {
          const entry = catalog[d.id];
          if (entry.rwep_factors && typeof entry.rwep_factors === "object") {
            const scoring = require("./scoring");
            // Match the stored factor shape: a boolean, or the post-weight
            // contribution the catalog norm holds.
            entry.rwep_factors.cisa_kev =
              typeof entry.rwep_factors.cisa_kev === "boolean"
                ? !!d.after
                : (d.after ? scoring.RWEP_WEIGHTS.cisa_kev : 0);
            entry.rwep_score = scoring.deriveRwepFromFactors(entry.rwep_factors);
          }
          // Nothing else clears the dates: the diff producer emits a
          // cisa_kev_date diff only when upstream HAS a date.
          if (d.after === false) {
            if ("cisa_kev_date" in entry) entry.cisa_kev_date = null;
            if ("cisa_kev_due_date" in entry) entry.cisa_kev_due_date = null;
            // Null, not false: false would assert a claim about a record that
            // no longer exists.
            if ("known_ransomware_use" in entry) entry.known_ransomware_use = null;
          }
        }
        catalog[d.id].last_verified = TODAY;
        updated++;
      }
      catalog._meta = catalog._meta || {};
      catalog._meta.last_updated = TODAY;
      // Refresh the in-memory view so later sources in this process see the write.
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated: updated + added, added, drift_updated: updated, errors };
  },
};

/**
 * Cache-mode KEV drift plus discoverNewKev() for entries the catalog lacks.
 */
function kevDiffWithDiscoveryFromCache(ctx) {
  const drift = kevDiffFromCache(ctx);
  if (ctx.driftOnly) {
    return { ...drift, spilled: 0, summary: `${drift.diffs.length} KEV drifts (from cache, discovery suppressed)` };
  }
  const discovery = discoverNewKev(ctx);
  const diffs = [...drift.diffs, ...discovery.diffs];
  const summary =
    `${drift.diffs.length} KEV drifts + ${discovery.diffs.length} new entries` +
    (discovery.spilled > 0 ? ` (+${discovery.spilled} spilled past cap)` : "") +
    " (from cache)";
  return {
    status: drift.status,
    diffs,
    errors: drift.errors + discovery.errors,
    spilled: discovery.spilled,
    summary,
  };
}

/**
 * EPSS publishes score, percentile and date as ONE row, so a field written
 * without the others leaves the entry describing two different days. The drift
 * threshold decides WHETHER an entry is refreshed, never WHICH of its fields.
 *
 * `local` is the catalog entry; `fetched` is {score, percentile, date} read from
 * one EPSS row.
 */
const EPSS_DRIFT = 0.05;

function epssTripleDiffs(id, local, fetched, drift) {
  const { score, percentile, date } = fetched;
  // Only a COMPLETE row produces a coherent triple, the date included — without
  // it the numbers land under the old epss_date. Finite rather than present: the
  // callers use Number(), and a NaN passes a nullish check and serialises null.
  if (!Number.isFinite(score) || !Number.isFinite(percentile) || !date) return [];

  const scoreMoved = local.epss_score != null && Math.abs(score - local.epss_score) > drift;
  const pctMoved = local.epss_percentile != null && Math.abs(percentile - local.epss_percentile) > drift;

  // The drift threshold cannot reach a half-populated entry: the absent side has
  // nothing to compare against, so a stable present side leaves it broken. An
  // entry carrying NO EPSS is left alone — an absent field is not an incoherent pair.
  const localIncomplete = (local.epss_score == null) !== (local.epss_percentile == null);
  if (!scoreMoved && !pctMoved && !localIncomplete) return [];

  // `coherent` records PROVENANCE: whatever subset differs, these diffs came
  // from one complete row. A consumer cannot infer that from the fields alone.
  const out = [];
  const emit = (field, before, after, severity) =>
    out.push({ id, field, before, after, severity, coherent: true });

  if (score !== local.epss_score) emit("epss_score", local.epss_score ?? null, score, "medium");
  if (percentile !== local.epss_percentile) emit("epss_percentile", local.epss_percentile ?? null, percentile, "medium");
  // `date` is non-empty by the guard at the top of this function.
  if (date !== local.epss_date) emit("epss_date", local.epss_date ?? null, date, "low");
  return out;
}

const EPSS_SOURCE = {
  name: "epss",
  description: "FIRST.org EPSS scores",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.epss) return synthesizeFromFixture(ctx, "epss");
    if (ctx.cacheDir) return epssDiffFromCache(ctx);
    const { validateAllCves } = require("../sources/validators");
    const report = await validateAllCves(ctx.cveCatalog, { concurrency: 4 });
    const diffs = [];
    let errors = 0;
    for (const r of report.results) {
      if (r.status === "unreachable") errors++;
      // Diff off the FETCHED ROW, not r.discrepancies: that list names only the
      // fields differing enough to report, which mixes publications.
      if (!r.fetched?.epss || !r.local) continue;
      diffs.push(...epssTripleDiffs(r.cve_id, r.local, r.fetched.epss, EPSS_DRIFT));
    }
    return {
      status: errors === 0 ? "ok" : errors === report.results.length ? "unreachable" : "partial",
      diffs,
      errors,
      summary: `${diffs.length} EPSS diffs; ${errors} unreachable / ${report.total} total`,
    };
  },
  async applyDiff(ctx, diffs) {
    let updated = 0;
    const errors = [];
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    await withCatalogLock(catalogPath, (catalog) => {
      const touchedFields = new Map();
      for (const d of diffs) {
        if (!catalog[d.id]) {
          errors.push(`EPSS: no local entry for ${d.id}`);
          continue;
        }
        catalog[d.id][d.field] = d.after;
        catalog[d.id].last_verified = TODAY;
        // An id is coherent only if EVERY diff applied to it declares that
        // provenance.
        touchedFields.set(d.id, (touchedFields.get(d.id) !== false) && d.coherent === true);
        updated++;
      }
      // `epss_note` restates the three fields in prose, so moving the numbers
      // without it leaves the entry stating two scores as of two dates. Rebuilt
      // only where a note exists — adding one is a content change.
      for (const [id, coherent] of touchedFields) {
        const e = catalog[id];
        if (typeof e.epss_note !== "string") continue;
        if (typeof e.epss_score !== "number" || typeof e.epss_percentile !== "number") continue;
        // Only diffs whose emitter vouched for one complete publication: this is
        // exported, and a fixture moving half the pair would rewrite the note
        // from a stale percentile and make a mixed entry read as current.
        if (!coherent) continue;
        e.epss_note = renderEpssNote(e);
      }
      catalog._meta = catalog._meta || {};
      catalog._meta.last_updated = TODAY;
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated, errors };
  },
};

const NVD_SOURCE = {
  name: "nvd",
  description: "NIST NVD 2.0 CVSS metrics",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.nvd) return synthesizeFromFixture(ctx, "nvd");
    if (ctx.cacheDir) return nvdDiffFromCache(ctx);
    const { validateAllCves } = require("../sources/validators");
    const report = await validateAllCves(ctx.cveCatalog, { concurrency: 4 });
    const diffs = [];
    let errors = 0;
    for (const r of report.results) {
      if (r.status === "unreachable") errors++;
      for (const d of r.discrepancies || []) {
        if (d.field === "cvss_score" || d.field === "cvss_vector") {
          diffs.push(cvssDiff(r.cve_id, d.field, d.local, d.fetched, d.severity, ctx.cveCatalog?.[r.cve_id]));
        }
      }
    }
    return {
      status: errors === 0 ? "ok" : errors === report.results.length ? "unreachable" : "partial",
      diffs,
      errors,
      summary: `${diffs.length} NVD CVSS diffs; ${errors} unreachable / ${report.total} total`,
    };
  },
  async applyDiff(ctx, diffs) {
    let updated = 0;
    const errors = [];
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    await withCatalogLock(catalogPath, (catalog) => {
      for (const d of diffs) {
        // A curator-owned CVSS re-score is reported, not applied.
        if (d.review_only) continue;
        if (!catalog[d.id]) {
          errors.push(`NVD: no local entry for ${d.id}`);
          continue;
        }
        catalog[d.id][d.field] = d.after;
        catalog[d.id].last_verified = TODAY;
        updated++;
      }
      catalog._meta = catalog._meta || {};
      catalog._meta.last_updated = TODAY;
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated, errors };
  },
};

const RFC_SOURCE = {
  name: "rfc",
  description: "IETF Datatracker RFC status + auto-discovery",
  applies_to: "data/rfc-references.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.rfc) return synthesizeFromFixture(ctx, "rfc");
    if (ctx.cacheDir) return rfcDiffWithDiscoveryFromCache(ctx);
    const { validateAllRfcs } = require("../sources/validators");
    const results = await validateAllRfcs(ctx.rfcCatalog, { concurrency: 4 });
    const diffs = [];
    let errors = 0;
    for (const r of results) {
      if (r.status === "unreachable") {
        errors++;
        continue;
      }
      if (r.status === "drift" && r.discrepancies) {
        for (const msg of r.discrepancies) {
          // The validator returns discrepancies as strings.
          const m = msg.match(/local "([^"]+)" vs Datatracker "([^"]+)"/);
          if (m) {
            diffs.push({ id: r.id, field: "status", before: m[1], after: m[2], severity: "medium" });
          } else {
            diffs.push({ id: r.id, field: "note", before: null, after: msg, severity: "low" });
          }
        }
      }
    }
    return {
      status: errors === 0 ? "ok" : errors === results.length ? "unreachable" : "partial",
      diffs,
      errors,
      summary: `${diffs.length} RFC drifts; ${errors} unreachable / ${results.length} total`,
    };
  },
  async applyDiff(ctx, diffs) {
    let updated = 0;
    let added = 0;
    const errors = [];
    const rfcPath = ABS("data/rfc-references.json");
    await withCatalogLock(rfcPath, (rfcCatalog) => {
      for (const d of diffs) {
        if (d.op === "add") {
          if (rfcCatalog[d.id]) continue;
          rfcCatalog[d.id] = d.entry;
          added++;
          continue;
        }
        if (d.field !== "status") continue; // notes are informational
        const entry = rfcCatalog[d.id];
        if (!entry) {
          errors.push(`RFC: no local entry for ${d.id}`);
          continue;
        }
        entry.status = d.after;
        entry.last_verified = TODAY;
        updated++;
      }
      rfcCatalog._meta = rfcCatalog._meta || {};
      rfcCatalog._meta.last_updated = TODAY;
      ctx.rfcCatalog = rfcCatalog;
      return rfcCatalog;
    });
    return { updated: updated + added, added, drift_updated: updated, errors };
  },
};

/**
 * Cache-mode RFC drift plus discoverNewRfcs(), which hits Datatracker live —
 * one HTTP call per working group per refresh.
 */
async function rfcDiffWithDiscoveryFromCache(ctx) {
  const drift = rfcDiffFromCache(ctx);
  if (ctx.driftOnly) {
    return { ...drift, spilled: 0, summary: `${drift.diffs.length} RFC drifts (from cache, discovery suppressed)` };
  }
  const discovery = await discoverNewRfcs(ctx);
  const diffs = [...drift.diffs, ...discovery.diffs];
  const summary =
    `${drift.diffs.length} RFC drifts + ${discovery.diffs.length} new entries` +
    (discovery.spilled > 0 ? ` (+${discovery.spilled} spilled past cap)` : "") +
    " (drift from cache, discovery live)";
  return {
    status: drift.status,
    diffs,
    errors: drift.errors + discovery.errors,
    spilled: discovery.spilled,
    summary,
  };
}

const PINS_SOURCE = {
  name: "pins",
  description: "MITRE ATLAS / ATT&CK / D3FEND / CWE upstream release pins",
  applies_to: "manifest.json + data/cwe-catalog.json + data/d3fend-catalog.json",
  report_only: true,
  async fetchDiff(ctx) {
    if (ctx.fixtures?.pins) return synthesizeFromFixture(ctx, "pins");
    if (ctx.cacheDir) return pinsDiffFromCache(ctx);
    const { checkAllPins } = require("../sources/validators/version-pin-validator");
    const results = await checkAllPins({
      manifest: ctx.manifest,
      cweCatalog: ctx.cweCatalog,
      d3fendCatalog: ctx.d3fendCatalog,
    });
    const diffs = [];
    let errors = 0;
    for (const r of results) {
      if (r.unreachable) {
        errors++;
        continue;
      }
      if (r.drift) {
        diffs.push({
          id: r.pin_name,
          field: "version",
          before: r.local_version,
          after: r.latest_version,
          severity: "medium",
          source_url: r.source_url,
          local_path_hint: r.local_path_hint,
          note: "Version-pin bump requires audit per AGENTS.md Hard Rule #12. Surface as GitHub issue, do not auto-apply.",
        });
      }
    }
    return {
      status: errors === 0 ? "ok" : errors === results.length ? "unreachable" : "partial",
      diffs,
      errors,
      summary: `${diffs.length} pin drifts; ${errors} unreachable / ${results.length} total`,
    };
  },
  async applyDiff() {
    return { updated: 0, errors: ["pin bumps are report-only — see Hard Rule #12"] };
  },
};

/**
 * GitHub Advisory Database. New CVE IDs land as drafts (`_auto_imported` +
 * `_draft`), which the strict validator treats as warnings; framework gaps, IoCs
 * and ATLAS/ATT&CK refs need `exceptd run cve-curation --advisory <id>`.
 */
const GHSA_SOURCE = {
  name: "ghsa",
  description: "GitHub Advisory Database — multi-ecosystem disclosure feed (npm, PyPI, Maven, Go, etc.)",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.ghsa) return synthesizeFromFixture(ctx, "ghsa");
    if (ctx.cacheDir) {
      return {
        status: "unreachable",
        diffs: [],
        errors: 0,
        summary: "GHSA: no cache layer; skipped in --from-cache mode (would require a live network call)",
      };
    }
    const ghsa = require("./source-ghsa");
    return ghsa.buildDiff(ctx);
  },
  async applyDiff(ctx, diffs) {
    // A mutation of ctx.cveCatalog alone never reaches disk, and under --swarm
    // another source's lock re-reads from disk and overwrites it.
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    let updated = 0;
    const errors = [];
    await withCatalogLock(catalogPath, (catalog) => {
      for (const d of diffs) {
        if (d.field !== "_new_entry") continue;
        if (!d.after || !d.id) continue;
        if (catalog[d.id]) continue; // never overwrite existing entries
        try {
          catalog[d.id] = d.after;
          updated++;
        } catch (e) {
          errors.push(`${d.id}: ${e.message}`);
        }
      }
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated, errors };
  },
};

/**
 * OSV.dev — MAL-*, Snyk, GHSA, RustSec, Mageia, Go Vuln DB and Ubuntu USN behind
 * one unauthenticated API. Entries land as drafts like GHSA's, keyed by the CVE
 * alias when there is one and by the OSV id verbatim otherwise.
 */
const OSV_SOURCE = {
  name: "osv",
  description: "OSV.dev — OSSF Malicious Packages (MAL-*) + Snyk + GHSA + RustSec + Mageia + Go Vuln DB + Ubuntu USN. Unauthenticated. Slot in for the broader supply-chain-class disclosure space — covers package compromises that don't have CVEs yet.",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.osv) return synthesizeFromFixture(ctx, "osv");
    if (ctx.cacheDir) {
      return {
        status: "unreachable",
        diffs: [],
        errors: 0,
        summary: "OSV: no cache layer; skipped in --from-cache mode (would require a live network call)",
      };
    }
    const osv = require("./source-osv");
    return osv.buildDiff(ctx);
  },
  async applyDiff(ctx, diffs) {
    // Lock-gated like GHSA: a ctx-only mutation never reaches disk.
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    let updated = 0;
    const errors = [];
    await withCatalogLock(catalogPath, (catalog) => {
      for (const d of diffs) {
        if (d.field !== "_new_entry") continue;
        if (!d.after || !d.id) continue;
        if (catalog[d.id]) continue; // never overwrite existing entries
        try {
          catalog[d.id] = d.after;
          updated++;
        } catch (e) {
          errors.push(`${d.id}: ${e.message}`);
        }
      }
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated, errors };
  },
};

// Primary advisory feeds (Qualys TRU, RHSA, USN, ZDI), report-only.
const { ADVISORIES_SOURCE } = require('./source-advisories');

// NEW-CTRL-074: flags poller-diff historical-CVE references as candidate silent
// regressions. Report-only, and it consumes the advisories run's output through
// ctx.advisoriesObservations (or ctx.advisoriesDiffs), so advisories runs first.
const { REGRESSION_WATCHER_SOURCE } = require('./cve-regression-watcher');

const ALL_SOURCES = {
  kev: KEV_SOURCE,
  epss: EPSS_SOURCE,
  nvd: NVD_SOURCE,
  rfc: RFC_SOURCE,
  pins: PINS_SOURCE,
  ghsa: GHSA_SOURCE,
  osv: OSV_SOURCE,
  advisories: ADVISORIES_SOURCE,
  'cve-regression-watcher': REGRESSION_WATCHER_SOURCE,
};

// Reads the prefetch cache lib/prefetch.js writes at <cacheDir>/<source>/<id>.json;
// a miss returns null, so one entry is unreachable rather than the whole source.
// Each payload's sha256 is recorded in _index.json at fetch time and verified here.
// The stored hash is over unindented JSON.stringify(payload) while the on-disk
// bytes are indented, so the parse round-trip re-canonicalizes before comparing.
function readCachedJson(cacheDir, source, id, opts) {
  const forceStale = !!(opts && opts.forceStale);
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(cacheDir, source, `${safe}.json`);
  if (!fs.existsSync(p)) return null;
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return null; }
  // Every payload on disk has a signed entry in _index.json, so an absent index
  // or a missing entry refuses rather than fails open. `--force-stale` proceeds
  // unverified but warns.
  const indexPath = path.join(cacheDir, "_index.json");
  if (!fs.existsSync(indexPath)) {
    if (forceStale) {
      process.emitWarning(
        `cache-integrity: _index.json missing under ${cacheDir}; proceeding unverified (--force-stale)`,
        { code: "EXCEPTD_CACHE_UNVERIFIED" },
      );
      return parsed;
    }
    const err = new Error(`cache-integrity: _index.json missing under ${cacheDir}; refusing to consume unindexed payload for ${source}/${id}`);
    err._exceptd_cache_integrity = true;
    err._exceptd_hint = true;
    err._exceptd_exit_code = 4;
    throw err;
  }
  let idx;
  try { idx = JSON.parse(fs.readFileSync(indexPath, "utf8")); }
  catch (e) {
    if (forceStale) {
      process.emitWarning(
        `cache-integrity: _index.json parse failed (${e.message}); proceeding unverified (--force-stale)`,
        { code: "EXCEPTD_CACHE_UNVERIFIED" },
      );
      return parsed;
    }
    const err = new Error(`cache-integrity: _index.json parse failed: ${e.message}`);
    err._exceptd_cache_integrity = true;
    err._exceptd_hint = true;
    err._exceptd_exit_code = 4;
    throw err;
  }
  const meta = idx && idx.entries && idx.entries[`${source}/${id}`];
  if (!meta || typeof meta.sha256 !== "string") {
    if (forceStale) {
      process.emitWarning(
        `cache-integrity: _index.json has no sha256 entry for ${source}/${id}; proceeding unverified (--force-stale)`,
        { code: "EXCEPTD_CACHE_UNVERIFIED" },
      );
      return parsed;
    }
    const err = new Error(`cache-integrity: _index.json has no sha256 entry for ${source}/${id}; cache may have been tampered or partially populated`);
    err._exceptd_cache_integrity = true;
    err._exceptd_hint = true;
    err._exceptd_exit_code = 4;
    throw err;
  }
  const expected = meta.sha256;
  const cryptoMod = require("crypto");
  const actual = cryptoMod.createHash("sha256").update(JSON.stringify(parsed)).digest("hex");
  if (expected !== actual) {
    // A hard tamper signal: `--force-stale` does NOT bypass it.
    const err = new Error(`cache-integrity: sha256 mismatch for ${source}/${id} (expected ${expected.slice(0, 16)}..., got ${actual.slice(0, 16)}...)`);
    err._exceptd_cache_integrity = true;
    err._exceptd_hint = true;
    err._exceptd_exit_code = 4;
    throw err;
  }
  return parsed;
}

// Strong human-curated exploitation signal. A de-listing of such an entry is far
// likelier a transient feed than a genuine CISA removal.
function hasCuratedExploitSignal(entry) {
  if (!entry || typeof entry !== "object") return false;
  const ae = typeof entry.active_exploitation === "string" ? entry.active_exploitation.toLowerCase() : "";
  if (ae === "confirmed" || ae === "suspected") return true;
  if (typeof entry.poc_description === "string" && entry.poc_description.trim()) return true;
  if (Array.isArray(entry.verification_sources) && entry.verification_sources.length > 0) return true;
  return false;
}

// An entry is curator-owned — its CVSS hand-verified — unless it carries
// `_auto_imported: true`. This keeps a same-version NVD re-score from overwriting
// a curated value, where the version-downgrade guards cannot.
function isCuratorOwnedCvss(entry) {
  return !!entry && typeof entry === "object" && entry._auto_imported !== true;
}

// Marks the diff review-only when the local entry is curator-owned: applyDiff
// preserves the curated value while the report still surfaces the delta.
function cvssDiff(id, field, before, after, severity, local) {
  const d = { id, field, before, after, severity };
  if (isCuratorOwnedCvss(local)) {
    d.review_only = true;
    d.cvss_review = true;
    d.note = `NVD ${field} change held for review: ${id} is curator-owned (hand-verified CVSS). Confirm and re-curate to accept NVD's ${after} over the curated ${before}; not auto-applied so the curated value is preserved.`;
  }
  return d;
}

// Below this many entries the KEV feed is a partial download or a tampered
// cache, not a CISA snapshot — the real feed carries thousands. De-listings are
// refused wholesale there.
const KEV_FEED_MIN_PLAUSIBLE = 500;

// The KEV fields both refresh paths reconcile, named once so the live path and
// the cache path cannot cover different subsets.
const KEV_RECONCILED_FIELDS = new Set([
  "cisa_kev", "cisa_kev_date", "cisa_kev_due_date", "known_ransomware_use",
]);

function kevDiffFromCache(ctx) {
  const feed = readCachedJson(ctx.cacheDir, "kev", "known_exploited_vulnerabilities", { forceStale: ctx.forceStale });
  if (!feed) {
    return { status: "unreachable", diffs: [], errors: 1, summary: "KEV: no cached feed" };
  }
  const kevSet = new Set();
  const kevDates = new Map();
  const kevDue = new Map();
  const kevRansom = new Map();
  for (const v of feed.vulnerabilities || []) {
    if (v && v.cveID) {
      kevSet.add(v.cveID);
      if (v.dateAdded) kevDates.set(v.cveID, v.dateAdded);
      if (v.dueDate) kevDue.set(v.cveID, v.dueDate);
      // Recorded ONLY for a value this code understands: absence is no answer,
      // not a negative one, and a coerced miss would propose downgrading a
      // curated true on a field the feed never carried.
      const r = typeof v.knownRansomwareCampaignUse === "string"
        ? v.knownRansomwareCampaignUse.trim().toLowerCase() : null;
      if (r === "known") kevRansom.set(v.cveID, true);
      else if (r === "unknown") kevRansom.set(v.cveID, false);
    }
  }
  // Only the de-list direction is suppressed; a small feed never invents a listing.
  const feedComplete = kevSet.size >= KEV_FEED_MIN_PLAUSIBLE;
  const diffs = [];
  for (const [id, entry] of Object.entries(ctx.cveCatalog)) {
    if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) continue;
    const upstream = kevSet.has(id);
    if (typeof entry.cisa_kev === "boolean" && entry.cisa_kev !== upstream) {
      const isDelist = entry.cisa_kev === true && upstream === false;
      // A de-listing of an entry with strong exploitation signal, or any against
      // an implausibly small feed, is review-only: applyDiff skips those.
      if (isDelist && (!feedComplete || hasCuratedExploitSignal(entry))) {
        diffs.push({
          id,
          field: "cisa_kev",
          before: entry.cisa_kev,
          after: upstream,
          severity: "high",
          review_only: true,
          kev_delist_review: true,
          note: !feedComplete
            ? `KEV de-listing held for review: cached feed has only ${kevSet.size} entries (< ${KEV_FEED_MIN_PLAUSIBLE}), likely incomplete. Confirm against a complete CISA KEV snapshot before de-listing.`
            : "KEV de-listing held for review: entry carries curated exploitation signal (active_exploitation / PoC / verification sources). Confirm a genuine CISA removal vs a transient feed gap before de-listing.",
        });
      } else {
        diffs.push({ id, field: "cisa_kev", before: entry.cisa_kev, after: upstream, severity: "high" });
      }
    }
    const upDate = kevDates.get(id) || null;
    // The flag flip and its listing date apply together — the strict validator
    // requires the date on a KEV-listed entry.
    if (upDate && (entry.cisa_kev_date || null) !== upDate) {
      diffs.push({ id, field: "cisa_kev_date", before: entry.cisa_kev_date ?? null, after: upDate, severity: "low" });
    }

    // CISA edits a listing after publishing it, moving the deadline and the
    // ransomware designation. Only entries upstream still lists are considered —
    // a de-listing clears both fields through the cisa_kev branch above.
    if (upstream) {
      const upDue = kevDue.get(id) || null;
      // The deadline is rendered into remediation output and regulator drafts.
      if (upDue && (entry.cisa_kev_due_date || null) !== upDue) {
        diffs.push({ id, field: "cisa_kev_due_date", before: entry.cisa_kev_due_date ?? null, after: upDue, severity: "medium" });
      }
      const upRansom = kevRansom.has(id) ? kevRansom.get(id) : null;
      // Consumers read a missing boolean as false, so an omission reads as "no
      // ransomware association" — the wrong answer rather than no answer. On a
      // KEV-listed CVE the value restates the feed, so it fills both directions.
      const localRansom = typeof entry.known_ransomware_use === "boolean" ? entry.known_ransomware_use : null;
      if (upRansom !== null && localRansom !== upRansom) {
        // An ADDED designation is upstream saying something new; one REMOVED
        // against an implausibly small feed is the feed saying nothing.
        const removing = localRansom === true && upRansom === false;
        const d = { id, field: "known_ransomware_use", before: localRansom, after: upRansom, severity: "medium" };
        if (removing && !feedComplete) {
          d.review_only = true;
          d.note = `Ransomware designation removal held for review: cached feed has only ${kevSet.size} entries (< ${KEV_FEED_MIN_PLAUSIBLE}), likely incomplete.`;
        }
        diffs.push(d);
      }
    }
  }
  return { status: "ok", diffs, errors: 0, summary: `${diffs.length} KEV diffs (from cache)` };
}

function epssDiffFromCache(ctx) {
  const cves = Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));
  const diffs = [];
  let errors = 0;
  const drift = EPSS_DRIFT;
  for (const id of cves) {
    const payload = readCachedJson(ctx.cacheDir, "epss", id, { forceStale: ctx.forceStale });
    if (!payload) { errors++; continue; }
    // Match the row by id: a blanket `|| data[0]` fallback attributes another
    // CVE's score to this id. The single-row fallback holds only for a keyless
    // payload, never for a row naming a different CVE.
    let row = (payload.data || []).find((r) => r?.cve === id);
    if (!row && (payload.data || []).length === 1 && (payload.data || [])[0]?.cve == null) row = (payload.data || [])[0];
    if (!row) continue;
    const fetched = {
      score: row.epss != null ? Number(row.epss) : null,
      percentile: row.percentile != null ? Number(row.percentile) : null,
      date: row.date || null,
    };
    diffs.push(...epssTripleDiffs(id, ctx.cveCatalog[id], fetched, drift));
  }
  const status = errors === 0 ? "ok" : errors === cves.length ? "unreachable" : "partial";
  return { status, diffs, errors, summary: `${diffs.length} EPSS diffs (from cache); ${errors} missing entries` };
}

function nvdDiffFromCache(ctx) {
  const cves = Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));
  const diffs = [];
  let errors = 0;
  for (const id of cves) {
    const payload = readCachedJson(ctx.cacheDir, "nvd", id, { forceStale: ctx.forceStale });
    if (!payload) { errors++; continue; }
    // Resolve the NVD vuln by id, not by position: vulnerabilities[0] attributes
    // another CVE's CVSS to this id.
    const vulnCves = (payload.vulnerabilities || []).map((v) => v?.cve).filter(Boolean);
    let vuln = vulnCves.find((c) => c.id && String(c.id).toUpperCase() === id.toUpperCase());
    // A single record whose cve carries no id cannot be a mismatch — the
    // id-keyed cache file is the binding. One naming a DIFFERENT cve is not.
    if (!vuln && vulnCves.length === 1 && vulnCves[0].id == null) vuln = vulnCves[0];
    if (!vuln) continue;
    const up = selectNvdCvss(vuln.metrics);
    if (!up) continue;
    const local = ctx.cveCatalog[id];
    // Never regress a curated higher-version CVSS to an older upstream metric:
    // NVD tags v2 "Primary" over a v3.1 "Secondary" on older CVEs. A same-version
    // drift still flows through.
    const localVersion = cvssVersionOf(local.cvss_vector);
    const isDowngrade =
      up.version != null && localVersion != null && up.version < localVersion;
    if (!isDowngrade) {
      if (up.baseScore != null && local.cvss_score != null && Math.abs(up.baseScore - local.cvss_score) > 0.05) {
        diffs.push(cvssDiff(id, "cvss_score", local.cvss_score, up.baseScore, "high", local));
      }
      if (up.vector && local.cvss_vector && up.vector !== local.cvss_vector) {
        diffs.push(cvssDiff(id, "cvss_vector", local.cvss_vector, up.vector, "medium", local));
      }
    }
  }
  const status = errors === 0 ? "ok" : errors === cves.length ? "unreachable" : "partial";
  return { status, diffs, errors, summary: `${diffs.length} NVD CVSS diffs (from cache); ${errors} missing entries` };
}

function rfcDiffFromCache(ctx) {
  const STATUS_MAP = {
    std: "Internet Standard", ps: "Proposed Standard", ds: "Draft Standard",
    bcp: "Best Current Practice", inf: "Informational", exp: "Experimental",
    his: "Historic", unkn: "Unknown",
  };
  const ids = Object.keys(ctx.rfcCatalog).filter((k) => !k.startsWith("_"));
  const diffs = [];
  let errors = 0;
  for (const id of ids) {
    let docName;
    if (id.startsWith("RFC-")) docName = `rfc${id.slice(4)}`;
    else if (id.startsWith("DRAFT-")) docName = `draft-${id.slice(6).toLowerCase()}`;
    if (!docName) continue;
    const payload = readCachedJson(ctx.cacheDir, "rfc", docName, { forceStale: ctx.forceStale });
    if (!payload) { errors++; continue; }
    const obj = payload.objects?.[0];
    if (!obj) continue;
    const upStatus = STATUS_MAP[obj.std_level] || null;
    const local = ctx.rfcCatalog[id];
    if (upStatus && local.status && upStatus !== local.status) {
      diffs.push({ id, field: "status", before: local.status, after: upStatus, severity: "medium" });
    }
  }
  const status = errors === 0 ? "ok" : errors === ids.length ? "unreachable" : "partial";
  return { status, diffs, errors, summary: `${diffs.length} RFC drifts (from cache); ${errors} missing entries` };
}

function pinsDiffFromCache(ctx) {
  // Cache layout under pins/: <owner>__<repo>__releases.json arrays, so only
  // repos publishing via GitHub Releases appear. D3FEND and CWE tag none;
  // lib/upstream-check.js monitors their pin currency against mitre.org instead.
  const PIN_REPOS = {
    atlas_version:  "mitre-atlas__atlas-data__releases",
    attack_version: "mitre-attack__attack-stix-data__releases",
  };
  const localOf = {
    atlas_version:  ctx.manifest.atlas_version,
    attack_version: ctx.manifest.attack_version,
  };
  const diffs = [];
  let errors = 0;
  for (const [pinName, file] of Object.entries(PIN_REPOS)) {
    const payload = readCachedJson(ctx.cacheDir, "pins", file, { forceStale: ctx.forceStale });
    if (!payload || !Array.isArray(payload)) { errors++; continue; }
    const stable = payload.find((r) => !r.draft && !r.prerelease);
    if (!stable) { errors++; continue; }
    const latest = String(stable.tag_name || "").replace(/^v/, "");
    const local = localOf[pinName] != null ? String(localOf[pinName]).replace(/^v/, "") : null;
    if (local && latest && local !== latest) {
      diffs.push({
        id: pinName,
        field: "version",
        before: local,
        after: latest,
        severity: "medium",
        source_url: stable.html_url,
        local_path_hint: pinName === "cwe_version" ? "data/cwe-catalog.json _meta.version"
          : pinName === "d3fend_version" ? "data/d3fend-catalog.json _meta.version"
          : `manifest.json — ${pinName}`,
        note: "Version-pin bump requires audit per AGENTS.md Hard Rule #12. Surface as GitHub issue, do not auto-apply.",
      });
    }
  }
  const status = errors === 0 ? "ok" : errors === Object.keys(PIN_REPOS).length ? "unreachable" : "partial";
  return { status, diffs, errors, summary: `${diffs.length} pin drifts (from cache); ${errors} missing entries` };
}

function synthesizeFromFixture(ctx, sourceName) {
  // tests/fixtures/refresh/<sourceName>.json holds { diffs, errors, summary }.
  const fp = path.join(ctx.fixtures.dir, `${sourceName}.json`);
  if (!fs.existsSync(fp)) {
    return { status: "ok", diffs: [], errors: 0, summary: `${sourceName}: no fixture` };
  }
  const fx = JSON.parse(fs.readFileSync(fp, "utf8"));
  return {
    status: fx.status || "ok",
    diffs: fx.diffs || [],
    errors: fx.errors || 0,
    summary: fx.summary || `${sourceName}: ${(fx.diffs || []).length} diffs (fixture)`,
  };
}

function loadCtx(opts) {
  const cvePath = resolveCatalogPath(opts);
  const ctx = {
    manifest: JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8")),
    cvePath, // remember the resolved path; applyDiff callbacks write through it
    cveCatalog: JSON.parse(fs.readFileSync(cvePath, "utf8")),
    rfcCatalog: JSON.parse(fs.readFileSync(ABS("data/rfc-references.json"), "utf8")),
    cweCatalog: JSON.parse(fs.readFileSync(ABS("data/cwe-catalog.json"), "utf8")),
    d3fendCatalog: JSON.parse(fs.readFileSync(ABS("data/d3fend-catalog.json"), "utf8")),
    fixtures: null,
    cacheDir: null,
    // Reaches lib/source-ghsa.js and lib/source-osv.js, which refuse egress on it.
    airGap: !!(opts && opts.airGap) || process.env.EXCEPTD_AIR_GAP === "1",
    // Lets readCachedJson downgrade cache-integrity refusals to warnings.
    forceStale: !!(opts && opts.forceStale),
    // Discovery yields drafts that need curation before they can ship, so
    // drift-only reconciles shipped entries without pulling that work in.
    driftOnly: !!(opts && opts.driftOnly),
  };
  if (opts.fromFixture) {
    // `--from-fixture` injects payloads as if they were live upstream responses,
    // so outside the harness it would forge diffs into the applied catalog.
    if (process.env.EXCEPTD_TEST_HARNESS !== "1") {
      const err = new Error(
        `refresh: --from-fixture is disabled outside the test harness.\n` +
        `Hint: Set EXCEPTD_TEST_HARNESS=1 to use --from-fixture; this flag is intended for test harnesses only and would otherwise allow forged upstream payloads.`
      );
      err._exceptd_hint = true;
      err._exceptd_exit_code = 4;
      err._exceptd_error_code = "from-fixture-disabled";
      throw err;
    }
    const fixtureDir = path.resolve(opts.fromFixture);
    ctx.fixtures = { dir: fixtureDir, kev: true, epss: true, nvd: true, rfc: true, pins: true, ghsa: true, osv: true };
    // Frozen advisories keep the poller off live RSS, which rotates between runs.
    const advFixPath = path.join(fixtureDir, "advisories.json");
    if (fs.existsSync(advFixPath)) {
      try {
        const fx = JSON.parse(fs.readFileSync(advFixPath, "utf8"));
        // Strip the _meta sidecar; the rest is feed-name → XML/CSAF string.
        const { _meta, ...feeds } = fx;
        void _meta;
        ctx.fixtures.advisories = feeds;
      } catch (e) {
        // Surface in dry-run report rather than failing the whole run.
        ctx.fixtures.advisories_load_error = e.message || String(e);
      }
    }
  } else if (opts.fromCache) {
    const abs = path.resolve(opts.fromCache);
    ctx.cacheDir = abs;
    if (!fs.existsSync(abs)) {
      const err = new Error(
        `refresh: --from-cache path does not exist: ${abs}\n` +
        `Hint: the cache is populated by running \`exceptd refresh --prefetch\` ` +
        `on a connected host first. Air-gap workflow: (1) on connected host: \`exceptd refresh --prefetch\`, ` +
        `(2) copy .cache/upstream/ across the boundary, (3) on offline host: \`exceptd refresh --from-cache --apply\`.`
      );
      err._exceptd_hint = true;
      throw err;
    }
    // The cache is Ed25519-signed at prefetch time; a sidecar that does not
    // verify against keys/public.pem, or is missing, is refused alike.
    try {
      const { verifyIndexSignature } = require("./prefetch.js");
      const sigResult = verifyIndexSignature(abs);
      if (sigResult.status !== "valid" && !opts.forceStale) {
        const err = new Error(
          `refresh: --from-cache signature verification failed (${sigResult.status}): ${sigResult.reason || "(no reason)"}.\n` +
          `Hint: The cache at ${abs} was prefetched without a signing key, or its _index.json / _index.json.sig was tampered. ` +
          `Re-run \`exceptd prefetch\` on a host with .keys/private.pem, or pass --force-stale to consume the cache anyway.`
        );
        err._exceptd_hint = true;
        err._exceptd_exit_code = 4;
        err._exceptd_error_code = "cache-signature";
        throw err;
      }
    } catch (e) {
      if (e && e._exceptd_hint) throw e;
      // A loader error is a hard refusal, not a fail-open.
      if (!opts.forceStale) {
        const err = new Error(
          `refresh: --from-cache signature verifier unavailable: ${e && e.message}.\n` +
          `Hint: Pass --force-stale to consume the cache without signature verification, or reinstall the package.`
        );
        err._exceptd_hint = true;
        err._exceptd_exit_code = 4;
        err._exceptd_error_code = "cache-signature";
        throw err;
      }
    }
    // A cache whose freshest fetched_at is older than 7 days is refused: KEV
    // gains entries weekly and EPSS shifts daily.
    try {
      const idxPath = path.join(abs, "_index.json");
      if (fs.existsSync(idxPath)) {
        const idx = JSON.parse(fs.readFileSync(idxPath, "utf8"));
        const entries = (idx && idx.entries) || {};
        let maxFetchedMs = 0;
        for (const k of Object.keys(entries)) {
          const t = entries[k] && entries[k].fetched_at ? new Date(entries[k].fetched_at).getTime() : NaN;
          if (Number.isFinite(t) && t > maxFetchedMs) maxFetchedMs = t;
        }
        if (maxFetchedMs > 0) {
          const ageMs = Date.now() - maxFetchedMs;
          const ageDays = ageMs / (24 * 3600 * 1000);
          if (ageDays > 7 && !opts.forceStale) {
            const err = new Error(
              `refresh: --from-cache freshest entry is ${ageDays.toFixed(1)} days old (>7d cutoff).\n` +
              `Hint: Re-run \`exceptd prefetch\` to refresh the cache, or pass --force-stale to consume it anyway.`
            );
            err._exceptd_hint = true;
            err._exceptd_exit_code = 4;
            err._exceptd_error_code = "cache-stale";
            err._exceptd_max_age_days = Number(ageDays.toFixed(2));
            err._exceptd_refresh_command = "exceptd prefetch";
            throw err;
          }
        }
      }
    } catch (e) {
      if (e && e._exceptd_hint) throw e;
      const err = new Error(`refresh: --from-cache _index.json unreadable: ${e && e.message}`);
      err._exceptd_hint = true;
      err._exceptd_exit_code = 4;
      throw err;
    }
  }
  return ctx;
}

// Every persisted JSON write goes through here. fs.renameSync is atomic for a
// `.tmp.<pid>.<rand>` beside the target, so a concurrent reader sees the old
// file or the new one, never a half-written buffer; the pid + random keeps two
// writers in one process off the same scratch path.
function writeJsonAtomic(p, obj) {
  const tmpPath = `${p}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 10)}`;
  // fsync before the rename so a power loss between the two leaves the durable
  // destination intact. Matching helper in lib/cve-curation.js.
  const fd = fs.openSync(tmpPath, 'w');
  try {
    fs.writeSync(fd, JSON.stringify(obj, null, 2) + "\n", 0, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmpPath, p);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch {}
    throw err;
  }
}

function writeJson(p, obj) {
  writeJsonAtomic(p, obj);
}

/**
 * Lockfile-gated read-modify-write for a JSON catalog: a sidecar lockfile
 * (O_EXCL via `flag: 'wx'`) serializes the triple, so two concurrent
 * `--advisory <id> --apply` processes cannot drop one another's CVE.
 *
 * The mutator, which may be async, receives the catalog as re-read INSIDE the
 * lock — never a copy from before acquisition — and returns the object to
 * write; returning undefined writes its in-place mutation instead.
 */
async function withCatalogLock(catalogPath, mutator) {
  const lockPath = `${catalogPath}.lock`;
  const MAX_RETRIES = 50;
  const STALE_LOCK_MS = 30_000;
  let acquired = false;
  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      fs.writeFileSync(lockPath, String(process.pid), { flag: "wx" });
      acquired = true;
      break;
    } catch (e) {
      // EEXIST is the POSIX signal that another process holds the lock; Windows
      // raises EPERM when the holder is mid-unlink. Both mean held, so back off.
      if (e.code !== "EEXIST" && e.code !== "EPERM") throw e;
      // Probe the holder PID before falling back to mtime: ESRCH means dead, so
      // reclaim now instead of waiting out STALE_LOCK_MS; EPERM means alive under
      // another user. Same pattern as orchestrator/index.js _acquireWatchLock.
      let reclaimedByPid = false;
      try {
        const raw = fs.readFileSync(lockPath, "utf8").trim();
        const pid = Number.parseInt(raw, 10);
        if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
          try {
            process.kill(pid, 0);
            // holder alive
          } catch (probeErr) {
            if (probeErr && probeErr.code === "ESRCH") {
              try { fs.unlinkSync(lockPath); reclaimedByPid = true; } catch {}
            }
            // EPERM and anything else: treat as alive, fall through to mtime/sleep.
          }
        }
      } catch {} // unreadable lockfile — proceed to mtime fallback
      if (reclaimedByPid) continue;
      // Check for a dead holder before sleeping out MAX_RETRIES * backoff.
      try {
        const stat = fs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > STALE_LOCK_MS) {
          try { fs.unlinkSync(lockPath); } catch {}
          continue; // retry immediately without sleeping
        }
      } catch {} // lockfile vanished between EEXIST and stat — fine, retry
      await new Promise((r) => setTimeout(r, 50 + Math.random() * 150));
    }
  }
  if (!acquired) {
    throw new Error(`withCatalogLock: could not acquire ${lockPath} after ${MAX_RETRIES} attempts`);
  }
  try {
    const catalog = JSON.parse(fs.readFileSync(catalogPath, "utf8"));
    const mutated = await mutator(catalog);
    const toWrite = mutated === undefined ? catalog : mutated;
    writeJsonAtomic(catalogPath, toWrite);
    return { wrote: true, result: toWrite };
  } finally {
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

function chosenSources(opts) {
  // Flag-absent means "all sources"; flag-present-but-empty (`--source ""`,
  // `--source ","`) is an operator error, not a silent run-everything.
  if (opts.source == null) return Object.values(ALL_SOURCES);
  const names = opts.source.split(",").map((s) => s.trim()).filter(Boolean);
  if (names.length === 0) {
    const err = new Error(`refresh-external: --source requires at least one source name. Valid: ${Object.keys(ALL_SOURCES).join(", ")}`);
    err._exceptd_unknown_source = true;
    throw err;
  }
  const out = [];
  for (const n of names) {
    if (!ALL_SOURCES[n]) {
      // Throw rather than process.exit(): an exit can truncate a buffered stdout
      // write, so main().catch() sets process.exitCode and the loop drains.
      const err = new Error(`refresh-external: unknown source "${n}". Valid: ${Object.keys(ALL_SOURCES).join(", ")}`);
      err._exceptd_unknown_source = true;
      throw err;
    }
    out.push(ALL_SOURCES[n]);
  }
  return out;
}

/**
 * Seeds one catalog entry from an advisory id via GHSA or OSV, printing the
 * draft or writing it (--apply). A produced draft exits 3 — review pending.
 */
async function seedSingleAdvisory(opts) {
  const id = opts.advisory;
  // OSV-native ids route through source-osv; CVE-* and GHSA-* go to GHSA.
  const osvMod = require("./source-osv");
  const useOsv = osvMod.isOsvId(id) && !/^GHSA-/i.test(id);
  const ghsa = require("./source-ghsa");
  const sourceMod = useOsv ? osvMod : ghsa;
  const sourceName = useOsv ? "osv" : "ghsa";
  const fixtureEnv = useOsv ? "EXCEPTD_OSV_FIXTURE" : "EXCEPTD_GHSA_FIXTURE";

  // The air-gap disposition must reach the fetch; dropping it here egresses.
  const airGap = !!opts.airGap || process.env.EXCEPTD_AIR_GAP === "1";

  let result = await sourceMod.fetchAdvisoryById(id, { airGap });
  // A CVE-* id can have an OSV record before GHSA publishes one, so a GHSA 404
  // retries through OSV's /v1/vulns/{id}. When both 404 the error names both.
  let fallbackSourceUsed = null;
  if (!result.ok && !useOsv && /^CVE-/i.test(id) && /HTTP 404/.test(result.error || "")) {
    const fallback = await osvMod.fetchAdvisoryById(id, { airGap });
    if (fallback.ok) {
      result = fallback;
      fallbackSourceUsed = "osv";
    } else if (/HTTP 404/.test(fallback.error || "") || /not in fixture/.test(fallback.error || "")) {
      const combined = { ok: false, verb: "refresh", error: `--advisory ${id}: not found in GHSA or OSV (GHSA: ${result.error}; OSV: ${fallback.error})`, source: "offline", routed_to: "ghsa+osv", hint: `Both GHSA and OSV.dev returned 404 for ${id}. Verify the CVE id (CVE-YYYY-NNNN) and that an advisory record exists upstream.` };
      if (opts.json) process.stdout.write(JSON.stringify(combined) + "\n");
      else process.stderr.write(`[refresh --advisory] ${combined.error}\n  hint: ${combined.hint}\n`);
      process.exitCode = 2;
      return;
    }
  }
  if (!result.ok) {
    const err = { ok: false, verb: "refresh", error: `--advisory ${id}: ${result.error}`, source: result.source, routed_to: sourceName, hint: `Verify the ID format (CVE-YYYY-NNNN, GHSA-*, MAL-*, SNYK-*, RUSTSEC-*, USN-*, etc.) and network reachability. Set ${fixtureEnv} for offline testing.` };
    if (opts.json) process.stdout.write(JSON.stringify(err) + "\n");
    else process.stderr.write(`[refresh --advisory] ${err.error}\n  hint: ${err.hint}\n`);
    process.exitCode = 2;
    return;
  }
  // After an OSV fallback the advisory shape is OSV's, so normalize through it.
  const effectiveMod = fallbackSourceUsed === "osv" ? osvMod : sourceMod;
  const effectiveName = fallbackSourceUsed === "osv" ? "osv" : sourceName;
  const advisory = result.advisories[0];
  if (!advisory) {
    const err = { ok: false, verb: "refresh", error: `--advisory ${id}: no matching advisory found`, source: result.source, routed_to: effectiveName };
    if (opts.json) process.stdout.write(JSON.stringify(err) + "\n");
    else process.stderr.write(`[refresh --advisory] ${err.error}\n`);
    process.exitCode = 2;
    return;
  }
  const normalized = effectiveMod.normalizeAdvisory(advisory);
  if (!normalized) {
    const err = { ok: false, verb: "refresh", error: `--advisory ${id}: advisory could not be normalized (missing required fields)`, routed_to: effectiveName, source_id: advisory.ghsa_id || advisory.id || null };
    if (opts.json) process.stdout.write(JSON.stringify(err) + "\n");
    else process.stderr.write(`[refresh --advisory] ${err.error}\n`);
    process.exitCode = 2;
    return;
  }
  const cveId = Object.keys(normalized)[0];

  if (!opts.apply) {
    const output = {
      ok: true,
      verb: "refresh",
      mode: "advisory-seed-dry-run",
      advisory_id: id,
      cve_id: cveId,
      draft: normalized[cveId],
      hint: "Re-run with --apply to write this draft into data/cve-catalog.json. After apply, run `exceptd run cve-curation --advisory " + cveId + "` to surface editorial proposals (framework gaps, IoCs, ATLAS/ATT&CK refs).",
    };
    if (opts.json) process.stdout.write(JSON.stringify(output) + "\n");
    else {
      process.stdout.write(`[refresh --advisory] ${cveId} draft prepared (not applied).\n`);
      process.stdout.write(`  Run with --apply to write into data/cve-catalog.json.\n`);
      process.stdout.write(`  Then: exceptd run cve-curation --advisory ${cveId}\n`);
    }
    process.exitCode = 3;
    return;
  }

  const catalogPath = resolveCatalogPath(opts);
  let humanCurated = null;
  await withCatalogLock(catalogPath, (catalog) => {
    if (catalog[cveId] && !catalog[cveId]._auto_imported && !catalog[cveId]._draft) {
      // Refuse to overwrite a human-curated entry; signalled through the closure
      // so the structured error emits after the lock releases.
      humanCurated = { last_updated: catalog[cveId].last_updated };
      return catalog; // unchanged write — idempotent, releases lock
    }
    catalog[cveId] = normalized[cveId];
    return catalog;
  });
  if (humanCurated) {
    const err = { ok: false, verb: "refresh", error: `${cveId} already present in catalog and is human-curated (not a draft). Refusing to overwrite. Edit manually if intentional.`, existing_last_updated: humanCurated.last_updated };
    if (opts.json) process.stdout.write(JSON.stringify(err) + "\n");
    else process.stderr.write(`[refresh --advisory] ${err.error}\n`);
    process.exitCode = 4;
    return;
  }
  const output = {
    ok: true,
    verb: "refresh",
    mode: "advisory-seed-applied",
    advisory_id: id,
    cve_id: cveId,
    written_to: "data/cve-catalog.json",
    is_draft: true,
    hint: "Draft written. Required next steps before this entry passes the strict catalog gate: (1) `exceptd run cve-curation --advisory " + cveId + "` to surface editorial proposals; (2) human review + fill in framework_control_gaps, atlas_refs, attack_refs, iocs; (3) add matching entry to data/zeroday-lessons.json; (4) remove `_auto_imported` and `_draft` flags.",
  };
  if (opts.json) process.stdout.write(JSON.stringify(output) + "\n");
  else process.stdout.write(`[refresh --advisory] ${cveId} draft written to data/cve-catalog.json.\n  Next: exceptd run cve-curation --advisory ${cveId}\n`);
  // Exit 3 even on successful write — "draft applied, editorial step pending."
  process.exitCode = 3;
}

const REFRESH_KNOWN_FLAGS = Object.freeze([
  "--apply", "--quiet", "--swarm", "--json", "--help", "-h", "--advisory",
  "--check-advisories", "--catalog", "--from-cache", "--source", "--from-fixture",
  "--report-out", "--air-gap", "--force-stale", "--force-stale-acked",
  "--no-network", "--prefetch", "--indexes-only", "--network", "--curate",
]);

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    printHelp();
    // exitCode + return, not process.exit() — buffered stdout must flush.
    process.exitCode = 0;
    return;
  }

  // Reject unknown flags BEFORE any network or catalog work: a swallowed typo
  // (`--aply`) otherwise falls through to a default all-sources live refresh.
  if (Array.isArray(opts._unknownFlags) && opts._unknownFlags.length > 0) {
    const uniq = [...new Set(opts._unknownFlags)];
    process.stderr.write(JSON.stringify({
      ok: false,
      verb: "refresh",
      error: `refresh: unknown flag(s): ${uniq.join(", ")}`,
      unknown_flags: uniq,
      known_flags: REFRESH_KNOWN_FLAGS,
    }) + "\n");
    process.exitCode = 2;
    return;
  }

  // Cache operations delegate to lib/prefetch.js exactly as bin/exceptd.js does,
  // so the direct path cannot egress and write a report despite --no-network.
  if (opts.prefetch || opts.noNetwork) {
    // prefetch.js knows only kev/nvd/epss/rfc/pins; the refresh-only sources
    // resolve by live id lookup and would die there as "unknown source", calling
    // a source unknown that the refresh help lists as valid.
    const PREFETCHABLE = new Set(["kev", "nvd", "epss", "rfc", "pins"]);
    let forwardSource = opts.source;
    if (opts.source) {
      const names = opts.source.split(",").map((s) => s.trim()).filter(Boolean);
      if (names.length === 0) {
        process.stderr.write(JSON.stringify({
          ok: false,
          verb: "refresh",
          error: `refresh: --source given but resolved to no source names (empty or comma-only value); prefetchable sources: ${[...PREFETCHABLE].join(",")}`,
        }) + "\n");
        process.exitCode = 2;
        return;
      }
      const unsupported = names.filter((n) => !PREFETCHABLE.has(n) && ALL_SOURCES[n]);
      const unknown = names.filter((n) => !PREFETCHABLE.has(n) && !ALL_SOURCES[n]);
      if (unknown.length > 0) {
        process.stderr.write(JSON.stringify({
          ok: false,
          verb: "refresh",
          error: `refresh: unknown source ${unknown.map((n) => `"${n}"`).join(", ")}; prefetchable sources: ${[...PREFETCHABLE].join(",")}`,
        }) + "\n");
        process.exitCode = 2;
        return;
      }
      if (unsupported.length > 0) {
        process.stderr.write(JSON.stringify({
          ok: false,
          verb: "refresh",
          error: `refresh: source ${unsupported.map((n) => `"${n}"`).join(", ")} has no prefetch cache layer (live id lookup only); prefetchable sources: ${[...PREFETCHABLE].join(",")}`,
        }) + "\n");
        process.exitCode = 2;
        return;
      }
      forwardSource = names.join(",");
    }
    const { spawnSync } = require("child_process");
    const pfArgs = [require.resolve("./prefetch.js")];
    if (opts.noNetwork) pfArgs.push("--no-network");
    if (forwardSource) pfArgs.push("--source", forwardSource);
    if (opts.quiet) pfArgs.push("--quiet");
    const r = spawnSync(process.execPath, pfArgs, { stdio: "inherit" });
    process.exitCode = r.status == null ? 1 : r.status;
    return;
  }

  // `--advisory <id>` short-circuits the source loop. An empty value must error
  // rather than falling through to a full-refresh dry run.
  if (opts.advisory != null && opts.advisory.trim() === "") {
    process.stderr.write(JSON.stringify({
      ok: false,
      error: "refresh: --advisory requires a non-empty identifier (e.g. CVE-2026-1234, GHSA-xxxx-xxxx-xxxx, MAL-2026-1).",
    }) + "\n");
    process.exitCode = 2;
    return;
  }
  if (opts.advisory) {
    return seedSingleAdvisory(opts);
  }

  const ctx = loadCtx(opts);
  const sources = chosenSources(opts);
  const log = (s) => opts.quiet || console.log(s);

  log(`\nrefresh-external — ${opts.apply ? "APPLY" : "dry-run"} mode${opts.swarm ? " (swarm)" : ""}`);
  log(`Sources: ${sources.map((s) => s.name).join(", ")}`);
  if (opts.fromFixture) log(`Fixture mode: ${opts.fromFixture}`);
  if (opts.fromCache) log(`Cache mode:   ${opts.fromCache}`);

  const report = {
    generated_at: new Date().toISOString(),
    mode: opts.apply ? "apply" : "dry-run",
    fixture_mode: !!opts.fromFixture,
    cache_mode: !!opts.fromCache,
    swarm: !!opts.swarm,
    sources: {},
  };

  let hadFailure = false;

  // Sequential keeps log output interleaved cleanly; --swarm fans the sources
  // out through Promise.all. Both modes produce the same report structure.
  const runOne = async (src) => {
    // GHSA and OSV honour --air-gap at the module level, but kev/epss/nvd/rfc/
    // pins fall through to their live branches without fixtures or a cacheDir.
    if (ctx.airGap && !ctx.fixtures?.[src.name] && !ctx.cacheDir) {
      return {
        src,
        diff: {
          status: "unreachable",
          diffs: [],
          errors: 0,
          summary: `air-gap mode: ${src.name} skipped (no fixture or cache configured; would have made a live network call)`,
          air_gap_blocked: true,
        },
      };
    }
    let diff;
    try {
      diff = await src.fetchDiff(ctx);
    } catch (err) {
      return { src, error: err };
    }
    return { src, diff };
  };

  // cve-regression-watcher consumes the advisories source's per-feed CVE
  // observations — they carry the in-catalog historical IDs the annotate verdict
  // needs — falling back to its diffs. Nothing else writes source output onto ctx.
  const threadAdvisoriesIntoCtx = (src, diff) => {
    if (src && src.name === "advisories" && diff && !diff.air_gap_blocked) {
      if (Array.isArray(diff.observations)) ctx.advisoriesObservations = diff.observations;
      if (Array.isArray(diff.diffs)) ctx.advisoriesDiffs = diff.diffs;
    }
  };

  let outcomes;
  if (!opts.swarm) {
    // Thread onto ctx as it resolves, BEFORE the next source's fetchDiff(ctx).
    outcomes = [];
    for (const src of sources) {
      const outcome = await runOne(src);
      if (!outcome.error) threadAdvisoriesIntoCtx(outcome.src, outcome.diff);
      outcomes.push(outcome);
    }
  } else {
    // Chaining through shared ctx cannot work inside one Promise.all, so the
    // watcher runs in a second pass. With advisories unselected it joins the
    // first batch — empty input is then the operator's choice, not a race.
    const hasAdvisories = sources.some((s) => s.name === "advisories");
    const watcher = hasAdvisories
      ? sources.find((s) => s.name === "cve-regression-watcher")
      : null;
    const firstBatch = watcher ? sources.filter((s) => s !== watcher) : sources;
    outcomes = await Promise.all(firstBatch.map(runOne));
    if (watcher) {
      for (const o of outcomes) {
        if (!o.error) threadAdvisoriesIntoCtx(o.src, o.diff);
      }
      const watcherOutcome = await runOne(watcher);
      // Preserve the operator's declared source order in the report.
      const idx = sources.indexOf(watcher);
      outcomes.splice(idx, 0, watcherOutcome);
    }
  }

  // runOne catches readCachedJson's cache-integrity refusals as per-source
  // errors, so _exceptd_exit_code=4 never reaches main().catch. Carry the marker
  // so exit 4 (precondition refusal) wins over the generic per-source failure 1.
  let cacheIntegrityFailure = false;
  for (const { src, diff, error } of outcomes) {
    if (error) {
      log(`\n  [${src.name}] ${src.description}`);
      log(`    error: ${error.message}`);
      report.sources[src.name] = { status: "error", error: error.message };
      if (error._exceptd_cache_integrity || error._exceptd_exit_code === 4) {
        report.sources[src.name].cache_integrity = true;
        cacheIntegrityFailure = true;
      }
      hadFailure = true;
      continue;
    }
    log(`\n  [${src.name}] ${src.description}`);
    log(`    ${diff.summary}`);
    report.sources[src.name] = {
      status: diff.status,
      summary: diff.summary,
      diff_count: diff.diffs.length,
      errors: diff.errors,
      diffs: diff.diffs,
      applies_to: src.applies_to,
      report_only: !!src.report_only,
      // Persisted so a stdout-parsing consumer can verify the network refusal.
      ...(diff.air_gap_blocked ? { air_gap_blocked: true } : {}),
      // The watcher stamps input_field_used onto _meta; persisting it makes the
      // chaining observable.
      ...(diff._meta ? { _meta: diff._meta } : {}),
      ...(Array.isArray(diff.observations) ? { observations: diff.observations } : {}),
    };
    if (opts.apply && diff.diffs.length > 0 && !src.report_only) {
      const r = await src.applyDiff(ctx, diff.diffs);
      report.sources[src.name].applied = r.updated;
      report.sources[src.name].apply_errors = r.errors;
      log(`    applied: ${r.updated} update(s)`);
      if (r.errors.length) log(`    apply errors: ${r.errors.join("; ")}`);
    }
  }

  // --report-out keeps concurrent runs off the shared refresh-report.json.
  const reportPath = opts.reportOut ? path.resolve(opts.reportOut) : ABS("refresh-report.json");
  writeJson(reportPath, report);
  log(`\nWrote ${path.relative(ROOT, reportPath)}`);

  if (opts.apply) {
    // Always regenerate indexes after an apply so validate-indexes passes.
    log(`\nRebuilding indexes (npm run build-indexes)`);
    try {
      execFileSync(process.execPath, [ABS("scripts/build-indexes.js")], { stdio: "inherit", cwd: ROOT });
    } catch (err) {
      console.error(`refresh-external: build-indexes failed: ${err.message}`);
      hadFailure = true;
    }
  }

  // exitCode + return, not process.exit(), which can truncate buffered stdout.
  // 4 (BLOCKED) wins over 1 when a source refused on a cache precondition.
  process.exitCode = cacheIntegrityFailure ? 4 : (hadFailure ? 1 : 0);
}

if (require.main === module) {
  main().catch((err) => {
    // A hinted error prints its message plus a JSON line, never a stack trace.
    if (err && err._exceptd_hint) {
      console.error(err.message);
      console.error(JSON.stringify({ ok: false, error: err.message.split("\n")[0], hint: err.message.split("\n").slice(1).join(" ").trim(), verb: "refresh" }));
    } else if (err && err._exceptd_unknown_source) {
      // chosenSources throws this for an unknown --source; no stack trace.
      console.error(err.message);
    } else {
      console.error(`refresh-external: fatal: ${err && err.stack ? err.stack : err}`);
    }
    // exitCode rather than process.exit(2), so stderr drains first. A refusal
    // carrying _exceptd_exit_code=4 reads as "blocked by precondition", not fatal.
    process.exitCode = (err && Number.isInteger(err._exceptd_exit_code)) ? err._exceptd_exit_code : 2;
  });
}

module.exports = { ALL_SOURCES, loadCtx, parseArgs, seedSingleAdvisory, withCatalogLock, writeJsonAtomic, nvdDiffFromCache, kevDiffFromCache, epssDiffFromCache, epssTripleDiffs, EPSS_DRIFT };
