"use strict";
/**
 * lib/refresh-external.js
 *
 * External-data refresh orchestrator. Pulls the latest from the canonical
 * upstream sources and either reports drift (dry-run, default) or applies
 * the drift as an upsert into the local catalog (--apply).
 *
 * Sources (each is independently pluggable):
 *
 *   KEV    — CISA Known Exploited Vulnerabilities (per-CVE upsert of
 *            cisa_kev / cisa_kev_date)
 *   EPSS   — FIRST EPSS (per-CVE upsert of epss_score / epss_percentile /
 *            epss_date)
 *   NVD    — NIST NVD 2.0 (per-CVE upsert of cvss_score / cvss_vector)
 *   RFC    — IETF Datatracker (per-RFC upsert of status)
 *   PINS   — MITRE ATLAS / ATT&CK / D3FEND / CWE upstream releases
 *            (REPORT-ONLY — version bumps need audit per AGENTS.md
 *            Hard Rule #12, so they surface as findings, not auto-applied)
 *
 * Usage:
 *   node lib/refresh-external.js              # dry-run all sources
 *   node lib/refresh-external.js --apply      # apply all sources
 *   node lib/refresh-external.js --source kev # one source, dry-run
 *   node lib/refresh-external.js --apply --source kev,epss
 *   node lib/refresh-external.js --from-fixture <path>   # use frozen fixture
 *                                                          payloads (offline)
 *
 * Exit codes:
 *   0 — dry-run completed (regardless of whether drift was found)
 *   1 — apply mode AND a downstream gate (validate-indexes, lint) failed
 *   2 — unrecoverable runner error
 *
 * The refresh-report.json artifact lives at the repo root and is
 * gitignored. CI uploads it as a workflow artifact.
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { selectNvdCvss, cvssVersionOf } = require("./cvss");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const TODAY = new Date().toISOString().slice(0, 10);

// v0.12.8: the CVE catalog path used by refresh-external is overridable so
// tests can redirect to a tempdir instead of mutating the real shipped
// data/cve-catalog.json. Resolution order:
//   1. opts.catalog (--catalog CLI arg)
//   2. process.env.EXCEPTD_CVE_CATALOG (env var)
//   3. ROOT/data/cve-catalog.json (default)
// All four write-sites in this file route through resolveCatalogPath() so
// that the redirect is consistent across the advisory-import, GHSA-import,
// and per-source merge code paths.
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
    advisory: null,      // v0.12.0: single-advisory seed (CVE-* or GHSA-*)
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
    // --check-advisories polls the primary-source advisory feeds (Qualys TRU,
    // RHSA, USN, ZDI, kernel.org, oss-security, vendor research blogs) and
    // reports newly-seen CVE IDs ahead of NVD enrichment. Report-only: it
    // selects the `advisories` source and never applies — operators triage the
    // diffs[] and seed promising IDs via `refresh --advisory <id> --apply`.
    else if (a === "--check-advisories") { out.source = "advisories"; out.apply = false; out.checkAdvisories = true; }
    else if (a === "--catalog") { out.catalog = argv[++i]; }
    else if (a.startsWith("--catalog=")) { out.catalog = a.slice("--catalog=".length); }
    else if (a === "--from-cache") {
      // accept either --from-cache <path> or --from-cache (default path)
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
    // Honour `--air-gap` here so it reaches the GHSA/OSV source modules.
    // EXCEPTD_AIR_GAP=1 still works as an env-var fallback so existing
    // automation isn't broken.
    else if (a === "--air-gap") out.airGap = true;
    // `--force-stale` bypasses cache-freshness + cache-signature refusals.
    // Required when the operator intentionally wants to consume a cache
    // older than 7d or one that was prefetched without a signing keypair.
    // EXCEPTD_FORCE_STALE=1 mirrors for non-interactive automation.
    else if (a === "--force-stale") out.forceStale = true;
    // --prefetch / --no-network are prefetch-cache operations. Capture them so
    // main() can delegate to lib/prefetch.js (the same routing bin/exceptd.js
    // performs) when this script is invoked directly — otherwise the help
    // text's "report-only, no cache write" promise for --no-network is a lie
    // on the direct path, which would fall through to the live refresh loop.
    else if (a === "--no-network") { out.noNetwork = true; }
    else if (a === "--prefetch") { out.prefetch = true; }
    // Remaining bin-translated aliases are tolerated as no-ops at this layer
    // so the unknown-flag guard below doesn't false-reject them.
    else if (
      a === "--indexes-only" ||
      a === "--network" || a === "--curate" || a === "--force-stale-acked"
    ) { /* accepted, no-op at this layer */ }
    // Any remaining --flag is an unrecognized typo. Record it; refuse after
    // the loop rather than silently dropping it into a default full-refresh
    // (which previously hit the live network on every source).
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

// --- Source modules ----------------------------------------------------

/**
 * Each source module exposes:
 *   name: string
 *   fetchDiff(ctx, opts) -> Promise<{ status, diffs, errors, summary }>
 *     status: "ok" | "unreachable" | "partial"
 *     diffs:  array of { id, field, before, after, severity? }
 *     summary: brief string
 *   applyDiff(ctx, diffs) -> Promise<{ updated, errors }>
 *     mutates local catalog and writes it
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
    for (const r of report.results) {
      if (r.status === "unreachable") errors++;
      for (const d of r.discrepancies || []) {
        if (d.field === "cisa_kev" || d.field === "cisa_kev_date") {
          diffs.push({ id: r.cve_id, field: d.field, before: d.local, after: d.fetched, severity: d.severity });
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
          // Auto-discovered new entry. Refuse to overwrite if the entry
          // somehow exists (race condition / stale fixture); skip silently.
          if (catalog[d.id]) continue;
          catalog[d.id] = d.entry;
          added++;
          continue;
        }
        if (!catalog[d.id]) {
          errors.push(`KEV: no local entry for ${d.id}`);
          continue;
        }
        // A de-listing flagged for review (a curated entry with strong
        // exploitation signal that upstream KEV no longer lists) is surfaced
        // in the report but NOT auto-applied: the curated flag, factor, score
        // and dates are left intact so a maintainer can confirm a genuine
        // CISA removal vs a transient / incomplete feed before the entry is
        // downgraded. Skip the write here.
        if (d.review_only) continue;
        catalog[d.id][d.field] = d.after;
        // A cisa_kev flip changes the entry's RWEP: the KEV factor carries
        // RWEP_WEIGHTS.cisa_kev points, and the catalog invariant requires
        // rwep_score to equal the factor sum. Writing the flag without the
        // factor + score left entries failing scoring.validate() (stored 45
        // vs computed 70 on the first real KEV listing the refresh applied).
        if (d.field === "cisa_kev") {
          const entry = catalog[d.id];
          if (entry.rwep_factors && typeof entry.rwep_factors === "object") {
            const scoring = require("./scoring");
            // Match the stored factor shape: Shape A keeps the boolean,
            // Shape B (the catalog norm) stores the post-weight contribution.
            entry.rwep_factors.cisa_kev =
              typeof entry.rwep_factors.cisa_kev === "boolean"
                ? !!d.after
                : (d.after ? scoring.RWEP_WEIGHTS.cisa_kev : 0);
            entry.rwep_score = scoring.deriveRwepFromFactors(entry.rwep_factors);
          }
          // A de-listing (true→false) leaves the listing date orphaned: the
          // CVE is no longer KEV-listed, so its dateAdded is stale intel.
          // The upstream diff producer only emits a cisa_kev_date diff when
          // upstream has a date, which a de-listed CVE no longer does — so
          // nothing else clears it. Drop the now-meaningless date fields here.
          if (d.after === false) {
            if ("cisa_kev_date" in entry) entry.cisa_kev_date = null;
            if ("cisa_kev_due_date" in entry) entry.cisa_kev_due_date = null;
          }
        }
        catalog[d.id].last_verified = TODAY;
        updated++;
      }
      catalog._meta = catalog._meta || {};
      catalog._meta.last_updated = TODAY;
      // Refresh the in-memory view so later sources in the same process
      // (sequential or --swarm) see the post-write state.
      ctx.cveCatalog = catalog;
      return catalog;
    });
    return { updated: updated + added, added, drift_updated: updated, errors };
  },
};

/**
 * Cache-mode KEV with auto-discovery merged in. Standard drift-check
 * for existing entries plus discoverNewKev() for entries upstream that
 * aren't in the local catalog. Spill count is surfaced in the summary.
 */
function kevDiffWithDiscoveryFromCache(ctx) {
  const drift = kevDiffFromCache(ctx);
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
      for (const d of r.discrepancies || []) {
        if (d.field === "epss_score" || d.field === "epss_percentile") {
          diffs.push({ id: r.cve_id, field: d.field, before: d.local, after: d.fetched, severity: d.severity });
        }
      }
      // epss_date refreshes when score does.
      if (r.fetched?.epss?.date && r.local) {
        diffs.push({ id: r.cve_id, field: "epss_date", before: r.local.epss_date, after: r.fetched.epss.date, severity: "low" });
      }
    }
    // Collapse duplicates: epss_date should appear once per CVE only when
    // an epss field actually moved.
    const epssCves = new Set(diffs.filter((d) => d.field === "epss_score" || d.field === "epss_percentile").map((d) => d.id));
    const filtered = diffs.filter((d) => d.field !== "epss_date" || epssCves.has(d.id));
    return {
      status: errors === 0 ? "ok" : errors === report.results.length ? "unreachable" : "partial",
      diffs: filtered,
      errors,
      summary: `${filtered.length} EPSS diffs; ${errors} unreachable / ${report.total} total`,
    };
  },
  async applyDiff(ctx, diffs) {
    let updated = 0;
    const errors = [];
    const catalogPath = ctx.cvePath || ABS("data/cve-catalog.json");
    await withCatalogLock(catalogPath, (catalog) => {
      for (const d of diffs) {
        if (!catalog[d.id]) {
          errors.push(`EPSS: no local entry for ${d.id}`);
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
        // A curator-owned CVSS re-score is surfaced in the report but not
        // applied — the curated value is preserved until a maintainer accepts
        // the upstream delta (symmetric with the KEV review_only path).
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
          // The current rfc-validator returns discrepancies as strings. We
          // attempt to parse a status drift; fall back to the raw message.
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
 * Cache-mode RFC with auto-discovery merged in. Drift-check for
 * existing entries (cache only) plus discoverNewRfcs() which hits
 * Datatracker live for new RFCs in project-relevant working groups.
 * Discovery makes ~30 HTTP calls (one per project WG) per refresh —
 * Datatracker's read budget is generous so this is well within limit.
 */
async function rfcDiffWithDiscoveryFromCache(ctx) {
  const drift = rfcDiffFromCache(ctx);
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
    // Version pins are intentionally not auto-applied.
    return { updated: 0, errors: ["pin bumps are report-only — see Hard Rule #12"] };
  },
};

/**
 * v0.12.0: GHSA (GitHub Advisory Database) source. Covers npm, PyPI,
 * RubyGems, Maven, NuGet, Go, Composer, Swift, Erlang, Pub, Rust — all
 * in one feed, updated within hours of disclosure. Much faster than KEV
 * (variable, often days) or NVD (~10 days).
 *
 * Apply path: new CVE IDs from GHSA land in data/cve-catalog.json as
 * DRAFTS (`_auto_imported: true` + `_draft: true`). The strict catalog
 * validator treats drafts as warnings, not errors, so the nightly
 * auto-PR pipeline can ship them without blocking on editorial review.
 * Framework gaps + IoCs + ATLAS/ATT&CK refs require human or AI-assisted
 * synthesis via `exceptd run cve-curation --advisory <id>`.
 */
const GHSA_SOURCE = {
  name: "ghsa",
  description: "GitHub Advisory Database — multi-ecosystem disclosure feed (npm, PyPI, Maven, Go, etc.)",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.ghsa) return synthesizeFromFixture(ctx, "ghsa");
    if (ctx.cacheDir) {
      // --from-cache is the offline ingest path: every source reads only
      // local cache files, never the network. GHSA has no cache layer, so
      // there is nothing to read offline. Skip it with a structured status
      // instead of falling through to the live api.github.com fetch, which
      // would silently egress on a host the operator believes is isolated.
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
    // v0.12.14: the prior shape mutated ctx.cveCatalog in
    // memory but NEVER persisted to disk. Bulk `--source ghsa --apply`
    // reported "applied: N updates" while the catalog file gained zero
    // entries. Worse under `--swarm`: KEV's withCatalogLock would re-read
    // catalog from disk INSIDE the lock and overwrite the unflushed
    // in-memory mutations. Route through the same withCatalogLock helper
    // that KEV/EPSS/NVD/RFC use (v0.12.12 concurrency fix).
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
 * v0.12.10: OSV.dev source. Aggregates OSSF Malicious Packages (MAL-*) +
 * Snyk (SNYK-*) + GitHub Advisory Database + RustSec (RUSTSEC-*) + Mageia
 * + Go Vuln DB + Ubuntu USN into one unauthenticated API. Slot in for the
 * package-compromise class that doesn't have a CVE yet — the MAL-*
 * namespace is the canonical key for those (e.g. MAL-2026-3083, the
 * elementary-data PyPI worm).
 *
 * Apply path mirrors GHSA: new entries land in data/cve-catalog.json as
 * drafts (`_auto_imported: true` + `_draft: true`). Catalog key is either
 * the CVE alias (when present) or the OSV id verbatim — preserving the
 * existing CVE-keyed convention while accepting OSV's broader identifier
 * shapes.
 */
const OSV_SOURCE = {
  name: "osv",
  description: "OSV.dev — OSSF Malicious Packages (MAL-*) + Snyk + GHSA + RustSec + Mageia + Go Vuln DB + Ubuntu USN. Unauthenticated. Slot in for the broader supply-chain-class disclosure space — covers package compromises that don't have CVEs yet.",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.osv) return synthesizeFromFixture(ctx, "osv");
    if (ctx.cacheDir) {
      // --from-cache is the offline ingest path. OSV resolves advisories by
      // live id lookup (ctx.osv_ids) and has no cache layer, so skip it with
      // a structured status rather than risk a live osv.dev fetch on a host
      // the operator believes is isolated.
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
    // v0.12.14: same fix as GHSA — route the read-modify-write
    // through withCatalogLock so writes actually land on disk and so
    // concurrent --source osv --apply doesn't lose updates.
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

// v0.13.1: ADVISORIES_SOURCE polls Qualys TRU + RHSA + USN + ZDI primary
// feeds and surfaces CVE IDs not yet in the catalog. Report-only — no
// auto-catalog mutation. Closes the post-mortem gap on CVE-2026-46333
// (ssh-keysign-pwn) where the existing NVD-based pollers lagged by 3+ days.
const { ADVISORIES_SOURCE } = require('./source-advisories');

// v0.13.17: REGRESSION_WATCHER_SOURCE is NEW-CTRL-074. Implements the
// detection method that surfaces poller-diff historical-CVE references as
// candidate silent-regression cases (the MiniPlasma class — a 2026 PoC
// drop that re-broke CVE-2020-17103 without any new ID being assigned).
// Report-only; consumes diffs + extracted-CVE-id list from a prior
// advisories run (loadCtx populates ctx.advisoriesDiffs +
// ctx.advisoriesExtractedCveIds when advisories runs alongside the
// watcher, or operators can chain explicitly via the source registry).
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

// --- Cache-mode helpers ------------------------------------------------
// When `--from-cache <dir>` is set, the source modules read their inputs
// from the prefetch cache instead of hitting upstream. The cache layout
// is fixed by lib/prefetch.js:
//   <cacheDir>/kev/known_exploited_vulnerabilities.json
//   <cacheDir>/nvd/<cve>.json
//   <cacheDir>/epss/<cve>.json
//   <cacheDir>/rfc/<doc-name>.json
//   <cacheDir>/pins/<owner__repo__releases>.json
//
// readCachedJson returns null on miss; callers report it as "unreachable"
// for that entry rather than failing the whole source.

// sha256 of on-disk cache entries is recorded in _index.json at fetch time
// but was never verified on consume. A coordinated tamper that rewrote
// e.g. `.cache/upstream/kev/known_exploited_vulnerabilities.json` between
// prefetch and refresh would silently feed false intelligence into the
// applied catalog. We now recompute the sha256 inside readCachedJson and
// refuse on mismatch.
//
// The sha256 stored at prefetch time is computed over JSON.stringify(payload)
// — unindented. The on-disk bytes use JSON.stringify(payload, null, 2)+"\n",
// so we round-trip parse and re-canonicalize to compute the comparable hash.
function readCachedJson(cacheDir, source, id, opts) {
  const forceStale = !!(opts && opts.forceStale);
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(cacheDir, source, `${safe}.json`);
  if (!fs.existsSync(p)) return null;
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return null; }
  // Look up the index entry. If the index is absent or doesn't have an
  // entry for this source/id, we cannot verify integrity — refuse rather
  // than fail-open. The cache invariant is: every payload on disk has a
  // signed entry in _index.json. `--force-stale` is the operator escape
  // hatch for pre-v0.12.24 caches that lack the per-entry sha256 records;
  // we proceed without integrity checking but emit a warning so the gap
  // is visible in logs.
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
    // sha256 mismatch is a hard tamper signal — `--force-stale` does NOT
    // bypass it. An operator who knows the cache is stale can re-prefetch;
    // an operator whose cache has been tampered should not proceed.
    const err = new Error(`cache-integrity: sha256 mismatch for ${source}/${id} (expected ${expected.slice(0, 16)}..., got ${actual.slice(0, 16)}...)`);
    err._exceptd_cache_integrity = true;
    err._exceptd_hint = true;
    err._exceptd_exit_code = 4;
    throw err;
  }
  return parsed;
}

// A curated entry carries strong human-curated exploitation signal when its
// active_exploitation is confirmed/suspected, or it has a non-empty PoC
// description / verification sources. A de-listing of such an entry is far
// more likely a transient or incomplete upstream feed than a genuine CISA
// removal, so it is surfaced for review rather than auto-applied.
function hasCuratedExploitSignal(entry) {
  if (!entry || typeof entry !== "object") return false;
  const ae = typeof entry.active_exploitation === "string" ? entry.active_exploitation.toLowerCase() : "";
  if (ae === "confirmed" || ae === "suspected") return true;
  if (typeof entry.poc_description === "string" && entry.poc_description.trim()) return true;
  if (Array.isArray(entry.verification_sources) && entry.verification_sources.length > 0) return true;
  return false;
}

// A catalog entry is curator-owned (its CVSS is hand-verified, not an upstream
// auto-import) unless it carries `_auto_imported: true`. An NVD CVSS re-score on
// a curator-owned entry is surfaced for review rather than auto-applied — the
// same principle as the curated-KEV de-listing guard above. The version-
// downgrade guards already suppress a v3.x→v2 regression; this additionally
// keeps a *same-version* NVD re-score (e.g. a curated 10.0 the maintainer pinned
// dropping to NVD's 9.8) from silently overwriting the curated value. Raw
// auto-imported drafts (`_auto_imported: true`) are not yet curated, so NVD is
// their source of truth and their CVSS applies normally.
function isCuratorOwnedCvss(entry) {
  return !!entry && typeof entry === "object" && entry._auto_imported !== true;
}

// Build an NVD CVSS diff, marking it review-only when the local entry is
// curator-owned so applyDiff preserves the curated value while the report still
// surfaces the upstream delta for a maintainer to accept deliberately.
function cvssDiff(id, field, before, after, severity, local) {
  const d = { id, field, before, after, severity };
  if (isCuratorOwnedCvss(local)) {
    d.review_only = true;
    d.cvss_review = true;
    d.note = `NVD ${field} change held for review: ${id} is curator-owned (hand-verified CVSS). Confirm and re-curate to accept NVD's ${after} over the curated ${before}; not auto-applied so the curated value is preserved.`;
  }
  return d;
}

// Below this many entries the cached KEV feed is treated as truncated /
// incomplete rather than a genuine CISA snapshot. CISA KEV has carried well
// over a thousand entries since 2021 and only grows; a feed this small means
// a partial download or a tampered cache, and trusting it to de-list curated
// entries would silently erase confirmed-exploitation intel. De-listings are
// refused wholesale when the feed is implausibly small.
const KEV_FEED_MIN_PLAUSIBLE = 500;

function kevDiffFromCache(ctx) {
  const feed = readCachedJson(ctx.cacheDir, "kev", "known_exploited_vulnerabilities", { forceStale: ctx.forceStale });
  if (!feed) {
    return { status: "unreachable", diffs: [], errors: 1, summary: "KEV: no cached feed" };
  }
  const kevSet = new Set();
  const kevDates = new Map();
  for (const v of feed.vulnerabilities || []) {
    if (v && v.cveID) {
      kevSet.add(v.cveID);
      if (v.dateAdded) kevDates.set(v.cveID, v.dateAdded);
    }
  }
  // An implausibly small feed cannot be trusted to de-list curated entries.
  // First-listings (false→true) still flow — a small feed never invents new
  // exploitation; only the de-list direction is suppressed.
  const feedComplete = kevSet.size >= KEV_FEED_MIN_PLAUSIBLE;
  const diffs = [];
  for (const [id, entry] of Object.entries(ctx.cveCatalog)) {
    if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) continue;
    const upstream = kevSet.has(id);
    if (typeof entry.cisa_kev === "boolean" && entry.cisa_kev !== upstream) {
      const isDelist = entry.cisa_kev === true && upstream === false;
      // Symmetric with the NVD path's curated-downgrade guard: never silently
      // regress curated exploitation intel against an upstream that disagrees.
      // A de-listing of a curated entry with strong exploitation signal, OR
      // any de-listing when the feed is implausibly small, is re-tagged as a
      // review-only diff — surfaced in the report so a maintainer confirms a
      // genuine CISA removal, but NOT auto-applied (applyDiff skips
      // review_only diffs, leaving cisa_kev / rwep / dates intact).
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
    // First listings arrive with a null local date — emit the date diff
    // whenever upstream has one that the local entry lacks or contradicts,
    // so the flag flip and its listing date apply together (the strict
    // catalog validator requires KEV-listed entries to carry the date).
    if (upDate && (entry.cisa_kev_date || null) !== upDate) {
      diffs.push({ id, field: "cisa_kev_date", before: entry.cisa_kev_date ?? null, after: upDate, severity: "low" });
    }
  }
  return { status: "ok", diffs, errors: 0, summary: `${diffs.length} KEV diffs (from cache)` };
}

function epssDiffFromCache(ctx) {
  const cves = Object.keys(ctx.cveCatalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));
  const diffs = [];
  let errors = 0;
  const drift = 0.05;
  for (const id of cves) {
    const payload = readCachedJson(ctx.cacheDir, "epss", id, { forceStale: ctx.forceStale });
    if (!payload) { errors++; continue; }
    const row = (payload.data || []).find((r) => r?.cve === id) || (payload.data || [])[0];
    if (!row) continue;
    const score = row.epss != null ? Number(row.epss) : null;
    const pct = row.percentile != null ? Number(row.percentile) : null;
    const local = ctx.cveCatalog[id];
    if (score != null && local.epss_score != null && Math.abs(score - local.epss_score) > drift) {
      diffs.push({ id, field: "epss_score", before: local.epss_score, after: score, severity: "medium" });
    }
    if (pct != null && local.epss_percentile != null && Math.abs(pct - local.epss_percentile) > drift) {
      diffs.push({ id, field: "epss_percentile", before: local.epss_percentile, after: pct, severity: "medium" });
    }
    if (row.date && local.epss_date && row.date !== local.epss_date) {
      // Only emit a date diff when we also emitted a score/percentile diff for this CVE.
      const moved = diffs.some((d) => d.id === id && (d.field === "epss_score" || d.field === "epss_percentile"));
      if (moved) diffs.push({ id, field: "epss_date", before: local.epss_date, after: row.date, severity: "low" });
    }
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
    const vuln = payload.vulnerabilities?.[0]?.cve;
    if (!vuln) continue;
    // Prefer the newest CVSS version NVD publishes (Primary within that
    // version), and normalize a bare v2 vector to its canonical prefix.
    const up = selectNvdCvss(vuln.metrics);
    if (!up) continue;
    const local = ctx.cveCatalog[id];
    // Never regress a curated higher-version CVSS to an older upstream metric.
    // NVD keeps many pre-2016 CVEs at v2 only (or tags v2 "Primary" over a
    // v3.1 "Secondary"); the catalog has been curated to v3.1. When the
    // selected upstream metric is an older CVSS version than the curated one,
    // suppress both the score and the vector diff. A same-version drift (a
    // genuine NVD re-score) still flows through.
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
  // Cache layout under pins/: <owner>__<repo>__releases.json arrays.
  // Only repos that publish via GitHub Releases live here — D3FEND and CWE
  // were removed in the same pass that pruned them from lib/prefetch.js's
  // SOURCES.pins (neither project tags releases on GitHub; D3FEND ships
  // the ontology from d3fend/d3fend-ontology without tagged releases,
  // and CWE distributes XML from cwe.mitre.org). Pin currency for those
  // two frameworks is monitored via lib/upstream-check.js against their
  // canonical mitre.org endpoints, not through the prefetch cache.
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

// --- Fixture-mode helper ----------------------------------------------

function synthesizeFromFixture(ctx, sourceName) {
  // The frozen fixture payloads are JSON files that look like:
  //   { diffs: [...], errors: 0, summary: "..." }
  // tests/fixtures/refresh/<sourceName>.json drives this path.
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

// --- IO helpers --------------------------------------------------------

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
    // Thread --air-gap (or EXCEPTD_AIR_GAP=1) through to ctx.airGap so the
    // GHSA + OSV source modules (lib/source-ghsa.js, lib/source-osv.js)
    // branch on it and refuse network egress.
    airGap: !!(opts && opts.airGap) || process.env.EXCEPTD_AIR_GAP === "1",
    // Thread --force-stale through so readCachedJson can downgrade cache-
    // integrity refusals to warnings when an operator explicitly opts out.
    forceStale: !!(opts && opts.forceStale),
  };
  if (opts.fromFixture) {
    // `--from-fixture` injects frozen test payloads as if they were live
    // upstream responses. Allowing this on an operator's host would let any
    // caller forge KEV / NVD / EPSS / pin diffs into the applied catalog.
    // Gate the flag behind EXCEPTD_TEST_HARNESS=1 so it only activates in
    // explicit test contexts.
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
    // v0.13.7: load tests/fixtures/refresh/advisories.json into
    // ctx.fixtures.advisories so the advisory poller (Qualys / RHSA / USN /
    // ZDI / kernel.org / oss-security / JFrog / CISA) uses frozen content
    // instead of falling through to live RSS. Prior to this load, two
    // back-to-back fixture-mode runs (e.g. sequential vs `--swarm`) hit
    // the real-world feeds at different moments and diverged on Pwn2Own /
    // Trend Micro / ZDI advisories rotated within the window — surfaced as
    // a CI flake on macOS runners where the test took longer to complete.
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
      // Operators following the air-gap workflow hit this with an unhelpful
      // "path does not exist" stack trace. The cache is populated by
      // `exceptd refresh --prefetch` (which routes to prefetch) — NOT by
      // `--no-network`, which is the report-only dry run that writes nothing.
      // Tell them exactly that, and emit a structured JSON error to stderr
      // instead of a fatal stack trace.
      const err = new Error(
        `refresh: --from-cache path does not exist: ${abs}\n` +
        `Hint: the cache is populated by running \`exceptd refresh --prefetch\` ` +
        `on a connected host first. Air-gap workflow: (1) on connected host: \`exceptd refresh --prefetch\`, ` +
        `(2) copy .cache/upstream/ across the boundary, (3) on offline host: \`exceptd refresh --from-cache --apply\`.`
      );
      err._exceptd_hint = true;
      throw err;
    }
    // _index.json signature verification. The cache was signed at
    // prefetch time with the Ed25519 private key. Refuse to consume any
    // cache whose sidecar signature does not verify against keys/public.pem,
    // unless the operator explicitly accepts the risk via --force-stale.
    // A missing sidecar (cache prefetched on a host without the signing
    // keypair) is treated identically: same refusal, same override.
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
      // Loader error (prefetch.js missing exports, etc.) — treat as a hard
      // refusal rather than fail-open. Operators on --force-stale still
      // pass through.
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
    // Max-age check. Cache entries whose freshest fetched_at is older
    // than 7 days are refused outright; intel that stale is more likely
    // to be misleading than helpful (KEV gains entries weekly; EPSS shifts
    // daily). --force-stale overrides for genuine air-gap workflows.
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
      // Index parse error — bubble up as a hint
      const err = new Error(`refresh: --from-cache _index.json unreadable: ${e && e.message}`);
      err._exceptd_hint = true;
      err._exceptd_exit_code = 4;
      throw err;
    }
  }
  return ctx;
}

// v0.12.12 C4: every persisted JSON write goes through writeJsonAtomic — a
// tmp + rename pattern. fs.renameSync is atomic on POSIX and on Windows for
// same-volume renames (which a `.tmp.<pid>.<rand>` adjacent to the target
// always satisfies). A concurrent reader either sees the prior file content
// in full or the new content in full — never a half-written buffer. The
// tmp name carries pid + random so two writers in the same process (e.g.
// worker threads) never collide on the same scratch path.
function writeJsonAtomic(p, obj) {
  const tmpPath = `${p}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 10)}`;
  // v0.13.0: fsync the tmp file before rename so a power loss between
  // write and rename leaves the durable destination intact. See the
  // matching helper in lib/cve-curation.js for the rationale.
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

// Back-compat alias — exported callers and historical sites still reference
// writeJson. Atomic by default; never the unsafe direct-write form.
function writeJson(p, obj) {
  writeJsonAtomic(p, obj);
}

/**
 * v0.12.12 C1: lockfile-gated read-modify-write helper for JSON catalogs.
 *
 * Two concurrent `refresh --advisory CVE-A --apply` and
 * `refresh --advisory CVE-B --apply` processes against the same catalog used
 * to race: each read the catalog, mutated its in-memory copy, then wrote —
 * the second write overwrote the first, silently dropping one CVE. The fix
 * is a sidecar lockfile (created with O_EXCL via `flag: 'wx'`) that
 * serializes the read-mutate-write triple. The mutator receives the
 * current-on-disk catalog (re-read inside the lock, NOT a stale in-memory
 * copy from before lock acquisition) and returns it after mutation; the
 * helper then writes atomically via writeJsonAtomic.
 *
 * Stale-lock recovery: if a holder crashes without unlinking, the lockfile
 * persists. After backoff, if the lockfile's mtime is older than 30s we
 * treat it as orphaned and unlink it before retrying. 30s is well past any
 * legitimate single-CVE apply (sub-second on modern disks).
 *
 * On acquisition failure after N retries, we throw — better than silently
 * proceeding without the lock.
 *
 * @param {string} catalogPath  path to the JSON catalog to lock
 * @param {(catalog: object) => object | Promise<object>} mutator
 *        receives current-on-disk catalog, returns mutated catalog. May be
 *        async. The return value is what gets written; if it returns
 *        undefined, the in-place mutation of the passed-in catalog is used.
 * @returns {Promise<{ wrote: boolean, result: any }>}
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
      // EEXIST is the POSIX signal another process holds the lock. On
      // Windows the same race surfaces as EPERM (sharing-violation raised
      // when the holder is mid-unlink). Treat both as "lock held, back off."
      if (e.code !== "EEXIST" && e.code !== "EPERM") throw e;
      // PID-liveness check before falling back to mtime. The lockfile
      // contains String(process.pid) of the holder; parse it and probe with
      // `process.kill(pid, 0)`. ESRCH means the holder is dead — reclaim
      // immediately rather than waiting STALE_LOCK_MS for the mtime gate
      // to expire. EPERM (holder alive, different user) is treated as
      // "alive, keep waiting." The mtime gate remains as a belt-and-
      // suspenders for cases where the lockfile content is missing /
      // malformed / belongs to a recycled PID. Matches the PID pattern in
      // orchestrator/index.js _acquireWatchLock and
      // lib/playbook-runner.js pidAlive().
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
      // Stale-lock check before sleeping — a long-dead holder shouldn't keep
      // us waiting MAX_RETRIES * backoff before we recover.
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
  // Flag-absent (opts.source == null) means "all sources" — the default
  // refresh behavior. Flag-present-but-empty (`--source ""`, or a value that
  // trims to nothing like `--source ","`) is an operator error, not a
  // silent run-everything: refuse and list the valid names so the typo is
  // visible rather than masquerading as a full refresh.
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
      // v0.12.12 C3: previously `process.exit(2)` after a console.error.
      // Stdout writes elsewhere in this run could truncate; throwing lets
      // main().catch() surface the error through the standard channel and
      // exit code via process.exitCode + natural event-loop drain.
      const err = new Error(`refresh-external: unknown source "${n}". Valid: ${Object.keys(ALL_SOURCES).join(", ")}`);
      err._exceptd_unknown_source = true;
      throw err;
    }
    out.push(ALL_SOURCES[n]);
  }
  return out;
}

/**
 * v0.12.0: single-advisory seed. Operator types
 *   exceptd refresh --advisory CVE-2026-45321
 * or
 *   exceptd refresh --advisory GHSA-xxxx-xxxx-xxxx --apply
 *
 * Tool fetches from GHSA (covers npm, PyPI, etc.), normalizes to the
 * exceptd catalog draft shape, and either prints the seed (default) or
 * writes it to data/cve-catalog.json (--apply). Always exits non-zero
 * when a draft is produced, signaling that editorial review is needed.
 */
async function seedSingleAdvisory(opts) {
  const id = opts.advisory;
  // v0.12.10: route OSV-native ids (MAL-*, SNYK-*, RUSTSEC-*, USN-*, etc.)
  // through source-osv. CVE-* and GHSA-* keep routing through GHSA because
  // GHSA carries richer field coverage for those identifier shapes.
  const osvMod = require("./source-osv");
  const useOsv = osvMod.isOsvId(id) && !/^GHSA-/i.test(id);
  const ghsa = require("./source-ghsa");
  const sourceMod = useOsv ? osvMod : ghsa;
  const sourceName = useOsv ? "osv" : "ghsa";
  const fixtureEnv = useOsv ? "EXCEPTD_OSV_FIXTURE" : "EXCEPTD_GHSA_FIXTURE";

  // Thread the air-gap disposition (the --air-gap flag OR EXCEPTD_AIR_GAP=1)
  // into the fetch. Previously this passed {} and dropped --air-gap, so
  // `refresh --advisory <id> --air-gap` egressed to the network — an air-gap
  // violation. Both source modules refuse (no fixture) when airGap is set.
  const airGap = !!opts.airGap || process.env.EXCEPTD_AIR_GAP === "1";

  let result = await sourceMod.fetchAdvisoryById(id, { airGap });
  // F4 (v0.12.11): CVE-* identifiers may have an OSV record before GHSA
  // publishes one (CNAs and OSV mirrors operate on different cadences).
  // When GHSA returns 404 specifically, retry through OSV's /v1/vulns/{id}
  // — OSV indexes CVE ids as primary keys. If both 404, surface a combined
  // error message so operators know both sources were tried before failing.
  let fallbackSourceUsed = null;
  if (!result.ok && !useOsv && /^CVE-/i.test(id) && /HTTP 404/.test(result.error || "")) {
    const fallback = await osvMod.fetchAdvisoryById(id, { airGap });
    if (fallback.ok) {
      result = fallback;
      fallbackSourceUsed = "osv";
    } else if (/HTTP 404/.test(fallback.error || "") || /not in fixture/.test(fallback.error || "")) {
      // Both sources tried, both 404 — combine the error message.
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
  // If the OSV fallback fired, normalize/route through the OSV module from
  // here on — the advisory shape is OSV's, not GHSA's.
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
    // Print the draft to stdout — operator pipes to jq / inspects /
    // commits manually. Exit 3 = "draft produced, not applied."
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

  // Apply: write to cve-catalog.json with the _auto_imported flag.
  // v0.12.8: honor --catalog / EXCEPTD_CVE_CATALOG so tests can redirect.
  // v0.12.12 C1: lock-gated RMW. Without this, two concurrent
  // `refresh --advisory CVE-A --apply` + `--advisory CVE-B --apply`
  // processes against the same catalog silently dropped one CVE 1-in-20
  // trials (read-old → mutate → write-overwrites-sibling-mutation).
  const catalogPath = resolveCatalogPath(opts);
  let humanCurated = null;
  await withCatalogLock(catalogPath, (catalog) => {
    if (catalog[cveId] && !catalog[cveId]._auto_imported && !catalog[cveId]._draft) {
      // Refuse to overwrite a human-curated entry — signal via closure so
      // we can emit the structured error after the lock releases.
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

// Known --flag base names refresh accepts (operator-facing surface + the
// bin-translated aliases). Drives the unknown-flag error message's known list.
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
    // v0.12.12 C3: exitCode + return so buffered stdout flushes naturally.
    process.exitCode = 0;
    return;
  }

  // Reject unknown flags BEFORE any network / catalog work. A swallowed typo
  // (e.g. `--aply`) previously fell through to a default all-sources live
  // refresh. Exit 2 matches refresh's own scheme (2 = error / unknown source).
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

  // `--prefetch` / `--no-network` are prefetch-cache operations. The operator
  // path (bin/exceptd.js) routes them to lib/prefetch.js; when this script is
  // invoked directly, delegate the SAME way so behavior matches the help text:
  // --prefetch populates the cache, --no-network is a report-only dry run that
  // writes nothing. Without this, the direct path fell through to the live
  // refresh loop and could egress + write refresh-report.json despite
  // --no-network.
  if (opts.prefetch || opts.noNetwork) {
    // Validate --source against the prefetchable (cache-backed) subset BEFORE
    // delegating to prefetch.js. prefetch.js only knows kev/nvd/epss/rfc/pins;
    // the refresh-only sources (ghsa, osv, advisories, cve-regression-watcher)
    // resolve advisories by live id lookup and have no cache layer. Without
    // this guard, `refresh --prefetch --source osv` reached prefetch.js and
    // died with `prefetch: fatal: unknown source "osv"` — leaking the internal
    // verb name (the operator typed `refresh`) and calling a source "unknown"
    // that the refresh help just listed as valid. Emit a refresh-prefixed,
    // actionable message instead and forward only the cacheable subset.
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

  // v0.12.0: `--advisory <id>` short-circuits the normal source loop and
  // seeds a single CVE catalog entry from GHSA. Exits non-zero ("draft
  // written, please review") so CI pipelines surface the needed editorial
  // step. Operator must run `--apply` for the write to land; without it,
  // the seed is printed to stdout for review.
  // An empty --advisory value (`--advisory ""` / `--advisory=`) must error
  // rather than silently falling through to a full-refresh dry-run.
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

  // Source fetches are independently I/O-bound. In normal mode we run them
  // sequentially so log output is interleaved cleanly. --swarm fans them
  // out via Promise.all() — each source already has its own per-source
  // queue with its own rate budget, so parallel sources don't compete
  // against each other for tokens. The two modes produce the same report
  // structure; only wall-clock differs.
  const runOne = async (src) => {
    // Audit 3 A.1: --air-gap was honored by GHSA/OSV at the source-module
    // level, but kev/epss/nvd/rfc/pins fell through to their live-network
    // branches when neither fixtures nor cacheDir was wired up. Refuse
    // here so the air-gap guarantee holds uniformly across every source.
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

  const outcomes = opts.swarm
    ? await Promise.all(sources.map(runOne))
    : await sequential(sources, runOne);

  // Cache-integrity refusals (sha256 mismatch, missing/partial _index.json,
  // unindexed payload) are thrown by readCachedJson with _exceptd_exit_code=4
  // but caught inside runOne and returned as a per-source error — so the
  // throw never reaches main().catch where the code is otherwise honored.
  // Carry the marker through here so main() can prefer exit 4 (BLOCKED /
  // precondition refusal) over the generic per-source-failure exit 1.
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
      // Audit 3 A.1: thread the central-dispatch air-gap short-circuit
      // marker through to the persisted report so stdout-parsing consumers
      // and the regression test can verify the network refusal happened.
      ...(diff.air_gap_blocked ? { air_gap_blocked: true } : {}),
    };
    if (opts.apply && diff.diffs.length > 0 && !src.report_only) {
      const r = await src.applyDiff(ctx, diff.diffs);
      report.sources[src.name].applied = r.updated;
      report.sources[src.name].apply_errors = r.errors;
      log(`    applied: ${r.updated} update(s)`);
      if (r.errors.length) log(`    apply errors: ${r.errors.join("; ")}`);
    }
  }

  // Persist report — tests can redirect via --report-out so concurrent
  // suites don't race on a shared refresh-report.json at the repo root.
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

  // v0.12.12 C3: same anti-pattern v0.12.9 fixed in prefetch's main(). After
  // Promise.all(sources.map(runOne)) in --swarm mode, process.exit() could
  // truncate buffered stdout (refresh-report path log line, summary log
  // lines piped to a consumer). exitCode + return lets the event loop end
  // naturally and stdout drains in full.
  // Prefer the documented BLOCKED (4) code when any source refused on a
  // cache-integrity precondition; fall back to generic failure (1) for other
  // per-source errors / downstream gate failures.
  process.exitCode = cacheIntegrityFailure ? 4 : (hadFailure ? 1 : 0);
}

async function sequential(items, fn) {
  const out = [];
  for (const it of items) out.push(await fn(it));
  return out;
}

if (require.main === module) {
  main().catch((err) => {
    // v0.11.14 (#129): hinted errors print the hint message + a structured
    // JSON line on stderr instead of a fatal stack trace.
    if (err && err._exceptd_hint) {
      console.error(err.message);
      console.error(JSON.stringify({ ok: false, error: err.message.split("\n")[0], hint: err.message.split("\n").slice(1).join(" ").trim(), verb: "refresh" }));
    } else if (err && err._exceptd_unknown_source) {
      // v0.12.12 C3: surface the source-validation error without leaking a
      // stack trace; chosenSources throws this for unknown --source values.
      console.error(err.message);
    } else {
      console.error(`refresh-external: fatal: ${err && err.stack ? err.stack : err}`);
    }
    // v0.12.12 C3: exitCode + return rather than process.exit(2) — the
    // event loop has no further work after main()'s rejection, so this
    // ends the process with code 2 but lets stderr drain first.
    // Cache-integrity / cache-stale / from-fixture-disabled refusals carry
    // an explicit exit code (4) via _exceptd_exit_code; honor that so
    // downstream automation can distinguish "blocked by precondition"
    // (exit 4) from "fatal/unhandled" (exit 2).
    process.exitCode = (err && Number.isInteger(err._exceptd_exit_code)) ? err._exceptd_exit_code : 2;
  });
}

module.exports = { ALL_SOURCES, loadCtx, parseArgs, seedSingleAdvisory, withCatalogLock, writeJsonAtomic, nvdDiffFromCache, kevDiffFromCache };
