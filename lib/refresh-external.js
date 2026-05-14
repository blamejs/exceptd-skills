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
  }
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
  --prefetch         (alias: --no-network) populate the cache for offline use.
                     Equivalent to \`exceptd prefetch\`.
  --from-cache [<p>] read from prefetch cache (default .cache/upstream).
                     Combine with --apply to upsert against cached data
                     entirely offline. Cache must be pre-populated via --prefetch.
  --source kev,epss  scope to a comma-separated list (kev|epss|nvd|rfc|pins|ghsa|osv)
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
        draft. Bulk import via package watchlist is a v0.13 follow-up.

Air-gap workflow:
  1. On a connected host:   \`exceptd refresh --prefetch\`
  2. Copy .cache/upstream/ across the boundary
  3. On the offline host:   \`exceptd refresh --from-cache --apply\`

Outputs:
  refresh-report.json (gitignored) — per-source status + every diff

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
        catalog[d.id][d.field] = d.after;
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
          diffs.push({ id: r.cve_id, field: d.field, before: d.local, after: d.fetched, severity: d.severity });
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
      // Cache parity: ghsa cache layout is .cache/upstream/ghsa/<published-date>.json
      // For v0.12.0 we fall through to live fetch — caching is a v0.13 follow-up.
    }
    const ghsa = require("./source-ghsa");
    return ghsa.buildDiff(ctx);
  },
  async applyDiff(ctx, diffs) {
    const ghsa = require("./source-ghsa");
    let updated = 0;
    const errors = [];
    for (const d of diffs) {
      if (d.field !== "_new_entry") continue;
      if (!d.after || !d.id) continue;
      if (ctx.cveCatalog[d.id]) continue; // never overwrite existing entries
      try {
        ctx.cveCatalog[d.id] = d.after;
        updated++;
      } catch (e) {
        errors.push(`${d.id}: ${e.message}`);
      }
    }
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
    const osv = require("./source-osv");
    return osv.buildDiff(ctx);
  },
  async applyDiff(ctx, diffs) {
    // Same shape as GHSA applyDiff — skip overwrites, surface conflicts.
    let updated = 0;
    const errors = [];
    for (const d of diffs) {
      if (d.field !== "_new_entry") continue;
      if (!d.after || !d.id) continue;
      if (ctx.cveCatalog[d.id]) continue; // never overwrite existing entries
      try {
        ctx.cveCatalog[d.id] = d.after;
        updated++;
      } catch (e) {
        errors.push(`${d.id}: ${e.message}`);
      }
    }
    return { updated, errors };
  },
};

const ALL_SOURCES = {
  kev: KEV_SOURCE,
  epss: EPSS_SOURCE,
  nvd: NVD_SOURCE,
  rfc: RFC_SOURCE,
  pins: PINS_SOURCE,
  ghsa: GHSA_SOURCE,
  osv: OSV_SOURCE,
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

function readCachedJson(cacheDir, source, id) {
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(cacheDir, source, `${safe}.json`);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return null; }
}

function kevDiffFromCache(ctx) {
  const feed = readCachedJson(ctx.cacheDir, "kev", "known_exploited_vulnerabilities");
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
  const diffs = [];
  for (const [id, entry] of Object.entries(ctx.cveCatalog)) {
    if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) continue;
    const upstream = kevSet.has(id);
    if (typeof entry.cisa_kev === "boolean" && entry.cisa_kev !== upstream) {
      diffs.push({ id, field: "cisa_kev", before: entry.cisa_kev, after: upstream, severity: "high" });
    }
    const upDate = kevDates.get(id) || null;
    if (upDate && entry.cisa_kev_date && entry.cisa_kev_date !== upDate) {
      diffs.push({ id, field: "cisa_kev_date", before: entry.cisa_kev_date, after: upDate, severity: "low" });
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
    const payload = readCachedJson(ctx.cacheDir, "epss", id);
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
    const payload = readCachedJson(ctx.cacheDir, "nvd", id);
    if (!payload) { errors++; continue; }
    const vuln = payload.vulnerabilities?.[0]?.cve;
    if (!vuln) continue;
    const m = vuln.metrics || {};
    const ordered = [...(m.cvssMetricV31 || []), ...(m.cvssMetricV30 || []), ...(m.cvssMetricV2 || [])];
    const primary = ordered.find((x) => x.type === "Primary") || ordered[0];
    const upScore = typeof primary?.cvssData?.baseScore === "number" ? primary.cvssData.baseScore : null;
    const upVector = primary?.cvssData?.vectorString || null;
    const local = ctx.cveCatalog[id];
    if (upScore != null && local.cvss_score != null && Math.abs(upScore - local.cvss_score) > 0.05) {
      diffs.push({ id, field: "cvss_score", before: local.cvss_score, after: upScore, severity: "high" });
    }
    if (upVector && local.cvss_vector && upVector !== local.cvss_vector) {
      diffs.push({ id, field: "cvss_vector", before: local.cvss_vector, after: upVector, severity: "medium" });
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
    const payload = readCachedJson(ctx.cacheDir, "rfc", docName);
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
    const payload = readCachedJson(ctx.cacheDir, "pins", file);
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
  };
  if (opts.fromFixture) {
    ctx.fixtures = { dir: path.resolve(opts.fromFixture), kev: true, epss: true, nvd: true, rfc: true, pins: true, ghsa: true, osv: true };
  } else if (opts.fromCache) {
    const abs = path.resolve(opts.fromCache);
    ctx.cacheDir = abs;
    if (!fs.existsSync(abs)) {
      // v0.11.14 (#129): operators following the website's air-gap workflow
      // hit this with an unhelpful "path does not exist" stack trace. The
      // cache is populated by `exceptd refresh --no-network` (which routes
      // to prefetch). Tell them exactly that, and emit a structured JSON
      // error to stderr instead of a fatal stack trace.
      const err = new Error(
        `refresh: --from-cache path does not exist: ${abs}\n` +
        `Hint: the cache is populated by running \`exceptd refresh --no-network\` (or \`exceptd refresh --prefetch\`) ` +
        `on a connected host first. Air-gap workflow: (1) on connected host: \`exceptd refresh --no-network\`, ` +
        `(2) copy .cache/upstream/ across the boundary, (3) on offline host: \`exceptd refresh --from-cache --apply\`.`
      );
      err._exceptd_hint = true;
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
  fs.writeFileSync(tmpPath, JSON.stringify(obj, null, 2) + "\n", "utf8");
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
  if (!opts.source) return Object.values(ALL_SOURCES);
  const names = opts.source.split(",").map((s) => s.trim()).filter(Boolean);
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

  let result = await sourceMod.fetchAdvisoryById(id, {});
  // F4 (v0.12.11): CVE-* identifiers may have an OSV record before GHSA
  // publishes one (CNAs and OSV mirrors operate on different cadences).
  // When GHSA returns 404 specifically, retry through OSV's /v1/vulns/{id}
  // — OSV indexes CVE ids as primary keys. If both 404, surface a combined
  // error message so operators know both sources were tried before failing.
  let fallbackSourceUsed = null;
  if (!result.ok && !useOsv && /^CVE-/i.test(id) && /HTTP 404/.test(result.error || "")) {
    const fallback = await osvMod.fetchAdvisoryById(id, {});
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

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    printHelp();
    // v0.12.12 C3: exitCode + return so buffered stdout flushes naturally.
    process.exitCode = 0;
    return;
  }

  // v0.12.0: `--advisory <id>` short-circuits the normal source loop and
  // seeds a single CVE catalog entry from GHSA. Exits non-zero ("draft
  // written, please review") so CI pipelines surface the needed editorial
  // step. Operator must run `--apply` for the write to land; without it,
  // the seed is printed to stdout for review.
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

  for (const { src, diff, error } of outcomes) {
    if (error) {
      log(`\n  [${src.name}] ${src.description}`);
      log(`    error: ${error.message}`);
      report.sources[src.name] = { status: "error", error: error.message };
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
  process.exitCode = hadFailure ? 1 : 0;
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
    process.exitCode = 2;
  });
}

module.exports = { ALL_SOURCES, loadCtx, parseArgs, seedSingleAdvisory };
