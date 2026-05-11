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

function parseArgs(argv) {
  const out = {
    apply: false,
    source: null,        // comma-separated list or null = all
    fromFixture: null,   // path to fixture dir
    help: false,
    quiet: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--apply") out.apply = true;
    else if (a === "--quiet") out.quiet = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--source") out.source = argv[++i];
    else if (a.startsWith("--source=")) out.source = a.slice("--source=".length);
    else if (a === "--from-fixture") out.fromFixture = argv[++i];
    else if (a.startsWith("--from-fixture=")) out.fromFixture = a.slice("--from-fixture=".length);
  }
  return out;
}

function printHelp() {
  console.log(`refresh-external — pull latest upstream data, optionally upsert into local catalogs.

Modes:
  (default)          dry-run all sources, write refresh-report.json
  --apply            apply diffs and rebuild indexes
  --source kev,epss  scope to a comma-separated list of source names (kev|epss|nvd|rfc|pins)
  --from-fixture <p> use frozen fixture payloads from <p> (offline; tests use this)

Outputs:
  refresh-report.json (gitignored) — summary of every diff + per-source status.

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

const KEV_SOURCE = {
  name: "kev",
  description: "CISA Known Exploited Vulnerabilities",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    const { validateAllCves } = require("../sources/validators");
    if (ctx.fixtures?.kev) {
      // Test harness path: skip the live network and just diff against the
      // frozen catalog state.
      return synthesizeFromFixture(ctx, "kev");
    }
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
    const errors = [];
    for (const d of diffs) {
      if (!ctx.cveCatalog[d.id]) {
        errors.push(`KEV: no local entry for ${d.id}`);
        continue;
      }
      ctx.cveCatalog[d.id][d.field] = d.after;
      ctx.cveCatalog[d.id].last_verified = TODAY;
      updated++;
    }
    ctx.cveCatalog._meta = ctx.cveCatalog._meta || {};
    ctx.cveCatalog._meta.last_updated = TODAY;
    writeJson(ABS("data/cve-catalog.json"), ctx.cveCatalog);
    return { updated, errors };
  },
};

const EPSS_SOURCE = {
  name: "epss",
  description: "FIRST.org EPSS scores",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.epss) return synthesizeFromFixture(ctx, "epss");
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
    for (const d of diffs) {
      if (!ctx.cveCatalog[d.id]) {
        errors.push(`EPSS: no local entry for ${d.id}`);
        continue;
      }
      ctx.cveCatalog[d.id][d.field] = d.after;
      ctx.cveCatalog[d.id].last_verified = TODAY;
      updated++;
    }
    ctx.cveCatalog._meta = ctx.cveCatalog._meta || {};
    ctx.cveCatalog._meta.last_updated = TODAY;
    writeJson(ABS("data/cve-catalog.json"), ctx.cveCatalog);
    return { updated, errors };
  },
};

const NVD_SOURCE = {
  name: "nvd",
  description: "NIST NVD 2.0 CVSS metrics",
  applies_to: "data/cve-catalog.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.nvd) return synthesizeFromFixture(ctx, "nvd");
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
    for (const d of diffs) {
      if (!ctx.cveCatalog[d.id]) {
        errors.push(`NVD: no local entry for ${d.id}`);
        continue;
      }
      ctx.cveCatalog[d.id][d.field] = d.after;
      ctx.cveCatalog[d.id].last_verified = TODAY;
      updated++;
    }
    ctx.cveCatalog._meta = ctx.cveCatalog._meta || {};
    ctx.cveCatalog._meta.last_updated = TODAY;
    writeJson(ABS("data/cve-catalog.json"), ctx.cveCatalog);
    return { updated, errors };
  },
};

const RFC_SOURCE = {
  name: "rfc",
  description: "IETF Datatracker RFC status",
  applies_to: "data/rfc-references.json",
  async fetchDiff(ctx) {
    if (ctx.fixtures?.rfc) return synthesizeFromFixture(ctx, "rfc");
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
    const errors = [];
    for (const d of diffs) {
      if (d.field !== "status") continue; // notes are informational
      const entry = ctx.rfcCatalog[d.id];
      if (!entry) {
        errors.push(`RFC: no local entry for ${d.id}`);
        continue;
      }
      entry.status = d.after;
      entry.last_verified = TODAY;
      updated++;
    }
    ctx.rfcCatalog._meta = ctx.rfcCatalog._meta || {};
    ctx.rfcCatalog._meta.last_updated = TODAY;
    writeJson(ABS("data/rfc-references.json"), ctx.rfcCatalog);
    return { updated, errors };
  },
};

const PINS_SOURCE = {
  name: "pins",
  description: "MITRE ATLAS / ATT&CK / D3FEND / CWE upstream release pins",
  applies_to: "manifest.json + data/cwe-catalog.json + data/d3fend-catalog.json",
  report_only: true,
  async fetchDiff(ctx) {
    if (ctx.fixtures?.pins) return synthesizeFromFixture(ctx, "pins");
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

const ALL_SOURCES = {
  kev: KEV_SOURCE,
  epss: EPSS_SOURCE,
  nvd: NVD_SOURCE,
  rfc: RFC_SOURCE,
  pins: PINS_SOURCE,
};

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
  const ctx = {
    manifest: JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8")),
    cveCatalog: JSON.parse(fs.readFileSync(ABS("data/cve-catalog.json"), "utf8")),
    rfcCatalog: JSON.parse(fs.readFileSync(ABS("data/rfc-references.json"), "utf8")),
    cweCatalog: JSON.parse(fs.readFileSync(ABS("data/cwe-catalog.json"), "utf8")),
    d3fendCatalog: JSON.parse(fs.readFileSync(ABS("data/d3fend-catalog.json"), "utf8")),
    fixtures: null,
  };
  if (opts.fromFixture) {
    ctx.fixtures = { dir: path.resolve(opts.fromFixture), kev: true, epss: true, nvd: true, rfc: true, pins: true };
  }
  return ctx;
}

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + "\n", "utf8");
}

function chosenSources(opts) {
  if (!opts.source) return Object.values(ALL_SOURCES);
  const names = opts.source.split(",").map((s) => s.trim()).filter(Boolean);
  const out = [];
  for (const n of names) {
    if (!ALL_SOURCES[n]) {
      console.error(`refresh-external: unknown source "${n}". Valid: ${Object.keys(ALL_SOURCES).join(", ")}`);
      process.exit(2);
    }
    out.push(ALL_SOURCES[n]);
  }
  return out;
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  const ctx = loadCtx(opts);
  const sources = chosenSources(opts);
  const log = (s) => opts.quiet || console.log(s);

  log(`\nrefresh-external — ${opts.apply ? "APPLY" : "dry-run"} mode`);
  log(`Sources: ${sources.map((s) => s.name).join(", ")}`);
  if (opts.fromFixture) log(`Fixture mode: ${opts.fromFixture}`);

  const report = {
    generated_at: new Date().toISOString(),
    mode: opts.apply ? "apply" : "dry-run",
    fixture_mode: !!opts.fromFixture,
    sources: {},
  };

  let hadFailure = false;

  for (const src of sources) {
    log(`\n  [${src.name}] ${src.description}`);
    let diff;
    try {
      diff = await src.fetchDiff(ctx);
    } catch (err) {
      log(`    error: ${err.message}`);
      report.sources[src.name] = { status: "error", error: err.message };
      hadFailure = true;
      continue;
    }
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

  // Persist report.
  const reportPath = ABS("refresh-report.json");
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

  process.exit(hadFailure ? 1 : 0);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`refresh-external: fatal: ${err && err.stack ? err.stack : err}`);
    process.exit(2);
  });
}

module.exports = { ALL_SOURCES, loadCtx, parseArgs };
