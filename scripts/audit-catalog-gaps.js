#!/usr/bin/env node
"use strict";
/**
 * scripts/audit-catalog-gaps.js
 *
 * Walks every data/*.json catalog and surfaces three classes of gap:
 *
 *   1. missing-context     entries that exist but lack one of the
 *                          documented context-search fields (e.g. RFC
 *                          without abstract; ATT&CK technique without
 *                          platforms; CVE without iocs)
 *
 *   2. dangling-ref        forward references from one catalog into
 *                          another that do not resolve (e.g. CVE
 *                          entry's cwe_refs cites CWE-XXX but the
 *                          local cwe-catalog does not carry that ID)
 *
 *   3. draft-debt          per-catalog count of _auto_imported rows
 *                          relative to operator-curated rows. High
 *                          draft-debt = bulk-imported surface that has
 *                          not been refined yet.
 *
 * Output: structured JSON to stdout (default) or human-readable summary
 * with `--pretty`. Returns exit 0 in --warn-only mode (default); exit
 * 1 in --strict mode if any class triggers.
 *
 * Usage:
 *   node scripts/audit-catalog-gaps.js                    # JSON
 *   node scripts/audit-catalog-gaps.js --pretty           # human
 *   node scripts/audit-catalog-gaps.js --strict           # exit 1 on gap
 *   node scripts/audit-catalog-gaps.js --catalog cve      # one catalog
 *   node scripts/audit-catalog-gaps.js --class missing-context
 *
 * npm: `npm run audit-catalog-gaps`
 *
 * Design note: the gap analyzer is a separate detection plane from
 * lib/validate-cve-catalog.js (schema validation, predeploy gate) and
 * scripts/refresh-reverse-refs.js (forward/reverse-ref currency). The
 * validator polices what's strictly required by the schema; the gap
 * analyzer polices the recommended-but-not-required context envelope
 * that lets an AI consumer find an entry by topic instead of by ID.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DATA = path.join(ROOT, "data");
const TODAY = new Date().toISOString().slice(0, 10);

// Per-catalog required context fields. Each entry in the array is a
// field path (dot-separated for nested) and a non-emptiness predicate.
// Pillar / Class / Pillar-abstraction CWEs and similar can opt out via
// the suppression key on the entry (_gap_skip: { fields: [...] }).
const SPEC = {
  "cve-catalog": {
    file: "cve-catalog.json",
    idShape: /^(CVE-|MAL-|BUG-|GHSA-|SNYK-)/,
    required_context: [
      { field: "iocs", check: (v) => v && (
        (Array.isArray(v.payload_artifacts) && v.payload_artifacts.length) ||
        (Array.isArray(v.behavioral) && v.behavioral.length)
      ), label: "iocs.payload_artifacts or iocs.behavioral" },
      { field: "framework_control_gaps", check: (v) => v && Object.keys(v).length > 0, label: "framework_control_gaps" },
      { field: "attack_refs", check: (v) => Array.isArray(v) && v.length > 0, label: "attack_refs" },
      { field: "cwe_refs", check: (v) => Array.isArray(v) && v.length > 0, label: "cwe_refs" },
      { field: "verification_sources", check: (v) => Array.isArray(v) && v.length > 0, label: "verification_sources" }
    ],
    refs: [
      { field: "cwe_refs", target: "cwe-catalog.json", item: true },
      { field: "attack_refs", target: "attack-techniques.json", item: true },
      { field: "atlas_refs", target: "atlas-ttps.json", item: true },
      { field: "framework_control_gaps", target: "framework-control-gaps.json", keys: true }
    ]
  },
  "cwe-catalog": {
    file: "cwe-catalog.json",
    idShape: /^CWE-\d+$/,
    required_context: [
      { field: "name", check: (v) => typeof v === "string" && v.length > 0, label: "name" },
      { field: "abstraction", check: (v) => typeof v === "string" && v.length > 0, label: "abstraction" },
      { field: "description", check: (v) => typeof v === "string" && v.length > 20, label: "description (>20 chars)" }
    ],
    refs: []
  },
  "attack-techniques": {
    file: "attack-techniques.json",
    idShape: /^T\d{4}(\.\d{3})?$/,
    required_context: [
      { field: "name", check: (v) => typeof v === "string" && v.length > 0, label: "name" },
      { field: "tactic", check: (v) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" && v.length > 0), label: "tactic" },
      { field: "description", check: (v) => typeof v === "string" && v.length > 0, label: "description (short)" },
      { field: "platforms", check: (v) => Array.isArray(v) && v.length > 0, label: "platforms" }
    ],
    refs: []
  },
  "atlas-ttps": {
    file: "atlas-ttps.json",
    idShape: /^AML\.T\d{4}(\.\d{3})?$/,
    required_context: [
      { field: "name", check: (v) => typeof v === "string" && v.length > 0, label: "name" },
      { field: "tactic", check: (v) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" && v.length > 0), label: "tactic" },
      { field: "description", check: (v) => typeof v === "string" && v.length > 0, label: "description" }
    ],
    refs: []
  },
  "d3fend-catalog": {
    file: "d3fend-catalog.json",
    idShape: /^D3-/,
    required_context: [
      { field: "name", check: (v) => typeof v === "string" && v.length > 0, label: "name" },
      { field: "tactic", check: (v) => typeof v === "string" && v.length > 0, label: "tactic" },
      { field: "description", check: (v) => typeof v === "string" && v.length > 0, label: "description" }
    ],
    refs: []
  },
  "rfc-references": {
    file: "rfc-references.json",
    idShape: /^(RFC-\d+|DRAFT-|ISO-|CSAF-)/,
    required_context: [
      { field: "title", check: (v) => typeof v === "string" && v.length > 0, label: "title" },
      { field: "status", check: (v) => typeof v === "string" && v.length > 0, label: "status" },
      { field: "abstract", check: (v) => typeof v === "string" && v.length > 20, label: "abstract (>20 chars)" }
    ],
    refs: []
  },
  "framework-control-gaps": {
    file: "framework-control-gaps.json",
    idShape: /^[A-Z]/,
    required_context: [
      { field: "framework", check: (v) => typeof v === "string" && v.length > 0, label: "framework" },
      { field: "control_id", check: (v) => typeof v === "string" && v.length > 0, label: "control_id" },
      { field: "control_name", check: (v) => typeof v === "string" && v.length > 0, label: "control_name" },
      { field: "real_requirement", check: (v) => typeof v === "string" && v.length > 20, label: "real_requirement (>20 chars)" },
      { field: "theater_test", check: (v) => v && typeof v.claim === "string" && typeof v.test === "string", label: "theater_test{claim,test}" },
      // evidence_cves is required UNLESS the entry declares forward_looking:true.
      // v0.13.19 used per-entry _gap_skip annotations on 84 framework gaps;
      // v0.13.20 replaces that with a first-class schema field operators can
      // see in the JSON. The check honors forward_looking via the entry
      // parameter — see the SCHEMA_FORWARD_LOOKING block in inspect().
      { field: "evidence_cves", check: (v, entry) => (entry && entry.forward_looking === true) || (Array.isArray(v) && v.length > 0), label: "evidence_cves (or forward_looking:true)" }
    ],
    refs: []
  },
  "zeroday-lessons": {
    file: "zeroday-lessons.json",
    idShape: /^(CVE-|MAL-|BUG-)/,
    required_context: [
      { field: "attack_vector", check: (v) => v && typeof v.description === "string" && v.description.length > 20, label: "attack_vector.description" },
      { field: "framework_coverage", check: (v) => v && Object.keys(v).length > 0, label: "framework_coverage" },
      { field: "new_control_requirements", check: (v) => Array.isArray(v) && v.length > 0, label: "new_control_requirements" }
    ],
    refs: []
  }
};

function loadCatalog(name) {
  return JSON.parse(fs.readFileSync(path.join(DATA, name), "utf8"));
}

function inspect(catalogKey) {
  const spec = SPEC[catalogKey];
  if (!spec) throw new Error(`unknown catalog: ${catalogKey}`);
  const cat = loadCatalog(spec.file);
  const ids = Object.keys(cat).filter((k) => k !== "_meta");
  const report = {
    catalog: catalogKey,
    entries: ids.length,
    auto_imported: 0,
    operator_curated: 0,
    missing_context: [],
    dangling_refs: []
  };
  for (const id of ids) {
    if (!spec.idShape.test(id)) continue;
    const e = cat[id];
    if (!e) continue;
    if (e._auto_imported) report.auto_imported++;
    else report.operator_curated++;
    const skip = e._gap_skip && Array.isArray(e._gap_skip.fields) ? new Set(e._gap_skip.fields) : new Set();
    for (const r of spec.required_context) {
      if (skip.has(r.field)) continue;
      // Pass the entry as the second argument so per-field checks can
      // inspect class-level schema flags (forward_looking, etc.). The
      // legacy check-functions only consumed the value; new ones can
      // opt into entry-aware evaluation.
      if (!r.check(e[r.field], e)) {
        report.missing_context.push({ id, field: r.field, label: r.label });
      }
    }
  }
  return report;
}

function inspectRefs(allCatalogs) {
  const findings = [];
  const cveCat = allCatalogs["cve-catalog"];
  const cweCat = allCatalogs["cwe-catalog"];
  const attCat = allCatalogs["attack-techniques"];
  const atlCat = allCatalogs["atlas-ttps"];
  const fwCat = allCatalogs["framework-control-gaps"];
  // Build presence sets keyed by id (sans _meta).
  const cweSet = new Set(Object.keys(cweCat).filter((k) => k !== "_meta"));
  const attSet = new Set(Object.keys(attCat).filter((k) => k !== "_meta"));
  const atlSet = new Set(Object.keys(atlCat).filter((k) => k !== "_meta"));
  const fwSet = new Set(Object.keys(fwCat).filter((k) => k !== "_meta"));
  for (const id of Object.keys(cveCat)) {
    if (id === "_meta") continue;
    const e = cveCat[id];
    if (!e) continue;
    for (const ref of (e.cwe_refs || [])) {
      if (!cweSet.has(ref)) findings.push({ kind: "dangling-ref", source_catalog: "cve-catalog", source_id: id, target_catalog: "cwe-catalog", missing: ref });
    }
    for (const ref of (e.attack_refs || [])) {
      if (!attSet.has(ref)) findings.push({ kind: "dangling-ref", source_catalog: "cve-catalog", source_id: id, target_catalog: "attack-techniques", missing: ref });
    }
    for (const ref of (e.atlas_refs || [])) {
      if (!atlSet.has(ref)) findings.push({ kind: "dangling-ref", source_catalog: "cve-catalog", source_id: id, target_catalog: "atlas-ttps", missing: ref });
    }
    const fcg = e.framework_control_gaps || {};
    for (const key of Object.keys(fcg)) {
      if (!fwSet.has(key)) findings.push({ kind: "dangling-ref", source_catalog: "cve-catalog", source_id: id, target_catalog: "framework-control-gaps", missing: key });
    }
  }
  return findings;
}

function parseArgs(argv) {
  const out = { pretty: false, strict: false, catalog: null, klass: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--pretty") out.pretty = true;
    else if (a === "--strict") out.strict = true;
    else if (a === "--catalog") out.catalog = argv[++i];
    else if (a === "--class") out.klass = argv[++i];
  }
  return out;
}

function emitPretty(report) {
  const lines = [];
  lines.push("Catalog gap audit");
  lines.push("=================");
  for (const r of report.per_catalog) {
    lines.push(`\n[${r.catalog}]  entries=${r.entries}  auto-imported=${r.auto_imported}  operator-curated=${r.operator_curated}`);
    if (r.missing_context.length === 0) {
      lines.push("  ✓ context complete on every entry");
    } else {
      // Group by field for tidier output.
      const byField = new Map();
      for (const m of r.missing_context) {
        if (!byField.has(m.field)) byField.set(m.field, []);
        byField.get(m.field).push(m.id);
      }
      for (const [field, ids] of byField) {
        lines.push(`  missing ${field} on ${ids.length} entries: ${ids.slice(0, 5).join(", ")}${ids.length > 5 ? `  ... +${ids.length - 5}` : ""}`);
      }
    }
  }
  lines.push("\nCross-catalog dangling refs:");
  if (report.dangling_refs.length === 0) {
    lines.push("  ✓ every cross-ref resolves");
  } else {
    const byTarget = new Map();
    for (const f of report.dangling_refs) {
      const key = `${f.source_catalog}.${f.target_catalog}`;
      if (!byTarget.has(key)) byTarget.set(key, []);
      byTarget.get(key).push(`${f.source_id} → ${f.missing}`);
    }
    for (const [k, list] of byTarget) {
      lines.push(`  ${k}: ${list.length} dangling`);
      for (const l of list.slice(0, 5)) lines.push(`    ${l}`);
      if (list.length > 5) lines.push(`    ... +${list.length - 5}`);
    }
  }
  lines.push("\nDraft debt (auto-imported / total):");
  for (const r of report.per_catalog) {
    const pct = r.entries === 0 ? 0 : ((r.auto_imported / r.entries) * 100).toFixed(1);
    lines.push(`  ${r.catalog.padEnd(28)} ${r.auto_imported} / ${r.entries}  (${pct}%)`);
  }
  return lines.join("\n");
}

// Valid finding-class names for the `--class` filter. The pretty + JSON
// emitters always include every section, but counts and strict-exit
// gating respect the active filter.
const VALID_CLASSES = new Set(["missing-context", "dangling-ref", "draft-debt"]);

function main() {
  const opts = parseArgs(process.argv);
  if (opts.klass && !VALID_CLASSES.has(opts.klass)) {
    console.error(`unknown class: ${opts.klass}  valid: ${[...VALID_CLASSES].join(", ")}`);
    process.exitCode = 2;
    return;
  }
  const catalogKeys = opts.catalog ? [opts.catalog] : Object.keys(SPEC);
  const perCatalog = [];
  const allLoaded = {};
  for (const k of catalogKeys) {
    if (!SPEC[k]) {
      console.error(`unknown catalog: ${k}  valid: ${Object.keys(SPEC).join(", ")}`);
      process.exitCode = 2;
      return;
    }
    perCatalog.push(inspect(k));
    allLoaded[k] = loadCatalog(SPEC[k].file);
  }
  // Load all needed catalogs for cross-ref pass even when --catalog scoped.
  for (const k of Object.keys(SPEC)) if (!allLoaded[k]) allLoaded[k] = loadCatalog(SPEC[k].file);
  const dangling = opts.catalog && opts.catalog !== "cve-catalog" ? [] : inspectRefs(allLoaded);

  // Apply the --class filter before counts + strict-exit gating.
  // Missing-context findings on per_catalog and dangling_refs are the
  // two policed classes; draft-debt is informational-only (the audit
  // surfaces draft-debt but it does not fail strict mode by design).
  const filteredPerCatalog = opts.klass === "dangling-ref" || opts.klass === "draft-debt"
    ? perCatalog.map((r) => ({ ...r, missing_context: [] }))
    : perCatalog;
  const filteredDangling = opts.klass === "missing-context" || opts.klass === "draft-debt"
    ? []
    : dangling;

  const report = {
    generated_at: TODAY,
    class_filter: opts.klass || null,
    per_catalog: filteredPerCatalog,
    dangling_refs: filteredDangling,
    totals: {
      catalogs: filteredPerCatalog.length,
      entries: filteredPerCatalog.reduce((n, r) => n + r.entries, 0),
      missing_context: filteredPerCatalog.reduce((n, r) => n + r.missing_context.length, 0),
      dangling_refs: filteredDangling.length
    }
  };
  if (opts.pretty) {
    process.stdout.write(emitPretty(report) + "\n");
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  }
  if (opts.strict && (report.totals.missing_context > 0 || report.totals.dangling_refs > 0)) {
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { SPEC, inspect, inspectRefs };
