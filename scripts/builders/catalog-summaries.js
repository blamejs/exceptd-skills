"use strict";
/**
 * scripts/builders/catalog-summaries.js
 *
 * Builds `data/_indexes/catalog-summaries.json` — for each data/<catalog>.json
 * file, a compact summary: purpose, entry count, version pin (where applicable),
 * source confidence, TLP, last-updated date. Consumers can load this single
 * file (~3-4 KB) instead of every _meta block to learn what catalogs are
 * available and how fresh they are.
 *
 * Curated human-readable purpose strings: keep these in lockstep with the
 * canonical catalog README in `docs/data-catalogs.md` if/when added.
 */

const fs = require("fs");
const path = require("path");

const CATALOG_PURPOSES = {
  "cve-catalog.json": "Per-CVE record (CVSS, EPSS, CISA KEV, RWEP, AI-discovery, vendor advisories, framework gaps, ATLAS/ATT&CK mappings). Cross-validated against NVD + CISA KEV + FIRST EPSS via validate-cves.",
  "cwe-catalog.json": "MITRE CWE entries used by the project (subset with skill citations), with severity hint and category. Pinned to a CWE catalog version.",
  "atlas-ttps.json": "MITRE ATLAS TTPs (AML.T0xxx) cited by skills, with tactic, name, description. Pinned to ATLAS v5.4.0 (February 2026).",
  "d3fend-catalog.json": "MITRE D3FEND countermeasures (D3-xxx) keyed by id, with tactic + name. Pinned to D3FEND v1.0.0 release.",
  "framework-control-gaps.json": "Per-control framework gap declarations: SI-2, A.8.8, PCI 6.3.3, etc. Each entry names the control, the lag, the evidence CVE, and remediation guidance.",
  "global-frameworks.json": "Multi-jurisdiction framework registry: 34 jurisdictions × applicable frameworks × patch_sla / notification_sla / critical_controls / framework_gaps. Cross-cutting authority for jurisdiction-clocks index.",
  "exploit-availability.json": "Per-CVE exploit availability: PoC public status, weaponization signal, AI-assist status, blast-radius. Project-curated (B2 Admiralty confidence) with source citations.",
  "zeroday-lessons.json": "Distilled lessons from notable zero-days and campaigns (SesameOp, Copy Fail, Dirty Frag, Copilot RCE, Windsurf MCP). Each entry: technique, distinguishing characteristic, what it means for the framework lag.",
  "rfc-references.json": "IETF RFCs + active Internet-Drafts cited by skills (TLS, IPsec, PQ crypto migration, HTTP/3, CT). Cross-validated against IETF Datatracker via validate-rfcs.",
  "dlp-controls.json": "DLP control inventory: per-pattern definitions for the dlp-gap-analysis skill, jurisdiction-tagged so a deployment can scope by applicable laws.",
};

function buildCatalogSummaries({ root, catalogFiles }) {
  const summaries = {};
  for (const rel of catalogFiles) {
    const base = path.basename(rel);
    const abs = path.join(root, rel);
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(abs, "utf8"));
    } catch (err) {
      summaries[base] = { error: `parse_error: ${err.message}` };
      continue;
    }
    const meta = parsed._meta || {};
    const entries = Object.keys(parsed).filter((k) => !k.startsWith("_"));
    summaries[base] = {
      path: rel,
      purpose: CATALOG_PURPOSES[base] || null,
      schema_version: meta.schema_version || null,
      last_updated: meta.last_updated || meta.last_verified || null,
      tlp: meta.tlp || null,
      source_confidence_default: meta.source_confidence?.default || null,
      freshness_policy: meta.freshness_policy || null,
      entry_count: entries.length,
      sample_keys: entries.slice(0, 5),
    };
  }
  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Per-catalog compact summary so AI consumers can discover available data without loading every _meta block. Purpose strings are curated in scripts/builders/catalog-summaries.js.",
      catalog_count: Object.keys(summaries).length,
    },
    catalogs: summaries,
  };
}

module.exports = { buildCatalogSummaries };
