"use strict";
/**
 * scripts/builders/frequency.js
 *
 * Builds `data/_indexes/frequency.json` — citation-count tables. For each
 * catalog (CWE, ATLAS, ATT&CK, D3FEND, framework gaps, RFC, DLP), counts
 * how many skills cite each entry. Surfaces which entries are load-bearing
 * (cited by many) vs. orphan-adjacent (cited by ≤1).
 *
 * Per-field shape:
 *   {
 *     <entry_id>: { count, skills: [name, ...] }
 *   }
 *
 * Plus rollups:
 *   - top_cited: top 10 entries per field
 *   - orphan_adjacent: entries cited by exactly one skill
 *   - uncited: catalog entries with zero skill citations (flagged for review)
 */

function buildFrequency({ skills, catalogs }) {
  const fields = ["cwe_refs", "d3fend_refs", "framework_gaps", "atlas_refs", "attack_refs", "rfc_refs", "dlp_refs"];
  const counts = {};
  for (const f of fields) counts[f] = {};

  for (const s of skills) {
    for (const f of fields) {
      for (const v of s[f] || []) {
        if (!counts[f][v]) counts[f][v] = { count: 0, skills: [] };
        counts[f][v].count++;
        counts[f][v].skills.push(s.name);
      }
    }
  }
  for (const f of fields) {
    for (const k of Object.keys(counts[f])) counts[f][k].skills.sort();
  }

  function topN(field, n = 10) {
    return Object.entries(counts[field])
      .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
      .slice(0, n)
      .map(([id, info]) => ({ id, count: info.count, skills: info.skills }));
  }

  const orphanAdjacent = {};
  for (const f of fields) {
    orphanAdjacent[f] = Object.entries(counts[f])
      .filter(([, info]) => info.count === 1)
      .map(([id]) => id)
      .sort();
  }

  // Uncited: catalog has an entry but zero skill cites it.
  const uncited = {};
  const catalogFieldMap = {
    cwe_refs: catalogs.cwe,
    atlas_refs: catalogs.atlas,
    d3fend_refs: catalogs.d3fend,
    framework_gaps: catalogs.frameworkGaps,
    rfc_refs: catalogs.rfc,
    dlp_refs: catalogs.dlp,
  };
  for (const [field, cat] of Object.entries(catalogFieldMap)) {
    if (!cat) continue;
    const inCatalog = Object.keys(cat).filter((k) => !k.startsWith("_"));
    uncited[field] = inCatalog.filter((id) => !counts[field][id]).sort();
  }

  // attack_refs has no catalog file (uses MITRE upstream directly), so no
  // uncited table for it — only counts.

  const topCited = {};
  for (const f of fields) topCited[f] = topN(f);

  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Citation-count tables per catalog field. top_cited surfaces load-bearing entries; orphan_adjacent identifies entries cited by exactly one skill; uncited identifies catalog entries with zero skill references (review whether they should be culled or whether a skill should pick them up).",
      fields_indexed: fields,
    },
    counts,
    top_cited: topCited,
    orphan_adjacent: orphanAdjacent,
    uncited,
  };
}

module.exports = { buildFrequency };
