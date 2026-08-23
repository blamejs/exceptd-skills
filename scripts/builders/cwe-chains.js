"use strict";
/**
 * Builds the CWE-keyed half of `data/_indexes/chains.json`, in the same
 * hydrated cross-walk shape as the CVE-keyed half.
 *
 * The CWE → CVE link is indirect: CWE ids are not stamped on CVE entries, so
 * related_cves is computed through the skill graph — skills cite CWEs, skills
 * cite framework_gaps, framework_gaps surface evidence_cves.
 */

function buildCweChains({ skills, cweCatalog, atlasTtps, cveCatalog, frameworkGaps, d3fendCatalog, rfcCatalog }) {
  const cweIds = Object.keys(cweCatalog).filter((k) => !k.startsWith("_"));
  const out = {};

  for (const cweId of cweIds) {
    const cweEntry = cweCatalog[cweId] || {};

    const referencingSkills = skills
      .filter((s) => (s.cwe_refs || []).includes(cweId))
      .map((s) => s.name);

    const accum = {
      atlas_refs: new Set(),
      attack_refs: new Set(),
      framework_gaps: new Set(),
      d3fend_refs: new Set(),
      rfc_refs: new Set(),
      dlp_refs: new Set(),
    };
    for (const name of referencingSkills) {
      const s = skills.find((x) => x.name === name);
      if (!s) continue;
      for (const field of Object.keys(accum)) {
        for (const v of s[field] || []) accum[field].add(v);
      }
    }

    const hydrated = {
      atlas: [...accum.atlas_refs].sort().map((a) => ({
        id: a,
        name: atlasTtps[a]?.name,
        tactic: atlasTtps[a]?.tactic,
      })),
      attack_refs: [...accum.attack_refs].sort(),
      framework_gaps: [...accum.framework_gaps].sort().map((f) => ({
        id: f,
        framework: frameworkGaps[f]?.framework,
        control_name: frameworkGaps[f]?.control_name,
      })),
      d3fend: [...accum.d3fend_refs].sort().map((d) => ({
        id: d,
        name: d3fendCatalog[d]?.name,
        tactic: d3fendCatalog[d]?.tactic,
      })),
      rfc_refs: [...accum.rfc_refs].sort().map((r) => ({
        id: r,
        title: rfcCatalog[r]?.title,
        status: rfcCatalog[r]?.status,
      })),
      dlp_refs: [...accum.dlp_refs].sort(),
    };

    // Draft (_draft) CVEs are skipped so this half agrees with the CVE half
    // (build-indexes.js) and the reverse-ref index.
    const relatedCves = new Set();
    for (const gap of accum.framework_gaps) {
      for (const ev of (frameworkGaps[gap]?.evidence_cves || [])) {
        if (cveCatalog[ev] && cveCatalog[ev]._draft !== true) relatedCves.add(ev);
      }
    }

    out[cweId] = {
      name: cweEntry.name,
      category: cweEntry.category,
      severity_hint: cweEntry.severity_hint,
      referencing_skills: referencingSkills,
      skill_count: referencingSkills.length,
      chain: hydrated,
      related_cves: [...relatedCves].sort(),
    };
  }

  return out;
}

module.exports = { buildCweChains };
