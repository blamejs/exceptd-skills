"use strict";
/**
 * scripts/builders/cwe-chains.js
 *
 * Builds the CWE side of `data/_indexes/chains.json`. The existing chains
 * object is keyed by CVE-id; this builder produces CWE-id entries with the
 * same hydrated cross-walk shape so AI consumers can start from a CWE and
 * see every skill / catalog dimension that touches the weakness class.
 *
 * Per-CWE shape:
 *   {
 *     name:                CWE catalog entry name
 *     category:            CWE catalog category (memory-safety / injection / etc.)
 *     referencing_skills:  every skill listing this CWE in cwe_refs
 *     chain: {
 *       atlas, attack_refs, framework_gaps, d3fend, rfc_refs, dlp_refs
 *     }
 *     related_cves:        CVEs in cve-catalog.json whose framework gaps
 *                          surface via skills that also cite this CWE
 *   }
 *
 * The CWE → CVE link is indirect — CWEs aren't currently stamped on each
 * CVE entry directly. The skill bodies are the connective tissue. So we
 * compute it the same way the CVE chains builder does: skills cite CWEs,
 * skills cite framework_gaps, framework_gaps surface evidence_cves. The
 * intersection through the skill graph gives the related-CVE set.
 */

function buildCweChains({ skills, cweCatalog, atlasTtps, cveCatalog, frameworkGaps, d3fendCatalog, rfcCatalog }) {
  const cweIds = Object.keys(cweCatalog).filter((k) => !k.startsWith("_"));
  const out = {};

  for (const cweId of cweIds) {
    const cweEntry = cweCatalog[cweId] || {};

    const referencingSkills = skills
      .filter((s) => (s.cwe_refs || []).includes(cweId))
      .map((s) => s.name);

    // Aggregate cross-refs from those skills.
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

    // Hydrate the cross-walk dimensions for the AI consumer.
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
    };

    // Related CVEs: walk evidence_cves on the framework_gaps that the
    // referencing skills cite. Inner join via the skill graph.
    const relatedCves = new Set();
    for (const gap of accum.framework_gaps) {
      for (const ev of (frameworkGaps[gap]?.evidence_cves || [])) {
        if (cveCatalog[ev]) relatedCves.add(ev);
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
