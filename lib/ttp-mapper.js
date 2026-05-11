'use strict';

/**
 * TTP Mapper — maps compliance framework control IDs to ATLAS/ATT&CK TTPs
 * and surfaces gaps where controls fail to cover attacker techniques.
 */

function map(controlId, gapCatalog) {
  const entry = gapCatalog[controlId];
  if (!entry) return { control_id: controlId, found: false, message: 'Control not in gap catalog' };
  return {
    found: true,
    control_id: controlId,
    framework: entry.framework,
    control_name: entry.control_name,
    designed_for: entry.designed_for,
    misses: entry.misses,
    real_requirement: entry.real_requirement,
    status: entry.status,
    evidence_cves: entry.evidence_cves
  };
}

function gapsFor(attackPattern, gapCatalog, atlasCatalog) {
  const results = [];
  for (const [controlId, entry] of Object.entries(gapCatalog)) {
    if (controlId.startsWith('_')) continue;
    if (entry.misses && entry.misses.some(m => m.toLowerCase().includes(attackPattern.toLowerCase()))) {
      results.push({ control_id: controlId, framework: entry.framework, control_name: entry.control_name, gap: entry.misses });
    }
  }
  if (results.length === 0) {
    return { attack_pattern: attackPattern, found_gaps: false, message: 'No documented gaps for this pattern — verify manually' };
  }
  return { attack_pattern: attackPattern, found_gaps: true, controls_with_gap: results };
}

function coverage(frameworkId, ttpId, gapCatalog, atlasCatalog) {
  const ttp = atlasCatalog[ttpId];
  if (!ttp) return { ttp_id: ttpId, found: false };

  // atlas-ttps.json uses controls_that_partially_help / controls_that_dont_help / framework_gap_detail
  const partialControls = ttp.controls_that_partially_help || [];
  const noHelpControls = ttp.controls_that_dont_help || [];
  const gapDetail = ttp.framework_gap_detail || '';
  const hasFrameworkGap = ttp.framework_gap === true;

  // Check if the requested framework has any coverage in the partially-helpful controls
  const frameworkPrefix = frameworkId.split('-')[0].toLowerCase();
  const partial = partialControls.find(c => c.toLowerCase().includes(frameworkPrefix));
  const noHelp = noHelpControls.find(c => c.toLowerCase().includes(frameworkPrefix));

  return {
    ttp_id: ttpId,
    ttp_name: ttp.name,
    framework: frameworkId,
    has_gap: hasFrameworkGap,
    partially_covered_by: partial || null,
    not_covered_by: noHelp || null,
    gap_detail: gapDetail,
    detection: ttp.detection || null
  };
}

function universalGaps() {
  return [
    { gap: 'AI pipeline integrity', no_framework_coverage: true },
    { gap: 'MCP/agent tool trust boundaries', no_framework_coverage: true },
    { gap: 'LLM prompt injection as access control failure', no_framework_coverage: true },
    { gap: 'AI-as-C2 detection and response', no_framework_coverage: true },
    { gap: 'Live kernel patching as required capability', no_framework_coverage: true, closest: 'ASD ISM-1623 (48h)' },
    { gap: 'Ephemeral infrastructure asset inventory alternatives', no_framework_coverage: true },
    { gap: 'AI-accelerated exploit weaponization in patch SLAs', no_framework_coverage: true },
    { gap: 'RAG pipeline integrity and retrieval security', no_framework_coverage: true },
    { gap: 'AI-generated phishing detection update requirement', no_framework_coverage: true },
    { gap: 'Post-quantum cryptography migration mandate (non-NSS)', no_framework_coverage: true, closest: 'NSA CNSA 2.0 (NSS only)' }
  ];
}

module.exports = { map, gapsFor, coverage, universalGaps };
