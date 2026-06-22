'use strict';

/**
 * TTP Mapper — maps compliance framework control IDs to ATLAS/ATT&CK TTPs
 * and surfaces gaps where controls fail to cover attacker techniques.
 */

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

function map(controlId, gapCatalog) {
  // hasOwnProperty guard: a bare gapCatalog[controlId] dereferences inherited
  // Object.prototype members, so controlId='__proto__' / 'toString' /
  // 'constructor' returned found:true for a key that is not a real catalog
  // entry. Only own enumerable keys are catalog controls.
  if (!gapCatalog || !hasOwn(gapCatalog, controlId)) {
    return { control_id: controlId, found: false, message: 'Control not in gap catalog' };
  }
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
  // Input guard before any deref — an empty / non-string frameworkId
  // yielded frameworkPrefix='' which matched EVERY control via
  // includes(''), and null/undefined threw on .split(). Match the
  // { found:false } contract already used for an unknown TTP. Surface
  // partially_covered_by / not_covered_by as an explicit null (not absent)
  // so the no-match outcome is observable rather than a silent universal
  // match.
  if (typeof frameworkId !== 'string' || frameworkId.trim() === '') {
    return { ttp_id: ttpId, found: false, error: 'frameworkId required', partially_covered_by: null, not_covered_by: null };
  }

  // hasOwnProperty guard: ttpId='__proto__' / 'toString' / 'constructor'
  // would otherwise resolve to an inherited Object.prototype member and be
  // treated as a real ATLAS technique. Only own keys are catalog techniques.
  if (!atlasCatalog || !hasOwn(atlasCatalog, ttpId)) {
    return { ttp_id: ttpId, found: false };
  }
  const ttp = atlasCatalog[ttpId];
  if (!ttp) return { ttp_id: ttpId, found: false };

  // atlas-ttps.json uses controls_that_partially_help / controls_that_dont_help / framework_gap_detail
  const partialControls = ttp.controls_that_partially_help || [];
  const noHelpControls = ttp.controls_that_dont_help || [];
  const gapDetail = ttp.framework_gap_detail || '';
  const hasFrameworkGap = ttp.framework_gap === true;

  // Check if the requested framework has any coverage in the partially-helpful
  // controls. Match on the first hyphen-delimited segment of the control id
  // (token-boundary), NOT bare substring containment: a bare includes() let
  // 'IS' match 'NIST' and '' match everything. A control id matches when it
  // begins with the prefix and the next char is a segment boundary (-, .) or
  // end-of-string, so 'soc2' still matches 'soc2-z' but 'is' never matches
  // 'nist-...'.
  const frameworkPrefix = frameworkId.split('-')[0].toLowerCase();
  if (frameworkPrefix.length === 0) {
    // frameworkId is a hyphen-led string (e.g. "-" or "-X") whose first
    // segment is empty — same universal-match hazard, same fail-closed result.
    return { ttp_id: ttpId, found: false, error: 'frameworkId required', partially_covered_by: null, not_covered_by: null };
  }
  const segMatch = (c) => {
    const cl = String(c).toLowerCase();
    if (!cl.startsWith(frameworkPrefix)) return false;
    const next = cl.charAt(frameworkPrefix.length);
    return next === '' || next === '-' || next === '.';
  };
  const partial = partialControls.find(segMatch);
  const noHelp = noHelpControls.find(segMatch);

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
