'use strict';

/**
 * RWEP — Real-World Exploit Priority scoring engine
 * Supplements CVSS with exploit availability, active exploitation, and operational constraints.
 */

const CVE_SCHEMA_REQUIRED = [
  'type', 'cvss_score', 'cvss_vector', 'cisa_kev', 'poc_available',
  'ai_discovered', 'active_exploitation', 'affected', 'patch_available',
  'patch_required_reboot', 'live_patch_available', 'live_patch_tools',
  'rwep_score', 'rwep_factors', 'atlas_refs', 'attack_refs',
  'source_verified', 'verification_sources', 'last_updated'
];

// blast_radius range is 0-30; represents breadth of affected population.
// AI-discovered and AI-assisted-weaponization both contribute the ai_factor (+15).
// reboot_required applies whenever patch requires reboot, regardless of live-patch availability,
// because live-patch is a temporary workaround — full remediation window is extended.
const RWEP_WEIGHTS = {
  cisa_kev:             25,
  poc_available:        20,
  ai_factor:            15,
  active_exploitation:  20,
  blast_radius:         30,
  patch_available:     -15,
  live_patch_available:-10,
  reboot_required:       5
};

function score(cveId, catalog) {
  const entry = catalog[cveId];
  if (!entry) throw new Error(`CVE not in catalog: ${cveId}`);
  return entry.rwep_score;
}

/**
 * E10: Validate an RWEP factor bag. Returns an array of warning strings
 * for missing-but-defaultable fields and out-of-range values. Does NOT
 * throw — operators wanting hard enforcement should treat a non-empty
 * return as a failure themselves.
 *
 * Range expectations:
 *   - cisa_kev, poc_available, ai_assisted_weapon, ai_discovered,
 *     patch_available, live_patch_available, reboot_required: boolean
 *     (or null, treated as false with a missing-field warning).
 *   - active_exploitation: 'none' | 'unknown' | 'suspected' | 'confirmed'.
 *   - blast_radius: integer in [0, 30] (clamped at the weight ceiling but
 *     flagged when out-of-range — out-of-range usually means a unit error).
 */
function validateFactors(factors) {
  const warnings = [];
  if (!factors || typeof factors !== 'object') {
    return ['factors: expected object, got ' + (factors === null ? 'null' : typeof factors)];
  }
  const boolFields = ['cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
                      'patch_available', 'live_patch_available', 'reboot_required'];
  for (const f of boolFields) {
    if (factors[f] === undefined || factors[f] === null) {
      warnings.push(`${f}: missing (treated as false; explicit value recommended)`);
    } else if (typeof factors[f] !== 'boolean') {
      warnings.push(`${f}: expected boolean, got ${typeof factors[f]} (${JSON.stringify(factors[f])})`);
    }
  }
  const aeAllowed = ['none', 'unknown', 'suspected', 'confirmed'];
  if (factors.active_exploitation === undefined || factors.active_exploitation === null) {
    warnings.push("active_exploitation: missing (treated as 'none')");
  } else if (!aeAllowed.includes(factors.active_exploitation)) {
    warnings.push(`active_exploitation: expected one of ${aeAllowed.join(', ')}, got ${JSON.stringify(factors.active_exploitation)}`);
  }
  if (factors.blast_radius === undefined || factors.blast_radius === null) {
    warnings.push('blast_radius: missing (treated as 0)');
  } else if (typeof factors.blast_radius !== 'number' || Number.isNaN(factors.blast_radius)) {
    warnings.push(`blast_radius: expected number, got ${typeof factors.blast_radius} (${JSON.stringify(factors.blast_radius)})`);
  } else if (factors.blast_radius < 0 || factors.blast_radius > 30) {
    warnings.push(`blast_radius: ${factors.blast_radius} out of expected range [0, 30] (clamped to weight ceiling, but the value usually indicates a unit-of-measure mistake)`);
  }
  return warnings;
}

/**
 * scoreCustom — compute the RWEP for a factor bag. Returns a number
 * (clamped to [0, 100]).
 *
 * Backward-compat note: this function has always returned a number;
 * callers in lib/auto-discovery.js etc. rely on that. E10 surfaces
 * warnings via the optional `opts.collectWarnings` flag — when true,
 * scoreCustom returns `{ score, _scoring_warnings }` instead of a bare
 * number. Operators wanting validation without the score can call
 * `validateFactors(factors)` directly.
 */
function scoreCustom(factors, opts) {
  const {
    cisa_kev = false,
    poc_available = false,
    ai_assisted_weapon = false,
    ai_discovered = false,
    active_exploitation = 'none',
    blast_radius = 0,
    patch_available = false,
    live_patch_available = false,
    reboot_required = false,
    // v0.12.15 (audit J F9): the CVE catalog field is `patch_required_reboot`
    // but scoreCustom historically expected `reboot_required`. validate()
    // already aliases at the call site; accept either spelling here so a
    // direct caller passing the catalog entry doesn't silently lose the
    // reboot factor.
    patch_required_reboot,
  } = factors || {};
  const rebootFactor = (reboot_required === true) || (patch_required_reboot === true);

  let score = 0;
  score += cisa_kev ? RWEP_WEIGHTS.cisa_kev : 0;
  score += poc_available ? RWEP_WEIGHTS.poc_available : 0;
  score += (ai_assisted_weapon || ai_discovered) ? RWEP_WEIGHTS.ai_factor : 0;
  score += active_exploitation === 'confirmed' ? RWEP_WEIGHTS.active_exploitation : 0;
  score += active_exploitation === 'suspected' ? Math.floor(RWEP_WEIGHTS.active_exploitation / 2) : 0;
  // v0.12.15 (audit J F1, F5): blast_radius numeric coercion must reject
  // NaN, Infinity, and strings explicitly. The prior `typeof === 'number'`
  // check passed NaN (which is `typeof === 'number'`) into `Math.min/max`
  // which propagates NaN through the final clamp, defeating the [0,100]
  // contract. Number.isFinite + Number() coercion catches all four classes:
  // NaN, Infinity, undefined, stringified-number.
  const brRaw = Number.isFinite(Number(blast_radius)) ? Number(blast_radius) : 0;
  const brClamped = Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, brRaw));
  score += brClamped;
  score += patch_available ? RWEP_WEIGHTS.patch_available : 0;
  score += live_patch_available ? RWEP_WEIGHTS.live_patch_available : 0;
  score += rebootFactor ? RWEP_WEIGHTS.reboot_required : 0;

  // v0.12.15 (audit J F1): defense-in-depth clamp against any unforeseen
  // NaN production above (negative weight + Infinity + math edge case).
  const clamped = Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0;
  if (opts && opts.collectWarnings) {
    return { score: clamped, _scoring_warnings: validateFactors(factors) };
  }
  return clamped;
}

function timeline(rwepScore) {
  if (rwepScore >= 90) return { hours: 4, label: 'Immediate — live patch or isolate within 4 hours' };
  if (rwepScore >= 75) return { hours: 24, label: 'Urgent — patch or compensating controls within 24 hours' };
  if (rwepScore >= 60) return { hours: 72, label: 'High — patch within 72 hours' };
  if (rwepScore >= 40) return { hours: 168, label: 'Elevated — patch within 7 days' };
  if (rwepScore >= 20) return { hours: 720, label: 'Standard — patch within 30 days' };
  return { hours: null, label: 'Low — next scheduled maintenance' };
}

function compare(cveId, catalog) {
  const entry = catalog[cveId];
  if (!entry) throw new Error(`CVE not in catalog: ${cveId}`);

  const rwep = entry.rwep_score;
  const cvss = entry.cvss_score;
  const cvssEquivalent = cvss * 10;
  const delta = rwep - cvssEquivalent;

  let explanation = '';
  if (delta > 20) {
    explanation = `RWEP significantly higher than CVSS equivalent. Factors driving delta: `;
    const driving = [];
    if (entry.cisa_kev) driving.push('CISA KEV (+25)');
    if (entry.poc_available) driving.push('public PoC (+20)');
    if (entry.ai_discovered) driving.push('AI-discovered (+15 weaponization)');
    if (entry.active_exploitation === 'confirmed') driving.push('confirmed exploitation (+20)');
    if (entry.patch_required_reboot && !entry.live_patch_available) driving.push('reboot required (+5)');
    explanation += driving.join(', ');
    explanation += '. Framework patch SLAs calibrated to CVSS are insufficient for this CVE.';
  } else if (delta < -20) {
    explanation = `RWEP lower than CVSS equivalent. Mitigating factors: `;
    const mitigating = [];
    if (entry.patch_available) mitigating.push('patch available (-15)');
    if (entry.live_patch_available) mitigating.push('live patch available (-10)');
    if (!entry.poc_available) mitigating.push('no public PoC');
    if (!entry.cisa_kev) mitigating.push('not CISA KEV');
    explanation += mitigating.join(', ');
  } else {
    explanation = 'CVSS and RWEP are broadly aligned for this CVE.';
  }

  return {
    cve_id: cveId,
    cvss: cvss,
    rwep: rwep,
    cvss_framework_sla: timeline(cvssEquivalent),
    rwep_actual_sla: timeline(rwep),
    delta,
    explanation
  };
}

function validate(catalog) {
  const errors = [];
  for (const [cveId, entry] of Object.entries(catalog)) {
    if (cveId.startsWith('_')) continue;
    for (const field of CVE_SCHEMA_REQUIRED) {
      if (!(field in entry)) {
        errors.push(`${cveId}: missing required field '${field}'`);
      }
    }
    if (entry.poc_available && (!entry.poc_description || entry.poc_description.trim() === '')) {
      errors.push(`${cveId}: poc_available=true but poc_description is empty`);
    }
    if (entry.live_patch_available && (!entry.live_patch_tools || entry.live_patch_tools.length === 0)) {
      errors.push(`${cveId}: live_patch_available=true but live_patch_tools is empty`);
    }
    const calculatedRwep = scoreCustom({
      cisa_kev: entry.cisa_kev,
      poc_available: entry.poc_available,
      ai_assisted_weapon: entry.ai_assisted_weaponization || false,
      ai_discovered: entry.ai_discovered || false,
      active_exploitation: entry.active_exploitation,
      blast_radius: entry.rwep_factors ? entry.rwep_factors.blast_radius : 0,
      patch_available: entry.patch_available,
      live_patch_available: entry.live_patch_available,
      reboot_required: entry.patch_required_reboot
    });
    if (Math.abs(calculatedRwep - entry.rwep_score) > 5) {
      errors.push(`${cveId}: rwep_score ${entry.rwep_score} diverges from calculated ${calculatedRwep} by more than 5 — verify factors`);
    }
  }
  return errors;
}

module.exports = { score, scoreCustom, timeline, compare, validate, validateFactors, RWEP_WEIGHTS };
