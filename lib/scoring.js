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

function scoreCustom(factors) {
  const {
    cisa_kev = false,
    poc_available = false,
    ai_assisted_weapon = false,
    ai_discovered = false,
    active_exploitation = 'none',
    blast_radius = 0,
    patch_available = false,
    live_patch_available = false,
    reboot_required = false
  } = factors;

  let score = 0;
  score += cisa_kev ? RWEP_WEIGHTS.cisa_kev : 0;
  score += poc_available ? RWEP_WEIGHTS.poc_available : 0;
  score += (ai_assisted_weapon || ai_discovered) ? RWEP_WEIGHTS.ai_factor : 0;
  score += active_exploitation === 'confirmed' ? RWEP_WEIGHTS.active_exploitation : 0;
  score += active_exploitation === 'suspected' ? Math.floor(RWEP_WEIGHTS.active_exploitation / 2) : 0;
  score += Math.min(RWEP_WEIGHTS.blast_radius, blast_radius);
  score += patch_available ? RWEP_WEIGHTS.patch_available : 0;
  score += live_patch_available ? RWEP_WEIGHTS.live_patch_available : 0;
  score += reboot_required ? RWEP_WEIGHTS.reboot_required : 0;

  return Math.min(100, Math.max(0, score));
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

module.exports = { score, scoreCustom, timeline, compare, validate, RWEP_WEIGHTS };
