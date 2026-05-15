'use strict';

/**
 * RWEP — Real-World Exploit Priority scoring engine
 * Supplements CVSS with exploit availability, active exploitation, and operational constraints.
 *
 * ----------------------------------------------------------------------------
 * `rwep_factors` dual-semantics
 * ----------------------------------------------------------------------------
 * Catalog entries (data/cve-catalog.json) store `rwep_factors` as an object
 * whose values are POST-WEIGHT CONTRIBUTIONS for boolean / ladder factors
 * but the RAW BLAST RADIUS for `blast_radius`. The two shapes coexist because
 * each surface has different requirements:
 *
 *   cisa_kev:             0 OR +25         (post-weight contribution)
 *   poc_available:        0 OR +20         (post-weight contribution)
 *   ai_factor:            0 OR +15         (post-weight contribution)
 *   active_exploitation:  0 / 10 / 5 / 20  (post-weight contribution from ladder)
 *   blast_radius:         0..30 RAW        (intentionally NOT post-weight —
 *                                          mirrors the weight ceiling so it
 *                                          reads as raw blast magnitude)
 *   patch_available:      0 OR -15         (post-weight contribution)
 *   live_patch_available: 0 OR -10         (post-weight contribution)
 *   reboot_required:      0 OR +5          (post-weight contribution)
 *
 * Operator-facing implication: summing `Object.values(rwep_factors)` produces
 * the stored `rwep_score` for catalog entries because the blast weight is 30
 * (matches the raw cap). This dual-shape is intentional but easy to misuse;
 * direct boolean inputs should go through `scoreCustom()` instead.
 *
 * scoreCustom() input shape is DIFFERENT — it accepts BOOLEAN factors plus
 * a numeric blast_radius and a string active_exploitation ladder value.
 * `deriveRwepFromFactors()` is the shape-detecting bridge: if values look
 * numeric (post-weighted), it sums; if values look boolean / string-ladder,
 * it routes through scoreCustom.
 *
 * The semantic ambiguity is grandfathered. A clean rename (raw_factors vs
 * weighted_contributions) is a minor-bump change and is deferred.
 * ----------------------------------------------------------------------------
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

// active_exploitation ladder. Aligned with playbook-runner's
// _activeExploitationLadder so the catalog scorer and the runtime evaluator
// produce identical results for the same string value. 'unknown' contributes
// a quarter of the confirmed weight (5 points) — operationally "we have not
// confirmed, but absence of evidence is not evidence of absence; do not
// score zero on a fresh CVE that hasn't been triaged yet".
const ACTIVE_EXPLOITATION_LADDER = {
  confirmed: 1.0,
  suspected: 0.5,
  unknown:   0.25,
  none:      0,
};

// The canonical set of factor keys scoreCustom recognises. Used by
// validateFactors to flag unknown keys.
const RECOGNISED_FACTOR_KEYS = new Set([
  'cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
  'active_exploitation', 'blast_radius', 'patch_available',
  'live_patch_available', 'reboot_required',
  // accepted alias for the catalog field name
  'patch_required_reboot',
]);

function score(cveId, catalog) {
  const entry = catalog[cveId];
  if (!entry) throw new Error(`CVE not in catalog: ${cveId}`);
  return entry.rwep_score;
}

/**
 * Validate an RWEP factor bag. Returns an array of warning strings
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
  // NaN diagnostics. The prior message read "expected number,
  // got number (null)" because `JSON.stringify(NaN) === 'null'` and `typeof
  // NaN === 'number'`. Number.isFinite catches NaN + Infinity + -Infinity
  // and emits a useful message.
  if (factors.blast_radius === undefined || factors.blast_radius === null) {
    warnings.push('blast_radius: missing (treated as 0)');
  } else if (typeof factors.blast_radius !== 'number') {
    warnings.push(`blast_radius: expected number, got ${typeof factors.blast_radius} (${JSON.stringify(factors.blast_radius)})`);
  } else if (Number.isNaN(factors.blast_radius)) {
    warnings.push('blast_radius: NaN is not a valid numeric value (treated as 0)');
  } else if (!Number.isFinite(factors.blast_radius)) {
    warnings.push(`blast_radius: ${factors.blast_radius > 0 ? 'Infinity' : '-Infinity'} is not a finite numeric value (treated as 0)`);
  } else if (factors.blast_radius < 0 || factors.blast_radius > 30) {
    warnings.push(`blast_radius: ${factors.blast_radius} out of expected range [0, 30] (clamped to weight ceiling, but the value usually indicates a unit-of-measure mistake)`);
  }
  // surface unknown factor keys so a typo'd answer file
  // (`patch_avilable`, `cisa-kev`, etc.) doesn't silently default to false
  // with no diagnostic.
  for (const k of Object.keys(factors)) {
    if (!RECOGNISED_FACTOR_KEYS.has(k)) {
      warnings.push(`unknown factor: ${k} (ignored — not in the recognised key set)`);
    }
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
    // v0.12.15: the CVE catalog field is `patch_required_reboot`
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
  // active_exploitation goes through the ladder rather
  // than two hand-written branches with `Math.floor(weight/2)`. The floor
  // was a no-op for even weights (20/2 = 10) but would have silently
  // truncated to asymmetric results if a future operator bumped the
  // weight to 21. The ladder + multiplication preserves the contribution
  // exactly, including the new `unknown → 0.25 × weight = 5` mapping that
  // aligns the catalog scorer with playbook-runner._activeExploitationLadder.
  const aeMultiplier = ACTIVE_EXPLOITATION_LADDER[active_exploitation] ?? 0;
  score += RWEP_WEIGHTS.active_exploitation * aeMultiplier;
  // v0.12.15: blast_radius numeric coercion must reject
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

  // keep the pre-clamp value so collectWarnings consumers can
  // see deduction magnitude (e.g. a -25 raw score collapsed to 0 hides the
  // fact that the entry had three mitigating factors).
  const rawUnclamped = score;

  // v0.12.15: defense-in-depth clamp against any unforeseen
  // NaN production above (negative weight + Infinity + math edge case).
  const clamped = Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0;
  if (opts && opts.collectWarnings) {
    return {
      score: clamped,
      _rwep_raw_unclamped: Number.isFinite(rawUnclamped) ? rawUnclamped : null,
      _scoring_warnings: validateFactors(factors),
    };
  }
  return clamped;
}

/**
 * Derive an RWEP score from a
 * `rwep_factors` object regardless of which shape it uses.
 *
 *   - SHAPE A (boolean / string-ladder): values are booleans + an
 *     active_exploitation string + a numeric blast_radius. Route through
 *     scoreCustom() — the canonical formula.
 *   - SHAPE B (catalog post-weight): values are numeric contributions
 *     (0 / ±N) plus a numeric blast_radius. Sum the numeric values and
 *     clamp to [0, 100]. This is how catalog `rwep_factors` are stored.
 *
 * Heuristic: if every value is a number, treat as Shape B (sum). If any
 * value is boolean or a recognised ladder string, treat as Shape A
 * (scoreCustom). This lets the curation apply-path and the auto-discovery
 * builder share one canonical derivation that handles either operator
 * input style without duplicating the scoring formula.
 */
function deriveRwepFromFactors(factors) {
  if (!factors || typeof factors !== 'object') return 0;
  const values = Object.values(factors);
  if (values.length === 0) return 0;
  const aeAllowed = new Set(['none', 'unknown', 'suspected', 'confirmed']);
  const hasBooleanOrLadder = values.some(
    (v) => typeof v === 'boolean' || (typeof v === 'string' && aeAllowed.has(v)),
  );
  if (hasBooleanOrLadder) {
    return scoreCustom(factors);
  }
  // Shape B: catalog post-weight. Sum + clamp.
  let sum = 0;
  for (const v of values) {
    if (typeof v === 'number' && Number.isFinite(v)) sum += v;
  }
  return Math.max(0, Math.min(100, sum));
}

function timeline(rwepScore) {
  if (rwepScore >= 90) return { hours: 4, label: 'Immediate — live patch or isolate within 4 hours' };
  if (rwepScore >= 75) return { hours: 24, label: 'Urgent — patch or compensating controls within 24 hours' };
  if (rwepScore >= 60) return { hours: 72, label: 'High — patch within 72 hours' };
  if (rwepScore >= 40) return { hours: 168, label: 'Elevated — patch within 7 days' };
  if (rwepScore >= 20) return { hours: 720, label: 'Standard — patch within 30 days' };
  return { hours: null, label: 'Low — next scheduled maintenance' };
}

function compare(cveId, catalog, opts) {
  const entry = catalog[cveId];
  if (!entry) throw new Error(`CVE not in catalog: ${cveId}`);

  // `--recompute` ignores the stored rwep_score and forces a
  // fresh computation from rwep_factors. Useful for catching catalog drift
  // (stored score grew stale relative to current weights) and for auditing
  // the divergence between stored vs. formula-derived scores.
  const recompute = !!(opts && opts.recompute);
  let rwep;
  if (recompute) {
    const factors = entry.rwep_factors || {};
    // The catalog's rwep_factors shape is "post-weight" (Shape B). Route
    // through the shape-detecting helper so a catalog whose factors were
    // hand-edited in either shape still produces a usable score.
    rwep = deriveRwepFromFactors(factors);
  } else {
    rwep = entry.rwep_score;
  }
  const cvss = entry.cvss_score;
  const cvssEquivalent = cvss * 10;
  const delta = rwep - cvssEquivalent;

  // narrow the "broadly aligned" band from ±20 to ±10. The old
  // ±20 band swallowed the Copy Fail RWEP-vs-CVSS divergence (delta = 12)
  // where the operator-facing point is precisely that the CVSS-calibrated
  // SLA is insufficient. ±10 is the tightest classifier that still treats
  // ordinary CVSS rounding noise as alignment.
  let explanation = '';
  if (delta > 10) {
    explanation = `RWEP significantly higher than CVSS equivalent. Factors driving delta: `;
    const driving = [];
    if (entry.cisa_kev) driving.push('CISA KEV (+25)');
    if (entry.poc_available) driving.push('public PoC (+20)');
    if (entry.ai_discovered) driving.push('AI-discovered (+15 weaponization)');
    if (entry.active_exploitation === 'confirmed') driving.push('confirmed exploitation (+20)');
    if (entry.patch_required_reboot && !entry.live_patch_available) driving.push('reboot required (+5)');
    explanation += driving.join(', ');
    explanation += '. Framework patch SLAs calibrated to CVSS are insufficient for this CVE.';
  } else if (delta < -10) {
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

  const out = {
    cve_id: cveId,
    cvss: cvss,
    rwep: rwep,
    cvss_framework_sla: timeline(cvssEquivalent),
    rwep_actual_sla: timeline(rwep),
    delta,
    explanation,
  };
  if (recompute) {
    out.stored_rwep_score = entry.rwep_score;
    out.recomputed = true;
  }
  return out;
}

function validate(catalog) {
  const errors = [];
  for (const [cveId, entry] of Object.entries(catalog)) {
    if (cveId.startsWith('_')) continue;
    // Skip auto-imported drafts. KEV/GHSA/OSV-discovered drafts store a
    // conservative-default rwep_score (poc=true, reboot=true, etc.)
    // alongside `poc_available: null` and other null-until-curated factor
    // fields, so the recomputed-vs-stored divergence check would always
    // fire against them and flood the predeploy gate. Drafts are reviewed
    // separately via the `_auto_imported_meta.curation_needed` list and
    // the strict catalog validator's draft-warning tier. Once curation
    // promotes
    // an entry, `_auto_imported` is cleared and full validation resumes.
    if (entry && entry._auto_imported === true) continue;
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

/**
 * Strict CVSS 3.1 vector parse. Returns `{ ok, version, reason? }`.
 *
 * The CSAF 2.0 cvss_v3 score block requires a canonical CVSS 3.1 vector
 * string. Strict validators (BSI CSAF Validator, ENISA dashboard) reject
 * documents that emit a cvss_v3 block keyed off a malformed vector — the
 * pre-fix permissive `^CVSS:(\d+\.\d+)/` regex let through 3.0 vectors,
 * truncated metric sets, and unknown environmental-metric values, which
 * downstream tooling then rejected wholesale.
 *
 * Required metric set (in order): AV / AC / PR / UI / S / C / I / A.
 * Optional temporal metrics: E / RL / RC.
 * Optional environmental metrics: CR / IR / AR / MAV / MAC / MPR / MUI /
 *                                 MS / MC / MI / MA.
 */
// CVSS 3.0 and 3.1 share an identical vector grammar (metric set, value enums,
// and metric order are the same; only the `CVSS:X.Y/` prefix differs). CSAF
// 2.0 §3.2.4.3 accepts both versions in the cvss_v3 block. The strict regex
// matches either prefix; the parser records which version the vector declared
// so the emitter can stamp the right `version` field.
const CVSS_3X_RE = /^CVSS:3\.[01]\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH](\/E:[XUPFH])?(\/RL:[XOTWU])?(\/RC:[XURC])?(\/CR:[XLMH])?(\/IR:[XLMH])?(\/AR:[XLMH])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MPR:[XNLH])?(\/MUI:[XNR])?(\/MS:[XUC])?(\/MC:[XNLH])?(\/MI:[XNLH])?(\/MA:[XNLH])?$/;

function parseCvss31Vector(v) {
  if (typeof v !== 'string' || v.length === 0) {
    return { ok: false, version: null, reason: 'cvss_vector is not a non-empty string' };
  }
  const versionMatch = v.match(/^CVSS:(\d+\.\d+)\//);
  if (!versionMatch) {
    return { ok: false, version: null, reason: 'cvss_vector does not start with a CVSS:X.Y/ version prefix' };
  }
  const version = versionMatch[1];
  if (version !== '3.0' && version !== '3.1') {
    return { ok: false, version, reason: `cvss_vector declares version ${version}; CSAF 2.0 cvss_v3 accepts 3.0 and 3.1 only. Backfill a CVSS 3.x vector against this CVE in the catalog, or wait for CSAF 2.1 (cvss_v4 support).` };
  }
  if (!CVSS_3X_RE.test(v)) {
    return { ok: false, version, reason: 'cvss_vector does not match the strict CVSS 3.x grammar (missing/invalid mandatory metric, unknown metric value, or out-of-order metric)' };
  }
  return { ok: true, version };
}

module.exports = {
  score,
  scoreCustom,
  timeline,
  compare,
  validate,
  validateFactors,
  deriveRwepFromFactors,
  parseCvss31Vector,
  RWEP_WEIGHTS,
  ACTIVE_EXPLOITATION_LADDER,
  RECOGNISED_FACTOR_KEYS,
};
