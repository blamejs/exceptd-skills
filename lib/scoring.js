'use strict';

/**
 * RWEP — Real-World Exploit Priority scoring engine. Supplements CVSS with
 * exploit availability, active exploitation and operational constraints.
 *
 * `rwep_factors` carries two shapes at once. Every factor stores its POST-WEIGHT
 * contribution except `blast_radius`, which stores its RAW 0..30 magnitude —
 * summing the object still yields `rwep_score` only because the blast weight is
 * also 30. Do not feed booleans in here; `scoreCustom()` takes those, plus a
 * numeric blast_radius and a ladder string. `deriveRwepFromFactors()` detects
 * which shape it was given and routes accordingly.
 */

// Loaded from the schema so the two cannot drift. live_patch_tools is
// deliberately absent: it is schema-optional, and the
// live_patch_available => live_patch_tools implication is enforced below.
const CVE_SCHEMA_REQUIRED = require('./schemas/cve-catalog.schema.json').required;

// reboot_required applies even when a live patch exists, because a live patch
// is a workaround and the full remediation window stays open.
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

// Must stay aligned with playbook-runner's _activeExploitationLadder so the
// catalog scorer and the runtime evaluator agree on the same string. 'unknown'
// scores a quarter rather than zero: an untriaged CVE is not a clean one.
// 'theoretical' is mapped explicitly at 0 — a published PoC carries its weight
// through poc_available, and an incidental `?? 0` fall-through here would be
// indistinguishable from an unrecognised value.
const ACTIVE_EXPLOITATION_LADDER = {
  confirmed:   1.0,
  suspected:   0.5,
  unknown:     0.25,
  theoretical: 0,
  none:        0,
};

/**
 * Ladder multiplier for an active_exploitation value, as
 * { multiplier, recognised, normalised }.
 *
 * Case- and whitespace-normalised, so 'Confirmed' resolves rather than zeroing.
 * null and undefined are the documented 'none' default and count as recognised.
 * Anything else returns multiplier 0 AND emits a process warning: an
 * out-of-vocabulary string would otherwise drop 20 points silently, and the
 * no-match path has to be observable. validateFactors() carries the structured
 * diagnostic for callers that collect warnings.
 */
function resolveActiveExploitation(active_exploitation) {
  if (active_exploitation === undefined || active_exploitation === null) {
    return { multiplier: ACTIVE_EXPLOITATION_LADDER.none, recognised: true, normalised: 'none' };
  }
  if (typeof active_exploitation === 'string') {
    const norm = active_exploitation.trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(ACTIVE_EXPLOITATION_LADDER, norm)) {
      return { multiplier: ACTIVE_EXPLOITATION_LADDER[norm], recognised: true, normalised: norm };
    }
    return { multiplier: 0, recognised: false, normalised: norm };
  }
  return { multiplier: 0, recognised: false, normalised: null };
}

function activeExploitationMultiplier(active_exploitation) {
  const r = resolveActiveExploitation(active_exploitation);
  if (!r.recognised) {
    // Observable diagnostic for the bare-number call path (scoreCustom without
    // collectWarnings, which the production write-paths use). Routed through
    // process.emitWarning so it lands on the standard Node diagnostic channel
    // without changing the function's number return contract; deduped per
    // distinct offending value so a batch curation run doesn't flood stderr.
    const detail = active_exploitation === undefined || active_exploitation === null
      ? String(active_exploitation)
      : (typeof active_exploitation === 'string' ? JSON.stringify(active_exploitation) : `${typeof active_exploitation} ${JSON.stringify(active_exploitation)}`);
    process.emitWarning(
      `active_exploitation ${detail} is not in the recognised ladder (${Object.keys(ACTIVE_EXPLOITATION_LADDER).join(', ')}); contributing 0 active-exploitation weight`,
      { type: 'RwepActiveExploitationUnrecognised', code: 'RWEP_AE_UNRECOGNISED' },
    );
  }
  return r.multiplier;
}

// Boolean-input (Shape-A) keys scoreCustom recognises; validateFactors flags
// anything else. The last two are the catalog's own field names, accepted as
// aliases so a factor bag built straight from an entry validates.
const RECOGNISED_FACTOR_KEYS = new Set([
  'cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
  'active_exploitation', 'blast_radius', 'patch_available',
  'live_patch_available', 'reboot_required',
  'ai_assisted_weaponization',
  'patch_required_reboot',
]);

// Post-weight (Shape-B) keys deriveRwepFromFactors may sum. `ai_factor` has to
// be added back: it is the +15 weight every Shape-B entry stores, and it is
// absent from the Shape-A set above, so filtering on that set alone would drop
// it from every derivation. A key outside this set is excluded from the sum and
// surfaced, so a typo cannot quietly change a score.
const RECOGNISED_POST_WEIGHT_KEYS = new Set([...RECOGNISED_FACTOR_KEYS, 'ai_factor']);

function score(cveId, catalog) {
  const entry = catalog[cveId];
  if (!entry) throw new Error(`CVE not in catalog: ${cveId}`);
  return entry.rwep_score;
}

/**
 * Warnings for a factor bag: missing-but-defaultable fields and out-of-range
 * values. Never throws — a caller wanting enforcement treats a non-empty return
 * as a failure. Booleans may be null (false, with a warning);
 * active_exploitation must be a ladder value; blast_radius is an integer in
 * [0, 30], flagged out of range because that usually means a unit error.
 */
function validateFactors(factors) {
  const warnings = [];
  if (!factors || typeof factors !== 'object') {
    return ['factors: expected object, got ' + (factors === null ? 'null' : typeof factors)];
  }
  const boolFields = ['cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
                      'patch_available', 'live_patch_available', 'reboot_required'];
  for (const f of boolFields) {
    // Honours the same aliasing as scoreCustom, so a bag supplying only the
    // catalog field name is not flagged missing.
    const present = (f === 'ai_assisted_weapon')
      ? (factors.ai_assisted_weapon ?? factors.ai_assisted_weaponization)
      : (f === 'reboot_required')
        ? (factors.reboot_required ?? factors.patch_required_reboot)
        : factors[f];
    if (present === undefined || present === null) {
      warnings.push(`${f}: missing (treated as false; explicit value recommended)`);
    } else if (typeof present !== 'boolean') {
      warnings.push(`${f}: expected boolean, got ${typeof present} (${JSON.stringify(present)})`);
    }
  }
  const aeAllowed = ['none', 'unknown', 'suspected', 'theoretical', 'confirmed'];
  const aeRaw = factors.active_exploitation;
  if (aeRaw === undefined || aeRaw === null) {
    warnings.push("active_exploitation: missing (treated as 'none')");
  } else {
    // Normalised before the vocabulary check so this accepts exactly what the
    // scorer accepts; otherwise 'Confirmed' is flagged here and consumed there.
    const aeNorm = typeof aeRaw === 'string' ? aeRaw.trim().toLowerCase() : aeRaw;
    if (!aeAllowed.includes(aeNorm)) {
      warnings.push(`active_exploitation: expected one of ${aeAllowed.join(', ')}, got ${JSON.stringify(aeRaw)}`);
    }
  }
  // Number.isFinite rather than a typeof check: `typeof NaN === 'number'` and
  // `JSON.stringify(NaN) === 'null'`, which together produce the useless
  // "expected number, got number (null)".
  if (factors.blast_radius === undefined || factors.blast_radius === null) {
    warnings.push('blast_radius: missing (treated as 0)');
  } else if (typeof factors.blast_radius !== 'number') {
    // scoreCustom coerces a numeric string via Number(), so a finite one is
    // noted rather than rejected — the scorer will use it either way.
    if (typeof factors.blast_radius === 'string' && Number.isFinite(Number(factors.blast_radius)) && factors.blast_radius.trim() !== '') {
      warnings.push(`blast_radius: numeric string "${factors.blast_radius}" accepted (coerced to ${Number(factors.blast_radius)}); prefer a JSON number`);
    } else {
      warnings.push(`blast_radius: expected number, got ${typeof factors.blast_radius} (${JSON.stringify(factors.blast_radius)})`);
    }
  } else if (Number.isNaN(factors.blast_radius)) {
    warnings.push('blast_radius: NaN is not a valid numeric value (treated as 0)');
  } else if (!Number.isFinite(factors.blast_radius)) {
    warnings.push(`blast_radius: ${factors.blast_radius > 0 ? 'Infinity' : '-Infinity'} is not a finite numeric value (treated as 0)`);
  } else if (factors.blast_radius < 0 || factors.blast_radius > 30) {
    warnings.push(`blast_radius: ${factors.blast_radius} out of expected range [0, 30] (clamped to weight ceiling, but the value usually indicates a unit-of-measure mistake)`);
  }
  // An unknown key is surfaced rather than ignored: `patch_avilable` would
  // otherwise default to false with no diagnostic.
  for (const k of Object.keys(factors)) {
    if (!RECOGNISED_FACTOR_KEYS.has(k)) {
      warnings.push(`unknown factor: ${k} (ignored — not in the recognised key set)`);
    }
  }
  return warnings;
}

/**
 * RWEP for a factor bag, clamped to [0, 100].
 *
 * Returns a bare number, which callers depend on. With
 * `opts.collectWarnings` it returns `{ score, _scoring_warnings }` instead;
 * for validation without a score, call `validateFactors()` directly.
 */
function scoreCustom(factors, opts) {
  const {
    cisa_kev = false,
    poc_available = false,
    ai_assisted_weapon = false,
    // Catalog field name, accepted as an alias so an entry-derived bag still
    // counts the +15 AI factor.
    ai_assisted_weaponization = false,
    ai_discovered = false,
    active_exploitation = 'none',
    blast_radius = 0,
    patch_available = false,
    live_patch_available = false,
    reboot_required = false,
    // Likewise: the catalog spells this `patch_required_reboot`, so both
    // spellings are accepted and a direct caller cannot lose the factor.
    patch_required_reboot,
  } = factors || {};
  const rebootFactor = (reboot_required === true) || (patch_required_reboot === true);

  let score = 0;
  score += cisa_kev ? RWEP_WEIGHTS.cisa_kev : 0;
  score += poc_available ? RWEP_WEIGHTS.poc_available : 0;
  score += (ai_assisted_weapon || ai_assisted_weaponization || ai_discovered) ? RWEP_WEIGHTS.ai_factor : 0;
  // Multiplied through the ladder rather than branched: a weight bumped to an
  // odd number would truncate under a `Math.floor(weight/2)` split.
  const aeMultiplier = activeExploitationMultiplier(active_exploitation);
  score += RWEP_WEIGHTS.active_exploitation * aeMultiplier;
  // Accepts only a finite number or a trimmed non-empty numeric string, which
  // is validateFactors' contract exactly. Bare Number() would turn `true` into
  // 1 and `[7]` into 7 — values the validator rejects — so the scorer would add
  // a contribution the validator calls invalid. NaN also has
  // `typeof === 'number'` and propagates through the final clamp.
  let brRaw = 0;
  if (typeof blast_radius === 'number' && Number.isFinite(blast_radius)) {
    brRaw = blast_radius;
  } else if (
    typeof blast_radius === 'string' &&
    blast_radius.trim() !== '' &&
    Number.isFinite(Number(blast_radius))
  ) {
    brRaw = Number(blast_radius);
  }
  const brClamped = Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, brRaw));
  score += brClamped;
  score += patch_available ? RWEP_WEIGHTS.patch_available : 0;
  score += live_patch_available ? RWEP_WEIGHTS.live_patch_available : 0;
  score += rebootFactor ? RWEP_WEIGHTS.reboot_required : 0;

  // Kept pre-clamp so collectWarnings consumers can see deduction magnitude: a
  // raw -25 collapsed to 0 hides that three mitigating factors applied.
  const rawUnclamped = score;

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
 * RWEP from a `rwep_factors` object of either shape, so the curation
 * apply-path and the auto-discovery builder share one derivation.
 *
 * Shape A (booleans, a ladder string, a numeric blast_radius) routes through
 * scoreCustom. Shape B (post-weight contributions, how the catalog stores them)
 * is summed and clamped to [0, 100].
 */
function deriveRwepFromFactors(factors) {
  if (!factors || typeof factors !== 'object') return 0;
  const entries = Object.entries(factors);
  if (entries.length === 0) return 0;
  // A boolean, or a ladder string, is Shape-A evidence. The ladder string
  // legitimately appears in BOTH shapes — Shape B may carry it as a readable
  // status beside its integers — so hasPostWeightInt below is what
  // disambiguates, not excluding active_exploitation from this check. Excluding
  // it here under-scores a ladder-only bag, which falls through to the sum and
  // skips the string entirely.
  const aeAllowed = new Set(['none', 'unknown', 'suspected', 'theoretical', 'confirmed']);
  const hasBooleanOrLadder = entries.some(
    ([, v]) => (typeof v === 'boolean' || (typeof v === 'string' && aeAllowed.has(v.trim().toLowerCase()))),
  );
  // A boolean-named key carrying a post-weight integer (>=5) is unambiguously
  // Shape B, even alongside a ladder string.
  const hasPostWeightInt = entries.some(
    ([k, v]) => k !== 'blast_radius' && typeof v === 'number' && Number.isFinite(v) && Math.abs(v) >= 5,
  );
  if (hasBooleanOrLadder && !hasPostWeightInt) {
    return scoreCustom(factors);
  }
  // Shape B: sum and clamp. blast_radius is the one field needing a per-factor
  // clamp first — it is a raw 0..30 magnitude, not a post-weight contribution,
  // so a unit error like 300 would otherwise reach only the aggregate clamp and
  // make the two scorers disagree, which would show up as a false divergence in
  // validate()'s recompute-vs-stored gate.
  let sum = 0;
  for (const [k, v] of Object.entries(factors)) {
    if (typeof v !== 'number' || !Number.isFinite(v)) continue;
    // An unrecognised key is excluded AND surfaced, matching what scoreCustom
    // and validateFactors do, so the three scoring surfaces agree on what a
    // typo means. Summing it blindly let a sub-5 typo inflate the breakdown
    // with no diagnostic.
    if (!RECOGNISED_POST_WEIGHT_KEYS.has(k)) {
      process.emitWarning(
        `rwep_factors carries unrecognised key '${k}'; excluded from the derived sum`,
        { type: 'RwepFactorUnrecognised', code: 'RWEP_FACTOR_UNRECOGNISED' },
      );
      continue;
    }
    // Aliases for one contribution; a block carrying both must count it once or
    // the derived score exceeds both the formula and the stored value.
    if (k === 'patch_required_reboot' && Object.prototype.hasOwnProperty.call(factors, 'reboot_required')) continue;
    if (k === 'blast_radius') {
      sum += Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, v));
    } else {
      sum += v;
    }
  }
  return Math.max(0, Math.min(100, sum));
}

// Post-weight (Shape-B) factor object required by cve-catalog.schema.json.
// Canonical home for the math auto-discovery.js/cve-enrich.js both consume,
// so Σ Object.values(...) === scoreCustom(inputs) (pre-clamp) by construction.
function postWeightFactors(inputs) {
  const i = inputs || {};
  const aeMultiplier = activeExploitationMultiplier(i.active_exploitation);
  const reboot = (i.reboot_required === true) || (i.patch_required_reboot === true);
  let blastRaw = 0;
  if (typeof i.blast_radius === 'number' && Number.isFinite(i.blast_radius)) blastRaw = i.blast_radius;
  else if (typeof i.blast_radius === 'string' && i.blast_radius.trim() !== '' && Number.isFinite(Number(i.blast_radius))) blastRaw = Number(i.blast_radius);
  const blast = Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, blastRaw));
  return {
    cisa_kev: i.cisa_kev ? RWEP_WEIGHTS.cisa_kev : 0,
    poc_available: i.poc_available ? RWEP_WEIGHTS.poc_available : 0,
    ai_factor: (i.ai_assisted_weapon || i.ai_assisted_weaponization || i.ai_discovered) ? RWEP_WEIGHTS.ai_factor : 0,
    active_exploitation: RWEP_WEIGHTS.active_exploitation * aeMultiplier,
    blast_radius: blast,
    patch_available: i.patch_available ? RWEP_WEIGHTS.patch_available : 0,
    live_patch_available: i.live_patch_available ? RWEP_WEIGHTS.live_patch_available : 0,
    reboot_required: reboot ? RWEP_WEIGHTS.reboot_required : 0,
  };
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

  // `recompute` ignores the stored score and re-derives from rwep_factors,
  // which is how catalog drift against current weights is caught. Routed
  // through the shape detector so hand-edited factors in either shape work.
  const recompute = !!(opts && opts.recompute);
  let rwep;
  if (recompute) {
    const factors = entry.rwep_factors || {};
    rwep = deriveRwepFromFactors(factors);
  } else {
    rwep = entry.rwep_score;
  }
  // Absent or non-finite CVSS must not reach `cvss * 10`: NaN fails every band
  // below and falls through to "broadly aligned", asserting an alignment never
  // computed. Absent CVSS is not-comparable, not zero.
  const cvss = (typeof entry.cvss_score === 'number' && Number.isFinite(entry.cvss_score))
    ? entry.cvss_score
    : null;
  const cvssAbsent = cvss == null;
  const cvssEquivalent = cvssAbsent ? 0 : cvss * 10;
  // Same guard on the RWEP side. delta is null rather than NaN so the result
  // serializes cleanly and never claims a divergence that was not computed.
  const rwepValid = (typeof rwep === 'number' && Number.isFinite(rwep));
  const delta = (cvssAbsent || !rwepValid) ? null : rwep - cvssEquivalent;

  // The "broadly aligned" band is ±10, the tightest that still reads ordinary
  // CVSS rounding as alignment. A ±20 band swallows a delta of 12, which is
  // exactly the case where the CVSS-calibrated SLA is the thing at issue.
  // A zero-vs-zero entry reports no scoring signal rather than alignment.
  let explanation = '';
  if (!rwepValid) {
    explanation = 'RWEP score absent or non-numeric for this CVE — no usable RWEP signal to compare. Backfill rwep_score / rwep_factors in the catalog.';
  } else if ((rwep == null || rwep === 0) && (cvss == null || cvss === 0)) {
    explanation = 'No scoring signal — both RWEP and CVSS are zero/null. Investigate the catalog entry; this CVE has no usable risk score.';
  } else if (cvssAbsent) {
    explanation = 'CVSS absent — RWEP is the only usable score for this CVE; no CVSS comparison is possible. Backfill cvss_score in the catalog to enable the comparison.';
  } else if (delta > 10) {
    explanation = `RWEP significantly higher than CVSS equivalent. Factors driving delta: `;
    // Lists every factor scoreCustom counts, through the same aliases and
    // normalization — otherwise an entry driven by ai_assisted_weaponization, a
    // stray-cased 'Confirmed' or the patch_required_reboot alias shows a raised
    // RWEP with no stated reason.
    const driving = [];
    if (entry.cisa_kev) driving.push('CISA KEV (+25)');
    if (entry.poc_available) driving.push('public PoC (+20)');
    if (entry.ai_discovered || entry.ai_assisted_weaponization) driving.push('AI-discovered (+15 weaponization)');
    // Through the same ladder, so suspected (+10) and unknown (+5) are listed
    // with their real contribution. A confirmed-only test leaves the enumerated
    // factors summing to less than the delta, or to nothing at all.
    const ae = resolveActiveExploitation(entry.active_exploitation);
    if (ae.multiplier > 0) {
      driving.push(`${ae.normalised} exploitation (+${Math.round(RWEP_WEIGHTS.active_exploitation * ae.multiplier)})`);
    }
    // blast_radius contributes its raw 0..30 value, so a blast-driven delta
    // needs it listed or the raised RWEP has no stated cause.
    const blastRaw = Number((entry.rwep_factors || {}).blast_radius);
    const blast = Number.isFinite(blastRaw) ? Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, blastRaw)) : 0;
    if (blast > 0) driving.push(`blast radius (+${Math.round(blast)})`);
    // Ungated by live_patch_available, mirroring scoreCustom's rebootFactor.
    // Gating it here hides a driver the score counted on any entry that both
    // needs a reboot and has a live patch.
    if (entry.reboot_required || entry.patch_required_reboot) driving.push('reboot required (+5)');
    // Names the structural cause rather than trailing off after "driving delta:".
    explanation += driving.length ? driving.join(', ') : 'blast magnitude / structural RWEP factors';
    explanation += '. Framework patch SLAs calibrated to CVSS are insufficient for this CVE.';
  } else if (delta < -10) {
    explanation = `RWEP lower than CVSS equivalent. Mitigating factors: `;
    const mitigating = [];
    if (entry.patch_available) mitigating.push('patch available (-15)');
    if (entry.live_patch_available) mitigating.push('live patch available (-10)');
    if (!entry.poc_available) mitigating.push('no public PoC');
    if (!entry.cisa_kev) mitigating.push('not CISA KEV');
    explanation += mitigating.length ? mitigating.join(', ') : 'high CVSS base vs. a modest RWEP (low blast radius / no exploitation signal)';
  } else {
    explanation = 'CVSS and RWEP are broadly aligned for this CVE.';
  }

  const out = {
    cve_id: cveId,
    cvss: cvss,
    rwep: rwepValid ? rwep : null,
    cvss_framework_sla: cvssAbsent ? { hours: null, label: 'CVSS unavailable — no framework SLA can be derived' } : timeline(cvssEquivalent),
    rwep_actual_sla: rwepValid ? timeline(rwep) : { hours: null, label: 'RWEP score unavailable' },
    delta,
    explanation,
  };
  if (recompute) {
    out.stored_rwep_score = entry.rwep_score;
    out.recomputed = true;
  }
  return out;
}

/**
 * Which shape an `rwep_factors` block uses: 'A' raw, 'B' post-weight,
 * 'unknown' for empty or ambiguous blocks, 'mixed' for the violating case.
 *
 * Mixing them inside one entry breaks the sum invariant silently:
 * `{ cisa_kev: true, blast_radius: 30 }` sums to 30 when the intended score is
 * 55, because a raw boolean contributes nothing to a post-weight sum.
 */
function detectFactorShape(factors) {
  if (!factors || typeof factors !== 'object') return 'unknown';
  // Both spellings per factor, so a post-weight integer on either canonical key
  // registers as Shape-B evidence rather than slipping past the detector.
  const boolFields = ['cisa_kev', 'poc_available', 'ai_assisted_weaponization', 'ai_discovered', 'ai_factor', 'active_exploitation', 'patch_available', 'live_patch_available', 'patch_required_reboot', 'reboot_required'];
  let sawBool = false;
  let sawWeightedInt = false;
  for (const [k, v] of Object.entries(factors)) {
    if (k === 'blast_radius') continue; // always integer in both shapes
    if (k === 'active_exploitation' && typeof v === 'string') {
      // Valid in both shapes, so it is not Shape-A evidence: counting it would
      // return 'mixed' on a clean Shape-B block. Its weight is resolved in the
      // post-weight path, not here.
      continue;
    }
    if (typeof v === 'boolean' || v === null) {
      sawBool = true;
    } else if (typeof v === 'number' && Math.abs(v) >= 5 && boolFields.includes(k)) {
      sawWeightedInt = true;   // a boolean-named field carrying a weight
    } else if (typeof v === 'number' && (v === 0 || v === 1) && boolFields.includes(k)) {
      continue;                // 0/1 fits either shape
    } else if (typeof v === 'string' && boolFields.includes(k)) {
      sawBool = true;
    }
  }
  if (sawBool && sawWeightedInt) return 'mixed';
  if (sawWeightedInt) return 'B';
  if (sawBool) return 'A';
  return 'unknown';
}

function validate(catalog) {
  const errors = [];
  for (const [cveId, entry] of Object.entries(catalog)) {
    if (cveId.startsWith('_')) continue;
    // Drafts carry a conservative-default rwep_score beside null-until-curated
    // factor fields, so the divergence check below would fire on every one of
    // them. They are reviewed through `_auto_imported_meta.curation_needed` and
    // the validator's draft tier instead; clearing `_auto_imported` at curation
    // restores full validation.
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
    const shape = detectFactorShape(entry.rwep_factors);
    if (shape === 'mixed') {
      errors.push(`${cveId}: rwep_factors mixes Shape A (booleans) with Shape B (post-weight integers) — sum invariant cannot hold. Convert factors to a single shape.`);
    }
    // Per-factor coherence: every Shape-B contribution must equal the weight
    // its source field implies, because two compensating errors cancel inside
    // the ±5 aggregate tolerance below. blast_radius is exempt — it is the one
    // judgment-set factor with no deriving field.
    if (shape === 'B') {
      const f = entry.rwep_factors;
      const aeMultiplier = resolveActiveExploitation(entry.active_exploitation).multiplier;
      const implied = {
        cisa_kev: entry.cisa_kev === true ? RWEP_WEIGHTS.cisa_kev : 0,
        poc_available: entry.poc_available === true ? RWEP_WEIGHTS.poc_available : 0,
        ai_factor: (entry.ai_assisted_weaponization === true || entry.ai_discovered === true) ? RWEP_WEIGHTS.ai_factor : 0,
        active_exploitation: RWEP_WEIGHTS.active_exploitation * aeMultiplier,
        patch_available: entry.patch_available === true ? RWEP_WEIGHTS.patch_available : 0,
        live_patch_available: entry.live_patch_available === true ? RWEP_WEIGHTS.live_patch_available : 0,
      };
      for (const [k, want] of Object.entries(implied)) {
        if (k in f && typeof f[k] === 'number' && f[k] !== want) {
          errors.push(`${cveId}: rwep_factors.${k} is ${f[k]} but the entry's source fields imply ${want}`);
        }
      }
      // One implied weight, two accepted spellings. Both are checked, or a
      // contradictory value stored under the alias passes the coherence gate.
      const rebootWant = entry.patch_required_reboot === true ? RWEP_WEIGHTS.reboot_required : 0;
      for (const rebootKey of ['reboot_required', 'patch_required_reboot']) {
        if (rebootKey in f && typeof f[rebootKey] === 'number' && f[rebootKey] !== rebootWant) {
          errors.push(`${cveId}: rwep_factors.${rebootKey} is ${f[rebootKey]} but the entry's source fields imply ${rebootWant}`);
        }
      }
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
      // Both spellings, mirroring scoreCustom: passing only one drops the other
      // and computes a divergent expected score.
      reboot_required: entry.reboot_required || entry.patch_required_reboot
    });
    if (Math.abs(calculatedRwep - entry.rwep_score) > 5) {
      errors.push(`${cveId}: rwep_score ${entry.rwep_score} diverges from calculated ${calculatedRwep} by more than 5 — verify factors`);
    }
  }
  return errors;
}

/**
 * Strict CVSS 3.x vector parse, as `{ ok, version, reason? }`.
 *
 * Strict CSAF validators reject a document whose cvss_v3 block is keyed off a
 * malformed vector, so a permissive parse here fails downstream rather than
 * here. Mandatory metrics in order are AV/AC/PR/UI/S/C/I/A; E/RL/RC and the
 * CR..MA environmental set are optional.
 *
 * 3.0 and 3.1 share one grammar and differ only in the prefix, and CSAF 2.0
 * accepts both, so the version is recorded rather than rejected.
 */
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

/**
 * Package-Confidence Score: a supplementary 0-100 supply-chain trust signal
 * shown alongside RWEP, never instead of it. Returns null with no usable input.
 *
 * Its polarity is the INVERSE of RWEP — high means trustworthy provenance, low
 * means it behaves like malware — so the two must never be summed or compared.
 * It is deliberately outside the RWEP factor key set and is never called from
 * validate(), scoreCustom() or deriveRwepFromFactors(), so it cannot perturb a
 * stored rwep_score or trip the divergence gate.
 *
 * Equal-weight mean of whichever sub-signals are present; an absent dimension is
 * skipped rather than scored 0, so a partly-curated entry is not punished.
 */
function packageConfidence(inputs) {
  if (!inputs || typeof inputs !== 'object') return null;
  const dims = ['maintainer', 'quality', 'behavioral', 'provenance'];
  const present = dims
    .map((d) => inputs[d])
    .filter((v) => typeof v === 'number' && Number.isFinite(v));
  if (!present.length) return null;
  const mean = present.reduce((a, b) => a + b, 0) / present.length;
  return Math.max(0, Math.min(100, Math.round(mean)));
}

module.exports = {
  score,
  scoreCustom,
  postWeightFactors,
  timeline,
  compare,
  packageConfidence,
  validate,
  validateFactors,
  deriveRwepFromFactors,
  parseCvss31Vector,
  resolveActiveExploitation,
  activeExploitationMultiplier,
  RWEP_WEIGHTS,
  ACTIVE_EXPLOITATION_LADDER,
  RECOGNISED_FACTOR_KEYS,
  RECOGNISED_POST_WEIGHT_KEYS,
};
