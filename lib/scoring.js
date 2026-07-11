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

// Required-field list is loaded from the catalog schema's entry-level
// `required` array so the two can never drift. (live_patch_tools is
// deliberately NOT hard-required here — it is schema-optional, and the
// live_patch_available => live_patch_tools implication is enforced
// separately below.)
const CVE_SCHEMA_REQUIRED = require('./schemas/cve-catalog.schema.json').required;

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
  confirmed:   1.0,
  suspected:   0.5,
  unknown:     0.25,
  // "theoretical" = a working PoC is published but no in-the-wild exploitation
  // is observed (per the catalog's active_exploitation_vocabulary). The PoC
  // itself carries weight via the separate poc_available factor; the
  // active-exploitation dimension is 0 (no observed exploitation). Mapped
  // explicitly so it's intentional, not an incidental `?? 0` fall-through —
  // and so it does not perturb the stored RWEP of theoretical-status entries.
  theoretical: 0,
  none:        0,
};

/**
 * Resolve the active_exploitation ladder multiplier for a factor value.
 *
 * The bare `ACTIVE_EXPLOITATION_LADDER[v] ?? 0` lookup silently mapped any
 * out-of-vocabulary string ('exploited', 'in-the-wild', a future vocabulary
 * value) AND any case/whitespace variant ('Confirmed', ' CONFIRMED ') to 0 —
 * dropping up to the full active_exploitation weight (20 pts) from the RWEP
 * with no diagnostic, while validateFactors() flagged the same string. This
 * is the recurring "out-of-vocab token -> silent zero" class: the no-match
 * path must surface an error, not a silent default (same remedy as the
 * playbook-runner condition-evaluator hyphen fix).
 *
 * - Case-normalises the lookup so 'Confirmed' / ' CONFIRMED ' resolve to the
 *   canonical ladder entry instead of zeroing.
 * - null / undefined are the documented "treated as 'none'" default (mult 0,
 *   recognised) — these are not typos.
 * - A non-empty string NOT in the ladder, or a non-string non-nullish value,
 *   is UNRECOGNISED: returns multiplier 0 AND emits a process warning so the
 *   zeroed factor is observable in the bare-number call path. The structured
 *   diagnostic for the collectWarnings path is produced by validateFactors().
 *
 * Returns { multiplier, recognised, normalised }.
 */
function resolveActiveExploitation(active_exploitation) {
  if (active_exploitation === undefined || active_exploitation === null) {
    // documented default: absent active_exploitation is scored as 'none'.
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

// The canonical set of factor keys scoreCustom recognises. Used by
// validateFactors to flag unknown keys.
const RECOGNISED_FACTOR_KEYS = new Set([
  'cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
  'active_exploitation', 'blast_radius', 'patch_available',
  'live_patch_available', 'reboot_required',
  // accepted aliases for the catalog field names: a factor bag built straight
  // from a catalog entry carries `ai_assisted_weaponization` (the field the
  // catalog declares) and `patch_required_reboot`, not the legacy short forms.
  'ai_assisted_weaponization',
  'patch_required_reboot',
]);

// Shape-B (catalog post-weight) keys deriveRwepFromFactors is allowed to sum.
// The post-weight summation operates on the catalog field names — which include
// `ai_factor`, the +15 AI weight every Shape-B catalog entry stores. `ai_factor`
// is deliberately ABSENT from RECOGNISED_FACTOR_KEYS (that set carries the
// Shape-A boolean inputs `ai_assisted_weapon` / `ai_discovered` /
// `ai_assisted_weaponization`), so the Shape-B allowlist must add it back — a
// plain `RECOGNISED_FACTOR_KEYS.has(k)` filter would silently drop the AI weight
// from every derivation. Any key NOT in this set is a typo or unknown field; it
// is excluded from the sum AND surfaced (see the Shape-B loop) rather than blindly
// added, so a sub-5 typo can't corrupt the derived score with no diagnostic.
const RECOGNISED_POST_WEIGHT_KEYS = new Set([...RECOGNISED_FACTOR_KEYS, 'ai_factor']);

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
 *   - active_exploitation: 'none' | 'unknown' | 'suspected' | 'theoretical' | 'confirmed'.
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
    // The catalog field `ai_assisted_weaponization` satisfies `ai_assisted_weapon`,
    // and `patch_required_reboot` satisfies `reboot_required` — the same aliasing
    // scoreCustom/deriveRwepFromFactors honor, so validateFactors must accept a
    // block that supplies only the alias instead of flagging it "missing".
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
    // Normalize (trim + lowercase) before the vocab check so validateFactors
    // accepts exactly what scoreCustom/resolveActiveExploitation accept — a
    // stray-cased 'Confirmed' / ' confirmed ' must not be flagged here while the
    // scorer consumes it, or the two surfaces disagree.
    const aeNorm = typeof aeRaw === 'string' ? aeRaw.trim().toLowerCase() : aeRaw;
    if (!aeAllowed.includes(aeNorm)) {
      warnings.push(`active_exploitation: expected one of ${aeAllowed.join(', ')}, got ${JSON.stringify(aeRaw)}`);
    }
  }
  // NaN diagnostics. The prior message read "expected number,
  // got number (null)" because `JSON.stringify(NaN) === 'null'` and `typeof
  // NaN === 'number'`. Number.isFinite catches NaN + Infinity + -Infinity
  // and emits a useful message.
  if (factors.blast_radius === undefined || factors.blast_radius === null) {
    warnings.push('blast_radius: missing (treated as 0)');
  } else if (typeof factors.blast_radius !== 'number') {
    // scoreCustom coerces a numeric string (e.g. "30") via Number(); keep the
    // two surfaces consistent — accept a finite numeric string with a soft note
    // rather than rejecting what the scorer will happily use.
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
    // The catalog field is `ai_assisted_weaponization`; accept it as an alias
    // so a factor bag built directly from a catalog entry still counts the AI
    // factor instead of silently dropping the +15 weight.
    ai_assisted_weaponization = false,
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
  score += (ai_assisted_weapon || ai_assisted_weaponization || ai_discovered) ? RWEP_WEIGHTS.ai_factor : 0;
  // active_exploitation goes through the ladder rather
  // than two hand-written branches with `Math.floor(weight/2)`. The floor
  // was a no-op for even weights (20/2 = 10) but would have silently
  // truncated to asymmetric results if a future operator bumped the
  // weight to 21. The ladder + multiplication preserves the contribution
  // exactly, including the new `unknown → 0.25 × weight = 5` mapping that
  // aligns the catalog scorer with playbook-runner._activeExploitationLadder.
  const aeMultiplier = activeExploitationMultiplier(active_exploitation);
  score += RWEP_WEIGHTS.active_exploitation * aeMultiplier;
  // v0.12.15: blast_radius numeric coercion must reject
  // NaN, Infinity, and strings explicitly. The prior `typeof === 'number'`
  // check passed NaN (which is `typeof === 'number'`) into `Math.min/max`
  // which propagates NaN through the final clamp, defeating the [0,100]
  // contract. Number.isFinite + Number() coercion catches all four classes:
  // NaN, Infinity, undefined, stringified-number.
  // Match validateFactors' contract exactly. Bare `Number()` coercion would
  // turn `true` into 1 and a single-element array like `[7]` into 7 — both of
  // which validateFactors rejects as "expected number" — so the scorer would
  // silently add a blast contribution the validator says is invalid. Accept
  // only a finite number or a trimmed-nonempty numeric string; everything
  // else (boolean, array, object, NaN, Infinity, empty/whitespace string)
  // contributes 0.
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
  const entries = Object.entries(factors);
  if (entries.length === 0) return 0;
  // A boolean factor OR a string active_exploitation ladder value is Shape-A
  // evidence — scoreCustom reads exactly those. active_exploitation's string
  // form legitimately appears in BOTH shapes (Shape A stores it as the literal
  // ladder string; a Shape B post-weight block can ALSO carry it as a
  // human-readable status alongside its post-weight integers), so it is the
  // hasPostWeightInt guard below — NOT excluding active_exploitation from this
  // check — that disambiguates them. Excluding it here under-scored an
  // active-exploitation-ONLY raw bag (e.g. `{ active_exploitation: 'confirmed',
  // blast_radius: 10 }`): hasBooleanOrLadder went false, the block fell through
  // to the Shape-B sum, and the ladder string was skipped (10 vs scoreCustom 30).
  const aeAllowed = new Set(['none', 'unknown', 'suspected', 'theoretical', 'confirmed']);
  const hasBooleanOrLadder = entries.some(
    ([, v]) => (typeof v === 'boolean' || (typeof v === 'string' && aeAllowed.has(v.trim().toLowerCase()))),
  );
  // A boolean-named key carrying a post-weight integer (>=5) is unambiguous
  // Shape-B evidence. When present, the block is Shape B even if it also carries
  // a string active_exploitation — route to the post-weight sum, not scoreCustom.
  const hasPostWeightInt = entries.some(
    ([k, v]) => k !== 'blast_radius' && typeof v === 'number' && Number.isFinite(v) && Math.abs(v) >= 5,
  );
  if (hasBooleanOrLadder && !hasPostWeightInt) {
    return scoreCustom(factors);
  }
  // Shape B: catalog post-weight. Sum + clamp.
  //
  // blast_radius is the one Shape B field with a per-factor ceiling: it is a
  // RAW 0..30 magnitude, not a post-weight contribution (see the dual-semantics
  // note at the top of this file). Clamp it to [0, RWEP_WEIGHTS.blast_radius]
  // before summing — exactly as scoreCustom does — so an out-of-range stored
  // value (a unit error such as 300, or a negative) cannot silently inflate or
  // zero the result by being absorbed only by the final aggregate clamp. Both
  // paths now produce the same score for the same factors, so the validate()
  // recompute-vs-stored divergence gate stays meaningful instead of flagging a
  // self-inconsistency the two scorers introduced. Every other Shape B value is
  // already a bounded post-weight contribution, so only blast_radius needs the
  // per-factor clamp.
  let sum = 0;
  for (const [k, v] of Object.entries(factors)) {
    if (typeof v !== 'number' || !Number.isFinite(v)) continue;
    // Unrecognised key (a typo such as `cisa_kevv` / `reboot_requiredd`, or a
    // field outside the post-weight vocabulary): do NOT add it to the sum, and
    // surface it. scoreCustom/validateFactors already drop+warn on unknown
    // keys; the Shape-B summation previously added ANY numeric value blindly, so
    // the three scoring surfaces disagreed on what an unknown key means (a sub-5
    // typo silently inflated the derived breakdown). Align them here. The
    // warning mirrors the activeExploitationMultiplier precedent above — an
    // observable diagnostic on the standard Node channel, not a silent skip, so
    // the no-match path surfaces an error instead of defaulting (the file's own
    // "out-of-vocab token -> must surface, not silent-default" rule).
    if (!RECOGNISED_POST_WEIGHT_KEYS.has(k)) {
      process.emitWarning(
        `rwep_factors carries unrecognised key '${k}'; excluded from the derived sum`,
        { type: 'RwepFactorUnrecognised', code: 'RWEP_FACTOR_UNRECOGNISED' },
      );
      continue;
    }
    // reboot_required and patch_required_reboot are aliases for the SAME
    // post-weight contribution (scoreCustom collapses them). A block carrying
    // both must count it once; summing both double-counts the reboot weight,
    // inflating the derived RWEP past the formula AND past the stored score the
    // validate() divergence gate compares against.
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
  // Normalize cvss before any arithmetic. An absent or non-finite cvss_score
  // must not flow into `cvss * 10` — `undefined * 10 === NaN` poisons the
  // delta, and NaN fails every `delta > 10` / `delta < -10` band, so the
  // entry would otherwise fall through to the "broadly aligned" arm and
  // assert an alignment that was never computed. Treat absent CVSS as
  // not-comparable instead.
  const cvss = (typeof entry.cvss_score === 'number' && Number.isFinite(entry.cvss_score))
    ? entry.cvss_score
    : null;
  const cvssAbsent = cvss == null;
  const cvssEquivalent = cvssAbsent ? 0 : cvss * 10;
  // delta is null (not NaN) when there is no CVSS to compare against, so the
  // emitted result serializes cleanly and never claims a numeric divergence
  // that does not exist.
  // Guard the RWEP side exactly like CVSS above: an absent or non-finite
  // rwep_score must not flow into `rwep - cvssEquivalent` — NaN poisons the
  // delta, fails every band, and falls through to a false "broadly aligned".
  const rwepValid = (typeof rwep === 'number' && Number.isFinite(rwep));
  const delta = (cvssAbsent || !rwepValid) ? null : rwep - cvssEquivalent;

  // narrow the "broadly aligned" band from ±20 to ±10. The old
  // ±20 band swallowed the Copy Fail RWEP-vs-CVSS divergence (delta = 12)
  // where the operator-facing point is precisely that the CVSS-calibrated
  // SLA is insufficient. ±10 is the tightest classifier that still treats
  // ordinary CVSS rounding noise as alignment.
  let explanation = '';
  // Surface the "no scoring signal" case distinctly from "broadly
  // aligned". Pre-fix a CVE with rwep_score: 0 AND cvss_score: 0 (e.g.
  // catalog entry created before scoring backfill) printed "broadly
  // aligned" — coincidence-passing per the field-present-not-populated
  // pitfall. Now the operator sees a specific signal pointing at the
  // catalog gap rather than a false sense of alignment.
  if (!rwepValid) {
    explanation = 'RWEP score absent or non-numeric for this CVE — no usable RWEP signal to compare. Backfill rwep_score / rwep_factors in the catalog.';
  } else if ((rwep == null || rwep === 0) && (cvss == null || cvss === 0)) {
    explanation = 'No scoring signal — both RWEP and CVSS are zero/null. Investigate the catalog entry; this CVE has no usable risk score.';
  } else if (cvssAbsent) {
    // RWEP carries a real signal but there is no CVSS to compare it against.
    // The two scores are not comparable, so do not assert alignment or a
    // divergence direction — surface the missing CVSS instead.
    explanation = 'CVSS absent — RWEP is the only usable score for this CVE; no CVSS comparison is possible. Backfill cvss_score in the catalog to enable the comparison.';
  } else if (delta > 10) {
    explanation = `RWEP significantly higher than CVSS equivalent. Factors driving delta: `;
    // The explanation must list every factor scoreCustom actually counts, via
    // the same aliases/normalization — otherwise a CVE whose RWEP is driven by
    // ai_assisted_weaponization (not ai_discovered), a stray-cased 'Confirmed',
    // or the patch_required_reboot alias shows a higher RWEP with no stated
    // reason for the delta.
    const driving = [];
    if (entry.cisa_kev) driving.push('CISA KEV (+25)');
    if (entry.poc_available) driving.push('public PoC (+20)');
    if (entry.ai_discovered || entry.ai_assisted_weaponization) driving.push('AI-discovered (+15 weaponization)');
    // active_exploitation via the SAME ladder scoreCustom uses, so suspected
    // (+10) and unknown (+5) are listed with their actual contribution rather
    // than only 'confirmed' (+20). The bare confirmed-only test dropped every
    // suspected/unknown driver — so the enumerated factors summed to less than
    // the delta, or (on a purely suspected/blast-driven entry) to nothing,
    // leaving a dangling "driving delta: .".
    const ae = resolveActiveExploitation(entry.active_exploitation);
    if (ae.multiplier > 0) {
      driving.push(`${ae.normalised} exploitation (+${Math.round(RWEP_WEIGHTS.active_exploitation * ae.multiplier)})`);
    }
    // blast_radius contributes its raw value (0..30) to RWEP but never appeared
    // in the driver list, so a blast-driven delta showed a higher RWEP with no
    // stated cause. List the clamped contribution when positive.
    const blastRaw = Number((entry.rwep_factors || {}).blast_radius);
    const blast = Number.isFinite(blastRaw) ? Math.max(0, Math.min(RWEP_WEIGHTS.blast_radius, blastRaw)) : 0;
    if (blast > 0) driving.push(`blast radius (+${Math.round(blast)})`);
    // Mirror scoreCustom's rebootFactor EXACTLY: the +5 reboot weight is added
    // whenever a reboot is required, regardless of live_patch_available (a live
    // patch is a temporary workaround; the full-remediation window still extends
    // — see the RWEP_WEIGHTS header note). Gating this driver on
    // !live_patch_available made the enumerated factors sum to less than the
    // delta on any entry that both requires a reboot AND has a live patch
    // available, hiding a driver the score actually counted.
    if (entry.reboot_required || entry.patch_required_reboot) driving.push('reboot required (+5)');
    // A positive delta with no enumerated driver still names the structural
    // cause instead of a dangling "driving delta: .".
    explanation += driving.length ? driving.join(', ') : 'blast magnitude / structural RWEP factors';
    explanation += '. Framework patch SLAs calibrated to CVSS are insufficient for this CVE.';
  } else if (delta < -10) {
    explanation = `RWEP lower than CVSS equivalent. Mitigating factors: `;
    const mitigating = [];
    if (entry.patch_available) mitigating.push('patch available (-15)');
    if (entry.live_patch_available) mitigating.push('live patch available (-10)');
    if (!entry.poc_available) mitigating.push('no public PoC');
    if (!entry.cisa_kev) mitigating.push('not CISA KEV');
    // A negative delta with no enumerated mitigator still names the structural
    // cause (high CVSS base vs. a modest RWEP) instead of a dangling list.
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
 * v0.13.0: detect rwep_factors shape. The catalog historically stored
 * factors in two distinct shapes that look identical at the field level:
 *
 *   Shape A (raw):    `{ cisa_kev: true, blast_radius: 30, ... }`
 *     - booleans + integers in their natural form
 *     - score derives from `scoreCustom(factors)` which applies weights
 *
 *   Shape B (post-weight): `{ cisa_kev: 25, blast_radius: 30, ... }`
 *     - integers in their post-weight contribution (cisa_kev: 25 not true)
 *     - score = sum of values; no second weight pass
 *
 * Mixing shapes inside ONE entry silently breaks the sum invariant —
 * a CVE with `cisa_kev: true, blast_radius: 30` reports rwep 30 (just
 * blast_radius summed) when the operator-intended score is 55 (KEV + br).
 * Until v0.13 nothing caught this; v0.13 adds shape detection that fires
 * an error when the entry mixes booleans with non-trivial numeric weights.
 *
 * Returns 'A' for raw, 'B' for post-weight, 'unknown' for empty/edge
 * cases, or 'mixed' for the violating case.
 */
function detectFactorShape(factors) {
  if (!factors || typeof factors !== 'object') return 'unknown';
  // Keys inspected for shape evidence. Covers BOTH spellings per factor:
  // the Shape A (raw boolean) names AND the Shape B (post-weight) names the
  // schema requires on rwep_factors — ai_factor and reboot_required — so a
  // post-weight integer on either canonical key registers as Shape B
  // evidence instead of slipping past the mixed-shape detector.
  const boolFields = ['cisa_kev', 'poc_available', 'ai_assisted_weaponization', 'ai_discovered', 'ai_factor', 'active_exploitation', 'patch_available', 'live_patch_available', 'patch_required_reboot', 'reboot_required'];
  let sawBool = false;
  let sawWeightedInt = false;
  for (const [k, v] of Object.entries(factors)) {
    if (k === 'blast_radius') continue; // always integer in both shapes
    if (k === 'active_exploitation' && typeof v === 'string') {
      // active_exploitation's string-ladder form is valid in BOTH shapes — a
      // Shape B (post-weight) block can carry it as the human-readable status
      // string alongside its post-weight integers, exactly the way Shape A does.
      // So a string active_exploitation is NOT Shape-A evidence; counting it as
      // sawBool produced a spurious 'mixed' verdict (and a validate() error) on
      // an otherwise-clean Shape B block. Its weight, when summed, is resolved
      // via resolveActiveExploitation in the post-weight path, not here.
      continue;
    }
    if (typeof v === 'boolean' || v === null) {
      sawBool = true;
    } else if (typeof v === 'number' && Math.abs(v) >= 5 && boolFields.includes(k)) {
      // Field that's nominally boolean carrying a numeric weight (e.g. 25,
      // 20, 15) — Shape B signature.
      sawWeightedInt = true;
    } else if (typeof v === 'number' && (v === 0 || v === 1) && boolFields.includes(k)) {
      // 0/1 on a boolean-named field could be either shape; ambiguous, ignore.
      continue;
    } else if (typeof v === 'string' && boolFields.includes(k)) {
      // String values on OTHER boolean-named fields are Shape A.
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
    // v0.13.0: detect Shape A / Shape B / mixed factor shape. A 'mixed'
    // shape would silently break the sum invariant; refuse it. See
    // detectFactorShape() doc above for the failure mode.
    const shape = detectFactorShape(entry.rwep_factors);
    if (shape === 'mixed') {
      errors.push(`${cveId}: rwep_factors mixes Shape A (booleans) with Shape B (post-weight integers) — sum invariant cannot hold. Convert factors to a single shape.`);
    }
    // Per-factor coherence: in a Shape B (post-weight) block every stored
    // contribution must equal the weight implied by its source field.
    // Without this, two compensating per-factor errors cancel inside the
    // ±5 aggregate tolerance below and a factor block that contradicts the
    // entry's own flags ships unnoticed. blast_radius is exempt — it is the
    // one judgment-set factor with no deriving source field.
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
      // The reboot contribution has ONE implied weight but TWO accepted
      // spellings — `reboot_required` (canonical) and `patch_required_reboot`
      // (the catalog field-name alias scoreCustom also honors). Check both
      // against that single weight; keying only on `reboot_required` let a
      // contradictory value stored under the alias slip past the coherence
      // gate, inflating the derived score.
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
      // Mirror the reboot alias scoreCustom itself honors (reboot_required OR
      // patch_required_reboot): passing only patch_required_reboot would drop a
      // top-level reboot_required field and compute a divergent expected RWEP.
      reboot_required: entry.reboot_required || entry.patch_required_reboot
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

/**
 * Package-Confidence Score (PCS) — a SUPPLEMENTARY 0-100 supply-chain
 * trustworthiness signal, surfaced ALONGSIDE RWEP, never replacing it.
 *
 * Polarity is the INVERSE of RWEP: high PCS = trustworthy provenance/behaviour;
 * low PCS = behaves like malware. RWEP answers "how urgently must I act on this
 * known vulnerability"; PCS answers "how much do I trust this package's
 * provenance/behaviour, independent of any CVE." The two are different axes and
 * must never be summed or compared numerically (the `package_confidence.polarity:
 * "trust"` const on catalog entries exists to assert direction before display).
 *
 * CRITICAL: this function is NEVER called inside validate() / scoreCustom() /
 * deriveRwepFromFactors(). PCS lives OUTSIDE the RWEP factor key set so the
 * RWEP sum invariant + >5 divergence gate cannot see it — adding it is purely
 * additive and cannot perturb any stored rwep_score.
 *
 * Equal-weight mean of the PRESENT sub-signals (maintainer / quality /
 * behavioral / provenance), each 0-100, clamped to [0,100]. Absent sub-signals
 * are skipped (not treated as 0) so a partially-curated entry isn't punished
 * for un-assessed dimensions. Returns null when no usable input is present.
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
