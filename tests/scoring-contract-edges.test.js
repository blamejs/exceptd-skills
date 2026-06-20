'use strict';
/**
 * tests/scoring-contract-edges.test.js
 *
 * Locks three RWEP-scoring contract edges where the scorer previously
 * diverged from its own validator or emitted a NaN/false verdict:
 *
 *   1. compare() with an absent cvss_score key must report "not comparable"
 *      with a finite (non-NaN) delta, never a false "broadly aligned" verdict.
 *   2. scoreCustom() must REJECT a non-number blast_radius (boolean, array,
 *      object) — contributing 0 — exactly as validateFactors rejects it,
 *      while still accepting a finite number and a trimmed numeric string.
 *   3. validate()'s Shape-B per-factor coherence must catch a contradictory
 *      reboot weight stored under EITHER the canonical `reboot_required` key
 *      OR the accepted catalog alias `patch_required_reboot`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  compare,
  scoreCustom,
  validate,
  validateFactors,
  deriveRwepFromFactors,
  resolveActiveExploitation,
  activeExploitationMultiplier,
} = require('../lib/scoring.js');

// ---------- 1. compare(): absent cvss_score ----------

test('compare() with absent cvss_score key emits a finite delta, never NaN', () => {
  const cid = 'CVE-TEST-NO-CVSS';
  const catalog = {
    [cid]: {
      rwep_score: 60,
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
      // cvss_score key intentionally absent
    },
  };
  const r = compare(cid, catalog, {});

  // delta must be a real value (null is the explicit "not comparable"
  // sentinel), never NaN — NaN would serialize to null and silently corrupt
  // any downstream consumer expecting a number.
  assert.equal(Number.isNaN(r.delta), false, 'delta must not be NaN');
  assert.equal(r.delta, null, 'absent cvss => delta is null (not comparable)');
  assert.equal(r.cvss, null, 'absent cvss => emitted cvss is null, not undefined/NaN');

  // The verdict must NOT claim alignment.
  assert.equal(
    /broadly aligned/i.test(r.explanation),
    false,
    'absent cvss must not produce a false alignment claim',
  );
  assert.match(
    r.explanation,
    /CVSS absent/i,
    'absent cvss must surface the missing-CVSS message',
  );

  // JSON round-trip: a NaN delta would serialize to null-from-NaN; an explicit
  // null must round-trip as null with the verdict intact.
  const round = JSON.parse(JSON.stringify(r));
  assert.equal(round.delta, null);
  assert.match(round.explanation, /CVSS absent/i);
});

test('compare() with explicit null cvss_score is handled the same as absent', () => {
  const cid = 'CVE-TEST-NULL-CVSS';
  const catalog = {
    [cid]: {
      rwep_score: 55,
      cvss_score: null,
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
    },
  };
  const r = compare(cid, catalog, {});
  assert.equal(Number.isNaN(r.delta), false);
  assert.equal(r.delta, null);
  assert.equal(/broadly aligned/i.test(r.explanation), false);
  assert.match(r.explanation, /CVSS absent/i);
});

test('compare() with a real numeric cvss_score still computes a numeric delta', () => {
  // Regression guard: the absent-cvss arm must not perturb the normal path.
  const cid = 'CVE-TEST-NUMERIC-CVSS';
  const catalog = {
    [cid]: {
      rwep_score: 60,
      cvss_score: 5.0, // equivalent 50; delta = 60 - 50 = 10 => "broadly aligned"
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
    },
  };
  const r = compare(cid, catalog, {});
  assert.equal(r.delta, 10);
  assert.equal(r.cvss, 5.0);
  assert.match(r.explanation, /broadly aligned/i);
});

// ---------- 2. scoreCustom(): non-number blast_radius rejection ----------
//
// All non-blast factors default to false/none, so blast_radius is the only
// contributor — the returned score IS the accepted blast contribution.

test('scoreCustom() rejects a boolean blast_radius (matches validateFactors)', () => {
  assert.equal(scoreCustom({ blast_radius: true }), 0);
  assert.equal(scoreCustom({ blast_radius: false }), 0);
});

test('scoreCustom() rejects an array blast_radius (matches validateFactors)', () => {
  assert.equal(scoreCustom({ blast_radius: [7] }), 0);
  assert.equal(scoreCustom({ blast_radius: [3] }), 0);
  assert.equal(scoreCustom({ blast_radius: [] }), 0);
});

test('scoreCustom() rejects an object blast_radius', () => {
  assert.equal(scoreCustom({ blast_radius: {} }), 0);
});

test('scoreCustom() still accepts the valid blast_radius forms', () => {
  assert.equal(scoreCustom({ blast_radius: 5 }), 5);
  assert.equal(scoreCustom({ blast_radius: '5' }), 5);
  assert.equal(scoreCustom({ blast_radius: '  5  ' }), 5);
  assert.equal(scoreCustom({ blast_radius: '  ' }), 0);
  assert.equal(scoreCustom({ blast_radius: NaN }), 0);
  assert.equal(scoreCustom({ blast_radius: Infinity }), 0);
});

test('scoreCustom() and validateFactors agree: a rejected-type blast_radius scores 0', () => {
  // Wire the two surfaces together so they cannot drift again. For every value
  // validateFactors flags with "expected number, got <type>" (NOT the soft
  // numeric-string note), scoreCustom must contribute 0 blast.
  const rejectedTypeValues = [true, false, [7], [], {}, null];
  for (const v of rejectedTypeValues) {
    const warns = validateFactors({ blast_radius: v });
    const flaggedAsWrongType = warns.some((w) =>
      /blast_radius:.*(expected number, got|missing)/.test(w),
    );
    assert.equal(
      flaggedAsWrongType,
      true,
      `validateFactors should flag blast_radius=${JSON.stringify(v)} as a non-number`,
    );
    assert.equal(
      scoreCustom({ blast_radius: v }),
      0,
      `scoreCustom must contribute 0 for the validator-rejected blast_radius=${JSON.stringify(v)}`,
    );
  }
});

// ---------- 3. validate(): Shape-B reboot alias coherence ----------

// A minimally-complete Shape-B entry the catalog validator's coherence loop
// accepts, parameterized so each test injects exactly one reboot contradiction.
function shapeBEntry(rwepFactors, overrides = {}) {
  return {
    cve_id: 'CVE-TEST-REBOOT',
    name: 'reboot-alias-coherence-fixture',
    rwep_score: 45,
    cvss_score: 7.0,
    active_exploitation: 'confirmed',
    cisa_kev: true,
    poc_available: false,
    ai_discovered: false,
    ai_assisted_weaponization: false,
    patch_available: false,
    live_patch_available: false,
    patch_required_reboot: false,
    rwep_factors: rwepFactors,
    ...overrides,
  };
}

function rebootErrors(catalog) {
  return validate(catalog).filter((e) => /reboot/.test(e));
}

test('validate() flags a contradictory reboot weight under the canonical key', () => {
  // Control: the canonical spelling was already covered — confirm it still is.
  const entry = shapeBEntry({
    cisa_kev: 25,
    active_exploitation: 20,
    blast_radius: 0,
    reboot_required: 5, // flag is false => implied 0 => contradiction
  });
  const errs = rebootErrors({ 'CVE-TEST-REBOOT': entry });
  assert.equal(errs.length, 1, 'exactly one reboot coherence error');
  assert.equal(
    errs[0],
    "CVE-TEST-REBOOT: rwep_factors.reboot_required is 5 but the entry's source fields imply 0",
  );
});

test('validate() flags a contradictory reboot weight under the patch_required_reboot alias', () => {
  // The previously-bypassed case: the contradiction lives under the alias key.
  const entry = shapeBEntry({
    cisa_kev: 25,
    active_exploitation: 20,
    blast_radius: 0,
    patch_required_reboot: 5, // flag is false => implied 0 => contradiction
  });
  const errs = rebootErrors({ 'CVE-TEST-REBOOT': entry });
  assert.equal(errs.length, 1, 'exactly one reboot coherence error for the alias spelling');
  assert.equal(
    errs[0],
    "CVE-TEST-REBOOT: rwep_factors.patch_required_reboot is 5 but the entry's source fields imply 0",
  );
});

test('validate() accepts a coherent reboot weight under the alias (no false positive)', () => {
  // patch_required_reboot flag true => implied 5; the alias factor stores 5.
  const entry = shapeBEntry(
    {
      cisa_kev: 25,
      active_exploitation: 20,
      blast_radius: 0,
      patch_required_reboot: 5,
    },
    { patch_required_reboot: true, rwep_score: 50 },
  );
  const errs = rebootErrors({ 'CVE-TEST-REBOOT': entry });
  assert.deepEqual(errs, [], 'a coherent alias reboot weight must not error');
});

test('validate() flags the symmetric case: reboot earned but alias factor stores 0', () => {
  // patch_required_reboot flag true => implied 5; the alias factor stores 0.
  const entry = shapeBEntry(
    {
      cisa_kev: 25,
      active_exploitation: 20,
      blast_radius: 0,
      patch_required_reboot: 0,
    },
    { patch_required_reboot: true, rwep_score: 45 },
  );
  const errs = rebootErrors({ 'CVE-TEST-REBOOT': entry });
  assert.equal(errs.length, 1);
  assert.equal(
    errs[0],
    "CVE-TEST-REBOOT: rwep_factors.patch_required_reboot is 0 but the entry's source fields imply 5",
  );
});

// ---------- 4. scoreCustom(): out-of-vocab active_exploitation ----------
//
// An active_exploitation string not in the ladder previously resolved to
// `?? 0` and silently dropped up to 20 active-exploitation points with no
// diagnostic — while validateFactors() flagged the same string. The scorer
// must (a) keep contributing 0 for a genuinely-unknown value, (b) surface
// that zeroing observably (the bare-number path emits a process warning;
// the collectWarnings path carries the structured warning), and (c)
// case-normalise so a stray-cased canonical value scores correctly instead
// of zeroing.

test('scoreCustom() and validateFactors agree: an out-of-vocab active_exploitation is flagged', () => {
  // Wire the two surfaces together: every AE string validateFactors flags as
  // non-enum, scoreCustom must contribute 0 AE weight for (cisa_kev is the
  // only other signal, so the score is 25 + AE-contribution).
  const outOfVocab = ['exploited', 'in-the-wild', 'active', 'KEV'];
  for (const ae of outOfVocab) {
    const warns = validateFactors({ active_exploitation: ae });
    const flagged = warns.some((w) => /^active_exploitation: expected one of/.test(w));
    assert.equal(flagged, true, `validateFactors should flag active_exploitation=${JSON.stringify(ae)}`);
    // 25 (cisa_kev) + 0 (unrecognised AE) — the AE 20-pt contribution is dropped.
    assert.equal(
      scoreCustom({ active_exploitation: ae, cisa_kev: true }),
      25,
      `scoreCustom must contribute 0 AE weight for the validator-flagged active_exploitation=${JSON.stringify(ae)}`,
    );
  }
});

test('scoreCustom() emits an observable warning when active_exploitation is out-of-vocab (no longer silent)', () => {
  const seen = [];
  const handler = (w) => { if (w && w.code === 'RWEP_AE_UNRECOGNISED') seen.push(w); };
  process.on('warning', handler);
  try {
    // resolveActiveExploitation is the synchronous source of truth for the
    // recognised flag; assert it directly so the test does not race the async
    // process-warning emission.
    const r = resolveActiveExploitation('exploited');
    assert.equal(r.recognised, false, 'out-of-vocab AE must be recognised:false');
    assert.equal(r.multiplier, 0, 'out-of-vocab AE must contribute multiplier 0');
    // the canonical theoretical/none entries score 0 but are RECOGNISED — they
    // must not be conflated with the unrecognised case.
    assert.equal(resolveActiveExploitation('theoretical').recognised, true);
    assert.equal(resolveActiveExploitation('none').recognised, true);
    assert.equal(resolveActiveExploitation(undefined).recognised, true);
    assert.equal(resolveActiveExploitation(null).recognised, true);
  } finally {
    process.removeListener('warning', handler);
  }
});

test('scoreCustom() case-normalises a stray-cased canonical active_exploitation instead of zeroing it', () => {
  // 'Confirmed' / '  CONFIRMED  ' must resolve to the same contribution as the
  // canonical 'confirmed' — pre-fix they fell through `?? 0` to 25.
  const canonical = scoreCustom({ active_exploitation: 'confirmed', cisa_kev: true });
  assert.equal(canonical, 45, 'confirmed + cisa_kev = 25 + 20 = 45');
  assert.equal(scoreCustom({ active_exploitation: 'Confirmed', cisa_kev: true }), 45);
  assert.equal(scoreCustom({ active_exploitation: '  CONFIRMED  ', cisa_kev: true }), 45);
  assert.equal(scoreCustom({ active_exploitation: 'SUSPECTED' }), 10);
  // resolveActiveExploitation reports these as recognised (no spurious warning).
  assert.equal(resolveActiveExploitation('Confirmed').recognised, true);
  assert.equal(resolveActiveExploitation('  CONFIRMED  ').normalised, 'confirmed');
});

test('deriveRwepFromFactors() inherits the AE fix on the Shape-A route', () => {
  // Shape A (a boolean present routes through scoreCustom): an out-of-vocab AE
  // inside the factor bag must drop only the AE weight, not poison the score.
  const inVocab = deriveRwepFromFactors({ cisa_kev: true, active_exploitation: 'confirmed', blast_radius: 10 });
  assert.equal(inVocab, 55, '25 + 20 + 10 = 55');
  const outOfVocab = deriveRwepFromFactors({ cisa_kev: true, active_exploitation: 'exploited', blast_radius: 10 });
  assert.equal(outOfVocab, 35, '25 + 0 (AE dropped) + 10 = 35 — observable via process warning');
});

// ---------- 4. activeExploitationMultiplier(): bare-number call path ----------
// resolveActiveExploitation returns the structured {multiplier, recognised,
// normalised}; activeExploitationMultiplier is the bare-number wrapper the
// production scoreCustom path calls. Both are exported and tested directly so
// the no-match -> observable-warning contract is pinned at the unit level, not
// only through scoreCustom integration.

test('activeExploitationMultiplier maps canonical + stray-cased values to the ladder, unknowns to 0', () => {
  // Canonical and case/whitespace variants resolve to the same non-zero weight.
  const confirmed = activeExploitationMultiplier('confirmed');
  assert.equal(typeof confirmed, 'number');
  assert.ok(confirmed > 0, 'a recognised active_exploitation must contribute a non-zero multiplier');
  assert.equal(activeExploitationMultiplier(' CONFIRMED '), confirmed,
    'a stray-cased / padded canonical value must normalise to the same multiplier, not zero');

  // null/undefined are the documented "treated as none" default (recognised, 0).
  const none = resolveActiveExploitation(null);
  assert.equal(none.recognised, true);
  assert.equal(none.normalised, 'none');

  // An out-of-vocabulary value is UNRECOGNISED and contributes 0.
  const r = resolveActiveExploitation('in-the-wild');
  assert.equal(r.recognised, false, 'an out-of-vocab active_exploitation must be flagged unrecognised');
  assert.equal(r.multiplier, 0);
  assert.equal(activeExploitationMultiplier('in-the-wild'), 0,
    'the bare-number path returns 0 for an unrecognised value (and emits a process warning)');
});
