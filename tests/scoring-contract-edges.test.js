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
