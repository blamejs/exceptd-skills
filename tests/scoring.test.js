'use strict';

/**
 * Tests for lib/scoring.js — RWEP scoring engine.
 * Runs under: node --test tests/
 * No external dependencies. Reads the real data/cve-catalog.json.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const scoring = require('../lib/scoring.js');
const catalog = require('../data/cve-catalog.json');

const {
  score,
  scoreCustom,
  timeline,
  compare,
  validate,
  validateFactors,
  deriveRwepFromFactors,
  resolveActiveExploitation,
  activeExploitationMultiplier,
  RWEP_WEIGHTS,
  RECOGNISED_POST_WEIGHT_KEYS,
  RECOGNISED_FACTOR_KEYS,
} = scoring;

const ROOT = path.join(__dirname, '..');

// ---------- RWEP_WEIGHTS sanity ----------

test('RWEP_WEIGHTS matches the documented formula', () => {
  assert.equal(RWEP_WEIGHTS.cisa_kev, 25);
  assert.equal(RWEP_WEIGHTS.poc_available, 20);
  assert.equal(RWEP_WEIGHTS.ai_factor, 15);
  assert.equal(RWEP_WEIGHTS.active_exploitation, 20);
  assert.equal(RWEP_WEIGHTS.blast_radius, 30);
  assert.equal(RWEP_WEIGHTS.patch_available, -15);
  assert.equal(RWEP_WEIGHTS.live_patch_available, -10);
  assert.equal(RWEP_WEIGHTS.reboot_required, 5);
});

// ---------- score(cveId, catalog) ----------

test('score() returns stored rwep_score for known CVE', () => {
  assert.equal(score('CVE-2026-31431', catalog), 90);
});

test('score() throws on unknown CVE', () => {
  assert.throws(() => score('CVE-9999-99999', catalog), /not in catalog/);
});

// ---------- scoreCustom() formula correctness ----------

test('scoreCustom() reproduces Copy Fail (CVE-2026-31431) at 90', () => {
  const s = scoreCustom({
    cisa_kev: true,
    poc_available: true,
    ai_discovered: true,
    active_exploitation: 'confirmed',
    blast_radius: 30,
    patch_available: true,
    live_patch_available: true,
    reboot_required: true
  });
  // 25 + 20 + 15 + 20 + 30 - 15 - 10 + 5 = 90
  assert.equal(s, 90);
});

test('scoreCustom() reproduces Copilot prompt-injection (CVE-2025-53773) at 30 — below CVSS-equivalent of 78', () => {
  // v0.12.6: CVE-2025-53773 CVSS corrected 9.6 → 7.8 (AV:N → AV:L per NVD). blast_radius
  // dropped 22 → 10 because the exploit is local-vector (developer-side IDE interaction;
  // the attacker doesn't reach in over the network). RWEP recomputed accordingly.
  const s = scoreCustom({
    cisa_kev: false,
    poc_available: true,
    ai_assisted_weapon: true,
    active_exploitation: 'suspected',
    blast_radius: 10,
    patch_available: true,
    live_patch_available: true,
    reboot_required: false
  });
  // 0 + 20 + 15 + 10 + 10 - 15 - 10 + 0 = 30
  assert.equal(s, 30);
  // CVSS 7.8 → cvssEquivalent 78 — RWEP still lower than the CVSS-equivalent ceiling
  assert.ok(s < 78, 'RWEP should be lower than CVSS-equivalent for prompt-injection CVE (patch + live-patch reduce RWEP substantially)');
});

test('scoreCustom() reproduces Dirty Frag (CVE-2026-43284) at 38', () => {
  const s = scoreCustom({
    cisa_kev: false,
    poc_available: true,
    ai_discovered: false,
    active_exploitation: 'suspected',
    blast_radius: 18,
    patch_available: true,
    live_patch_available: false,
    reboot_required: true
  });
  // 0 + 20 + 0 + 10 + 18 - 15 - 0 + 5 = 38
  assert.equal(s, 38);
});

test('scoreCustom() default factors return 0 (no signals)', () => {
  assert.equal(scoreCustom({}), 0);
});

test('scoreCustom() clamps to [0, 100] on extreme inputs', () => {
  // Way over 100
  const high = scoreCustom({
    cisa_kev: true, poc_available: true, ai_discovered: true,
    active_exploitation: 'confirmed', blast_radius: 30,
    patch_available: false, live_patch_available: false, reboot_required: true
  });
  assert.ok(high <= 100, `clamp upper bound violated: ${high}`);
  assert.equal(high, 100);

  // Force a strongly negative base; result must clamp to 0
  const low = scoreCustom({
    cisa_kev: false, poc_available: false, ai_discovered: false,
    active_exploitation: 'none', blast_radius: 0,
    patch_available: true, live_patch_available: true, reboot_required: false
  });
  // 0 - 15 - 10 + 0 = -25 → clamp to 0
  assert.equal(low, 0);
});

test('scoreCustom() caps blast_radius at the weight ceiling of 30', () => {
  const s = scoreCustom({ blast_radius: 999 });
  // Only blast contributes; should max out at 30
  assert.equal(s, 30);
});

test('scoreCustom() honours blast_radius of 0', () => {
  const s = scoreCustom({ blast_radius: 0, cisa_kev: true });
  assert.equal(s, 25);
});

test('scoreCustom() suspected exploitation contributes half of confirmed', () => {
  const confirmed = scoreCustom({ active_exploitation: 'confirmed' });
  const suspected = scoreCustom({ active_exploitation: 'suspected' });
  const none = scoreCustom({ active_exploitation: 'none' });
  assert.equal(confirmed, 20);
  assert.equal(suspected, 10);
  assert.equal(none, 0);
});

test('scoreCustom() ai_factor fires from either ai_discovered or ai_assisted_weapon', () => {
  const a = scoreCustom({ ai_discovered: true });
  const b = scoreCustom({ ai_assisted_weapon: true });
  const both = scoreCustom({ ai_discovered: true, ai_assisted_weapon: true });
  assert.equal(a, 15);
  assert.equal(b, 15);
  // NOTE: ai_factor is not double-counted when both flags are true (current code uses ||).
  assert.equal(both, 15);
});

test('scoreCustom() tolerates missing fields without throwing', () => {
  assert.doesNotThrow(() => scoreCustom({}));
  assert.doesNotThrow(() => scoreCustom({ cisa_kev: true })); // others default
});

// ---------- Every catalog entry validates against the formula within ±5 ----------

test('Every catalog entry has stored rwep_score within ±5 of formula-computed score', () => {
  for (const [cveId, e] of Object.entries(catalog)) {
    if (cveId.startsWith('_')) continue;
    const computed = scoreCustom({
      cisa_kev: e.cisa_kev,
      poc_available: e.poc_available,
      ai_assisted_weapon: e.ai_assisted_weaponization || false,
      ai_discovered: e.ai_discovered || false,
      active_exploitation: e.active_exploitation,
      blast_radius: e.rwep_factors ? e.rwep_factors.blast_radius : 0,
      patch_available: e.patch_available,
      live_patch_available: e.live_patch_available,
      reboot_required: e.patch_required_reboot
    });
    const delta = Math.abs(computed - e.rwep_score);
    assert.ok(delta <= 5, `${cveId}: stored ${e.rwep_score} vs computed ${computed} (delta ${delta})`);
  }
});

// ---------- timeline() bucketing ----------

test('timeline() returns the immediate-action bucket for RWEP >= 90', () => {
  const t = timeline(90);
  assert.equal(t.hours, 4);
  assert.match(t.label, /Immediate/);
});

test('timeline() returns 24h bucket for 75 <= rwep < 90', () => {
  assert.equal(timeline(75).hours, 24);
  assert.equal(timeline(89).hours, 24);
});

test('timeline() returns the low/no-rush bucket for very low scores', () => {
  const t = timeline(5);
  assert.equal(t.hours, null);
  assert.match(t.label, /Low/);
});

test('timeline() boundary at 60 maps to 72h, 40 to 7-day, 20 to 30-day', () => {
  assert.equal(timeline(60).hours, 72);
  assert.equal(timeline(40).hours, 168);
  assert.equal(timeline(20).hours, 720);
});

// ---------- compare() ----------

test('compare() flags Copy Fail as RWEP-significantly-higher-than-CVSS-equivalent (band tightened to ±10 in audit J F15)', () => {
  const r = compare('CVE-2026-31431', catalog);
  assert.equal(r.cve_id, 'CVE-2026-31431');
  assert.equal(r.cvss, 7.8);
  assert.equal(r.rwep, 90);
  // cvssEquivalent = 78; delta = 90 - 78 = 12 → above the new ±10 band → "significantly higher".
  // The old ±20 band swallowed this divergence (the operator-facing point is that the
  // CVSS-calibrated SLA is insufficient); narrowing the band surfaces the gap explicitly.
  assert.equal(r.delta, 12);
  assert.match(r.explanation, /significantly higher/);
  assert.equal(r.rwep_actual_sla.hours, 4);
});

test('compare() flags Copilot prompt-injection as RWEP-lower-than-CVSS-equivalent (overscored)', () => {
  // v0.12.6: CVSS corrected 9.6 → 7.8 (AV:N → AV:L per NVD); RWEP recomputed 42 → 30.
  // cvssEquivalent = 78; delta = 30 - 78 = -48; still well below -20 threshold.
  const r = compare('CVE-2025-53773', catalog);
  assert.equal(r.cvss, 7.8);
  assert.equal(r.rwep, 30);
  assert.equal(r.delta, -48);
  assert.match(r.explanation, /lower than CVSS equivalent/);
});

test('compare() throws on unknown CVE', () => {
  assert.throws(() => compare('CVE-0000-0000', catalog), /not in catalog/);
});

// ---------- validate() ----------

test('validate() returns no errors for the shipping catalog', () => {
  const errors = validate(catalog);
  assert.deepEqual(errors, [], `Catalog validation errors:\n  ${errors.join('\n  ')}`);
});

test('validate() ignores keys that start with underscore (metadata)', () => {
  const errs = validate({ _meta: { version: 'x' } });
  assert.deepEqual(errs, []);
});

test('validate() rejects an entry missing required fields', () => {
  const partial = {
    'CVE-TEST-0001': {
      type: 'LPE',
      cvss_score: 7.0
      // every other required field intentionally missing
    }
  };
  const errs = validate(partial);
  // Many missing-field complaints expected, plus a divergence complaint
  assert.ok(errs.length > 0, 'expected at least one validation error');
  assert.ok(errs.some(e => e.includes("missing required field")), 'expected missing-field errors');
});

test('validate() flags poc_available without poc_description', () => {
  const bad = {
    'CVE-TEST-0002': {
      type: 'LPE', cvss_score: 7, cvss_vector: 'x', cisa_kev: false,
      poc_available: true, poc_description: '',
      ai_discovered: false, active_exploitation: 'none',
      affected: 'x', patch_available: true, patch_required_reboot: false,
      live_patch_available: false, live_patch_tools: [],
      rwep_score: 5, rwep_factors: { blast_radius: 0 },
      atlas_refs: [], attack_refs: [],
      source_verified: '2026-01-01', verification_sources: [], last_updated: '2026-01-01'
    }
  };
  const errs = validate(bad);
  assert.ok(errs.some(e => /poc_description is empty/.test(e)), `got: ${errs.join('|')}`);
});

test('validate() flags live_patch_available without live_patch_tools', () => {
  const bad = {
    'CVE-TEST-0003': {
      type: 'LPE', cvss_score: 7, cvss_vector: 'x', cisa_kev: false,
      poc_available: false, ai_discovered: false, active_exploitation: 'none',
      affected: 'x', patch_available: true, patch_required_reboot: false,
      live_patch_available: true, live_patch_tools: [],
      rwep_score: 0, rwep_factors: { blast_radius: 0 },
      atlas_refs: [], attack_refs: [],
      source_verified: '2026-01-01', verification_sources: [], last_updated: '2026-01-01'
    }
  };
  const errs = validate(bad);
  assert.ok(errs.some(e => /live_patch_tools is empty/.test(e)), `got: ${errs.join('|')}`);
});

test('validate() flags rwep_score that diverges from the formula by more than 5', () => {
  const bad = {
    'CVE-TEST-0004': {
      type: 'LPE', cvss_score: 7, cvss_vector: 'x', cisa_kev: false,
      poc_available: false, ai_discovered: false, active_exploitation: 'none',
      affected: 'x', patch_available: true, patch_required_reboot: false,
      live_patch_available: false, live_patch_tools: [],
      rwep_score: 99, // way off; formula would produce -15
      rwep_factors: { blast_radius: 0 },
      atlas_refs: [], attack_refs: [],
      source_verified: '2026-01-01', verification_sources: [], last_updated: '2026-01-01'
    }
  };
  const errs = validate(bad);
  assert.ok(errs.some(e => /diverges from calculated/.test(e)), `got: ${errs.join('|')}`);
});

test('scoreCustom counts the AI factor from the catalog field name ai_assisted_weaponization', () => {
  // A factor bag built straight from a catalog entry carries
  // `ai_assisted_weaponization` (the field the catalog declares), not the
  // legacy `ai_assisted_weapon`. Pre-fix scoreCustom only read the legacy
  // name, so the +15 AI factor was silently dropped for every such bag.
  const base = { cisa_kev: false, poc_available: false, active_exploitation: 'none', blast_radius: 0 };
  const withAi = scoring.scoreCustom({ ...base, ai_assisted_weaponization: true });
  const withoutAi = scoring.scoreCustom({ ...base });
  assert.equal(withAi - withoutAi, scoring.RWEP_WEIGHTS.ai_factor,
    'ai_assisted_weaponization:true must add exactly the ai_factor weight');
  // The legacy name still works, and validateFactors does not spuriously warn
  // the catalog field is "missing".
  assert.equal(scoring.scoreCustom({ ...base, ai_assisted_weapon: true }) - withoutAi,
    scoring.RWEP_WEIGHTS.ai_factor, 'legacy ai_assisted_weapon still counts');
  const warns = scoring.validateFactors({
    ...base, ai_assisted_weaponization: true, cisa_kev: false, poc_available: false,
    ai_discovered: false, patch_available: false, live_patch_available: false, reboot_required: false,
  });
  assert.ok(!warns.some(w => w.includes('ai_assisted_weapon: missing')),
    'ai_assisted_weaponization must satisfy the ai_assisted_weapon presence check');
});

test('compare guards an absent/non-numeric rwep_score instead of emitting delta:NaN + false alignment', () => {
  // No rwep_score must not flow into delta (NaN) and must not fall through to
  // the "broadly aligned" arm — the same hardening the CVSS side already had.
  const r = scoring.compare('CVE-X', { 'CVE-X': { cvss_score: 5 } });
  assert.equal(r.rwep, null, 'absent rwep must serialize as null, not NaN/undefined');
  assert.equal(r.delta, null, 'delta must be null (not NaN) when rwep is unusable');
  assert.match(r.explanation, /absent or non-numeric/);
  assert.notEqual(r.explanation, 'CVSS and RWEP are broadly aligned for this CVE.');
  assert.equal(r.rwep_actual_sla.hours, null, 'no bogus SLA for an absent rwep');
});

// ==========================================================================
// compare() / deriveRwepFromFactors regression pins (cvss_framework_sla
// fabrication + Shape-B unknown-key filter).
// ==========================================================================

// --------------------------------------------------------------------------
// #6 — cvss_framework_sla must not be fabricated when CVSS is absent.
// --------------------------------------------------------------------------

test('#6 compare() does not fabricate a cvss_framework_sla when CVSS is absent', () => {
  const r = compare('C', {
    C: {
      rwep_score: 95,
      active_exploitation: 'confirmed',
      rwep_factors: { blast_radius: 30 },
    },
  });

  // CVSS genuinely absent.
  assert.equal(r.cvss, null);

  // Presence AND content: the SLA object exists, its hours are null, and its
  // label states CVSS is unavailable — NOT the timeline(0) "Low / next
  // scheduled maintenance" bucket the pre-fix code emitted.
  assert.equal(typeof r.cvss_framework_sla, 'object');
  assert.notEqual(r.cvss_framework_sla, null);
  assert.equal(r.cvss_framework_sla.hours, null);
  assert.match(r.cvss_framework_sla.label, /CVSS unavailable/i);
  assert.equal(/next scheduled maintenance/i.test(r.cvss_framework_sla.label), false);

  // The RWEP-side SLA still resolves to the real bucket for rwep_score 95.
  assert.equal(r.rwep_actual_sla.hours, 4);
  assert.match(r.rwep_actual_sla.label, /Immediate/i);

  // delta is null (not-comparable) when there is no CVSS — unchanged behavior.
  assert.equal(r.delta, null);
});

test('#6 a real cvss_score: 0 still maps to the genuine Low bucket (fix gates only on absence)', () => {
  const r = compare('C', {
    C: {
      cvss_score: 0,
      rwep_score: 95,
      active_exploitation: 'confirmed',
      rwep_factors: { blast_radius: 30 },
    },
  });

  // A real 0.0 CVSS is present, not absent.
  assert.equal(r.cvss, 0);

  // It must resolve to the genuine timeline(0) Low bucket — the fix must NOT
  // touch the present-cvss path, only the absent one.
  const low = timeline(0);
  assert.equal(r.cvss_framework_sla.hours, low.hours);
  assert.equal(r.cvss_framework_sla.label, low.label);
  assert.equal(/CVSS unavailable/i.test(r.cvss_framework_sla.label), false);
});

test('#6 a real high cvss_score still maps to its real bucket (no regression)', () => {
  const r = compare('C', {
    C: {
      cvss_score: 9.8, // -> cvssEquivalent 98 -> timeline(98) Immediate (4h)
      rwep_score: 95,
      active_exploitation: 'confirmed',
      rwep_factors: { blast_radius: 30 },
    },
  });
  assert.equal(r.cvss, 9.8);
  assert.equal(r.cvss_framework_sla.hours, 4);
  assert.match(r.cvss_framework_sla.label, /Immediate/i);
  // delta is now a real number, not null.
  assert.equal(typeof r.delta, 'number');
});

// --------------------------------------------------------------------------
// #8 — deriveRwepFromFactors Shape-B must ignore unrecognised keys.
// --------------------------------------------------------------------------

test('#8 deriveRwepFromFactors Shape-B sums only recognised keys', () => {
  // Baseline: a clean recognised bag.
  assert.equal(deriveRwepFromFactors({ cisa_kev: 25, blast_radius: 10 }), 35);
});

test('#8 a typo key is excluded from the derived sum, not added', () => {
  // Pre-fix: cisa_kevv:25 was blindly summed -> 60. Post-fix: dropped -> 35.
  assert.equal(
    deriveRwepFromFactors({ cisa_kev: 25, cisa_kevv: 25, blast_radius: 10 }),
    35,
    'a typo key must not be summed',
  );
});

test('#8 verifier-hint case: typo excluded, ai_factor preserved', () => {
  // cisa_kev 25 + ai_factor 15 + blast_radius 10 = 50; reboot_requiredd 5 is a
  // typo and must be excluded. This is the exact case from the refined fix.
  assert.equal(
    deriveRwepFromFactors({
      cisa_kev: 25,
      ai_factor: 15,
      blast_radius: 10,
      reboot_requiredd: 5,
    }),
    50,
  );
});

test('#8 ai_factor (the catalog post-weight AI key) is NOT silently dropped', () => {
  // ai_factor is ABSENT from RECOGNISED_FACTOR_KEYS but present in
  // RECOGNISED_POST_WEIGHT_KEYS. A naive RECOGNISED_FACTOR_KEYS-only filter
  // would drop the +15 AI weight from every Shape-B derivation. Prove it
  // contributes its full 15.
  assert.equal(RECOGNISED_FACTOR_KEYS.has('ai_factor'), false);
  assert.equal(RECOGNISED_POST_WEIGHT_KEYS.has('ai_factor'), true);

  const withAi = deriveRwepFromFactors({ cisa_kev: 25, ai_factor: 15, blast_radius: 10 });
  const withoutAi = deriveRwepFromFactors({ cisa_kev: 25, blast_radius: 10 });
  assert.equal(withAi, 50);
  assert.equal(withoutAi, 35);
  assert.equal(withAi - withoutAi, 15, 'ai_factor must contribute its full +15');
});

test('#8 the unrecognised key emits an observable RWEP_FACTOR_UNRECOGNISED warning', async () => {
  // Node dispatches process warnings on the 'warning' event one tick after
  // emitWarning, and dedupes identical warnings process-wide. Use a key name
  // unique to this test so a duplicate emission from another case cannot have
  // been already-deduped before this listener attaches.
  const uniqueKey = `bogus_warn_probe_${process.pid}_${Date.now()}`;
  const seen = [];
  const handler = (w) => { seen.push(w); };
  process.on('warning', handler);
  try {
    deriveRwepFromFactors({ cisa_kev: 25, [uniqueKey]: 99, blast_radius: 10 });
    // Yield a macrotask so the queued 'warning' event is delivered before we assert.
    await new Promise((resolve) => setImmediate(resolve));
    const match = seen.find(
      (w) => w && w.code === 'RWEP_FACTOR_UNRECOGNISED' && w.message.includes(uniqueKey),
    );
    assert.ok(match, 'expected an RWEP_FACTOR_UNRECOGNISED warning naming the bogus key');
    assert.equal(match.name, 'RwepFactorUnrecognised');
  } finally {
    process.removeListener('warning', handler);
  }
});

test('#8 curation-apply parity: a typo post-weight key does not inflate the derived rwep_score', () => {
  // cve-curation.js derives entry.rwep_score via
  // deriveRwepFromFactors(entry.rwep_factors) when rwep_factors is supplied
  // without an explicit rwep_score. A typo'd key in that bag must NOT inflate
  // the derived score — it lands excluded, exactly as scoreCustom/validateFactors
  // treat an unknown key. This is the root-cause behavior the curation path relies on.
  const factorsWithTypo = {
    cisa_kev: 25,
    poc_available: 20,
    ai_factor: 15,
    blast_radius: 20,
    patch_avilable: -15, // typo for patch_available — must be excluded
  };
  const factorsClean = {
    cisa_kev: 25,
    poc_available: 20,
    ai_factor: 15,
    blast_radius: 20,
  };
  // The typo must not be applied: the derived score equals the clean-bag score,
  // NOT clean - 15 (the value the typo would have contributed had it been summed).
  assert.equal(deriveRwepFromFactors(factorsWithTypo), deriveRwepFromFactors(factorsClean));
  assert.equal(deriveRwepFromFactors(factorsWithTypo), 80);
});

test('#8 recognised aliases (patch_required_reboot, ai_assisted_weaponization) still sum', () => {
  // These catalog field names ARE recognised post-weight keys; a clean bag
  // using them must not be dropped by the new filter.
  // reboot_required +5 (no patch_required_reboot present to dedupe against).
  assert.equal(deriveRwepFromFactors({ cisa_kev: 25, reboot_required: 5 }), 30);
  // patch_required_reboot alone (the catalog alias) +5.
  assert.equal(deriveRwepFromFactors({ cisa_kev: 25, patch_required_reboot: 5 }), 30);
  // Both present: the reboot weight counts once (alias dedupe preserved).
  assert.equal(
    deriveRwepFromFactors({ cisa_kev: 25, reboot_required: 5, patch_required_reboot: 5 }),
    30,
  );
});

test('#8 blast_radius per-factor clamp is preserved alongside the unknown-key filter', () => {
  // An out-of-range blast_radius (unit error) is still clamped to the weight
  // ceiling (30), and an unknown key alongside it is still excluded.
  assert.equal(
    deriveRwepFromFactors({ blast_radius: 300, bogus: 7 }),
    30,
    'blast_radius clamp + unknown-key exclusion both apply',
  );
});

// ==========================================================================
// RWEP-scoring contract edges: compare() absent-cvss, scoreCustom()
// non-number blast_radius rejection, validate() Shape-B reboot alias
// coherence, out-of-vocab active_exploitation handling.
// ==========================================================================

// ---------- 1. compare(): absent cvss_score ----------

test('compare() with absent cvss_score key emits a finite delta, never NaN', () => {
  const cid = 'CVE-TEST-NO-CVSS';
  const catalogLocal = {
    [cid]: {
      rwep_score: 60,
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
      // cvss_score key intentionally absent
    },
  };
  const r = compare(cid, catalogLocal, {});

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
  const catalogLocal = {
    [cid]: {
      rwep_score: 55,
      cvss_score: null,
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
    },
  };
  const r = compare(cid, catalogLocal, {});
  assert.equal(Number.isNaN(r.delta), false);
  assert.equal(r.delta, null);
  assert.equal(/broadly aligned/i.test(r.explanation), false);
  assert.match(r.explanation, /CVSS absent/i);
});

test('compare() with a real numeric cvss_score still computes a numeric delta', () => {
  // Regression guard: the absent-cvss arm must not perturb the normal path.
  const cid = 'CVE-TEST-NUMERIC-CVSS';
  const catalogLocal = {
    [cid]: {
      rwep_score: 60,
      cvss_score: 5.0, // equivalent 50; delta = 60 - 50 = 10 => "broadly aligned"
      active_exploitation: 'none',
      rwep_factors: { blast_radius: 10 },
    },
  };
  const r = compare(cid, catalogLocal, {});
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

// ==========================================================================
// RWEP scorer alias + explanation consistency.
//
// The three scoring surfaces — scoreCustom/deriveRwepFromFactors (the numbers),
// validateFactors (the linter), and compare() (the human explanation) — must
// agree on the same aliases and normalization, or a CVE is scored one way and
// described/validated another.
// ==========================================================================

test('E4: deriveRwepFromFactors counts the reboot alias once (no double-count)', () => {
  const one = deriveRwepFromFactors({ cisa_kev: 25, reboot_required: 5, blast_radius: 0 });
  const both = deriveRwepFromFactors({ cisa_kev: 25, reboot_required: 5, patch_required_reboot: 5, blast_radius: 0 });
  assert.equal(one, 30, 'single reboot key => 30');
  assert.equal(both, 30, 'both reboot keys must still be 30 (alias counted once), not 35');
});

test('E2: validateFactors accepts a stray-cased active_exploitation the scorer accepts', () => {
  for (const v of ['Confirmed', ' confirmed ', 'CONFIRMED']) {
    const warns = validateFactors({ active_exploitation: v });
    assert.ok(!warns.some(w => w.includes('active_exploitation: expected')),
      `validateFactors must not flag normalized ${JSON.stringify(v)} that scoreCustom consumes`);
  }
  // A genuinely out-of-vocab value is still flagged.
  assert.ok(validateFactors({ active_exploitation: 'in-the-wild' }).some(w => w.includes('active_exploitation: expected')),
    'an out-of-vocab value must still be flagged');
});

test('E3: validateFactors treats patch_required_reboot as satisfying reboot_required', () => {
  const warns = validateFactors({ patch_required_reboot: true });
  assert.ok(!warns.some(w => w.startsWith('reboot_required: missing')),
    'the patch_required_reboot alias must satisfy reboot_required, not warn missing');
});

test('E1: compare() explanation lists the AI factor for ai_assisted_weaponization (not only ai_discovered)', () => {
  const e = {
    cve_id: 'X', rwep_score: 90, cvss_score: 6, active_exploitation: 'none',
    cisa_kev: false, poc_available: false, ai_discovered: false, ai_assisted_weaponization: true,
    patch_available: false, live_patch_available: false, patch_required_reboot: false,
    rwep_factors: { blast_radius: 30 },
  };
  const r = compare('X', { X: e });
  assert.match(r.explanation, /AI-discovered/,
    'an ai_assisted_weaponization-driven delta must surface the AI factor in the explanation');
});

// ==========================================================================
// compare() no-scoring-signal branch.
// ==========================================================================

test('F7: lib/scoring.js compare() surfaces "no scoring signal" when rwep+cvss are zero', () => {
  // compare() takes the catalog map directly (cveId -> entry).
  const stubCatalog = {
    'CVE-TEST-NO-SIGNAL': {
      cvss_score: 0,
      rwep_score: 0,
      rwep_factors: {},
      cisa_kev: false,
      poc_available: false,
      ai_discovered: false,
      active_exploitation: 'none',
      patch_available: false,
    },
  };
  const r = compare('CVE-TEST-NO-SIGNAL', stubCatalog);
  assert.ok(r, 'compare() must return a result');
  assert.match(r.explanation, /No scoring signal/i,
    `expected "no scoring signal" branch; got: ${r.explanation}`);
});

// ==========================================================================
// scoreCustom() reboot alias equivalence + validate() recompute mirroring.
// ==========================================================================

test('scoreCustom honors the reboot alias identically — the property scoring.validate() now mirrors', () => {
  // A base where the reboot factor is observable (not clamped at 0 or 100).
  const base = {
    cisa_kev: true, poc_available: true, ai_assisted_weapon: false, ai_discovered: false,
    active_exploitation: 'none', blast_radius: 3, patch_available: false, live_patch_available: false,
  };
  const viaReboot = scoreCustom({ ...base, reboot_required: true });
  const viaPatchReboot = scoreCustom({ ...base, patch_required_reboot: true });
  const noReboot = scoreCustom({ ...base });
  assert.equal(viaReboot, viaPatchReboot, 'reboot_required and patch_required_reboot must score identically (the alias)');
  assert.notEqual(viaReboot, noReboot, 'the reboot factor must be non-zero, else the alias is moot'); // allow-notEqual: proves the alias is meaningful, not vacuous

  // validate() previously passed only `entry.patch_required_reboot` to its
  // recompute, dropping a top-level reboot_required and computing a divergent
  // expected RWEP. It now passes `reboot_required || patch_required_reboot`,
  // mirroring the equivalence asserted above.
  const SRC = fs.readFileSync(path.join(ROOT, 'lib', 'scoring.js'), 'utf8');
  assert.match(SRC, /reboot_required:\s*entry\.reboot_required\s*\|\|\s*entry\.patch_required_reboot/,
    'validate() must recompute with the reboot alias, not patch_required_reboot alone');
});

// ==========================================================================
// compare() explanation must mirror scoreCustom's rebootFactor exactly — the
// +5 reboot driver is added whenever a reboot is required, REGARDLESS of
// live_patch_available. Gating the driver on !live_patch_available made the
// enumerated factors sum to less than the delta on entries that both require a
// reboot and have a live patch available.
// ==========================================================================

test('compare() explanation includes the reboot driver even when live_patch_available is true, and factors sum to the delta', () => {
  // CVE-2026-31431 (Copy Fail): rwep 90, cvss 7.8 (equiv 78), delta 12, and the
  // entry has reboot_required(via patch_required_reboot) AND
  // live_patch_available:true. Pre-fix the reboot driver was suppressed, so the
  // enumerated factors summed to 80 (90 - 10 reboot) while the delta was 12.
  const r = compare('CVE-2026-31431', catalog);
  assert.equal(r.delta, 12);
  assert.match(r.explanation, /significantly higher/);
  // The reboot driver MUST be present in the enumerated factors.
  assert.match(r.explanation, /reboot required \(\+5\)/,
    'reboot driver must be listed even when live_patch_available is true');

  // Parse every "(+N)" / "(-N)" magnitude out of the explanation and confirm
  // their signed sum equals the stored delta. This is the load-bearing
  // invariant: the enumerated drivers must account for the whole divergence.
  const e = catalog['CVE-2026-31431'];
  assert.equal(e.live_patch_available, true, 'fixture must have live_patch_available:true');
  assert.equal(e.patch_required_reboot, true, 'fixture must require a reboot');
  // Match each "(+N" / "(-N" magnitude. The AI driver renders as
  // "(+15 weaponization)" so the closing paren is not adjacent to the digits —
  // anchor on the opening paren only.
  const magnitudes = [...r.explanation.matchAll(/\(([+-]\d+)/g)].map((m) => Number(m[1]));
  // Drivers in the "significantly higher" arm are the positive contributors the
  // delta is built from: cisa_kev +25, poc +20, ai +15, confirmed AE +20,
  // blast radius +30, reboot +5 => 115. The blast_radius driver is now
  // enumerated (it was previously omitted from the list even though it
  // contributes to RWEP), so the enumerated total includes its clamped +30.
  // Assert the reboot +5 and blast +30 are both present and the enumerated sum
  // is the full positive-driver total (115), not 80 (dropping reboot) and not
  // 85 (dropping the blast driver).
  assert.ok(magnitudes.includes(5), 'the +5 reboot magnitude must be enumerated');
  assert.ok(magnitudes.includes(30), 'the +30 blast-radius magnitude must be enumerated');
  const enumeratedSum = magnitudes.reduce((a, b) => a + b, 0);
  assert.equal(typeof enumeratedSum, 'number');
  assert.equal(enumeratedSum, 115,
    'enumerated drivers must sum to 115 (incl. reboot +5 and blast +30); dropping reboot gives 80, dropping blast gives 85');
});

// ==========================================================================
// deriveRwepFromFactors: a Shape-B (post-weight) block that ALSO carries a
// string active_exploitation must NOT be misrouted to scoreCustom (which does
// not read the post-weight ai_factor key), dropping the +15 AI weight.
// ==========================================================================

test('deriveRwepFromFactors keeps ai_factor for a Shape-B block with a string active_exploitation', () => {
  // Shape B post-weight integers + a string active_exploitation status.
  // Pre-fix: the string 'confirmed' tripped hasBooleanOrLadder -> routed to
  // scoreCustom -> ai_factor:15 (a post-weight key scoreCustom ignores) dropped.
  const shapeB = {
    cisa_kev: 25,
    poc_available: 20,
    ai_factor: 15,
    active_exploitation: 'confirmed', // string status alongside post-weight ints
    blast_radius: 10,
  };
  const score = deriveRwepFromFactors(shapeB);
  assert.equal(typeof score, 'number');
  // Post-weight sum: 25 + 20 + 15 + 10 = 70 (the string AE is skipped in the
  // sum; the post-weight integer contribution it represents is not double-added).
  assert.equal(score, 70, 'ai_factor (+15) must be preserved — Shape-B routing, not scoreCustom');

  // Proof of the +15: the same block without ai_factor scores exactly 15 less.
  const withoutAi = deriveRwepFromFactors({
    cisa_kev: 25,
    poc_available: 20,
    active_exploitation: 'confirmed',
    blast_radius: 10,
  });
  assert.equal(withoutAi, 55);
  assert.equal(score - withoutAi, 15, 'the ai_factor must contribute its full +15, not be dropped');
});

// ==========================================================================
// detectFactorShape: a Shape-B block carrying a string active_exploitation must
// validate as Shape B, NOT 'mixed'. The string AE form is valid in both shapes.
// ==========================================================================

test('detectFactorShape returns B (not mixed) for a Shape-B block with a string active_exploitation', () => {
  // Build a minimally-complete Shape-B catalog entry whose rwep_factors store
  // post-weight integers AND a string active_exploitation. Pre-fix the string
  // tripped sawBool, producing a 'mixed' verdict and a validate() error.
  const entry = {
    cve_id: 'CVE-TEST-SHAPEB-STR-AE',
    rwep_score: 70,
    cvss_score: 7.0,
    active_exploitation: 'confirmed',
    cisa_kev: true,
    poc_available: true,
    ai_discovered: false,
    ai_assisted_weaponization: true,
    patch_available: false,
    live_patch_available: false,
    patch_required_reboot: false,
    type: 'LPE',
    cvss_vector: 'x',
    affected: 'x',
    poc_description: 'present',
    live_patch_tools: [],
    atlas_refs: [], attack_refs: [],
    source_verified: '2026-01-01', verification_sources: [], last_updated: '2026-01-01',
    rwep_factors: {
      cisa_kev: 25,
      poc_available: 20,
      ai_factor: 15,
      active_exploitation: 'confirmed', // string status in a post-weight block
      blast_radius: 0,
    },
  };
  // No 'mixed' shape error from validate().
  const errs = validate({ 'CVE-TEST-SHAPEB-STR-AE': entry }).filter((e) => /mixes Shape A/.test(e));
  assert.deepEqual(errs, [],
    'a Shape-B block with a string active_exploitation must not be flagged as mixed-shape');
});


// ---- routed from catalog-data-integrity ----
require("node:test").describe("catalog-data-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a catalog data-integrity / curation pass:
 *
 *   - The AI supply-chain families (ShadowMQ, Triton auth-bypass) carry ATLAS
 *     mappings — they were unmapped while sibling family entries carried
 *     AML.T0049 (Hard Rule #7 coherence).
 *   - The active_exploitation "theoretical" status is an explicit entry in the
 *     RWEP scoring ladder (not an incidental `?? 0` fall-through).
 *   - The jurisdiction count is consistent across the stale-content and
 *     catalog-summaries builders and the README badge (all count GLOBAL → 35).
 *   - framework-control-gaps _meta.entry_count matches the actual entry count
 *     (a gate now enforces this).
 *   - Shipped playbook threat_currency_score stays within the documented band.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const cve = require(path.join(ROOT, "data", "cve-catalog.json"));
const atlas = require(path.join(ROOT, "data", "atlas-ttps.json"));
const gaps = require(path.join(ROOT, "data", "framework-control-gaps.json"));
const gf = require(path.join(ROOT, "data", "global-frameworks.json"));
const scoring = require(path.join(ROOT, "lib", "scoring.js"));

test("the RWEP active_exploitation ladder defines 'theoretical' explicitly", () => {
  // Score a factor bag with theoretical exploitation and confirm it's handled
  // deterministically (no NaN / no crash). The exact value is an
  // implementation detail; the point is it's a recognized key.
  const s = scoring.scoreCustom({ active_exploitation: "theoretical", blast_radius: 5 });
  assert.equal(typeof s, "number");
  assert.ok(Number.isFinite(s), "scoring a theoretical-exploitation factor bag must be finite");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});

require("node:test").describe("scoring: active-exploitation-only Shape A bag (codex P2 round-2)", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const s = require("../lib/scoring.js");
  test("deriveRwepFromFactors routes an active_exploitation-only raw bag to scoreCustom, not the Shape-B sum that drops the ladder", () => {
    // hasPostWeightInt is false (no boolean-named integer >=5), so this is Shape A
    // and must score via scoreCustom (active_exploitation 'confirmed' = +20). The
    // Shape-B sum would skip the string and under-score it.
    const ae = s.deriveRwepFromFactors({ active_exploitation: "confirmed", blast_radius: 10 });
    assert.equal(ae, 30, `active_exploitation 'confirmed' (+20) + blast_radius 10 must score 30, not ~10; got ${ae}`);
  });
  test("a Shape-B post-weight block with a string active_exploitation still sums its weighted factors (F4 preserved)", () => {
    const withAi = s.deriveRwepFromFactors({ cisa_kev: 25, ai_factor: 15, active_exploitation: "confirmed", blast_radius: 0 });
    const noAi = s.deriveRwepFromFactors({ cisa_kev: 25, active_exploitation: "confirmed", blast_radius: 0 });
    assert.equal(withAi - noAi, 15, "the post-weight ai_factor must be summed, not dropped");
  });
});

require("node:test").describe("compare() driving-factors enumeration: suspected/unknown AE + blast driver, no dangling list", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const s = require("../lib/scoring.js");

  test("compare() lists a SUSPECTED active_exploitation (+10) AND blast radius (+N) as delta drivers", () => {
    // The driving-factors list previously enumerated active_exploitation only
    // for the 'confirmed' (+20) ladder rung and never listed blast_radius at
    // all. A delta>10 driven by SUSPECTED exploitation (+10 via the 0.5
    // multiplier) plus a positive blast_radius then either showed those drivers
    // missing or — on a purely suspected/blast-driven entry — left a dangling
    // "Factors driving delta: ." Build such an entry and pin both drivers by name.
    const entry = {
      cve_id: "CVE-TEST-DRIVE-1",
      cvss_score: 5.0, // cvssEquivalent 50
      rwep_score: 80, // delta = 80 - 50 = 30 (> 10)
      active_exploitation: "suspected",
      rwep_factors: { blast_radius: 25 },
    };
    const out = s.compare("CVE-TEST-DRIVE-1", { "CVE-TEST-DRIVE-1": entry });

    // delta must be the real divergence the drivers explain.
    assert.equal(out.delta, 30);
    assert.match(out.explanation, /significantly higher/);

    // The SUSPECTED rung (20 * 0.5 = 10) is named with its actual contribution —
    // not silently dropped because it is not 'confirmed'.
    assert.match(
      out.explanation,
      /suspected exploitation \(\+10\)/,
      "suspected AE must be enumerated as 'suspected exploitation (+10)', not omitted",
    );
    // blast_radius is a first-class driver and lists its clamped contribution.
    assert.match(
      out.explanation,
      /blast radius \(\+/,
      "a positive blast_radius must appear as 'blast radius (+N)'",
    );
    // The exact clamped magnitude for blast_radius 25 (<= the 30 ceiling) is +25.
    assert.match(out.explanation, /blast radius \(\+25\)/);
  });

  test("compare() enumerates an UNKNOWN active_exploitation (+5) rung, not only 'confirmed'", () => {
    // The 'unknown' rung resolves to 20 * 0.25 = 5 — another rung the
    // confirmed-only enumeration dropped. Pin it lands as "unknown exploitation (+5)".
    const entry = {
      cve_id: "CVE-TEST-DRIVE-UNK",
      cvss_score: 3.0, // cvssEquivalent 30
      rwep_score: 60, // delta = 30 (> 10)
      active_exploitation: "unknown",
      rwep_factors: { blast_radius: 20 },
    };
    const out = s.compare("CVE-TEST-DRIVE-UNK", { "CVE-TEST-DRIVE-UNK": entry });
    assert.equal(out.delta, 30);
    assert.match(
      out.explanation,
      /unknown exploitation \(\+5\)/,
      "unknown AE must be enumerated as 'unknown exploitation (+5)'",
    );
    assert.match(out.explanation, /blast radius \(\+20\)/);
  });

  test("compare() with blast as the ONLY driver enumerates it (no dangling 'driving delta: .')", () => {
    // delta>10 driven solely by blast_radius — no KEV, PoC, AI, or AE signal.
    // The list must name blast radius, never emit an empty "Factors driving
    // delta: ." with nothing after the colon.
    const entry = {
      cve_id: "CVE-TEST-DRIVE-BLAST",
      cvss_score: 2.0, // cvssEquivalent 20
      rwep_score: 50, // delta = 30 (> 10)
      active_exploitation: "none", // no AE driver
      cisa_kev: false,
      poc_available: false,
      ai_discovered: false,
      ai_assisted_weaponization: false,
      rwep_factors: { blast_radius: 30 },
    };
    const out = s.compare("CVE-TEST-DRIVE-BLAST", { "CVE-TEST-DRIVE-BLAST": entry });
    assert.equal(out.delta, 30);
    assert.match(out.explanation, /blast radius \(\+30\)/);

    // The text between "driving delta: " and the closing sentence must be
    // non-empty — a dangling list would leave it blank.
    const m = out.explanation.match(/driving delta:\s*(.+?)\.\s+Framework patch SLAs/);
    assert.ok(m, "the driving-factors clause must be present and terminated");
    assert.ok(
      m[1] && m[1].trim().length > 0,
      `the enumerated driver text must be non-empty, got: ${JSON.stringify(m && m[1])}`,
    );
    // Specifically it must NOT be a bare empty list (the dangling-"." regression).
    assert.equal(
      /Factors driving delta:\s*\./.test(out.explanation),
      false,
      "must never emit a dangling 'Factors driving delta: .' with no driver",
    );
  });

  test("compare() never leaves a dangling driver list even when NO factor is enumerable (structural fallback)", () => {
    // delta>10 from a stored rwep_score with an empty factor bag and no flags:
    // there is literally nothing to enumerate, so the structural fallback string
    // must fill the list rather than leaving "driving delta: ." dangling.
    const entry = {
      cve_id: "CVE-TEST-DRIVE-EMPTY",
      cvss_score: 2.0, // cvssEquivalent 20
      rwep_score: 50, // delta = 30 (> 10)
      active_exploitation: "none",
      cisa_kev: false,
      poc_available: false,
      ai_discovered: false,
      ai_assisted_weaponization: false,
      patch_required_reboot: false,
      reboot_required: false,
      rwep_factors: { blast_radius: 0 },
    };
    const out = s.compare("CVE-TEST-DRIVE-EMPTY", { "CVE-TEST-DRIVE-EMPTY": entry });
    assert.equal(out.delta, 30);
    assert.match(
      out.explanation,
      /structural RWEP factors/,
      "an un-enumerable positive delta must name the structural fallback, not dangle",
    );
    assert.equal(
      /Factors driving delta:\s*\./.test(out.explanation),
      false,
      "the structural fallback must not collapse to a dangling 'driving delta: .'",
    );
  });
});
