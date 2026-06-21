'use strict';

// Regression tests for two confirmed scoring.js bugs:
//
//   #6  compare() fabricated a "Low / next scheduled maintenance"
//       cvss_framework_sla when the CVE has no CVSS (the coercion of an absent
//       cvss to 0 for safe delta arithmetic leaked into the operator-facing SLA
//       field). The field was present but its content was derived from a
//       nonexistent input — the field-present != field-populated class.
//
//   #8  deriveRwepFromFactors' Shape-B (catalog post-weight) summation added ANY
//       numeric key, so a typo'd / unknown key silently inflated the derived
//       score with no diagnostic — disagreeing with scoreCustom/validateFactors,
//       which drop+warn on unknown keys.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  compare,
  deriveRwepFromFactors,
  timeline,
  RECOGNISED_POST_WEIGHT_KEYS,
  RECOGNISED_FACTOR_KEYS,
} = require('../lib/scoring');

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
