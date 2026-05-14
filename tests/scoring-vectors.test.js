'use strict';

/**
 * tests/scoring-vectors.test.js
 *
 * Regression vector table for lib/scoring.js scoreCustom().
 * Each row asserts the computed score AND that the score is a finite
 * number — i.e. NaN / Infinity never escape the formula, including for
 * malformed inputs (NaN blast_radius, string blast_radius, etc.).
 *
 * Vector coverage (audit J output):
 *   - max-everything           — every positive factor on, score clamps at 100
 *   - copy-fail                — real catalog entry CVE-2026-31431 reproduced
 *   - copilot-pi               — real catalog entry CVE-2025-53773 reproduced
 *   - only-mitigations         — purely negative weights, clamps to 0
 *   - blast-overflow           — blast_radius=999 caps at 30
 *   - blast-NaN                — NaN blast_radius coerces to 0
 *   - blast-string             — '15' string coerces to 15
 *   - blast-Infinity           — Infinity coerces to 0
 *   - blast-negative           — negative blast_radius coerces to 0
 *   - unknown-exploit          — active_exploitation='unknown' → +5 (J F4)
 *   - suspected-only           — active_exploitation='suspected' → +10
 *   - confirmed-only           — active_exploitation='confirmed' → +20
 *   - both-ai-flags            — both AI flags on; ai_factor still single-counted
 *   - empty                    — {} returns 0
 *   - null                     — null factors returns 0
 *   - undefined                — undefined factors returns 0
 *   - unknown-key              — unknown key surfaced via validateFactors
 *   - float-blast              — fractional blast_radius preserved through clamp
 *   - collectWarnings-roundtrip — collectWarnings returns same score + raw
 *   - all-flags-no-blast       — every boolean on but blast=0
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  scoreCustom,
  validateFactors,
  deriveRwepFromFactors,
  ACTIVE_EXPLOITATION_LADDER,
  RECOGNISED_FACTOR_KEYS,
} = require('../lib/scoring.js');

const VECTORS = [
  {
    name: 'max-everything',
    factors: {
      cisa_kev: true, poc_available: true, ai_discovered: true,
      ai_assisted_weapon: true, active_exploitation: 'confirmed',
      blast_radius: 30, patch_available: false, live_patch_available: false,
      reboot_required: true,
    },
    // 25 + 20 + 15 + 20 + 30 + 0 + 0 + 5 = 115 → clamp to 100
    expected: 100,
  },
  {
    name: 'copy-fail (CVE-2026-31431)',
    factors: {
      cisa_kev: true, poc_available: true, ai_discovered: true,
      active_exploitation: 'confirmed', blast_radius: 30,
      patch_available: true, live_patch_available: true, reboot_required: true,
    },
    // 25 + 20 + 15 + 20 + 30 - 15 - 10 + 5 = 90
    expected: 90,
  },
  {
    name: 'copilot-pi (CVE-2025-53773)',
    factors: {
      cisa_kev: false, poc_available: true, ai_assisted_weapon: true,
      active_exploitation: 'suspected', blast_radius: 10,
      patch_available: true, live_patch_available: true, reboot_required: false,
    },
    // 0 + 20 + 15 + 10 + 10 - 15 - 10 + 0 = 30
    expected: 30,
  },
  {
    name: 'only-mitigations',
    factors: {
      cisa_kev: false, poc_available: false, ai_discovered: false,
      active_exploitation: 'none', blast_radius: 0,
      patch_available: true, live_patch_available: true, reboot_required: false,
    },
    // -15 - 10 = -25 → clamp to 0
    expected: 0,
  },
  {
    name: 'blast-overflow',
    factors: { blast_radius: 999 },
    // only blast contributes; caps at 30
    expected: 30,
  },
  {
    name: 'blast-NaN',
    factors: { blast_radius: NaN },
    // NaN coerces to 0, no other contributions
    expected: 0,
  },
  {
    name: 'blast-string',
    factors: { blast_radius: '15' },
    // string coerces via Number('15') = 15
    expected: 15,
  },
  {
    name: 'blast-Infinity',
    factors: { blast_radius: Infinity },
    expected: 0,
  },
  {
    name: 'blast-negative',
    factors: { blast_radius: -10 },
    // Math.max(0, ...) → 0
    expected: 0,
  },
  {
    name: 'unknown-exploit (audit J F4)',
    factors: { active_exploitation: 'unknown' },
    // unknown multiplier 0.25 × weight 20 = 5
    expected: 5,
  },
  {
    name: 'suspected-only',
    factors: { active_exploitation: 'suspected' },
    expected: 10,
  },
  {
    name: 'confirmed-only',
    factors: { active_exploitation: 'confirmed' },
    expected: 20,
  },
  {
    name: 'both-ai-flags',
    factors: { ai_discovered: true, ai_assisted_weapon: true },
    // ai_factor fires once even when both flags are true
    expected: 15,
  },
  {
    name: 'empty',
    factors: {},
    expected: 0,
  },
  {
    name: 'null',
    factors: null,
    expected: 0,
  },
  {
    name: 'undefined',
    factors: undefined,
    expected: 0,
  },
  {
    name: 'unknown-key',
    // typo'd key — should be ignored by scoreCustom but flagged by validateFactors
    factors: { cisa_kev: true, cisa_kev_typo: true },
    expected: 25,
  },
  {
    name: 'float-blast',
    factors: { blast_radius: 12.5 },
    // float preserved; total = 12.5 (clamp doesn't truncate)
    expected: 12.5,
  },
  {
    name: 'all-flags-no-blast',
    factors: {
      cisa_kev: true, poc_available: true, ai_discovered: true,
      active_exploitation: 'confirmed', blast_radius: 0,
      patch_available: false, live_patch_available: false, reboot_required: true,
    },
    // 25 + 20 + 15 + 20 + 0 + 0 + 0 + 5 = 85
    expected: 85,
  },
];

for (const vec of VECTORS) {
  test(`scoreCustom vector: ${vec.name}`, () => {
    const out = scoreCustom(vec.factors);
    assert.equal(out, vec.expected, `vector ${vec.name}: expected ${vec.expected}, got ${out}`);
    assert.ok(
      Number.isFinite(out),
      `vector ${vec.name}: score must be a finite number (NaN/Infinity must never escape)`,
    );
  });
}

// audit J F10: collectWarnings round-trip — score must match the bare call,
// _rwep_raw_unclamped must be the pre-clamp value, _scoring_warnings must
// be an array.
test('scoreCustom vector: collectWarnings-roundtrip', () => {
  const factors = {
    cisa_kev: false, poc_available: false, ai_discovered: false,
    active_exploitation: 'none', blast_radius: 0,
    patch_available: true, live_patch_available: true, reboot_required: false,
  };
  const bare = scoreCustom(factors);
  const wrapped = scoreCustom(factors, { collectWarnings: true });
  assert.equal(wrapped.score, bare);
  assert.equal(wrapped.score, 0);
  // pre-clamp shows the deduction magnitude (-25): the entry has -15 - 10
  // worth of mitigating factors, which the clamp would have hidden.
  assert.equal(wrapped._rwep_raw_unclamped, -25);
  assert.ok(Array.isArray(wrapped._scoring_warnings));
});

// audit J F8: unknown factor keys surface via validateFactors.
test('validateFactors flags unknown keys (audit J F8)', () => {
  const warnings = validateFactors({ cisa_kev: true, cisa_kev_typo: true });
  assert.ok(
    warnings.some((w) => /unknown factor: cisa_kev_typo/.test(w)),
    `expected an unknown-factor warning; got: ${warnings.join(' | ')}`,
  );
});

// audit J F6: NaN diagnostic uses Number.isFinite + a dedicated message
// rather than the misleading "expected number, got number (null)".
test('validateFactors emits a specific message for NaN blast_radius (audit J F6)', () => {
  const warnings = validateFactors({ blast_radius: NaN });
  assert.ok(
    warnings.some((w) => /NaN is not a valid numeric value/.test(w)),
    `expected NaN-specific warning; got: ${warnings.join(' | ')}`,
  );
});

test('validateFactors emits a specific message for Infinity blast_radius', () => {
  const warnings = validateFactors({ blast_radius: Infinity });
  assert.ok(
    warnings.some((w) => /not a finite numeric value/.test(w)),
    `expected Infinity-specific warning; got: ${warnings.join(' | ')}`,
  );
});

// audit J F4: ACTIVE_EXPLOITATION_LADDER aligns with playbook-runner.
test('ACTIVE_EXPLOITATION_LADDER matches the playbook-runner ladder (audit J F4)', () => {
  assert.equal(ACTIVE_EXPLOITATION_LADDER.confirmed, 1.0);
  assert.equal(ACTIVE_EXPLOITATION_LADDER.suspected, 0.5);
  assert.equal(ACTIVE_EXPLOITATION_LADDER.unknown, 0.25);
  assert.equal(ACTIVE_EXPLOITATION_LADDER.none, 0);
});

// audit J F3 + audit M P1-C: deriveRwepFromFactors detects shape correctly.
test('deriveRwepFromFactors handles Shape A (boolean inputs) via scoreCustom', () => {
  const factors = {
    cisa_kev: true, poc_available: true, ai_discovered: false,
    active_exploitation: 'suspected', blast_radius: 15,
    patch_available: false, live_patch_available: false, reboot_required: true,
  };
  // 25 + 20 + 0 + 10 + 15 + 0 + 0 + 5 = 75
  assert.equal(deriveRwepFromFactors(factors), 75);
});

test('deriveRwepFromFactors handles Shape B (catalog post-weight) via sum + clamp', () => {
  const factors = {
    cisa_kev: 0, poc_available: 20, ai_factor: 15, active_exploitation: 10,
    blast_radius: 10, patch_available: -15, live_patch_available: -10,
    reboot_required: 0,
  };
  // sum = 30
  assert.equal(deriveRwepFromFactors(factors), 30);
});

test('deriveRwepFromFactors clamps Shape B sums to [0, 100]', () => {
  // Shape B: post-weight values
  assert.equal(deriveRwepFromFactors({ a: 200, b: 50 }), 100);
  assert.equal(deriveRwepFromFactors({ a: -50, b: -30 }), 0);
});

test('deriveRwepFromFactors returns 0 for empty / null / undefined', () => {
  assert.equal(deriveRwepFromFactors({}), 0);
  assert.equal(deriveRwepFromFactors(null), 0);
  assert.equal(deriveRwepFromFactors(undefined), 0);
});

// audit J F8: RECOGNISED_FACTOR_KEYS is the authoritative set.
test('RECOGNISED_FACTOR_KEYS contains every key scoreCustom destructures', () => {
  const required = [
    'cisa_kev', 'poc_available', 'ai_assisted_weapon', 'ai_discovered',
    'active_exploitation', 'blast_radius', 'patch_available',
    'live_patch_available', 'reboot_required', 'patch_required_reboot',
  ];
  for (const k of required) {
    assert.ok(RECOGNISED_FACTOR_KEYS.has(k), `${k} must be in RECOGNISED_FACTOR_KEYS`);
  }
});
