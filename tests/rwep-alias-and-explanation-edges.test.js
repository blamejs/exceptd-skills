'use strict';

/**
 * RWEP scorer alias + explanation consistency (adjacent-hunt E1-E4).
 *
 * The three scoring surfaces — scoreCustom/deriveRwepFromFactors (the numbers),
 * validateFactors (the linter), and compare() (the human explanation) — must
 * agree on the same aliases and normalization, or a CVE is scored one way and
 * described/validated another.
 *
 *   E4 (critical): deriveRwepFromFactors must count reboot_required and its
 *     alias patch_required_reboot ONCE, not sum both (double-counts +5).
 *   E2: validateFactors must accept a stray-cased active_exploitation the
 *     scorer accepts (resolveActiveExploitation normalizes), not flag it.
 *   E3: validateFactors must treat patch_required_reboot as satisfying
 *     reboot_required (not warn "missing").
 *   E1: compare()'s driving-factors explanation must list the AI factor when
 *     ai_assisted_weaponization drives the delta (not only ai_discovered).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { deriveRwepFromFactors, validateFactors, compare } = require('../lib/scoring.js');

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
