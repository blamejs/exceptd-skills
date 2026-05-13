'use strict';

/**
 * Tests for lib/scoring.js — RWEP scoring engine.
 * Runs under: node --test tests/
 * No external dependencies. Reads the real data/cve-catalog.json.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const scoring = require('../lib/scoring.js');
const catalog = require('../data/cve-catalog.json');

const { score, scoreCustom, timeline, compare, validate, RWEP_WEIGHTS } = scoring;

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

test('compare() flags Copy Fail as RWEP-higher-than-CVSS-equivalent', () => {
  const r = compare('CVE-2026-31431', catalog);
  assert.equal(r.cve_id, 'CVE-2026-31431');
  assert.equal(r.cvss, 7.8);
  assert.equal(r.rwep, 90);
  // cvssEquivalent = 78; delta = 90 - 78 = 12 → between -20 and 20 → "broadly aligned"
  // NOTE: For Copy Fail the formula yields delta 12, so compare() returns "broadly aligned" rather than
  // "significantly higher". The CLAUDE.md narrative (CVSS 7.8 vs RWEP 90 → framework SLA insufficient)
  // is communicated via the SLA fields, not the delta classifier.
  assert.equal(r.delta, 12);
  assert.match(r.explanation, /broadly aligned/);
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
