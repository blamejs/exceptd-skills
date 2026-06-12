'use strict';

/**
 * Regression: a VEX-fixed (vendor-patched) CVE must not drive RWEP factor
 * scaling. baseRwep already excluded vex-fixed entries, but the factor-scaling
 * source was `matchedCves[0]` — so a patched CVE that sorted first still scaled
 * the adjusted score (and its exploitation status fed notification drafts).
 * factorCve now prefers the first RWEP-eligible (non-vex-fixed) CVE, and the
 * finding-shape's worst active_exploitation excludes vex-fixed entries.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const runner = require('../lib/playbook-runner');
const kernel = require('../data/playbooks/kernel.json');

const DIR = kernel.directives[0].id;
const TOP = kernel.domain.cve_refs[0]; // highest-rwep, CISA-KEV, confirmed-exploitation kernel CVE
const DET = {
  indicators: [{ id: 'kver-in-affected-range', verdict: 'hit', deterministic: true, confidence: 'high' }],
  classification: 'detected',
};

test('a VEX-fixed top CVE does not drive RWEP factor scaling or inflate adjusted RWEP', () => {
  const unfixed = runner.analyze('kernel', DIR, DET, { [TOP]: true, 'kver-in-affected-range': true }, {});
  const fixed = runner.analyze('kernel', DIR, DET, { [TOP]: true, vex_fixed: [TOP], 'kver-in-affected-range': true }, {});

  // The vex-fixed CVE is the highest-rwep matched entry; still surfaced for the
  // audit trail, but flagged.
  const top = (fixed.matched_cves || []).find(c => c.cve_id === TOP);
  assert.equal(top?.vex_status, 'fixed');

  // Base excludes it (pre-existing) and adjusted is strictly lower.
  assert.ok(fixed.rwep.base < unfixed.rwep.base,
    `vex-fixed base (${fixed.rwep.base}) must be below un-fixed (${unfixed.rwep.base})`);
  assert.ok(fixed.rwep.adjusted < unfixed.rwep.adjusted,
    `vex-fixed adjusted (${fixed.rwep.adjusted}) must be below un-fixed (${unfixed.rwep.adjusted})`);

  // Discriminating (catches the factorCve fix specifically, not just the base
  // exclusion): the vex-fixed top CVE is 'confirmed' exploitation (scale 1.0).
  // With scaling sourced from the eligible (lower-exploitation) CVE, the fired
  // active_exploitation factor scales strictly below the confirmed level. Pre-
  // fix it scaled by the vex-fixed CVE → factor_scale 1.0.
  const unfixedAe = (unfixed.rwep.breakdown || []).find(b => b.rwep_factor === 'active_exploitation' && b.fired);
  const fixedAe = (fixed.rwep.breakdown || []).find(b => b.rwep_factor === 'active_exploitation' && b.fired);
  assert.equal(unfixedAe?.factor_scale, 1.0, 'un-fixed run scales active_exploitation by the confirmed top CVE (1.0)');
  assert.ok(fixedAe && fixedAe.factor_scale < 1.0,
    `vex-fixed run active_exploitation factor_scale (${fixedAe?.factor_scale}) must reflect the eligible CVE, not the vex-fixed confirmed one`);
});

test('when EVERY matched CVE is VEX-fixed, factor scaling is suppressed (adjusted RWEP stays 0)', () => {
  // codex P2: with rwepEligible empty, factorCve must not fall back to a fixed
  // matchedCves[0]; base is 0, and a vendor-fixed CVE's KEV/exploitation/PoC
  // factors must not lift the adjusted score above 0 (the finding is remediated).
  const cves = kernel.domain.cve_refs;
  const sig = { 'kver-in-affected-range': true };
  for (const c of cves) sig[c] = true;
  const allFixed = runner.analyze('kernel', DIR, DET, { ...sig, vex_fixed: cves }, {});

  assert.ok((allFixed.matched_cves || []).length > 0, 'expected matched CVEs in this scenario');
  assert.equal((allFixed.matched_cves || []).filter((c) => c.vex_status !== 'fixed').length, 0,
    'every matched CVE must be VEX-fixed in this scenario');
  assert.equal(allFixed.rwep.base, 0, 'base must be 0 when all matched CVEs are fixed');
  assert.equal(allFixed.rwep.adjusted, 0,
    `adjusted must not be lifted above 0 by a vendor-fixed CVE; got ${allFixed.rwep.adjusted}`);
  for (const b of (allFixed.rwep.breakdown || []).filter((x) => x.fired)) {
    assert.equal(b.factor_scale, 0,
      `fired factor ${b.rwep_factor} must scale by 0 when all matched CVEs are fixed`);
  }
});
