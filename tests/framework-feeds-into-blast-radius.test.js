'use strict';

// Regression: the framework playbook is the compliance-theater correlator whose
// whole purpose is to chain other playbooks' findings forward. Its only
// feeds_into target is `sbom`, gated on
//   "any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4"
//
// Two defects made that chain dead, both producing a silent `false` rather than
// an error:
//   1. close()'s feeds_into eval context exposed `analyze.blast_radius_score`
//      and `analyze.compliance_theater_check.verdict` but NOT the BARE tokens
//      `blast_radius_score` / `compliance_theater_check` the catalog condition
//      references. resolvePath returned null, so `null >= 4` was false
//      regardless of the engine-computed blast radius — while the SAME bare
//      token fired in the escalation context (where the key was present).
//   2. evalCondition had no handling for the `any `/`all ` quantifier prefix, so
//      `any compliance_theater_check.verdict == 'theater'` was unparseable and
//      fell through to false.
//
// These assert the EXACT feeds_into array membership (not just truthiness) for
// the firing case, the gating case, and the poison-resistance case.

const test = require('node:test');
const it = test.test;
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const PB = 'framework';
const DIR = 'correlate-all-upstream-findings';

function chain(closeSignals, analyzeSignals = closeSignals) {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, analyzeSignals);
  const v = runner.validate(PB, DIR, an, {});
  return runner.close(PB, DIR, an, v, closeSignals);
}

test('framework feeds_into → sbom chain (bare blast_radius_score + any quantifier)', () => {
  it('chains into sbom when theater verdict fires AND blast_radius_score >= 4', () => {
    const c = chain({ blast_radius_score: 5, theater_verdict: 'theater' });
    assert.deepEqual(c.feeds_into, ['sbom'],
      'framework→sbom feeds_into must fire when verdict==theater and blast_radius_score>=4');
  });

  it('does NOT chain when blast_radius_score < 4 (gate holds)', () => {
    const c = chain({ blast_radius_score: 2, theater_verdict: 'theater' });
    assert.deepEqual(c.feeds_into, [],
      'framework→sbom must not fire below the blast_radius_score>=4 threshold');
  });

  it('engine-computed blast radius wins over a suppressing operator signal in close()', () => {
    // analyze sees blast_radius_score:5 (engine value). A later close() call that
    // passes blast_radius_score:0 (an operator suppression attempt) must NOT
    // suppress the chain — feedsCtx spreads ...agentSignals FIRST, then the
    // engine keys, so the engine value is authoritative.
    const c = chain(
      { blast_radius_score: 0, theater_verdict: 'theater' }, // close signals (poison)
      { blast_radius_score: 5, theater_verdict: 'theater' }  // analyze signals (engine truth)
    );
    assert.deepEqual(c.feeds_into, ['sbom'],
      'a submitted blast_radius_score:0 must not override the engine-computed 5');
  });
});

test('framework escalation → sbom trigger (any quantifier + bare compliance_theater_check)', () => {
  it('fires the trigger_playbook:sbom escalation when verdict==theater and blast_radius_score>=3', () => {
    const det = runner.detect(PB, DIR, {});
    const an = runner.analyze(PB, DIR, det, { blast_radius_score: 5, theater_verdict: 'theater' });
    const sbomEsc = (an.escalations || []).find(e => e.target_playbook === 'sbom');
    assert.ok(sbomEsc, 'the framework analyze phase must fire the trigger_playbook:sbom escalation');
    assert.equal(sbomEsc.condition,
      "analyze.compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 3");
  });
});

test('evalCondition quantifier prefix handling', () => {
  const ev = runner._evalCondition;

  it('scalar-path "any" is prose emphasis and evaluates the bare comparison', () => {
    assert.equal(
      ev("any compliance_theater_check.verdict == 'theater'",
        { compliance_theater_check: { verdict: 'theater' } }, {}),
      true);
  });

  it('array-path "any" is existential across elements', () => {
    const ctx = { matched_cve: [{ attack_class: 'x' }, { attack_class: 'kernel-lpe' }] };
    assert.equal(ev("any matched_cve.attack_class == 'kernel-lpe'", ctx, {}), true);
    assert.equal(ev("any matched_cve.attack_class == 'mcp-supply-chain'", ctx, {}), false);
  });

  it('array-path "all" is universal across elements', () => {
    assert.equal(
      ev("all matched_cve.attack_class == 'kernel-lpe'",
        { matched_cve: [{ attack_class: 'kernel-lpe' }, { attack_class: 'x' }] }, {}),
      false);
    assert.equal(
      ev("all matched_cve.attack_class == 'kernel-lpe'",
        { matched_cve: [{ attack_class: 'kernel-lpe' }] }, {}),
      true);
  });
});
