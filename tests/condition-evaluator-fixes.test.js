'use strict';

/**
 * Regression for the condition mini-language (lib/playbook-runner.js
 * evalCondition). Conditions gate escalation_criteria, feeds_into chains, and
 * remediation preconditions across the catalog; a silently-false condition
 * disables its rule.
 *
 *   - hyphenated signal/indicator ids (the catalog naming convention) must
 *     parse, not fall through to false
 *   - severity comparison is by the low<medium<high<critical ladder, not
 *     lexicographic string order (so 'critical' >= 'high' is true)
 *   - `contains` is a synonym for `includes`
 *   - an operator-submitted signal cannot override an engine-computed value
 *   - an unparseable condition surfaces a condition_unparsed runtime error
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));
const evalCondition = runner._evalCondition;

test('hyphenated LHS evaluates against the matching ctx key (not silently false)', () => {
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': true }), true);
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': false }), false);
  assert.equal(evalCondition('kver-in-affected-range == true AND kaslr-disabled == true',
    { 'kver-in-affected-range': true, 'kaslr-disabled': true }), true);
});

test('severity comparison uses the ordinal ladder, not lexicographic order', () => {
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'critical' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'high' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'medium' } }), false);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'low' } }), false);
  // numeric comparison still works (regression guard)
  assert.equal(evalCondition('rwep >= 90', { rwep: 100 }), true);
  assert.equal(evalCondition('rwep >= 90', { rwep: 50 }), false);
});

test('`contains` is accepted as a synonym for `includes`', () => {
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets includes named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['local'] } }), false);
});

test('`matches` accepts both the slash and the quote delimiter (mcp feeds_into uses the quoted form)', () => {
  // The catalog authors both forms; mcp.json's feeds_into matches the CI-platform
  // OR-branch with the quoted form. A delimiter-specific parser silently disabled
  // it (returned false + a condition_unparsed runtime error) for every input.
  const slashErrs = [];
  assert.equal(evalCondition("finding.x matches /(a|b)/", { finding: { x: 'a' }, _runErrors: slashErrs }), true);
  assert.equal(slashErrs.length, 0, 'slash form parses, no condition_unparsed');

  const quoteErrs = [];
  assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'a' }, _runErrors: quoteErrs }), true);
  assert.equal(quoteErrs.length, 0, 'single-quote form parses, no condition_unparsed');

  // double-quote form also parses
  assert.equal(evalCondition('finding.x matches "(a|b)"', { finding: { x: 'b' } }), true);

  // a non-match is false (not a parse failure)
  assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'c' } }), false);

  // the exact mcp.json feeds_into condition fires via the regex OR-branch alone,
  // with the other two OR-branches false (pre-fix the whole OR collapsed to false)
  const mcpCond = "finding.mcp_server_location matches '(github_actions|gitlab_runner|jenkins|buildkite|circleci)'"
    + " OR finding.tool_invoked_from == 'ci_pipeline'"
    + " OR analyze.blast_radius_score >= 4 AND finding.pipeline_credentials_in_scope == true";
  assert.equal(evalCondition(mcpCond, {
    finding: { mcp_server_location: 'buildkite', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
    analyze: { blast_radius_score: 0 },
  }), true);
});

test('an unparseable (prose) condition pushes a condition_unparsed runtime error (not a silent false)', () => {
  const errs = [];
  // A genuine prose sentence the mini-language can't evaluate. (The `any … ==`
  // quantifier form below is now PARSED — see the quantifier test — so a prose
  // clause is what should still surface the diagnostic.)
  const r = evalCondition('a single compromised identity can rewrite the trail', { _runErrors: errs });
  assert.equal(r, false, 'unparseable still returns false');
  assert.equal(errs.length, 1, 'a runtime error is recorded');
  assert.equal(errs[0].kind, 'condition_unparsed');
});

test('`any`/`all` quantifier prefix parses and fires (not condition_unparsed)', () => {
  // Scalar LHS — the quantifier is prose emphasis; the scalar comparison is the
  // test. framework.json's feeds_into to sbom is exactly this shape. Pre-fix the
  // `any ` leaf fell through to condition_unparsed → false, disabling BOTH paths
  // by which framework chains into sbom.
  const cond = "any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4";
  const errs = [];
  assert.equal(
    evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 5, _runErrors: errs }),
    true,
    'theater verdict + blast_radius 5 fires the framework→sbom chain'
  );
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'the any-prefixed leaf parses — no condition_unparsed');
  // Negatives: each conjunct gates independently.
  assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'clear' }, blast_radius_score: 5 }), false,
    'non-theater verdict does not chain');
  assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 2 }), false,
    'blast_radius below 4 does not chain');

  // Array LHS — existential / universal over members. sbom.json's feeds_into
  // uses `any matched_cve.attack_class == 'kernel-lpe'`.
  const hit = { matched_cve: [{ attack_class: 'mcp-supply-chain' }, { attack_class: 'kernel-lpe' }] };
  const miss = { matched_cve: [{ attack_class: 'mcp-supply-chain' }] };
  assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", hit), true,
    'any matches when one array element satisfies the predicate');
  assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", miss), false,
    'any is false when no element satisfies the predicate');
  assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'", hit), false,
    'all is false when only some elements satisfy the predicate');
  assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'",
    { matched_cve: [{ attack_class: 'kernel-lpe' }, { attack_class: 'kernel-lpe' }] }), true,
    'all is true when every element satisfies the predicate');
});

test('a submitted signal cannot override an engine-computed value in an escalation condition', () => {
  // ai-api declares escalations gated on engine values. Run it with detection
  // confirmed so the engine computes a high rwep, then try to suppress the
  // escalation by submitting signals.rwep:0 — the engine value must win.
  const base = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
    { signals: { detection_classification: 'detected' }, artifacts: {} },
    { operator_consent: { explicit: true } });
  const poisoned = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
    { signals: { detection_classification: 'detected', rwep: 0, finding: { severity: 'low' } }, artifacts: {} },
    { operator_consent: { explicit: true } });
  const esc = (res) => JSON.stringify((res.phases.analyze.escalations || []).map((e) => e.action).sort());
  assert.equal(esc(poisoned), esc(base),
    'submitted signals.rwep / finding must not change which escalations fire');
});

test('framework chains into sbom when the theater verdict + blast radius gate is met', () => {
  // framework.json declares the same chain on TWO paths: a feeds_into entry and
  // a trigger_playbook escalation, both targeting sbom. Both previously used an
  // `any `-prefixed, bare-path condition that resolved to false for every input,
  // so neither chain could ever fire. Run the playbook with a theater verdict +
  // a blast radius above the gate and assert both surfaces name sbom.
  const out = runner.run('framework', 'correlate-all-upstream-findings',
    { signals: { theater_verdict: 'theater', blast_radius_score: 5 }, artifacts: {} },
    { operator_consent: { explicit: true } });

  assert.deepEqual(out.phases.close.feeds_into, ['sbom'],
    'feeds_into chains framework → sbom on a theater verdict + blast_radius >= 4');

  const escTargets = (out.phases.analyze.escalations || [])
    .filter((e) => e.action === 'trigger_playbook')
    .map((e) => e.target_playbook);
  assert.ok(escTargets.includes('sbom'),
    'the trigger_playbook escalation fires framework → sbom on a theater verdict + blast_radius >= 3');

  // Neither chain's condition is left dead (the bug signature was a silent
  // condition_unparsed on the framework→sbom clauses specifically).
  const allErrs = (out.phases.analyze.runtime_errors || []).concat(out.phases.close.runtime_errors || []);
  const deadFrameworkSbom = allErrs.filter((e) =>
    e.kind === 'condition_unparsed' && /compliance_theater_check\.verdict/.test(e.condition || ''));
  assert.equal(deadFrameworkSbom.length, 0,
    'the framework→sbom theater conditions parse — no condition_unparsed on them');
});

test('a non-theater framework run does NOT chain into sbom', () => {
  const out = runner.run('framework', 'correlate-all-upstream-findings',
    { signals: { theater_verdict: 'clear', blast_radius_score: 5 }, artifacts: {} },
    { operator_consent: { explicit: true } });
  assert.deepEqual(out.phases.close.feeds_into, [],
    'a clear verdict does not chain framework → sbom');
});
