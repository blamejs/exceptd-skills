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

test('an unparseable condition pushes a condition_unparsed runtime error (not a silent false)', () => {
  const errs = [];
  const r = evalCondition('any compliance.verdict == theater', { _runErrors: errs });
  assert.equal(r, false, 'unparseable still returns false');
  assert.equal(errs.length, 1, 'a runtime error is recorded');
  assert.equal(errs[0].kind, 'condition_unparsed');
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
