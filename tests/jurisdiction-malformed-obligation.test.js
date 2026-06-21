'use strict';

/**
 * Close-phase resilience to malformed jurisdiction obligations (runtime
 * validation of a playbook is not enforced, so close() must not crash or emit
 * bogus records on a hand-crafted / corrupt playbook):
 *
 *  - A matched obligation with a non-number window_hours must NOT crash the
 *    deadline arithmetic (new Date(getTime() + NaN).toISOString()); the deadline
 *    falls back to the pending sentinel.
 *  - A notification_action whose obligation_ref resolves to no obligation is
 *    dropped (already surfaced as a runtime_error) instead of emitting a record
 *    with null jurisdiction/regulation.
 *  - A notify obligation with a non-number window_hours is not synthesized into a
 *    "…/… undefinedh" record; it is surfaced as a runtime_error and skipped.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');

function freshRunner(playbookDir) {
  process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}
function tmpDir(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-jur-${label}-`)); }
function writePlaybook(dir, id, body) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body, null, 2));
}
function synthPlaybook(govObligations, notificationActions) {
  return {
    _meta: {
      id: 'jur-malformed', last_threat_review: '2026-05-11',
      threat_currency_score: 95,
      owner: '@blamejs/test', air_gap_mode: false, preconditions: [], mutex: [], feeds_into: [],
    },
    domain: {
      name: 'synth', attack_class: 'kernel-lpe', atlas_refs: [], attack_refs: [],
      cve_refs: [], cwe_refs: [], d3fend_refs: [], frameworks_in_scope: ['nist-800-53'],
    },
    phases: {
      govern: { jurisdiction_obligations: govObligations, theater_fingerprints: [], framework_context: {}, skill_preload: [] },
      direct: { threat_context: 'x', rwep_threshold: { escalate: 90, monitor: 70, close: 30 }, framework_lag_declaration: 'x', skill_chain: [], token_budget: {} },
      look: { artifacts: [], collection_scope: {}, environment_assumptions: [], fallback_if_unavailable: [] },
      detect: { indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }], false_positive_profile: [], minimum_signal: { detected: 'x', inconclusive: 'x', not_detected: 'x' } },
      analyze: { rwep_inputs: [], blast_radius_model: { scope_question: '?', scoring_rubric: [] }, compliance_theater_check: null, framework_gap_mapping: [], escalation_criteria: [] },
      validate: { remediation_paths: [], validation_tests: [], residual_risk_statement: null, evidence_requirements: [], regression_trigger: [] },
      close: { evidence_package: null, learning_loop: { enabled: false }, notification_actions: notificationActions, exception_generation: null, regression_schedule: null },
    },
    directives: [{ id: 'default', title: 'default', applies_to: { always: true } }],
  };
}

function drive(dir, agentSignals, runOpts) {
  const r = freshRunner(dir);
  const det = r.detect('p', 'default', { signal_overrides: { sig: 'hit' } });
  const an = r.analyze('p', 'default', det);
  const v = r.validate('p', 'default', an, {});
  // close(playbookId, directiveId, analyzeResult, validateResult, agentSignals, runOpts)
  return r.close('p', 'default', an, v, agentSignals, runOpts);
}

test('a matched obligation with a missing window_hours does not crash close(); deadline falls back to the sentinel', () => {
  const dir = tmpDir('nan');
  try {
    // obligation: 'report' (not 'notify') so synthesis ignores it; the explicit
    // notification_action references it by the "EU/TEST undefinedh" ref the same
    // formula produces, so the obligation IS matched and the deadline path runs.
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'EU', regulation: 'TEST', clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'report' }],
      [{ obligation_ref: 'EU/TEST undefinedh', recipient: 'r@e', draft_notification: 'x', evidence_attached: [] }],
    ));
    let close;
    assert.doesNotThrow(() => {
      // Fire the clock so clockValid is true — this is the exact condition under
      // which the unguarded arithmetic computed new Date(NaN) and threw.
      close = drive(dir, { clock_started_at_detect_confirmed: '2026-05-11T10:00:00Z' }, { _runErrors: [] });
    }, 'close() must not throw on an obligation missing window_hours');
    const n = close.notification_actions.find(x => x.obligation_ref === 'EU/TEST undefinedh');
    assert.ok(n, 'the matched notification record is present');
    assert.equal(n.deadline, 'pending_clock_start_event', 'a non-number window_hours yields the pending sentinel, not a crash');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a notification_action with an unresolved obligation_ref is dropped and surfaced as a runtime_error', () => {
  const dir = tmpDir('unresolved');
  try {
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'EU', regulation: 'REAL', window_hours: 24, clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'report' }],
      [{ obligation_ref: 'ZZ/NONEXISTENT 99h', recipient: 'r@e', draft_notification: 'x', evidence_attached: [] }],
    ));
    const runErrors = [];
    const close = drive(dir, {}, { _runErrors: runErrors });
    const orphan = close.notification_actions.find(x => x.obligation_ref === 'ZZ/NONEXISTENT 99h');
    assert.equal(orphan, undefined, 'the unresolved-ref record must be dropped, not emitted with null jurisdiction');
    assert.ok(
      runErrors.some(e => e.kind === 'unresolved_obligation_ref' && e.obligation_ref === 'ZZ/NONEXISTENT 99h'),
      `the unmatched ref must surface a runtime_error; got ${JSON.stringify(runErrors)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a notify obligation with a non-number window_hours is not synthesized as "undefinedh"; it surfaces a runtime_error', () => {
  const dir = tmpDir('synth');
  try {
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'ZZ', regulation: 'BADWIN', clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'notify' }],
      [],
    ));
    const runErrors = [];
    const close = drive(dir, {}, { _runErrors: runErrors });
    const bogus = close.notification_actions.find(x => String(x.obligation_ref).includes('undefinedh'));
    assert.equal(bogus, undefined, 'a malformed notify obligation must not synthesize an "undefinedh" record');
    assert.ok(
      runErrors.some(e => e.kind === 'malformed_obligation_window_hours'),
      `a malformed window_hours must surface a runtime_error; got ${JSON.stringify(runErrors)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
