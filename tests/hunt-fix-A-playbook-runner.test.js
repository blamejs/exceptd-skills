'use strict';

/**
 * Regression coverage for the playbook-runner engine fixes (cluster
 * A-playbook-runner). Each case fails on the pre-fix behavior and passes after.
 *
 *   #1 finding.includes_X, finding.cve_class, finding.tool_surface are
 *      host-AI-asserted and must survive into the escalation + feeds_into eval
 *      contexts, while engine-owned finding keys (severity, …) win on collision.
 *   #3 the analyze result exposes a non-underscore `classification` alias so
 *      catalog `analyze.classification == 'detected'` conditions resolve.
 *   #4 a dotted-LHS comparison whose path is absent surfaces a
 *      condition_path_unresolved diagnostic (observability only); a bare
 *      single-segment flag absent, or present-but-null, stays a silent
 *      legitimate false.
 *   #5 the feeds_into theater_score scores an allowlisted 'present' verdict 100
 *      (gap detected = worse), not 0.
 *   #7 the runner's active_exploitation RWEP factor routes through scoring's
 *      shared resolver, so a stray-cased value normalises and an out-of-vocab
 *      value is observable rather than a silent zero.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const runner = require(RUNNER_PATH);
const evalCondition = runner._evalCondition;
const { run, close, loadPlaybook } = runner;
const scoring = require(path.resolve(__dirname, '..', 'lib', 'scoring.js'));

const OPTS = { forceStale: true, operator_consent: { explicit: true } };
// _meta.preconditions[].id keys (preflight matches on pc.id, not the check expr).
const SSO_PCS = {
  'idp-audit-api-reachable': true,
  'read-only-admin-rbac': true,
  'tenant-ownership': true,
};

// --- #1: agent-asserted finding.includes_* survives into the eval contexts,
//         engine-owned finding.severity wins over a poisoning signal. ---

test('#1 escalation + feeds_into fire on agent-supplied finding.includes_cloud_role_assumption', () => {
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: {
      blast_radius_score: 4,
      detection_classification: 'detected',
      finding: { includes_cloud_role_assumption: true },
    },
  }, OPTS);
  // Did not block at preflight.
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);

  // Escalation: `blast_radius_score >= 3 AND finding.includes_cloud_role_assumption == true`
  //   → action trigger_playbook, target cloud-iam-incident.
  const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
  assert.equal(escTargets.includes('cloud-iam-incident'), true);
  const cloudEsc = res.phases.analyze.escalations.find((e) => e.target_playbook === 'cloud-iam-incident');
  assert.equal(typeof cloudEsc, 'object');
  assert.equal(cloudEsc.action, 'trigger_playbook');

  // feeds_into: `finding.includes_cloud_role_assumption == true` → cloud-iam-incident.
  assert.equal(Array.isArray(res.phases.close.feeds_into), true);
  assert.equal(res.phases.close.feeds_into.includes('cloud-iam-incident'), true);
});

test('#1 absent finding.includes_* leaves the cloud-iam-incident chain dead (the present case is not coincidental)', () => {
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: { blast_radius_score: 4, detection_classification: 'detected' },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
  assert.equal(escTargets.includes('cloud-iam-incident'), false);
  assert.equal(res.phases.close.feeds_into.includes('cloud-iam-incident'), false);
});

test('#1 engine-computed finding.severity wins over a poisoning signals.finding.severity', () => {
  // secrets.json feeds_into cred-stores on `finding.severity >= 'high'`.
  // No matched CVEs → engine rwep 0 → engine severity 'low'. A poisoning
  // signals.finding.severity='critical' must NOT flip the feeds_into.
  const res = run('secrets', 'full-repo-secret-scan', {
    precondition_checks: { 'repo-context': true },
    signals: { finding: { severity: 'critical' } },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  assert.equal(res.phases.analyze.rwep.adjusted, 0);
  assert.equal(res.phases.close.feeds_into.includes('cred-stores'), false);
});

test('#1 a non-object / array signals.finding is ignored (no numeric-index injection)', () => {
  // signals.finding = [] must not inject array indices into the finding ctx.
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: { blast_radius_score: 4, detection_classification: 'detected', finding: [1, 2, 3] },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  // includes_cloud_role_assumption was not asserted → chain stays dead.
  const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
  assert.equal(escTargets.includes('cloud-iam-incident'), false);
});

// --- #3: analyze.classification alias resolves the catalog's natural path. ---

test('#3 analyze.classification alias resolves equal to _detect_classification', () => {
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: { blast_radius_score: 4, detection_classification: 'detected' },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  assert.equal(typeof res.phases.analyze.classification, 'string');
  assert.equal(res.phases.analyze.classification, res.phases.analyze._detect_classification);
  assert.equal(res.phases.analyze.classification, 'detected');
});

test('#3 analyze.classification == "detected" condition resolves true through the alias', () => {
  assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'detected' } }), true);
  assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'not_detected' } }), false);
});

// --- #4: dotted-LHS absent path surfaces a condition_path_unresolved diagnostic. ---

test('#4 dotted-LHS comparison with an absent LEAF emits condition_path_unresolved', () => {
  const errs = [];
  const result = evalCondition('finding.includes_cloud_role_assumption == true', { finding: { severity: 'high' }, _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 1);
  assert.equal(errs[0].kind, 'condition_path_unresolved');
  assert.equal(errs[0].condition, 'finding.includes_cloud_role_assumption == true');
});

test('#4 dotted-LHS comparison with an absent INTERMEDIATE also emits the diagnostic (the strict-undefined gate would miss this)', () => {
  const errs = [];
  const result = evalCondition("analyze.classification == 'detected'", { _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 1);
  assert.equal(errs[0].kind, 'condition_path_unresolved');
});

test('#4 a bare single-segment flag absent does NOT emit a diagnostic (legitimate false)', () => {
  const errs = [];
  const result = evalCondition('agent_has_filesystem_read == true', { _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 0);
});

test('#4 a present-but-null single-segment flag does NOT emit a diagnostic', () => {
  const errs = [];
  const result = evalCondition('patch_available == true', { patch_available: null, _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 0);
});

test('#4 a present-and-matching dotted comparison emits nothing', () => {
  const errs = [];
  const result = evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'detected' }, _runErrors: errs });
  assert.equal(result, true);
  assert.equal(errs.length, 0);
});

// --- #5: theater_score scores an allowlisted 'present' verdict 100, not 0. ---

function feedsForVerdict(verdict) {
  const pb = JSON.parse(JSON.stringify(loadPlaybook('framework')));
  pb._meta = pb._meta || {};
  // Inject a theater_score-gated feeds_into into the cached playbook so the
  // real close() path computes feedsCtx.theater_score (line 2060) and evaluates
  // it. No shipped condition consumes theater_score today (latent), so this is
  // the canonical way to exercise the computed value end-to-end.
  pb._meta.feeds_into = [{ playbook_id: 'sbom', condition: 'theater_score >= 50' }];
  const analyzeResult = {
    phase: 'analyze',
    playbook_id: 'framework',
    directive_id: 'baseline-framework-gap-inventory',
    matched_cves: [],
    catalog_baseline_cves: [],
    rwep: { base: 0, adjusted: 0, breakdown: [] },
    blast_radius_score: null,
    compliance_theater_check: { verdict },
    framework_gap_mapping: [],
    _detect_indicators: [],
    _detect_classification: 'not_detected',
    classification: 'not_detected',
    escalations: [],
  };
  const validateResult = { phase: 'validate', remediation_paths_considered: [], selected_remediation_path: null };
  const res = close('framework', 'baseline-framework-gap-inventory', analyzeResult, validateResult, {}, { _playbookCache: pb, session_id: 'hunt-fix-A' });
  return res.feeds_into;
}

test('#5 theater_score scores a "present" verdict 100 → fires the theater_score >= 50 feeds_into', () => {
  assert.deepEqual(feedsForVerdict('present'), ['sbom']);
});

test('#5 theater_score scores a "theater" verdict 100 (unchanged)', () => {
  assert.deepEqual(feedsForVerdict('theater'), ['sbom']);
});

test('#5 theater_score scores a "clear" verdict 0 → no fire', () => {
  assert.deepEqual(feedsForVerdict('clear'), []);
});

// --- #7: runner active_exploitation factor routes through scoring's resolver. ---

test('#7 scoring.activeExploitationMultiplier returns the canonical ladder multipliers (parity with the prior inline lookup)', () => {
  assert.equal(scoring.activeExploitationMultiplier('confirmed'), 1);
  assert.equal(scoring.activeExploitationMultiplier('suspected'), 0.5);
  assert.equal(scoring.activeExploitationMultiplier('unknown'), 0.25);
  assert.equal(scoring.activeExploitationMultiplier('theoretical'), 0);
  assert.equal(scoring.activeExploitationMultiplier('none'), 0);
  assert.equal(scoring.activeExploitationMultiplier(undefined), 0);
});

test('#7 a stray-cased active_exploitation value normalises instead of zeroing', () => {
  assert.equal(scoring.activeExploitationMultiplier('Confirmed'), 1);
  assert.equal(scoring.activeExploitationMultiplier(' SUSPECTED '), 0.5);
});

test('#7 an out-of-vocab active_exploitation value is observable (RWEP_AE_UNRECOGNISED), not a silent zero', async () => {
  // process.emitWarning delivers the 'warning' event on the next tick, so await it.
  const warned = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      process.removeListener('warning', onWarn);
      reject(new Error('RWEP_AE_UNRECOGNISED warning was not emitted for an out-of-vocab value'));
    }, 1000);
    function onWarn(w) {
      if (w && w.code === 'RWEP_AE_UNRECOGNISED') {
        clearTimeout(timer);
        process.removeListener('warning', onWarn);
        resolve(w);
      }
    }
    process.on('warning', onWarn);
  });
  // Use a value that no other test in this file has warned on (warnings with a
  // `code` are emitted once per process for a given code only when --no-warnings
  // is off; a fresh value guarantees the event fires here).
  const mult = scoring.activeExploitationMultiplier('in-the-wild-hunt-fix-A');
  assert.equal(mult, 0);
  const w = await warned;
  assert.equal(w.code, 'RWEP_AE_UNRECOGNISED');
});

test('#7 the runner active_exploitation factor branch routes through scoring.activeExploitationMultiplier (no inline ?? 0 ladder)', () => {
  // Structural guard: _factorScale is a local closure (not exported), so assert
  // on the source that the active_exploitation case delegates to the shared
  // observable resolver and the dead inline-ladder alias is gone. This catches a
  // silent regression back to `_activeExploitationLadder[v] ?? 0`.
  const src = fs.readFileSync(RUNNER_PATH, 'utf8');
  const branch = src.slice(src.indexOf("case 'active_exploitation':"));
  const branchHead = branch.slice(0, branch.indexOf('case ', 1));
  assert.equal(/scoring\.activeExploitationMultiplier\(/.test(branchHead), true);
  assert.equal(/_activeExploitationLadder\s*\[/.test(branchHead), false);
  // The local `const _activeExploitationLadder = scoring.ACTIVE_EXPLOITATION_LADDER;`
  // alias inside analyze() is removed (the module re-export at the bottom is a
  // separate, intentional surface and is allowed to keep referencing scoring).
  assert.equal(/const _activeExploitationLadder\b/.test(src), false);
});
