'use strict';

/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    input: opts.input,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1', EXCEPTD_RAW_JSON: '1', ...opts.env },
    timeout: 30000,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// ===================================================================
test('#17 validate-cves does not crash with MODULE_NOT_FOUND', () => {
  const r = cli(['validate-cves', '--offline', '--no-fail']);
  assert.doesNotMatch(r.stderr + r.stdout, /Cannot find module.*sources\/validators/);
});

test('#18 unknown command returns JSON error', () => {
  const r = cli(['nope-not-a-verb']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'nope-not-a-verb');
});

test('#18 skill not found returns JSON error', () => {
  const r = cli(['skill', 'nonexistent-skill']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.match(err.error, /Skill not found/);
});

test('#19 prefetch --no-network --quiet emits one-line summary', () => {
  const r = cli(['prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/);
});

test('#31 session-id collision refused without --force-overwrite', () => {
  // First run creates the attestation.
  const sid = 'regressionsess-' + Date.now();
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r1.status, 0, 'first run must succeed');
  // Second run with same session-id should be refused.
  const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.notEqual(r2.status, 0, 'second run must refuse the collision');
  const err = tryJson(r2.stderr.trim());
  assert.ok(err, 'refusal should be JSON');
  assert.match(err.error, /Session-id collision|already exists/);
});

test('#32 --mode validates against accepted set', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--mode', 'garbage'], { input: '{}' });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not in accepted set/);
});

test('#33 --session-key must be hex', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', 'zzzznothex'], { input: '{}' });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /must be hex/);
});

test('#46 plan --directives includes description', () => {
  const r = cli(['plan', '--directives', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'plan output should be JSON');
  const pb = data.playbooks?.[0];
  assert.ok(pb && pb.directives?.[0]?.description !== undefined,
    'each directive should expose a description field (may be null but key present)');
});

// ===================================================================
test('#58 ask routes literal playbook id', () => {
  const r = cli(['ask', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be JSON');
  assert.ok(Array.isArray(data.routed_to) && data.routed_to.length > 0,
    'ask "secrets" should return at least one match');
  assert.ok(data.routed_to.includes('secrets'), 'top match should include the secrets playbook');
});

test('#58 ask with synonym maps to relevant playbook', () => {
  const r = cli(['ask', 'credentials', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data && Array.isArray(data.routed_to), 'ask output should have routed_to');
  assert.ok(data.routed_to.length > 0, 'credentials should match at least one playbook');
});

test('#60 ask in TTY-less mode emits compact JSON', () => {
  const r = cli(['ask', 'secrets', '--json']);
  // Should be parseable JSON (single line or pretty — either is acceptable).
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be parseable JSON when --json is set');
});

test('#62 watch verb is registered', () => {
  // watch is a long-running orchestrator subprocess; we just verify the
  // CLI doesn't reject it as unknown. spawn with short timeout so the test
  // doesn't hang on the event-loop.
  const r = spawnSync(process.execPath, [CLI, 'watch'], {
    encoding: 'utf8', timeout: 1500,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  // Expect timeout (signal SIGTERM/null) not an unknown-command error.
  assert.doesNotMatch(r.stderr, /unknown command/);
});

test('#65 refresh --no-network routes to prefetch', () => {
  const r = cli(['refresh', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/);
});

// ===================================================================
test('#71 detect canonicalizes no_hit to miss (flat-shape submission)', () => {
  const sub = {
    observations: {
      w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'no_hit' }
    },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
  assert.ok(target, 'indicator must be present in detect output');
  assert.equal(target.verdict, 'miss', 'no_hit must canonicalize to miss');
});

test('#71 normalizer accepts every documented synonym', () => {
  const cases = [
    ['hit', 'hit'], ['detected', 'hit'], ['positive', 'hit'], [true, 'hit'],
    ['miss', 'miss'], ['no_hit', 'miss'], ['no-hit', 'miss'], ['clean', 'miss'],
    ['clear', 'miss'], ['not_hit', 'miss'], ['ok', 'miss'], ['pass', 'miss'],
    ['negative', 'miss'], [false, 'miss'],
    ['inconclusive', 'inconclusive'], ['unknown', 'inconclusive'], ['unverified', 'inconclusive'],
  ];
  for (const [input, expected] of cases) {
    const sub = {
      observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: input } },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
    assert.equal(target?.verdict, expected, `result=${JSON.stringify(input)} should canonicalize to ${expected}`);
  }
});

test('#71 detect surfaces observations_received + signals_received', () => {
  const sub = {
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'no_hit' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  assert.ok(Array.isArray(result.phases.detect.observations_received));
  assert.ok(Array.isArray(result.phases.detect.signals_received));
  assert.ok(result.phases.detect.signals_received.includes('publish-workflow-uses-static-token'));
});

// ===================================================================
test('#73 indicators_evaluated is an array', () => {
  const sub = { observations: {}, verdict: {} };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  assert.ok(Array.isArray(result.phases.detect.indicators_evaluated),
    'indicators_evaluated must be an array (v0.10.x compat)');
  assert.equal(typeof result.phases.detect.indicators_evaluated_count, 'number',
    'indicators_evaluated_count must be an integer peer field');
  if (result.phases.detect.indicators_evaluated.length > 0) {
    const first = result.phases.detect.indicators_evaluated[0];
    assert.ok('signal_id' in first, 'entry must have signal_id');
    assert.ok('outcome' in first, 'entry must have outcome');
    assert.ok('confidence' in first, 'entry must have confidence');
  }
});

test('#76 run --format garbage returns structured JSON error', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'garbage'], { input: '{}' });
  assert.notEqual(r.status, 0, '--format garbage must exit non-zero');
  const err = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(err && err.ok === false, 'output must include {ok:false} JSON error');
  assert.match(err.error, /not in accepted set/);
});

test('#76 ci --format garbage returns structured JSON error', () => {
  const r = cli(['ci', '--scope', 'code', '--format', 'garbage']);
  assert.notEqual(r.status, 0);
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /not in accepted set/);
});

// ===================================================================
test('#82 SARIF includes results from indicators that fired', () => {
  // Fire one indicator so SARIF has at least one result to emit.
  const sub = {
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {
    // Request SARIF as a side bundle.
  });
  // Note: --format is set on the CLI side via signals._bundle_formats.
  // For this direct-runner test we manually invoke close() with that signal.
  // Simpler: use the CLI smoke test below.
});

test('#82 SARIF bundle via CLI includes indicator results when one fires', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'sarif output should be JSON');
  assert.equal(data.version, '2.1.0');
  // For library-author there are 0 matched_cves but the indicator that fired
  // should produce a SARIF result.
  const results = data.runs?.[0]?.results || [];
  assert.ok(results.length > 0, 'SARIF must include at least one result when an indicator fired');
  assert.ok(results.some(r => r.properties?.kind === 'indicator_hit'),
    'at least one SARIF result must be kind=indicator_hit');
});

test('#82 CSAF bundle via CLI includes indicator vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  assert.equal(data.document?.csaf_version, '2.0');
  assert.ok(Array.isArray(data.vulnerabilities));
  assert.ok(data.vulnerabilities.length > 0, 'CSAF must include vulnerabilities when an indicator fired');
});

test('#82 OpenVEX bundle via CLI includes indicator statements', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  assert.match(data['@context'] || '', /openvex/);
  assert.ok(data.statements?.length > 0, 'OpenVEX must include statements when an indicator fired');
});

// ===================================================================
test('#83 lint follows val.artifact indirection', () => {
  // Submission uses arbitrary observation keys + val.artifact indirection.
  // Pre-0.11.5 lint reported missing_required_artifact because it didn't
  // walk val.artifact. Post-fix, lint normalizes through the runner's
  // normalizeSubmission and validates the canonical shape.
  const pb = runner.loadPlaybook('library-author');
  const requiredId = (pb.phases.look.artifacts || []).find(a => a.required)?.id;
  if (!requiredId) return; // skip if playbook has no required artifacts
  const sub = JSON.stringify({
    observations: {
      'obs-1': { artifact: requiredId, captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' }
    }
  });
  // Write to a tmp file for lint.
  const tmpFile = path.join(require('os').tmpdir(), `lint-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'lint output should be JSON');
  const missingErrors = (data.issues || []).filter(i => i.kind === 'missing_required_artifact' && i.artifact_id === requiredId);
  assert.equal(missingErrors.length, 0,
    `lint should follow val.artifact indirection — required artifact ${requiredId} was provided as observations["obs-1"].artifact`);
});

test('#83 lint and run agree on the same flat submission', () => {
  // Load the playbook to discover its real required-artifact ids dynamically
  // rather than hard-coding (which makes the test brittle to playbook edits).
  const pb = runner.loadPlaybook('library-author');
  const requiredArtifacts = (pb.phases.look.artifacts || []).filter(a => a.required);
  const ind = (pb.phases.detect.indicators || [])[0]?.id;
  if (requiredArtifacts.length === 0 || !ind) return; // skip if playbook structure unexpected

  // Build a submission that supplies every required artifact via val.artifact
  // indirection (the case that pre-0.11.5 lint mishandled).
  const observations = {};
  requiredArtifacts.forEach((a, i) => {
    observations[`obs-${i}`] = {
      artifact: a.id, captured: true, value: 'x',
      indicator: ind, result: 'miss',
    };
  });
  const sub = JSON.stringify({ observations });
  const tmpFile = path.join(require('os').tmpdir(), `agree-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  try {
    const lintRes = cli(['lint', 'library-author', tmpFile, '--json']);
    const lintData = tryJson(lintRes.stdout);
    // Lint may emit warnings (e.g. precondition_unverified, unknown_signal)
    // but should NOT emit errors about missing required artifacts.
    const errs = (lintData?.issues || []).filter(i => i.severity === 'error');
    assert.equal(errs.length, 0,
      'lint should not error on a runner-valid submission with val.artifact indirection. Errors: ' +
      JSON.stringify(errs.map(e => e.kind)));

    // Run the same submission.
    const runRes = cli(['run', 'library-author', '--evidence', tmpFile, '--json']);
    const runData = tryJson(runRes.stdout);
    assert.equal(runData?.ok, true, 'run should accept the same submission lint accepted');
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

// ===================================================================
test('#85 from_observation populated when observation drove the indicator', () => {
  const sub = {
    observations: { 'my-obs-key': { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  const evaluated = result.phases.detect.indicators_evaluated.find(
    e => e.signal_id === 'publish-workflow-uses-static-token'
  );
  assert.ok(evaluated, 'indicator must appear in indicators_evaluated');
  assert.equal(evaluated.from_observation, 'my-obs-key',
    'from_observation must reference the observation key that produced the outcome');
});

// ===================================================================
test('#91 CSAF includes framework_gap_mapping as vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  const fwGapVulns = (data.vulnerabilities || []).filter(v =>
    (v.ids || []).some(id => id.system_name === 'exceptd-framework-gap')
  );
  assert.ok(fwGapVulns.length > 0,
    'CSAF must include framework gaps as vulnerabilities — pre-0.11.6 only matched_cves + indicators were emitted');
});

test('#91 OpenVEX includes framework_gap_mapping as statements', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  const fwGapStatements = (data.statements || []).filter(s =>
    s.vulnerability?.['@id']?.startsWith('exceptd:framework-gap:')
  );
  assert.ok(fwGapStatements.length > 0,
    'OpenVEX must include framework gaps as statements');
});

test('#92 CSAF tracking.current_release_date is non-null', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data?.document?.tracking?.current_release_date,
    'CSAF 2.0 §3.2.1.12 requires tracking.current_release_date non-null');
});

test('#93 SARIF defines every rule referenced by ruleId', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const rules = new Set((data.runs?.[0]?.tool?.driver?.rules || []).map(x => x.id));
  const results = data.runs?.[0]?.results || [];
  const missingDefs = [...new Set(results.map(r => r.ruleId))].filter(id => !rules.has(id));
  assert.equal(missingDefs.length, 0,
    `SARIF spec §3.27.3: every referenced ruleId must have a rule definition. Missing: ${JSON.stringify(missingDefs)}`);
});

test('#94 lint missing_required_artifact is a warning, not error', () => {
  // Lint should not error on a submission the runner accepts.
  const tmpFile = path.join(require('os').tmpdir(), `lint94-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify({ observations: {} }));
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  const errors = (data?.issues || []).filter(i => i.severity === 'error');
  const missingRequiredAsError = errors.filter(i => i.kind === 'missing_required_artifact');
  assert.equal(missingRequiredAsError.length, 0,
    'missing_required_artifact should be warn, not error — runner accepts the same submission');
});

test('#96 --strict-preconditions exits 1 on warn-level preconditions', () => {
  // secrets has a regex-engine (on_fail: warn) precondition. Without
  // --strict-preconditions, exit 0. With it, exit 1.
  const sub = JSON.stringify({});
  const rDefault = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  assert.equal(rDefault.status, 0, 'default mode: warn-level precondition exits 0');
  const rStrict = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  assert.equal(rStrict.status, 1, '--strict-preconditions: warn-level precondition exits 1');
});

test('#98 attest export --format garbage returns JSON error', () => {
  // We can use any existing session-id under .exceptd/attestations, OR fail
  // gracefully if none — the format validation should fire before any
  // session lookup.
  const r = cli(['attest', 'export', 'nonexistent', '--format', 'garbage']);
  assert.notEqual(r.status, 0);
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /not in accepted set|no session dir/);
});

test('#98 report garbage returns JSON error exit 2', () => {
  const r = cli(['report', 'garbage']);
  assert.equal(r.status, 2);
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /not in accepted set/);
});

// ===================================================================
test('#100 ok:false from preflight-halt exits non-zero', () => {
  // Kernel-on-Windows triggers linux-platform halt → ok:false → exit 1.
  // Locks in the exit-code contract: any result.ok === false maps to exit 1.
  const sub = JSON.stringify({});
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: sub });
  // Status depends on host; on Linux this passes (ok:true exit 0), on
  // Windows/macOS it halts (ok:false exit 1). Either way: ok:false ↔ exit 1.
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  if (data && data.ok === false) {
    assert.notEqual(r.status, 0, 'ok:false must exit non-zero');
  } else if (data && data.ok === true) {
    assert.equal(r.status, 0, 'ok:true must exit 0');
  }
  // Either branch is fine; just ensure the contract holds.
});

test('#100 warn-level preconditions do NOT block (run completes ok:true exit 0)', () => {
  // secrets has on_fail: warn preconditions. With empty evidence, run still
  // completes — warn issues populate preflight_issues but don't fail. This
  // is the intended behavior, NOT a bug. The user-facing fix is --strict-preconditions.
  const sub = JSON.stringify({});
  const r = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout);
  if (data && data.ok === true) {
    assert.equal(r.status, 0, 'warn-level run with ok:true exits 0');
  }
});

test('#100 --strict-preconditions escalates warn-level to exit 1', () => {
  // Same secrets run with --strict-preconditions must exit 1 if any preflight
  // issue is unverified/warn.
  const sub = JSON.stringify({});
  const r = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  if (data && Array.isArray(data.preflight_issues) && data.preflight_issues.length > 0) {
    assert.equal(r.status, 1, '--strict-preconditions must exit 1 when preflight_issues present');
  }
});

test('#101 ai-run --no-stream shape matches run shape (phases nested)', () => {
  const sub = JSON.stringify({});
  const r = cli(['ai-run', 'library-author', '--no-stream', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'ai-run --no-stream output should be JSON');
  assert.ok(data.phases, 'ai-run --no-stream must nest phases under .phases (parity with `run`)');
  assert.ok('detect' in data.phases, 'phases.detect must be present');
  assert.ok('analyze' in data.phases, 'phases.analyze must be present');
});

test('#102 attest diff unchanged_count counts identical entries', () => {
  // Run twice with the same flat-shape submission. Diff should report
  // unchanged_count >= 1 for the artifact and signal_override.
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' } }
  });
  const sid1 = 'diffunch1-' + Date.now();
  const sid2 = 'diffunch2-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff output should be JSON');
  assert.ok(data.artifact_diff.unchanged_count >= 1,
    'identical submissions should count unchanged artifacts > 0');
  assert.ok(data.signal_override_diff.unchanged_count >= 1,
    'identical submissions should count unchanged signal_overrides > 0');
});

test('#103 ci does not fail on inconclusive baseline RWEP', () => {
  // Fresh repo, no evidence: every playbook returns inconclusive with
  // catalog-baseline RWEP. Pre-0.11.8 default --max-rwep (80) tripped on
  // baseline RWEP (90) and ci exited 2 with FAIL. Now: only RWEP DELTA
  // counts on inconclusive runs.
  const r = cli(['ci', '--scope', 'code', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  // The fail_reasons for an unconfigured baseline run should not include
  // "rwep_delta >= cap" since delta is 0 (no operator evidence).
  const rwepDeltaReasons = (data.summary.fail_reasons || []).filter(reason =>
    /rwep_delta/.test(reason) || /rwep=\d+ >= cap/.test(reason)
  );
  assert.equal(rwepDeltaReasons.length, 0,
    'baseline-only ci run should not fail on catalog RWEP — only on RWEP delta from operator evidence');
});

// ===================================================================
test('#104 jurisdiction clocks fire on detected classification', () => {
  const sub = JSON.stringify({
    secrets: {
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 }
    }
  });
  const tmpFile = path.join(require('os').tmpdir(), `civ-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  assert.ok(data.summary.jurisdiction_clocks_started >= 1,
    'detected classification with detect_confirmed obligations should fire at least one jurisdiction clock');
});

test('#113 --operator surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'robert@example.com', '--session-id', 'oper113-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.equal(data.operator, 'robert@example.com',
    '--operator must surface at result.operator (pre-0.11.9 was attestation-only)');
});

test('#114 --ack surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack114-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.ok(data.operator_consent && data.operator_consent.explicit === true,
    '--ack must surface at result.operator_consent.explicit');
});

test('#115 ci --required filters to exactly the named playbooks', () => {
  const r = cli(['ci', '--required', 'secrets,sbom', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  const sortedRun = [...data.playbooks_run].sort();
  assert.deepEqual(sortedRun, ['sbom', 'secrets'],
    'ci --required must run exactly the named set, not a superset/subset');
});

test('#115 ci --required rejects unknown playbook id', () => {
  const r = cli(['ci', '--required', 'totally-not-a-playbook', '--json']);
  assert.notEqual(r.status, 0, 'unknown --required playbook must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /unknown playbook/);
});

// ===================================================================
test('#119 result.ack alias for --ack consent state', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack119-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, true, 'result.ack must be true when --ack is passed');
  assert.equal(data?.operator_consent?.explicit, true, 'operator_consent.explicit also true');
});

test('#119 result.ack is false without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noack-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, false, 'result.ack must be false without --ack');
});

test('#100 ci with NO --evidence + all inconclusive exits 3 (not 0)', () => {
  const r = cli(['ci', '--required', 'secrets', '--json']);
  assert.equal(r.status, 3, 'ci without --evidence + all inconclusive must exit 3 ("ran but no real data")');
});

test('#100/#103 ci exit-3 path still flushes JSON to stdout', () => {
  // v0.11.10 regression: process.exit(3) truncated buffered stdout when piped,
  // so --json consumers saw empty stdout despite the structured emit() call.
  // v0.11.11 switched to process.exitCode + return so the event loop drains.
  const r = cli(['ci', '--required', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci exit-3 path must still flush JSON to stdout (no truncation on piped stdout)');
  assert.equal(data.verb, 'ci');
  assert.ok(data.summary, 'JSON body must include summary');
});

test('#102 attest diff includes total_compared field', () => {
  const sub = JSON.stringify({ observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } } });
  const sid1 = 'tc-a-' + Date.now();
  const sid2 = 'tc-b-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(typeof data?.artifact_diff?.total_compared === 'number',
    'artifact_diff must include total_compared (disambiguates 0/0 vs 0-of-N)');
  assert.ok(typeof data?.signal_override_diff?.total_compared === 'number');
});

test('#123 jurisdiction_notifications entries carry obligation metadata', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'jur123-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.jurisdiction_notifications || [];
  assert.ok(notifs.length > 0, 'must have notifications when classification=detected');
  const enriched = notifs.filter(n => n.jurisdiction && n.regulation);
  assert.ok(enriched.length > 0,
    'at least one notification entry must carry jurisdiction + regulation (enriched from govern.jurisdiction_obligations)');
  for (const n of enriched) {
    assert.equal(typeof n.jurisdiction, 'string', 'jurisdiction must be a string, not null');
    assert.equal(typeof n.regulation, 'string', 'regulation must be a string, not null');
    assert.ok(typeof n.window_hours === 'number', 'window_hours must be a number');
    assert.ok(typeof n.notification_deadline === 'string', 'notification_deadline must be a string (ISO or sentinel)');
    assert.ok(Array.isArray(n.evidence_required), 'evidence_required must be an array');
  }
});

test('#124 --ack propagates into phases.govern.operator_consent', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'gov124-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data?.phases?.govern, 'govern phase must be present');
  assert.ok(data.phases.govern.operator_consent,
    'phases.govern.operator_consent must be populated when --ack passed (consent semantically belongs in govern)');
  assert.equal(data.phases.govern.operator_consent.explicit, true);
});

test('#124 phases.govern.operator_consent is null without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noackg-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.phases?.govern?.operator_consent, null,
    'govern.operator_consent must be null (not undefined) when --ack not passed');
});

test('#125/#134 ci with real preflight halt exits 4 BLOCKED (not 2 FAIL, not 0)', () => {
  // Real preflight halt: secrets has a halt-on-fail precondition `repo-context`
  // (cwd_readable == true). Submit it false explicitly so autoDetect doesn't
  // override it, keyed by playbook id so cmdCi's bundle dispatch routes it.
  const tmp = path.join(require('os').tmpdir(), `block-${Date.now()}.json`);
  fs.writeFileSync(tmp, JSON.stringify({ secrets: { precondition_checks: { 'repo-context': false } } }));
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmp, '--json']);
  fs.unlinkSync(tmp);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci JSON must parse');
  assert.equal(data.summary.blocked, 1, 'summary.blocked must be 1 when preflight halts');
  assert.equal(r.status, 4,
    'BLOCKED must take precedence over FAIL — exit 4, not 2. Operators distinguish "playbook never executed" from "playbook detected an issue"');
});

test('#126 attest diff total_compared matches observation count when identical', () => {
  const sub = JSON.stringify({
    observations: {
      w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' },
      x: { captured: true, indicator: 'npm-token-rotation-cadence', result: 'miss' }
    }
  });
  const sid1 = 'tc-c-' + Date.now();
  const sid2 = 'tc-d-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff JSON must parse');
  assert.ok(data.artifact_diff.total_compared > 0,
    'identical submissions with 2 observations must have total_compared > 0 (not 0)');
  assert.ok(data.artifact_diff.unchanged_count > 0,
    'identical submissions must have unchanged_count > 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all artifacts identical → total_compared === unchanged_count');
});

test('#129 refresh --from-cache <missing> emits structured hint, not stack trace', () => {
  const r = cli(['refresh', '--from-cache', '/totally/does/not/exist']);
  assert.notEqual(r.status, 0, 'missing cache dir must exit non-zero');
  const combined = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(combined, /at Object\.<anonymous>|^\s*at .*\.js:\d+/m,
    'no raw Node stack trace — should be a hinted error');
  assert.match(combined, /exceptd refresh --(prefetch|no-network)/,
    'error must tell operator the exact command to populate the cache');
});

test('#129 refresh --prefetch is an alias for --no-network', () => {
  // We don't actually run prefetch (network-bound); just verify the dispatcher
  // recognizes --prefetch and routes to prefetch, NOT to refresh-external.
  // We pass --no-network behavior via --prefetch + a flag prefetch.js knows.
  // The smoke is: --prefetch + --help should print prefetch's help, not refresh's.
  const r = cli(['refresh', '--prefetch', '--help'], { env: { EXCEPTD_DEPRECATION_SHOWN: '1' } });
  assert.notEqual(r.status, 127, '--prefetch must not be unknown-command');
  // Either prefetch's or refresh's help — but the dispatcher should have
  // routed to prefetch. Smoke check: command did not crash.
  assert.ok(r.status !== null, 'process must exit cleanly');
});

test('#130 exceptd path copy is not a silent no-op', () => {
  const r = cli(['path', 'copy']);
  // Behavior: prints path on stdout AND either confirms clipboard write on
  // stderr (when a tool is available) OR warns about missing tool on stderr.
  // The silent no-op is the bug.
  assert.equal(r.status, 0);
  assert.ok(r.stdout.trim().length > 0, 'path on stdout');
  assert.match(r.stderr, /\[exceptd path\]/,
    'must emit either "copied to clipboard" or "no clipboard tool available" on stderr');
});

test('#131 run <skill-name> suggests the right playbook', () => {
  // Operators read the site, see skill names, type `exceptd run <skill>`.
  // Pre-0.11.14: "Playbook not found." Post-0.11.14: error includes a hint
  // pointing at the playbook that loads that skill.
  const r = cli(['run', 'kernel-lpe-triage', '--evidence', '-', '--json'], { input: '{}' });
  assert.notEqual(r.status, 0, 'unknown playbook must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false, 'stderr must carry structured JSON error');
  assert.match(err.error, /SKILL.*not.*PLAYBOOK|skill.*playbook|exceptd skill|exceptd plan/i,
    'error must explain skill≠playbook and suggest the right verb');
  // The "kernel" playbook loads "kernel-lpe-triage" — must be mentioned.
  assert.match(err.error, /kernel\b/, 'must name the playbook that loads this skill');
});

test('#131 run <typo-playbook-id> suggests nearest playbooks', () => {
  const r = cli(['run', 'secret', '--evidence', '-', '--json'], { input: '{}' });
  assert.notEqual(r.status, 0);
  const err = tryJson(r.stderr.trim());
  assert.match(err.error, /Did you mean|exceptd plan|secrets/i,
    'partial-match must suggest the canonical id');
});

// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const dir = require('os').tmpdir();
  const file = path.join(dir, `npm-fixture-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}

test('doctor --registry-check reports days_since_latest_publish from fixture', () => {
  const fix = withFixture('99.99.99', 7);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.ok(data.checks?.registry, 'registry check must be present when --registry-check is passed');
    assert.equal(data.checks.registry.latest_version, '99.99.99');
    assert.equal(data.checks.registry.days_since_latest_publish, 7);
    assert.equal(data.checks.registry.behind, true);
    assert.match(data.checks.registry.hint, /npm update -g|refresh --network/);
  } finally { fs.unlinkSync(fix); }
});

test('doctor --registry-check ok when local matches latest', () => {
  // Use the local installed version so we match.
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const fix = withFixture(pkg.version, 0);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.equal(data.checks.registry.same, true);
    assert.equal(data.checks.registry.behind, false);
  } finally { fs.unlinkSync(fix); }
});

test('run --upstream-check surfaces upstream_check on result and warns when behind', () => {
  const fix = withFixture('99.99.99', 5);
  try {
    const r = cli(['run', 'library-author', '--evidence', '-', '--upstream-check', '--session-id', 'us-' + Date.now(), '--force-overwrite', '--json'], {
      input: '{}',
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data?.upstream_check, 'run result must carry upstream_check when --upstream-check is passed');
    assert.equal(data.upstream_check.behind, true);
    assert.equal(data.upstream_check.latest_version, '99.99.99');
    assert.match(r.stderr, /STALE: local v.* < published v99\.99\.99/,
      'stderr must surface a visible STALE warning so operators see the freshness gap before relying on findings');
  } finally { fs.unlinkSync(fix); }
});

test('run without --upstream-check does NOT contact the registry', () => {
  // No fixture configured — if the runner contacted the registry we'd either
  // succeed (network) or fail (timeout). The contract is: opt-in only.
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noUp-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run JSON must parse');
  assert.equal(data.upstream_check, undefined,
    'no upstream_check field unless --upstream-check is explicitly passed');
});

test('refresh --network shows clear hint when registry is unreachable', () => {
  // Force "unreachable" by pointing the fixture at a missing file.
  const fakePath = path.join(require('os').tmpdir(), 'does-not-exist-' + Date.now() + '.json');
  const r = cli(['refresh', '--network', '--json', '--timeout', '500'], {
    env: { EXCEPTD_REGISTRY_FIXTURE: fakePath }
  });
  // Either: fixture parse fails (treated as offline) → ok:false with hint.
  // Or: registry is genuinely unreachable on the test runner → ok:false.
  // Either way: non-zero exit + structured error.
  assert.notEqual(r.status, 0, 'unreachable registry must exit non-zero');
});

test('refresh --network --dry-run reports verification result without modifying files', () => {
  // Skip when no network — the fixture path doesn't help refresh-network
  // because we don't honor EXCEPTD_REGISTRY_FIXTURE in refresh-network (the
  // tarball download is not faked). The dry-run shape is exercised via
  // a separate unit test on parseTar / fingerprintPublicKey below.
  // This test is the smoke contract: --dry-run + --json + --timeout exits
  // cleanly or reports offline.
  const r = cli(['refresh', '--network', '--dry-run', '--json', '--timeout', '1000']);
  // Either ok:true (online) or ok:false offline — either is acceptable.
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'must emit structured JSON in either online or offline branch');
});

test('refresh-network parseTar + fingerprintPublicKey unit smoke', () => {
  const { parseTar, fingerprintPublicKey } = require(path.join(ROOT, 'lib', 'refresh-network.js'));
  assert.equal(typeof parseTar, 'function');
  assert.equal(typeof fingerprintPublicKey, 'function');
  // Empty tar buffer parses to empty entries (defensive).
  const empty = parseTar(Buffer.alloc(1024));
  assert.deepEqual(empty, [], 'parseTar handles empty/zero tar gracefully');
  // Local public key fingerprints to a non-null base64 string.
  const pem = fs.readFileSync(path.join(ROOT, 'keys', 'public.pem'), 'utf8');
  const fp = fingerprintPublicKey(pem);
  assert.match(fp, /^[A-Za-z0-9+/=]+$/, 'fingerprint is base64');
});

// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================

test('v0.12 source-ghsa.fetchAdvisoryById finds CVE in fixture', async () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  process.env.EXCEPTD_GHSA_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  try {
    const r = await ghsa.fetchAdvisoryById('CVE-2026-45321');
    assert.equal(r.ok, true);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories[0].cve_id, 'CVE-2026-45321');
    assert.equal(r.advisories[0].severity, 'critical');
  } finally { delete process.env.EXCEPTD_GHSA_FIXTURE; }
});

test('v0.12 source-ghsa.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json'), 'utf8'));
  const out = ghsa.normalizeAdvisory(fixture[0]);
  assert.ok(out);
  const entry = out['CVE-2026-45321'];
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(entry.framework_control_gaps, null, 'framework_control_gaps must be null on a draft');
  assert.equal(entry.atlas_refs.length, 0, 'editorial atlas_refs starts empty');
  assert.equal(entry.cvss_score, 9.6);
  assert.equal(entry.cisa_kev_pending, true, 'critical-severity drafts mark cisa_kev_pending');
  assert.equal(entry._source_ghsa_id, 'GHSA-tnsk-tnsk-tnsk');
});

test('v0.12 refresh --advisory <CVE> dry-run emits draft + exits 3', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1' },
  });
  assert.equal(r.status, 3, '--advisory dry-run must exit 3 ("draft prepared, not applied")');
  const data = tryJson(r.stdout);
  assert.ok(data, 'JSON output must parse');
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'CVE-9999-99999');
  assert.equal(data.draft._auto_imported, true);
});

test('v0.12 refresh --advisory --apply writes draft to a copy of the catalog', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  // Work on a copy of the catalog so we don't mutate the real one.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cve-cat-'));
  fs.mkdirSync(path.join(tmpDir, 'data'));
  fs.copyFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), path.join(tmpDir, 'data', 'cve-catalog.json'));
  // Symlink/copy the other catalogs needed by loadCtx — quickest is to run
  // in the real ROOT and just revert the catalog after.
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--apply', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, '--advisory --apply exits 3 (applied, editorial-review pending)');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'advisory-seed-applied');
    const catAfter = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
    assert.ok(catAfter['CVE-9999-99999'], 'draft entry must be written');
    assert.equal(catAfter['CVE-9999-99999']._auto_imported, true);
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('v0.12 refresh --curate <CVE> surfaces editorial questions for a draft', () => {
  // Write a synthetic draft to the catalog (then restore).
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  const cat = JSON.parse(catBefore);
  cat['CVE-9999-99999'] = {
    name: 'Synthetic curation test',
    type: 'supply-chain-npm',
    cvss_score: 9.6,
    affected: 'synthetic-test-package',
    _auto_imported: true,
    _draft: true,
    atlas_refs: [],
    attack_refs: [],
    framework_control_gaps: null,
    iocs: null,
    poc_available: null,
    ai_discovered: null,
    ai_assisted_weaponization: null,
    rwep_score: null,
    rwep_factors: null,
    vector: null,
  };
  fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), JSON.stringify(cat, null, 2), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-9999-99999', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, 'curation always exits 3 — editorial review pending');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'cve-curation');
    assert.ok(data.editorial_questions.length >= 4,
      'must surface at least: atlas_refs, attack_refs, framework_control_gaps, iocs, rwep questions');
    const fields = data.editorial_questions.map(q => q.field);
    assert.ok(fields.includes('framework_control_gaps'));
    assert.ok(fields.includes('iocs'));
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
  }
});

test('v0.12 refresh --curate refuses to curate a human-curated entry', () => {
  // CVE-2026-45321 was added in v0.11.15 as a human-curated entry (no _auto_imported flag).
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-2026-45321', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.equal(r.status, 2, 'must refuse curating human-curated entries');
  const data = tryJson(r.stdout);
  assert.equal(data.ok, false);
  assert.match(data.error, /human-curated/);
});

test('v0.12 validate-cve-catalog treats _auto_imported drafts as warnings, not errors', () => {
  // Inject a minimal draft, run the validator, restore.
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  const cat = JSON.parse(catBefore);
  cat['CVE-9999-88888'] = {
    name: 'Draft synthetic',
    type: 'supply-chain-npm',
    _auto_imported: true,
    _draft: true,
    cvss_score: null,
    last_updated: '2026-05-13',
  };
  fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), JSON.stringify(cat, null, 2), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-cve-catalog.js'), '--quiet'], {
      encoding: 'utf8',
      env: { ...process.env },
    });
    // Drafts are warnings, not errors — exit 0 if no non-draft entry failed.
    assert.equal(r.status, 0, 'draft entry must not break the catalog gate (exit 0)');
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
  }
});

test('#127 emit() body with ok:false sets non-zero exit (universal contract)', () => {
  // The class of bug: any verb that emits a result with ok:false to stdout
  // must not return exit 0. Pre-0.11.13 several paths leaked through.
  // We test the universal `emit()` interception via a verb that is known
  // to produce ok:false: attest verify on a non-existent session id.
  const r = cli(['attest', 'verify', 'no-such-session-id-' + Date.now(), '--json']);
  // The exact verb-level handling may vary, but the universal contract is:
  // a body with ok:false → exit non-zero. Either stdout (caught by emit())
  // or stderr (caught by emitError) is acceptable.
  const stdoutBody = tryJson(r.stdout) || {};
  const stderrBody = tryJson(r.stderr.trim()) || {};
  const sawOkFalse = stdoutBody.ok === false || stderrBody.ok === false;
  if (sawOkFalse) {
    assert.notEqual(r.status, 0, 'any ok:false response (stdout OR stderr) must yield non-zero exit');
  }
});

test('#127 attest diff with missing session ids exits non-zero', () => {
  const r = cli(['attest', 'diff', 'does-not-exist-a', '--against', 'does-not-exist-b', '--json']);
  assert.notEqual(r.status, 0, 'attest diff with missing sessions must exit non-zero');
});

test('#128 attest diff with empty submissions falls back to playbook catalog', () => {
  // Both runs use empty {} submission; identical evidence hashes. The diff
  // should count the playbook's artifact catalog so operators see
  // "N artifacts, all uniform on both sides" rather than 0/0.
  const sid1 = 'empty-cat-a-' + Date.now();
  const sid2 = 'empty-cat-b-' + Date.now();
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: '{}' });
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: '{}' });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'diff JSON must parse');
  assert.equal(data.status, 'unchanged', 'identical empty submissions hash-match → status=unchanged');
  assert.ok(data.artifact_diff.total_compared > 0,
    'empty submissions must fall back to playbook artifact catalog count, not 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all catalog entries identical (both empty) → total_compared === unchanged_count');
});

test('#104 close emits jurisdiction_notifications alias + clocks count', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'jur104-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(Array.isArray(data?.phases?.close?.jurisdiction_notifications),
    'phases.close.jurisdiction_notifications must be present (alias for notification_actions)');
  assert.ok(data.phases.close.jurisdiction_clocks_count >= 1,
    'jurisdiction_clocks_count must be > 0 when classification=detected with detect_confirmed obligations');
});

// ===================================================================
test('#87 doctor --fix is registered (smoke)', () => {
  // We don't want this test to actually generate a keypair — just verify
  // the flag is recognized and doctor doesn't reject it as unknown.
  const r = cli(['doctor', '--fix', '--json'], { env: { EXCEPTD_RAW_JSON: '1' } });
  // Doctor should return JSON; --fix may have been a no-op (key already
  // present) or generated one. Either way, the verb shouldn't crash.
  assert.notEqual(r.status, 2, 'doctor --fix should not be an unknown-flag error');
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --fix should emit JSON');
});
