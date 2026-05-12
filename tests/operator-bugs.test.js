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
