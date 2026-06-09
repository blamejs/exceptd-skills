'use strict';

/**
 * The e2e scenario runner (scripts/run-e2e-scenarios.js) must not let a
 * scenario pass when the CLI did not actually run as intended:
 *
 *   (1) spawnSync's failure channels (res.error on launch failure / timeout,
 *       res.signal on a kill) must surface as failures. Reading only
 *       res.status let a timed-out run (status null) masquerade as a plain
 *       non-zero exit or a JSON-parse failure.
 *   (2) a scenario that binds NO positive assertion (no expect_exit, no
 *       json_path_* matcher) must FAIL as a config error rather than passing
 *       vacuously for any CLI behavior including a crash.
 *
 * evaluateScenario is pure (takes a synthetic spawnSync result), so both gates
 * are tested deterministically without a real timeout or subprocess.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { evaluateScenario, diffExpect, runScenario } = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

test('a spawnSync timeout (status null + SIGTERM + ETIMEDOUT) is surfaced, not masked', () => {
  const res = { status: null, signal: 'SIGTERM', error: Object.assign(new Error('spawnSync ETIMEDOUT'), { code: 'ETIMEDOUT' }), stdout: '', stderr: '' };
  const failures = evaluateScenario({ expect_exit: 0 }, {}, res);
  assert.ok(failures.some(f => /spawn error: ETIMEDOUT/.test(f)), 'the ETIMEDOUT spawn error must be reported');
  assert.ok(failures.some(f => /killed by signal SIGTERM/.test(f)), 'the SIGTERM kill must be reported');
});

test('a launch failure (ENOENT, status null, no signal) is surfaced', () => {
  const res = { status: null, signal: null, error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }), stdout: '', stderr: '' };
  const failures = evaluateScenario({ expect_exit: 0 }, {}, res);
  assert.ok(failures.some(f => /spawn error: ENOENT/.test(f)), 'the ENOENT launch failure must be reported');
});

test('a scenario with no binding assertion fails as a config error (not vacuous pass)', () => {
  // No expect_exit, empty expect — both gates would be skipped.
  const res = { status: 0, signal: null, error: undefined, stdout: '', stderr: '' };
  const failures = evaluateScenario({}, {}, res);
  assert.ok(failures.some(f => /no binding assertion/.test(f)),
    'a zero-assertion scenario must fail rather than pass vacuously');
});

test('a scenario crash (non-zero exit, no JSON) is caught even with only a json assertion', () => {
  // Before the fix a crash with no stdout and only json_path assertions would
  // surface as a JSON-parse failure (correct), but a crash under a
  // no-assertion scenario passed. Confirm the json-assertion path still fails
  // a crash, and that a CLEAN run satisfying its assertion passes.
  const crash = { status: 1, signal: null, error: undefined, stdout: '', stderr: 'boom' };
  const crashFailures = evaluateScenario({}, { json_path_present: ['ok'] }, crash);
  assert.ok(crashFailures.some(f => /did not parse as JSON/.test(f)), 'a crash with a json assertion must fail');

  const good = { status: 0, signal: null, error: undefined, stdout: '{"ok":true}', stderr: '' };
  const goodFailures = evaluateScenario({ expect_exit: 0 }, { json_path_equals: { ok: true } }, good);
  assert.deepEqual(goodFailures, [], 'a clean run meeting its assertions must pass');
});

test('diffExpect reports every matcher class and passes a fully-satisfied expect', () => {
  const body = { ok: true, score: 7, label: 'CRITICAL', nested: { id: 'x' } };
  const ctx = { stdout: '', stderr: 'warning: stale', status: 0 };

  // Each matcher class produces a distinct, attributable failure.
  assert.ok(diffExpect(body, { json_path_equals: { ok: false } }, ctx).some(f => /json_path_equals\.ok/.test(f)));
  assert.ok(diffExpect(body, { json_path_present: ['missing'] }, ctx).some(f => /json_path_present\.missing: missing/.test(f)));
  assert.ok(diffExpect(body, { json_path_min: { score: 10 } }, ctx).some(f => /json_path_min\.score/.test(f)));
  assert.ok(diffExpect(body, { json_path_match: { label: '^low$' } }, ctx).some(f => /json_path_match\.label/.test(f)));
  assert.ok(diffExpect(body, { stderr_must_not_match: ['stale'] }, ctx).some(f => /stderr_must_not_match/.test(f)));

  // A fully-satisfied expect (including a nested path and a negative guard
  // that does NOT match) yields zero failures.
  const pass = diffExpect(body, {
    json_path_equals: { 'nested.id': 'x' },
    json_path_present: ['ok'],
    json_path_min: { score: 5 },
    json_path_match: { label: '^CRIT' },
    stderr_must_not_match: ['ETIMEDOUT'],
  }, ctx);
  assert.deepEqual(pass, []);
});

test('runScenario skips a directory with no scenario.json instead of throwing', () => {
  // The runner walks scenario directories; one lacking scenario.json is a
  // skip, not an error that aborts the whole sweep.
  const res = runScenario(path.join(__dirname, '_no_such_scenario_dir_'));
  assert.equal(res.skipped, true);
  assert.match(res.reason, /no scenario\.json/);
});
