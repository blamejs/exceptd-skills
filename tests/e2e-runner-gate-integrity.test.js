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

const { evaluateScenario } = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

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
