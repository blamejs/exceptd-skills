'use strict';

/**
 * The e2e scenario runner's negative guards and its JSON-extraction heuristic
 * must hold even when stdout is not a single clean JSON envelope:
 *
 *   (1) stderr_must_not_match is a release-gate ban on forbidden tokens in
 *       stderr. It must fire regardless of whether stdout parsed as JSON. A
 *       scenario whose stdout is a human banner (only an expect_exit
 *       assertion) previously skipped the ban entirely, a false pass in the
 *       pre-publish gate.
 *
 *   (2) tryParseJson must bind assertions to the verb's JSON envelope, not to
 *       a trailing JSON-parseable scalar log line. Returning a trailing
 *       "done"/42/true would silently test the wrong value.
 *
 * The runner's helpers are pure, so both are tested without spawning the CLI.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  evaluateScenario,
  stderrBanFailures,
  tryParseJson,
} = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

// --- stderr_must_not_match decoupled from JSON parsing -----------------------

test('stderr_must_not_match fires even when stdout is not JSON', () => {
  const res = {
    status: 0,
    signal: null,
    error: undefined,
    stdout: 'human banner, not json',
    stderr: 'BLOCKED happened here',
  };
  const failures = evaluateScenario({ expect_exit: 0 }, { stderr_must_not_match: ['BLOCKED'] }, res);
  assert.ok(
    failures.some(f => /stderr_must_not_match \/BLOCKED\/: stderr contains it/.test(f)),
    'the forbidden token in stderr must fail the scenario even though stdout is a banner',
  );
});

test('non-JSON stdout with clean stderr yields no stderr ban failure (negative control)', () => {
  const res = {
    status: 0,
    signal: null,
    error: undefined,
    stdout: 'human banner, not json',
    stderr: 'all clear',
  };
  const failures = evaluateScenario({ expect_exit: 0 }, { stderr_must_not_match: ['BLOCKED'] }, res);
  assert.deepEqual(failures, [], 'a clean stderr under a banner stdout must pass');
});

test('a json assertion plus a stderr ban reports BOTH the parse failure and the ban', () => {
  // stdout fails to parse AND stderr carries the banned token: the runner must
  // surface both signals, not just the parse failure.
  const res = {
    status: 0,
    signal: null,
    error: undefined,
    stdout: 'human banner, not json',
    stderr: 'BLOCKED here',
  };
  const failures = evaluateScenario(
    { expect_exit: 0 },
    { json_path_present: ['ok'], stderr_must_not_match: ['BLOCKED'] },
    res,
  );
  assert.ok(failures.some(f => /did not parse as JSON/.test(f)), 'the parse failure must be reported');
  assert.ok(
    failures.some(f => /stderr_must_not_match \/BLOCKED\/: stderr contains it/.test(f)),
    'the stderr ban must ALSO be reported, not swallowed by the parse failure',
  );
});

test('the stderr ban still fires on a parsed JSON body (no regression for the happy path)', () => {
  const res = {
    status: 0,
    signal: null,
    error: undefined,
    stdout: '{"ok":true}',
    stderr: 'BLOCKED here',
  };
  const failures = evaluateScenario(
    { expect_exit: 0 },
    { json_path_equals: { ok: true }, stderr_must_not_match: ['BLOCKED'] },
    res,
  );
  assert.ok(
    failures.some(f => /stderr_must_not_match \/BLOCKED\//.test(f)),
    'the ban must fire when stdout DOES parse, too',
  );
});

test('stderrBanFailures reports one failure per banned token that matches', () => {
  const failures = stderrBanFailures({ stderr_must_not_match: ['BLOCKED', 'STALE', 'clean'] }, 'BLOCKED and STALE');
  assert.equal(failures.length, 2, 'exactly the two matching tokens fail');
  assert.ok(failures.some(f => /\/BLOCKED\//.test(f)));
  assert.ok(failures.some(f => /\/STALE\//.test(f)));
  assert.ok(!failures.some(f => /\/clean\//.test(f)), 'a non-matching token must not fail');
});

// --- tryParseJson selects the envelope, not a trailing scalar ----------------

const ENVELOPE = '{"ok":true,"phases":{"detect":{"classification":"detected"}}}';

test('tryParseJson returns the object envelope, not a trailing JSON string scalar', () => {
  const body = tryParseJson(`${ENVELOPE}\n"done"`);
  assert.equal(typeof body, 'object');
  assert.equal(body.phases.detect.classification, 'detected', 'must bind to the envelope, not the trailing "done"');
});

test('tryParseJson returns the object envelope, not a trailing JSON number scalar', () => {
  const body = tryParseJson(`${ENVELOPE}\n42`);
  assert.equal(body && body.ok, true);
  assert.equal(body.phases.detect.classification, 'detected');
});

test('tryParseJson skips a trailing non-JSON log line and binds to the envelope', () => {
  const body = tryParseJson(`${ENVELOPE}\nplain log text`);
  assert.equal(body.phases.detect.classification, 'detected');
});

test('tryParseJson handles a single-line envelope unchanged', () => {
  const body = tryParseJson(ENVELOPE);
  assert.equal(body.phases.detect.classification, 'detected');
});

test('a single-line bare scalar stdout yields no body (no envelope present)', () => {
  // A lone scalar is not a verb envelope; it must not be accepted as the body.
  assert.equal(tryParseJson('"done"'), null);
  assert.equal(tryParseJson('42'), null);
  assert.equal(tryParseJson('true'), null);
});

test('evaluateScenario binds json_path assertions to the envelope despite a trailing scalar', () => {
  const res = {
    status: 0,
    signal: null,
    error: undefined,
    stdout: `${ENVELOPE}\n"done"`,
    stderr: '',
  };
  const failures = evaluateScenario(
    { expect_exit: 0 },
    { json_path_equals: { 'phases.detect.classification': 'detected' } },
    res,
  );
  assert.deepEqual(failures, [], 'the envelope satisfies the assertion; the trailing scalar must not break it');
});
