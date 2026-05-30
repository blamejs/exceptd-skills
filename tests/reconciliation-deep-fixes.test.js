'use strict';

/**
 * tests/reconciliation-deep-fixes.test.js
 *
 * Regression coverage for the deep-reconciliation pass: error-envelope
 * consistency (verb attribution + error_class), the run --format missing-value
 * guard, and the validate-cves offline exit using safeExit instead of a
 * truncation-prone process.exit after a stdout write. Each test pins an exact
 * exit code and value+type per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const home = makeSuiteHome('exceptd-reconcile-deep-');
const cli = makeCli(home);

for (const verb of ['ci', 'run-all', 'ai-run']) {
  test(`${verb} attributes a --session-id validation error to itself, not "run"`, () => {
    // dispatchPlaybook is shared by run/ci/run-all/ai-run, but its attestation
    // validators hardcoded "run:" + omitted verb, mis-attributing the error
    // when invoked via a sibling verb.
    const r = cli([verb, 'kernel', '--session-id', '../evil', '--json'], { input: '{}' });
    assert.equal(r.status, 1, `${verb} session-id refusal must exit exactly 1`);
    const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(err.ok, false, 'error envelope carries ok:false');
    assert.equal(err.verb, verb, `verb field must be "${verb}"`);
    assert.equal(typeof err.verb, 'string', 'verb is a string');
    assert.match(err.error, new RegExp(`^${verb}:`), `message prefix is "${verb}:"`);
    assert.doesNotMatch(err.error, /^run:/, 'message must not mis-attribute to run');
  });
}

test('ci --mode garbage attributes the error to ci (not run) and carries verb', () => {
  const r = cli(['ci', 'kernel', '--mode', 'garbage', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'invalid --mode exits exactly 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.verb, 'ci', 'verb is ci');
  assert.match(err.error, /^ci:/, 'prefix is ci:');
});

test('brief --ack irrelevant-flag refusal carries flag + error_class like its siblings', () => {
  // --ack was the only one of six irrelevant-flag refusals lacking flag +
  // error_class, both of which are load-bearing machine-readable fields.
  const r = cli(['brief', 'kernel-lpe-triage', '--ack', '--json']);
  assert.equal(r.status, 1, '--ack on brief refuses with exit 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.ok, false, 'ok:false');
  assert.equal(err.error_class, 'irrelevant-flag', 'error_class names the class');
  assert.equal(err.flag, 'ack', 'flag names the offending flag');
  assert.equal(err.verb, 'brief', 'verb is brief');
});

test('run --format with no value refuses (format is now a known value-bearing flag)', () => {
  const r = cli(['run', 'kernel', '--format', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'missing --format value exits exactly 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.ok, false, 'ok:false');
  assert.equal(err.flag, 'format', 'names the flag missing its value');
  assert.match(err.error, /--format requires a value/, 'states the missing value');
});

test('framework-gap unknown-framework refusal carries the verb field', () => {
  const r = cli(['framework-gap', 'NONSENSE-FRAMEWORK', 'prompt injection', '--json']);
  assert.equal(r.status, 1, 'unknown framework exits exactly 1');
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.equal(body.ok, false, 'ok:false');
  assert.equal(body.verb, 'framework-gap', 'verb field present');
  assert.equal(typeof body.verb, 'string', 'verb is a string');
  assert.ok(Array.isArray(body.known_frameworks), 'still lists known_frameworks');
});

test('validate-cves --offline exits 0 with its trailing summary intact (no truncation)', () => {
  // The offline path used process.exit(0) right after a console.log, the
  // truncation-prone pattern the project forbids; it now uses safeExit. Pin
  // exact status 0 AND the presence of the last line written before exit.
  const r = cli(['validate-cves', '--offline']);
  assert.equal(r.status, 0, 'offline validate-cves exits exactly 0');
  assert.match(r.stdout, /offline mode — no network calls made\. \d+ entries listed/,
    'the trailing summary line (last bytes before exit) survives');
});

test('discover --help documents --cwd (accepted + typo-suggestible but was undocumented)', () => {
  const out = (cli(['discover', '--help']).stdout || '') + (cli(['discover', '--help']).stderr || '');
  assert.match(out, /--cwd/, 'discover --help must document --cwd');
});
