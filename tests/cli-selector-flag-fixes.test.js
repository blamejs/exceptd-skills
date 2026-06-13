'use strict';

/**
 * Regression for CLI selector + flag-relevance handling.
 *
 *   - `ci --required ""` / `ci --scope ""` must REFUSE (empty selector), not
 *     fall through to cwd auto-detect and emit a green pass for an unrequested
 *     playbook set (a false green)
 *   - `ci --required` with no value must give a clean usage refusal, not an
 *     "internal error … file a bug" report
 *   - `report --json` (no format) must emit JSON, not exit 1 on "--json" as a
 *     format; `--json` must produce JSON for the non-csaf formats too
 *   - `--cwd` on a verb that does not consume it (run) must be refused, not
 *     silently ignored
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

const SUITE_HOME = makeSuiteHome('exceptd-selector-fix-');
const cli = makeCli(SUITE_HOME);

test('ci --required "" is refused (no false-green fall-through)', () => {
  const r = cli(['ci', '--required', '', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.equal(body.ok, false);
  assert.match(body.error, /empty playbook list/);
});

test('ci --scope "" is refused with the accepted-set message', () => {
  const r = cli(['ci', '--scope', '', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.equal(body.ok, false);
  assert.doesNotMatch(JSON.stringify(body), /"verdict":\s*"PASS"/);
});

test('ci --required with no value gives a clean usage refusal, not an internal error', () => {
  const r = cli(['ci', '--required']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.equal(body.ok, false);
  assert.match(body.error, /--required requires a value/);
  assert.doesNotMatch(body.error, /internal error/);
});

test('run --cwd is refused on a verb that does not consume it', () => {
  const r = cli(['run', 'secrets', '--cwd', '/nonexistent-path', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.equal(body.ok, false);
  assert.match(JSON.stringify(body), /irrelevant|only applies to.*collect/i);
});

test('report --json (no format) emits parseable JSON, not a format error', () => {
  const r = cli(['report', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body && typeof body === 'object', 'stdout must parse as JSON');
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'report');
  assert.equal(body.format, 'technical');
});

test('report executive --json emits JSON for a non-csaf format (not Markdown)', () => {
  const r = cli(['report', 'executive', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body && typeof body === 'object', 'stdout must parse as JSON, not render Markdown');
  assert.equal(body.format, 'executive');
  assert.ok(body.summary && typeof body.summary === 'object');
});
