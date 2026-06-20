'use strict';

/**
 * Regression: `--session-id ""` / `--session-id=` must be refused, not
 * silently substituted with a random id.
 *
 * The dispatcher gated session-id validation on truthiness
 * (`if (args["session-id"])`), so an explicit empty value fell through the
 * validate-and-assign block entirely. runOpts.session_id stayed unset and the
 * runner auto-generated a random id — the operator's explicit intent to pin a
 * session id to "" was discarded with no error, inconsistent with --operator
 * (which rejects empty/whitespace). The value-less form (`--session-id` with no
 * argument) was already caught by REQUIRES_VALUE because it parses to boolean
 * true; only the explicit-empty-string forms slipped.
 *
 * The fix is presence-gating (`!== undefined`) so validateIdComponent runs on
 * "" and returns "must not be empty". These tests assert the EXACT exit code
 * (1), the ok:false envelope, and the "must not be empty" reason — while
 * keeping the positive paths (valid id pins, omitted flag auto-generates,
 * traversal still refused) intact so the fix cannot over-correct.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-session-id-empty-');
const cli = makeCli(SUITE_HOME);

const STDIN = JSON.stringify({ observations: {}, verdict: {} });

test('--session-id "" is refused with exit 1 and "must not be empty"', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', '', '--json'],
    { input: STDIN });
  assert.equal(r.status, 1,
    `--session-id "" must exit 1 (framework error), not auto-generate a random id. ` +
    `status=${r.status} stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 300)}`);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false, 'envelope must be ok:false');
  assert.equal(err.verb, 'run');
  assert.match(err.error || '', /--session-id must not be empty/,
    'error must name the empty-session-id refusal; got: ' + (err.error || ''));
});

test('--session-id= (eq form, empty) is refused with exit 1', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id=', '--json'],
    { input: STDIN });
  assert.equal(r.status, 1,
    `--session-id= must exit 1; got status=${r.status} stderr=${r.stderr.slice(0, 300)}`);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /--session-id must not be empty/,
    'eq-form empty must refuse with the same reason; got: ' + (err.error || ''));
});

test('positive: a valid --session-id still pins the id and runs', () => {
  // Guard against over-correction — presence-gating must not refuse a real id.
  const sid = 'pinned-session-' + Date.now();
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', sid, '--json'],
    { input: STDIN });
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
  assert.equal(body.session_id, sid,
    `valid --session-id must be honored verbatim; got session_id=${JSON.stringify(body.session_id)} ` +
    `status=${r.status} stderr=${r.stderr.slice(0, 200)}`);
});

test('positive: omitting --session-id still auto-generates a random id', () => {
  // The benign fallback must remain — the bug was only that "" reached it.
  const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: STDIN });
  const body = tryJson(r.stdout.trim()) || {};
  assert.equal(body.ok, true, 'omitted session-id must run cleanly; stderr=' + r.stderr.slice(0, 200));
  assert.equal(typeof body.session_id, 'string');
  assert.ok(body.session_id.length > 0, 'auto-generated session id must be non-empty');
});

test('positive: a traversal --session-id is still refused (no security regression)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', '../escape', '--json'],
    { input: STDIN });
  assert.equal(r.status, 1, 'traversal session-id must still exit 1; got ' + r.status);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /--session-id must match/,
    'traversal must refuse via the charset constraint; got: ' + (err.error || ''));
});
