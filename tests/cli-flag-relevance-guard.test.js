'use strict';

/**
 * Regression: PASSTHROUGH_FLAGS that are meaningful on only a subset of verbs
 * (e.g. --max-rwep, consumed only by `ci`) must be REFUSED with the established
 * "irrelevant-flag" guidance when supplied to a verb that does not consume
 * them — not silently dropped. Pre-fix, PASSTHROUGH_FLAGS short-circuited the
 * typo/relevance loop, so `brief secrets --max-rwep 5` exited 0 with the flag
 * read by nothing (output unchanged), giving the operator no signal that the
 * cap was ignored. The fix adds a relevance guard mirroring the bundle-flag
 * refusals (--csaf-status / --tlp / --ack).
 *
 * Exact exit-code + envelope assertions per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-flag-relevance-');
const cli = makeCli(SUITE_HOME);

// A flag only `ci` consumes, supplied to an info-only verb, must be refused.
test('brief --max-rwep → exit 1 with irrelevant-flag error naming ci as the consumer', () => {
  const r = cli(['brief', 'secrets', '--max-rwep', '5', '--json']);
  assert.equal(r.status, 1,
    `brief --max-rwep must exit EXACTLY 1; status=${r.status} stderr=${r.stderr.slice(0, 300)}`);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false, 'error body.ok must be false');
  assert.equal(err.error_class, 'irrelevant-flag',
    `error_class must be "irrelevant-flag"; got ${JSON.stringify(err.error_class)}`);
  assert.equal(err.flag, 'max-rwep',
    `error body must name the offending flag; got ${JSON.stringify(err.flag)}`);
  assert.equal(err.verb, 'brief', `error body must record the invoking verb; got ${JSON.stringify(err.verb)}`);
  assert.deepEqual([...(err.accepted_verbs || [])].sort(), ['ci'],
    `accepted_verbs must be exactly the consuming set; got ${JSON.stringify(err.accepted_verbs)}`);
});

// Positive control: the consuming verb still accepts the flag (no irrelevant
// refusal). `ci --scope code` runs the code-scope playbooks; the cap is honored.
test('ci --scope code --max-rwep 70 is accepted (not refused as irrelevant)', () => {
  const r = cli(['ci', '--scope', 'code', '--max-rwep', '70', '--json'], { timeout: 60000 });
  const body = tryJson((r.stdout || '').trim()) || {};
  // The flag must NOT trigger an irrelevant-flag refusal. The ci run itself
  // may exit 0/2/3/4 depending on findings; what matters is the flag was
  // consumed (no error_class:"irrelevant-flag").
  const err = tryJson(r.stderr.trim()) || {};
  assert.notEqual(err.error_class, 'irrelevant-flag',
    `--max-rwep must be accepted on ci; got refusal: ${r.stderr.slice(0, 300)}`);
  assert.equal(body.verb, 'ci', `ci should produce a ci body; got ${JSON.stringify(body.verb)} stderr=${r.stderr.slice(0, 200)}`);
});

// A second single-verb passthrough flag (--diff-from-latest, consumed only by
// `run`) is refused on an info verb, so the guard is not a one-flag special case.
test('brief --diff-from-latest → exit 1 with irrelevant-flag error naming run', () => {
  const r = cli(['brief', 'secrets', '--diff-from-latest', '--json']);
  assert.equal(r.status, 1, `brief --diff-from-latest must exit EXACTLY 1; status=${r.status}`);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.error_class, 'irrelevant-flag');
  assert.equal(err.flag, 'diff-from-latest');
  assert.deepEqual([...(err.accepted_verbs || [])].sort(), ['run']);
});
