'use strict';

/**
 * tests/usability-fixes-v016.test.js
 *
 * Regression coverage for the operator-usability fixes shipped in 0.16.0,
 * derived from the multi-agent usability audit. Each test pins a fixed
 * behavior so the gap cannot silently regress.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const home = makeSuiteHome('exceptd-usability-v016-');
const cli = makeCli(home);

test('run <playbook> --evidence-dir refuses loudly instead of silently running on empty evidence', () => {
  // Usability P1: a single named playbook ignored --evidence-dir (a contract-run
  // input), so `run secrets --evidence-dir ./ev` reported a clean verdict
  // against EMPTY evidence — a falsely-reassuring result from a security tool.
  const r = cli(['run', 'secrets', '--evidence-dir', home, '--json']);
  assert.notEqual(r.status, 0, 'must NOT exit 0 — silently ignoring --evidence-dir produced a false all-clear');
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.equal(body.ok, false, 'error envelope must carry ok:false');
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /--evidence-dir/, 'message names the offending flag');
  assert.match(text, /--evidence\b|contract|--all|--scope/, 'message points at the correct alternative (--evidence / contract run)');
});

test('empty stdin on the auto-promotion path does NOT emit the nudge (so 2>&1 | jq stays parseable in CI)', () => {
  // Usability P1: `run <pb>` with a non-TTY stdin auto-promotes to --evidence -,
  // and an empty read wrote a "[exceptd] note: ... read 0 bytes" line to stderr,
  // corrupting `run ... 2>&1 | jq` pipelines that passed at a TTY.
  const r = cli(['run', 'secrets', '--json'], { input: '' });
  assert.doesNotMatch(r.stderr || '', /read 0 bytes from stdin/, 'auto-promoted empty stdin must not nudge on stderr');
});

test('an EXPLICIT --evidence - with empty stdin still nudges (the operator asked to pipe)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
  assert.match(r.stderr || '', /read 0 bytes from stdin/, 'explicit --evidence - with empty stdin should still warn the operator');
});
