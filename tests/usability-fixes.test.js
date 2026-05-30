'use strict';

/**
 * tests/usability-fixes.test.js
 *
 * Regression coverage for the operator-usability fixes for the operator-usability pass,
 * derived from the multi-agent usability audit. Each test pins a fixed
 * behavior so the gap cannot silently regress.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const home = makeSuiteHome('exceptd-usability-');
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

test('exceptd skill (no args) lists every skill ID so they are discoverable', () => {
  // Usability P1: skill IDs were undiscoverable — `skill` and its not-found
  // error pointed at `brief --all`, which lists playbooks, not skills.
  const manifest = require('../manifest.json');
  const r = cli(['skill', '--json']);
  assert.notEqual(r.status, 0, 'no-args skill is a usage error (non-zero)');
  const body = tryJson(r.stdout) || {};
  assert.equal(body.ok, false, 'usage envelope is ok:false');
  assert.ok(Array.isArray(body.skills), 'lists a skills array');
  assert.equal(body.skills.length, manifest.skills.length, 'lists every manifest skill');
  assert.ok(body.skills.every(s => s.id && typeof s.description === 'string'), 'each entry has an id + description');
  const human = cli(['skill']);
  assert.match(human.stderr || '', new RegExp(`Available skills \\(${manifest.skills.length}\\)`), 'human usage shows the skill count');
});

test('brief <playbook> footer reveals the collect verb (so brief-first operators do not run on empty evidence)', () => {
  // Usability P1: brief ended with `Run: exceptd run <pb> --evidence <file|->`
  // but never said where that file comes from — the collect verb was invisible.
  // brief renders human output unless EXCEPTD_RAW_JSON is set (the harness sets
  // it for determinism); clear it here so we exercise the human footer.
  const r = cli(['brief', 'secrets'], { env: { EXCEPTD_RAW_JSON: '' } });
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /exceptd collect secrets \| exceptd run secrets --evidence -/, 'brief footer must show the collect pipeline');
});
