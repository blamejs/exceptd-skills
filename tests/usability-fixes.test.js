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

test('a blocked run renders a human line (not a raw JSON wall) in default human mode', () => {
  // Usability P2: a blocked verdict (preflight precondition unmet — e.g. a
  // Linux-gated playbook on a non-Linux host) emitted the raw ok:false JSON
  // envelope even in human mode, so an operator's first `run` was a wall of
  // JSON. Force the block portably by submitting precondition_checks that set
  // a required precondition false (blocks on every platform, incl. the ubuntu
  // CI leg where kernel would otherwise auto-detect linux-platform=true).
  const r = cli(['run', 'kernel', '--evidence', '-'], {
    input: '{"precondition_checks":{"linux-platform":false}}',
    env: { EXCEPTD_RAW_JSON: '' },
  });
  assert.notEqual(r.status, 0, 'a blocked run is non-zero');
  const out = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(r.stdout || '', /^\s*\{"ok":false/, 'human mode must NOT dump the raw ok:false JSON envelope');
  assert.match(out, /\[blocked\]/, 'human render tags the verdict as [blocked]');
  assert.match(out, /exceptd brief --all|re-run with --json/, 'human render points the operator at a next step');
});

test('a blocked run still returns the full JSON envelope under --json', () => {
  const r = cli(['run', 'kernel', '--evidence', '-', '--json'], {
    input: '{"precondition_checks":{"linux-platform":false}}',
  });
  assert.notEqual(r.status, 0, 'blocked is non-zero under --json too');
  const body = tryJson(r.stdout) || {};
  assert.equal(body.ok, false, '--json keeps the ok:false envelope for machine consumers');
  assert.equal(body.verdict, 'blocked', 'verdict is blocked');
  assert.equal(body.blocked_by, 'precondition', 'blocked_by names the preflight cause');
});

test('--quiet is a recognized global flag (accepted on run/doctor, not refused as unknown)', () => {
  // Usability: --quiet was the one audit-list item with no implementation. It
  // must be accepted on every verb (it lives in VERB_FLAG_ALLOWLIST._global)
  // so the typo-defense does not refuse it. doctor keeps its own flag set, so
  // exercise both the run-class validator and doctor's separate one.
  const r = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '{}' });
  assert.doesNotMatch((r.stdout || '') + (r.stderr || ''), /unknown flag/, '--quiet must not be refused on a run-class verb');
  const d = cli(['doctor', '--signatures', '--quiet', '--json']);
  assert.doesNotMatch((d.stdout || '') + (d.stderr || ''), /unknown flag/, '--quiet must not be refused on doctor');
});

test('--quiet suppresses advisory stderr notes (keeps pipelines clean) but unknown flags still refuse', () => {
  // --quiet drops the "[exceptd] note:" advisories. The explicit-evidence
  // empty-stdin nudge is a deterministic advisory to assert against.
  const noisy = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
  assert.match(noisy.stderr || '', /read 0 bytes from stdin/, 'baseline: the nudge fires without --quiet');
  const quiet = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '' });
  assert.doesNotMatch(quiet.stderr || '', /read 0 bytes from stdin/, '--quiet suppresses the advisory note');
  // --quiet must NOT weaken reject-unknown-flags: a genuine typo still refuses.
  const bogus = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--bogusflag', '--json'], { input: '{}' });
  assert.notEqual(bogus.status, 0, 'an unknown flag is still refused even with --quiet present');
  assert.match((bogus.stdout || '') + (bogus.stderr || ''), /unknown flag/, 'the refusal names the unknown flag');
});

test('recipes --help shows real help, not the "no per-verb help available" fallback', () => {
  const r = cli(['recipes', '--help']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(out, /no per-verb help available/, 'recipes must have real per-verb help');
  assert.match(out, /recipes/i, 'recipes help mentions the verb');
});

test('report --help states the default output format (Markdown), not just --json', () => {
  const r = cli(['report', '--help']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /Markdown/i, 'report --help must state the Markdown default so operators do not pipe Markdown into a JSON tool');
});
