'use strict';

/**
 * tests/reconciliation-fixes.test.js
 *
 * Regression coverage for the codebase-reconciliation pass: removed-verb
 * stale surface, the worst-active-exploitation rank fix, and the help-text
 * accuracy corrections. Each test pins a behavior so the drift cannot
 * silently return.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const home = makeSuiteHome('exceptd-reconcile-');
const cli = makeCli(home);
const CLI = path.join(__dirname, '..', 'bin', 'exceptd.js');

const REMOVED_VERBS = ['plan', 'govern', 'direct', 'look', 'ingest'];

test('worstActiveExploitation ranks `theoretical` between none and unknown (worst-of holds)', () => {
  // P1: the rank table omitted `theoretical`, so `?? -1` lost to the -1 start —
  // an all-theoretical set wrongly reduced to 'unknown' and theoretical+none
  // dropped the theoretical entry. `theoretical` is first-class catalog vocab.
  const worst = require('../lib/playbook-runner.js')._worstActiveExploitation;
  assert.equal(typeof worst, 'function', 'runner must export _worstActiveExploitation');
  assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'none' }]),
    'theoretical', 'theoretical must outrank none');
  assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'confirmed' }]),
    'confirmed', 'confirmed still outranks theoretical');
  assert.equal(worst([{ active_exploitation: 'none' }, { active_exploitation: 'theoretical' }, { active_exploitation: 'suspected' }]),
    'suspected', 'worst-of across a mixed set');
  // Empty / all-unrecognized matched set defaults to 'none', not 'unknown' —
  // a draft must not assert exploitation it never observed.
  assert.equal(worst([]), 'none', 'empty set → none');
  assert.equal(worst([{ active_exploitation: 'bogus-value' }]), 'none', 'unrecognized-only → none');
});

test('`help <removed-verb>` refuses with exit 1 + the replacement (no stale live help)', () => {
  // The cmds map shipped full live help for plan/govern/direct/look/ingest,
  // reachable via `help <verb>` at exit 0 — contradicting the bare-verb
  // refusal. Now `help <removed>` mirrors the removal error.
  for (const v of REMOVED_VERBS) {
    const r = cli(['help', v]);
    assert.equal(r.status, 1, `help ${v} must exit 1; got ${r.status}`);
    const body = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(body.ok, false, `help ${v} must emit ok:false`);
    assert.match(body.error || '', /removed in v0\.13\.0/, `help ${v} must say it was removed`);
    assert.ok(typeof body.replacement === 'string' && body.replacement.length > 0,
      `help ${v} must name a replacement`);
  }
});

test('a real verb still gets its help block (the removed-verb guard is not over-broad)', () => {
  const r = cli(['help', 'recipes']);
  assert.equal(r.status, 0, 'help recipes is a live verb → exit 0');
  assert.match((r.stdout || '') + (r.stderr || ''), /recipes/i, 'recipes help renders');
});

test('ai-run help states the correct SESSION_ID_COLLISION exit code (7, not 3)', () => {
  const r = cli(['help', 'ai-run']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /7\s+SESSION_ID_COLLISION/, 'ai-run help must show code 7 for SESSION_ID_COLLISION');
  assert.doesNotMatch(out, /3\s+SESSION_ID_COLLISION/, 'must NOT mislabel it as code 3 (that is RAN_NO_EVIDENCE)');
});

test('brief --flat drops the scope grouping; default brief --all keeps it', () => {
  const grouped = tryJson(cli(['brief', '--all', '--json']).stdout) || {};
  assert.equal(typeof grouped.grouped_by_scope, 'object', 'default brief --all carries grouped_by_scope');
  const flat = tryJson(cli(['brief', '--all', '--flat', '--json']).stdout) || {};
  assert.ok(!('grouped_by_scope' in flat) && !('scope_summary' in flat),
    'brief --flat must omit grouped_by_scope and scope_summary');
});

test('brief --help documents --flat (it lived only in the dead plan help block before)', () => {
  const out = (cli(['brief', '--help']).stdout || '') + (cli(['brief', '--help']).stderr || '');
  assert.match(out, /--flat/, 'brief --help must document --flat');
});

test('attest --help documents the prune subverb (it works and is in top-help)', () => {
  const out = (cli(['attest', '--help']).stdout || '') + (cli(['attest', '--help']).stderr || '');
  assert.match(out, /attest prune/, 'attest --help must list prune');
  assert.match(out, /list \| show \| export \| verify \| diff \| prune/, 'prune must be in the subverbs summary');
});

test('doctor accepts --air-gap on both validation paths (allowlist drift fixed)', () => {
  // doctor --bogus routes through the central flagsFor() allowlist; the known
  // flags it lists must now include --air-gap (was missing, diverging from
  // KNOWN_DOCTOR_FLAGS which always included it).
  const r = cli(['doctor', '--bogus', '--json']);
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.ok(Array.isArray(body.known_flags), 'doctor --bogus emits known_flags');
  assert.ok(body.known_flags.includes('--air-gap'), 'doctor known_flags must include --air-gap');
  // And --air-gap itself is accepted (not refused as unknown).
  const ok = cli(['doctor', '--signatures', '--air-gap', '--json']);
  assert.doesNotMatch((ok.stdout || '') + (ok.stderr || ''), /unknown flag/, '--air-gap must be accepted on doctor');
});

test('printPlaybookVerbHelp ships no help block keyed by a removed verb (root-cause guard)', () => {
  // The cmds map previously held live help blocks for plan/govern/direct/look/
  // ingest, reachable via `help <verb>` at exit 0. Guard the class at the
  // source: no removed verb may have a `<verb>: \`...\`` entry in the map.
  // (The legitimate "Replaces plan + govern + direct + look" framing in
  // brief's help and the top-level `[REMOVED] <verb> → <repl>` migration
  // listing are descriptive, not live dispatch, and are covered by the
  // behavioral `help <removed>` refusal test above.)
  const src = fs.readFileSync(CLI, 'utf8');
  for (const v of REMOVED_VERBS) {
    assert.doesNotMatch(src, new RegExp(`\\n    ${v}: \``),
      `printPlaybookVerbHelp must not ship a help block for removed verb "${v}"`);
  }
});
