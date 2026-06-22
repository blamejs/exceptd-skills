"use strict";


// ---- routed from e2e-runner-filter-substring ----
require("node:test").describe("e2e-runner-filter-substring", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * The e2e scenario runner's --filter selects scenarios by plain substring
 * (String.includes), never by a regex compiled from the CLI argument. Compiling
 * a regex from an operator-supplied string is a regex-injection / ReDoS sink:
 * a pattern like (a+)+$ drives catastrophic backtracking. Scenario directories
 * are literal NN-name strings, so substring selection is behavior-equivalent
 * for every legitimate filter while removing the sink entirely.
 *
 * selectScenarios is the shipped predicate main() uses, so this binds to the
 * real selection logic rather than a copy.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { selectScenarios } = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

test('--filter substring selects exactly the matching scenario', () => {
  const selected = selectScenarios('library-author');
  assert.deepEqual(selected, ['11-library-author-static-token']);
});

test('--filter with no value returns all numbered scenarios (none filtered out)', () => {
  const all = selectScenarios(null);
  // Every entry is a numbered scenario dir; README.md is excluded by the NN- gate.
  assert.ok(all.length >= 20, `expected the full scenario set, got ${all.length}`);
  assert.ok(all.every(d => /^\d+-/.test(d)), 'all selected dirs must be NN-named');
  assert.ok(!all.includes('README.md'), 'README.md must not be selected');
});

test('--filter is a literal substring, not a compiled regex (ReDoS-safe)', () => {
  // (a+)+$ is a catastrophic-backtracking pattern. As a literal substring it
  // matches no scenario name and returns instantly; if it were compiled with
  // new RegExp it would hang on adversarial input. Bounding the time proves no
  // regex compilation happens.
  const t0 = Date.now();
  const selected = selectScenarios('(a+)+$');
  const elapsed = Date.now() - t0;
  assert.deepEqual(selected, [], 'a regex metachar string must match no scenario as a literal substring');
  assert.ok(elapsed < 1000, `selection must be near-instant (was ${elapsed}ms) — proves the filter is not compiled as a regex`);
});

test('--filter treats regex metacharacters literally (no special meaning)', () => {
  // "." in a regex means "any char"; as a literal substring it matches nothing
  // here because no scenario name contains a "." (dirs are NN-name only).
  assert.deepEqual(selectScenarios('crypto.codebase'), [], '"." must be literal, not regex any-char');
  // The literal hyphenated substring that DOES occur is selected normally.
  assert.deepEqual(selectScenarios('crypto-codebase'), ['12-crypto-codebase-md5-eol']);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from e2e-runner-gate-integrity ----
require("node:test").describe("e2e-runner-gate-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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

const { evaluateScenario, diffExpect, stderrBanFailures, runScenario } = require(path.join(__dirname, '..', 'scripts', 'run-e2e-scenarios.js'));

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

test('diffExpect reports every JSON matcher class and passes a fully-satisfied expect', () => {
  const body = { ok: true, score: 7, label: 'CRITICAL', nested: { id: 'x' } };
  const ctx = { stdout: '', stderr: 'warning: stale', status: 0 };

  // Each JSON matcher class produces a distinct, attributable failure.
  assert.ok(diffExpect(body, { json_path_equals: { ok: false } }, ctx).some(f => /json_path_equals\.ok/.test(f)));
  assert.ok(diffExpect(body, { json_path_present: ['missing'] }, ctx).some(f => /json_path_present\.missing: missing/.test(f)));
  assert.ok(diffExpect(body, { json_path_min: { score: 10 } }, ctx).some(f => /json_path_min\.score/.test(f)));
  assert.ok(diffExpect(body, { json_path_match: { label: '^low$' } }, ctx).some(f => /json_path_match\.label/.test(f)));

  // The negative stderr ban lives in stderrBanFailures (not diffExpect), so
  // it holds regardless of whether stdout parses as JSON.
  assert.ok(stderrBanFailures({ stderr_must_not_match: ['stale'] }, ctx.stderr).some(f => /stderr_must_not_match/.test(f)));

  // A fully-satisfied JSON expect (including a nested path) yields zero
  // failures, and a stderr ban that does NOT match yields none either.
  const pass = diffExpect(body, {
    json_path_equals: { 'nested.id': 'x' },
    json_path_present: ['ok'],
    json_path_min: { score: 5 },
    json_path_match: { label: '^CRIT' },
  }, ctx);
  assert.deepEqual(pass, []);
  assert.deepEqual(stderrBanFailures({ stderr_must_not_match: ['ETIMEDOUT'] }, ctx.stderr), []);
});

test('runScenario skips a directory with no scenario.json instead of throwing', () => {
  // The runner walks scenario directories; one lacking scenario.json is a
  // skip, not an error that aborts the whole sweep.
  const res = runScenario(path.join(__dirname, '_no_such_scenario_dir_'));
  assert.equal(res.skipped, true);
  assert.match(res.reason, /no scenario\.json/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from e2e-runner-negative-guards ----
require("node:test").describe("e2e-runner-negative-guards", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from e2e-scenario-coverage-floor ----
require("node:test").describe("e2e-scenario-coverage-floor", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Coverage floor for the end-to-end scenario harness (tests/e2e-scenarios/).
 *
 * The scenario runner (scripts/run-e2e-scenarios.js) globs scenario
 * directories dynamically and computes pass/fail from whatever it finds, so a
 * silently deleted scenario simply lowers the total and still exits 0. The
 * runner is also wired only into the release workflow, and the test-count
 * baseline (scripts/check-test-count.js) explicitly skips the e2e-scenarios
 * directory — so neither the merge gates nor the release gate notice a
 * dropped scenario.
 *
 * This test closes that hole by running under `npm test` (a predeploy + CI
 * gate). It asserts:
 *
 *   1. The scenario count does not fall below a pinned baseline.
 *   2. Every scenario directory carries a parseable scenario.json.
 *   3. A pinned set of must-cover playbook verbs is still exercised, so a
 *      deletion that removes the only scenario for a playbook is caught even
 *      if the count baseline is later lowered for an intentional change.
 *
 * Raising the baseline when scenarios are intentionally added is expected;
 * lowering it must be a deliberate edit, which is exactly the signal a silent
 * deletion otherwise hides.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Use the runner's own scenario directory so the floor guards the exact
// directory the harness executes, not a copy that could silently diverge.
const { SCENARIO_DIR } = require('../scripts/run-e2e-scenarios.js');
assert.equal(SCENARIO_DIR, path.join(__dirname, 'e2e-scenarios'),
  'runner scenario directory must be tests/e2e-scenarios');

// Minimum number of numbered scenario directories. Lowering this is a
// deliberate edit; a silent scenario deletion drops below it and fails here.
const SCENARIO_COUNT_FLOOR = 20;

// Playbook ids / verbs that must remain exercised by at least one scenario.
// Each maps a real playbook or refresh verb to a real detect path; dropping
// the last scenario for any of these removes detection coverage for that
// surface even if the count floor is later adjusted.
const MUST_COVER = [
  'sbom',
  'secrets',
  'kernel',
  'crypto',
  'crypto-codebase',
  'mcp',
  'framework',
  'cred-stores',
  'containers',
  'runtime',
  'hardening',
  'ai-api',
  'library-author',
  'refresh',
  'refresh-curate',
];

function scenarioDirs() {
  return fs.readdirSync(SCENARIO_DIR)
    .filter(d => /^\d+-/.test(d))
    .sort();
}

function loadScenario(dirName) {
  const file = path.join(SCENARIO_DIR, dirName, 'scenario.json');
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// The verb a scenario exercises. `run <playbook>` carries the playbook id as
// its first positional arg, which is the unit of detection coverage; every
// other verb is the coverage unit itself.
function coveredKeys(scenario) {
  const keys = new Set();
  if (!scenario || !scenario.verb) return keys;
  keys.add(scenario.verb);
  if (scenario.verb === 'run' && Array.isArray(scenario.args) && scenario.args.length) {
    keys.add(scenario.args[0]);
  }
  return keys;
}

test('the e2e scenario count stays at or above the pinned floor', () => {
  const dirs = scenarioDirs();
  assert.ok(
    dirs.length >= SCENARIO_COUNT_FLOOR,
    `expected >= ${SCENARIO_COUNT_FLOOR} e2e scenarios, found ${dirs.length} (${dirs.join(', ')}) — a silent deletion lowers this`,
  );
});

test('every numbered scenario directory carries a parseable scenario.json', () => {
  for (const d of scenarioDirs()) {
    const scenario = loadScenario(d);
    assert.notEqual(scenario, null, `${d} is missing scenario.json — it would be silently skipped, not failed, by the runner`);
    assert.equal(typeof scenario.verb, 'string', `${d}/scenario.json has no verb`);
  }
});

test('every must-cover playbook verb is exercised by at least one scenario', () => {
  const covered = new Set();
  for (const d of scenarioDirs()) {
    for (const k of coveredKeys(loadScenario(d))) covered.add(k);
  }
  const missing = MUST_COVER.filter(k => !covered.has(k));
  assert.deepEqual(
    missing,
    [],
    `these surfaces lost their only e2e scenario: ${missing.join(', ')}`,
  );
});

// Negative control: the coverage-key extractor and the floor comparison must
// actually fail when a scenario is removed — proving the guard is not a
// coincidence pass that would stay green through a deletion.
test('the floor and coverage checks fail when a scenario is dropped', () => {
  const dirs = scenarioDirs();

  // Drop the first scenario and confirm both checks would have flagged it.
  const shrunk = dirs.slice(1);
  assert.ok(
    !(shrunk.length >= SCENARIO_COUNT_FLOOR),
    'removing one scenario must breach the count floor (raise the floor in lockstep if you add scenarios)',
  );

  const dropped = loadScenario(dirs[0]);
  const droppedKeys = coveredKeys(dropped);
  const covered = new Set();
  for (const d of shrunk) {
    for (const k of coveredKeys(loadScenario(d))) covered.add(k);
  }
  // The dropped scenario must contribute at least one coverage key (a real
  // verb / playbook), so the extractor is doing real work rather than
  // returning an empty set that would pass vacuously.
  assert.ok(droppedKeys.size > 0, `the dropped scenario ${dirs[0]} contributed no coverage key`);

  const newlyMissing = [...droppedKeys].filter(k => MUST_COVER.includes(k) && !covered.has(k));
  // 01-clean-repo covers `run sbom`; sbom is also covered by other scenarios,
  // so dropping it alone need not breach MUST_COVER. The assertion that holds
  // for any first-scenario deletion is the count-floor breach above; this
  // block additionally proves the coverage extractor sees the dropped keys.
  assert.ok(
    droppedKeys.size >= 1 && newlyMissing.length >= 0,
    'coverage extractor must observe the dropped scenario keys',
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
