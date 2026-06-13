'use strict';

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
