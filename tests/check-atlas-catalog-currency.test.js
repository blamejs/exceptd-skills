"use strict";

// ---- routed from atlas-catalog-currency ----
require("node:test").describe("atlas-catalog-currency", () => {
/**
 * Regression for the ATLAS catalog currency gate
 * (scripts/check-atlas-catalog-currency.js).
 *
 * The gate compares data/atlas-ttps.json against the ATLAS release it pins.
 * Two pieces carry the judgment and are pinned here: reading id and name pairs
 * out of the release's format-6 file, and deciding whether a catalog name is a
 * different technique or the same one rendered with its parent.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { parseNames, isRenderingOf, parentNameOf, parseTactics, tacticProblems } =
  require(path.resolve(__dirname, '..', 'scripts', 'check-atlas-catalog-currency.js'));

const SAMPLE = [
  "format-version: 6.0.0",
  "collection:",
  "  version: '2026.08'",
  "tactics:",
  "  AML.TA0001:",
  "    name: AI Attack Adaptation",
  "    description: 'something'",
  "techniques:",
  "  AML.T0072:",
  "    name: Cyber Communication Channel",
  "    description: 'other'",
  "  AML.T0115.000:",
  "    name: Datasets",
  "  AML.T0018:",
  '    name: "Manipulate AI Model"',
  "  AML.M0037:",
  "    name: AI Agent Authority Expansion Controls",
  "  AML.CS0069:",
  "    name: GTG-1002 Claude Code Espionage Campaign",
  "",
].join("\n");

test('parseNames reads ids and names out of the format-6 layout', () => {
  const m = parseNames(SAMPLE);
  assert.equal(m.get('AML.TA0001'), 'AI Attack Adaptation');
  assert.equal(m.get('AML.T0072'), 'Cyber Communication Channel');
  assert.equal(m.get('AML.T0115.000'), 'Datasets');
  assert.equal(m.get('AML.M0037'), 'AI Agent Authority Expansion Controls');
  assert.equal(m.get('AML.CS0069'), 'GTG-1002 Claude Code Espionage Campaign');
});

test('parseNames unquotes a double-quoted name', () => {
  assert.equal(parseNames(SAMPLE).get('AML.T0018'), 'Manipulate AI Model');
});

test('parseNames covers every object in the sample and invents none', () => {
  const m = parseNames(SAMPLE);
  assert.equal(m.size, 6, 'one entry per id in the sample');
  assert.equal(m.has('AML.T9999'), false);
});

test('parseNames ignores an id that is not a name-bearing object', () => {
  // Cross references name an id as a value; only a keyed object declares a name.
  const withRef = SAMPLE + "\nrelationships:\n  - target: AML.T0072\n    kind: related\n";
  const m = parseNames(withRef);
  assert.equal(m.size, 6);
});

const TACTIC_SAMPLE = [
  "tactics:",
  "  AML.TA0000:",
  "    name: AI Model Access",
  "  AML.TA0001:",
  "    name: AI Attack Adaptation",
  "  AML.TA0006:",
  "    name: Persistence",
  "techniques:",
  "  AML.T0018:",
  "    name: Manipulate AI Model",
  "  AML.T0018.000:",
  "    name: Poison AI Model",
  "  AML.T0044:",
  "    name: Full AI Model Access",
  "relationships:",
  "  AML.T0018:",
  "    achieves:",
  "    - source: AML.T0018",
  "      target: AML.TA0001",
  "      relationship-type: achieves",
  "    - source: AML.T0018",
  "      target: AML.TA0006",
  "      relationship-type: achieves",
  "  AML.T0044:",
  "    achieves:",
  "    - source: AML.T0044",
  "      target: AML.TA0000",
  "      relationship-type: achieves",
  "    employs:",
  "    - source: AML.CS0001",
  "      target: AML.T0044",
  "      relationship-type: employs",
  "",
].join("\n");

test('parseTactics reads each technique\'s tactics from its achieves relationships', () => {
  const t = parseTactics(TACTIC_SAMPLE, parseNames(TACTIC_SAMPLE));
  assert.deepEqual([...t.get('AML.T0018')].sort(), ['AI Attack Adaptation', 'Persistence']);
  assert.deepEqual([...t.get('AML.T0044')], ['AI Model Access']);
  assert.equal(t.has('AML.CS0001'), false, 'an employs relationship does not assign a tactic');
});

test('tacticProblems accepts a tactic upstream assigns, alone or as part of a list', () => {
  const t = parseTactics(TACTIC_SAMPLE, parseNames(TACTIC_SAMPLE));
  assert.deepEqual(tacticProblems('AML.T0044', 'AI Model Access', t), []);
  assert.deepEqual(tacticProblems('AML.T0018', ['Persistence', 'AI Attack Adaptation'], t), []);
  assert.deepEqual(tacticProblems('AML.T0018', 'Persistence', t), [], 'listing fewer tactics than upstream is allowed');
});

test('tacticProblems reports a tactic upstream does not assign, including a stale slug', () => {
  const t = parseTactics(TACTIC_SAMPLE, parseNames(TACTIC_SAMPLE));
  assert.deepEqual(tacticProblems('AML.T0044', 'Collection', t),
    [{ id: 'AML.T0044', ours: 'Collection', theirs: ['AI Model Access'] }]);
  const p = tacticProblems('AML.T0018', ['Persistence', 'ai-attack-staging'], t);
  assert.equal(p.length, 1);
  assert.equal(p[0].ours, 'ai-attack-staging');
});

test('tacticProblems checks a sub-technique with no tactics of its own against its parent', () => {
  const t = parseTactics(TACTIC_SAMPLE, parseNames(TACTIC_SAMPLE));
  assert.deepEqual(tacticProblems('AML.T0018.000', 'Persistence', t), []);
  assert.equal(tacticProblems('AML.T0018.000', 'Impact', t).length, 1);
});

test('tacticProblems does not check an empty tactic or an id upstream assigns none to', () => {
  const t = parseTactics(TACTIC_SAMPLE, parseNames(TACTIC_SAMPLE));
  assert.deepEqual(tacticProblems('AML.T0044', '', t), []);
  assert.deepEqual(tacticProblems('AML.T0044', [], t), []);
  assert.deepEqual(tacticProblems('AML.T0999', 'Impact', t), []);
});

test('isRenderingOf accepts a sub-technique written with its parent', () => {
  assert.equal(isRenderingOf('Publish Poisoned AI Artifacts: Datasets', 'Datasets', 'Publish Poisoned AI Artifacts'), true);
  assert.equal(isRenderingOf('Use Alternate Authentication Material: Web Session Cookie', 'Web Session Cookie', 'Use Alternate Authentication Material'), true);
});

test('isRenderingOf rejects a "Parent: Child" name whose prefix is not the parent', () => {
  // The suffix matching upstream is not enough: an arbitrary or renamed parent
  // would otherwise pass the gate.
  assert.equal(isRenderingOf('Unrelated Technique: Datasets', 'Datasets', 'Publish Poisoned AI Artifacts'), false);
});

test('isRenderingOf rejects the "Parent: Child" form on a technique with no parent', () => {
  assert.equal(isRenderingOf('Publish Poisoned AI Artifacts: Datasets', 'Datasets', null), false);
  assert.equal(isRenderingOf('Publish Poisoned AI Artifacts: Datasets', 'Datasets'), false);
});

test('parentNameOf resolves a sub-technique to its parent and a technique to nothing', () => {
  const up = new Map([['AML.T0115', 'Publish Poisoned AI Artifacts'], ['AML.T0115.000', 'Datasets']]);
  assert.equal(parentNameOf('AML.T0115.000', up), 'Publish Poisoned AI Artifacts');
  assert.equal(parentNameOf('AML.T0115', up), null);
  assert.equal(parentNameOf('AML.T0999.001', up), null, 'an unknown parent resolves to nothing, not a guess');
});

test('isRenderingOf accepts a parenthetical qualifier', () => {
  assert.equal(isRenderingOf('AI Agent (as Attacker Asset)', 'AI Agent'), true);
  assert.equal(isRenderingOf('Exploitation for Credential Access (AI Pipeline)', 'Exploitation for Credential Access'), true);
});

test('isRenderingOf rejects a name that is a different technique', () => {
  assert.equal(isRenderingOf('LLM Plugin Compromise', 'AI Agent Tool Invocation'), false);
  assert.equal(isRenderingOf('Victim Research', 'Search Open AI Vulnerability Analysis'), false);
  assert.equal(isRenderingOf('Discover ML Model Ontology', 'Develop Capabilities'), false);
});

test('isRenderingOf rejects a qualifier that renames rather than qualifies', () => {
  // The part before the colon may add context; the part after must be the name.
  assert.equal(isRenderingOf('Obtain Capabilities: Develop Capabilities', 'Obtain Capabilities'), false);
});

test('isRenderingOf treats a missing upstream name as no match', () => {
  assert.equal(isRenderingOf('Anything', undefined), false);
  assert.equal(isRenderingOf('Anything', ''), false);
});

test('the divergence baseline is committed and names the pin it was taken against', () => {
  const fs = require('node:fs');
  const p = path.resolve(__dirname, '.atlas-divergence-baseline.json');
  assert.ok(fs.existsSync(p), 'tests/.atlas-divergence-baseline.json must ship (see the .gitignore negation)');
  const b = JSON.parse(fs.readFileSync(p, 'utf8'));
  const catalog = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'data', 'atlas-ttps.json'), 'utf8'));
  assert.equal(b.pinned_release, catalog._meta.atlas_version,
    'the baseline records divergences against one release; it must name the release the catalog pins');
  assert.ok(b.names && typeof b.names === 'object', 'baseline.names must be an object');
  assert.ok(Array.isArray(b.missing_ids), 'baseline.missing_ids must be a list');
  assert.ok(Array.isArray(b.missing_subtechniques), 'baseline.missing_subtechniques must be a list');
});

test('the baseline records sub-technique ids one at a time, never their parent', () => {
  // Recording a parent would exempt every id under it, so a sub-technique added
  // after the baseline was taken would inherit the exemption and pass unseen.
  const fs = require('node:fs');
  const b = JSON.parse(fs.readFileSync(path.resolve(__dirname, '.atlas-divergence-baseline.json'), 'utf8'));
  for (const id of b.missing_subtechniques) {
    assert.match(id, /^AML\.T[0-9]+\.[0-9]+$/,
      `${id} must be a full sub-technique id; a bare parent id would exempt its siblings`);
  }
});

test('a recorded name does not also excuse that id existing', () => {
  const fs = require('node:fs');
  const b = JSON.parse(fs.readFileSync(path.resolve(__dirname, '.atlas-divergence-baseline.json'), 'utf8'));
  // The two lists are separate on purpose: a wrong name and a missing id are
  // different findings, and recording one must not silence the other.
  for (const id of Object.keys(b.names)) {
    assert.equal(b.missing_ids.includes(id), false,
      `${id} is recorded as misnamed; if it is also absent upstream that is a separate entry`);
  }
});
});
