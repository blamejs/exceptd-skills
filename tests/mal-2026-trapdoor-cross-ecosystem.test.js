'use strict';

/**
 * tests/mal-2026-trapdoor-cross-ecosystem.test.js
 *
 * Per-subject coverage for MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM (cross-ecosystem
 * stealer with AI-assistant weaponization). Combines the catalog threat-intel
 * pins (RWEP = sum(factors), AI-assisted weaponization, ATLAS prompt-injection
 * ref, populated iocs) with the Package-Confidence Score (PCS) invariants.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CAT = require(path.join(ROOT, 'data', 'cve-catalog.json'));
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));

const ID = 'MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM';

function rwepSum(e) { return Object.values(e.rwep_factors).reduce((a, b) => a + b, 0); }
function iocsPopulated(e) {
  return e.iocs && typeof e.iocs === 'object' && !Array.isArray(e.iocs) && Object.keys(e.iocs).length > 0;
}

test('MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM — RWEP 55, AI-assistant weaponization, populated iocs', () => {
  const e = CAT[ID];
  assert.ok(e, 'TrapDoor entry must be in the catalog');
  assert.equal(e.cisa_kev, false);
  assert.equal(e.ai_assisted_weaponization, true, 'the .cursorrules/CLAUDE.md zero-width poisoning is AI-assisted weaponization');
  assert.equal(e.rwep_score, 55);
  assert.equal(rwepSum(e), 55);
  assert.ok(iocsPopulated(e));
  assert.ok(e.atlas_refs.includes('AML.T0051'), 'LLM prompt injection (AI-assistant poisoning vector)');
});

test('MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM has a paired zeroday-lesson', () => {
  const lessons = require(path.join(ROOT, 'data', 'zeroday-lessons.json'));
  assert.ok(lessons[ID], `${ID} must have a paired zeroday-lessons entry`);
  assert.ok(Array.isArray(lessons[ID].new_control_requirements) && lessons[ID].new_control_requirements.length >= 1,
    `${ID} lesson must generate at least one new control requirement`);
});

test('MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM carries a valid trust-polarity PCS that matches its inputs', () => {
  const e = CAT[ID];
  const pc = e.package_confidence;
  assert.ok(pc, `${ID} must carry package_confidence`);
  assert.equal(pc.polarity, 'trust', 'polarity const guards against summing with RWEP');
  assert.ok(Number.isInteger(pc.score) && pc.score >= 0 && pc.score <= 100, 'score is an integer in [0,100]');
  assert.equal(pc.score, scoring.packageConfidence(pc.inputs), `${ID} score must equal packageConfidence(inputs)`);
});

test('PCS does not perturb RWEP — MAL-2026-TRAPDOOR-CROSS-ECOSYSTEM still has rwep_score == sum(rwep_factors)', () => {
  const e = CAT[ID];
  assert.equal(e.rwep_score, rwepSum(e), `${ID}: PCS must not change the RWEP sum invariant`);
});
