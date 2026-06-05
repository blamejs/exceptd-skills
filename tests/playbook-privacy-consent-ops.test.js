"use strict";
/**
 * tests/playbook-privacy-consent-ops.test.js
 *
 * Structure + cross-ref coverage for the privacy-consent-ops playbook
 * (privacy / consent / sanctions operational integrity) and its companion
 * skill. References every look-artifact id and detect-indicator id
 * (diff-coverage), and asserts the seven-phase shape, the TTP/CWE/framework
 * mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/privacy-consent-ops.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('privacy-consent-ops has the seven-phase contract + compliance-theater class', () => {
  assert.equal(PB._meta.id, 'privacy-consent-ops');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'compliance-theater');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('domain maps to real ATT&CK + present CWEs + global-first frameworks (UK+AU); feeds_into resolves', () => {
  for (const t of ['T1036', 'T1565.001', 'T1070']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-807', 'CWE-345', 'CWE-778', 'CWE-672']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const f of ['uk-caf', 'au-ism']) assert.ok(PB.domain.frameworks_in_scope.includes(f), `framework ${f} (Hard Rule #5)`);
  assert.deepEqual((PB._meta.feeds_into || []).map((x) => x.playbook_id), ['framework'], 'feeds_into is a real playbook only');
});

test('every look artifact has an air_gap_alternative + the privacy surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['sanctions-screening-config', 'consent-config', 'dsr-erasure-config', 'ropa-and-dark-patterns']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all seven privacy/sanctions indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'sanctions-screening-homoglyph-evasion',
    'sanctions-screening-alias-transliteration-gap',
    'consent-record-no-integrity-binding',
    'consent-not-revalidated-at-processing',
    'dsr-erasure-no-completion-proof',
    'dsr-erasure-not-propagated-downstream',
    'ropa-drifts-from-actual-processing',
  ]) {
    assert.ok(ids.includes(need), `indicator ${need} present`);
  }
  for (const ind of PB.phases.detect.indicators) {
    assert.ok(Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1, `${ind.id} FP checks`);
    assert.ok(PB.domain.attack_refs.includes(ind.attack_ref), `${ind.id} attack_ref in domain`);
  }
});

test('remediation for_signals reference real indicators; companion skill registered + signed', () => {
  const ids = new Set(PB.phases.detect.indicators.map((i) => i.id));
  for (const rp of PB.phases.validate.remediation_paths) for (const s of (rp.for_signals || [])) assert.ok(ids.has(s), `remediation ${rp.id} for_signals ${s}`);
  const skill = MANIFEST.skills.find((s) => s.name === 'privacy-consent-ops');
  assert.ok(skill && skill.signature, 'privacy-consent-ops skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
