"use strict";
/**
 * tests/playbook-self-update-integrity.test.js
 *
 * Structure + cross-ref coverage for the self-update-integrity playbook
 * (consumer-side update-channel integrity) and its companion skill. References
 * every look-artifact id and detect-indicator id (diff-coverage), and asserts
 * the seven-phase shape, the TTP/CWE mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/self-update-integrity.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('self-update-integrity has the seven-phase contract + supply-chain class', () => {
  assert.equal(PB._meta.id, 'self-update-integrity');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'supply-chain');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('domain maps to real ATT&CK + present CWEs + global-first frameworks (UK+AU)', () => {
  for (const t of ['T1195.002', 'T1574']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-494', 'CWE-829', 'CWE-353', 'CWE-347']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const f of ['uk-caf', 'au-ism']) assert.ok(PB.domain.frameworks_in_scope.includes(f), `framework ${f} (Hard Rule #5)`);
});

test('every look artifact has an air_gap_alternative + the update surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['self-update-config', 'update-key-and-channel-config', 'importmap-sri-config', 'provenance-and-transparency-config']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all eight consumer-side indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'self-update-no-signature-verification',
    'self-update-no-anti-rollback',
    'self-update-key-not-pinned',
    'self-update-channel-not-authenticated',
    'importmap-sri-not-enforced',
    'content-credentials-not-verified',
    'transparency-log-not-checked',
    'update-applied-without-verifier-gate',
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
  const skill = MANIFEST.skills.find((s) => s.name === 'self-update-integrity');
  assert.ok(skill && skill.signature, 'self-update-integrity skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
