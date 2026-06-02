"use strict";
/**
 * tests/playbook-audit-log-integrity.test.js
 *
 * Structure + cross-ref coverage for the audit-log-integrity playbook
 * (tamper-evidence + WORM + deception) and its companion skill. References
 * every look-artifact id and detect-indicator id (diff-coverage), and asserts
 * the seven-phase shape, the TTP/CWE mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/audit-log-integrity.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('audit-log-integrity has the seven-phase contract + cloud-misconfig class', () => {
  assert.equal(PB._meta.id, 'audit-log-integrity');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'cloud-misconfig');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('domain maps to real ATT&CK (T1070/T1565.001/T1562.008) + present CWEs', () => {
  for (const t of ['T1070', 'T1565.001', 'T1562.008']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-345', 'CWE-347', 'CWE-284', 'CWE-778']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
});

test('every look artifact has an air_gap_alternative + the audit surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['audit-chain-and-signing-config', 'worm-and-retention-config', 'deception-config', 'break-glass-and-duty-separation']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all eight integrity indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'audit-hash-chain-not-verified',
    'audit-log-not-signed-or-key-colocated',
    'worm-immutability-not-enforced',
    'legal-hold-not-blocking-purge',
    'honeytoken-not-deployed',
    'honeytoken-trip-not-triaged',
    'break-glass-no-dual-control-or-audit',
    'audit-log-deletable-by-writing-identity',
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
  const skill = MANIFEST.skills.find((s) => s.name === 'audit-log-integrity');
  assert.ok(skill && skill.signature, 'audit-log-integrity skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
