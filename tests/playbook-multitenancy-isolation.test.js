"use strict";
/**
 * tests/playbook-multitenancy-isolation.test.js
 *
 * Structure + cross-ref coverage for the multitenancy-isolation playbook
 * (cross-tenant isolation + availability/DoS) and its companion skill.
 * References every look-artifact id and detect-indicator id (diff-coverage),
 * and asserts the seven-phase shape, the TTP/CWE/framework mapping, and
 * per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/multitenancy-isolation.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('multitenancy-isolation has the seven-phase contract + api-abuse class', () => {
  assert.equal(PB._meta.id, 'multitenancy-isolation');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'api-abuse');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('domain maps to real ATT&CK + present CWEs + the Rapid Reset CVE + global-first frameworks', () => {
  for (const t of ['T1078', 'T1499', 'T1499.001', 'T1530']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-639', 'CWE-770', 'CWE-863', 'CWE-668', 'CWE-400']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  assert.ok(PB.domain.cve_refs.includes('CVE-2023-44487'), 'Rapid Reset CVE referenced');
  for (const f of ['uk-caf', 'au-ism']) assert.ok(PB.domain.frameworks_in_scope.includes(f), `framework ${f} (Hard Rule #5)`);
});

test('every look artifact has an air_gap_alternative + the multitenant surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['tenant-context-config', 'data-isolation-config', 'shared-infra-namespacing', 'availability-controls']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all nine isolation/availability indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'tenant-id-trusted-from-client',
    'query-not-scoped-by-tenant',
    'row-policy-bypassable-by-role-context',
    'cross-tenant-cache-or-queue-key-collision',
    'http2-rapid-reset-uncapped',
    'no-per-tenant-rate-or-byte-quota',
    'unbounded-resource-allocation-per-request',
    'distributed-lock-without-fencing',
    'no-circuit-breaker-on-dependency',
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
  const skill = MANIFEST.skills.find((s) => s.name === 'multitenancy-isolation');
  assert.ok(skill && skill.signature, 'multitenancy-isolation skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
