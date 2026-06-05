"use strict";
/**
 * tests/playbook-network-trust.test.js
 *
 * Structure + cross-ref coverage for the network-trust playbook (AiTM
 * resistance: DNS / TLS-pinning / time) and its companion skill. References
 * every look-artifact id and detect-indicator id (diff-coverage), and asserts
 * the seven-phase shape, the TTP/CWE mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/network-trust.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('network-trust has the seven-phase contract + cloud-misconfig class', () => {
  assert.equal(PB._meta.id, 'network-trust');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'cloud-misconfig');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('domain maps to real ATT&CK + present CWEs + the DNSSEC resolver-DoS CVEs', () => {
  for (const t of ['T1557', 'T1071.004', 'T1556']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-345', 'CWE-918', 'CWE-290', 'CWE-347']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const c of ['CVE-2023-50387', 'CVE-2023-50868']) assert.ok(PB.domain.cve_refs.includes(c), `cve ${c}`);
});

test('every look artifact has an air_gap_alternative + the trust surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['dns-trust-config', 'dane-tsig-config', 'time-trust-config', 'mtls-trust-config', 'message-signature-and-psl-config']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all eight AiTM-resistance indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'dnssec-validation-not-enforced',
    'dane-tlsa-not-checked',
    'unauthenticated-ntp-no-nts',
    'tsig-absent-on-zone-operations',
    'mtls-ca-not-pinned',
    'http-message-signature-not-verified',
    'dns-rebinding-unguarded',
    'public-suffix-list-stale',
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
  const skill = MANIFEST.skills.find((s) => s.name === 'network-trust');
  assert.ok(skill && skill.signature, 'network-trust skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
