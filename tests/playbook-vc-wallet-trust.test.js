"use strict";
/**
 * tests/playbook-vc-wallet-trust.test.js
 *
 * Structure + cross-ref coverage for the vc-wallet-trust playbook (verifiable-
 * credential / digital-wallet verifier trust) and its companion skill. Asserts
 * the load-bearing trust-check indicators, the TTP/CWE mapping, the seven-phase
 * shape, and that every detect indicator carries false-positive checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/vc-wallet-trust.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('vc-wallet-trust playbook has the seven-phase contract + identity-abuse class', () => {
  assert.equal(PB._meta.id, 'vc-wallet-trust');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'identity-abuse');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) {
    assert.ok(PB.phases[ph], `phase ${ph} present`);
  }
});

test('look artifacts cover the verifier trust surface and each carries an air_gap_alternative', () => {
  const arts = PB.phases.look.artifacts;
  const ids = arts.map((a) => a.id);
  for (const need of [
    'vc-verifier-config',
    'revocation-and-statuslist-config',
    'did-resolution-config',
    'oid4vp-request-config',
    'mdoc-trust-config',
    'federation-anchor-config',
    'algorithm-policy',
  ]) {
    assert.ok(ids.includes(need), `look artifact ${need} present`);
  }
  for (const a of arts) {
    assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0,
      `artifact ${a.id} has an air_gap_alternative`);
  }
});

test('domain maps to real ATT&CK techniques + present CWEs (no orphans)', () => {
  assert.deepEqual(PB.domain.attack_refs, ['T1556', 'T1606', 'T1550']);
  for (const w of ['CWE-347', 'CWE-290', 'CWE-863', 'CWE-200', 'CWE-672']) {
    assert.ok(PB.domain.cwe_refs.includes(w), `cwe_refs includes ${w}`);
  }
});

test('the core trust-check indicators are present and each carries false-positive checks', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'issuer-key-not-pinned-to-trust-anchor',
    'credential-revocation-status-not-checked',
    'did-web-resolution-unpinned',
    'presentation-no-nonce-audience-binding',
    'mdoc-device-signature-not-verified',
    'credential-algorithm-allowlist-absent',
    'key-attestation-not-verified',
    'openid-federation-anchor-not-pinned',
    'over-disclosure-not-filtered',
    'status-list-issuer-not-trust-scoped',
  ]) {
    assert.ok(ids.includes(need), `indicator ${need} present`);
  }
  // Every indicator must carry >=1 false-positive check (the marker-vs-real discipline).
  for (const ind of PB.phases.detect.indicators) {
    assert.ok(Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1,
      `indicator ${ind.id} has false_positive_checks_required`);
    assert.ok(['T1556', 'T1606', 'T1550'].includes(ind.attack_ref), `indicator ${ind.id} maps to a domain TTP`);
  }
  // every false_positive_profile entry references a real indicator
  for (const fp of PB.phases.detect.false_positive_profile) {
    assert.ok(ids.includes(fp.indicator_id), `fp_profile ${fp.indicator_id} references a real indicator`);
  }
});

test('remediation paths reference real indicator ids via for_signals', () => {
  const ids = new Set(PB.phases.detect.indicators.map((i) => i.id));
  for (const rp of PB.phases.validate.remediation_paths) {
    for (const sig of (rp.for_signals || [])) {
      assert.ok(ids.has(sig), `remediation ${rp.id} for_signals ${sig} is a real indicator`);
    }
  }
});

test('companion skill vc-wallet-trust is registered (standalone) and signed', () => {
  const skill = MANIFEST.skills.find((s) => s.name === 'vc-wallet-trust');
  assert.ok(skill, 'vc-wallet-trust skill in manifest');
  assert.equal(skill.path, 'skills/vc-wallet-trust/skill.md');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
  assert.deepEqual(skill.attack_refs, ['T1556', 'T1606', 'T1550']);
  assert.ok(skill.signature, 'skill is signed');
});
