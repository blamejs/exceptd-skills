'use strict';

/**
 * tests/sbom-capability-signals.test.js
 *
 * Pins the package-capability signals added to the supply-chain (sbom)
 * playbook: the package-capability-surface evidence artifact, the
 * across-version-bump capability-creep detector, and the absolute
 * capability-surface screen. Each assertion checks CONTENT (the capability
 * vocabulary, the false-positive checks, the TTP ref), not bare presence —
 * a presence-only test would pass even if the detector's guardrails were
 * deleted.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const ARTIFACTS = PB.phases.look.artifacts;
const INDICATORS = PB.phases.detect.indicators;
const FP_PROFILE = PB.phases.detect.false_positive_profile;

const CAPABILITY_TAGS = ['network', 'filesystem', 'shell', 'env', 'eval', 'install-script', 'telemetry', 'native-binary'];

function byId(arr, id) { return arr.find((x) => x.id === id); }

test('package-capability-surface look artifact exists and carries the 8-tag capability vocabulary', () => {
  const a = byId(ARTIFACTS, 'package-capability-surface');
  assert.ok(a, 'package-capability-surface artifact must be present');
  assert.equal(a.type, 'config_file', 'capability-surface is a manifest read (config_file)');
  assert.equal(a.required, false, 'optional sweep artifact — absence must not halt the run');
  for (const tag of CAPABILITY_TAGS) {
    assert.ok((a.source + ' ' + a.description).includes(tag),
      `capability vocabulary must name "${tag}" so the AI classifies against the full taxonomy`);
  }
  // air-gap conditional: a config_file artifact with no network-call substring needs no air_gap_alternative.
  assert.ok(!/https?:\/\/|gh api|curl /.test(a.source), 'capability-surface source must not issue network calls');
});

test('capability-creep across-version-bump indicator fires on a capability GAIN, gated by FP checks', () => {
  const i = byId(INDICATORS, 'dependency-capability-creep-across-version-bump');
  assert.ok(i, 'across-version-bump capability-creep indicator must be present');
  assert.equal(i.type, 'behavioral_signal');
  assert.equal(i.deterministic, false, 'capability creep is probabilistic — must not auto-verdict');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.ok(Array.isArray(i.false_positive_checks_required) && i.false_positive_checks_required.length >= 4,
    'load-bearing FP checks keep the high-recall heuristic from over-firing on build tooling');
  assert.ok(/version bump/i.test(i.value), 'value must describe the version-delta semantics');
});

test('package-capability-creep absolute-surface screen flags install-script + high-trust capability, no CVE needed', () => {
  const i = byId(INDICATORS, 'package-capability-creep');
  assert.ok(i, 'absolute capability-surface indicator must be present');
  assert.equal(i.type, 'config_value');
  assert.equal(i.deterministic, false);
  assert.equal(i.attack_ref, 'T1195.002');
  assert.ok(!('cve_ref' in i), 'capability-surface is CVE-independent — must not pin a cve_ref');
  assert.ok(Array.isArray(i.false_positive_checks_required) && i.false_positive_checks_required.length >= 4,
    'FP checks must cover the build-tooling/native-addon benign class');
  assert.ok(/install-script/.test(i.value) && /credential-harvesting|delivery/.test(i.value),
    'value must name the install-script + high-trust-capability delivery shape');
});

test('both capability indicators carry a paired false_positive_profile entry', () => {
  for (const id of ['dependency-capability-creep-across-version-bump', 'package-capability-creep']) {
    const fp = FP_PROFILE.find((x) => x.indicator_id === id);
    assert.ok(fp, `${id} must have a false_positive_profile entry`);
    assert.ok(typeof fp.distinguishing_test === 'string' && fp.distinguishing_test.length > 40,
      `${id} FP profile must carry a real distinguishing test`);
  }
});

test('sbom playbook _meta.version advanced to 1.3.0 with a matching changelog rung', () => {
  assert.equal(PB._meta.version, '1.3.0', 'playbook semver must reflect the capability-signal additions');
  assert.ok(Array.isArray(PB._meta.changelog), 'playbook must carry a changelog');
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.3.0'),
    'a 1.3.0 changelog rung must document the capability taxonomy');
});
