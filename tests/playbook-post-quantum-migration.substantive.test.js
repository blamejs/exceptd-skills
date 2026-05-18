'use strict';

/**
 * tests/playbook-post-quantum-migration.substantive.test.js
 *
 * Pins the canonical indicator + artifact ids for the
 * post-quantum-migration playbook. The diff-coverage gate
 * (scripts/check-test-coverage.js) refuses to merge a playbook surface
 * change unless the new ids appear by quoted-string match somewhere in
 * tests/. Beyond that gate, this file is the contract that downstream
 * skill-chain code (crypto / framework / sbom feeds_into) relies on:
 * renaming any of these ids is a breaking change for evidence-bundle
 * consumers and must come with an explicit migration.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const PLAYBOOK = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'data', 'playbooks', 'post-quantum-migration.json'),
  'utf8',
));

const EXPECTED_INDICATORS = [
  'no-cryptographic-asset-register',
  'register-incomplete-per-asset-fields',
  'hsm-firmware-no-pqc',
  'vendor-no-pqc-commitment',
  'long-retention-classical-only-asset',
  'policy-without-vendor-sla',
  'regulator-deadline-missing-or-stale',
  'no-downgrade-detection',
  'embedded-tls-stack-classical-only',
];

const EXPECTED_ARTIFACTS = [
  'cryptographic-asset-register',
  'asset-cmdb-extract',
  'hsm-kms-inventory',
  'tls-library-inventory',
  'certificate-pki-inventory',
  'vendor-pqc-roadmap-attestations',
  'data-retention-policy',
  'compensating-control-inventory',
  'regulator-deadline-tracker',
];

function ids(arr) { return new Set((arr || []).map((x) => x.id).filter(Boolean)); }

test('post-quantum-migration: playbook id + attack class', () => {
  assert.equal(PLAYBOOK._meta.id, 'post-quantum-migration');
  assert.equal(PLAYBOOK.domain.attack_class, 'pqc-exposure');
});

test('post-quantum-migration: every documented indicator id is present', () => {
  const present = ids(PLAYBOOK.phases.detect.indicators);
  for (const id of EXPECTED_INDICATORS) {
    assert.ok(present.has(id), `missing indicator id: ${id}`);
  }
});

test('post-quantum-migration: every documented artifact id is present', () => {
  const present = ids(PLAYBOOK.phases.look.artifacts);
  for (const id of EXPECTED_ARTIFACTS) {
    assert.ok(present.has(id), `missing artifact id: ${id}`);
  }
});

test('post-quantum-migration: feeds_into chain reaches crypto + framework + sbom', () => {
  const feeds = (PLAYBOOK._meta.feeds_into || []).map((f) => f.playbook_id);
  for (const target of ['crypto', 'framework', 'sbom']) {
    assert.ok(feeds.includes(target), `missing feeds_into target: ${target}`);
  }
});
