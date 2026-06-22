"use strict";


// ---- routed from playbook-post-quantum-migration.substantive ----
require("node:test").describe("playbook-post-quantum-migration.substantive", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from pqc-notify-legal-escalation ----
require("node:test").describe("pqc-notify-legal-escalation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * post-quantum-migration: the notify_legal escalation gated on an EU
 * jurisdiction obligation must actually fire.
 *
 * The condition read `jurisdiction_obligations contains NIS2-Art21-2h` — an
 * unquoted literal that no obligation field equals (the regulation field is
 * "NIS2 Art.21(2)(h)"). The clause parsed cleanly and returned a legitimate
 * false with no diagnostic, so the escalation was permanently dead. It now
 * gates on `contains 'EU'`, the jurisdiction dimension the other playbooks use.
 *
 * Asserts the exact firing condition (signal fired AND EU obligation present)
 * and that it stays quiet without the signal — a coincidence-passing
 * truthiness check would miss the dead-literal regression this guards.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const PB = 'post-quantum-migration';
const DIR = 'full-programme-audit';

test('PQC notify_legal escalation fires when the asset-register gap is found under an EU obligation', () => {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, { 'no-cryptographic-asset-register': 'fired' });
  const esc = (an.escalations || []).find((e) => e.action === 'notify_legal');
  assert.ok(esc, 'the notify_legal escalation must fire when no-cryptographic-asset-register is fired and the govern phase carries an EU obligation');
  assert.match(esc.condition, /jurisdiction_obligations contains 'EU'/,
    'the escalation must gate on the EU jurisdiction obligation, not an unmatchable literal');
});

test('PQC notify_legal escalation stays quiet when the asset-register signal is not fired', () => {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, {});
  const esc = (an.escalations || []).find((e) => e.action === 'notify_legal');
  assert.ok(!esc, 'notify_legal must not fire without the no-cryptographic-asset-register signal');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
