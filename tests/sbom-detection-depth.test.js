'use strict';

/**
 * tests/sbom-detection-depth.test.js
 *
 * Pins the supply-chain detection-depth indicators: typosquat/homoglyph
 * name detection, the static content red-flag screen, and the dependency-
 * confusion resolution-source check. Asserts the load-bearing content (the
 * TTP refs, the codepoint-class reuse, the MOIKA correlation, the FP checks)
 * rather than bare presence.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const IND = PB.phases.detect.indicators;
const ART = PB.phases.look.artifacts;
const FPP = PB.phases.detect.false_positive_profile;
const byId = (arr, id) => arr.find((x) => x.id === id);

test('typosquat/homoglyph detector reuses the vendored codepoint-class + maps T1195.002', () => {
  const i = byId(IND, 'dependency-name-typosquat');
  assert.ok(i, 'dependency-name-typosquat indicator must be present');
  assert.equal(i.attack_ref, 'T1195.002');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.equal(i.deterministic, false);
  assert.ok(/codepoint-class/.test(i.value), 'must route names through the vendored confusable detection (no re-invention)');
  assert.ok(/edit-distance|Levenshtein/i.test(i.value), 'must describe the edit-distance typosquat check');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks gate the high-recall name heuristic');
  assert.ok(byId(ART, 'package-name-similarity-surface'), 'paired name-similarity look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-name-typosquat'), 'paired FP profile must exist');
});

test('content-obfuscation screen maps T1027 and is distinct from the capability screens', () => {
  const i = byId(IND, 'package-content-obfuscation-screen');
  assert.ok(i, 'package-content-obfuscation-screen indicator must be present');
  assert.equal(i.attack_ref, 'T1027', 'obfuscation maps to T1027 (Obfuscated Files or Information)');
  assert.equal(i.deterministic, false);
  assert.ok(/minified|entropy|trivial|eval/.test(i.value), 'must name the content red-flags');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks must cover minified-dist / WASM / trivial-inert / framework-eval');
  assert.ok(byId(ART, 'package-source-content-surface'), 'paired source-content look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'package-content-obfuscation-screen'));
});

test('dependency-confusion resolution check correlates to MOIKA and gates on resolution-source', () => {
  const i = byId(IND, 'dependency-confusion-internal-scope-public-resolution');
  assert.ok(i, 'dep-confusion resolution indicator must be present');
  assert.equal(i.cve_ref, 'MAL-2026-MOIKA-DEPCONFUSION', 'must correlate to the catalogued MOIKA campaign');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.ok(/resolution-source|public registry|internal/i.test(i.value), 'must describe resolution-source confusion');
  assert.ok(i.false_positive_checks_required.length >= 5, 'five AND-conditions gate the resolution check');
  const art = byId(ART, 'dep-confusion-resolution-config');
  assert.ok(art && art.required === false, 'paired resolution-config artifact must exist and be optional');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-confusion-internal-scope-public-resolution'));
});

test('all three new indicators are distinct ids and the playbook advanced to 1.3.1', () => {
  const ids = ['dependency-name-typosquat', 'package-content-obfuscation-screen', 'dependency-confusion-internal-scope-public-resolution'];
  assert.equal(new Set(ids).size, 3, 'three distinct new indicator ids');
  assert.equal(PB._meta.version, '1.3.1');
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.3.1'), 'a 1.3.1 changelog rung must document the detection-depth pass');
  // cve_ref on the dep-confusion indicator must resolve to a real catalog entry.
  const cat = require(path.join(__dirname, '..', 'data', 'cve-catalog.json'));
  assert.ok(cat['MAL-2026-MOIKA-DEPCONFUSION'], 'the dep-confusion cve_ref must resolve to a real catalog entry');
});
