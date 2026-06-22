'use strict';

/**
 * tests/mal-2026-moika-depconfusion.test.js
 *
 * Per-subject coverage for MAL-2026-MOIKA-DEPCONFUSION (first dependency-
 * confusion catalog entry). Combines: the catalog threat-intel pins (RWEP =
 * sum(factors), populated iocs, C2 oob.moika.tech), the Package-Confidence
 * Score (PCS) invariants, the SARIF MAL-rule authority routing (no NVD link),
 * and the sbom playbook dep-confusion indicator that correlates to this id.
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CAT = require(path.join(ROOT, 'data', 'cve-catalog.json'));
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));
const runner = require(path.resolve(ROOT, 'lib', 'playbook-runner.js'));

const ID = 'MAL-2026-MOIKA-DEPCONFUSION';

function rwepSum(e) { return Object.values(e.rwep_factors).reduce((a, b) => a + b, 0); }
function iocsPopulated(e) {
  return e.iocs && typeof e.iocs === 'object' && !Array.isArray(e.iocs) && Object.keys(e.iocs).length > 0;
}

// ---------------------------------------------------------------------------
// catalog threat-intel (protestware-and-malware-catalog-entries)
// ---------------------------------------------------------------------------

test('MAL-2026-MOIKA-DEPCONFUSION — first dependency-confusion entry: RWEP 43, populated iocs', () => {
  const e = CAT[ID];
  assert.ok(e, 'MOIKA entry must be in the catalog');
  assert.equal(e.cisa_kev, false);
  assert.equal(e.type, 'supply-chain-dependency-confusion');
  assert.equal(e.rwep_score, 43);
  assert.equal(rwepSum(e), 43);
  assert.ok(iocsPopulated(e));
  assert.ok(/oob\.moika\.tech/.test(JSON.stringify(e.iocs)), 'C2 oob.moika.tech must be recorded in iocs');
});

test('MAL-2026-MOIKA-DEPCONFUSION has a paired zeroday-lesson', () => {
  const lessons = require(path.join(ROOT, 'data', 'zeroday-lessons.json'));
  assert.ok(lessons[ID], `${ID} must have a paired zeroday-lessons entry`);
  assert.ok(Array.isArray(lessons[ID].new_control_requirements) && lessons[ID].new_control_requirements.length >= 1,
    `${ID} lesson must generate at least one new control requirement`);
});

// ---------------------------------------------------------------------------
// Package-Confidence Score (package-confidence) — per-entry slices
// ---------------------------------------------------------------------------

test('MAL-2026-MOIKA-DEPCONFUSION carries a valid trust-polarity PCS that matches its inputs', () => {
  const e = CAT[ID];
  const pc = e.package_confidence;
  assert.ok(pc, `${ID} must carry package_confidence`);
  assert.equal(pc.polarity, 'trust', 'polarity const guards against summing with RWEP');
  assert.ok(Number.isInteger(pc.score) && pc.score >= 0 && pc.score <= 100, 'score is an integer in [0,100]');
  assert.equal(pc.score, scoring.packageConfidence(pc.inputs), `${ID} score must equal packageConfidence(inputs)`);
});

test('PCS does not perturb RWEP — MAL-2026-MOIKA-DEPCONFUSION still has rwep_score == sum(rwep_factors)', () => {
  const e = CAT[ID];
  assert.equal(e.rwep_score, rwepSum(e), `${ID}: PCS must not change the RWEP sum invariant`);
});

// ---------------------------------------------------------------------------
// SARIF MAL-rule authority routing (csaf-sarif-identifiers)
// ---------------------------------------------------------------------------

describe('SARIF rule helpUri — MAL-2026-MOIKA-DEPCONFUSION carries no NVD link', () => {
  function sarifRulesFor(matched) {
    const pb = runner.loadPlaybook('sbom');
    const directiveId = pb.directives[0].id;
    const analyzeResult = {
      matched_cves: matched,
      rwep: { adjusted: 95 }, blast_radius_score: 4, framework_gap_mapping: [],
      _detect_indicators: [], _detect_classification: 'detected',
      compliance_theater_check: { verdict: 'present' },
    };
    const out = runner.close('sbom', directiveId, analyzeResult, { regression_next_run: null, selected_remediation: { id: 'rem-1', description: 'patch' } },
      { _bundle_formats: ['sarif'] }, { session_id: 'abcdef0123456789' });
    return out.evidence_package.bundles_by_format['sarif'].runs[0].tool.driver.rules;
  }

  it('a MAL- rule carries no nvd.nist.gov helpUri and labels its authority', () => {
    const rules = sarifRulesFor([
      { cve_id: 'CVE-2026-43284', rwep: 90, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
      { cve_id: ID, rwep: 88, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
    ]);
    const malRule = rules.find(r => r.id.endsWith(ID));
    assert.ok(malRule, 'MAL rule present');
    assert.equal(malRule.helpUri, undefined);
    assert.equal(malRule.shortDescription.text, `${ID} (Malicious-Package)`);
  });

  it('advisoryAuthorityFor routes the MAL- prefix to Malicious-Package with no helpUri', () => {
    const a = runner._advisoryAuthorityFor;
    assert.deepEqual(a('MAL-2026-X'), { system_name: 'Malicious-Package', helpUri: null });
  });
});

// ---------------------------------------------------------------------------
// sbom playbook dep-confusion indicator correlates to MOIKA (sbom-detection-depth)
// ---------------------------------------------------------------------------

test('dependency-confusion resolution check correlates to MOIKA and gates on resolution-source', () => {
  const PB = require(path.join(ROOT, 'data', 'playbooks', 'sbom.json'));
  const IND = PB.phases.detect.indicators;
  const ART = PB.phases.look.artifacts;
  const FPP = PB.phases.detect.false_positive_profile;
  const byId = (arr, id) => arr.find((x) => x.id === id);

  const i = byId(IND, 'dependency-confusion-internal-scope-public-resolution');
  assert.ok(i, 'dep-confusion resolution indicator must be present');
  assert.equal(i.cve_ref, ID, 'must correlate to the catalogued MOIKA campaign');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.ok(/resolution-source|public registry|internal/i.test(i.value), 'must describe resolution-source confusion');
  assert.ok(i.false_positive_checks_required.length >= 5, 'five AND-conditions gate the resolution check');
  const art = byId(ART, 'dep-confusion-resolution-config');
  assert.ok(art && art.required === false, 'paired resolution-config artifact must exist and be optional');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-confusion-internal-scope-public-resolution'));
  // cve_ref on the dep-confusion indicator must resolve to a real catalog entry.
  assert.ok(CAT[ID], 'the dep-confusion cve_ref must resolve to a real catalog entry');
});
