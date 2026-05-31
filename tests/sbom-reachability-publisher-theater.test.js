'use strict';

/**
 * tests/sbom-reachability-publisher-theater.test.js
 *
 * Pins the final socket.dev adoptions in the supply-chain playbook: the CVE-
 * reachability demoter, the publisher-identity-change detector, and the two
 * new compliance-theater fingerprints. Asserts the load-bearing content +
 * the reachability indicator's confidence/deterministic contract (which is
 * what keeps it out of the 'detected' classification branch — it can never
 * mute a real CVE match). Exact-value pins per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const IND = PB.phases.detect.indicators;
const ART = PB.phases.look.artifacts;
const FPP = PB.phases.detect.false_positive_profile;
const TF = PB.phases.govern.theater_fingerprints;
const byId = (arr, id) => arr.find((x) => x.id === id);
const byPat = (arr, pid) => arr.find((x) => x.pattern_id === pid);

test('dependency-cve-unreachable is a low-confidence non-deterministic demoter that cannot reach detected', () => {
  const i = byId(IND, 'dependency-cve-unreachable');
  assert.ok(i, 'reachability demoter must be present');
  // The load-bearing contract: confidence low + deterministic false means a
  // firing hit satisfies neither hasDeterministicHit nor hasHighConfHit, so it
  // never drives classification 'detected' and can never mute a real match.
  assert.equal(i.confidence, 'low');
  assert.equal(i.deterministic, false);
  assert.equal(i.attack_ref, 'T1195.002');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.ok(!('cve_ref' in i), 'reachability is a cross-cutting annotation, not bound to one CVE');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks gate it to demote-only-with-attestation');
  assert.ok(/over-approximate/i.test(i.false_positive_checks_required[0]),
    'the over-approximate-uncertain-to-reachable check must be first (makes it demote-only, never mute-by-default)');
  assert.ok(byId(ART, 'cve-reachability-surface'), 'paired reachability look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-cve-unreachable'), 'paired FP profile must exist');
  // The matcher it annotates must be left untouched (no FP-checks => still fires high).
  const matcher = byId(IND, 'package-matches-catalogued-cve');
  assert.equal(matcher.confidence, 'high', 'the core matcher stays high-confidence');
  assert.ok(!('false_positive_checks_required' in matcher), 'the core matcher must NOT gain FP-checks (would change its firing)');
});

test('publisher-identity-change detector fires on identity discontinuity absent a capability change', () => {
  const i = byId(IND, 'dependency-publisher-identity-change-without-capability-change');
  assert.ok(i, 'publisher-identity-change indicator must be present');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.equal(i.deterministic, false);
  assert.ok(/capability surface is UNCHANGED|absent a behavior delta|without requiring any capability/i.test(i.value),
    'must require capability UNCHANGED (the gap capability-creep cannot see)');
  assert.ok(i.false_positive_checks_required.length >= 5, 'FP checks gate the identity-change heuristic');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-publisher-identity-change-without-capability-change'));
});

test('two new govern theater-fingerprints (license + publisher-trust) with mapped controls', () => {
  const lic = byPat(TF, 'license-policy-attested-but-not-enforced');
  assert.ok(lic, 'license theater fingerprint must be present');
  assert.ok(lic.implicated_controls.includes('eu-cra-art13'), 'license fingerprint maps to a real framework control');
  assert.ok(/blocking gate|fails the build|BLOCK/.test(lic.fast_detection_test), 'must test enforcement, not attestation');
  const pub = byPat(TF, 'publisher-trust-attested-but-not-enforced');
  assert.ok(pub, 'publisher-trust theater fingerprint must be present');
  assert.ok(pub.implicated_controls.length >= 1 && pub.fast_detection_test.length > 60);
  // No attack_ref/atlas_ref on fingerprints — they map to implicated_controls, not TTPs (no orphaned-control obligation).
  assert.ok(!('attack_ref' in lic) && !('attack_ref' in pub), 'theater fingerprints carry no TTP ref');
});

test('theater-fingerprint count is 8 and the hardcoded skill-chain count was updated', () => {
  assert.equal(TF.length, 8, 'six original + license + publisher-trust = eight');
  const sc = PB.phases.direct.skill_chain.find((s) => s.purpose && /theater fingerprints in govern/.test(s.purpose));
  assert.ok(sc, 'the theater-fingerprint skill-chain step must exist');
  assert.ok(/eight theater fingerprints/.test(sc.purpose), 'the hardcoded count must read "eight", not "six"');
  assert.ok(!/the six theater fingerprints/.test(sc.purpose), 'the stale "six" count must be gone');
});

test('sbom playbook advanced to 1.4.0 with a matching changelog rung (version only advances)', () => {
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.4.0'), 'a 1.4.0 changelog rung must document the additions');
  const [maj, min] = String(PB._meta.version).split('.').map(Number);
  assert.ok(maj > 1 || (maj === 1 && min >= 4), `playbook _meta.version (${PB._meta.version}) must be >= 1.4.0`);
});
