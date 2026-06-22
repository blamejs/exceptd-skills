"use strict";

/**
 * tests/self-update-integrity.test.js
 *
 * Structural + cross-reference pin for the self-update-integrity playbook
 * (data/playbooks/self-update-integrity.json).
 *
 * Asserts:
 *   - The file parses and _meta carries id/version/last_threat_review and a
 *     threat_currency_score at or above the engine hard-block threshold (50).
 *   - phases.detect.indicators is non-empty and every indicator carries the
 *     schema-required fields with unique ids and a vocabulary confidence.
 *   - The playbook validates with ZERO error-severity findings through the
 *     live validator (schema validate() + checkCrossRefs()).
 *   - The playbook maps to at least one ATT&CK technique (Hard Rule #4) and
 *     every declared attack_ref resolves against the live technique catalog.
 *   - feeds_into / remediation for_signals / fp_profile cross-refs resolve.
 *   - The consumer-side update surface (signature-before-apply, anti-rollback,
 *     verifier-gating) is present.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const VALIDATOR = path.join(ROOT, "lib", "validate-playbooks.js");
const PLAYBOOK_ID = "self-update-integrity";
const PLAYBOOK_PATH = path.join(ROOT, "data", "playbooks", `${PLAYBOOK_ID}.json`);

const { validate, checkCrossRefs, loadContext, loadPlaybooks } = require(VALIDATOR);
const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);
const ATTACK_CATALOG = JSON.parse(
  fs.readFileSync(path.join(ROOT, "data", "attack-techniques.json"), "utf8"),
);
const CWE_CATALOG = JSON.parse(
  fs.readFileSync(path.join(ROOT, "data", "cwe-catalog.json"), "utf8"),
);

const CURRENCY_HARD_BLOCK = 50;
const CONFIDENCE_VOCAB = new Set(["low", "medium", "high", "deterministic"]);

function loadPlaybook() {
  return JSON.parse(fs.readFileSync(PLAYBOOK_PATH, "utf8"));
}

function ctxAndIds() {
  const ctx = loadContext();
  const ids = new Set(loadPlaybooks().filter((p) => p.data).map((p) => p.data._meta.id));
  return { ctx, ids };
}

test("parses and _meta is well-formed", () => {
  const pb = loadPlaybook();
  assert.equal(pb._meta.id, PLAYBOOK_ID, "_meta.id must equal the filename stem");
  assert.match(pb._meta.version, /^\d+\.\d+\.\d+$/, "version is semver");
  assert.match(pb._meta.last_threat_review, /^\d{4}-\d{2}-\d{2}$/, "last_threat_review is an ISO date");
  assert.ok(
    pb._meta.threat_currency_score >= CURRENCY_HARD_BLOCK,
    `threat_currency_score ${pb._meta.threat_currency_score} must be >= the engine hard-block ${CURRENCY_HARD_BLOCK}`,
  );
  assert.ok(Array.isArray(pb._meta.changelog) && pb._meta.changelog.length >= 1, "changelog non-empty");
});

test("detect.indicators is non-empty and every indicator is well-shaped with a unique id", () => {
  const pb = loadPlaybook();
  const indicators = pb.phases.detect.indicators;
  assert.ok(Array.isArray(indicators) && indicators.length >= 1, "indicators must be a non-empty array");

  const ids = new Set();
  for (const ind of indicators) {
    for (const field of ["id", "type", "value", "confidence", "deterministic"]) {
      assert.ok(field in ind, `indicator ${ind.id || "?"} missing required field "${field}"`);
    }
    assert.equal(typeof ind.value, "string");
    assert.ok(ind.value.length > 0, `indicator ${ind.id} must have a non-empty value`);
    assert.equal(typeof ind.deterministic, "boolean");
    assert.ok(CONFIDENCE_VOCAB.has(ind.confidence), `indicator ${ind.id} confidence "${ind.confidence}" out of vocabulary`);
    assert.ok(!ids.has(ind.id), `duplicate indicator id "${ind.id}"`);
    ids.add(ind.id);
  }
});

test("validates with zero error-severity findings through the live validator", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = loadPlaybook();
  const findings = [
    ...validate(pb, SCHEMA, "playbook", PLAYBOOK_ID),
    ...checkCrossRefs(pb, ctx, ids),
  ];
  const errors = findings.filter((f) => f.severity === "error");
  assert.deepEqual(
    errors,
    [],
    `${PLAYBOOK_ID} must have zero error-severity findings; got:\n` +
      errors.map((e) => `  - ${e.message}`).join("\n"),
  );
});

test("maps to ATT&CK techniques and CWE refs resolve against live catalogs", () => {
  const pb = loadPlaybook();
  const attackRefs = pb.domain.attack_refs || [];
  // Supply-chain consumer-side playbook with no first-party CVEs; mapped via
  // domain.attack_refs (Hard Rule #4) and anchored on the supply-chain CWEs.
  assert.ok(attackRefs.length >= 1, "self-update-integrity must map to at least one ATT&CK technique");
  assert.deepEqual(pb.domain.cve_refs, [], "this playbook declares no first-party CVEs");
  // T1195.002 (Compromise Software Supply Chain) is the anchor technique.
  assert.ok(attackRefs.includes("T1195.002"), "the supply-chain-compromise technique must be referenced");
  for (const tech of attackRefs) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(ATTACK_CATALOG, tech),
      `domain.attack_refs "${tech}" must resolve to data/attack-techniques.json`,
    );
  }
  // CWE-494 (Download of Code Without Integrity Check) is the defining weakness.
  assert.ok((pb.domain.cwe_refs || []).includes("CWE-494"), "the download-without-integrity-check CWE must be referenced");
  for (const cwe of pb.domain.cwe_refs || []) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(CWE_CATALOG, cwe),
      `domain.cwe_refs "${cwe}" must resolve to data/cwe-catalog.json`,
    );
  }
});

test("feeds_into references resolve and use resolvable condition roots", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = loadPlaybook();
  assert.ok(Array.isArray(pb._meta.feeds_into) && pb._meta.feeds_into.length >= 1, "expected at least one feeds_into edge");
  const targets = new Set(pb._meta.feeds_into.map((fi) => fi.playbook_id));
  // An unverified dependency update chains into the sbom supply-chain playbook;
  // a theater verdict chains into framework correlation.
  assert.ok(targets.has("sbom"), "must feed into the sbom playbook on an unverified dependency update");
  assert.ok(targets.has("framework"), "must feed into the framework correlation playbook");
  for (const fi of pb._meta.feeds_into) {
    assert.ok(ids.has(fi.playbook_id), `feeds_into target "${fi.playbook_id}" must be a real playbook`);
    assert.ok(typeof fi.condition === "string" && fi.condition.length > 0);
  }
  const rootErrs = checkCrossRefs(pb, ctx, ids).filter((f) =>
    /feeds_into\[\d+\]\.condition: path root .* is not resolvable/.test(f.message),
  );
  assert.deepEqual(rootErrs, [], "no feeds_into condition may be rooted at an unresolvable phase");
});

test("remediation for_signals and fp_profile indicator_ids all reference real indicator ids", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  for (const rp of pb.phases.validate.remediation_paths || []) {
    for (const sig of rp.for_signals || []) {
      assert.ok(indIds.has(sig), `remediation ${rp.id} for_signals "${sig}" must reference a real indicator`);
    }
  }
  for (const fp of pb.phases.detect.false_positive_profile || []) {
    assert.ok(indIds.has(fp.indicator_id), `fp_profile indicator_id "${fp.indicator_id}" must reference a real indicator`);
  }
});

test("consumer-side update surface: signature-before-apply, anti-rollback, and verifier-gate indicators are present", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  assert.ok(indIds.has("self-update-no-signature-verification"), "the no-signature-verification indicator must be present");
  assert.ok(indIds.has("self-update-no-anti-rollback"), "the anti-rollback indicator must be present");
  assert.ok(indIds.has("update-applied-without-verifier-gate"), "the verifier-gate indicator must be present");

  for (const ind of pb.phases.detect.indicators) {
    if ("false_positive_checks_required" in ind) {
      assert.ok(
        Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1,
        `indicator ${ind.id} declares false_positive_checks_required but it is empty`,
      );
    }
  }
});

test("every remediation for_signals link is covered and the highest-RWEP signal has a priority-1 remediation", () => {
  const pb = loadPlaybook();
  const rps = pb.phases.validate.remediation_paths || [];
  // The signature-before-apply gap carries the largest blast_radius weight; it
  // must have a priority-1 remediation that names it.
  const sigRemediation = rps.find(
    (rp) => Array.isArray(rp.for_signals) && rp.for_signals.includes("self-update-no-signature-verification"),
  );
  assert.ok(sigRemediation, "self-update-no-signature-verification must have a remediation path");
  assert.equal(sigRemediation.priority, 1, "the signature-before-apply remediation must be priority 1");

  // Every indicator that appears in an rwep_input must be remediable.
  const remediatedSignals = new Set(rps.flatMap((rp) => rp.for_signals || []));
  for (const ri of pb.phases.analyze.rwep_inputs || []) {
    assert.ok(
      remediatedSignals.has(ri.signal_id),
      `rwep_input signal "${ri.signal_id}" must be covered by at least one remediation path`,
    );
  }
});
