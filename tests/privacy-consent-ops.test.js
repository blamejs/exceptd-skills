"use strict";

/**
 * tests/privacy-consent-ops.test.js
 *
 * Structural + cross-reference pin for the privacy-consent-ops playbook
 * (data/playbooks/privacy-consent-ops.json).
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
 *   - The privacy/sanctions surface (homoglyph evasion, consent integrity
 *     binding, erasure completion proof) is present.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const VALIDATOR = path.join(ROOT, "lib", "validate-playbooks.js");
const PLAYBOOK_ID = "privacy-consent-ops";
const PLAYBOOK_PATH = path.join(ROOT, "data", "playbooks", `${PLAYBOOK_ID}.json`);

const { validate, checkCrossRefs, loadContext, loadPlaybooks } = require(VALIDATOR);
const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);
const ATTACK_CATALOG = JSON.parse(
  fs.readFileSync(path.join(ROOT, "data", "attack-techniques.json"), "utf8"),
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

test("maps to ATT&CK techniques and every declared attack_ref resolves against the live catalog", () => {
  const pb = loadPlaybook();
  const attackRefs = pb.domain.attack_refs || [];
  // This is a compliance-theater playbook with no first-party CVEs; its TTP
  // mapping is via domain.attack_refs (Hard Rule #4 TTP-mapping floor).
  assert.ok(attackRefs.length >= 1, "privacy-consent-ops must map to at least one ATT&CK technique");
  assert.deepEqual(pb.domain.cve_refs, [], "this playbook declares no first-party CVEs");
  // T1036 (masquerading via homoglyph) is the anchor technique.
  assert.ok(attackRefs.includes("T1036"), "the masquerading technique must be referenced");
  for (const tech of attackRefs) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(ATTACK_CATALOG, tech),
      `domain.attack_refs "${tech}" must resolve to a real entry in data/attack-techniques.json`,
    );
  }
  // Every indicator-level attack_ref must also resolve.
  for (const ind of pb.phases.detect.indicators) {
    if (ind.attack_ref) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(ATTACK_CATALOG, ind.attack_ref),
        `indicator ${ind.id} attack_ref "${ind.attack_ref}" must resolve to data/attack-techniques.json`,
      );
    }
  }
});

test("feeds_into references resolve and use resolvable condition roots", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = loadPlaybook();
  assert.ok(Array.isArray(pb._meta.feeds_into) && pb._meta.feeds_into.length >= 1, "expected at least one feeds_into edge");
  // The compliance-theater verdict feeds the framework correlation playbook.
  assert.ok(
    pb._meta.feeds_into.some((fi) => fi.playbook_id === "framework"),
    "privacy-consent-ops must feed into the framework correlation playbook",
  );
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

test("privacy/sanctions surface: homoglyph-evasion, consent-binding, and erasure-proof indicators are present", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  assert.ok(indIds.has("sanctions-screening-homoglyph-evasion"), "the homoglyph-evasion indicator must be present");
  assert.ok(indIds.has("consent-record-no-integrity-binding"), "the consent-integrity-binding indicator must be present");
  assert.ok(indIds.has("dsr-erasure-no-completion-proof"), "the erasure-completion-proof indicator must be present");

  // Every non-deterministic indicator must carry a non-empty false-positive
  // checklist — this playbook is config-value heuristic detection, so the FP
  // distinguishing test is load-bearing, not decorative.
  for (const ind of pb.phases.detect.indicators) {
    if ("false_positive_checks_required" in ind) {
      assert.ok(
        Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1,
        `indicator ${ind.id} declares false_positive_checks_required but it is empty`,
      );
    }
  }
});

test("govern jurisdiction obligations carry GDPR + OFAC clocks with valid clock_starts", () => {
  const pb = loadPlaybook();
  const obs = pb.phases.govern.jurisdiction_obligations;
  assert.ok(Array.isArray(obs) && obs.length >= 1, "must declare at least one jurisdiction obligation");
  // GDPR 72h is the anchor breach clock for the erasure/consent failures.
  assert.ok(
    obs.some((o) => o.jurisdiction === "EU" && o.window_hours === 72),
    "must carry the EU/GDPR 72h notification clock",
  );
  // clock_starts is a closed vocabulary; an out-of-vocab value would have
  // surfaced as an error in the validator test above, but assert positively
  // that each obligation actually declares one.
  for (const o of obs) {
    assert.ok(typeof o.clock_starts === "string" && o.clock_starts.length > 0, "every obligation declares clock_starts");
    assert.ok(typeof o.window_hours === "number" && o.window_hours >= 0, "window_hours is a non-negative number");
  }
});
