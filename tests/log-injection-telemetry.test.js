"use strict";

/**
 * tests/log-injection-telemetry.test.js
 *
 * Structural + cross-reference pin for the log-injection-telemetry playbook
 * (data/playbooks/log-injection-telemetry.json).
 *
 * Asserts:
 *   - The file parses and _meta carries id/version/last_threat_review and a
 *     threat_currency_score at or above the engine's hard-block threshold (50).
 *   - phases.detect.indicators is non-empty and every indicator carries the
 *     schema-required fields (id, type, value, confidence, deterministic) with
 *     unique ids and a confidence drawn from the closed vocabulary.
 *   - The playbook validates with ZERO error-severity findings through the
 *     live validator (schema validate() + checkCrossRefs()).
 *   - feeds_into / remediation for_signals / false_positive_profile cross-refs
 *     resolve to real targets.
 *   - The telemetry-specific surface is present: the CR/LF-injection indicator,
 *     the secrets-in-logs indicator, and the CWE-117 domain mapping.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const VALIDATOR = path.join(ROOT, "lib", "validate-playbooks.js");
const PLAYBOOK_ID = "log-injection-telemetry";
const PLAYBOOK_PATH = path.join(ROOT, "data", "playbooks", `${PLAYBOOK_ID}.json`);

const { validate, checkCrossRefs, loadContext, loadPlaybooks } = require(VALIDATOR);
const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);

// Engine hard-block threshold (lib/playbook-runner.js): score < 50 blocks.
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
  assert.equal(typeof pb._meta.threat_currency_score, "number");
  assert.ok(
    pb._meta.threat_currency_score >= CURRENCY_HARD_BLOCK,
    `threat_currency_score ${pb._meta.threat_currency_score} must be >= the engine hard-block ${CURRENCY_HARD_BLOCK}`,
  );
  assert.ok(Array.isArray(pb._meta.changelog) && pb._meta.changelog.length >= 1, "changelog non-empty");
  assert.equal(typeof pb._meta.air_gap_mode, "boolean");
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
    assert.equal(typeof ind.id, "string");
    assert.ok(ind.id.length > 0);
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

test("feeds_into references resolve to real playbooks and use resolvable condition roots", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = loadPlaybook();
  assert.ok(Array.isArray(pb._meta.feeds_into) && pb._meta.feeds_into.length >= 1, "expected at least one feeds_into edge");
  for (const fi of pb._meta.feeds_into) {
    assert.ok(ids.has(fi.playbook_id), `feeds_into target "${fi.playbook_id}" must be a real playbook`);
    assert.equal(typeof fi.condition, "string");
    assert.ok(fi.condition.length > 0);
  }
  // checkCrossRefs surfaces an error if any feeds_into condition is rooted at
  // an unresolvable phase name — assert none of those fire.
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

test("telemetry-specific surface: CR/LF-injection + secrets-in-logs indicators and CWE-117 mapping are present", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  assert.ok(indIds.has("crlf-log-injection-unsanitized"), "the CR/LF log-injection indicator must be present");
  assert.ok(indIds.has("secrets-or-pii-logged-without-redaction"), "the secrets-in-logs indicator must be present");

  // The changelog states this playbook adds CWE-117 to the catalog mapping.
  assert.ok(
    (pb.domain.cwe_refs || []).includes("CWE-117"),
    "domain.cwe_refs must include CWE-117 (improper output neutralization for logs)",
  );

  // Every indicator carrying false_positive_checks_required must list at least
  // one concrete check (the runner downgrades a hit to inconclusive otherwise).
  for (const ind of pb.phases.detect.indicators) {
    if ("false_positive_checks_required" in ind) {
      assert.ok(
        Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1,
        `indicator ${ind.id} declares false_positive_checks_required but it is empty`,
      );
    }
  }
});
