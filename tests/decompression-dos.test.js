"use strict";

/**
 * tests/decompression-dos.test.js
 *
 * Behavioral tests for the data/playbooks/decompression-dos.json playbook
 * (decompression-bomb / parser-DoS / ReDoS).
 *
 * Asserts the playbook parses, carries engine-usable _meta, validates against
 * lib/schemas/playbook.schema.json with zero error-severity findings, resolves
 * every cross-reference, declares the amplification-DoS weakness catalog
 * (CWE-409 data amplification + CWE-1333 inefficient regex complexity), and
 * carries the indicators that define the class: unbounded archive
 * decompression (zip bomb), Zip Slip path traversal, XML entity expansion
 * (billion laughs / XXE), and catastrophic-backtracking ReDoS. Negative paths
 * confirm the validator rejects a broken copy.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PLAYBOOK_ID = "decompression-dos";
const PLAYBOOK_PATH = path.join(ROOT, "data", "playbooks", `${PLAYBOOK_ID}.json`);

const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);

const {
  validate,
  checkCrossRefs,
  loadContext,
  loadPlaybooks,
  obligationKey,
} = require(path.join(ROOT, "lib", "validate-playbooks.js"));

const ENGINE_HARD_BLOCK = 50;

function loadPlaybook() {
  return JSON.parse(fs.readFileSync(PLAYBOOK_PATH, "utf8"));
}

function ctxAndIds() {
  const ctx = loadContext();
  const ids = new Set(loadPlaybooks().filter((p) => p.data).map((p) => p.data._meta.id));
  return { ctx, ids };
}

function errorsOf(findings) {
  return findings.filter((f) => f.severity === "error");
}

test(`${PLAYBOOK_ID}: parses and _meta is engine-usable`, () => {
  const pb = loadPlaybook();
  assert.equal(pb._meta.id, PLAYBOOK_ID);
  assert.match(pb._meta.version, /^\d+\.\d+\.\d+$/);
  assert.match(pb._meta.last_threat_review, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(typeof pb._meta.threat_currency_score, "number");
  assert.ok(
    pb._meta.threat_currency_score >= ENGINE_HARD_BLOCK,
    `threat_currency_score ${pb._meta.threat_currency_score} must be >= ${ENGINE_HARD_BLOCK}`,
  );
  assert.ok(pb._meta.threat_currency_score <= 100);
  assert.equal(pb._meta.air_gap_mode, false);
  assert.equal(pb._meta.scope, "code", "decompression-dos is a code-scope (parser) playbook");
});

test(`${PLAYBOOK_ID}: validates against the schema with zero error-severity findings`, () => {
  const pb = loadPlaybook();
  const findings = validate(pb, SCHEMA, "playbook", PLAYBOOK_ID);
  assert.deepEqual(
    errorsOf(findings),
    [],
    "schema validation must produce no error-severity findings; got:\n" +
      errorsOf(findings).map((e) => `  - ${e.message}`).join("\n"),
  );
});

test(`${PLAYBOOK_ID}: resolves every cross-reference with zero error-severity findings`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  const findings = checkCrossRefs(pb, ctx, ids);
  assert.deepEqual(
    errorsOf(findings),
    [],
    "cross-ref resolution must produce no error-severity findings; got:\n" +
      errorsOf(findings).map((e) => `  - ${e.message}`).join("\n"),
  );
});

test(`${PLAYBOOK_ID}: declares the amplification weakness catalog and resolves cwe_refs`, () => {
  const pb = loadPlaybook();
  const { ctx } = ctxAndIds();
  const cwes = pb.domain.cwe_refs || [];
  // The two weaknesses this playbook's changelog says it adds.
  assert.ok(cwes.includes("CWE-409"), "expected CWE-409 (data amplification)");
  assert.ok(cwes.includes("CWE-1333"), "expected CWE-1333 (inefficient regex complexity)");
  for (const cwe of cwes) {
    assert.ok(ctx.cweKeys.has(cwe), `cwe_ref "${cwe}" is not in data/cwe-catalog.json`);
  }
});

test(`${PLAYBOOK_ID}: detect.indicators is non-empty with required fields and the class-defining signals`, () => {
  const pb = loadPlaybook();
  const indicators = pb.phases.detect.indicators;
  assert.ok(Array.isArray(indicators) && indicators.length > 0);

  const confEnum = new Set(["low", "medium", "high", "deterministic"]);
  const ids = new Set();
  for (const ind of indicators) {
    assert.equal(typeof ind.id, "string");
    assert.ok(ind.id.length > 0);
    assert.equal(ids.has(ind.id), false, `indicator id "${ind.id}" must be unique`);
    ids.add(ind.id);
    assert.equal(typeof ind.value, "string");
    assert.ok(confEnum.has(ind.confidence), `${ind.id}.confidence "${ind.confidence}" invalid`);
    assert.equal(typeof ind.deterministic, "boolean");
  }

  for (const required of [
    "archive-decompression-unbounded",
    "zip-slip-path-traversal",
    "xml-entity-expansion-enabled",
    "redos-catastrophic-backtracking",
    "length-field-unbounded-allocation",
  ]) {
    assert.ok(ids.has(required), `expected indicator "${required}" in the detect set`);
  }
});

test(`${PLAYBOOK_ID}: every indicator carries non-empty false_positive_checks_required`, () => {
  // This class is high-FP (a streaming/RE2/size-capped lower layer makes the
  // pattern benign), so each indicator must ship its distinguishing checks or
  // the runner cannot downgrade a hit to inconclusive.
  const pb = loadPlaybook();
  for (const ind of pb.phases.detect.indicators) {
    assert.ok(
      Array.isArray(ind.false_positive_checks_required) &&
        ind.false_positive_checks_required.length > 0,
      `${ind.id} must carry false_positive_checks_required`,
    );
  }
});

test(`${PLAYBOOK_ID}: false_positive_profile entries all resolve to a real indicator`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  const fp = pb.phases.detect.false_positive_profile || [];
  assert.ok(fp.length > 0);
  for (const entry of fp) {
    assert.ok(
      indicatorIds.has(entry.indicator_id),
      `false_positive_profile.indicator_id "${entry.indicator_id}" has no matching indicator`,
    );
  }
});

test(`${PLAYBOOK_ID}: remediation_paths.for_signals resolve and validation_tests cover the negative class`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  for (const rp of pb.phases.validate.remediation_paths || []) {
    for (const sig of rp.for_signals || []) {
      assert.ok(indicatorIds.has(sig), `for_signals "${sig}" has no matching indicator`);
    }
  }
  // The validate phase must include negative exploit-replay tests (zip bomb,
  // Zip Slip, billion laughs, ReDoS) plus a functional legitimate-input test.
  const tests = pb.phases.validate.validation_tests || [];
  const negatives = tests.filter((t) => t.test_type === "negative");
  const functionals = tests.filter((t) => t.test_type === "functional");
  assert.ok(negatives.length >= 3, "expected multiple negative validation tests");
  assert.ok(functionals.length >= 1, "expected a functional no-regression test");
});

test(`${PLAYBOOK_ID}: notification obligations include the CRA + NIS2 clocks and obligation_refs resolve`, () => {
  const pb = loadPlaybook();
  const byKey = new Set((pb.phases.govern.jurisdiction_obligations || []).map(obligationKey));
  assert.ok(byKey.has("EU/NIS2 Art.23 24h"), "expected the NIS2 Art.23 24h obligation");
  assert.ok(byKey.has("EU/EU CRA Annex I 24h"), "expected the EU CRA Annex I 24h obligation");
  for (const na of pb.phases.close.notification_actions || []) {
    assert.ok(byKey.has(na.obligation_ref), `obligation_ref "${na.obligation_ref}" does not resolve`);
  }
});

test(`${PLAYBOOK_ID}: feeds_into edges resolve and the theater chain is wired`, () => {
  const pb = loadPlaybook();
  const { ids } = ctxAndIds();
  const feeds = pb._meta.feeds_into || [];
  assert.ok(feeds.length > 0);
  const targets = new Set(feeds.map((f) => f.playbook_id));
  for (const f of feeds) {
    assert.ok(ids.has(f.playbook_id), `feeds_into target "${f.playbook_id}" is not a real playbook`);
    assert.equal(typeof f.condition, "string");
  }
  assert.ok(targets.has("framework"), "a theater verdict must feed into the framework playbook");
});

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

test(`${PLAYBOOK_ID}: a duplicate indicator id is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  assert.ok(pb.phases.detect.indicators.length >= 2);
  pb.phases.detect.indicators[1].id = pb.phases.detect.indicators[0].id;
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /duplicate indicator id/.test(f.message));
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: removing all TTP mappings is a hard error (Hard Rule #4)`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.domain.atlas_refs = [];
  pb.domain.attack_refs = [];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /domain: no TTP mapping/.test(f.message));
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: an out-of-vocabulary frameworks_in_scope value is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.domain.frameworks_in_scope = [...pb.domain.frameworks_in_scope, "not-a-framework"];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /frameworks_in_scope\[\d+\]: invalid value "not-a-framework"/.test(f.message),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: a non-semver _meta.version trips the schema pattern`, () => {
  const pb = loadPlaybook();
  pb._meta.version = "1.0";
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter(
    (f) => /_meta\.version/.test(f.message) && /does not match pattern/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one version-pattern error expected");
  assert.equal(matched[0].severity, "error");
});
