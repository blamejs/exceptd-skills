"use strict";

/**
 * tests/audit-log-integrity.test.js
 *
 * Behavioral tests for the data/playbooks/audit-log-integrity.json playbook.
 *
 * The playbook is data, but it is load-bearing data: the engine reads its
 * _meta currency score, the validator resolves its cross-references, and the
 * runner walks its indicators. These tests assert the playbook
 *   - parses and carries the _meta the engine requires (id == filename,
 *     semver version, ISO last_threat_review, threat_currency_score >= the
 *     engine's hard-block threshold of 50);
 *   - validates against lib/schemas/playbook.schema.json with ZERO
 *     error-severity findings (via the exported validate());
 *   - resolves every cross-reference the validator checks with ZERO
 *     error-severity findings (via the exported checkCrossRefs());
 *   - carries the domain-specific integrity indicators (hash-chain
 *     verification, off-host signing, compliance-WORM, writer/custodian
 *     separation) with the required indicator fields and unique ids;
 *   - wires every false_positive_profile / remediation for_signals /
 *     notification obligation_ref / feeds_into reference to a real target.
 *
 * Negative paths confirm the validator actually rejects a broken copy of THIS
 * playbook — a test that only asserts the good form passes is a coincidence
 * waiting to happen.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PLAYBOOK_ID = "audit-log-integrity";
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

// The engine hard-blocks below this score (lib/playbook-runner.js preflight()).
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
  assert.equal(pb._meta.id, PLAYBOOK_ID, "_meta.id must match the filename stem");
  assert.match(pb._meta.version, /^\d+\.\d+\.\d+$/, "version must be semver");
  assert.match(
    pb._meta.last_threat_review,
    /^\d{4}-\d{2}-\d{2}$/,
    "last_threat_review must be an ISO date",
  );
  assert.equal(
    typeof pb._meta.threat_currency_score,
    "number",
    "threat_currency_score must be numeric or the engine treats the playbook as stale",
  );
  assert.ok(
    pb._meta.threat_currency_score >= ENGINE_HARD_BLOCK,
    `threat_currency_score ${pb._meta.threat_currency_score} must be >= the engine hard-block ${ENGINE_HARD_BLOCK}`,
  );
  assert.ok(pb._meta.threat_currency_score <= 100, "score must be <= 100");
  assert.equal(typeof pb._meta.owner, "string");
  assert.equal(pb._meta.air_gap_mode, false);
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

test(`${PLAYBOOK_ID}: detect.indicators is non-empty and each carries the required fields`, () => {
  const pb = loadPlaybook();
  const indicators = pb.phases.detect.indicators;
  assert.ok(Array.isArray(indicators) && indicators.length > 0, "indicators must be non-empty");

  const confEnum = new Set(["low", "medium", "high", "deterministic"]);
  const ids = new Set();
  for (const ind of indicators) {
    assert.equal(typeof ind.id, "string", "indicator id must be a string");
    assert.ok(ind.id.length > 0, "indicator id must be non-empty");
    assert.equal(ids.has(ind.id), false, `indicator id "${ind.id}" must be unique`);
    ids.add(ind.id);
    assert.equal(typeof ind.value, "string", `${ind.id}.value must be a string`);
    assert.ok(confEnum.has(ind.confidence), `${ind.id}.confidence "${ind.confidence}" invalid`);
    assert.equal(typeof ind.deterministic, "boolean", `${ind.id}.deterministic must be boolean`);
    assert.equal(typeof ind.type, "string");
  }

  // Domain-specific floor: the four integrity controls that define this
  // playbook must all be present as indicators. If any is renamed or dropped,
  // the playbook stops covering the privileged-attacker-rewrites-the-trail
  // threat it exists for.
  for (const required of [
    "audit-hash-chain-not-verified",
    "audit-log-not-signed-or-key-colocated",
    "worm-immutability-not-enforced",
    "audit-log-deletable-by-writing-identity",
  ]) {
    assert.ok(ids.has(required), `expected indicator "${required}" in the detect set`);
  }
});

test(`${PLAYBOOK_ID}: every false_positive_profile.indicator_id resolves to a real indicator`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  const fp = pb.phases.detect.false_positive_profile || [];
  assert.ok(fp.length > 0, "expected at least one false_positive_profile entry");
  for (const entry of fp) {
    assert.ok(
      indicatorIds.has(entry.indicator_id),
      `false_positive_profile.indicator_id "${entry.indicator_id}" has no matching indicator`,
    );
    assert.equal(typeof entry.distinguishing_test, "string");
    assert.ok(entry.distinguishing_test.length > 0);
  }
});

test(`${PLAYBOOK_ID}: remediation_paths.for_signals all resolve to real indicators`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  const paths = pb.phases.validate.remediation_paths || [];
  assert.ok(paths.length > 0, "expected at least one remediation path");
  for (const rp of paths) {
    for (const sig of rp.for_signals || []) {
      assert.ok(
        indicatorIds.has(sig),
        `remediation_paths[${rp.id}].for_signals "${sig}" has no matching indicator`,
      );
    }
  }
});

test(`${PLAYBOOK_ID}: notification obligation_refs resolve to a govern obligation key`, () => {
  const pb = loadPlaybook();
  const obligationKeys = new Set(
    (pb.phases.govern.jurisdiction_obligations || []).map(obligationKey),
  );
  // This playbook carries the NIS2 24h + US spoliation 0h obligations.
  assert.ok(obligationKeys.has("EU/NIS2 Art.23 24h"), "expected the NIS2 Art.23 24h obligation");
  for (const na of pb.phases.close.notification_actions || []) {
    assert.ok(
      obligationKeys.has(na.obligation_ref),
      `notification_actions.obligation_ref "${na.obligation_ref}" does not resolve`,
    );
  }
});

test(`${PLAYBOOK_ID}: feeds_into targets resolve and the theater chain is wired`, () => {
  const pb = loadPlaybook();
  const { ids } = ctxAndIds();
  const feeds = pb._meta.feeds_into || [];
  assert.ok(feeds.length > 0, "expected feeds_into edges");
  const targets = new Set(feeds.map((f) => f.playbook_id));
  for (const f of feeds) {
    assert.ok(ids.has(f.playbook_id), `feeds_into target "${f.playbook_id}" is not a real playbook`);
    assert.equal(typeof f.condition, "string");
    assert.ok(f.condition.length > 0);
  }
  // The theater verdict must chain into the framework correlation playbook.
  assert.ok(targets.has("framework"), "a theater verdict must feed into the framework playbook");
});

// ---------------------------------------------------------------------------
// Negative paths — the validator must actually reject a broken copy of THIS
// playbook, not just bless the shipped one.
// ---------------------------------------------------------------------------

test(`${PLAYBOOK_ID}: a duplicate indicator id is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  assert.ok(pb.phases.detect.indicators.length >= 2, "need >= 2 indicators to dupe");
  pb.phases.detect.indicators[1].id = pb.phases.detect.indicators[0].id;
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /duplicate indicator id/.test(f.message));
  assert.equal(matched.length, 1, "exactly one duplicate-id error expected");
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: an rwep_threshold ordering violation is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.phases.direct.rwep_threshold = { close: 90, monitor: 50, escalate: 10 };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /rwep_threshold.*ordering violation/i.test(f.message));
  assert.equal(matched.length, 1, "exactly one ordering-violation error expected");
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: removing all TTP mappings is a hard error (Hard Rule #4)`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.domain.atlas_refs = [];
  pb.domain.attack_refs = [];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /domain: no TTP mapping/.test(f.message));
  assert.equal(matched.length, 1, "exactly one no-TTP error expected");
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: a typo'd clock_starts is a hard error so the regulatory clock can't ship broken`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  assert.ok(pb.phases.govern.jurisdiction_obligations.length >= 1);
  pb.phases.govern.jurisdiction_obligations[0].clock_starts = "detect_confirmd";
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /clock_starts: invalid value "detect_confirmd"/.test(f.message));
  assert.equal(matched.length, 1, "exactly one clock_starts error expected");
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: emptying detect.indicators trips the schema minItems error`, () => {
  const pb = loadPlaybook();
  pb.phases.detect.indicators = [];
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter((f) =>
    /phases\.detect\.indicators: array shorter than minItems 1/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one detect.indicators minItems error expected");
  assert.equal(matched[0].severity, "error");
});
