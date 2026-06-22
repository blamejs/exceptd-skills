"use strict";

/**
 * tests/cloud-iam-incident.test.js
 *
 * Behavioral tests for the data/playbooks/cloud-iam-incident.json playbook.
 *
 * Asserts the playbook parses, carries engine-usable _meta, validates against
 * lib/schemas/playbook.schema.json with zero error-severity findings, resolves
 * every cross-reference, and carries the cloud-IAM-specific incident
 * structure: the cross-account assume-role chain indicator (the dominant
 * 2024-2026 lateral-movement vector), the DORA 4h notification clock, the
 * cve_refs that anchor it to the live catalog, and the feeds_into edges that
 * chain a blast_radius>=4 finding into cred-stores and a theater verdict into
 * framework. Negative paths confirm the validator rejects a broken copy.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PLAYBOOK_ID = "cloud-iam-incident";
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

test(`${PLAYBOOK_ID}: cve_refs all resolve against the live cve-catalog`, () => {
  const pb = loadPlaybook();
  const { ctx } = ctxAndIds();
  assert.ok((pb.domain.cve_refs || []).length > 0, "cloud-iam playbook declares anchoring CVEs");
  for (const cve of pb.domain.cve_refs) {
    assert.ok(ctx.cveKeys.has(cve), `cve_ref "${cve}" is not in data/cve-catalog.json`);
  }
});

test(`${PLAYBOOK_ID}: detect.indicators is non-empty with required fields and the cross-account chain indicator`, () => {
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

  // The defining signal of this playbook: the cross-account assume-role chain,
  // invisible to AC-2 / CC6 lifecycle controls. Plus the audit-log-disabled
  // defence-evasion primitive and the dormant-then-active key-creation pattern.
  for (const required of [
    "cross_account_assume_role_anomaly",
    "root_login_from_new_asn",
    "iam_access_key_created_no_iac_ticket",
    "cloudtrail_logging_disabled_event",
  ]) {
    assert.ok(ids.has(required), `expected indicator "${required}" in the detect set`);
  }
});

test(`${PLAYBOOK_ID}: rwep_inputs only reference real indicators and use valid factors`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  const validFactors = new Set([
    "cisa_kev", "public_poc", "ai_weaponization", "active_exploitation",
    "patch_available", "live_patch_available", "blast_radius",
  ]);
  const inputs = pb.phases.analyze.rwep_inputs || [];
  assert.ok(inputs.length > 0, "expected rwep_inputs");
  for (const ri of inputs) {
    assert.ok(
      indicatorIds.has(ri.signal_id),
      `rwep_inputs.signal_id "${ri.signal_id}" has no matching indicator`,
    );
    assert.ok(validFactors.has(ri.rwep_factor), `rwep_factor "${ri.rwep_factor}" invalid`);
    assert.equal(typeof ri.weight, "number");
  }
});

test(`${PLAYBOOK_ID}: DORA 4h + GDPR 72h + NIS2 24h clocks are present and obligation_refs resolve`, () => {
  const pb = loadPlaybook();
  const obligations = pb.phases.govern.jurisdiction_obligations || [];
  const byKey = new Set(obligations.map(obligationKey));

  // The cloud-IAM playbook must carry the fastest financial-sector clock.
  assert.ok(byKey.has("EU/DORA Art.19 4h"), "expected the DORA Art.19 4h obligation");
  assert.ok(byKey.has("EU/NIS2 Art.23 24h"), "expected the NIS2 Art.23 24h obligation");

  // Every clock_starts must be in the closed vocabulary the runner honors.
  const validClock = new Set(["detect_confirmed", "analyze_complete", "validate_complete", "manual"]);
  for (const o of obligations) {
    assert.ok(validClock.has(o.clock_starts), `clock_starts "${o.clock_starts}" out of vocabulary`);
    assert.equal(typeof o.window_hours, "number");
  }

  for (const na of pb.phases.close.notification_actions || []) {
    assert.ok(byKey.has(na.obligation_ref), `obligation_ref "${na.obligation_ref}" does not resolve`);
  }
});

test(`${PLAYBOOK_ID}: feeds_into chains a high-blast finding into cred-stores and a theater verdict into framework`, () => {
  const pb = loadPlaybook();
  const { ids } = ctxAndIds();
  const feeds = pb._meta.feeds_into || [];
  assert.ok(feeds.length >= 2, "expected at least two feeds_into edges");

  const byTarget = new Map(feeds.map((f) => [f.playbook_id, f.condition]));
  for (const f of feeds) {
    assert.ok(ids.has(f.playbook_id), `feeds_into target "${f.playbook_id}" is not a real playbook`);
  }
  assert.ok(byTarget.has("cred-stores"), "a cloud-IAM compromise must chain into cred-stores");
  assert.match(
    byTarget.get("cred-stores"),
    /blast_radius_score\s*>=\s*4/,
    "the cred-stores chain must gate on blast_radius_score >= 4",
  );
  assert.ok(byTarget.has("framework"), "a theater verdict must chain into framework");
});

test(`${PLAYBOOK_ID}: blast_radius_model rubric is monotonic 1..5 and covers the cross-account boundary`, () => {
  const pb = loadPlaybook();
  const rubric = pb.phases.analyze.blast_radius_model.scoring_rubric;
  assert.ok(Array.isArray(rubric) && rubric.length > 0);
  const scores = rubric.map((r) => r.blast_radius_score);
  for (const s of scores) {
    assert.ok(Number.isInteger(s) && s >= 1 && s <= 5, `blast_radius_score ${s} out of 1..5`);
  }
  // The model must include the >= 4 tier that the cred-stores feeds_into gates on.
  assert.ok(scores.includes(4), "rubric must define a blast_radius_score of 4");
  assert.ok(Math.max(...scores) === 5, "rubric must top out at 5 (identity-boundary collapse)");
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

test(`${PLAYBOOK_ID}: an unresolvable cve_ref surfaces as a finding`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.domain.cve_refs = [...(pb.domain.cve_refs || []), "CVE-1999-99999"];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /cve_refs: unresolved "CVE-1999-99999"/.test(f.message));
  assert.equal(matched.length, 1, "exactly one unresolved-cve finding expected");
});

test(`${PLAYBOOK_ID}: a feeds_into condition rooted at an unavailable phase is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  // `detect.` is not a resolvable root in the feeds_into eval context.
  pb._meta.feeds_into = [{ playbook_id: "framework", condition: "detect.classification == 'detected'" }];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /feeds_into\[0\]\.condition: path root "detect\." is not resolvable/.test(f.message),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: an out-of-range blast_radius_score trips the schema maximum`, () => {
  const pb = loadPlaybook();
  pb.phases.analyze.blast_radius_model.scoring_rubric[0].blast_radius_score = 9;
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter((f) =>
    /blast_radius_score: value 9 > maximum 5/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one out-of-range blast_radius_score error expected");
  assert.equal(matched[0].severity, "error");
});
