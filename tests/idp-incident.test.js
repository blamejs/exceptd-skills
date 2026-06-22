"use strict";

/**
 * tests/idp-incident.test.js
 *
 * Behavioral tests for the data/playbooks/idp-incident.json playbook
 * (identity-provider tenant compromise + federated-trust abuse + OAuth consent
 * abuse).
 *
 * Asserts the playbook parses, carries engine-usable _meta, validates against
 * lib/schemas/playbook.schema.json with zero error-severity findings, resolves
 * every cross-reference, and carries the IdP-control-plane structure that
 * defines it: the single DETERMINISTIC federated-trust-modification indicator
 * (the highest-leverage control-plane object), the OAuth-consent-abuse and
 * help-desk-MFA-swap indicators, the DORA 4h clock, and the feeds_into edges.
 * The minimum_signal.detected clause must key off the deterministic indicator,
 * and that indicator must actually be marked deterministic. Negative paths
 * confirm the validator rejects a broken copy.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PLAYBOOK_ID = "idp-incident";
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
const DETERMINISTIC_INDICATOR = "anomalous-federated-trust-addition";

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
  assert.equal(pb.domain.attack_class, "identity-abuse");
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

test(`${PLAYBOOK_ID}: cve_refs resolve against the live catalog`, () => {
  const pb = loadPlaybook();
  const { ctx } = ctxAndIds();
  assert.ok((pb.domain.cve_refs || []).length > 0);
  for (const cve of pb.domain.cve_refs) {
    assert.ok(ctx.cveKeys.has(cve), `cve_ref "${cve}" is not in data/cve-catalog.json`);
  }
});

test(`${PLAYBOOK_ID}: detect.indicators carry required fields, unique ids, and the IdP-plane signals`, () => {
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
    DETERMINISTIC_INDICATOR,
    "unauthorized-consent-grant-from-non-corp-tenant",
    "mfa-factor-swap-without-password-reset",
    "service-account-unused-then-active",
  ]) {
    assert.ok(ids.has(required), `expected indicator "${required}" in the detect set`);
  }
});

test(`${PLAYBOOK_ID}: the federated-trust indicator is the one deterministic indicator and is marked so`, () => {
  const pb = loadPlaybook();
  const deterministic = pb.phases.detect.indicators.filter((i) => i.deterministic === true);
  assert.equal(
    deterministic.length,
    1,
    "exactly one indicator should be deterministic (federated-trust modification)",
  );
  const fed = deterministic[0];
  assert.equal(fed.id, DETERMINISTIC_INDICATOR);
  assert.equal(
    fed.confidence,
    "deterministic",
    "the deterministic federated-trust indicator must also carry confidence:deterministic",
  );
});

test(`${PLAYBOOK_ID}: minimum_signal.detected keys off the deterministic indicator`, () => {
  const pb = loadPlaybook();
  const ms = pb.phases.detect.minimum_signal;
  assert.equal(typeof ms.detected, "string");
  assert.equal(typeof ms.inconclusive, "string");
  assert.equal(typeof ms.not_detected, "string");
  assert.match(
    ms.detected,
    new RegExp(DETERMINISTIC_INDICATOR),
    "minimum_signal.detected must reference the deterministic federated-trust indicator",
  );
});

test(`${PLAYBOOK_ID}: rwep_inputs reference real indicators and ai_weaponization is in play`, () => {
  const pb = loadPlaybook();
  const indicatorIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  const validFactors = new Set([
    "cisa_kev", "public_poc", "ai_weaponization", "active_exploitation",
    "patch_available", "live_patch_available", "blast_radius",
  ]);
  const inputs = pb.phases.analyze.rwep_inputs || [];
  assert.ok(inputs.length > 0);
  const factorsUsed = new Set();
  for (const ri of inputs) {
    assert.ok(indicatorIds.has(ri.signal_id), `rwep_inputs.signal_id "${ri.signal_id}" unresolved`);
    assert.ok(validFactors.has(ri.rwep_factor), `rwep_factor "${ri.rwep_factor}" invalid`);
    assert.equal(typeof ri.weight, "number");
    factorsUsed.add(ri.rwep_factor);
  }
  // The deterministic federated-trust signal must drive blast_radius scoring.
  assert.ok(
    inputs.some((ri) => ri.signal_id === DETERMINISTIC_INDICATOR && ri.rwep_factor === "blast_radius"),
    "the federated-trust indicator must contribute to blast_radius",
  );
});

test(`${PLAYBOOK_ID}: the full multi-jurisdiction clock set is present and all obligation_refs resolve`, () => {
  const pb = loadPlaybook();
  const byKey = new Set((pb.phases.govern.jurisdiction_obligations || []).map(obligationKey));
  for (const expected of [
    "EU/GDPR Art.33 72h",
    "EU/NIS2 Art.23 24h",
    "EU/DORA Art.19 4h",
  ]) {
    assert.ok(byKey.has(expected), `expected the "${expected}" obligation`);
  }
  // Every close-phase notification must point at a real obligation.
  const nas = pb.phases.close.notification_actions || [];
  assert.ok(nas.length > 0);
  for (const na of nas) {
    assert.ok(byKey.has(na.obligation_ref), `obligation_ref "${na.obligation_ref}" does not resolve`);
  }
});

test(`${PLAYBOOK_ID}: feeds_into chains a high-blast finding into cred-stores and a theater verdict into framework`, () => {
  const pb = loadPlaybook();
  const { ids } = ctxAndIds();
  const feeds = pb._meta.feeds_into || [];
  assert.ok(feeds.length >= 2);
  const byTarget = new Map(feeds.map((f) => [f.playbook_id, f.condition]));
  for (const f of feeds) {
    assert.ok(ids.has(f.playbook_id), `feeds_into target "${f.playbook_id}" is not a real playbook`);
  }
  assert.ok(byTarget.has("cred-stores"), "an IdP compromise must chain into cred-stores");
  assert.match(byTarget.get("cred-stores"), /blast_radius_score\s*>=\s*4/);
  assert.ok(byTarget.has("framework"), "a theater verdict must chain into framework");
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

test(`${PLAYBOOK_ID}: an escalation condition rooted at an unavailable phase is a hard error`, () => {
  const pb = loadPlaybook();
  const { ctx, ids } = ctxAndIds();
  pb.phases.analyze.escalation_criteria = [
    { condition: "validate.tests_passed == true", action: "raise_severity" },
  ];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /escalation_criteria\[0\]\.condition: path root "validate\." is not resolvable/.test(f.message),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, "error");
});

test(`${PLAYBOOK_ID}: a bogus indicator confidence trips the schema enum (under --strict-equivalent error)`, () => {
  const pb = loadPlaybook();
  // confidence enum drift is a warning by default; assert it is at least
  // surfaced (the generic validator emits it as a warning-severity finding).
  pb.phases.detect.indicators[0].confidence = "extreme";
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter(
    (f) => /\.confidence/.test(f.message) && /not in enum/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one confidence-enum finding expected");
  assert.equal(matched[0].severity, "warning");
});

test(`${PLAYBOOK_ID}: a missing required indicator field (value) is a hard error`, () => {
  const pb = loadPlaybook();
  delete pb.phases.detect.indicators[0].value;
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter((f) =>
    /phases\.detect\.indicators\[0\]: missing required field "value"/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one missing-value error expected");
  assert.equal(matched[0].severity, "error");
});
