"use strict";

/**
 * tests/ransomware.test.js
 *
 * Structural + cross-reference pin for the ransomware incident-response
 * playbook (data/playbooks/ransomware.json).
 *
 * Asserts:
 *   - The file parses and _meta carries id/version/last_threat_review and a
 *     threat_currency_score at or above the engine hard-block threshold (50).
 *   - phases.detect.indicators is non-empty and every indicator carries the
 *     schema-required fields with unique ids and a vocabulary confidence.
 *   - The playbook validates with ZERO error-severity findings through the
 *     live validator (schema validate() + checkCrossRefs()).
 *   - The declared CVE references (the initial-access exemplars: ScreenConnect,
 *     Citrix, xz, runc) resolve against the live CVE catalog.
 *   - Every declared attack_ref resolves against the live technique catalog.
 *   - feeds_into / remediation for_signals / fp_profile cross-refs resolve.
 *   - The ransomware-specific surface (mass-encryption, shadow-copy deletion,
 *     exfil-before-encrypt) and the sanctions/insurance jurisdiction clocks
 *     are present.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const VALIDATOR = path.join(ROOT, "lib", "validate-playbooks.js");
const PLAYBOOK_ID = "ransomware";
const PLAYBOOK_PATH = path.join(ROOT, "data", "playbooks", `${PLAYBOOK_ID}.json`);

const { validate, checkCrossRefs, loadContext, loadPlaybooks } = require(VALIDATOR);
const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);
const CVE_CATALOG = JSON.parse(
  fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"),
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

test("declared CVE references resolve against the live CVE catalog", () => {
  const pb = loadPlaybook();
  const cveRefs = pb.domain.cve_refs || [];
  assert.ok(cveRefs.length >= 1, "ransomware declares its initial-access exemplar CVEs");
  // ScreenConnect (CVE-2024-1709) and xz (CVE-2024-3094) are anchor exemplars
  // for the documented 2024-2026 ransomware initial-access distribution.
  assert.ok(cveRefs.includes("CVE-2024-1709"), "the ScreenConnect initial-access CVE must be referenced");
  for (const cve of cveRefs) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(CVE_CATALOG, cve),
      `domain.cve_refs "${cve}" must resolve to a real entry in data/cve-catalog.json`,
    );
  }
});

test("declared attack_refs resolve against the live technique catalog and encryption is the anchor", () => {
  const pb = loadPlaybook();
  const attackRefs = pb.domain.attack_refs || [];
  assert.ok(attackRefs.length >= 1, "ransomware must map to at least one ATT&CK technique");
  // T1486 (Data Encrypted for Impact) is the defining technique.
  assert.ok(attackRefs.includes("T1486"), "the data-encrypted-for-impact technique must be referenced");
  for (const tech of attackRefs) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(ATTACK_CATALOG, tech),
      `domain.attack_refs "${tech}" must resolve to data/attack-techniques.json`,
    );
  }
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
  // Lateral-movement-via-credentials chains into cred-stores; theater verdict
  // chains into the framework correlation playbook.
  const targets = new Set(pb._meta.feeds_into.map((fi) => fi.playbook_id));
  assert.ok(targets.has("cred-stores"), "must feed into cred-stores on credential lateral movement");
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

test("fp_profile indicator_ids all reference real indicator ids", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  for (const fp of pb.phases.detect.false_positive_profile || []) {
    assert.ok(indIds.has(fp.indicator_id), `fp_profile indicator_id "${fp.indicator_id}" must reference a real indicator`);
  }
});

test("ransomware kill-chain surface: mass-encryption, shadow-copy deletion, and exfil-before-encrypt indicators are present", () => {
  const pb = loadPlaybook();
  const indIds = new Set(pb.phases.detect.indicators.map((i) => i.id));
  assert.ok(indIds.has("mass-file-extension-change-event"), "the mass-encryption indicator must be present");
  assert.ok(indIds.has("shadow-copy-deletion-no-iac-ticket"), "the shadow-copy-deletion indicator must be present");
  assert.ok(indIds.has("large-outbound-transfer-pre-encryption"), "the exfil-before-encrypt indicator must be present");

  for (const ind of pb.phases.detect.indicators) {
    if ("false_positive_checks_required" in ind) {
      assert.ok(
        Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1,
        `indicator ${ind.id} declares false_positive_checks_required but it is empty`,
      );
    }
  }
});

test("sanctions-before-payment and insurance jurisdiction clocks are present with valid clock_starts", () => {
  const pb = loadPlaybook();
  const obs = pb.phases.govern.jurisdiction_obligations;
  assert.ok(Array.isArray(obs) && obs.length >= 5, "ransomware declares its multi-jurisdiction obligation matrix");
  // OFAC sanctions screen is a 0h blocking gate on the payment posture.
  assert.ok(
    obs.some((o) => o.jurisdiction === "US" && o.obligation === "sanctions_screen_before_payment"),
    "the OFAC sanctions-before-payment gate must be present",
  );
  // Cyber-insurance carrier 24h notice is the insurance-aware clock.
  assert.ok(
    obs.some((o) => o.obligation === "notify_insurance_carrier" && o.window_hours === 24),
    "the cyber-insurance 24h carrier-notification clock must be present",
  );
  for (const o of obs) {
    assert.ok(typeof o.clock_starts === "string" && o.clock_starts.length > 0, "every obligation declares clock_starts");
    assert.ok(typeof o.window_hours === "number" && o.window_hours >= 0, "window_hours is a non-negative number");
  }
});

test("rwep_threshold is ordered (close <= monitor <= escalate) and in range", () => {
  const pb = loadPlaybook();
  const t = pb.phases.direct.rwep_threshold;
  assert.equal(typeof t.close, "number");
  assert.equal(typeof t.monitor, "number");
  assert.equal(typeof t.escalate, "number");
  assert.ok(t.close <= t.monitor && t.monitor <= t.escalate, `expected close <= monitor <= escalate; got ${JSON.stringify(t)}`);
  for (const [k, v] of Object.entries(t)) {
    assert.ok(v >= 0 && v <= 100, `rwep_threshold.${k} ${v} must be within 0..100`);
  }
});
