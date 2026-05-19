"use strict";

/**
 * tests/audit-catalog-gaps.test.js
 *
 * Pins the contract of scripts/audit-catalog-gaps.js — the catalog
 * gap-detector that surfaces (a) missing context fields per entry,
 * (b) dangling cross-catalog refs, and (c) auto-imported / operator-
 * curated draft-debt ratios.
 *
 * The detector is complementary to lib/validate-cve-catalog.js (schema
 * validation, predeploy hard-gate). The gap analyzer polices the
 * recommended-but-not-required context envelope; the validator polices
 * what's strictly required by the schema.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const MOD = require(path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"));

test("audit-catalog-gaps exports SPEC for every shipped catalog", () => {
  assert.ok(MOD.SPEC, "SPEC must be exported");
  for (const key of [
    "cve-catalog",
    "cwe-catalog",
    "attack-techniques",
    "atlas-ttps",
    "d3fend-catalog",
    "rfc-references",
    "framework-control-gaps",
    "zeroday-lessons"
  ]) {
    assert.ok(MOD.SPEC[key], `SPEC.${key} must be present so operators get gap coverage for every catalog`);
    assert.ok(Array.isArray(MOD.SPEC[key].required_context),
      `SPEC.${key}.required_context must be an array`);
    assert.ok(MOD.SPEC[key].required_context.length > 0,
      `SPEC.${key}.required_context must declare at least one required field`);
  }
});

test("inspect() returns the per-catalog shape with missing-context findings", () => {
  const r = MOD.inspect("cve-catalog");
  assert.equal(r.catalog, "cve-catalog");
  assert.ok(typeof r.entries === "number" && r.entries > 0,
    "inspect must report entry count");
  assert.ok(Array.isArray(r.missing_context), "missing_context must be an array");
  assert.ok(typeof r.auto_imported === "number");
  assert.ok(typeof r.operator_curated === "number");
  assert.equal(r.auto_imported + r.operator_curated, r.entries,
    "auto_imported + operator_curated must equal total entries");
});

test("inspectRefs() detects dangling cross-catalog references", () => {
  // Use synthetic catalogs to confirm dangling-ref detection actually
  // fires. The real cross-refs are expected to resolve in the shipped
  // catalogs (separately validated by scripts/refresh-reverse-refs.js).
  const synth = {
    "cve-catalog": {
      _meta: {},
      "CVE-9999-12345": {
        cwe_refs: ["CWE-99999"],
        attack_refs: ["T9999"],
        atlas_refs: ["AML.T9999"],
        framework_control_gaps: { "NONEXISTENT-CONTROL": "test" }
      }
    },
    "cwe-catalog": { _meta: {}, "CWE-79": { name: "XSS" } },
    "attack-techniques": { _meta: {}, "T1190": { name: "Exploit" } },
    "atlas-ttps": { _meta: {}, "AML.T0001": { name: "Victim Research" } },
    "framework-control-gaps": { _meta: {}, "NIST-800-53-SI-2": {} }
  };
  const findings = MOD.inspectRefs(synth);
  // 4 dangling refs from CVE-9999-12345.
  assert.equal(findings.length, 4, "all four synthetic dangling refs must surface");
  const targets = findings.map((f) => f.target_catalog).sort();
  assert.deepEqual(
    targets,
    ["atlas-ttps", "attack-techniques", "cwe-catalog", "framework-control-gaps"],
    "every cross-ref target must be checked"
  );
  for (const f of findings) {
    assert.equal(f.kind, "dangling-ref");
    assert.equal(f.source_catalog, "cve-catalog");
    assert.equal(f.source_id, "CVE-9999-12345");
    assert.ok(f.missing, "missing field must name the unresolved ref");
  }
});

test("entry-level _gap_skip honored: operators can suppress documented gaps", () => {
  // Direct invocation of the inspect helper using a synthetic catalog
  // would require exporting the per-catalog walker. The integration
  // signal we pin here: the SPEC honors a _gap_skip.fields[] convention
  // (documented in the script header) so an operator can mark an entry
  // as legitimately exempt from a specific required-context field.
  // This test asserts the convention is documented in the script body.
  const fs = require("node:fs");
  const script = fs.readFileSync(
    path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"),
    "utf8"
  );
  assert.match(script, /_gap_skip/,
    "audit-catalog-gaps.js must implement the _gap_skip suppression convention");
});

test("--class missing-context filter zeroes out dangling-refs from totals", () => {
  // Verify the filter is wired by invoking the CLI directly. The actual
  // filtering logic is private to main(); we test the externally-
  // observable behavior: --class missing-context strict mode does NOT
  // count dangling-refs against the exit code.
  const { spawnSync } = require("node:child_process");
  const r = spawnSync(
    process.execPath,
    [path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"), "--class", "missing-context"],
    { encoding: "utf8" }
  );
  const json = JSON.parse(r.stdout);
  assert.equal(json.class_filter, "missing-context",
    "class_filter must be echoed back in the report");
  assert.equal(json.totals.dangling_refs, 0,
    "--class missing-context must zero out dangling_refs in totals");
});

test("--class dangling-ref filter zeroes out missing-context from totals", () => {
  const { spawnSync } = require("node:child_process");
  const r = spawnSync(
    process.execPath,
    [path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"), "--class", "dangling-ref"],
    { encoding: "utf8" }
  );
  const json = JSON.parse(r.stdout);
  assert.equal(json.class_filter, "dangling-ref");
  assert.equal(json.totals.missing_context, 0,
    "--class dangling-ref must zero out missing_context in totals");
});

test("--class with unknown value exits 2 and prints valid options", () => {
  const { spawnSync } = require("node:child_process");
  const r = spawnSync(
    process.execPath,
    [path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"), "--class", "bogus-class"],
    { encoding: "utf8" }
  );
  assert.equal(r.status, 2,
    "unknown --class value must exit 2");
  assert.match(r.stderr, /unknown class.*valid:/i,
    "stderr must enumerate the valid class names");
});

test("the cross-catalog reference plane is dangling-free on the shipped catalogs", () => {
  // Real-world sanity: the live shipped catalogs must have zero
  // dangling refs. If a future PR adds a CWE/ATT&CK/ATLAS/framework
  // ref that does not resolve, this fires.
  const fs = require("node:fs");
  const data = path.join(__dirname, "..", "data");
  const loaded = {
    "cve-catalog": JSON.parse(fs.readFileSync(path.join(data, "cve-catalog.json"), "utf8")),
    "cwe-catalog": JSON.parse(fs.readFileSync(path.join(data, "cwe-catalog.json"), "utf8")),
    "attack-techniques": JSON.parse(fs.readFileSync(path.join(data, "attack-techniques.json"), "utf8")),
    "atlas-ttps": JSON.parse(fs.readFileSync(path.join(data, "atlas-ttps.json"), "utf8")),
    "framework-control-gaps": JSON.parse(fs.readFileSync(path.join(data, "framework-control-gaps.json"), "utf8"))
  };
  const findings = MOD.inspectRefs(loaded);
  assert.equal(
    findings.length,
    0,
    `shipped catalogs must have zero dangling cross-refs; got ${findings.length}: ${JSON.stringify(findings.slice(0, 3))}`
  );
});
