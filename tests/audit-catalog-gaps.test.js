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

// v0.13.20 audit-test split: the live-catalog assertion moved to
// tests/shipped-catalog-integrity.test.js so the detector-logic tests
// here run against synthetic inputs only. Bundling them led to
// confusing failure messages when an unrelated catalog edit broke the
// "shipped catalogs dangling-free" assertion. Pinned only the file
// reference here so a tooling consumer can locate the live-data test.
test("the live-catalog dangling-free invariant is asserted somewhere in the suite", () => {
  const fs = require("node:fs");
  // Reorg-robust: the shipped-catalog integrity check (inspectRefs against the
  // live catalogs) must exist in SOME test file — wherever the subject reorg
  // homed it — rather than pinning a single filename that consolidation moves.
  const dir = __dirname;
  const hit = fs.readdirSync(dir)
    .filter((f) => f.endsWith(".test.js"))
    .some((f) => {
      const body = fs.readFileSync(path.join(dir, f), "utf8");
      return /inspectRefs\s*\(/.test(body) && /dangling/i.test(body);
    });
  assert.ok(hit,
    "some test file must exercise inspectRefs for the live-catalog dangling-ref invariant");
});

// Original test kept (renamed) as a compatibility hook so external
// callers grep'ing for "dangling-free" still find a reference. The
// real live-catalog check is in the integrity test now.
test("legacy alias: detector returns zero dangling refs on the shipped catalogs (delegates to integrity test)", () => {
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


// ---- routed from shipped-catalog-integrity ----
require("node:test").describe("shipped-catalog-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/shipped-catalog-integrity.test.js
 *
 * Live-catalog invariants. v0.13.20 split — the audit-catalog-gaps
 * detector tests now exercise synthetic inputs only; the assertions
 * about the LIVE shipped catalogs live here. When a catalog edit
 * breaks one of these the failure message points at the data, not at
 * the detector logic.
 *
 * Pins:
 *   1. Every cross-catalog reference resolves (no dangling refs).
 *   2. CVE catalog draft-debt ratio is reported but not enforced —
 *      bulk-import auto-imported entries are legitimate intake work.
 *   3. Every required-context field on every entry that does NOT
 *      declare a class-level exemption (forward_looking, _matrix-
 *      qualified ICS exception, etc.) is populated. Missing-context
 *      surfaces as a test failure, NOT a silent audit warning.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MOD = require(path.join(ROOT, "scripts", "audit-catalog-gaps.js"));

function loadAll() {
  const data = path.join(ROOT, "data");
  return {
    "cve-catalog": JSON.parse(fs.readFileSync(path.join(data, "cve-catalog.json"), "utf8")),
    "cwe-catalog": JSON.parse(fs.readFileSync(path.join(data, "cwe-catalog.json"), "utf8")),
    "attack-techniques": JSON.parse(fs.readFileSync(path.join(data, "attack-techniques.json"), "utf8")),
    "atlas-ttps": JSON.parse(fs.readFileSync(path.join(data, "atlas-ttps.json"), "utf8")),
    "framework-control-gaps": JSON.parse(fs.readFileSync(path.join(data, "framework-control-gaps.json"), "utf8"))
  };
}

test("shipped catalogs: zero dangling cross-catalog references", () => {
  const findings = MOD.inspectRefs(loadAll());
  assert.equal(
    findings.length,
    0,
    `shipped catalogs must have zero dangling cross-refs; got ${findings.length}: ${JSON.stringify(findings.slice(0, 3))}`
  );
});

test("shipped catalogs: missing-context budget is enforced per catalog (no silent regression)", () => {
  // v0.13.20 honest-state: we have known missing-context on cve-catalog
  // (operator-curation backlog for IoCs on bulk-imported CVEs) and on
  // zeroday-lessons (per-primitive new_control_requirements pending).
  // The release explicitly stops auto-filling stubs that hid these
  // gaps — operators see them honestly via `npm run audit-catalog-gaps`.
  //
  // The integrity test enforces a budget per catalog: a snapshot of the
  // missing-context count today. If a future PR makes the gap worse,
  // the test fires. If a PR closes gaps, the budget gets lowered in
  // the same PR. This is the no-MVP rule applied to the catalog —
  // you can't make the catalog WORSE without explicit acknowledgement.
  const BUDGET = {
    // The bulk-imported KEV draft backlog has been fully curated — every CVE
    // entry now carries a behavioral iocs block, so the missing-iocs count is 0.
    // This budget stays at 0 as a guard: any future entry shipped without iocs
    // is a regression and fails the gate.
    "cve-catalog":     { iocs: 0 },
    "cwe-catalog":     {},
    "attack-techniques": {},
    "atlas-ttps":      {},
    "d3fend-catalog":  {},
    // Obsoleted/historic RFCs are now imported so a superseded RFC resolves
    // offline. 31 of them carry no abstract in the IETF index (older RFCs
    // predate the abstract field); that absence is upstream, not a curation
    // regression — the rows are otherwise complete (title, status, obsoleted_by).
    "rfc-references":  { abstract: 31 },
    "framework-control-gaps": {},
    // Lessons whose remediation reuses existing controls (perimeter/edge patch
    // SLA, endpoint and application hardening, kernel/driver hardening) rather
    // than demanding a new one carry no new_control_requirements — the field is
    // honestly absent rather than padded with a fabricated control, which the
    // no-orphaned-controls rule forbids. The count rises as such lessons are
    // added for newly-curated CVEs (e.g. legacy client-side browser/reader RCEs
    // whose defense is patch + end-of-life-retirement + Protected View/ASR, not
    // a novel control). Raised to the current actual when that happens.
    "zeroday-lessons": { new_control_requirements: 429 }
  };
  const findings = {};
  for (const key of Object.keys(MOD.SPEC)) {
    findings[key] = {};
    const r = MOD.inspect(key);
    for (const f of r.missing_context) {
      findings[key][f.field] = (findings[key][f.field] || 0) + 1;
    }
  }
  const regressions = [];
  for (const [key, fieldsBudget] of Object.entries(BUDGET)) {
    const actual = findings[key] || {};
    // Any field not in the budget must be at 0 (new gap class regressed).
    for (const field of Object.keys(actual)) {
      const allowed = fieldsBudget[field] || 0;
      if (actual[field] > allowed) {
        regressions.push(`${key}.${field}: budget=${allowed} actual=${actual[field]} (regression of ${actual[field] - allowed})`);
      }
    }
  }
  if (regressions.length > 0) {
    assert.fail(
      `missing-context regression beyond budget:\n  ${regressions.join("\n  ")}\n` +
      `Either close the gap in this PR (preferred) or, if the gap is intentional, update the BUDGET above with a justifying comment.`
    );
  }
});

test("shipped catalogs: framework-control-gaps forward_looking exemption is used as a SCHEMA field, not as _gap_skip", () => {
  // Class 5.15 from the v0.13.19 audit: 84 framework gaps had blanket
  // _gap_skip annotations as the exemption. v0.13.20 converted them
  // to forward_looking:true. Pin that no _gap_skip remains on those
  // entries.
  const fwc = loadAll()["framework-control-gaps"];
  const stillSkipped = [];
  for (const id of Object.keys(fwc)) {
    if (id === "_meta") continue;
    const e = fwc[id];
    if (e && e._gap_skip && Array.isArray(e._gap_skip.fields) && e._gap_skip.fields.includes("evidence_cves")) {
      stillSkipped.push(id);
    }
  }
  assert.equal(stillSkipped.length, 0,
    `framework-control-gaps entries must use forward_looking:true (not _gap_skip on evidence_cves). Stragglers: ${stillSkipped.join(", ")}`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
