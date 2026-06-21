"use strict";

// Regression tests for the main-thread completions of the hunt-pass fixes —
// the cross-ownership items the per-cluster fix agents correctly could not
// touch (catalog conditions, the playbook schema, the lint-skills staleness
// gate, the d3fend-key hygiene, and the exit-after-stdout conversions surfaced
// by the now-accurate codebase-patterns detector). Each asserts the exact
// post-fix behavior and would fail on the pre-fix state.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const { _evalCondition } = require("../lib/playbook-runner.js");
const { validateFrontmatter } = require("../lib/lint-skills.js");

// ---------------------------------------------------------------------------
// #2 — sbom EU CRA Art.14 24h escalation: the composite-member `contains` form
// was permanently dead against the object-array obligations; the reworked
// quantifier form fires when a matched CVE is actively exploited under an EU
// obligation.
// ---------------------------------------------------------------------------
test("#2 sbom EU-CRA escalation: reworked condition fires, old composite form is dead", () => {
  const ctx = {
    matched_cve: [{ active_exploitation: "confirmed" }],
    jurisdiction_obligations: [{ jurisdiction: "EU", regulation: "EU CRA Art.14" }],
  };
  assert.equal(
    _evalCondition("any matched_cve.active_exploitation == 'confirmed' AND jurisdiction_obligations contains 'EU'", ctx),
    true,
    "reworked form must fire when a matched CVE is actively exploited under an EU obligation"
  );
  assert.equal(
    _evalCondition("any actively_exploited_match AND jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'", ctx),
    false,
    "old composite-member form stays dead (no obligation field equals the composite string)"
  );
});

test("#2 sbom.json carries the reworked escalation condition, not the dead composite form", () => {
  const raw = fs.readFileSync(path.join(ROOT, "data/playbooks/sbom.json"), "utf8");
  // Path-agnostic: assert on the catalog text regardless of where the
  // escalation lives (phase vs _meta). The JSON must still parse.
  JSON.parse(raw);
  assert.ok(
    raw.includes("any matched_cve.active_exploitation == 'confirmed' AND jurisdiction_obligations contains 'EU'"),
    "reworked EU-CRA escalation condition must be present"
  );
  assert.ok(
    !raw.includes("any actively_exploited_match AND jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'"),
    "the dead composite-member escalation condition must be gone"
  );
});

// ---------------------------------------------------------------------------
// phases.detect.classification — referenced a path the engine never exposes;
// rewritten to analyze.classification (the alias the engine populates).
// ---------------------------------------------------------------------------
test("phases.detect rewrite: analyze.classification resolves and no catalog condition uses the dead phases.detect path", () => {
  assert.equal(_evalCondition("analyze.classification == 'detected'", { analyze: { classification: "detected" } }), true);
  assert.equal(_evalCondition("analyze.classification == 'detected'", { analyze: { classification: "skipped" } }), false);

  const dir = path.join(ROOT, "data/playbooks");
  const offenders = [];
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".json"))) {
    const raw = fs.readFileSync(path.join(dir, f), "utf8");
    // Only flag a *condition* token, not prose summaries that mention the phase.
    const re = /"condition"\s*:\s*"[^"]*phases\.detect\.classification/;
    if (re.test(raw)) offenders.push(f);
  }
  assert.deepEqual(offenders, [], "no playbook condition may reference the engine-absent phases.detect.classification path");
});

// ---------------------------------------------------------------------------
// #21 — playbook schema `source` pattern must match API-verb-phrased network
// sources in lockstep with the imperative validate-playbooks regex.
// ---------------------------------------------------------------------------
test("#21 playbook.schema.json source pattern flags API-verb network sources and still flags URLs", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(ROOT, "lib/schemas/playbook.schema.json"), "utf8"));
  // Locate the source pattern (nested in the air-gap allOf/anyOf guard).
  const raw = fs.readFileSync(path.join(ROOT, "lib/schemas/playbook.schema.json"), "utf8");
  const m = raw.match(/"pattern":\s*"(\([^"]*https:\/\/[^"]*)"/);
  assert.ok(m, "source pattern must be present in the schema");
  const re = new RegExp(m[1]);
  assert.equal(re.test("Entra ID: GET /directoryRoles via Microsoft Graph"), true, "API-verb + Graph source must match");
  assert.equal(re.test("Okta admin console"), true, "Okta source must match");
  assert.equal(re.test("https://example.test/x"), true, "URL source must still match");
  assert.equal(re.test("/etc/passwd local file read"), false, "a benign local path must not match");
  // schema object is well-formed JSON
  assert.equal(typeof schema, "object");
});

// ---------------------------------------------------------------------------
// #41 — lint-skills staleness gate must reject a structurally-ISO but
// non-calendar date (e.g. 2026-13-99) rather than letting NaN slip past as
// "not older than 365 days".
// ---------------------------------------------------------------------------
test("#41 validateFrontmatter rejects a structurally-ISO but invalid calendar date", () => {
  const bad = validateFrontmatter({ last_threat_review: "2026-13-99" }, "fixture-skill");
  assert.ok(Array.isArray(bad.errors), "validateFrontmatter returns an errors array");
  assert.ok(
    bad.errors.some((e) => /last_threat_review/.test(e) && /ISO date/.test(e)),
    "a 2026-13-99 date must be rejected as not a valid ISO date"
  );
  // A real, current calendar date must NOT raise the date-format error.
  const good = validateFrontmatter({ last_threat_review: "2026-06-01" }, "fixture-skill");
  assert.ok(
    !good.errors.some((e) => /last_threat_review/.test(e) && /ISO date/.test(e)),
    "a valid calendar date must not raise the ISO-date format error"
  );
});

// ---------------------------------------------------------------------------
// d3fend key hygiene — the trailing-period artifact ids are normalized so the
// orphan/cross-ref token scanners can round-trip them, and the OWL importer
// strips a terminal period so the artifact cannot recur.
// ---------------------------------------------------------------------------
test("d3fend-catalog has no trailing-period artifact ids and keeps the normalized keys", () => {
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "data/d3fend-catalog.json"), "utf8"));
  const badKeys = Object.keys(cat).filter((k) => /\.$/.test(k));
  assert.deepEqual(badKeys, [], "no catalog key may end in a period");
  assert.ok(cat["D3A-C4"] && cat["D3A-C4"].id === "D3A-C4", "D3A-C4 normalized key present with matching id");
  assert.ok(cat["D3A-C5"] && cat["D3A-C5"].id === "D3A-C5", "D3A-C5 normalized key present with matching id");
  assert.equal(/\.\/$/.test(cat["D3A-C4"].reference_url), false, "reference_url must not carry the spurious period-slash");
});

test("refresh-upstream d3fend importer strips a terminal period from d3fend-id", () => {
  const src = fs.readFileSync(path.join(ROOT, "scripts/refresh-upstream-catalogs.js"), "utf8");
  assert.match(
    src,
    /d3fendEntryFromOwl[\s\S]{0,400}replace\(\/\\\.\$\/,\s*""\)/,
    "d3fendEntryFromOwl must strip a trailing period from the OWL d3fend-id"
  );
});

// ---------------------------------------------------------------------------
// Exit-after-stdout conversions surfaced by the now-accurate detector — the
// flagged sites use exitCode/throw, not process.exit() after a stdout write.
// (The codebase-patterns predeploy gate is the live enforcement; these are
// belt-and-suspenders structural pins on the specific sites.)
// ---------------------------------------------------------------------------
test("exit-after-stdout sites converted to exitCode/throw", () => {
  const gap = fs.readFileSync(path.join(ROOT, "scripts/check-catalog-gap-budget.js"), "utf8");
  assert.equal(/process\.exit\(1\)/.test(gap), false, "check-catalog-gap-budget no longer process.exit(1) after the summary stdout write");
  assert.match(gap, /process\.exitCode = 1; return;/);

  const bi = fs.readFileSync(path.join(ROOT, "scripts/build-indexes.js"), "utf8");
  assert.match(bi, /unknown output[\s\S]{0,160}process\.exitCode = 2; return;/, "build-indexes unknown-output uses exitCode+return");

  const rel = fs.readFileSync(path.join(ROOT, "scripts/release.js"), "utf8");
  assert.match(rel, /throw new Error\(\s*\n?\s*"CHANGELOG\.md top heading is/, "release prepare throws on a changelog-version mismatch (aborts `all`, no exit-after-stdout)");
});
