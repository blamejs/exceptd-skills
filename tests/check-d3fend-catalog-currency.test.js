"use strict";
/**
 * Regression for the D3FEND catalog currency gate
 * (scripts/check-d3fend-catalog-currency.js), against a synthetic JSON-LD
 * release so no network is needed. Pins reading ids, labels and tactics out of
 * the release, the name renderings that count as the same technique, and each
 * problem class checkCatalog reports.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { parseRelease, isRenderingOf, tacticProblems, findDivergences, checkCatalog } =
  require(path.resolve(__dirname, "..", "scripts", "check-d3fend-catalog-currency.js"));

const FIXTURE = JSON.stringify({
  "@context": {},
  "@graph": [
    { "@id": "d3f:Harden", "@type": ["owl:Class", "d3f:DefensiveTactic"], "rdfs:label": "Harden" },
    { "@id": "d3f:Detect", "@type": ["owl:Class", "d3f:DefensiveTactic"], "rdfs:label": "Detect" },
    {
      "@id": "d3f:PlatformHardening",
      "@type": ["owl:Class"],
      "d3f:d3fend-id": "D3-PH",
      "d3f:enables": { "@id": "d3f:Harden" },
      "rdfs:label": "Platform Hardening",
      "rdfs:subClassOf": [{ "@id": "d3f:DefensiveTechnique" }, { "@id": "_:b1" }],
    },
    {
      "@id": "d3f:BootloaderAuthentication",
      "@type": ["owl:Class"],
      "d3f:d3fend-id": "D3-BA",
      "rdfs:label": "Bootloader Authentication",
      "rdfs:subClassOf": [{ "@id": "d3f:PlatformHardening" }],
    },
    {
      "@id": "d3f:NetworkTrafficAnalysis",
      "@type": ["owl:Class"],
      "d3f:d3fend-id": "D3-NTA",
      "d3f:enables": { "@id": "d3f:Detect" },
      "rdfs:label": { "@value": "Network Traffic Analysis" },
    },
    {
      "@id": "d3f:Variability",
      "@type": ["owl:Class"],
      "d3f:d3fend-id": "D3A-VAR",
      "rdfs:label": "Variability",
      "rdfs:subClassOf": { "@id": "d3f:Statistic" },
    },
    { "@id": "d3f:LogisticRegression", "d3f:d3fend-id": "D3A-LR", "rdfs:label": "Logistic Regression" },
    { "@id": "d3f:LinearRegression", "d3f:d3fend-id": "D3A-LR", "rdfs:label": "Linear Regression" },
    { "@id": "d3f:LogicalRules", "d3f:d3fend-id": "D3A-LR", "rdfs:label": "Logical Rules" },
    { "@id": "d3f:ClassifierFour", "d3f:d3fend-id": "D3A-C4.", "rdfs:label": "Classifier Four" },
    {
      "@id": "d3f:KernelbasedProcessIsolation",
      "d3f:d3fend-id": "D3-KBPI",
      "d3f:enables": { "@id": "d3f:Harden" },
      "rdfs:label": "Kernel-based Process Isolation",
    },
    { "@id": "d3f:NoId", "rdfs:label": "Not A Technique" },
  ],
});

const release = parseRelease(FIXTURE);

function entry(id, name, tactic) {
  return { id, name, tactic };
}

test("parseRelease reads ids and labels, including a value object", () => {
  assert.equal(release.names.get("D3-PH"), "Platform Hardening");
  assert.equal(release.names.get("D3-NTA"), "Network Traffic Analysis");
  assert.equal(release.names.get("D3A-VAR"), "Variability");
  assert.equal(release.names.size, 7, "only nodes with a d3fend-id are read, one key per id");
});

test("parseRelease keeps every label of an id shared between artifacts", () => {
  assert.deepEqual(release.labels.get("D3A-LR"), ["Logistic Regression", "Linear Regression", "Logical Rules"]);
  assert.deepEqual(release.labels.get("D3-PH"), ["Platform Hardening"]);
});

test("parseRelease keys an id written with a trailing dot without the dot", () => {
  assert.equal(release.names.has("D3A-C4."), false);
  assert.equal(release.names.get("D3A-C4"), "Classifier Four");
});

test("every label that shares an id is accepted, and an unrelated name is not", () => {
  const ok = (name) => checkCatalog({ "D3A-LR": entry("D3A-LR", name, "Defensive") }, release, null, "1.3.0").problems;
  assert.deepEqual(ok("Logistic Regression"), []);
  assert.deepEqual(ok("Linear Regression"), []);
  assert.deepEqual(ok("Logical Rules"), []);
  const bad = ok("Lasso Regression");
  assert.equal(bad.length, 1);
  assert.match(bad[0], /D3A-LR is named "Lasso Regression"; D3FEND 1\.3\.0 names it "Logistic Regression \| Linear Regression \| Logical Rules"/);
});

test("a catalog id without the trailing dot matches the release id that has one", () => {
  const catalog = { "D3A-C4": entry("D3A-C4", "Classifier Four", "Defensive") };
  assert.deepEqual(checkCatalog(catalog, release, null, "1.3.0").problems, []);
});

test("names compare without regard to case", () => {
  const catalog = { "D3-KBPI": entry("D3-KBPI", "Kernel-Based Process Isolation", "Harden") };
  assert.deepEqual(checkCatalog(catalog, release, null, "1.3.0").problems, []);
});

test("parseRelease assigns a tactic from the node and from its named ancestors", () => {
  assert.deepEqual([...release.tactics.get("D3-PH")], ["Harden"]);
  assert.deepEqual([...release.tactics.get("D3-BA")], ["Harden"], "inherited through subClassOf");
  assert.deepEqual([...release.tactics.get("D3-NTA")], ["Detect"]);
  assert.equal(release.tactics.get("D3A-VAR").size, 0);
  assert.deepEqual([...release.tacticLabels].sort(), ["Detect", "Harden"]);
});

test("isRenderingOf accepts an exact name and a parenthetical qualifier", () => {
  assert.equal(isRenderingOf("Platform Hardening", "Platform Hardening"), true);
  assert.equal(isRenderingOf("Platform Hardening (Firmware)", "Platform Hardening"), true);
});

test("isRenderingOf rejects a different name and a missing upstream name", () => {
  assert.equal(isRenderingOf("Linear Regression", "Logistic Regression"), false);
  assert.equal(isRenderingOf("Kernel-Based Process Isolation", "Kernel-based Process Isolation"), true);
  assert.equal(isRenderingOf("Linear Regression", ["Logistic Regression", "Linear Regression"]), true);
  assert.equal(isRenderingOf("Linear Regression", []), false);
  assert.equal(isRenderingOf("Anything", ""), false);
  assert.equal(isRenderingOf("Anything", undefined), false);
});

test("tacticProblems accepts an assigned tactic and ignores non-root tactics", () => {
  assert.deepEqual(tacticProblems("D3-PH", "Harden", release), []);
  assert.deepEqual(tacticProblems("D3-PH", "Defensive", release), []);
  assert.deepEqual(tacticProblems("D3-PH", "", release), []);
  assert.deepEqual(tacticProblems("D3A-VAR", "Harden", release), [], "no upstream tactic, nothing to compare");
});

test("tacticProblems reports a root tactic the release does not assign", () => {
  assert.deepEqual(tacticProblems("D3-NTA", "Harden", release),
    [{ id: "D3-NTA", ours: "Harden", theirs: ["Detect"] }]);
});

test("a clean catalog produces no problems", () => {
  const catalog = {
    _meta: {},
    "D3-PH": entry("D3-PH", "Platform Hardening", "Harden"),
    "D3A-VAR": entry("D3A-VAR", "Variability", "Defensive"),
  };
  const r = checkCatalog(catalog, release, null, "1.3.0");
  assert.deepEqual(r.problems, []);
  assert.equal(r.checked, 2);
});

test("the gate fails on an injected wrong name", () => {
  const catalog = { "D3-PH": entry("D3-PH", "Platform Fortification", "Harden") };
  const r = checkCatalog(catalog, release, null, "1.3.0");
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /D3-PH is named "Platform Fortification"; D3FEND 1\.3\.0 names it "Platform Hardening"/);
});

test("the gate fails on an injected absent id", () => {
  const catalog = { "D3-ZZZ": entry("D3-ZZZ", "Invented Technique", "Harden") };
  const r = checkCatalog(catalog, release, null, "1.3.0");
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /D3-ZZZ .* does not exist in D3FEND 1\.3\.0/);
});

test("the gate fails on an injected wrong tactic", () => {
  const catalog = { "D3-NTA": entry("D3-NTA", "Network Traffic Analysis", "Harden") };
  const r = checkCatalog(catalog, release, null, "1.3.0");
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /D3-NTA lists tactic "Harden"; D3FEND 1\.3\.0 assigns "Detect"/);
});

test("ids outside the D3 namespace and underscore keys are not checked", () => {
  const catalog = { _meta: {}, "T1059": entry("T1059", "Whatever", "Harden") };
  assert.equal(findDivergences(catalog, release).ids.length, 0);
});

test("a recorded divergence is allowed, once, for that name only", () => {
  const catalog = { "D3-PH": entry("D3-PH", "Platform Fortification", "Harden") };
  const baseline = { names: { "D3-PH": "Platform Fortification" }, missing_ids: [], tactics: {} };
  assert.deepEqual(checkCatalog(catalog, release, baseline, "1.3.0").problems, []);
  const renamed = { "D3-PH": entry("D3-PH", "Platform Strengthening", "Harden") };
  assert.equal(checkCatalog(renamed, release, baseline, "1.3.0").problems.length, 2,
    "a different wrong name fails, and the stale record is reported");
});

test("a recorded divergence that has been repaired is an error", () => {
  const catalog = {
    "D3-PH": entry("D3-PH", "Platform Hardening", "Harden"),
    "D3-NTA": entry("D3-NTA", "Network Traffic Analysis", "Detect"),
  };
  const baseline = {
    names: { "D3-PH": "Platform Fortification" },
    missing_ids: ["D3-NTA"],
    tactics: { "D3-NTA": ["Harden"] },
  };
  const problems = checkCatalog(catalog, release, baseline, "1.3.0").problems;
  assert.equal(problems.length, 3);
  assert.ok(problems.some((p) => /D3-PH is recorded as a name divergence/.test(p)));
  assert.ok(problems.some((p) => /D3-NTA is recorded as absent/.test(p)));
  assert.ok(problems.some((p) => /D3-NTA is recorded as listing tactic "Harden"/.test(p)));
});

test("the divergence baseline ships and names the pin it was taken against", () => {
  const p = path.resolve(__dirname, ".d3fend-divergence-baseline.json");
  assert.ok(fs.existsSync(p), "tests/.d3fend-divergence-baseline.json must ship (see the .gitignore negation)");
  const b = JSON.parse(fs.readFileSync(p, "utf8"));
  const catalog = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "data", "d3fend-catalog.json"), "utf8"));
  assert.equal(b.pinned_release, catalog._meta.d3fend_version);
  assert.ok(b.names && typeof b.names === "object");
  assert.ok(Array.isArray(b.missing_ids));
  assert.ok(b.tactics && typeof b.tactics === "object");
  for (const id of Object.keys(b.names)) {
    assert.equal(b.missing_ids.includes(id), false, `${id} is recorded as both misnamed and absent`);
  }
});
