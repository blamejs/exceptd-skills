"use strict";

/**
 * Pins the SARIF results[].locations support: a submission's optional
 * `evidence_locations` map is threaded onto firing indicators and emitted as
 * SARIF physical locations, so secret/file findings carry a real location
 * instead of shipping location-less (which GitHub code-scanning drops).
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-sariflocs-"));

// A library-author observation-hit drives a clean 'hit' (the existing SARIF
// tests use this path). Supply evidence_locations in both accepted forms.
const SUB = JSON.stringify({
  observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } },
  evidence_locations: {
    "publish-workflow-uses-static-token": [
      ".github/workflows/release.yml",
      { uri: ".github/workflows/publish.yml", startLine: 12 },
    ],
  },
});

test("SARIF result for a firing indicator carries the submission's evidence_locations", () => {
  const r = cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: SUB });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0", `expected SARIF 2.1.0; got ${r.stdout.slice(0, 160)}`);
  const result = (sarif.runs?.[0]?.results || []).find(x => /publish-workflow-uses-static-token/.test(x.ruleId));
  assert.ok(result, "the fired indicator must have a SARIF result");
  assert.ok(Array.isArray(result.locations) && result.locations.length === 2,
    `expected 2 locations; got ${JSON.stringify(result.locations)}`);
  const uris = result.locations.map(l => l.physicalLocation?.artifactLocation?.uri);
  assert.ok(uris.includes(".github/workflows/release.yml"), "string-form location must become a uri");
  const withLine = result.locations.find(l => l.physicalLocation?.artifactLocation?.uri === ".github/workflows/publish.yml");
  assert.equal(withLine.physicalLocation.region.startLine, 12, "object-form startLine must become a SARIF region");
});

test("a firing indicator with no evidence_locations does not crash and yields a valid SARIF doc", () => {
  const sub = JSON.stringify({ observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } } });
  const r = cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: sub });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0");
  const result = (sarif.runs?.[0]?.results || []).find(x => /publish-workflow-uses-static-token/.test(x.ruleId));
  assert.ok(result, "result present");
  // locations may be absent or the coarse playbook-source fallback; either is
  // valid SARIF — just assert no crash and the result exists.
  if (result.locations !== undefined) assert.ok(Array.isArray(result.locations));
});
