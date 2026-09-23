"use strict";

require("node:test").describe("ism-control-references", () => {
/**
 * Regression for the ISM control reference gate
 * (scripts/check-ism-control-references.js).
 *
 * The gate compares every ISM-NNNN citation in the repository, and every
 * AU-ISM-NNNN registry key, with the ISM release pinned in sources/index.json.
 * The pieces pinned here are the ones that carry judgment: reading controls out
 * of ASD's OSCAL catalog, finding citations in text, and deciding whether a
 * registry entry describes the control its key names.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { parseControls, findTokens, registryProblems } =
  require(path.resolve(__dirname, "..", "scripts", "check-ism-control-references.js"));

const SAMPLE = JSON.stringify({
  catalog: {
    metadata: { version: "2026.09.4" },
    groups: [{
      title: "Guidelines for system access",
      groups: [{
        title: "Authentication",
        controls: [
          { id: "ism-1546", parts: [{ name: "statement", prose: "Users are authenticated before they are granted access to a system and its resources." }] },
          { id: "ism-1685", parts: [{ name: "statement", prose: "Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed." }] },
        ],
      }],
    }, {
      title: "Guidelines for system management",
      controls: [
        { id: "ism-1877", parts: [{ name: "guidance", prose: "not the statement" }, { name: "statement", prose: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist." }] },
        { id: "ism-principle-gov-01", parts: [{ name: "statement", prose: "A principle, not a control." }] },
      ],
    }],
  },
});

test("parseControls reads every numbered control from nested groups", () => {
  const c = parseControls(SAMPLE);
  assert.equal(c.size, 3, "three numbered controls, and the principle is not one");
  assert.ok(c.has("ISM-1546") && c.has("ISM-1685") && c.has("ISM-1877"));
});

test("parseControls takes the statement part, not guidance", () => {
  assert.match(parseControls(SAMPLE).get("ISM-1877"), /^Patches, updates or other vendor mitigations/);
});

test("findTokens reports each citation with its line", () => {
  const t = findTokens("first line\nsee ISM-1546 and ISM-1877\nnone here\nAU-ISM-1685-IdP");
  assert.deepEqual(t, [
    { id: "ISM-1546", line: 2 },
    { id: "ISM-1877", line: 2 },
    { id: "ISM-1685", line: 4 },
  ]);
});

test("findTokens ignores a number that is not four digits", () => {
  assert.deepEqual(findTokens("ISM-123 and ISM-12345"), []);
});

test("findTokens ignores ISM- inside another word but reads it after a hyphen", () => {
  assert.deepEqual(findTokens("PRISM-1234 and AU-ISM-1546 and ASD-ISM-1623"), [
    { id: "ISM-1546", line: 1 },
    { id: "ISM-1623", line: 1 },
  ]);
});

test("registryProblems accepts an entry that names and quotes its control", () => {
  const c = parseControls(SAMPLE);
  assert.deepEqual(registryProblems("AU-ISM-1546", {
    control_id: "ISM-1546",
    control_name: "Users are authenticated before they are granted access to a system and its resources",
  }, c), []);
});

test("registryProblems accepts a scope suffix after the verbatim statement", () => {
  const c = parseControls(SAMPLE);
  assert.deepEqual(registryProblems("AU-ISM-1685-IdP", {
    control_id: "ISM-1685",
    control_name: "Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed (identity provider tenant)",
  }, c), []);
});

test("registryProblems rejects an entry that describes a different control", () => {
  // The failure this gate exists for: the key names ISM-1546 and the entry
  // describes patching.
  const c = parseControls(SAMPLE);
  const p = registryProblems("AU-ISM-1546", { control_id: "ISM-1546", control_name: "Patch operating systems and applications" }, c);
  assert.equal(p.length, 1);
  assert.match(p[0], /does not begin with the statement of ISM-1546/);
});

test("registryProblems rejects a paraphrase of the statement", () => {
  const c = parseControls(SAMPLE);
  const p = registryProblems("AU-ISM-1685-IdP", {
    control_id: "ISM-1685",
    control_name: "Credentials for break glass, local administrator and service accounts are managed",
  }, c);
  assert.equal(p.length, 1);
});

test("registryProblems rejects a control_id that disagrees with the key", () => {
  const c = parseControls(SAMPLE);
  const p = registryProblems("AU-ISM-1546", {
    control_id: "ISM-1877",
    control_name: "Users are authenticated before they are granted access to a system and its resources",
  }, c);
  assert.ok(p.some((x) => /control_id is "ISM-1877", expected ISM-1546/.test(x)));
});

test("registryProblems rejects a key naming a control the release does not have", () => {
  const c = parseControls(SAMPLE);
  const p = registryProblems("AU-ISM-9999", { control_id: "ISM-9999", control_name: "anything" }, c);
  assert.deepEqual(p, ["AU-ISM-9999: ISM-9999 does not exist in the pinned release"]);
});

test("registryProblems leaves keys that do not name an ISM control alone", () => {
  const c = parseControls(SAMPLE);
  assert.deepEqual(registryProblems("AU-Essential-8-Patch", { control_id: "Patch applications", control_name: "x" }, c), []);
});

test("the pin is set and has the release tag shape", () => {
  const s = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "sources", "index.json"), "utf8"));
  const ism = (s.sources || s).au_frameworks.ism;
  assert.match(ism.oscal_release, /^v[0-9]{4}\.[0-9]{2}\.[0-9]+$/);
});

test("every AU-ISM registry key is written AU-ISM-NNNN with an optional scope", () => {
  const g = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "data", "framework-control-gaps.json"), "utf8"));
  for (const k of Object.keys(g).filter((x) => x.startsWith("AU-ISM"))) {
    assert.match(k, /^AU-ISM-[0-9]{4}(?:-[A-Za-z0-9-]+)?$/, `${k} must name a four-digit ISM control`);
  }
});
});
