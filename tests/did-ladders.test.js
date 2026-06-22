"use strict";

/**
 * tests/did-ladders.test.js
 *
 * Behavioral coverage for scripts/builders/did-ladders.js (buildDidLadders) —
 * the builder that emits the canonical defense-in-depth ladders and validates
 * every layer's source_skill + D3FEND refs against the live catalogs (throwing
 * on an unknown ref).
 *
 * Strategy: drive the pure builder with synthetic { skills, d3fendCatalog }
 * inputs to exercise the happy path AND both throw paths (unknown skill,
 * unknown D3FEND id), then validate the shipped LADDERS against the real
 * manifest + d3fend-catalog so the curated content stays internally consistent.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { buildDidLadders } = require("../scripts/builders/did-ladders.js");

const ROOT = path.join(__dirname, "..");
const manifest = require(path.join(ROOT, "manifest.json"));
const d3Catalog = require(path.join(ROOT, "data", "d3fend-catalog.json"));

// Build the union of every skill + D3FEND id the shipped ladders reference so a
// synthetic "valid" input can satisfy the builder's referential check.
function realCatalogs() {
  const skills = manifest.skills.map((s) => ({ name: s.name }));
  return { skills, d3fendCatalog: d3Catalog };
}

test("module contract: exports buildDidLadders as a function", () => {
  assert.equal(typeof buildDidLadders, "function");
});

test("happy path: returns _meta + ladders with a matching ladder_count", () => {
  const out = buildDidLadders(realCatalogs());
  assert.equal(out._meta.schema_version, "1.0.0");
  assert.equal(typeof out._meta.note, "string");
  assert.ok(Array.isArray(out.ladders) && out.ladders.length > 0);
  assert.equal(out._meta.ladder_count, out.ladders.length);
});

test("every ladder has the required shape: id, attack_class, primary_ttps, non-empty layers", () => {
  const out = buildDidLadders(realCatalogs());
  const seenIds = new Set();
  for (const ladder of out.ladders) {
    assert.equal(typeof ladder.id, "string");
    assert.ok(ladder.id.length > 0);
    assert.equal(seenIds.has(ladder.id), false, `duplicate ladder id ${ladder.id}`);
    seenIds.add(ladder.id);
    assert.equal(typeof ladder.attack_class, "string");
    assert.ok(Array.isArray(ladder.primary_ttps) && ladder.primary_ttps.length > 0);
    assert.ok(Array.isArray(ladder.layers) && ladder.layers.length > 0);
    for (const layer of ladder.layers) {
      assert.equal(typeof layer.layer, "string");
      assert.equal(typeof layer.control, "string");
      assert.equal(typeof layer.source_skill, "string");
      assert.ok(Array.isArray(layer.d3fend));
    }
  }
});

test("referential integrity: every source_skill + D3FEND ref resolves against the live catalogs", () => {
  const out = buildDidLadders(realCatalogs());
  const skillNames = new Set(manifest.skills.map((s) => s.name));
  const d3Ids = new Set(Object.keys(d3Catalog).filter((k) => !k.startsWith("_")));
  for (const ladder of out.ladders) {
    for (const layer of ladder.layers) {
      assert.ok(skillNames.has(layer.source_skill), `ladder ${ladder.id}: unknown skill ${layer.source_skill}`);
      for (const ref of layer.d3fend) {
        assert.ok(d3Ids.has(ref), `ladder ${ladder.id}: unknown D3FEND ref ${ref}`);
      }
    }
  }
});

test("negative path: an unknown source_skill makes the builder throw and names the offending skill", () => {
  // Drop one skill from the allowed set so a layer that references it fails.
  const { skills } = realCatalogs();
  const out = buildDidLadders(realCatalogs());
  const aReferencedSkill = out.ladders[0].layers[0].source_skill;
  const trimmed = skills.filter((s) => s.name !== aReferencedSkill);
  assert.throws(
    () => buildDidLadders({ skills: trimmed, d3fendCatalog: d3Catalog }),
    (err) => {
      assert.match(err.message, /did-ladders\.js/);
      assert.match(err.message, /unknown source_skill/);
      assert.ok(err.message.includes(aReferencedSkill), `error should name ${aReferencedSkill}`);
      return true;
    }
  );
});

test("negative path: an unknown D3FEND ref makes the builder throw", () => {
  const { skills } = realCatalogs();
  // An empty d3fend catalog makes every D3FEND ref in the curated ladders unknown.
  assert.throws(
    () => buildDidLadders({ skills, d3fendCatalog: { _meta: {} } }),
    (err) => {
      assert.match(err.message, /unknown D3FEND ref/);
      return true;
    }
  );
});

test("the prompt-injection ladder exists and chains perimeter through detection", () => {
  const out = buildDidLadders(realCatalogs());
  const pi = out.ladders.find((l) => l.id === "prompt-injection");
  assert.ok(pi, "prompt-injection ladder must be present");
  const layerNames = pi.layers.map((l) => l.layer.toLowerCase());
  assert.ok(layerNames.some((n) => n.includes("perimeter") || n.includes("input")));
  assert.ok(layerNames.some((n) => n.includes("detection")));
});

test("builder is read-only: it does not mutate the d3fendCatalog input", () => {
  const cat = { _meta: { v: 1 }, "D3-CA": {}, "D3-X": {} };
  const before = JSON.stringify(cat);
  // It will throw (most refs unknown), but must not have mutated the input.
  try {
    buildDidLadders({ skills: realCatalogs().skills, d3fendCatalog: cat });
  } catch (_) {
    /* expected */
  }
  assert.equal(JSON.stringify(cat), before, "input d3fendCatalog must not be mutated");
});
