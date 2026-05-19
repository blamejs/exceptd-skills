"use strict";

/**
 * tests/refresh-upstream-catalogs.test.js
 *
 * Pins the exported surface of scripts/refresh-upstream-catalogs.js so
 * the four upstream-catalog refreshers and their dispatcher remain
 * callable by per-type wrapper scripts + downstream tooling.
 *
 * Network-free — we assert the module exports the expected functions
 * + SOURCES registry. The refresh functions themselves hit live MITRE /
 * IETF endpoints, so end-to-end tests run in a separate `npm run
 * refresh-upstream-catalogs --dry-run` smoke check rather than the
 * default test suite.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const MOD = require(path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"));

test("refresh-upstream-catalogs exports the four refresher functions", () => {
  assert.equal(typeof MOD.refreshRfc, "function",
    "refreshRfc must be exported (consumed by scripts/refresh-rfc-index.js wrapper)");
  assert.equal(typeof MOD.refreshAttack, "function",
    "refreshAttack must be exported (consumed by scripts/refresh-mitre-attack.js wrapper)");
  assert.equal(typeof MOD.refreshAtlas, "function",
    "refreshAtlas must be exported (consumed by scripts/refresh-mitre-atlas.js wrapper)");
  assert.equal(typeof MOD.refreshD3fend, "function",
    "refreshD3fend must be exported (consumed by scripts/refresh-mitre-d3fend.js wrapper)");
});

test("refresh-upstream-catalogs exports SOURCES registry with all four keys", () => {
  assert.ok(MOD.SOURCES && typeof MOD.SOURCES === "object",
    "SOURCES registry must be exported");
  for (const key of ["rfc", "attack", "atlas", "d3fend"]) {
    assert.ok(MOD.SOURCES[key], `SOURCES.${key} must be present`);
    assert.equal(typeof MOD.SOURCES[key].run, "function",
      `SOURCES.${key}.run must be a function (CLI dispatcher target)`);
    assert.equal(typeof MOD.SOURCES[key].name, "string",
      `SOURCES.${key}.name must declare the canonical intake-method tag`);
  }
});

test("refresh-upstream-catalogs exports runCli for the CLI entrypoint", () => {
  assert.equal(typeof MOD.runCli, "function",
    "runCli must be exported so the per-type wrappers + the unified entrypoint share dispatch");
});

test("per-type wrapper scripts exist and import from refresh-upstream-catalogs", () => {
  const fs = require("fs");
  const wrappers = [
    "refresh-rfc-index.js",
    "refresh-mitre-attack.js",
    "refresh-mitre-atlas.js",
    "refresh-mitre-d3fend.js"
  ];
  for (const w of wrappers) {
    const p = path.join(__dirname, "..", "scripts", w);
    assert.ok(fs.existsSync(p), `${w} per-type wrapper must exist`);
    const body = fs.readFileSync(p, "utf8");
    assert.match(body, /refresh-upstream-catalogs/,
      `${w} must import from refresh-upstream-catalogs.js (single source of truth)`);
  }
});
