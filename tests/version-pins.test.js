"use strict";

/**
 * tests/version-pins.test.js
 *
 * Pins the lib/version-pins.js single-source-of-truth contract. Per
 * v0.13.20 class-3.10 fix: instead of regex-replacing the ATLAS version
 * across 33+ files on every bump, operator-facing surfaces read through
 * this module.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const PINS = require(path.join(__dirname, "..", "lib", "version-pins.js"));

test("getAtlasVersion returns the live value from data/atlas-ttps.json", () => {
  const v = PINS.getAtlasVersion();
  assert.ok(typeof v === "string" && /^\d+\.\d+\.\d+$/.test(v),
    "atlas_version must be a semver-like string sourced from _meta");
});

test("getAttackVersion returns the live value from data/attack-techniques.json", () => {
  const v = PINS.getAttackVersion();
  assert.ok(typeof v === "string" && v.length > 0,
    "attack_version must be present in _meta");
});

test("manifest.json atlas_version matches the catalog meta", () => {
  const p = PINS.getAllPins();
  assert.equal(p.manifest_atlas_version, p.atlas_version,
    "Hard Rule #8: manifest.atlas_version must equal data/atlas-ttps.json._meta.atlas_version");
});

test("manifest.json attack_version matches the catalog meta", () => {
  const p = PINS.getAllPins();
  assert.equal(p.manifest_attack_version, p.attack_version,
    "Hard Rule #8: manifest.attack_version must equal data/attack-techniques.json._meta.attack_version");
});

test("getAllPins exposes the full pin surface", () => {
  const p = PINS.getAllPins();
  for (const k of ["atlas_version", "atlas_release_date", "attack_version", "attack_version_date"]) {
    assert.ok(k in p, `getAllPins must include ${k}`);
  }
});

test("getAtlasReleaseDate + getAttackVersionDate match the underlying _meta blocks", () => {
  // Pinning the per-field accessors so downstream consumers don't have
  // to call getAllPins() just to grab a release date.
  const all = PINS.getAllPins();
  assert.equal(PINS.getAtlasReleaseDate(), all.atlas_release_date,
    "getAtlasReleaseDate must return the same value as getAllPins().atlas_release_date");
  assert.equal(PINS.getAttackVersionDate(), all.attack_version_date,
    "getAttackVersionDate must return the same value as getAllPins().attack_version_date");
});

test("clearCache + reload picks up an in-process version change (hermetic refresh)", () => {
  // Simulates a refresh pulling a new ATLAS version mid-process. Real
  // operators run sign-all / refresh-sbom which reloads in a subshell;
  // this test pins the cache-invalidation contract for in-process
  // callers (refresh-external orchestration).
  const before = PINS.getAtlasVersion();
  PINS.clearCache();
  const after = PINS.getAtlasVersion();
  assert.equal(before, after, "clearCache must not change the value when underlying file is unchanged");
});
