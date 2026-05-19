"use strict";

/**
 * tests/canonical-eq.test.js
 *
 * Pins the canonical-form deep-equal contract used by the diff-coverage
 * gate. Replaces the JSON.stringify comparator that v0.13.17 and v0.13.19
 * had to patch with two layers of skip rules (_auto_imported, _iocs_stub)
 * because non-canonical JSON.stringify reported false changes on key-
 * order rearrangement.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { canonicalEqual, canonicalStringify } = require(path.join(__dirname, "..", "lib", "canonical-eq.js"));

test("canonicalEqual: primitives compare by strict equality", () => {
  assert.equal(canonicalEqual(1, 1), true);
  assert.equal(canonicalEqual("a", "a"), true);
  assert.equal(canonicalEqual(true, true), true);
  assert.equal(canonicalEqual(null, null), true);
  assert.equal(canonicalEqual(undefined, undefined), true);
  assert.equal(canonicalEqual(1, "1"), false);
  assert.equal(canonicalEqual(0, false), false);
  assert.equal(canonicalEqual(null, undefined), false);
});

test("canonicalEqual: NaN === NaN (deviates from Object.is for catalog totality)", () => {
  assert.equal(canonicalEqual(NaN, NaN), true);
});

test("canonicalEqual: arrays compare element-by-element IN ORDER", () => {
  // Order matters — IoC arrays use most-relevant-first convention; a
  // reordered array is a semantically-meaningful diff.
  assert.equal(canonicalEqual([1, 2, 3], [1, 2, 3]), true);
  assert.equal(canonicalEqual([1, 2, 3], [3, 2, 1]), false);
  assert.equal(canonicalEqual([], []), true);
  assert.equal(canonicalEqual([1], [1, 2]), false);
});

test("canonicalEqual: objects compare key-set + per-key recursively, IGNORING key order", () => {
  // This is the bug that motivated the v0.13.20 refactor. JSON.stringify
  // produces different strings for { a:1, b:2 } vs { b:2, a:1 }.
  // canonicalEqual must say they're identical.
  assert.equal(canonicalEqual({ a: 1, b: 2 }, { b: 2, a: 1 }), true);
  assert.equal(canonicalEqual({ a: 1 }, { a: 1, b: 2 }), false,
    "extra key on one side must be detected");
  assert.equal(canonicalEqual({ a: 1, b: 2 }, { a: 1, b: 3 }), false,
    "value mismatch must be detected");
});

test("canonicalEqual: nested structures (IoC blob shape) compare recursively", () => {
  const a = {
    payload_artifacts: ["x", "y"],
    behavioral: ["z"],
    version_exposure: ["v1"]
  };
  const b = {
    behavioral: ["z"],
    version_exposure: ["v1"],
    payload_artifacts: ["x", "y"]
  };
  assert.equal(canonicalEqual(a, b), true,
    "reordered top-level keys on a 3-array IoC blob must compare equal");
  const c = {
    payload_artifacts: ["x", "y"],
    behavioral: ["zz"],  // value differs
    version_exposure: ["v1"]
  };
  assert.equal(canonicalEqual(a, c), false,
    "deep value mismatch must surface");
});

test("canonicalEqual: cycle protection — self-referential structures don't recurse infinitely", () => {
  const a = { name: "x" };
  a.self = a;
  const b = { name: "x" };
  b.self = b;
  // Both are isomorphic self-cycles — comparator must terminate and
  // return true.
  assert.equal(canonicalEqual(a, b), true);
});

test("canonicalEqual: array-vs-object type mismatch returns false", () => {
  assert.equal(canonicalEqual([1, 2], { 0: 1, 1: 2, length: 2 }), false,
    "an array and an array-like object must compare unequal");
});

test("canonicalStringify: sorted-key recursive output is stable for hashing", () => {
  const a = { b: 2, a: 1, c: { z: 9, y: 8 } };
  const b = { a: 1, c: { y: 8, z: 9 }, b: 2 };
  assert.equal(canonicalStringify(a), canonicalStringify(b),
    "two semantically-identical objects must serialize to identical canonical strings");
  assert.equal(canonicalStringify(a), '{"a":1,"b":2,"c":{"y":8,"z":9}}');
});

test("canonicalStringify: arrays preserve order", () => {
  assert.equal(canonicalStringify([3, 1, 2]), "[3,1,2]");
});
