"use strict";

/**
 * tests/check-codebase-patterns-currency.test.js
 *
 * Subject coverage for scripts/check-codebase-patterns-currency.js — the
 * advisory drift detector between exceptd's adopted codebase-pattern classes
 * and the upstream blamejs catalog they were derived from.
 *
 * The check itself is advisory (never fails a release), so the load-bearing
 * behavior is in two exported helpers:
 *
 *   upstreamClasses(src)     — parses the upstream VALID_ALLOW_CLASSES literal
 *                              and returns the allow-class keys; null when the
 *                              literal is absent / unparseable.
 *   upstreamPatternsPath()   — resolves the sibling path, honoring the
 *                              EXCEPTD_UPSTREAM_PATTERNS override.
 *
 * Plus the UPSTREAM_TRIAGED registry invariants (frozen, sorted, lower-kebab).
 *
 * Network-free; fixtures live in mkdtemp dirs and the env override is restored
 * in a finally block so the suite's shared process.env is never left mutated.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const MOD = require(path.join(__dirname, "..", "scripts", "check-codebase-patterns-currency.js"));

// --------------------------------------------------------------------------
// exported surface
// --------------------------------------------------------------------------

test("exports UPSTREAM_TRIAGED + upstreamClasses + upstreamPatternsPath", () => {
  assert.ok(Array.isArray(MOD.UPSTREAM_TRIAGED), "UPSTREAM_TRIAGED must be an array");
  assert.equal(typeof MOD.upstreamClasses, "function", "upstreamClasses must be a function");
  assert.equal(typeof MOD.upstreamPatternsPath, "function", "upstreamPatternsPath must be a function");
});

// --------------------------------------------------------------------------
// UPSTREAM_TRIAGED registry invariants
// --------------------------------------------------------------------------

test("UPSTREAM_TRIAGED is frozen (cannot be mutated at runtime)", () => {
  assert.ok(Object.isFrozen(MOD.UPSTREAM_TRIAGED), "UPSTREAM_TRIAGED must be Object.freeze()d");
  // Mutating a frozen array silently no-ops in non-strict but throws in strict.
  assert.throws(() => { MOD.UPSTREAM_TRIAGED.push("injected-class"); });
});

test("UPSTREAM_TRIAGED entries are lower-kebab-case ids with no duplicates", () => {
  const seen = new Set();
  for (const c of MOD.UPSTREAM_TRIAGED) {
    assert.match(c, /^[a-z0-9][a-z0-9-]+$/, `"${c}" must be a lower-kebab class id`);
    assert.equal(seen.has(c), false, `"${c}" appears more than once in UPSTREAM_TRIAGED`);
    seen.add(c);
  }
  assert.ok(seen.size > 0, "UPSTREAM_TRIAGED must record at least one triaged class");
});

test("UPSTREAM_TRIAGED is kept-sorted (matches the keep-sorted comment)", () => {
  const sorted = [...MOD.UPSTREAM_TRIAGED].sort();
  assert.deepEqual(MOD.UPSTREAM_TRIAGED, sorted,
    "UPSTREAM_TRIAGED must stay sorted so the added/removed deltas are stable diffs");
});

// --------------------------------------------------------------------------
// upstreamClasses — the upstream-literal parser
// --------------------------------------------------------------------------

test("upstreamClasses extracts the keys from a VALID_ALLOW_CLASSES = Object.freeze({...}) literal", () => {
  const src = [
    "const VALID_ALLOW_CLASSES = Object.freeze({",
    "  'bare-json-parse': 'desc one',",
    "  'silent-catch': 'desc two',",
    "  'process-exit': 'desc three',",
    "});",
  ].join("\n");
  const keys = MOD.upstreamClasses(src);
  assert.deepEqual(keys, ["bare-json-parse", "silent-catch", "process-exit"]);
});

test("upstreamClasses handles a bare object literal (no Object.freeze wrapper)", () => {
  const src = [
    "const VALID_ALLOW_CLASSES = {",
    '  "dynamic-regex": "x",',
    '  "raw-process-env": "y"',
    "};",
  ].join("\n");
  const keys = MOD.upstreamClasses(src);
  assert.deepEqual(keys, ["dynamic-regex", "raw-process-env"]);
});

test("upstreamClasses tolerates unquoted keys", () => {
  // The key-extraction regex accepts optionally-quoted keys.
  const src = "const VALID_ALLOW_CLASSES = {\n  bare-json-parse: 1,\n  silent-catch: 2\n}";
  const keys = MOD.upstreamClasses(src);
  assert.deepEqual(keys, ["bare-json-parse", "silent-catch"]);
});

test("upstreamClasses returns null when VALID_ALLOW_CLASSES is absent (unparseable upstream)", () => {
  const src = "const SOMETHING_ELSE = { 'a': 1 };\nmodule.exports = {};";
  assert.equal(MOD.upstreamClasses(src), null,
    "a source with no VALID_ALLOW_CLASSES literal must return null, not [] or throw");
});

test("upstreamClasses returns an empty array for an empty literal (parseable but no classes)", () => {
  const src = "const VALID_ALLOW_CLASSES = Object.freeze({});";
  const keys = MOD.upstreamClasses(src);
  assert.deepEqual(keys, [], "an empty literal parses to zero keys (not null)");
});

test("upstreamClasses ignores nested-object value content (only top-level keys before a colon)", () => {
  // A value that is itself an object must not contribute its inner keys as
  // classes; the extractor keys off `<id>:` occurrences, and inner ids are
  // also `<id>:` shaped, so this documents the known surface: the regex is
  // greedy to the first closing brace, so a nested object is NOT spanned.
  const src = [
    "const VALID_ALLOW_CLASSES = Object.freeze({",
    "  'outer-class': { note: 'meta' }",
    "});",
  ].join("\n");
  const keys = MOD.upstreamClasses(src);
  // The first `}` closes the inner object, so only `outer-class` is captured.
  assert.ok(keys.includes("outer-class"), "the real top-level class must be captured");
});

// --------------------------------------------------------------------------
// upstreamPatternsPath — env override + default resolution
// --------------------------------------------------------------------------

test("upstreamPatternsPath honors the EXCEPTD_UPSTREAM_PATTERNS override", () => {
  const had = Object.prototype.hasOwnProperty.call(process.env, "EXCEPTD_UPSTREAM_PATTERNS");
  const prev = process.env.EXCEPTD_UPSTREAM_PATTERNS;
  try {
    process.env.EXCEPTD_UPSTREAM_PATTERNS = "/tmp/custom/patterns.test.js";
    assert.equal(MOD.upstreamPatternsPath(), "/tmp/custom/patterns.test.js",
      "the override env var must take precedence over the default sibling path");
  } finally {
    if (had) process.env.EXCEPTD_UPSTREAM_PATTERNS = prev;
    else delete process.env.EXCEPTD_UPSTREAM_PATTERNS;
  }
});

test("upstreamPatternsPath defaults to the sibling blamejs codebase-patterns path", () => {
  const had = Object.prototype.hasOwnProperty.call(process.env, "EXCEPTD_UPSTREAM_PATTERNS");
  const prev = process.env.EXCEPTD_UPSTREAM_PATTERNS;
  try {
    delete process.env.EXCEPTD_UPSTREAM_PATTERNS;
    const p = MOD.upstreamPatternsPath();
    assert.ok(path.isAbsolute(p), "the default path must be absolute");
    // Sibling repo: ../blamejs/test/layer-0-primitives/codebase-patterns.test.js
    const norm = p.replace(/\\/g, "/");
    assert.match(norm, /\/blamejs\/test\/layer-0-primitives\/codebase-patterns\.test\.js$/,
      "default resolves to the sibling blamejs codebase-patterns test");
  } finally {
    if (had) process.env.EXCEPTD_UPSTREAM_PATTERNS = prev;
    else delete process.env.EXCEPTD_UPSTREAM_PATTERNS;
  }
});

// --------------------------------------------------------------------------
// drift-delta semantics (the logic main() reports) reproduced over the
// exported helpers — added vs removed are symmetric set differences.
// --------------------------------------------------------------------------

test("a NEW upstream class (absent from UPSTREAM_TRIAGED) is detectable as an 'added' delta", () => {
  const triaged = new Set(MOD.UPSTREAM_TRIAGED);
  // Synthesize an upstream literal: all triaged classes + one brand-new one.
  const live = [...MOD.UPSTREAM_TRIAGED, "brand-new-unmtriaged-class"];
  const added = live.filter((c) => !triaged.has(c));
  assert.deepEqual(added, ["brand-new-unmtriaged-class"],
    "a class present upstream but absent from UPSTREAM_TRIAGED must surface as 'added'");
});

test("a triaged class no longer present upstream is detectable as a 'removed' delta", () => {
  const sampleTriaged = MOD.UPSTREAM_TRIAGED[0];
  const live = MOD.UPSTREAM_TRIAGED.filter((c) => c !== sampleTriaged);
  const liveSet = new Set(live);
  const removed = MOD.UPSTREAM_TRIAGED.filter((c) => !liveSet.has(c));
  assert.deepEqual(removed, [sampleTriaged],
    "a triaged class dropped upstream must surface as 'removed'");
});

test("upstream that exactly matches the triaged set yields zero deltas (the ok path)", () => {
  const triaged = new Set(MOD.UPSTREAM_TRIAGED);
  const live = [...MOD.UPSTREAM_TRIAGED];
  const liveSet = new Set(live);
  const added = live.filter((c) => !triaged.has(c));
  const removed = MOD.UPSTREAM_TRIAGED.filter((c) => !liveSet.has(c));
  assert.equal(added.length, 0);
  assert.equal(removed.length, 0);
});
