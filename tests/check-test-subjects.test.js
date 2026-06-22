"use strict";

/**
 * tests/check-test-subjects.test.js
 *
 * Subject coverage for scripts/check-test-subjects.js — the bidirectional
 * test<->subject gate. The two exported functions are read-only against the
 * live repo:
 *
 *   deriveSubjects() -> Map<name, kind>  — every valid test SUBJECT derived
 *     dynamically from source modules, exported fn names, data catalogs,
 *     CVE/playbook primitives, workflows, CLI verbs, and repo artifacts.
 *   run() -> { subjects, forward[], reverse[] } — forward (a test with no
 *     subject) and reverse (a subject with no test) violations.
 *
 * These assert the derivation CONTRACT against the real repo (known canonical
 * subjects must be present, kinds are well-formed) and the run() shape +
 * suggestion logic — not a brittle exact count. Network-free; no repo mutation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const MOD = require(path.join(__dirname, "..", "scripts", "check-test-subjects.js"));

// --------------------------------------------------------------------------
// exported surface
// --------------------------------------------------------------------------

test("exports deriveSubjects + run", () => {
  assert.equal(typeof MOD.deriveSubjects, "function");
  assert.equal(typeof MOD.run, "function");
});

// --------------------------------------------------------------------------
// deriveSubjects — derived from the real repo tree
// --------------------------------------------------------------------------

test("deriveSubjects returns a non-empty Map of name -> kind", () => {
  const subjects = MOD.deriveSubjects();
  assert.ok(subjects instanceof Map, "deriveSubjects must return a Map");
  assert.ok(subjects.size > 50, `expected many subjects, got ${subjects.size}`);
  for (const [name, kind] of subjects) {
    assert.equal(typeof name, "string");
    assert.ok(name.length > 0, "subject names are non-empty");
    assert.equal(name, name.toLowerCase(), `subject "${name}" must be lowercased (the add() invariant)`);
    assert.equal(typeof kind, "string");
    assert.ok(kind.length > 0, `kind for "${name}" must be non-empty`);
  }
});

test("deriveSubjects includes the canonical engine + CLI + orchestrator subjects", () => {
  const subjects = MOD.deriveSubjects();
  // These are durable subjects that must always be derivable.
  for (const name of ["scoring", "playbook-runner", "cli", "orchestrator"]) {
    assert.ok(subjects.has(name), `"${name}" must be a derived subject`);
  }
  // scoring is a real lib module; its kind must point at lib/scoring.js.
  assert.equal(subjects.get("scoring"), "module:lib/scoring.js");
  // orchestrator is explicitly aliased to its index entry point.
  assert.match(subjects.get("orchestrator"), /orchestrator/, "orchestrator subject points at the orchestrator dir");
});

test("deriveSubjects records a data-catalog file subject (rfc-references)", () => {
  const subjects = MOD.deriveSubjects();
  // rfc-references.json -> subject "rfc-references" with kind "data" (this
  // basename is not also a module/fn name, so first-wins keeps it "data").
  assert.ok(subjects.has("rfc-references"), "rfc-references.json must be a data subject");
  assert.equal(subjects.get("rfc-references"), "data");
  // cve-catalog.json is always derivable as a subject too (its kind may be
  // claimed by an exported fn first; membership is the contract here).
  assert.ok(subjects.has("cve-catalog"), "cve-catalog must be a derivable subject");
});

test("deriveSubjects records playbook primitives + their playbook- alias", () => {
  const subjects = MOD.deriveSubjects();
  // A playbook id whose basename is NOT also a module/fn name keeps the
  // playbook-primitive kind under the first-wins add() rule.
  assert.ok(subjects.has("ai-discovered-cve-triage"), "the ai-discovered-cve-triage playbook must be a derived primitive subject");
  assert.equal(subjects.get("ai-discovered-cve-triage"), "playbook-primitive");
  // The playbook-<id> alias is always derived (and is alias-kinded).
  assert.ok(subjects.has("playbook-sbom"), "the playbook-<id> alias must also be derived");
  assert.equal(subjects.get("playbook-sbom"), "alias:playbook");
});

test("deriveSubjects records CVE-id primitives from data/cve-catalog.json (one CVE == one subject)", () => {
  const subjects = MOD.deriveSubjects();
  const cvePrimitives = [...subjects].filter(([, kind]) => kind === "cve-primitive");
  assert.ok(cvePrimitives.length > 100,
    `expected many cve-primitive subjects, got ${cvePrimitives.length}`);
  // Every CVE-primitive subject id is lowercased and CVE/MAL/GHSA-shaped.
  for (const [name] of cvePrimitives.slice(0, 25)) {
    assert.match(name, /^(cve|mal|ghsa)-/, `"${name}" should be a lowercased CVE/MAL/GHSA id`);
  }
});

test("deriveSubjects records workflow subjects + the -workflow alias", () => {
  const subjects = MOD.deriveSubjects();
  // release.yml -> "release" + "release-workflow".
  assert.ok(subjects.has("release"), "release workflow base subject");
  assert.ok(subjects.has("release-workflow"), "release-workflow alias subject");
  assert.equal(subjects.get("release-workflow"), "workflow");
});

test("deriveSubjects records repo-artifact subjects (README, AGENTS, package, governance)", () => {
  const subjects = MOD.deriveSubjects();
  assert.ok(subjects.has("readme"), "README.md -> readme repo subject");
  assert.ok(subjects.has("package"), "package.json -> package repo subject");
  assert.ok(subjects.has("agents-md"), "AGENTS.md -> agents-md repo subject");
  assert.ok(subjects.has("governance"), "governance repo subject present");
  assert.match(subjects.get("readme"), /^repo:/, "repo-artifact kind is prefixed repo:");
});

test("deriveSubjects kinds use the documented kind prefixes only", () => {
  const subjects = MOD.deriveSubjects();
  const allowedExact = new Set([
    "data", "cve-primitive", "playbook-primitive", "cli-verb", "workflow",
  ]);
  const allowedPrefix = ["module:", "fn:", "alias:", "vendor:", "repo:", "aggregate:"];
  for (const [name, kind] of subjects) {
    const ok = allowedExact.has(kind) || allowedPrefix.some((p) => kind.startsWith(p));
    assert.ok(ok, `subject "${name}" has an unexpected kind "${kind}"`);
  }
});

test("deriveSubjects derives an exported-function subject (kebab-cased) — e.g. derive-subjects itself", () => {
  const subjects = MOD.deriveSubjects();
  // check-test-subjects.js exports deriveSubjects + run; those become fn subjects.
  assert.ok(subjects.has("derive-subjects"), "the exported deriveSubjects fn must kebab to derive-subjects");
  assert.equal(subjects.get("derive-subjects"), "fn:scripts/check-test-subjects.js");
});

// --------------------------------------------------------------------------
// run() — forward/reverse violation shape
// --------------------------------------------------------------------------

test("run() returns { subjects:number, forward:[], reverse:[] } with well-formed entries", () => {
  const r = MOD.run();
  assert.equal(typeof r.subjects, "number");
  assert.ok(r.subjects > 0);
  assert.ok(Array.isArray(r.forward), "forward must be an array");
  assert.ok(Array.isArray(r.reverse), "reverse must be an array");
  for (const f of r.forward) {
    assert.match(f.file, /^tests\/.*\.test\.js$/, "forward entries name a tests/*.test.js file");
    assert.ok("suggested" in f, "forward entries carry a 'suggested' field (string or null)");
  }
  for (const rv of r.reverse) {
    assert.equal(typeof rv.subject, "string");
    assert.equal(typeof rv.kind, "string");
  }
});

test("run() count equals deriveSubjects().size (the same subject map drives both)", () => {
  const r = MOD.run();
  const subjects = MOD.deriveSubjects();
  assert.equal(r.subjects, subjects.size,
    "run().subjects must equal the derived subject-map size");
});

test("run() does NOT list a forward violation for a test whose name is a real subject", () => {
  const r = MOD.run();
  const subjects = MOD.deriveSubjects();
  // Every forward violation must genuinely lack a matching subject — assert the
  // gate isn't flagging a test that DOES map (a false positive would be a bug).
  for (const f of r.forward) {
    const base = f.file.replace(/^tests\//, "").replace(/\.test\.js$/, "").toLowerCase();
    assert.equal(subjects.has(base), false,
      `forward violation ${f.file} should not correspond to an existing subject "${base}"`);
  }
});

test("run() reverse entries are genuinely subjects with no matching test file", () => {
  const r = MOD.run();
  const subjects = MOD.deriveSubjects();
  for (const rv of r.reverse) {
    assert.ok(subjects.has(rv.subject),
      `reverse subject "${rv.subject}" must be a real derived subject`);
  }
});

test("this very test file maps to a derived subject (no forward violation for check-test-subjects)", () => {
  // This file is tests/check-test-subjects.test.js; its base name must be a
  // valid subject (the module scripts/check-test-subjects.js basename).
  const subjects = MOD.deriveSubjects();
  assert.ok(subjects.has("check-test-subjects"),
    "check-test-subjects must be a derived subject (module basename) so this test is not a forward violation");
});

require("node:test").describe("check-test-subjects detector fixes (round-2 hunt)", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const m = require("../scripts/check-test-subjects.js");
  test("F12: module.exports is brace-balanced — an export after a nested object literal is captured, not truncated", () => {
    // lib/cross-ref-api.js exports getLoadErrors AFTER a nested {...} inside its
    // module.exports; the old non-greedy /\{([\s\S]*?)\}/ stopped at the nested
    // brace and dropped it, so the export had no derived subject.
    assert.ok(m.deriveSubjects().has("get-load-errors"), "getLoadErrors (post-nested-brace export) must be a derived subject");
  });
  test("F11: deriveSubjects loads the CVE catalog — an absent/empty catalog throws rather than silently deriving zero", () => {
    let cve = 0; for (const k of m.deriveSubjects().values()) if (k === "cve-primitive") cve++;
    assert.ok(cve >= 400, `expected the shipped catalog's CVE-primitive subjects, got ${cve}`);
  });
  test("F10: run() exposes reverseRequired (module/cve/playbook only); both gate modes gate on it", () => {
    const r = m.run();
    assert.ok(Array.isArray(r.reverseRequired));
    assert.ok(r.reverseRequired.every((x) => /^(module:|cve-primitive|playbook-primitive)/.test(x.kind)), "reverseRequired holds only reverse-required kinds");
    assert.ok(r.reverse.length >= r.reverseRequired.length, "reverseRequired is a subset of reverse");
    const nonReq = r.reverse.find((x) => /^(alias:|data|cli|vendor:|repo:|aggregate:|fn:|workflow)/.test(x.kind));
    if (nonReq) assert.ok(!r.reverseRequired.includes(nonReq), "a non-required reverse entry is excluded from reverseRequired");
  });
});
