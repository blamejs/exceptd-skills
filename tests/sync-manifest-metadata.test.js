"use strict";

/**
 * tests/sync-manifest-metadata.test.js
 *
 * scripts/sync-manifest-metadata.js keeps manifest.json's per-skill cache in
 * step with each skill's frontmatter (the single source of truth the linter +
 * staleness gate read). It runs sync() at module load and exports nothing, and
 * its only side effect is rewriting the repo's manifest.json when the cache has
 * drifted. So it is tested three ways, none of which mutates a tracked file:
 *
 *   1. The actual script, run as a read-only subprocess against the clean repo.
 *      The repo cache is in sync, so sync() is a genuine no-op — it must report
 *      "0 field(s) synced" and exit 0 without rewriting manifest.json. This
 *      exercises the real load → sync() → exit path end-to-end.
 *   2. The load-bearing source contract: the field partition the script keeps
 *      distinct — MIRROR (scalar, exact), MIRRORED_ARRAY (exact), and COVER
 *      (union, enrichment-preserving). A regression that moved a cross-ref
 *      array out of the COVER set would silently start dropping curated refs.
 *   3. The documented MIRROR-vs-COVER algorithm, re-implemented against a
 *      synthetic manifest + frontmatter built with the SAME lint helpers the
 *      script uses (extractFrontmatterBlock + parseFrontmatter). This proves
 *      the two sync disciplines: MIRROR replaces; COVER unions and NEVER drops
 *      the manifest's own curated extras.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "sync-manifest-metadata.js");
const MANIFEST = path.join(ROOT, "manifest.json");
const lint = require(path.join(ROOT, "lib", "lint-skills.js"));

// The field partition the script declares. Kept in sync with the script's
// header: these are the three sync disciplines that must remain distinct.
const MIRRORED_SCALAR = ["last_threat_review"];
const MIRRORED_ARRAY = ["forward_watch"];
const MIRRORED_COVER = ["data_deps", "framework_gaps", "atlas_refs", "attack_refs", "rfc_refs", "cwe_refs", "d3fend_refs"];

// ---------------------------------------------------------------------------
// 1. Real script, read-only subprocess against the clean repo: a no-op.
// ---------------------------------------------------------------------------

test("the real sync script is a no-op on the in-sync repo (reports 0 synced, exits 0)", () => {
  const before = fs.readFileSync(MANIFEST, "utf8");
  // execFileSync throws on a non-zero exit; a clean in-sync repo must exit 0.
  const out = execFileSync(process.execPath, [SCRIPT], { encoding: "utf8" });
  assert.match(out, /\[sync-manifest-metadata\] 0 field\(s\) synced from frontmatter/,
    "an in-sync repo must report exactly 0 fields synced (the manifest cache already mirrors frontmatter)");
  const after = fs.readFileSync(MANIFEST, "utf8");
  assert.equal(after, before,
    "a no-op sync must leave manifest.json byte-identical (it only writes when changed > 0)");
});

// ---------------------------------------------------------------------------
// 2. Source contract: the field partition stays distinct.
// ---------------------------------------------------------------------------

test("the script declares the three sync disciplines as distinct field sets", () => {
  const src = fs.readFileSync(SCRIPT, "utf8");
  assert.match(src, /const MIRRORED_SCALAR = \[\s*"last_threat_review"\s*\]/,
    "last_threat_review must be a MIRROR (scalar, exact-copy) field");
  assert.match(src, /const MIRRORED_ARRAY = \[\s*"forward_watch"\s*\]/,
    "forward_watch must be a MIRRORED_ARRAY (exact-copy) field");
  // Every cross-reference array must be in the COVER (union) set — moving one
  // out (e.g. into MIRRORED_ARRAY, which replaces) would drop curated refs.
  const coverLine = src.match(/const MIRRORED_COVER = \[([^\]]*)\]/);
  assert.ok(coverLine, "MIRRORED_COVER set must be declared");
  for (const key of MIRRORED_COVER) {
    assert.ok(coverLine[1].includes(`"${key}"`),
      `${key} must be a COVER (union) field so curated enrichment is preserved`);
  }
  // The sets must be disjoint — a field synced two ways is a contradiction.
  const all = [...MIRRORED_SCALAR, ...MIRRORED_ARRAY, ...MIRRORED_COVER];
  assert.equal(new Set(all).size, all.length, "the three field sets must be disjoint");
});

// ---------------------------------------------------------------------------
// 3. MIRROR-vs-COVER algorithm, behaviorally, against a synthetic fixture
//    built with the same lint helpers the script uses.
// ---------------------------------------------------------------------------

// Re-implementation of the script's sync loop, threading frontmatter parsed by
// the SAME lint helpers the script imports. Mutates `manifest` in place and
// returns the changed count, exactly like the script's sync().
function syncManifest(manifest, frontmatterById) {
  let changed = 0;
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    const fm = frontmatterById[id];
    if (!fm) throw new Error(`${id}: skill.md not found`);
    for (const key of MIRRORED_SCALAR) {
      if (key in fm && entry[key] !== fm[key]) { entry[key] = fm[key]; changed++; }
    }
    for (const key of MIRRORED_ARRAY) {
      const want = Array.isArray(fm[key]) ? fm[key] : [];
      const have = Array.isArray(entry[key]) ? entry[key] : [];
      if (JSON.stringify(have) !== JSON.stringify(want)) { entry[key] = want; changed++; }
    }
    for (const key of MIRRORED_COVER) {
      const want = Array.isArray(fm[key]) ? fm[key] : [];
      if (!want.length) continue;
      const have = Array.isArray(entry[key]) ? entry[key] : [];
      const haveSet = new Set(have);
      const missing = want.filter((x) => !haveSet.has(x));
      if (missing.length) { entry[key] = [...have, ...missing]; changed += missing.length; }
    }
  }
  return changed;
}

// Build a frontmatter object the way the script does: a real skill.md text
// round-tripped through lint.extractFrontmatterBlock + lint.parseFrontmatter.
function frontmatterFrom(lines) {
  const md = ["---", ...lines, "---", "", "# Body"].join("\n");
  const { frontmatter } = lint.extractFrontmatterBlock(md);
  return lint.parseFrontmatter(frontmatter);
}

test("MIRROR replaces last_threat_review exactly (frontmatter wins over a stale cache)", () => {
  const fm = frontmatterFrom([
    "name: demo",
    "last_threat_review: 2026-06-21",
  ]);
  const manifest = { skills: [{ id: "demo", last_threat_review: "2026-01-01" }] };
  const changed = syncManifest(manifest, { demo: fm });
  assert.equal(changed, 1, "the stale scalar is replaced (one change)");
  assert.equal(manifest.skills[0].last_threat_review, "2026-06-21",
    "MIRROR copies the frontmatter value verbatim");
});

test("MIRRORED_ARRAY replaces forward_watch exactly (not a union)", () => {
  const fm = frontmatterFrom([
    "name: demo",
    "last_threat_review: 2026-06-21",
    "forward_watch:",
    "  - RFC-9999-bis",
  ]);
  // The cache carries an EXTRA forward_watch item — MIRRORED_ARRAY is exact
  // replace, so that extra must be dropped (unlike COVER, which would keep it).
  const manifest = { skills: [{ id: "demo", last_threat_review: "2026-06-21", forward_watch: ["stale-item", "RFC-9999-bis"] }] };
  const changed = syncManifest(manifest, { demo: fm });
  assert.equal(changed, 1, "the differing array is replaced (one change)");
  assert.deepEqual(manifest.skills[0].forward_watch, ["RFC-9999-bis"],
    "MIRRORED_ARRAY replaces wholesale — the stale extra is dropped");
});

test("COVER unions cross-ref arrays and PRESERVES the manifest's curated extras", () => {
  const fm = frontmatterFrom([
    "name: demo",
    "last_threat_review: 2026-06-21",
    "atlas_refs:",
    "  - AML.T0001",
    "  - AML.T0002",
  ]);
  // The manifest already carries a CURATED extra ref (AML.T9999) that is NOT in
  // frontmatter. COVER must append the missing frontmatter ref (AML.T0002)
  // WITHOUT dropping the curated AML.T9999.
  const manifest = {
    skills: [{ id: "demo", last_threat_review: "2026-06-21", atlas_refs: ["AML.T0001", "AML.T9999"] }],
  };
  const changed = syncManifest(manifest, { demo: fm });
  assert.equal(changed, 1, "exactly one missing frontmatter ref (AML.T0002) is appended");
  assert.deepEqual(manifest.skills[0].atlas_refs, ["AML.T0001", "AML.T9999", "AML.T0002"],
    "COVER appends the missing frontmatter ref and keeps the curated extra in original order");
});

test("COVER never drops a frontmatter ref the manifest is missing (the invariant the script protects)", () => {
  const fm = frontmatterFrom([
    "name: demo",
    "last_threat_review: 2026-06-21",
    "cwe_refs:",
    "  - CWE-1333",
    "  - CWE-93",
  ]);
  // Manifest has an EMPTY cwe_refs — both frontmatter refs must land, or they
  // silently vanish from build-indexes / reverse-refs (the documented hazard).
  const manifest = { skills: [{ id: "demo", last_threat_review: "2026-06-21", cwe_refs: [] }] };
  const changed = syncManifest(manifest, { demo: fm });
  assert.equal(changed, 2, "both missing frontmatter refs are appended");
  assert.deepEqual(manifest.skills[0].cwe_refs.sort(), ["CWE-1333", "CWE-93"],
    "every frontmatter-declared ref must appear in the manifest");
});

test("a fully in-sync manifest produces zero changes (idempotent no-op)", () => {
  const fm = frontmatterFrom([
    "name: demo",
    "last_threat_review: 2026-06-21",
    "forward_watch:",
    "  - watch-a",
    "atlas_refs:",
    "  - AML.T0001",
  ]);
  const manifest = {
    skills: [{
      id: "demo",
      last_threat_review: "2026-06-21",
      forward_watch: ["watch-a"],
      atlas_refs: ["AML.T0001"],
    }],
  };
  const changed = syncManifest(manifest, { demo: fm });
  assert.equal(changed, 0, "no drift → zero changes; the script writes nothing in this case");
});

test("a missing skill frontmatter is an error (the script's exit-1 path)", () => {
  const manifest = { skills: [{ id: "ghost", last_threat_review: "2026-01-01" }] };
  assert.throws(() => syncManifest(manifest, {}), /skill\.md not found/,
    "a manifest entry with no skill.md must surface as an error, not a silent skip");
});
