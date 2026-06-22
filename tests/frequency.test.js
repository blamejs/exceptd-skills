"use strict";

/**
 * tests/frequency.test.js
 *
 * Behavioral coverage for scripts/builders/frequency.js (buildFrequency) — the
 * citation-count builder. For each cross-reference field it counts how many
 * skills cite each entry, then derives top_cited (sorted), orphan_adjacent
 * (count===1), and uncited (catalog entry with zero citations).
 *
 * Strategy: hand-craft a small { skills, catalogs } fixture with known citation
 * counts so every rollup is asserted against a computed-by-hand expectation,
 * then smoke against the live manifest/catalogs for shape stability.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { buildFrequency } = require("../scripts/builders/frequency.js");

const ROOT = path.join(__dirname, "..");

// Minimal fixture: three skills with overlapping cwe_refs / atlas_refs, plus a
// catalog that contains an entry no skill references (to exercise `uncited`).
function fixture() {
  const skills = [
    { name: "skill-c", cwe_refs: ["CWE-79", "CWE-89"], atlas_refs: ["AML.T0051"] },
    { name: "skill-a", cwe_refs: ["CWE-79"], atlas_refs: ["AML.T0051"] },
    { name: "skill-b", cwe_refs: ["CWE-79", "CWE-22"] },
  ];
  const catalogs = {
    cwe: { _meta: {}, "CWE-79": {}, "CWE-89": {}, "CWE-22": {}, "CWE-918": {} }, // CWE-918 uncited
    atlas: { _meta: {}, "AML.T0051": {}, "AML.T0099": {} }, // AML.T0099 uncited
  };
  return { skills, catalogs };
}

test("module contract: exports buildFrequency as a function", () => {
  assert.equal(typeof buildFrequency, "function");
});

test("envelope shape: _meta + counts + top_cited + orphan_adjacent + uncited over every field", () => {
  const out = buildFrequency(fixture());
  assert.equal(out._meta.schema_version, "1.0.0");
  const fields = ["cwe_refs", "d3fend_refs", "framework_gaps", "atlas_refs", "attack_refs", "rfc_refs", "dlp_refs"];
  assert.deepEqual(out._meta.fields_indexed, fields);
  for (const f of fields) {
    assert.ok(out.counts[f], `counts.${f} present`);
    assert.ok(Array.isArray(out.top_cited[f]), `top_cited.${f} is an array`);
    assert.ok(Array.isArray(out.orphan_adjacent[f]), `orphan_adjacent.${f} is an array`);
  }
});

test("counts: CWE-79 cited by all three skills, with skills sorted ascending", () => {
  const out = buildFrequency(fixture());
  assert.equal(out.counts.cwe_refs["CWE-79"].count, 3);
  // skills list is sorted, so insertion order (c,a,b) becomes a,b,c.
  assert.deepEqual(out.counts.cwe_refs["CWE-79"].skills, ["skill-a", "skill-b", "skill-c"]);
  assert.equal(out.counts.cwe_refs["CWE-89"].count, 1);
  assert.equal(out.counts.atlas_refs["AML.T0051"].count, 2);
});

test("top_cited: ordered by count desc then id asc; entry shape is {id,count,skills}", () => {
  const out = buildFrequency(fixture());
  const cwe = out.top_cited.cwe_refs;
  // CWE-79 (3) leads; CWE-22 and CWE-89 both at 1 break ties by id ascending.
  assert.equal(cwe[0].id, "CWE-79");
  assert.equal(cwe[0].count, 3);
  const tail = cwe.slice(1).map((r) => r.id);
  assert.deepEqual(tail, ["CWE-22", "CWE-89"]);
  for (const r of cwe) {
    assert.equal(typeof r.id, "string");
    assert.ok(r.count >= 1);
    assert.ok(Array.isArray(r.skills));
  }
});

test("orphan_adjacent: exactly the entries cited by precisely one skill, sorted", () => {
  const out = buildFrequency(fixture());
  // CWE-89 (skill-c only) and CWE-22 (skill-b only) each have count 1.
  assert.deepEqual(out.orphan_adjacent.cwe_refs, ["CWE-22", "CWE-89"]);
  // AML.T0051 has count 2 -> NOT orphan-adjacent.
  assert.deepEqual(out.orphan_adjacent.atlas_refs, []);
});

test("uncited: catalog entries with zero skill citations are flagged; cited ones are not", () => {
  const out = buildFrequency(fixture());
  // CWE-918 exists in the catalog but no skill cites it.
  assert.deepEqual(out.uncited.cwe_refs, ["CWE-918"]);
  assert.deepEqual(out.uncited.atlas_refs, ["AML.T0099"]);
  // _meta key in the catalog must not appear as an uncited entry.
  assert.ok(!out.uncited.cwe_refs.includes("_meta"));
});

test("attack_refs has counts but no uncited table (no backing catalog)", () => {
  const out = buildFrequency({
    skills: [{ name: "s1", attack_refs: ["T1059", "T1059"] }],
    catalogs: {},
  });
  // T1059 cited twice within the same skill -> count 2.
  assert.equal(out.counts.attack_refs["T1059"].count, 2);
  // No catalog mapping for attack_refs, so the uncited rollup must omit it.
  assert.equal("attack_refs" in out.uncited, false);
});

test("missing catalog for a field is skipped without throwing", () => {
  const out = buildFrequency({
    skills: [{ name: "s1", rfc_refs: ["RFC8446"] }],
    catalogs: { cwe: { _meta: {}, "CWE-1": {} } }, // rfc catalog absent
  });
  assert.equal(out.counts.rfc_refs["RFC8446"].count, 1);
  assert.equal("rfc_refs" in out.uncited, false); // no rfc catalog -> no uncited table
  assert.deepEqual(out.uncited.cwe_refs, ["CWE-1"]); // cwe present, uncited
});

test("empty skills set: all counts empty, every rollup degenerate but well-formed", () => {
  const out = buildFrequency({ skills: [], catalogs: { cwe: { _meta: {}, "CWE-7": {} } } });
  assert.deepEqual(out.counts.cwe_refs, {});
  assert.deepEqual(out.top_cited.cwe_refs, []);
  assert.deepEqual(out.orphan_adjacent.cwe_refs, []);
  // The single catalog entry is uncited because no skill referenced it.
  assert.deepEqual(out.uncited.cwe_refs, ["CWE-7"]);
});

test("smoke against live data: top_cited entries are well-formed and never exceed 10 per field", () => {
  const manifest = require(path.join(ROOT, "manifest.json"));
  const skillNames = new Set(manifest.skills.map((s) => s.name));
  // Use loadSources so the skills carry their frontmatter-overlaid ref arrays.
  const { loadSources } = require(path.join(ROOT, "scripts", "build-indexes.js"));
  const ctx = loadSources();
  const out = buildFrequency({
    skills: ctx.skills,
    catalogs: {
      cwe: ctx.cweCatalog,
      atlas: ctx.atlasTtps,
      d3fend: ctx.d3Catalog,
      frameworkGaps: ctx.frameworkGaps,
      rfc: ctx.rfcCatalog,
      dlp: ctx.dlpCatalog,
    },
  });
  for (const [field, rows] of Object.entries(out.top_cited)) {
    assert.ok(rows.length <= 10, `${field} top_cited exceeds 10`);
    for (const r of rows) {
      assert.ok(r.count >= 1);
      for (const s of r.skills) assert.ok(skillNames.has(s), `${field}: unknown skill ${s}`);
    }
  }
});
