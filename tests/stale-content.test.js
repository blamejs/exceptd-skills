"use strict";

/**
 * tests/stale-content.test.js
 *
 * Subject coverage for scripts/builders/stale-content.js (buildStaleContent):
 *  - the envelope shape (_meta + findings) and the deterministic
 *    reference_date contract (manifest.threat_review_date, not "now");
 *  - a retired/renamed-skill token in a skill body produces a
 *    stale_renamed_skill HIGH finding with line refs, and a clean body
 *    produces none;
 *  - README badge drift fires only when the badge count diverges from the
 *    live skill count;
 *  - a skill last_threat_review > 180d before the reference date yields a
 *    skill_review_stale LOW finding, and a recent one does not;
 *  - a catalog whose last_updated exceeds freshness_policy.stale_after_days
 *    yields catalog_stale; a fresh one abstains;
 *  - by_severity tallies match the findings array.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { buildStaleContent } = require("../scripts/builders/stale-content.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-stale-"));
process.on("exit", () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });

let _n = 0;
function mkroot() {
  const d = path.join(TMP, "root-" + _n++);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function writeSkill(root, rel, body) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body, "utf8");
}

test("exports buildStaleContent as a function", () => {
  assert.equal(typeof buildStaleContent, "function");
});

test("envelope shape: _meta + findings, reference_date is the manifest date (deterministic)", () => {
  const root = mkroot();
  writeSkill(root, "skills/a/skill.md", "# A\n\nClean body, nothing stale.\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [{ name: "a", path: "skills/a/skill.md", last_threat_review: "2026-05-01" }];

  const out = buildStaleContent({ root, manifest, skills, catalogFiles: [] });

  assert.equal(out._meta.schema_version, "1.0.0");
  assert.equal(out._meta.reference_date, "2026-05-15");
  assert.ok(Array.isArray(out.findings));
  assert.equal(out._meta.finding_count, out.findings.length);
  // reference_date is the manifest date, not wall-clock — re-running is byte-identical.
  const out2 = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  assert.deepEqual(out, out2);
});

test("stale_renamed_skill: a retired token in a skill body is a HIGH finding with refs; clean body is silent", () => {
  const root = mkroot();
  writeSkill(root, "skills/dirty/skill.md",
    "# Dirty\n\nThis still routes to `age-gates-minor` which was retired.\n");
  writeSkill(root, "skills/clean/skill.md",
    "# Clean\n\nNo retired tokens here, just `age-verification`.\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [
    { name: "dirty", path: "skills/dirty/skill.md" },
    { name: "clean", path: "skills/clean/skill.md" },
  ];

  const out = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  const renamed = out.findings.filter((f) => f.category === "stale_renamed_skill");
  assert.ok(renamed.length >= 1, "the dirty skill must produce a stale_renamed_skill finding");
  const dirtyHit = renamed.find((f) => f.artifact === "skills/dirty/skill.md");
  assert.ok(dirtyHit, "finding must be attributed to the dirty skill");
  assert.equal(dirtyHit.severity, "high");
  assert.ok(Array.isArray(dirtyHit.refs) && dirtyHit.refs.length >= 1);
  assert.equal(typeof dirtyHit.refs[0].line, "number");
  // The clean skill must NOT produce a stale_renamed_skill finding.
  assert.ok(!renamed.some((f) => f.artifact === "skills/clean/skill.md"));
});

test("badge_drift: README skills badge fires only when it diverges from live count", () => {
  const root = mkroot();
  writeSkill(root, "skills/a/skill.md", "# A\n\nbody\n");
  writeSkill(root, "skills/b/skill.md", "# B\n\nbody\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [
    { name: "a", path: "skills/a/skill.md" },
    { name: "b", path: "skills/b/skill.md" },
  ];

  // Badge claims 99 but live count is 2 -> drift.
  fs.writeFileSync(path.join(root, "README.md"), "![skills](skills-99-blue)\n");
  const drifted = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  assert.ok(drifted.findings.some(
    (f) => f.category === "badge_drift" && f.artifact === "README.md"
  ), "a wrong skills badge must produce badge_drift");

  // Badge matching live count -> no skills badge_drift.
  fs.writeFileSync(path.join(root, "README.md"), "![skills](skills-2-blue)\n");
  const matched = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  assert.ok(!matched.findings.some(
    (f) => f.category === "badge_drift" && /skills badge/.test(f.detail || "")
  ), "a correct skills badge must not produce badge_drift");
});

test("skill_review_stale: > 180d before reference date fires LOW; recent does not", () => {
  const root = mkroot();
  writeSkill(root, "skills/old/skill.md", "# Old\n\nbody\n");
  writeSkill(root, "skills/new/skill.md", "# New\n\nbody\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [
    { name: "old", path: "skills/old/skill.md", last_threat_review: "2025-01-01" }, // > 180d
    { name: "new", path: "skills/new/skill.md", last_threat_review: "2026-05-01" }, // ~14d
  ];

  const out = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  const stale = out.findings.filter((f) => f.category === "skill_review_stale");
  assert.ok(stale.some((f) => f.artifact === "skills/old/skill.md"), "the old skill must be stale");
  assert.equal(stale.find((f) => f.artifact === "skills/old/skill.md").severity, "low");
  assert.ok(!stale.some((f) => f.artifact === "skills/new/skill.md"), "the recent skill must not be stale");
});

test("catalog_stale: last_updated past freshness_policy.stale_after_days fires; fresh abstains", () => {
  const root = mkroot();
  writeSkill(root, "skills/a/skill.md", "# A\n\nbody\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [{ name: "a", path: "skills/a/skill.md" }];

  const staleCat = "data/stale-cat.json";
  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  fs.writeFileSync(path.join(root, staleCat), JSON.stringify({
    _meta: { freshness_policy: { stale_after_days: 30 }, last_updated: "2025-01-01" },
  }));
  const freshCat = "data/fresh-cat.json";
  fs.writeFileSync(path.join(root, freshCat), JSON.stringify({
    _meta: { freshness_policy: { stale_after_days: 365 }, last_updated: "2026-05-10" },
  }));

  const out = buildStaleContent({ root, manifest, skills, catalogFiles: [staleCat, freshCat] });
  const catStale = out.findings.filter((f) => f.category === "catalog_stale");
  assert.ok(catStale.some((f) => f.artifact === staleCat), "an overdue catalog must be flagged");
  assert.ok(!catStale.some((f) => f.artifact === freshCat), "a fresh catalog must not be flagged");
  assert.equal(catStale.find((f) => f.artifact === staleCat).severity, "medium");
});

test("by_severity tallies are consistent with the findings array", () => {
  const root = mkroot();
  writeSkill(root, "skills/dirty/skill.md",
    "# Dirty\n\nrefers to `age-gates-minor-safeguarding` token\n");
  const manifest = { threat_review_date: "2026-05-15" };
  const skills = [{ name: "dirty", path: "skills/dirty/skill.md", last_threat_review: "2024-01-01" }];

  const out = buildStaleContent({ root, manifest, skills, catalogFiles: [] });
  const recomputed = { high: 0, medium: 0, low: 0 };
  for (const f of out.findings) recomputed[f.severity] = (recomputed[f.severity] || 0) + 1;
  for (const sev of Object.keys(recomputed)) {
    assert.equal(out._meta.by_severity[sev] || 0, recomputed[sev],
      `by_severity.${sev} must equal the actual count`);
  }
  // The dirty token (high) + stale review (low) must both be present.
  assert.ok(out._meta.by_severity.high >= 1);
  assert.ok(out._meta.by_severity.low >= 1);
});
