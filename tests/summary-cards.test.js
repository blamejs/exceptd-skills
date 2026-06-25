"use strict";

/**
 * tests/summary-cards.test.js
 *
 * Subject coverage for scripts/builders/summary-cards.js (buildSummaryCards):
 *  - per-skill card shape (description, excerpts, key_xrefs, *_count, path);
 *  - threat_context_excerpt pulls the first prose paragraph below
 *    `## Threat Context`, skipping leading bold-prefix metadata / H3 / rules;
 *  - a `## ` line INSIDE a fenced code block is not treated as a section
 *    boundary (findRealH2Indices);
 *  - produces is null when there is no Output Format section;
 *  - handoff_targets contains only backtick-quoted sibling skill names found
 *    in the Hand-Off section (self excluded), sorted;
 *  - the *_count fields equal the lengths of the corresponding xref arrays.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { buildSummaryCards } = require("../scripts/builders/summary-cards.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-cards-"));
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

test("exports buildSummaryCards as a function", () => {
  assert.equal(typeof buildSummaryCards, "function");
});

test("card shape + threat-context excerpt skips leading bold metadata; counts mirror xref arrays", () => {
  const root = mkroot();
  const body = [
    "# Alpha skill",
    "",
    "## Threat Context",
    "",
    "**Last reviewed:** 2026-05-01",
    "---",
    "The real threat is prompt injection through an authorized service account.",
    "It crosses no identity boundary, which is the point.",
    "",
    "## Output Format",
    "",
    "Produces a structured finding with severity + RWEP.",
    "",
    "## Hand-Off",
    "",
    "Escalate to `bravo` for deeper analysis.",
    "",
  ].join("\n");
  writeSkill(root, "skills/alpha/skill.md", body);
  writeSkill(root, "skills/bravo/skill.md", "# Bravo\n\nbody\n");

  const manifest = {};
  const skills = [
    {
      name: "alpha", path: "skills/alpha/skill.md", description: "Alpha desc",
      cwe_refs: ["CWE-77", "CWE-78"], atlas_refs: ["AML.T0051"], attack_refs: ["T1059"],
      framework_gaps: ["GAP-1"], triggers: ["t1", "t2", "t3"], rfc_refs: ["RFC-8446"],
      d3fend_refs: ["D3-X"], last_threat_review: "2026-05-01",
    },
    { name: "bravo", path: "skills/bravo/skill.md", description: "Bravo desc" },
  ];

  const out = buildSummaryCards({ root, manifest, skills });
  assert.equal(out._meta.schema_version, "1.0.0");
  const card = out.skills.alpha;
  assert.ok(card, "alpha card present");
  assert.equal(card.description, "Alpha desc");
  assert.equal(card.path, "skills/alpha/skill.md");

  // Excerpt skips the bold metadata + the --- rule, lands on real prose.
  assert.ok(/prompt injection/.test(card.threat_context_excerpt));
  assert.ok(!/Last reviewed/.test(card.threat_context_excerpt),
    "bold-prefix metadata must be skipped, not captured as the excerpt");

  // produces pulls Output Format chunk.
  assert.ok(/structured finding/.test(card.produces));

  // *_count fields mirror the xref array lengths.
  assert.equal(card.cwe_count, 2);
  assert.equal(card.atlas_count, 1);
  assert.equal(card.attack_count, 1);
  assert.equal(card.framework_gap_count, 1);
  assert.equal(card.trigger_count, 3);
  assert.equal(card.rfc_count, 1);
  assert.equal(card.d3fend_count, 1);
  assert.deepEqual(card.key_xrefs.cwe_refs, ["CWE-77", "CWE-78"]);

  // handoff_targets contains the backtick-quoted sibling, self excluded.
  assert.deepEqual(card.handoff_targets, ["bravo"]);
  // bravo references nobody -> empty handoff list.
  assert.deepEqual(out.skills.bravo.handoff_targets, []);
});

test("handoff_targets are bounded to the Hand-Off section, not scanned to EOF", () => {
  const root = mkroot();
  // `bravo` is named in the Hand-Off section (a real target). `charlie` is
  // named only in a LATER section after the next H2. The old EOF-slice picked
  // up charlie; the fence-aware section-bounded slice must not.
  const body = [
    "# Alpha",
    "",
    "## Hand-Off",
    "",
    "Escalate to `bravo` for deeper analysis.",
    "",
    "## See Also",
    "",
    "Unrelated reference to `charlie` that is not a hand-off target.",
    "",
  ].join("\n");
  writeSkill(root, "skills/alpha/skill.md", body);
  writeSkill(root, "skills/bravo/skill.md", "# Bravo\n\nbody\n");
  writeSkill(root, "skills/charlie/skill.md", "# Charlie\n\nbody\n");
  const skills = [
    { name: "alpha", path: "skills/alpha/skill.md", description: "a" },
    { name: "bravo", path: "skills/bravo/skill.md", description: "b" },
    { name: "charlie", path: "skills/charlie/skill.md", description: "c" },
  ];

  const out = buildSummaryCards({ root, manifest: {}, skills });
  const targets = out.skills.alpha.handoff_targets;
  assert.ok(Array.isArray(targets), "handoff_targets must be an array");
  // Exact set: only the in-section target, charlie (post-section) excluded.
  assert.deepEqual(targets, ["bravo"], "only in-Hand-Off-section targets are returned");
  assert.equal(targets.includes("charlie"), false,
    "a sibling named after the next H2 must not be treated as a hand-off target");
});

test("Hand-Off header inside a fenced code block is not treated as a section", () => {
  const root = mkroot();
  // The only `## Hand-Off` line lives inside a fence — it is not a real H2, so
  // there is no Hand-Off section and `bravo` named below must not be collected.
  const body = [
    "# Alpha",
    "",
    "## Threat Context",
    "",
    "```md",
    "## Hand-Off",
    "Escalate to `bravo`.",
    "```",
    "Real prose with no genuine hand-off section.",
    "",
  ].join("\n");
  writeSkill(root, "skills/alpha/skill.md", body);
  writeSkill(root, "skills/bravo/skill.md", "# Bravo\n\nbody\n");
  const skills = [
    { name: "alpha", path: "skills/alpha/skill.md", description: "a" },
    { name: "bravo", path: "skills/bravo/skill.md", description: "b" },
  ];

  const out = buildSummaryCards({ root, manifest: {}, skills });
  assert.deepEqual(out.skills.alpha.handoff_targets, [],
    "a fenced ## Hand-Off is not a real section boundary");
});

test("a `## ` line inside a fenced code block is not a section boundary", () => {
  const root = mkroot();
  const body = [
    "# Gamma",
    "",
    "## Threat Context",
    "",
    "```bash",
    "## this is a shell comment, not an H2",
    "echo hi",
    "```",
    "The genuine threat-context prose follows the fenced block.",
    "",
  ].join("\n");
  writeSkill(root, "skills/gamma/skill.md", body);
  const skills = [{ name: "gamma", path: "skills/gamma/skill.md", description: "g" }];

  const out = buildSummaryCards({ root, manifest: {}, skills });
  const card = out.skills.gamma;
  // The fenced "## this is a shell comment" must NOT terminate the section;
  // the prose after the fence is the excerpt.
  assert.ok(/genuine threat-context prose/.test(card.threat_context_excerpt));
});

test("produces is null when there is no Output Format section", () => {
  const root = mkroot();
  writeSkill(root, "skills/delta/skill.md",
    "# Delta\n\n## Threat Context\n\nA threat with no output-format section.\n");
  const skills = [{ name: "delta", path: "skills/delta/skill.md", description: "d" }];

  const out = buildSummaryCards({ root, manifest: {}, skills });
  assert.equal(out.skills.delta.produces, null);
});

test("missing Threat Context yields a null excerpt and empty xref arrays default to []", () => {
  const root = mkroot();
  writeSkill(root, "skills/epsilon/skill.md", "# Epsilon\n\nNo recognized sections at all.\n");
  const skills = [{ name: "epsilon", path: "skills/epsilon/skill.md" }];

  const out = buildSummaryCards({ root, manifest: {}, skills });
  const card = out.skills.epsilon;
  assert.equal(card.threat_context_excerpt, null);
  assert.equal(card.description, null);
  assert.deepEqual(card.key_xrefs.cwe_refs, []);
  assert.equal(card.cwe_count, 0);
  assert.equal(card.trigger_count, 0);
});
