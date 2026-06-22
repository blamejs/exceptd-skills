"use strict";

/**
 * tests/theater-fingerprints.test.js
 *
 * Subject coverage for scripts/builders/theater-fingerprints.js
 * (buildTheaterFingerprints):
 *  - run against the LIVE compliance-theater skill (read-only): the envelope
 *    has all 7 patterns, each with the curated control map + ttps + fast_test,
 *    and the prose fields (claim/reality/...) extract non-null from the skill;
 *  - the by_control inverted index round-trips every control back to the
 *    pattern that declares it;
 *  - against a synthetic skill fixture, the `### Pattern N:` extractor stops at
 *    `### Pattern N+1:` / the next H2, and pullField extracts the labeled prose
 *    while a Pattern-2 label does not bleed into Pattern-1's body.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { buildTheaterFingerprints } = require("../scripts/builders/theater-fingerprints.js");

const ROOT = path.join(__dirname, "..");

test("exports buildTheaterFingerprints as a function", () => {
  assert.equal(typeof buildTheaterFingerprints, "function");
});

test("live skill: 7 patterns, full record shape, prose fields extract non-null", () => {
  const out = buildTheaterFingerprints({ root: ROOT });

  assert.equal(out._meta.schema_version, "1.0.0");
  assert.equal(out._meta.pattern_count, 7);
  assert.equal(Object.keys(out.patterns).length, 7);

  for (let n = 1; n <= 7; n++) {
    const p = out.patterns["pattern-" + n];
    assert.ok(p, `pattern-${n} present`);
    assert.equal(p.pattern_number, n);
    assert.equal(typeof p.pattern_name, "string");
    assert.ok(p.pattern_name.length > 0);
    assert.equal(p.source_skill, "compliance-theater");
    assert.ok(Array.isArray(p.controls) && p.controls.length >= 1,
      `pattern-${n} must carry >= 1 control`);
    for (const c of p.controls) {
      assert.equal(typeof c.framework, "string");
      assert.equal(typeof c.control_id, "string");
    }
    assert.ok(Array.isArray(p.ttps) && p.ttps.length >= 1, `pattern-${n} must carry >= 1 ttp`);
    assert.equal(typeof p.fast_test, "string");
    assert.ok(p.fast_test.includes("THEATER FLAG"));
    // The prose fields are extracted from the live skill markdown — at least
    // the claim must parse, proving the extractor is wired to real headings.
    assert.ok(p.claim && typeof p.claim === "string" && p.claim.length > 0,
      `pattern-${n} claim must extract from the skill body (field-populated, not just present)`);
  }
});

test("by_control inverted index round-trips every control to its declaring pattern", () => {
  const out = buildTheaterFingerprints({ root: ROOT });

  // Every control declared on a pattern must appear under the matching
  // by_control key, pointing back at that pattern.
  for (const [pid, p] of Object.entries(out.patterns)) {
    for (const c of p.controls) {
      const key = `${c.framework}::${c.control_id}`;
      assert.ok(Array.isArray(out.by_control[key]),
        `by_control["${key}"] must exist for ${pid}`);
      assert.ok(out.by_control[key].includes(pid),
        `by_control["${key}"] must include ${pid}`);
    }
  }
  // A known control from Pattern 1 resolves to pattern-1.
  assert.ok(out.by_control["NIST 800-53::SI-2"].includes("pattern-1"));
});

test("synthetic skill: pattern extractor stops at the next pattern/H2 and pullField scopes to its pattern", () => {
  // Drive the extractor through a tempdir skill containing 2 patterns so the
  // boundary logic (### Pattern N -> ### Pattern N+1, and the trailing H2) is
  // exercised deterministically without depending on the live skill's wording.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-theater-fx-"));
  try {
    const skillRel = "skills/compliance-theater/skill.md";
    const abs = path.join(tmp, skillRel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    const body = [
      "# Compliance Theater",
      "",
      "## Patterns",
      "",
      "### Pattern 1: Patch Management Theater",
      "",
      "**The claim:** Critical patches applied within 30 days.",
      "",
      "**The reality:** KEV-listed bugs are weaponized in hours.",
      "",
      "### Pattern 2: Network Segmentation Theater (IPsec)",
      "",
      "**The claim:** IPsec tunnels separate the trust zones.",
      "",
      "## Framework Lag Declaration",
      "",
      "trailing section that must not bleed into pattern bodies",
      "",
    ].join("\n");
    fs.writeFileSync(abs, body, "utf8");

    const out = buildTheaterFingerprints({ root: tmp });
    const p1 = out.patterns["pattern-1"];
    const p2 = out.patterns["pattern-2"];

    // Pattern 1's claim/reality parse from its own body only.
    assert.ok(/within 30 days/.test(p1.claim), "pattern-1 claim parses");
    assert.ok(/weaponized in hours/.test(p1.reality), "pattern-1 reality parses");
    // Pattern 2's claim must NOT have leaked into pattern 1.
    assert.ok(!/IPsec tunnels/.test(p1.claim || ""),
      "pattern-2 prose must not bleed into pattern-1");
    // Pattern 2 parses its own claim; the trailing H2 section is not captured.
    assert.ok(/IPsec tunnels separate/.test(p2.claim), "pattern-2 claim parses");
    assert.ok(!/trailing section/.test(JSON.stringify(p2)),
      "the next H2 must terminate pattern-2's extracted body");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("an absent pattern heading yields null prose fields (no throw)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-theater-empty-"));
  try {
    const abs = path.join(tmp, "skills/compliance-theater/skill.md");
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    // No "### Pattern N:" headings at all.
    fs.writeFileSync(abs, "# Compliance Theater\n\nNo pattern sections here.\n", "utf8");

    const out = buildTheaterFingerprints({ root: tmp });
    // Curated metadata (controls/ttps/fast_test) is still present from the map,
    // but the markdown-extracted prose is null because no heading matched.
    assert.equal(out.patterns["pattern-1"].claim, null);
    assert.equal(out.patterns["pattern-1"].reality, null);
    assert.ok(Array.isArray(out.patterns["pattern-1"].controls));
    assert.equal(out._meta.pattern_count, 7);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
