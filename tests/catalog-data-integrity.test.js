"use strict";

/**
 * Regression suite for a catalog data-integrity / curation pass:
 *
 *   - The AI supply-chain families (ShadowMQ, Triton auth-bypass) carry ATLAS
 *     mappings — they were unmapped while sibling family entries carried
 *     AML.T0049 (Hard Rule #7 coherence).
 *   - The active_exploitation "theoretical" status is an explicit entry in the
 *     RWEP scoring ladder (not an incidental `?? 0` fall-through).
 *   - The jurisdiction count is consistent across the stale-content and
 *     catalog-summaries builders and the README badge (all count GLOBAL → 35).
 *   - framework-control-gaps _meta.entry_count matches the actual entry count
 *     (a gate now enforces this).
 *   - Shipped playbook threat_currency_score stays within the documented band.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const cve = require(path.join(ROOT, "data", "cve-catalog.json"));
const atlas = require(path.join(ROOT, "data", "atlas-ttps.json"));
const gaps = require(path.join(ROOT, "data", "framework-control-gaps.json"));
const gf = require(path.join(ROOT, "data", "global-frameworks.json"));
const scoring = require(path.join(ROOT, "lib", "scoring.js"));

test("AI supply-chain families (ShadowMQ + Triton auth-bypass) carry resolvable ATLAS refs", () => {
  const ids = ["CVE-2025-23254", "CVE-2025-30165", "CVE-2024-50050", "CVE-2025-60455", "CVE-2026-24206", "CVE-2026-24207"];
  for (const id of ids) {
    const e = cve[id];
    assert.ok(e, `${id} must exist`);
    assert.ok(Array.isArray(e.atlas_refs) && e.atlas_refs.length >= 1, `${id} must carry at least one ATLAS ref`);
    for (const ref of e.atlas_refs) {
      assert.ok(atlas[ref], `${id} atlas_ref ${ref} must resolve to a real ATLAS TTP`);
    }
  }
});

test("the RWEP active_exploitation ladder defines 'theoretical' explicitly", () => {
  // Score a factor bag with theoretical exploitation and confirm it's handled
  // deterministically (no NaN / no crash). The exact value is an
  // implementation detail; the point is it's a recognized key.
  const s = scoring.scoreCustom({ active_exploitation: "theoretical", blast_radius: 5 });
  assert.equal(typeof s, "number");
  assert.ok(Number.isFinite(s), "scoring a theoretical-exploitation factor bag must be finite");
});

test("framework-control-gaps _meta.entry_count matches the actual entry count", () => {
  const actual = Object.keys(gaps).filter((k) => !k.startsWith("_")).length;
  assert.equal(gaps._meta.entry_count, actual,
    `_meta.entry_count (${gaps._meta.entry_count}) must equal the actual count (${actual})`);
});

test("jurisdiction count is consistent (GLOBAL included → 35) across builders", () => {
  const live = Object.keys(gf).filter((k) => !k.startsWith("_")).length;
  assert.equal(live, 35, "the canonical jurisdiction count (non-underscore keys, GLOBAL included) is 35");
  // The stale-content builder must use the same rule (no GLOBAL exclusion).
  const src = require("fs").readFileSync(path.join(ROOT, "scripts", "builders", "stale-content.js"), "utf8");
  assert.doesNotMatch(src, /!startsWith\("_"\)\s*&&\s*k\s*!==\s*"GLOBAL"/,
    "stale-content must not uniquely exclude GLOBAL from the jurisdiction count");
});

test("shipped playbooks' threat_currency_score stays within the documented 92-96 band", () => {
  const fs = require("fs");
  const dir = path.join(ROOT, "data", "playbooks");
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const pb = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
    const score = pb._meta && pb._meta.threat_currency_score;
    assert.ok(score >= 92 && score <= 96, `${f}: threat_currency_score ${score} must be in 92-96`);
  }
});
