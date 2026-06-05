"use strict";

/**
 * Per-factor coherence for the CVE catalog's rwep_factors breakdown.
 *
 * Each stored rwep_factors value is the operator-facing explanation of how an
 * entry's RWEP score is built. scoring.validate() only compares the SUM of the
 * breakdown against rwep_score with a >5 tolerance, so two individual factors
 * can be wrong by equal-and-opposite amounts (or each wrong by 5, landing on
 * the tolerance boundary) while the sum invariant still holds. That lets a
 * breakdown ship that contradicts the entry's own source fields: a reboot
 * contribution of 0 next to patch_required_reboot=true, an active-exploitation
 * contribution of 5 next to active_exploitation="theoretical", and so on.
 *
 * This guard reconstructs each post-weight factor from the entry's source
 * fields using the canonical RWEP_WEIGHTS and ACTIVE_EXPLOITATION_LADDER, then
 * asserts every stored Shape-B factor equals its reconstructed value. It scopes
 * to curated entries (those scoring.validate() itself processes — drafts marked
 * _auto_imported are exempt there and here) and to the post-weight (Shape B)
 * storage form the catalog uses, so raw boolean Shape-A bags are left alone.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const cve = require(path.join(ROOT, "data", "cve-catalog.json"));
const scoring = require(path.join(ROOT, "lib", "scoring.js"));

const W = scoring.RWEP_WEIGHTS;
const LADDER = scoring.ACTIVE_EXPLOITATION_LADDER;

// The post-weight contribution each boolean/ladder factor must carry, derived
// from the entry's own source fields exactly the way scoreCustom() does.
function expectedFactors(entry) {
  return {
    cisa_kev: entry.cisa_kev ? W.cisa_kev : 0,
    poc_available: entry.poc_available ? W.poc_available : 0,
    ai_factor: (entry.ai_assisted_weaponization || entry.ai_discovered) ? W.ai_factor : 0,
    active_exploitation: W.active_exploitation * (LADDER[entry.active_exploitation] ?? 0),
    patch_available: entry.patch_available ? W.patch_available : 0,
    live_patch_available: entry.live_patch_available ? W.live_patch_available : 0,
    reboot_required: entry.patch_required_reboot === true ? W.reboot_required : 0,
  };
}

// Shape B stores every non-blast_radius factor as a numeric post-weight
// contribution. Raw boolean/string Shape-A bags are derived a different way and
// are out of scope for this per-factor reconstruction.
function isShapeB(factors) {
  return Object.entries(factors).every(
    ([k, v]) => k === "blast_radius" || typeof v === "number",
  );
}

function curatedShapeBEntries() {
  const out = [];
  for (const [id, entry] of Object.entries(cve)) {
    if (id.startsWith("_")) continue;
    if (entry._auto_imported === true) continue;
    if (!entry.rwep_factors || typeof entry.rwep_factors !== "object") continue;
    if (!isShapeB(entry.rwep_factors)) continue;
    out.push([id, entry]);
  }
  return out;
}

test("every curated rwep_factors breakdown agrees with the entry's source fields", () => {
  const mismatches = [];
  for (const [id, entry] of curatedShapeBEntries()) {
    const expected = expectedFactors(entry);
    for (const key of Object.keys(expected)) {
      const stored = entry.rwep_factors[key] || 0;
      if (stored !== expected[key]) {
        mismatches.push(
          `${id}.${key}: stored ${stored}, source fields imply ${expected[key]}`,
        );
      }
    }
  }
  assert.equal(
    mismatches.length,
    0,
    `rwep_factors contradict their source fields:\n  ${mismatches.join("\n  ")}`,
  );
});

test("a reboot-required kernel LPE carries the reboot factor in its breakdown", () => {
  const e = cve["CVE-2026-46333"];
  assert.ok(e, "CVE-2026-46333 must exist");
  assert.equal(e.patch_required_reboot, true);
  assert.equal(e.rwep_factors.reboot_required, 5);
  assert.equal(e.rwep_score, 35);
});

test("a no-reboot client-app patch carries no reboot factor", () => {
  const e = cve["CVE-2009-3459"];
  assert.ok(e, "CVE-2009-3459 must exist");
  assert.equal(e.patch_required_reboot, false);
  assert.equal(e.rwep_factors.reboot_required, 0);
  assert.equal(e.rwep_score, 65);
});

test("an unknown-exploitation entry scores the quarter-weight ladder rung", () => {
  const e = cve["CVE-2023-43472"];
  assert.ok(e, "CVE-2023-43472 must exist");
  assert.equal(e.active_exploitation, "unknown");
  assert.equal(e.rwep_factors.active_exploitation, 5);
  assert.equal(e.rwep_score, 35);
});

test("a theoretical entry scores zero active-exploitation and keeps its reboot factor", () => {
  const e = cve["CVE-2026-31635"];
  assert.ok(e, "CVE-2026-31635 must exist");
  assert.equal(e.active_exploitation, "theoretical");
  assert.equal(e.patch_required_reboot, true);
  assert.equal(e.rwep_factors.active_exploitation, 0);
  assert.equal(e.rwep_factors.reboot_required, 5);
  assert.equal(e.rwep_score, 35);
});

test("the corrected entries' stored score matches the canonical scorer exactly", () => {
  for (const id of ["CVE-2026-46333", "CVE-2009-3459", "CVE-2023-43472", "CVE-2026-31635"]) {
    const e = cve[id];
    const calculated = scoring.scoreCustom({
      cisa_kev: e.cisa_kev,
      poc_available: e.poc_available,
      ai_assisted_weapon: e.ai_assisted_weaponization || false,
      ai_discovered: e.ai_discovered || false,
      active_exploitation: e.active_exploitation,
      blast_radius: e.rwep_factors ? e.rwep_factors.blast_radius : 0,
      patch_available: e.patch_available,
      live_patch_available: e.live_patch_available,
      reboot_required: e.patch_required_reboot,
    });
    assert.equal(calculated, e.rwep_score, `${id}: stored rwep_score must equal scoreCustom`);
    const sum = Object.values(e.rwep_factors).reduce((a, b) => a + b, 0);
    assert.equal(sum, e.rwep_score, `${id}: rwep_factors must sum to rwep_score`);
  }
});
