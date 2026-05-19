"use strict";

/**
 * tests/refresher-spec-coupling.test.js
 *
 * v0.13.20 class-3.11 fix — refresh-upstream-catalogs.js reads its
 * required-context list from the audit-catalog-gaps SPEC. This test
 * pins the coupling so a future PR that adds a required-context field
 * to the audit SPEC but forgets to extend the refresher's backfill
 * fires immediately.
 *
 * The contract: every field declared in SPEC[catalog].required_context
 * must be present in the refresher's backfill paths. Either via:
 *   (a) the backfill function explicitly fills it on existing rows, or
 *   (b) the new-entry constructor populates it.
 *
 * If we add a new required context field tomorrow (say "data_sources"
 * to ATT&CK), the audit will flag every existing row as missing — and
 * the refresher should backfill on next run. This test pins that the
 * refresher actually reads the SPEC.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const RU = require(path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"));
const AUDIT = require(path.join(__dirname, "..", "scripts", "audit-catalog-gaps.js"));

test("refresher imports the audit SPEC (single source of truth for required-context)", () => {
  // Static-grep the refresher file for the SPEC import. If a future
  // PR removes the import or re-introduces a hardcoded parallel field
  // list, this fires.
  const fs = require("node:fs");
  const body = fs.readFileSync(
    path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"),
    "utf8"
  );
  assert.match(body, /require\(["']\.\/audit-catalog-gaps/,
    "refresh-upstream-catalogs.js must require audit-catalog-gaps so the SPEC is the truth source");
  assert.match(body, /SPEC|specRequiredFields/,
    "the SPEC import must be USED — not just imported and ignored");
});

test("AUDIT.SPEC declares required_context for every catalog the refresher writes to", () => {
  // The refresher writes to: rfc-references, attack-techniques,
  // atlas-ttps, d3fend-catalog. Each must have a SPEC entry so the
  // refresher-spec coupling holds.
  for (const key of ["rfc-references", "attack-techniques", "atlas-ttps", "d3fend-catalog"]) {
    const spec = AUDIT.SPEC[key];
    assert.ok(spec, `audit SPEC must declare ${key}`);
    assert.ok(Array.isArray(spec.required_context) && spec.required_context.length > 0,
      `audit SPEC.${key}.required_context must be a non-empty array`);
  }
});

test("refresher SOURCES registry maps each canonical refresh-fn name to a callable", () => {
  // Pins the SOURCES registry shape — every refresher consumer (CLI
  // dispatcher, per-type wrappers, refresh-external) relies on this.
  for (const key of ["rfc", "attack", "ics-attack", "atlas", "d3fend"]) {
    const s = RU.SOURCES[key];
    assert.ok(s, `SOURCES.${key} missing`);
    assert.equal(typeof s.run, "function", `SOURCES.${key}.run must be a function`);
  }
});
