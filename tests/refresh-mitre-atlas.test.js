"use strict";

/**
 * tests/refresh-mitre-atlas.test.js
 *
 * Subject coverage for scripts/refresh-mitre-atlas.js — the thin per-type
 * wrapper for the MITRE ATLAS refresher.
 *
 * The wrapper fires the network refresher at require-time (top-level
 * refreshAtlas(...).catch(...)), so requiring it directly would hit the live
 * MITRE STIX endpoint. We therefore test it WITHOUT requiring it:
 *
 *   1. Structural contract on the wrapper source — it imports refreshAtlas
 *      from the single-source-of-truth module, parses --dry-run, and wires the
 *      run + error-exit path.
 *   2. Behavioral coverage of refreshAtlas itself (the function the wrapper
 *      executes) driven entirely off injected _deps: a synthetic ATLAS STIX
 *      bundle fed through a fake fetchUrl, a fake in-memory catalog, and a
 *      captured writeCatalog. No live network, no repo-file mutation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SCRIPTS = path.join(__dirname, "..", "scripts");
const WRAPPER = path.join(SCRIPTS, "refresh-mitre-atlas.js");
// Safe to require the underlying module — its network logic only runs under
// require.main === module, which is false when imported here.
const UPSTREAM = require(path.join(SCRIPTS, "refresh-upstream-catalogs.js"));

// A synthetic ATLAS STIX bundle: one live AML.* attack-pattern + one matrix
// object carrying the version, plus one revoked technique that must be skipped.
function atlasStixBundle() {
  return JSON.stringify({
    type: "bundle",
    objects: [
      {
        type: "x-mitre-matrix",
        name: "ATLAS Matrix",
        x_mitre_version: "2026.05",
      },
      {
        type: "attack-pattern",
        id: "attack-pattern--atlas-live-1",
        name: "Synthetic Model Evasion",
        description: "Adversaries may evade an ML model. Fixture content for the round-trip.",
        external_references: [
          { source_name: "mitre-atlas", external_id: "AML.T9999", url: "https://atlas.mitre.org/techniques/AML.T9999" },
        ],
        kill_chain_phases: [
          { kill_chain_name: "mitre-atlas", phase_name: "ml-attack-staging" },
        ],
        x_mitre_platforms: ["ML"],
        x_mitre_detection: "Watch for anomalous model queries.",
        x_mitre_version: "1.0",
      },
      {
        // Revoked — must NOT be added.
        type: "attack-pattern",
        revoked: true,
        external_references: [
          { source_name: "mitre-atlas", external_id: "AML.T0001", url: "x" },
        ],
      },
      {
        // Non-AML attack-pattern — must be filtered out (only AML.* are ATLAS).
        type: "attack-pattern",
        external_references: [
          { source_name: "mitre-attack", external_id: "T1001", url: "x" },
        ],
      },
    ],
  });
}

// --------------------------------------------------------------------------
// wrapper structural contract
// --------------------------------------------------------------------------

test("the refresh-mitre-atlas wrapper exists and imports refreshAtlas from the SoT module", () => {
  assert.ok(fs.existsSync(WRAPPER), "scripts/refresh-mitre-atlas.js must exist");
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /require\(["']\.\/refresh-upstream-catalogs\.js["']\)/,
    "the wrapper must import from the single-source-of-truth refresh module");
  assert.match(src, /refreshAtlas/,
    "the wrapper must call refreshAtlas (not re-implement the refresher)");
});

test("the wrapper parses --dry-run and wires a non-zero error exit", () => {
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /--dry-run/, "the wrapper must support the --dry-run flag");
  assert.match(src, /argv\.includes\(["']--dry-run["']\)/,
    "the dry flag must come from process.argv");
  assert.match(src, /\.catch\(/, "the wrapper must catch a rejected refresh");
  assert.match(src, /process\.exit\(1\)/, "a failed refresh must exit non-zero");
});

test("refreshAtlas is the exported function the wrapper depends on", () => {
  assert.equal(typeof UPSTREAM.refreshAtlas, "function",
    "refreshAtlas must be exported so the wrapper can import it");
  assert.ok(UPSTREAM.SOURCES.atlas, "SOURCES.atlas registry entry backs the refresher");
  assert.equal(UPSTREAM.SOURCES.atlas.name, "mitre-atlas-stix");
  assert.equal(UPSTREAM.SOURCES.atlas.run, UPSTREAM.refreshAtlas,
    "SOURCES.atlas.run must be the same function the wrapper invokes");
});

// --------------------------------------------------------------------------
// refreshAtlas behavior (what the wrapper actually runs) — network-free
// --------------------------------------------------------------------------

test("refreshAtlas adds a new AML.* technique from a synthetic STIX bundle (dependency-injected)", async () => {
  let written = null;
  const cat = { _meta: { atlas_version: "2025.01", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } };
  const deps = {
    fetchUrl: async () => atlasStixBundle(),
    loadCatalog: () => cat,
    writeCatalog: (rel, obj) => { written = { rel, obj }; },
  };

  const r = await UPSTREAM.refreshAtlas({ _deps: deps });

  assert.equal(r.added, 1, "the one live AML.T9999 technique must be added");
  assert.equal(r.backfilled, 0, "nothing pre-existed to backfill");
  assert.equal(r.atlasVersion, "2026.05", "the matrix x_mitre_version must be surfaced");
  assert.ok(written, "a changed refresh must call writeCatalog");
  assert.equal(written.rel, "atlas-ttps.json", "writes the ATLAS catalog file");

  const row = written.obj["AML.T9999"];
  assert.ok(row, "AML.T9999 must be present in the written catalog");
  assert.equal(row.name, "Synthetic Model Evasion");
  assert.equal(row.tactic, "AI Attack Staging", "kill-chain phase must map to the ATLAS tactic name");
  assert.equal(row._intake_method, "mitre-atlas-stix", "the row records its intake method");
  assert.equal(row._auto_imported, true, "auto-imported rows are flagged so operator curation is preserved");
  assert.match(row.description, /evade an ML model/i, "the short description is the first sentence");
  // Revoked + non-AML techniques must NOT appear.
  assert.equal(written.obj["AML.T0001"], undefined, "revoked AML technique must be skipped");
  assert.equal(written.obj["T1001"], undefined, "non-AML technique must be filtered out");
  // _meta is advanced + the version bumped on a real change.
  assert.equal(written.obj._meta.atlas_version, "2026.05");
  assert.notEqual(written.obj._meta.last_updated, "2026-01-01", "last_updated advances on a real change");
});

test("refreshAtlas DRY-RUN reports the add but never writes the catalog", async () => {
  let wrote = false;
  const deps = {
    fetchUrl: async () => atlasStixBundle(),
    loadCatalog: () => ({ _meta: { atlas_version: "2025.01" } }),
    writeCatalog: () => { wrote = true; },
  };
  const r = await UPSTREAM.refreshAtlas({ dry: true, _deps: deps });
  assert.equal(r.added, 1, "dry-run still reports the would-be add");
  assert.equal(wrote, false, "dry-run must NOT call writeCatalog");
});

test("refreshAtlas backfills an existing row's missing context fields instead of re-adding it", async () => {
  let written = null;
  // The catalog already has AML.T9999 but is missing description_full + platforms.
  const cat = {
    _meta: { atlas_version: "2026.05", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "AML.T9999": { id: "AML.T9999", name: "Synthetic Model Evasion", tactic: "AI Attack Staging" },
  };
  const deps = {
    fetchUrl: async () => atlasStixBundle(),
    loadCatalog: () => cat,
    writeCatalog: (rel, obj) => { written = { rel, obj }; },
  };
  const r = await UPSTREAM.refreshAtlas({ _deps: deps });
  assert.equal(r.added, 0, "the existing row must not be re-added");
  assert.equal(r.backfilled, 1, "the existing row must be backfilled with the new context fields");
  assert.ok(written, "a backfill is a change and must write");
  const row = written.obj["AML.T9999"];
  assert.ok(row.description_full, "description_full must be backfilled from the STIX description");
  assert.deepEqual(row.platforms, ["ML"], "platforms must be backfilled");
});

test("refreshAtlas leaves the catalog unwritten when nothing changes (no-op determinism)", async () => {
  let wrote = false;
  // Bundle has zero AML techniques AND the recorded version already matches.
  const emptyBundle = JSON.stringify({
    objects: [{ type: "x-mitre-matrix", name: "ATLAS Matrix", x_mitre_version: "2026.05" }],
  });
  const cat = { _meta: { atlas_version: "2026.05", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } };
  const deps = {
    fetchUrl: async () => emptyBundle,
    loadCatalog: () => cat,
    writeCatalog: () => { wrote = true; },
  };
  const r = await UPSTREAM.refreshAtlas({ _deps: deps });
  assert.equal(r.added, 0);
  assert.equal(r.backfilled, 0);
  assert.equal(wrote, false,
    "a genuine no-op (no adds, no backfills, version unchanged) must NOT write");
});

test("refreshAtlas rejects when the fetch errors (fail-closed, no partial write)", async () => {
  let wrote = false;
  const deps = {
    fetchUrl: async () => { throw new Error("simulated network failure"); },
    loadCatalog: () => ({ _meta: {} }),
    writeCatalog: () => { wrote = true; },
  };
  await assert.rejects(() => UPSTREAM.refreshAtlas({ _deps: deps }), /simulated network failure/,
    "a fetch failure must propagate (the wrapper's .catch exits non-zero)");
  assert.equal(wrote, false, "no catalog write on a failed fetch");
});
