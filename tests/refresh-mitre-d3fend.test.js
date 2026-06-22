"use strict";

/**
 * tests/refresh-mitre-d3fend.test.js
 *
 * scripts/refresh-mitre-d3fend.js is a thin per-type wrapper that imports
 * refreshD3fend from scripts/refresh-upstream-catalogs.js and runs it. The
 * wrapper itself has no exported surface and its only side effect is calling
 * the refresher (which hits live MITRE D3FEND on a real run), so the wrapper
 * is tested two ways, neither of which touches the network or mutates a
 * tracked file:
 *
 *   1. The wrapper contract — the file imports refreshD3fend from the
 *      single-source-of-truth module and is wired as the npm alias.
 *   2. The behavior of the refresher the wrapper delegates to — exercised in
 *      isolation with injected fetch/load/write deps against a synthetic
 *      D3FEND ontology fixture in a tempdir. This proves the wrapper's
 *      delegate actually adds rows, backfills empty fields on curated rows,
 *      stamps _meta only on a real change, and leaves the catalog
 *      byte-identical on a no-op.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SCRIPTS = path.join(__dirname, "..", "scripts");
const WRAPPER = path.join(SCRIPTS, "refresh-mitre-d3fend.js");
const MOD = require(path.join(SCRIPTS, "refresh-upstream-catalogs.js"));

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "d3fend-wrap-"));
}

// A synthetic D3FEND ontology body in the @graph/OWL shape the refresher
// walks. Each technique node carries the @id + d3f:d3fend-id + rdfs:label the
// `techs` filter requires, plus relationship fields the entry-builder reads.
function d3fendOntology(nodes) {
  return JSON.stringify({ "@graph": nodes });
}

function techNode({ id, label, def, counters, broader }) {
  return {
    "@id": `d3f:${label.replace(/\s+/g, "")}`,
    "d3f:d3fend-id": id,
    "rdfs:label": label,
    "d3f:definition": def,
    ...(counters ? { "d3f:counters": counters.map((c) => ({ "@id": `d3f:${c}` })) } : {}),
    ...(broader ? { "d3f:broader": { "@id": `d3f:${broader}` } } : {}),
  };
}

test("wrapper imports refreshD3fend from the single-source-of-truth module", () => {
  assert.ok(fs.existsSync(WRAPPER), "scripts/refresh-mitre-d3fend.js must exist");
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /require\(["']\.\/refresh-upstream-catalogs\.js["']\)/,
    "wrapper must import from refresh-upstream-catalogs.js (no parallel logic)");
  assert.match(src, /refreshD3fend/,
    "wrapper must call refreshD3fend");
  assert.match(src, /--dry-run/,
    "wrapper must honor the --dry-run flag operators pass");
  assert.match(src, /process\.env\.CAP/,
    "wrapper must honor the CAP env cap documented in its header");
});

test("refreshD3fend (the wrapper's delegate) is exported and registered", () => {
  assert.equal(typeof MOD.refreshD3fend, "function",
    "refreshD3fend must be exported so the wrapper can import it");
  assert.ok(MOD.SOURCES && MOD.SOURCES.d3fend,
    "SOURCES.d3fend must be registered");
  assert.equal(MOD.SOURCES.d3fend.name, "mitre-d3fend-owl",
    "SOURCES.d3fend.name declares the _intake_method tag stamped on imported rows");
  assert.equal(MOD.SOURCES.d3fend.run, MOD.refreshD3fend,
    "the registry run target must be the same function the wrapper imports");
});

test("refreshD3fend adds a new technique row with the documented context fields", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const ontology = d3fendOntology([
    techNode({
      id: "D3-NTA",
      label: "Network Traffic Analysis",
      def: "Analyzing network traffic to detect adversary activity. Fixture body.",
      counters: ["T1071"],
      broader: "Detect",
    }),
  ]);

  const deps = {
    fetchUrl: async () => ontology,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshD3fend({ _deps: deps });
  assert.equal(r.added, 1, "the new D3-NTA technique must be added");
  assert.equal(r.backfilled, 0, "nothing to backfill on a fresh add");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const row = after["D3-NTA"];
  assert.ok(row, "D3-NTA row present after the add");
  assert.equal(row.name, "Network Traffic Analysis", "rdfs:label becomes the row name");
  assert.equal(row.tactic, "Detect",
    "Network Traffic Analysis maps to the Detect tactic via d3fendTactic");
  assert.ok(typeof row.description === "string" && row.description.length > 0,
    "the first-sentence short description is extracted");
  assert.deepEqual(row.counters, ["T1071"],
    "d3f:counters relationship is extracted as a stripped id list");
  assert.equal(row._auto_imported, true, "imported row is marked _auto_imported");
  assert.equal(row._intake_method, "mitre-d3fend-owl",
    "imported row records the upstream intake method");
  assert.notEqual(after._meta.last_updated, "2026-01-01",
    "_meta.last_updated advances when a row was actually added");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshD3fend backfills empty fields on a curated row WITHOUT overwriting populated ones", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  // Operator-curated row: name + description already set (must be preserved),
  // counters empty (must be backfilled from the ontology).
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "D3-NTA": {
      id: "D3-NTA",
      name: "Curated Name",
      description: "Curated description that must survive.",
      counters: [],
    },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const ontology = d3fendOntology([
    techNode({
      id: "D3-NTA",
      label: "Network Traffic Analysis",
      def: "Upstream definition. Fixture body.",
      counters: ["T1071", "T1095"],
    }),
  ]);

  const deps = {
    fetchUrl: async () => ontology,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshD3fend({ _deps: deps });
  assert.equal(r.added, 0, "no new row — D3-NTA already existed");
  assert.equal(r.backfilled, 1, "the curated row gets its empty fields backfilled");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const row = after["D3-NTA"];
  assert.equal(row.name, "Curated Name", "curated name preserved (not overwritten)");
  assert.equal(row.description, "Curated description that must survive.",
    "curated description preserved (not overwritten)");
  assert.deepEqual(row.counters, ["T1071", "T1095"],
    "the empty counters array is backfilled from the ontology");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshD3fend no-op leaves the catalog byte-identical (no _meta-only restamp)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  // Row already fully populated, so every fillIfEmpty is a no-op and nothing
  // is added — the changed flag must stay false and writeCatalog must not run.
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "D3-NTA": {
      id: "D3-NTA",
      name: "Network Traffic Analysis",
      tactic: "Detect",
      description: "x.",
      description_full: "x",
      synonyms: ["s"],
      defends_against: ["d"],
      counters: ["T1071"],
      enables: ["e"],
      broader_of: ["b"],
      narrower_of: ["n"],
      requires: ["r"],
      inventories: ["i"],
      kb_reference: "k",
      reference_url: "u",
    },
  };
  const beforeBytes = JSON.stringify(cat, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const ontology = d3fendOntology([
    techNode({ id: "D3-NTA", label: "Network Traffic Analysis", def: "x" }),
  ]);
  const deps = {
    fetchUrl: async () => ontology,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshD3fend({ _deps: deps });
  assert.equal(r.added, 0, "no add on a fully-populated catalog");
  assert.equal(r.backfilled, 0, "no backfill on a fully-populated catalog");
  assert.equal(wrote, false, "a genuine no-op must NOT call writeCatalog");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "the catalog must be byte-identical after a no-op (no _meta-only diff)");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshD3fend --dry-run reports counts but never writes", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
  };
  const beforeBytes = JSON.stringify(cat, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const ontology = d3fendOntology([
    techNode({ id: "D3-NTA", label: "Network Traffic Analysis", def: "Detect adversary traffic." }),
  ]);
  const deps = {
    fetchUrl: async () => ontology,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshD3fend({ dry: true, _deps: deps });
  assert.equal(r.added, 1, "dry-run still reports the would-add count");
  assert.equal(wrote, false, "dry-run must NOT write the catalog");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "the on-disk catalog must be untouched after a dry-run");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshD3fend honors the cap on new adds", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const ontology = d3fendOntology([
    techNode({ id: "D3-A", label: "Aaa Bbb", def: "first." }),
    techNode({ id: "D3-B", label: "Ccc Ddd", def: "second." }),
    techNode({ id: "D3-C", label: "Eee Fff", def: "third." }),
  ]);
  const deps = {
    fetchUrl: async () => ontology,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshD3fend({ cap: 2, _deps: deps });
  assert.equal(r.added, 2, "cap=2 must stop adds at 2 even with 3 ontology techniques");
  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const rowCount = Object.keys(after).filter((k) => k !== "_meta").length;
  assert.equal(rowCount, 2, "only 2 rows written under cap=2");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshD3fend surfaces a fetch error (does not silently swallow it)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "d3fend-catalog.json");
  fs.writeFileSync(file, JSON.stringify({ _meta: {} }, null, 2) + "\n");

  let wrote = false;
  const deps = {
    fetchUrl: async () => { throw new Error("HTTP 503 for d3fend"); },
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: () => { wrote = true; },
  };

  await assert.rejects(() => MOD.refreshD3fend({ _deps: deps }), /HTTP 503/,
    "a fetch rejection must propagate out of refreshD3fend, not be swallowed");
  assert.equal(wrote, false, "no catalog write when the fetch failed");

  fs.rmSync(dir, { recursive: true, force: true });
});
