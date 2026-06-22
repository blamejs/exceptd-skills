"use strict";

/**
 * tests/refresh-mitre-ics-attack.test.js
 *
 * scripts/refresh-mitre-ics-attack.js is a thin per-type wrapper that imports
 * refreshIcsAttack from scripts/refresh-upstream-catalogs.js and runs it. On a
 * real run it fetches the MITRE ICS-ATT&CK STIX bundle and writes ICS rows
 * into data/attack-techniques.json. The wrapper has no exported surface, so it
 * is tested via (1) the wrapper-import contract and (2) the behavior of the
 * refresher it delegates to — exercised with injected fetch/load/write deps
 * against a synthetic ICS STIX bundle in a tempdir. No network, no tracked
 * file mutation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SCRIPTS = path.join(__dirname, "..", "scripts");
const WRAPPER = path.join(SCRIPTS, "refresh-mitre-ics-attack.js");
const MOD = require(path.join(SCRIPTS, "refresh-upstream-catalogs.js"));

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ics-wrap-"));
}

// A synthetic ICS-ATT&CK STIX bundle. The refresher filters attack-pattern
// objects that are not revoked/deprecated, reads the external_id from a
// mitre-ics-attack (or mitre-attack) reference, and maps kill_chain phases
// whose kill_chain_name contains "ics" through ICS_TACTIC_NAME.
function icsStix(objects) {
  return JSON.stringify({ type: "bundle", objects });
}

function icsTech({ id, name, desc, phase = "inhibit-response-function", revoked = false, deprecated = false }) {
  return {
    type: "attack-pattern",
    id: `attack-pattern--${id}`,
    name,
    description: desc,
    ...(revoked ? { revoked: true } : {}),
    ...(deprecated ? { x_mitre_deprecated: true } : {}),
    external_references: [
      { source_name: "mitre-ics-attack", external_id: id, url: `https://attack.mitre.org/techniques/${id}/` },
    ],
    kill_chain_phases: [{ kill_chain_name: "mitre-ics-attack", phase_name: phase }],
    x_mitre_platforms: ["Field Controller/RTU/PLC/IED"],
  };
}

test("wrapper imports refreshIcsAttack from the single-source-of-truth module", () => {
  assert.ok(fs.existsSync(WRAPPER), "scripts/refresh-mitre-ics-attack.js must exist");
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /require\(["']\.\/refresh-upstream-catalogs\.js["']\)/,
    "wrapper must import from refresh-upstream-catalogs.js (no parallel logic)");
  assert.match(src, /refreshIcsAttack/, "wrapper must call refreshIcsAttack");
  assert.match(src, /--dry-run/, "wrapper must honor --dry-run");
});

test("refreshIcsAttack (the wrapper's delegate) is exported and registered", () => {
  assert.equal(typeof MOD.refreshIcsAttack, "function",
    "refreshIcsAttack must be exported so the wrapper can import it");
  assert.ok(MOD.SOURCES && MOD.SOURCES["ics-attack"],
    "SOURCES['ics-attack'] must be registered");
  assert.equal(MOD.SOURCES["ics-attack"].name, "mitre-ics-attack-stix",
    "SOURCES['ics-attack'].name declares the _intake_method tag");
  assert.equal(MOD.SOURCES["ics-attack"].run, MOD.refreshIcsAttack,
    "the registry run target must be the function the wrapper imports");
});

test("refreshIcsAttack adds a new ICS technique with ICS-tagged tactic + intake method", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  fs.writeFileSync(file, JSON.stringify(
    { _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } },
    null, 2) + "\n");

  const stix = icsStix([
    icsTech({ id: "T0816", name: "Device Restart/Shutdown", desc: "Adversaries may forcibly restart a device. Fixture.", phase: "inhibit-response-function" }),
  ]);

  const deps = {
    fetchUrl: async () => stix,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshIcsAttack({ _deps: deps });
  assert.equal(r.added, 1, "T0816 must be added");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const row = after["T0816"];
  assert.ok(row, "T0816 row present");
  assert.equal(row.name, "Device Restart/Shutdown");
  assert.equal(row._matrix, "ics-attack", "ICS rows carry the _matrix tag");
  assert.equal(row._intake_method, "mitre-ics-attack-stix");
  assert.equal(row.version, "ics-attack-v15");
  assert.deepEqual(row.tactic, ["Inhibit Response Function"],
    "the inhibit-response-function phase maps through ICS_TACTIC_NAME");
  assert.ok(typeof row.description === "string" && row.description.endsWith("."),
    "the short description is sentence-terminated");
  assert.notEqual(after._meta.last_updated, "2026-01-01",
    "_meta advances on a real add");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshIcsAttack skips revoked/deprecated techniques", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  fs.writeFileSync(file, JSON.stringify({ _meta: {} }, null, 2) + "\n");

  const stix = icsStix([
    icsTech({ id: "T0001", name: "Live", desc: "Live technique." }),
    icsTech({ id: "T0002", name: "Revoked", desc: "Revoked technique.", revoked: true }),
    icsTech({ id: "T0003", name: "Deprecated", desc: "Deprecated technique.", deprecated: true }),
  ]);

  const deps = {
    fetchUrl: async () => stix,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshIcsAttack({ _deps: deps });
  assert.equal(r.added, 1, "only the live technique is added; revoked + deprecated are skipped");
  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(after["T0001"], "live technique present");
  assert.equal(after["T0002"], undefined, "revoked technique not imported");
  assert.equal(after["T0003"], undefined, "deprecated technique not imported");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshIcsAttack backfills an existing curated row instead of duplicating it", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  // Curated row exists with only name/version; the ICS refresher should
  // backfill its empty description/platforms, not add a second T0816.
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "T0816": { id: "T0816", name: "Device Restart/Shutdown", version: "ics-attack-v15" },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const stix = icsStix([
    icsTech({ id: "T0816", name: "Device Restart/Shutdown", desc: "Upstream description. Fixture body." }),
  ]);

  const deps = {
    fetchUrl: async () => stix,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshIcsAttack({ _deps: deps });
  assert.equal(r.added, 0, "no new row — T0816 already existed");
  assert.equal(r.backfilled, 1, "the curated row's empty fields are backfilled");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const rowCount = Object.keys(after).filter((k) => k !== "_meta").length;
  assert.equal(rowCount, 1, "no duplicate row created");
  assert.ok(after["T0816"].description, "description backfilled onto the curated row");
  assert.equal(after["T0816"].name, "Device Restart/Shutdown", "curated name preserved");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshIcsAttack --dry-run reports counts but never writes", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  const beforeBytes = JSON.stringify({ _meta: {} }, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const stix = icsStix([icsTech({ id: "T0817", name: "Drive-by", desc: "x." })]);
  const deps = {
    fetchUrl: async () => stix,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshIcsAttack({ dry: true, _deps: deps });
  assert.equal(r.added, 1, "dry-run reports the would-add count");
  assert.equal(wrote, false, "dry-run must NOT write");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes, "file untouched after dry-run");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshIcsAttack no-op (no live techniques) leaves the catalog byte-identical", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  const beforeBytes = JSON.stringify(
    { _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } },
    null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  // Only a revoked technique → nothing added, nothing backfilled → no-op.
  const stix = icsStix([icsTech({ id: "T0099", name: "Gone", desc: "x.", revoked: true })]);
  const deps = {
    fetchUrl: async () => stix,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshIcsAttack({ _deps: deps });
  assert.equal(r.added, 0, "nothing added");
  assert.equal(r.backfilled, 0, "nothing backfilled");
  assert.equal(wrote, false, "no write on a genuine no-op");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "catalog byte-identical after a no-op (no _meta-only restamp)");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshIcsAttack surfaces invalid JSON from the fetch (does not swallow it)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "attack-techniques.json");
  fs.writeFileSync(file, JSON.stringify({ _meta: {} }, null, 2) + "\n");

  let wrote = false;
  const deps = {
    fetchUrl: async () => "<html>not json error page</html>",
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: () => { wrote = true; },
  };

  await assert.rejects(() => MOD.refreshIcsAttack({ _deps: deps }),
    "a non-JSON fetch body must make refreshIcsAttack reject, not write garbage");
  assert.equal(wrote, false, "no write when the STIX body could not be parsed");

  fs.rmSync(dir, { recursive: true, force: true });
});
