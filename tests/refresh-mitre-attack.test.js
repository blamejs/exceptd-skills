"use strict";

/**
 * tests/refresh-mitre-attack.test.js
 *
 * Subject coverage for scripts/refresh-mitre-attack.js — the thin per-type
 * wrapper for the MITRE ATT&CK refresher.
 *
 * The wrapper fires the network refresher at require-time (top-level
 * refreshAttack(...).catch(...)), so requiring it directly would hit the live
 * MITRE CTI endpoint. We therefore test it WITHOUT requiring it:
 *
 *   1. Structural contract on the wrapper source — it imports refreshAttack
 *      from the single-source-of-truth module, parses --dry-run, reads the CAP
 *      env var, and wires the run + error-exit path.
 *   2. Behavioral coverage of refreshAttack itself (the function the wrapper
 *      executes) driven entirely off injected _deps: a synthetic ATT&CK STIX
 *      bundle fed through a fake fetchUrl, a fake in-memory catalog, and a
 *      captured writeCatalog — including the cap limit the wrapper threads
 *      through from CAP. No live network, no repo-file mutation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SCRIPTS = path.join(__dirname, "..", "scripts");
const WRAPPER = path.join(SCRIPTS, "refresh-mitre-attack.js");
// Safe to require — the module's network logic only runs under
// require.main === module, which is false on import.
const UPSTREAM = require(path.join(SCRIPTS, "refresh-upstream-catalogs.js"));

// A synthetic ATT&CK STIX bundle: two live techniques (one sub-technique) +
// one revoked technique that must be skipped on the add pass.
function attackStixBundle() {
  return JSON.stringify({
    type: "bundle",
    objects: [
      {
        type: "attack-pattern",
        id: "attack-pattern--live-1",
        name: "Synthetic Privilege Escalation",
        description: "Adversaries may abuse a synthetic primitive. Fixture content.",
        external_references: [
          { source_name: "mitre-attack", external_id: "T9001", url: "https://attack.mitre.org/techniques/T9001/" },
        ],
        kill_chain_phases: [
          { kill_chain_name: "mitre-attack", phase_name: "privilege-escalation" },
        ],
        x_mitre_platforms: ["Linux", "Windows"],
        x_mitre_is_subtechnique: false,
        x_mitre_version: "1.0",
        x_mitre_detection: "Watch for privilege-token operations.",
      },
      {
        type: "attack-pattern",
        id: "attack-pattern--live-2",
        name: "Synthetic Credential Dumping Sub",
        description: "A sub-technique fixture. More detail here.",
        external_references: [
          { source_name: "mitre-attack", external_id: "T9002.001", url: "https://attack.mitre.org/techniques/T9002/001/" },
        ],
        kill_chain_phases: [
          { kill_chain_name: "mitre-attack", phase_name: "credential-access" },
        ],
        x_mitre_is_subtechnique: true,
        x_mitre_version: "1.0",
      },
      {
        // Revoked — must NOT be added.
        type: "attack-pattern",
        revoked: true,
        external_references: [
          { source_name: "mitre-attack", external_id: "T0000", url: "x" },
        ],
      },
    ],
  });
}

// --------------------------------------------------------------------------
// wrapper structural contract
// --------------------------------------------------------------------------

test("the refresh-mitre-attack wrapper exists and imports refreshAttack from the SoT module", () => {
  assert.ok(fs.existsSync(WRAPPER), "scripts/refresh-mitre-attack.js must exist");
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /require\(["']\.\/refresh-upstream-catalogs\.js["']\)/,
    "the wrapper must import from the single-source-of-truth refresh module");
  assert.match(src, /refreshAttack/,
    "the wrapper must call refreshAttack (not re-implement the refresher)");
});

test("the wrapper parses --dry-run, reads the CAP env var, and wires a non-zero error exit", () => {
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /argv\.includes\(["']--dry-run["']\)/,
    "the dry flag must come from process.argv");
  assert.match(src, /process\.env\.CAP/,
    "the ATT&CK wrapper must honor the CAP env var (large catalog, capped batches)");
  assert.match(src, /\.catch\(/, "the wrapper must catch a rejected refresh");
  assert.match(src, /process\.exit\(1\)/, "a failed refresh must exit non-zero");
});

test("refreshAttack is the exported function the wrapper depends on", () => {
  assert.equal(typeof UPSTREAM.refreshAttack, "function",
    "refreshAttack must be exported so the wrapper can import it");
  assert.ok(UPSTREAM.SOURCES.attack, "SOURCES.attack registry entry backs the refresher");
  assert.equal(UPSTREAM.SOURCES.attack.name, "mitre-attack-stix");
  assert.equal(UPSTREAM.SOURCES.attack.run, UPSTREAM.refreshAttack,
    "SOURCES.attack.run must be the same function the wrapper invokes");
});

// --------------------------------------------------------------------------
// refreshAttack behavior (what the wrapper actually runs) — network-free
// --------------------------------------------------------------------------

test("refreshAttack adds live techniques from a synthetic STIX bundle and maps the tactic", async () => {
  let written = null;
  const cat = { _meta: { last_updated: "2026-01-01", last_threat_review: "2026-01-01" } };
  const deps = {
    fetchUrl: async () => attackStixBundle(),
    loadCatalog: () => cat,
    writeCatalog: (rel, obj) => { written = { rel, obj }; },
  };

  const r = await UPSTREAM.refreshAttack({ _deps: deps });

  assert.equal(r.added, 2, "both live techniques must be added (revoked skipped)");
  assert.equal(r.backfilled, 0, "nothing pre-existed to backfill");
  assert.ok(written, "a changed refresh must write");
  assert.equal(written.rel, "attack-techniques.json", "writes the ATT&CK catalog file");

  const t1 = written.obj["T9001"];
  assert.ok(t1, "T9001 must be present");
  assert.equal(t1.name, "Synthetic Privilege Escalation");
  assert.deepEqual(t1.tactic, ["Privilege Escalation"],
    "the kill-chain phase must map to the ATT&CK tactic display name");
  assert.deepEqual(t1.platforms, ["Linux", "Windows"]);
  assert.equal(t1.is_subtechnique, false);
  assert.equal(t1._intake_method, "mitre-attack-stix");
  assert.equal(t1._auto_imported, true);

  const t2 = written.obj["T9002.001"];
  assert.ok(t2, "the sub-technique T9002.001 must be present");
  assert.equal(t2.is_subtechnique, true);
  assert.deepEqual(t2.tactic, ["Credential Access"]);

  // Revoked technique must be absent.
  assert.equal(written.obj["T0000"], undefined, "revoked technique must not be added");
});

test("refreshAttack honors the cap (the wrapper passes CAP through as cap)", async () => {
  let written = null;
  const deps = {
    fetchUrl: async () => attackStixBundle(),
    loadCatalog: () => ({ _meta: {} }),
    writeCatalog: (rel, obj) => { written = { rel, obj }; },
  };
  // cap=1 → only the first new technique is added this run.
  const r = await UPSTREAM.refreshAttack({ cap: 1, _deps: deps });
  assert.equal(r.added, 1, "the cap must limit new adds to 1");
  const ids = Object.keys(written.obj).filter((k) => k !== "_meta");
  assert.equal(ids.length, 1, "exactly one technique row written under cap=1");
});

test("refreshAttack DRY-RUN reports adds but never writes", async () => {
  let wrote = false;
  const deps = {
    fetchUrl: async () => attackStixBundle(),
    loadCatalog: () => ({ _meta: {} }),
    writeCatalog: () => { wrote = true; },
  };
  const r = await UPSTREAM.refreshAttack({ dry: true, _deps: deps });
  assert.equal(r.added, 2, "dry-run still reports the would-be adds");
  assert.equal(wrote, false, "dry-run must NOT write");
});

test("refreshAttack backfills an existing row's missing context instead of re-adding it", async () => {
  let written = null;
  // Existing row carries only {name, version} — the classic under-populated
  // original-catalog shape that needs tactic + description backfill.
  const cat = {
    _meta: { last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "T9001": { id: "T9001", name: "Synthetic Privilege Escalation", version: "v19" },
  };
  const deps = {
    fetchUrl: async () => attackStixBundle(),
    loadCatalog: () => cat,
    writeCatalog: (rel, obj) => { written = { rel, obj }; },
  };
  const r = await UPSTREAM.refreshAttack({ _deps: deps });
  assert.equal(r.added, 1, "only the genuinely-new T9002.001 is added");
  assert.equal(r.backfilled, 1, "the existing T9001 row is backfilled, not re-added");
  const row = written.obj["T9001"];
  assert.deepEqual(row.tactic, ["Privilege Escalation"], "tactic backfilled onto the bare existing row");
  assert.deepEqual(row.platforms, ["Linux", "Windows"], "platforms backfilled");
  assert.ok(row.description, "short description backfilled");
});

test("refreshAttack leaves the catalog unwritten when nothing changes (no-op determinism)", async () => {
  let wrote = false;
  const emptyBundle = JSON.stringify({ objects: [] });
  const deps = {
    fetchUrl: async () => emptyBundle,
    loadCatalog: () => ({ _meta: { last_updated: "2026-01-01" } }),
    writeCatalog: () => { wrote = true; },
  };
  const r = await UPSTREAM.refreshAttack({ _deps: deps });
  assert.equal(r.added, 0);
  assert.equal(r.backfilled, 0);
  assert.equal(wrote, false, "an empty STIX bundle that adds/backfills nothing must NOT write");
});

test("refreshAttack rejects when the fetch errors (fail-closed, no partial write)", async () => {
  let wrote = false;
  const deps = {
    fetchUrl: async () => { throw new Error("simulated network failure"); },
    loadCatalog: () => ({ _meta: {} }),
    writeCatalog: () => { wrote = true; },
  };
  await assert.rejects(() => UPSTREAM.refreshAttack({ _deps: deps }), /simulated network failure/,
    "a fetch failure must propagate (the wrapper's .catch exits non-zero)");
  assert.equal(wrote, false, "no catalog write on a failed fetch");
});

test("refreshAttack rejects on an unparseable (non-JSON) body", async () => {
  const deps = {
    fetchUrl: async () => "<html>not json</html>",
    loadCatalog: () => ({ _meta: {} }),
    writeCatalog: () => {},
  };
  await assert.rejects(() => UPSTREAM.refreshAttack({ _deps: deps }),
    "a non-JSON STIX body must throw at JSON.parse, not silently write an empty catalog");
});
