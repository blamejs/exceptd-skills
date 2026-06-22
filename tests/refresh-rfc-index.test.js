"use strict";

/**
 * tests/refresh-rfc-index.test.js
 *
 * scripts/refresh-rfc-index.js is a thin per-type wrapper that imports
 * refreshRfc from scripts/refresh-upstream-catalogs.js and runs it. On a real
 * run it fetches the IETF RFC index and writes data/rfc-references.json. The
 * wrapper has no exported surface, so it is tested via (1) the wrapper-import
 * contract and (2) the behavior of the refresher it delegates to — exercised
 * with injected fetch/load/write deps against synthetic IETF index XML in a
 * tempdir. No network, no tracked file mutation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SCRIPTS = path.join(__dirname, "..", "scripts");
const WRAPPER = path.join(SCRIPTS, "refresh-rfc-index.js");
const MOD = require(path.join(SCRIPTS, "refresh-upstream-catalogs.js"));

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rfc-wrap-"));
}

// One <rfc-entry> block with the given fields. status defaults to a current
// series so the entry is eligible for new-add.
function rfcEntry({ num, title, status = "PROPOSED STANDARD", obsoletedBy = null, abstract = null }) {
  return `<rfc-entry>
<doc-id>RFC${String(num).padStart(4, "0")}</doc-id>
<title>${title}</title>
<current-status>${status}</current-status>
<date><month>May</month><year>2026</year></date>
${abstract ? `<abstract><p>${abstract}</p></abstract>` : ""}
${obsoletedBy ? `<obsoleted-by><doc-id>RFC${String(obsoletedBy).padStart(4, "0")}</doc-id></obsoleted-by>` : ""}
</rfc-entry>`;
}

function rfcIndex(entries) {
  return `<?xml version="1.0"?>\n<rfc-index>\n${entries.join("\n")}\n</rfc-index>`;
}

test("wrapper imports refreshRfc from the single-source-of-truth module", () => {
  assert.ok(fs.existsSync(WRAPPER), "scripts/refresh-rfc-index.js must exist");
  const src = fs.readFileSync(WRAPPER, "utf8");
  assert.match(src, /require\(["']\.\/refresh-upstream-catalogs\.js["']\)/,
    "wrapper must import from refresh-upstream-catalogs.js (no parallel logic)");
  assert.match(src, /refreshRfc/, "wrapper must call refreshRfc");
  assert.match(src, /--dry-run/, "wrapper must honor --dry-run");
});

test("refreshRfc (the wrapper's delegate) is exported and registered", () => {
  assert.equal(typeof MOD.refreshRfc, "function",
    "refreshRfc must be exported so the wrapper can import it");
  assert.ok(MOD.SOURCES && MOD.SOURCES.rfc, "SOURCES.rfc must be registered");
  assert.equal(MOD.SOURCES.rfc.name, "ietf-rfc-index",
    "SOURCES.rfc.name declares the canonical intake-method tag");
  assert.equal(MOD.SOURCES.rfc.run, MOD.refreshRfc,
    "the registry run target must be the function the wrapper imports");
});

test("refreshRfc adds a new current RFC with the mapped status + imported markers", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  fs.writeFileSync(file, JSON.stringify(
    { _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } },
    null, 2) + "\n");

  const body = rfcIndex([
    rfcEntry({ num: 9999, title: "Synthetic Test Standard", status: "PROPOSED STANDARD", abstract: "A synthetic abstract." }),
  ]);

  const deps = {
    fetchUrl: async () => body,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 1, "RFC-9999 must be added");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const row = after["RFC-9999"];
  assert.ok(row, "RFC-9999 row present");
  assert.equal(row.number, 9999);
  assert.equal(row.title, "Synthetic Test Standard");
  assert.equal(row.status, "Proposed Standard",
    "the upper-case index status maps to the canonical RFC_STATUS_MAP form");
  assert.equal(row.abstract, "A synthetic abstract.", "abstract extracted from the index");
  assert.equal(row._auto_imported, true);
  assert.equal(row._intake_method, "ietf-rfc-index");
  assert.match(row.txt_url, /rfc9999\.txt$/, "the canonical txt_url is synthesized");
  assert.notEqual(after._meta.last_updated, "2026-01-01", "_meta advances on a real add");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc THROWS on a zero-entry (error/empty) body and does not write", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  const beforeBytes = JSON.stringify(
    { _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" } },
    null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const deps = {
    fetchUrl: async () => "<html><body>503 error page, no rfc-entry blocks</body></html>",
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: () => { wrote = true; },
  };

  await assert.rejects(() => MOD.refreshRfc({ _deps: deps }), /parsed 0 entries/,
    "a body that parses to zero RFC entries must be refused (never stamp _meta on a non-fetch)");
  assert.equal(wrote, false, "no write on a zero-entry fetch");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "catalog byte-identical after the refused refresh (no stale staleness advance)");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc no-op leaves the catalog byte-identical (no _meta-only restamp)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  // RFC-9999 already fully populated → 0 added / 0 backfilled / 0 status bumps.
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "RFC-9999": {
      number: 9999, title: "Synthetic Test Standard", status: "Proposed Standard", published: "2026-05",
      authors: ["A"], stream: "IETF", area: "sec", working_group: "tls",
      abstract: "A synthetic abstract.", keywords: ["k"], page_count: 1, doi: "10.x/RFC9999",
      obsoletes: [], updates: [], updated_by: [], obsoleted_by: [], is_also: [],
      errata_count: 0, tracker: "t", txt_url: "tx", html_url: "ht",
      relevance: "r", skills_referencing: [], last_verified: "2026-05-01",
    },
  };
  const beforeBytes = JSON.stringify(cat, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const body = rfcIndex([rfcEntry({ num: 9999, title: "Synthetic Test Standard", abstract: "A synthetic abstract." })]);
  const deps = {
    fetchUrl: async () => body,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 0, "no add");
  assert.equal(r.backfilled, 0, "no backfill (row already complete)");
  assert.equal(r.statusBumped, 0, "no status bump");
  assert.equal(wrote, false, "a genuine no-op must NOT write");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "catalog byte-identical after a no-op refresh");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc backfills an abstract onto an existing row lacking one", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    // Existing row with NO abstract; the backfill pass should add it.
    "RFC-9999": { number: 9999, title: "Synthetic Test Standard", status: "Proposed Standard", _auto_imported: true },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const body = rfcIndex([
    rfcEntry({ num: 9999, title: "Synthetic Test Standard", abstract: "Backfilled abstract text." }),
  ]);
  const deps = {
    fetchUrl: async () => body,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 0, "no new row — RFC-9999 already existed");
  assert.ok(r.backfilled >= 1, "the existing row gets at least the abstract backfilled");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(after["RFC-9999"].abstract, "Backfilled abstract text.",
    "the empty abstract is backfilled from the index");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc marks an obsoleted RFC with _obsoleted when adding it", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  fs.writeFileSync(file, JSON.stringify({ _meta: { last_updated: "2026-01-01" } }, null, 2) + "\n");

  const body = rfcIndex([
    rfcEntry({ num: 8000, title: "Old Standard", status: "PROPOSED STANDARD", obsoletedBy: 9000 }),
  ]);
  const deps = {
    fetchUrl: async () => body,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 1, "an obsoleted RFC is still added (for offline 'superseded by' answers)");
  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const row = after["RFC-8000"];
  assert.ok(row, "RFC-8000 present");
  assert.equal(row._obsoleted, true, "an obsoleted-by RFC carries the _obsoleted marker");
  assert.deepEqual(row.obsoleted_by, ["RFC9000"], "obsoleted_by relationship captured");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc --dry-run reports counts but never writes", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  const beforeBytes = JSON.stringify({ _meta: { last_updated: "2026-01-01" } }, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const body = rfcIndex([rfcEntry({ num: 7777, title: "Dry Run RFC" })]);
  const deps = {
    fetchUrl: async () => body,
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: () => { wrote = true; },
  };

  const r = await MOD.refreshRfc({ dry: true, _deps: deps });
  assert.equal(r.added, 1, "dry-run reports the would-add count");
  assert.equal(wrote, false, "dry-run must NOT write");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes, "file untouched after dry-run");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("refreshRfc surfaces a fetch error (does not swallow it)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  fs.writeFileSync(file, JSON.stringify({ _meta: {} }, null, 2) + "\n");

  let wrote = false;
  const deps = {
    fetchUrl: async () => { throw new Error("HTTP 503 for rfc"); },
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: () => { wrote = true; },
  };

  await assert.rejects(() => MOD.refreshRfc({ _deps: deps }), /HTTP 503/,
    "a fetch rejection must propagate out of refreshRfc");
  assert.equal(wrote, false, "no write when the fetch failed");

  fs.rmSync(dir, { recursive: true, force: true });
});
