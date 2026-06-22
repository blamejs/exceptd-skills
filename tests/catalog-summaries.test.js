"use strict";

/**
 * tests/catalog-summaries.test.js
 *
 * Behavioral coverage for scripts/builders/catalog-summaries.js
 * (buildCatalogSummaries) — the builder that compacts every data/<catalog>.json
 * into a single discovery index of purpose / version / freshness / entry count.
 *
 * Strategy: exercise the pure builder against fixture catalogs written into an
 * os.tmpdir() tree (full control of the _meta shapes + a parse-error path), and
 * additionally smoke it against the live data/ tree read-only for realism.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { buildCatalogSummaries } = require("../scripts/builders/catalog-summaries.js");

const REPO_ROOT = path.join(__dirname, "..");

function tmpRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "catsum-"));
}
function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best effort */
  }
}
function writeCatalog(root, rel, obj) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, typeof obj === "string" ? obj : JSON.stringify(obj));
}

test("module contract: exports buildCatalogSummaries as a function", () => {
  assert.equal(typeof buildCatalogSummaries, "function");
});

test("envelope shape: _meta + catalogs map with a correct catalog_count", () => {
  const root = tmpRoot();
  try {
    writeCatalog(root, "data/cve-catalog.json", {
      _meta: { schema_version: "2.1", last_updated: "2026-06-01", tlp: "CLEAR" },
      "CVE-2026-0001": { cvss: 9.8 },
      "CVE-2026-0002": { cvss: 7.5 },
    });
    writeCatalog(root, "data/cwe-catalog.json", {
      _meta: { last_verified: "2026-05-20" },
      "CWE-79": {},
    });
    const out = buildCatalogSummaries({
      root,
      catalogFiles: ["data/cve-catalog.json", "data/cwe-catalog.json"],
    });

    assert.equal(out._meta.schema_version, "1.0.0");
    assert.equal(out._meta.catalog_count, 2);
    assert.equal(typeof out._meta.note, "string");
    assert.ok(out.catalogs["cve-catalog.json"]);
    assert.ok(out.catalogs["cwe-catalog.json"]);
    assert.equal(Object.keys(out.catalogs).length, 2);
  } finally {
    rmrf(root);
  }
});

test("entry_count excludes underscore-prefixed keys; sample_keys is capped at 5", () => {
  const root = tmpRoot();
  try {
    const big = { _meta: { schema_version: "1" }, _note: "ignored" };
    for (let i = 0; i < 8; i++) big["E-" + i] = { i };
    writeCatalog(root, "data/big.json", big);

    const out = buildCatalogSummaries({ root, catalogFiles: ["data/big.json"] });
    const s = out.catalogs["big.json"];
    // 8 real entries; _meta and _note must not be counted.
    assert.equal(s.entry_count, 8);
    assert.equal(s.sample_keys.length, 5);
    assert.ok(!s.sample_keys.some((k) => k.startsWith("_")), "no underscore keys leak into sample");
  } finally {
    rmrf(root);
  }
});

test("_meta fields are surfaced; last_updated falls back to last_verified", () => {
  const root = tmpRoot();
  try {
    writeCatalog(root, "data/a.json", {
      _meta: {
        schema_version: "3.0",
        last_verified: "2026-04-04", // no last_updated -> fallback path
        tlp: "AMBER",
        source_confidence: { default: "B2" },
        freshness_policy: "weekly",
      },
      "X-1": {},
    });
    const out = buildCatalogSummaries({ root, catalogFiles: ["data/a.json"] });
    const s = out.catalogs["a.json"];
    assert.equal(s.schema_version, "3.0");
    assert.equal(s.last_updated, "2026-04-04");
    assert.equal(s.tlp, "AMBER");
    assert.equal(s.source_confidence_default, "B2");
    assert.equal(s.freshness_policy, "weekly");
    assert.equal(s.path, "data/a.json");
  } finally {
    rmrf(root);
  }
});

test("missing _meta yields null fields rather than throwing", () => {
  const root = tmpRoot();
  try {
    writeCatalog(root, "data/bare.json", { "K-1": {}, "K-2": {} });
    const out = buildCatalogSummaries({ root, catalogFiles: ["data/bare.json"] });
    const s = out.catalogs["bare.json"];
    assert.equal(s.schema_version, null);
    assert.equal(s.last_updated, null);
    assert.equal(s.tlp, null);
    assert.equal(s.source_confidence_default, null);
    assert.equal(s.entry_count, 2);
  } finally {
    rmrf(root);
  }
});

test("known catalog basenames get a curated purpose; unknown ones get null", () => {
  const root = tmpRoot();
  try {
    writeCatalog(root, "data/cve-catalog.json", { _meta: {}, "CVE-2026-1": {} });
    writeCatalog(root, "data/unknown-catalog.json", { _meta: {}, "X": {} });
    const out = buildCatalogSummaries({
      root,
      catalogFiles: ["data/cve-catalog.json", "data/unknown-catalog.json"],
    });
    assert.equal(typeof out.catalogs["cve-catalog.json"].purpose, "string");
    assert.ok(out.catalogs["cve-catalog.json"].purpose.length > 0);
    assert.equal(out.catalogs["unknown-catalog.json"].purpose, null);
  } finally {
    rmrf(root);
  }
});

test("negative path: a malformed JSON catalog records a parse_error, others still summarized", () => {
  const root = tmpRoot();
  try {
    writeCatalog(root, "data/good.json", { _meta: {}, "G-1": {} });
    writeCatalog(root, "data/broken.json", "{ this is : not json ");
    const out = buildCatalogSummaries({
      root,
      catalogFiles: ["data/good.json", "data/broken.json"],
    });
    assert.ok(out.catalogs["good.json"].entry_count === 1);
    assert.ok(
      /^parse_error:/.test(out.catalogs["broken.json"].error),
      `expected parse_error marker, got ${JSON.stringify(out.catalogs["broken.json"])}`
    );
    // A broken catalog still counts toward catalog_count (it has a summary entry).
    assert.equal(out._meta.catalog_count, 2);
  } finally {
    rmrf(root);
  }
});

test("empty catalogFiles produces an empty catalogs map, not an error", () => {
  const root = tmpRoot();
  try {
    const out = buildCatalogSummaries({ root, catalogFiles: [] });
    assert.deepEqual(out.catalogs, {});
    assert.equal(out._meta.catalog_count, 0);
  } finally {
    rmrf(root);
  }
});

test("smoke against the live data/ tree: every summarized catalog has a numeric entry_count", () => {
  const dataDir = path.join(REPO_ROOT, "data");
  const catalogFiles = fs
    .readdirSync(dataDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => "data/" + f);
  const out = buildCatalogSummaries({ root: REPO_ROOT, catalogFiles });
  assert.equal(Object.keys(out.catalogs).length, catalogFiles.length);
  for (const [base, s] of Object.entries(out.catalogs)) {
    assert.ok(!("error" in s), `live catalog ${base} failed to parse: ${s.error}`);
    assert.ok(Number.isInteger(s.entry_count) && s.entry_count >= 0);
    assert.ok(Array.isArray(s.sample_keys) && s.sample_keys.length <= 5);
  }
});
