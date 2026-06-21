"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const ROOT = path.join(__dirname, "..");
const CATALOG = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));

test("MAL-2024-PYPI-ULTRALYTICS-XMRIG is present and well-formed in the catalog", () => {
  const e = CATALOG["MAL-2024-PYPI-ULTRALYTICS-XMRIG"];
  assert.ok(e, "MAL-2024-PYPI-ULTRALYTICS-XMRIG must exist in data/cve-catalog.json");
  assert.ok(e.rwep_factors && typeof e.rwep_factors === "object", "carries rwep_factors");
  assert.equal(typeof e.rwep_score, "number", "carries a numeric rwep_score");
});
