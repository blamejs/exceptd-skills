'use strict';

/**
 * tests/collectors-scan-excludes.test.js
 *
 * Subject coverage for lib/collectors/scan-excludes.js:
 *  - lineFromOffset maps a byte offset to a 1-based line, clamping out-of-range
 *    offsets to the first / last line.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const { lineFromOffset } = require(path.join(ROOT, 'lib', 'collectors', 'scan-excludes.js'));

test("lineFromOffset maps byte offset to 1-based line", () => {
  const content = "line1\nline2\nline3";
  assert.equal(lineFromOffset(content, 0), 1);
  assert.equal(lineFromOffset(content, 6), 2);   // start of line2
  assert.equal(lineFromOffset(content, 12), 3);  // start of line3
  assert.equal(lineFromOffset(content, -5), 1);  // fallback
  assert.equal(lineFromOffset(content, 99999), 3); // clamped to content end
});

test.describe("cli-surface-drift", () => {
  const fsSD = require("node:fs");
  const osSD = require("node:os");
  const pathSD = require("node:path");
  const { walkTree } = require("../lib/collectors/scan-excludes.js");

  test("walkTree emits forward-slash rel paths so artifact summaries match SARIF evidence locations", () => {
    const root = fsSD.mkdtempSync(pathSD.join(osSD.tmpdir(), "walk-rel-"));
    try {
      fsSD.mkdirSync(pathSD.join(root, "src", "config"), { recursive: true });
      const target = pathSD.join(root, "src", "config", "app.env");
      fsSD.writeFileSync(target, "TOKEN=x");
      const files = walkTree(root);
      const hit = files.find(f => f.name === "app.env");
      assert.ok(hit, "walkTree must surface the nested file");
      assert.equal(hit.rel, "src/config/app.env");
      assert.ok(!hit.rel.includes("\\"), "rel must not contain a backslash separator");
    } finally {
      fsSD.rmSync(root, { recursive: true, force: true });
    }
  });
});
