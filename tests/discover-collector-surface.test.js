"use strict";

/**
 * tests/discover-collector-surface.test.js
 *
 * Pins the discover envelope: every entry in recommended_playbooks
 * carries collector_available + collect_cmd, both derived from
 * on-disk presence of lib/collectors/<id>.js. Human renderer prints
 * a [collector] tag + a pipe-pointer line for entries where the
 * collector exists.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    timeout: 30000,
    ...opts,
  });
}

test("discover JSON envelope: every recommendation carries collector_available + collect_cmd, matching on-disk truth", () => {
  const r = runCli(["discover", "--json"]);
  assert.equal(r.status, 0, `discover exit non-zero; stderr=${r.stderr.slice(0, 400)}`);
  const body = JSON.parse(r.stdout);
  assert.ok(Array.isArray(body.recommended_playbooks), "recommended_playbooks missing or non-array");
  assert.ok(body.recommended_playbooks.length > 0, "expected at least one recommendation from project root");

  for (const rec of body.recommended_playbooks) {
    assert.equal(typeof rec.id, "string", `rec missing id: ${JSON.stringify(rec)}`);
    assert.equal(typeof rec.collector_available, "boolean", `rec ${rec.id} missing collector_available`);
    const onDisk = fs.existsSync(path.join(ROOT, "lib", "collectors", rec.id + ".js"));
    assert.equal(rec.collector_available, onDisk,
      `rec ${rec.id}: collector_available=${rec.collector_available} but file presence=${onDisk}`);
    if (rec.collector_available) {
      assert.equal(rec.collect_cmd, `exceptd collect ${rec.id}`);
    } else {
      assert.equal(rec.collect_cmd, null);
    }
  }
});

test("discover human renderer: [collector] tag + pipe-pointer line render when collector_available is true", () => {
  const r = runCli(["discover"]);
  assert.equal(r.status, 0);
  // The project root carries a .git + a node lockfile → at least
  // secrets / sbom / library-author / crypto-codebase recommendations
  // fire, and all four have collectors.
  assert.match(r.stdout, /\[collector\]/, "expected at least one [collector] tag in human output");
  assert.match(r.stdout, /exceptd collect \S+ \| exceptd run \S+ --evidence -/,
    "expected pipe-pointer line in human output");
  // framework recommendation always fires + has no collector — must
  // appear WITHOUT a [collector] tag.
  assert.match(r.stdout, /-\s+framework\s+(?!\[collector\])/,
    "framework recommendation must not be tagged [collector]");
});
