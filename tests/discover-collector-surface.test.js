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

test("discover recommends cicd-pipeline-compromise when .github/workflows/ exists at cwd", () => {
  // The exceptd repo itself has .github/workflows/ — running discover
  // here MUST surface cicd-pipeline-compromise in the recommendation
  // list. (Stream-1 finding F1.1: before this fix, the 4 collectors
  // cicd / mcp / ai-api / crypto were never surfaced by discover.)
  const r = runCli(["discover", "--json"]);
  const body = JSON.parse(r.stdout);
  const ids = body.recommended_playbooks.map(p => p.id);
  assert.ok(ids.includes("cicd-pipeline-compromise"),
    `cicd-pipeline-compromise must be recommended (cwd has .github/workflows/); got: ${ids.join(", ")}`);
  // Its reason text should mention the trigger artifact.
  const rec = body.recommended_playbooks.find(p => p.id === "cicd-pipeline-compromise");
  assert.match(rec.reason, /\.github\/workflows\//);
});

test("discover reason text uses 'project' (not 'lockfile') so package.json-only repos aren't misrepresented", () => {
  // The exceptd repo has package-lock.json, but the heuristic now
  // labels the reason as 'node project' rather than 'node lockfile'
  // so repos with only package.json (e.g. expressjs/express) don't
  // claim a lockfile that doesn't exist. F1.2.
  const r = runCli(["discover", "--json"]);
  const body = JSON.parse(r.stdout);
  const sec = body.recommended_playbooks.find(p => p.id === "secrets");
  assert.ok(sec, "secrets must be recommended on the exceptd repo");
  assert.match(sec.reason, /project/, `reason text should say 'project' not 'lockfile'; got: ${sec.reason}`);
  assert.doesNotMatch(sec.reason, /lockfile/, "reason text must not claim 'lockfile' for the broad node-detection trigger");
});

test("discover human renderer omits `--scope code` next-step when no code playbooks were recommended", () => {
  // Run discover from a fresh tempdir with no .git / no manifest /
  // no Dockerfile → recommendations should be empty-of-code-scope,
  // and the next-step list must NOT include `--scope code`. F2.3.
  const os = require("node:os");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "discover-empty-"));
  try {
    const r = runCli(["discover"], { cwd: tmp });
    assert.equal(r.status, 0);
    assert.doesNotMatch(r.stdout, /exceptd run --scope code/,
      "next-step `--scope code` must NOT appear when no code-scope playbooks were recommended");
    assert.doesNotMatch(r.stdout, /exceptd ci --scope code/,
      "next-step `ci --scope code` must NOT appear when no code-scope playbooks were recommended");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("help section header omits any pinned-version text", () => {
  // Help should not lead with a version tag in the section header.
  // The header IS the surface; the version belongs in CHANGELOG /
  // git tags, not in operator-facing help prose.
  const r = runCli(["help"]);
  assert.equal(r.status, 0);
  assert.doesNotMatch(r.stdout, /v\d+\.\d+\.\d+ canonical surface/,
    "help text section header must not pin a version tag");
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
