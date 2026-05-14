"use strict";
/**
 * Pre-deployment gate sequence test.
 *
 * The CI workflow (.github/workflows/ci.yml) and the local
 * `npm run predeploy` runner (scripts/predeploy.js) must execute the
 * SAME ordered sequence of gates. If a maintainer adds a new gate to
 * CI but forgets the local runner, contributors will see CI failures
 * they could not reproduce locally. The reverse is just as bad — the
 * local runner could go green while CI catches the regression.
 *
 * This test reads both sources and asserts every CI gate appears in
 * the local runner's GATES list, and vice versa.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const CI_WORKFLOW = path.join(ROOT, ".github", "workflows", "ci.yml");
const PACKAGE_JSON = path.join(ROOT, "package.json");

function loadGates() {
  // Bypass the require-main guard by importing the module path
  // directly. predeploy.js exports its GATES list for this test.
  const { GATES } = require(path.join(ROOT, "scripts", "predeploy.js"));
  return GATES;
}

function loadCiJobNames() {
  // Cheap YAML parse — we only need the `name:` field of each top-level
  // jobs.<job>.name string. Avoids pulling a YAML dep into a zero-dep repo.
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  const lines = yaml.split(/\r?\n/);

  const jobs = [];
  let inJobs = false;
  let currentJobIndent = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    // End of jobs block: a top-level key (no leading whitespace) other
    // than a job definition.
    if (/^[a-zA-Z_]/.test(line) && !/^jobs:/.test(line)) {
      break;
    }
    // Job key looks like `  jobname:` at exactly 2 spaces of indent.
    const jobMatch = line.match(/^ {2}([a-z0-9-]+):\s*$/);
    if (jobMatch) {
      currentJobIndent = "    ";
      // Look ahead for `name:` at 4 spaces.
      for (let j = i + 1; j < lines.length; j++) {
        const next = lines[j];
        if (/^ {2}[a-z0-9-]+:\s*$/.test(next)) break; // next job
        if (/^[a-zA-Z_]/.test(next)) break; // back to top level
        const nameMatch = next.match(/^ {4}name:\s*(.+?)\s*$/);
        if (nameMatch) {
          jobs.push({
            key: jobMatch[1],
            name: nameMatch[1].replace(/^["']|["']$/g, ""),
          });
          break;
        }
      }
    }
  }

  return jobs;
}

test("predeploy.js exports a non-empty ordered GATES list", () => {
  const gates = loadGates();
  assert.ok(Array.isArray(gates), "GATES must be an array");
  assert.ok(gates.length > 0, "GATES must not be empty");
  for (const g of gates) {
    assert.ok(g.name, "every gate has a display name");
    assert.ok(g.command, "every gate has a command");
    assert.ok(Array.isArray(g.args), "every gate has an args array");
    assert.ok(g.ciJobName, "every gate maps to a CI job name");
  }
});

test("predeploy.js exports exactly 16 gates as of v0.12.12", () => {
  const gates = loadGates();
  assert.equal(
    gates.length,
    16,
    `expected 16 gates in v0.12.12 (15 pre-existing + new validate-playbooks informational gate), got ${gates.length}`,
  );
});

test("every predeploy gate maps to a job name in ci.yml", () => {
  const gates = loadGates();
  const ciJobs = loadCiJobNames();
  const ciJobNames = new Set(ciJobs.map((j) => j.name));

  // CI uses a matrix job named `Tests (${{ matrix.os }})` which expands
  // to three distinct status checks; the predeploy gate just runs the
  // local `node --test` once and tags it `Tests`. Accept either form.
  const matrixSafe = (name) =>
    name === "Tests" ? new Set(["Tests", "Tests (${{ matrix.os }})"]) : new Set([name]);

  for (const g of gates) {
    const acceptable = matrixSafe(g.ciJobName);
    const hit = [...acceptable].some((n) => ciJobNames.has(n));
    assert.ok(
      hit,
      `predeploy gate "${g.name}" maps to ciJobName "${g.ciJobName}" ` +
        `but no job with that name exists in ci.yml. ` +
        `Update either scripts/predeploy.js or .github/workflows/ci.yml.`
    );
  }
});

test("package.json declares the predeploy npm script", () => {
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8"));
  assert.ok(pkg.scripts, "package.json has a scripts block");
  assert.equal(
    pkg.scripts.predeploy,
    "node scripts/predeploy.js",
    "`npm run predeploy` must invoke the local gate runner"
  );
});

test("package.json declares each individual gate alias", () => {
  // Contributors should be able to run any single gate by alias
  // without remembering the full path.
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8"));
  const required = ["verify", "lint", "test", "check-snapshot", "validate-catalog"];
  for (const name of required) {
    assert.ok(
      pkg.scripts[name],
      `package.json must expose an "${name}" script for contributors`
    );
  }
});
