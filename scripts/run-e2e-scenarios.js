#!/usr/bin/env node
"use strict";

/**
 * scripts/run-e2e-scenarios.js
 *
 * Drives the end-to-end scenario harness under tests/e2e-scenarios/. Each
 * scenario directory stages a synthetic file tree (real IoC patterns the
 * playbooks check for) + an evidence.json + an expect.json. The runner:
 *
 *   1. mkdtemp a working dir
 *   2. recursive-copy fixtures/ into it
 *   3. recursive-copy any evidence.json next to scenario.json into it
 *   4. cd into the working dir
 *   5. spawnSync the CLI with the scenario's verb + args
 *   6. parse stdout as JSON
 *   7. diff against expect.json (path-based assertions)
 *
 * Container parity: this script is invoked unchanged inside the Docker
 * `e2e` target (npm run test:docker:e2e). The container only adds Linux
 * file-permission realism and Node version pinning; the script itself
 * runs identically on host + container.
 *
 * Release gate: .github/workflows/release.yml runs this BEFORE
 * `npm publish` so a regression that breaks any playbook detection
 * blocks the release.
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");
const SCENARIO_DIR = path.join(ROOT, "tests", "e2e-scenarios");
const FIXTURE_DIR = path.join(ROOT, "tests", "fixtures");

function copyRecursive(src, dst) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dst, entry));
    }
  } else {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
  }
}

function getJsonPath(obj, dotted) {
  return dotted.split(".").reduce((acc, key) => acc?.[key], obj);
}

function diffExpect(jsonBody, expect, ctx) {
  const failures = [];
  if (expect.json_path_equals) {
    for (const [p, want] of Object.entries(expect.json_path_equals)) {
      const got = getJsonPath(jsonBody, p);
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        failures.push(`json_path_equals.${p}: want ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
      }
    }
  }
  if (expect.json_path_present) {
    for (const p of expect.json_path_present) {
      const got = getJsonPath(jsonBody, p);
      if (got === undefined || got === null) {
        failures.push(`json_path_present.${p}: missing`);
      }
    }
  }
  if (expect.json_path_min) {
    for (const [p, min] of Object.entries(expect.json_path_min)) {
      const got = getJsonPath(jsonBody, p);
      if (typeof got !== "number" || got < min) {
        failures.push(`json_path_min.${p}: want >= ${min}, got ${JSON.stringify(got)}`);
      }
    }
  }
  if (expect.json_path_match) {
    for (const [p, regex] of Object.entries(expect.json_path_match)) {
      const got = getJsonPath(jsonBody, p);
      if (typeof got !== "string" || !new RegExp(regex).test(got)) {
        failures.push(`json_path_match.${p}: want match /${regex}/, got ${JSON.stringify(got)}`);
      }
    }
  }
  if (expect.stderr_must_not_match) {
    for (const regex of expect.stderr_must_not_match) {
      if (new RegExp(regex).test(ctx.stderr)) {
        failures.push(`stderr_must_not_match /${regex}/: stderr contains it`);
      }
    }
  }
  return failures;
}

function tryParseJson(s) {
  if (!s) return null;
  try { return JSON.parse(s.trim()); } catch { /* ignore */ }
  // Some verbs may emit trailing logs; pick the LAST complete JSON object on stdout.
  const lines = s.trim().split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    try { return JSON.parse(lines[i]); } catch { /* keep looking */ }
  }
  return null;
}

function runScenario(scenarioPath) {
  const name = path.basename(scenarioPath);
  const scenarioFile = path.join(scenarioPath, "scenario.json");
  if (!fs.existsSync(scenarioFile)) {
    return { name, skipped: true, reason: "no scenario.json" };
  }
  const scenario = JSON.parse(fs.readFileSync(scenarioFile, "utf8"));
  const expect = fs.existsSync(path.join(scenarioPath, "expect.json"))
    ? JSON.parse(fs.readFileSync(path.join(scenarioPath, "expect.json"), "utf8"))
    : {};

  // Stage temp working dir
  const work = fs.mkdtempSync(path.join(os.tmpdir(), `e2e-${name}-`));
  try {
    const fixturesDir = path.join(scenarioPath, "fixtures");
    if (fs.existsSync(fixturesDir)) copyRecursive(fixturesDir, work);
    const evidenceSrc = path.join(scenarioPath, "evidence.json");
    if (fs.existsSync(evidenceSrc)) {
      fs.copyFileSync(evidenceSrc, path.join(work, "evidence.json"));
    }

    // Resolve env. @@FIXTURE@@ in env values expands to ROOT/tests/fixtures.
    const env = { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1" };
    if (scenario.env) {
      for (const [k, v] of Object.entries(scenario.env)) {
        env[k] = String(v).replace(/@@FIXTURE@@/g, FIXTURE_DIR);
      }
    }

    // Resolve args
    const args = (scenario.args || []).slice();

    // Verb routing. `refresh` + `refresh-curate` are not the same as `run` —
    // the dispatcher in bin/exceptd.js handles the translation, so we just
    // pass the verb + args verbatim. `refresh-curate` is the internal name
    // for `refresh --curate`; surfaced here for test directness.
    const verb = scenario.verb;
    let cmd, cmdArgs;
    if (verb === "refresh-curate") {
      // Invoke the curation helper directly. Production path is via the
      // dispatcher in bin/exceptd.js (which dispatches refresh --curate).
      cmd = process.execPath;
      cmdArgs = [path.join(ROOT, "lib", "cve-curation.js"), ...args];
    } else {
      cmd = process.execPath;
      cmdArgs = [CLI, verb, ...args];
    }

    const res = spawnSync(cmd, cmdArgs, {
      cwd: work,
      encoding: "utf8",
      env,
      timeout: 60000,
    });

    const stdout = res.stdout || "";
    const stderr = res.stderr || "";
    const status = res.status;
    const body = tryParseJson(stdout);

    const failures = [];
    if (typeof scenario.expect_exit === "number" && status !== scenario.expect_exit) {
      failures.push(`exit: want ${scenario.expect_exit}, got ${status}`);
    }
    if (!body && (expect.json_path_equals || expect.json_path_present || expect.json_path_min || expect.json_path_match)) {
      failures.push(`stdout did not parse as JSON; first 200 chars: ${stdout.slice(0, 200)}`);
    }
    if (body) failures.push(...diffExpect(body, expect, { stdout, stderr, status }));

    return {
      name,
      description: scenario.description || "",
      ok: failures.length === 0,
      exit_status: status,
      failures,
      stdout_preview: stdout.slice(0, 200),
      stderr_preview: stderr.slice(0, 200),
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

function main() {
  const filter = process.argv.find(a => a.startsWith("--filter="));
  const filterRe = filter ? new RegExp(filter.slice("--filter=".length)) : null;
  const json = process.argv.includes("--json");

  const scenarios = fs.readdirSync(SCENARIO_DIR)
    .filter(d => /^\d+-/.test(d))
    .filter(d => !filterRe || filterRe.test(d))
    .map(d => path.join(SCENARIO_DIR, d))
    .sort();

  const results = [];
  for (const s of scenarios) {
    results.push(runScenario(s));
  }

  const failed = results.filter(r => !r.ok && !r.skipped);
  const passed = results.filter(r => r.ok);
  const skipped = results.filter(r => r.skipped);

  if (json) {
    process.stdout.write(JSON.stringify({
      verb: "e2e",
      total: results.length,
      passed: passed.length,
      failed: failed.length,
      skipped: skipped.length,
      results,
    }, null, 2) + "\n");
  } else {
    for (const r of results) {
      const tag = r.skipped ? "SKIP" : r.ok ? "PASS" : "FAIL";
      process.stdout.write(`${tag}  ${r.name}\n`);
      if (!r.ok && !r.skipped) {
        for (const f of r.failures) process.stdout.write(`        - ${f}\n`);
        if (r.stderr_preview) process.stdout.write(`        stderr: ${r.stderr_preview}\n`);
      }
    }
    process.stdout.write(`\n${passed.length}/${results.length} scenarios passed${failed.length ? `, ${failed.length} failed` : ""}${skipped.length ? `, ${skipped.length} skipped` : ""}.\n`);
  }

  process.exit(failed.length === 0 ? 0 : 1);
}

main();
