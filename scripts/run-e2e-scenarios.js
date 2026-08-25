#!/usr/bin/env node
"use strict";

/**
 * Drives the scenario harness under tests/e2e-scenarios/. A scenario directory
 * stages a synthetic file tree plus an evidence.json and an expect.json; each
 * one runs in its own temp copy against the real CLI.
 *
 * The Docker `e2e` target and release.yml run this script unchanged, so host and
 * container behaviour must not diverge. Node stdlib only, zero npm deps.
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

// Separate from diffExpect because the ban has to hold whether or not stdout
// parsed as JSON; evaluateScenario calls it unconditionally.
function stderrBanFailures(expect, stderr) {
  const failures = [];
  if (expect.stderr_must_not_match) {
    for (const regex of expect.stderr_must_not_match) {
      if (new RegExp(regex).test(stderr || "")) {
        failures.push(`stderr_must_not_match /${regex}/: stderr contains it`);
      }
    }
  }
  return failures;
}

// Positive matchers against the parsed JSON body only; the stderr ban is separate.
function diffExpect(jsonBody, expect) {
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
  return failures;
}

function tryParseJson(s) {
  if (!s) return null;
  try {
    const v = JSON.parse(s.trim());
    if (v && typeof v === "object") return v;
  } catch { /* ignore */ }
  // Trailing logs are possible, so take the LAST complete object or array. A bare
  // scalar is never a verb envelope; accepting one would bind to a log line.
  const lines = s.trim().split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const v = JSON.parse(lines[i]);
      if (v && typeof v === "object") return v;
    } catch { /* keep looking */ }
  }
  return null;
}

// Pure over a raw spawnSync result, so the failure logic is testable without
// spawning anything. Returns the list of failure strings; empty means pass.
function evaluateScenario(scenario, expect, res) {
  const stdout = res.stdout || "";
  const stderr = res.stderr || "";
  const status = res.status;
  const body = tryParseJson(stdout);
  const failures = [];

  // A timeout or launch failure sets res.error with status null, so reading only
  // res.status lets a killed or never-launched run pass as a non-zero exit.
  if (res.error) failures.push(`spawn error: ${res.error.code || res.error.message}`);
  if (res.signal) failures.push(`killed by signal ${res.signal}${res.signal === "SIGTERM" ? " (likely the 60s timeout)" : ""}`);

  // Every scenario must bind one positive check: with neither an expect_exit nor
  // a json_path_* matcher, both gates below skip and the scenario passes for any
  // behaviour at all. A negative guard like stderr_must_not_match binds nothing.
  const hasExitAssertion = typeof scenario.expect_exit === "number";
  const hasJsonAssertion = !!(expect.json_path_equals || expect.json_path_present || expect.json_path_min || expect.json_path_match);
  if (!hasExitAssertion && !hasJsonAssertion) {
    failures.push("scenario has no binding assertion (set expect_exit or an expect.json_path_* matcher) — refusing to pass vacuously");
  }

  if (hasExitAssertion && status !== scenario.expect_exit) {
    failures.push(`exit: want ${scenario.expect_exit}, got ${status}`);
  }
  if (!body && hasJsonAssertion) {
    failures.push(`stdout did not parse as JSON; first 200 chars: ${stdout.slice(0, 200)}`);
  }
  if (body) failures.push(...diffExpect(body, expect));

  // Unconditional, outside every `if (body)` branch above.
  failures.push(...stderrBanFailures(expect, stderr));
  return failures;
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

  const work = fs.mkdtempSync(path.join(os.tmpdir(), `e2e-${name}-`));
  try {
    const fixturesDir = path.join(scenarioPath, "fixtures");
    if (fs.existsSync(fixturesDir)) copyRecursive(fixturesDir, work);
    const evidenceSrc = path.join(scenarioPath, "evidence.json");
    if (fs.existsSync(evidenceSrc)) {
      fs.copyFileSync(evidenceSrc, path.join(work, "evidence.json"));
    }

    // @@FIXTURE@@ inside an env value expands to ROOT/tests/fixtures.
    const env = { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1" };
    if (scenario.env) {
      for (const [k, v] of Object.entries(scenario.env)) {
        env[k] = String(v).replace(/@@FIXTURE@@/g, FIXTURE_DIR);
      }
    }

    const args = (scenario.args || []).slice();

    // The verb and args pass through verbatim; bin/exceptd.js does the routing.
    const verb = scenario.verb;
    let cmd, cmdArgs;
    if (verb === "refresh-curate") {
      // The curation helper direct; operators reach it as `refresh --curate`.
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

    const failures = evaluateScenario(scenario, expect, res);

    return {
      name,
      description: scenario.description || "",
      ok: failures.length === 0,
      exit_status: res.status,
      failures,
      stdout_preview: (res.stdout || "").slice(0, 200),
      stderr_preview: (res.stderr || "").slice(0, 200),
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// Sorted basenames. The filter is a plain substring, never `new RegExp`: a
// pattern compiled from a CLI argument is a regex-injection and ReDoS vector,
// and scenario names are literal NN-name strings anyway.
function selectScenarios(filterStr, dir = SCENARIO_DIR) {
  return fs.readdirSync(dir)
    .filter(d => /^\d+-/.test(d))
    .filter(d => !filterStr || d.includes(filterStr))
    .sort();
}

function main() {
  const filter = process.argv.find(a => a.startsWith("--filter="));
  const filterStr = filter ? filter.slice("--filter=".length) : null;
  const json = process.argv.includes("--json");

  const scenarios = selectScenarios(filterStr)
    .map(d => path.join(SCENARIO_DIR, d));

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

  process.exit(failed.length === 0 ? 0 : 1); // allow:process-exit-after-stdout-write — local e2e runner; the pass/fail summary above is human/CI-read on a TTY, not a piped --json result channel
}

module.exports = { evaluateScenario, diffExpect, tryParseJson, stderrBanFailures, runScenario, selectScenarios, SCENARIO_DIR };

if (require.main === module) main();
