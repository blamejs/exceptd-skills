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

// Evaluate the negative stderr guard against raw stderr text. Lives here, NOT
// inside diffExpect, because the ban must hold regardless of whether stdout
// parsed as JSON — a scenario whose stdout is a human banner (no JSON body,
// only an expect_exit assertion) must still enforce a forbidden-token ban on
// stderr. evaluateScenario calls this unconditionally.
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

// Diff a parsed JSON body against the positive expect matchers. The negative
// stderr guard is NOT evaluated here (see stderrBanFailures); this function
// only inspects the JSON body so it cannot be silently skipped when stdout
// fails to parse.
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
  return failures;
}

function tryParseJson(s) {
  if (!s) return null;
  try {
    const v = JSON.parse(s.trim());
    if (v && typeof v === "object") return v;
  } catch { /* ignore */ }
  // Some verbs may emit trailing logs; pick the LAST complete JSON object or
  // array on stdout. A verb envelope is always an object/array, so bare
  // scalars (a trailing JSON-parseable "done"/42/true log line) are skipped —
  // binding assertions against a trailing scalar would silently test the
  // wrong value.
  const lines = s.trim().split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const v = JSON.parse(lines[i]);
      if (v && typeof v === "object") return v;
    } catch { /* keep looking */ }
  }
  return null;
}

// Evaluate a spawnSync result against a scenario's expectations. Pure: takes
// the raw spawnSync result so the failure logic is unit-testable without
// spawning a process. Surfaces spawn-level failures (timeout/launch error)
// that res.status alone hides, and refuses to pass a scenario that binds no
// assertion.
function evaluateScenario(scenario, expect, res) {
  const stdout = res.stdout || "";
  const stderr = res.stderr || "";
  const status = res.status;
  const body = tryParseJson(stdout);
  const failures = [];

  // spawnSync failure channels: a timeout sets res.error (ETIMEDOUT) +
  // res.signal 'SIGTERM' with status null; a launch failure (ENOENT/EACCES)
  // sets res.error with status null. Reading only res.status lets a killed-
  // or-never-launched run masquerade as a plain non-zero exit or a JSON-parse
  // failure, hiding the real cause.
  if (res.error) failures.push(`spawn error: ${res.error.code || res.error.message}`);
  if (res.signal) failures.push(`killed by signal ${res.signal}${res.signal === "SIGTERM" ? " (likely the 60s timeout)" : ""}`);

  // Assertion floor: every scenario must bind at least one positive check.
  // Without an expect_exit or a json_path_* matcher, both gates below are
  // skipped and the scenario would pass for ANY CLI behavior, including a
  // crash. (stderr_must_not_match is a negative guard and cannot bind
  // behavior on its own, so it does not satisfy the floor.)
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
  if (body) failures.push(...diffExpect(body, expect, { stdout, stderr, status }));

  // The forbidden-token ban on stderr runs unconditionally — it does not
  // depend on stdout parsing as JSON. A scenario with only an expect_exit
  // assertion (human-banner stdout) must still fail if stderr carries a banned
  // token.
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

function main() {
  const filter = process.argv.find(a => a.startsWith("--filter="));
  // Plain substring match, not new RegExp(operatorArg): a regex compiled from a
  // CLI argument is a regex-injection / ReDoS vector, and scenario filtering only
  // needs substring selection (e.g. --filter=library-author).
  const filterStr = filter ? filter.slice("--filter=".length) : null;
  const json = process.argv.includes("--json");

  const scenarios = fs.readdirSync(SCENARIO_DIR)
    .filter(d => /^\d+-/.test(d))
    .filter(d => !filterStr || d.includes(filterStr))
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

module.exports = { evaluateScenario, diffExpect, tryParseJson, stderrBanFailures, runScenario, SCENARIO_DIR };

if (require.main === module) main();
