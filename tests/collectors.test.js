"use strict";

/**
 * tests/collectors.test.js
 *
 * Pins the collector interface contract + reference implementations:
 *   - exceptd collect <unknown> -> structured error + exit 1 + lists
 *     the available collectors so an operator can discover them.
 *   - exceptd collect <known> -> submission JSON with the required
 *     top-level keys (precondition_checks, artifacts,
 *     signal_overrides, collector_meta, collector_errors).
 *   - exceptd collect <known> | exceptd run <known> --evidence -
 *     round-trips: the runner accepts the collector's output without
 *     schema errors.
 *   - exceptd collect <known> --cwd <nonexistent> -> structured error.
 *   - secrets collector finds expected file types on a synthetic
 *     repo with a fake .env + fake .npmrc.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// Direct module imports so the diff-coverage gate sees the exports
// are exercised by unit-level tests, not just via subprocess
// invocation through the CLI.
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const kernelCollector = require(path.join(ROOT, "lib", "collectors", "kernel.js"));
const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));

test("collector modules export the contract: playbook_id + collect()", () => {
  for (const mod of [secretsCollector, kernelCollector, sbomCollector]) {
    assert.equal(typeof mod.playbook_id, "string", "playbook_id must be a string");
    assert.ok(mod.playbook_id.length > 0);
    assert.equal(typeof mod.collect, "function", "collect must be a function");
  }
  assert.equal(secretsCollector.playbook_id, "secrets");
  assert.equal(kernelCollector.playbook_id, "kernel");
  assert.equal(sbomCollector.playbook_id, "sbom");
});

test("collector.collect() returns the contract envelope when called directly", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-direct-"));
  try {
    const result = sbomCollector.collect({ cwd: tmp });
    for (const k of ["precondition_checks", "artifacts", "signal_overrides", "collector_meta", "collector_errors"]) {
      assert.ok(k in result, `direct collect() return must carry "${k}"`);
    }
    assert.equal(result.collector_meta.collector_id, "sbom");
    // Empty tempdir has no lockfile and no SBOM → lockfile-absent hit.
    assert.equal(result.signal_overrides["lockfile-absent"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

test("collect <unknown> exits 1 with structured error + lists available collectors", () => {
  const r = cli(["collect", "this-collector-does-not-exist"]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err, "stderr must be parseable JSON");
  assert.equal(err.type, "collector_not_found");
  assert.ok(Array.isArray(err.collectors_available));
  // The three reference collectors must be present.
  assert.ok(err.collectors_available.includes("secrets"));
  assert.ok(err.collectors_available.includes("kernel"));
  assert.ok(err.collectors_available.includes("sbom"));
  // The error must point the operator at the AI-evidence path.
  assert.match(err.error, /AI-evidence path remains/);
});

test("collect kernel emits the contract envelope shape", () => {
  const r = cli(["collect", "kernel", "--json"]);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `must emit parseable JSON; stdout: ${r.stdout.slice(0, 200)}`);
  for (const k of ENVELOPE_KEYS) {
    assert.ok(k in body, `envelope must carry "${k}" top-level key`);
  }
  assert.equal(body.collector_meta.collector_id, "kernel");
  assert.equal(typeof body.collector_meta.captured_at, "string");
  // linux-platform precondition is deterministic from process.platform.
  assert.equal(typeof body.precondition_checks["linux-platform"], "boolean");
});

test("collect secrets pipes through to run --evidence - without schema errors", () => {
  // Use a synthetic tempdir as the collect target so the test is
  // deterministic + bounded.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-pipe-"));
  try {
    fs.writeFileSync(path.join(tmp, ".env"), "AWS_KEY=AKIA1234567890ABCDEF\nOTHER=value\n");
    fs.writeFileSync(path.join(tmp, "README.md"), "no secrets here\n");
    const collectR = cli(["collect", "secrets", "--cwd", tmp, "--json"]);
    assert.equal(collectR.status, 0);
    const submission = tryJson(collectR.stdout);
    assert.ok(submission, "collector stdout must be parseable JSON");
    assert.equal(submission.signal_overrides["aws-access-key-id"], "hit",
      "secrets collector must flip aws-access-key-id to hit when a real AKIA literal is present");
    // Pipe collector output into run.
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "collect-run-"));
    const runR = cli(["run", "secrets", "--evidence", "-"],
      { input: JSON.stringify(submission), env: { EXCEPTD_HOME: tmpHome } });
    assert.equal(runR.status, 0, `run must accept the collector's submission; stderr: ${runR.stderr.slice(0, 200)}`);
    // The run human output must show the indicator firing.
    assert.match(runR.stdout, /\[!! DETECTED\]|aws-access-key-id/,
      "the runner must recognise the collector-supplied signal_overrides");
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect --cwd <nonexistent> exits with structured error", () => {
  const r = cli(["collect", "kernel", "--cwd", "/path/that/absolutely/does/not/exist-" + Date.now()]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err);
  assert.match(err.error, /does not exist/);
});

test("collect sbom finds lockfile + sbom-document.absent indicator wiring", () => {
  // Synthetic tempdir with a package-lock.json + no SBOM document
  // should fire sbom-document-absent=hit.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-sbom-"));
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/foo": {} } }));
    const r = cli(["collect", "sbom", "--cwd", tmp, "--json"]);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body);
    assert.equal(body.signal_overrides["sbom-document-absent"], "hit",
      "sbom collector must flip sbom-document-absent to hit when only a lockfile is present");
    assert.equal(body.signal_overrides["lockfile-absent"], "miss");
    assert.match(body.artifacts["lockfile-inventory"].value, /npm:package-lock\.json/);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect <pb> --pretty produces indented JSON envelope", () => {
  const r = cli(["collect", "kernel", "--pretty"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^\{\n /, "pretty mode must indent the JSON envelope");
  const body = tryJson(r.stdout);
  assert.ok(body);
  assert.equal(body.collector_meta.collector_id, "kernel");
});
