"use strict";

/**
 * tests/doctor-collectors.test.js
 *
 * Pins the doctor collector-layer health gate: --collectors flag
 * emits a structured envelope, default no-flag doctor pass folds
 * it in, ok: true on a clean tree, policy_skips covers the
 * catalogued judgement-shaped playbooks, with_collector +
 * without_collector counts match on-disk truth.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");
const PLAYBOOK_DIR = path.join(ROOT, "data", "playbooks");
const COLLECTOR_DIR = path.join(ROOT, "lib", "collectors");

const POLICY_SKIPS = [
  "framework", "ransomware", "ai-discovered-cve-triage",
  "cloud-iam-incident", "idp-incident", "identity-sso-compromise",
  "llm-tool-use-exfil", "supply-chain-recovery",
  "post-quantum-migration", "webhook-callback-abuse",
];

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    timeout: 60000,
    ...opts,
  });
}

test("doctor --collectors emits a structured envelope with the catalogued shape", () => {
  const r = runCli(["doctor", "--collectors", "--json"]);
  assert.equal(r.status, 0, `doctor --collectors exit non-zero; stderr=${r.stderr.slice(0, 400)}`);
  const body = JSON.parse(r.stdout);
  assert.ok(body.checks, "envelope missing checks");
  const c = body.checks.collectors;
  assert.ok(c, "envelope missing checks.collectors");
  assert.equal(c.ok, true, `collectors ok=false: ${JSON.stringify(c)}`);
  assert.equal(typeof c.total_playbooks, "number");
  assert.equal(typeof c.with_collector, "number");
  assert.ok(Array.isArray(c.without_collector));
  assert.ok(Array.isArray(c.load_errors));
  assert.ok(Array.isArray(c.policy_skips));
  for (const pid of POLICY_SKIPS) {
    assert.ok(c.policy_skips.includes(pid), `policy_skips missing ${pid}`);
  }
});

test("doctor --collectors counts match on-disk truth (every playbook resolved against lib/collectors/<id>.js)", () => {
  const r = runCli(["doctor", "--collectors", "--json"]);
  const body = JSON.parse(r.stdout);
  const c = body.checks.collectors;

  const playbooks = fs.readdirSync(PLAYBOOK_DIR)
    .filter(f => f.endsWith(".json") && !f.startsWith("_"))
    .map(f => f.replace(/\.json$/, ""));

  assert.equal(c.total_playbooks, playbooks.length);

  let actualWith = 0;
  const actualWithout = [];
  for (const pid of playbooks) {
    if (fs.existsSync(path.join(COLLECTOR_DIR, pid + ".js"))) actualWith++;
    else actualWithout.push(pid);
  }
  assert.equal(c.with_collector, actualWith);
  assert.deepEqual(c.without_collector.sort(), actualWithout.sort());
});

test("default doctor pass (no flags) folds in the collector gate", () => {
  const r = runCli(["doctor", "--json"]);
  assert.equal(r.status, 0, `doctor exit non-zero; stderr=${r.stderr.slice(0, 400)}`);
  const body = JSON.parse(r.stdout);
  assert.ok(body.checks.collectors, "default doctor pass missing collectors gate");
  assert.equal(body.checks.collectors.ok, true);
});

test("doctor --collectors human renderer prints the collector-layer line + skip note", () => {
  const r = runCli(["doctor", "--collectors"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /collector layer:\s+\d+\/\d+ playbooks have collectors/);
  assert.match(r.stdout, /judgement-shaped playbooks intentionally without/);
});
