"use strict";


// ---- routed from collectors ----
require("node:test").describe("collectors", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
const containersCollector = require(path.join(ROOT, "lib", "collectors", "containers.js"));
const libraryAuthorCollector = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
const cryptoCodebaseCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const credStoresCollector = require(path.join(ROOT, "lib", "collectors", "cred-stores.js"));
const hardeningCollector = require(path.join(ROOT, "lib", "collectors", "hardening.js"));
const runtimeCollector = require(path.join(ROOT, "lib", "collectors", "runtime.js"));
const aiApiCollector = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));
const mcpCollector = require(path.join(ROOT, "lib", "collectors", "mcp.js"));



const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
