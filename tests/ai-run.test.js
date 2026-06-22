"use strict";


// ---- routed from audit-correctness-cluster ----
require("node:test").describe("audit-correctness-cluster", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a correctness cluster found auditing the run/ci/ai-run
 * verbs and the close/framework-gap surfaces for silent-wrong-answer bugs:
 *
 *   H1 — `ci <playbook> --evidence -` given a FLAT submission (the same shape
 *        `run` accepts) silently produced a PASS: the runner keyed the bundle
 *        by playbook id, found nothing, and evaluated an empty submission.
 *        ci must now treat a single-positional flat submission as belonging to
 *        that playbook, matching `run`'s verdict.
 *
 *   H2 — `ai-run <pb> --no-stream --evidence -` bypassed the evidence-shape
 *        guard `run` enforces, so `null` / `[]` / a scalar ran as if empty.
 *        It must be rejected at the read boundary with an actionable message.
 *
 *   H3 — the ci framework_gap_rollup read a nonexistent `why_insufficient`
 *        key, so every rollup entry's explanation was null. The data lives in
 *        `actual_gap`; the rollup must surface it.
 *
 *   M1 — the regulatory clock only started when the AGENT submitted
 *        detection_classification:'detected'. An engine-confirmed detection
 *        (indicators fired, engine classified 'detected') with --ack never
 *        started the clock, so notification deadlines silently stalled.
 *
 *   M2 — `framework-gap <bogus> <scenario>` produced a zero-gap report
 *        indistinguishable from a real "no gaps" result, so a typo read as
 *        proof the framework covered the scenario. An unknown framework must
 *        be refused; documented short forms ("NIST-800-53") must still resolve.
 *
 * Discipline: exact exit codes; presence assertions paired with value/type.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-auditcorrect-"));

// A flat secrets submission whose overrides fire real indicators.
const FLAT_SECRETS = JSON.stringify({
  signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" },
});





// The bug codex flagged: the guard above only fires on `--evidence`, but
// --no-stream ALSO auto-reads stdin. Whether a spawnSync pipe triggers the
// auto-stdin path is platform-divergent (POSIX FIFOs report readable; win32
// spawnSync pipes do not), so probe reachability first and only assert the
// rejection where the path is actually live — never coincidence-pass.
function autoStdinReachable() {
  const probe = cli(["ai-run", "secrets", "--no-stream", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } }),
  });
  const pj = tryJson(probe.stdout);
  return !!(pj && pj.phases?.analyze?._detect_classification === "detected");
}




const AI_API_FIRES = JSON.stringify({
  signal_overrides: {
    "cleartext-api-key-in-dotfile": "hit",
    "ai-api-beaconing-cadence": "hit",
    "long-lived-aws-keys": "hit",
  },
});

test("H2: ai-run --no-stream rejects a non-object evidence submission", () => {
  const r = cli(["ai-run", "secrets", "--no-stream", "--evidence", "-"], { input: "null" });
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false, "must emit a structured error");
  assert.match(body.error, /evidence must be a JSON object/, "must name the shape requirement");
  assert.match(body.error, /got null/, "must name what it got");
});

test("H2: ai-run --no-stream still accepts a well-formed object submission", () => {
  const sub = JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } });
  const r = cli(["ai-run", "secrets", "--no-stream", "--evidence", "-", "--json"], { input: sub });
  const body = tryJson(r.stdout);
  assert.ok(body, "must emit JSON for a valid object submission");
  assert.notEqual(body.ok, false, "a well-formed object must not be rejected"); // allow-notEqual: assert valid path is NOT the rejected one
});

test("H2: ai-run --no-stream rejects a bare non-object piped via stdin (no --evidence flag)", (t) => {
  if (!autoStdinReachable()) {
    t.skip("spawnSync stdin pipe is not auto-read in this environment (win32); the guard is exercised via --evidence above and on POSIX CI here");
    return;
  }
  const r = cli(["ai-run", "secrets", "--no-stream", "--json"], { input: "null" });
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false, "a bare null piped via stdin must be rejected, not run as empty");
  assert.match(body.error, /evidence must be a JSON object/, "must name the shape requirement");
});

test("H2: ai-run --no-stream still reads a valid bare submission piped via stdin", (t) => {
  if (!autoStdinReachable()) {
    t.skip("spawnSync stdin pipe is not auto-read in this environment (win32)");
    return;
  }
  const r = cli(["ai-run", "secrets", "--no-stream", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } }),
  });
  const j = tryJson(r.stdout);
  assert.ok(j && j.ok, "valid stdin submission must run");
  assert.equal(j.phases.analyze._detect_classification, "detected", "the piped signals must actually be evaluated");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#101 ai-run --no-stream shape matches run shape (phases nested)', () => {
  const sub = JSON.stringify({});
  const r = cli(['ai-run', 'library-author', '--no-stream', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'ai-run --no-stream output should be JSON');
  assert.ok(data.phases, 'ai-run --no-stream must nest phases under .phases (parity with `run`)');
  assert.ok('detect' in data.phases, 'phases.detect must be present');
  assert.ok('analyze' in data.phases, 'phases.analyze must be present');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
