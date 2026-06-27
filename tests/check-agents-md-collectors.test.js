"use strict";


// ---- routed from check-agents-md-collectors-require-throw ----
require("node:test").describe("check-agents-md-collectors-require-throw", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/check-agents-md-collectors-require-throw.test.js
 *
 * scripts/check-agents-md-collectors.js builds the on-disk collector set by
 * require()-ing every lib/collectors/*.js and keeping those exporting a
 * collect() function. The classifier previously caught a require() throw and
 * returned false, which excluded a broken module from BOTH the count and the
 * AGENTS.md enumeration cross-check — a collector with a load-time exception
 * (syntax error, bad top-level require, init-time throw) shipped in the
 * tarball yet passed the gate undetected, leaving the gate's count
 * non-authoritative.
 *
 * The fix splits the three cases: require-succeeds-with-collect (counted),
 * require-succeeds-without-collect (a helper such as scan-excludes.js,
 * legitimately excluded), and require-throws (a parse error, exit 2, naming
 * the file). These tests lock both the static absence of the silent-catch and
 * the behavioral exit code.
 *
 * Per the anti-coincidence rule: the behavioral assertion checks the EXACT
 * exit code (2), never notEqual(0).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const GATE = path.join(ROOT, 'scripts', 'check-agents-md-collectors.js');
const { classifyCollectors } = require(GATE);

function runGate(extraEnv) {
  return spawnSync(process.execPath, [GATE], {
    encoding: 'utf8',
    timeout: 30000,
    env: extraEnv ? { ...process.env, ...extraEnv } : process.env,
  });
}

// Stage fixture collectors in a throwaway tempdir and run fn against it. The
// fixtures NEVER touch the real lib/collectors/, so a process-killed run can
// no longer leak a broken module that poisons every collector-enumerating
// test (the failure mode this suite previously had).
function withTempCollectorDir(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-collectors-'));
  try {
    for (const [name, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), content);
    }
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Spawn the gate against a tempdir. The dir override is honored only with the
// explicit test-only switch — the same switch the gate requires so a stray
// EXCEPTD_COLLECTOR_DIR can never redirect a real predeploy/CI run.
function runGateOnDir(dir) {
  return runGate({ EXCEPTD_COLLECTOR_DIR_TESTONLY: '1', EXCEPTD_COLLECTOR_DIR: dir });
}

test('the dir override is ignored without the explicit test-only switch', () => {
  // EXCEPTD_COLLECTOR_DIR alone (no _TESTONLY=1) must NOT redirect the gate —
  // it validates the real lib/collectors/ and stays green, so a stray env var
  // can't mask missing/broken real collectors.
  withTempCollectorDir(
    { 'broken-collector.js': '"use strict";\nthrow new Error("must not be reached");\n' },
    (dir) => {
      const r = runGate({ EXCEPTD_COLLECTOR_DIR: dir });
      assert.equal(r.status, 0, `override without the test-only switch must be ignored; stderr: ${r.stderr}`);
      assert.match(r.stdout, /collectors enumerated correctly/);
    }
  );
});

// Strip comments + string literals so the static assertion matches only
// EXECUTABLE code — the explanatory comment in the fixed script names the
// removed silent-catch by description, and that prose must not trip the guard.
function executableSource(file) {
  let s = fs.readFileSync(file, 'utf8');
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');            // block comments
  s = s.replace(/(^|[^:])\/\/.*$/gm, '$1');          // line comments (not ://)
  s = s.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''"); // strings
  return s;
}

test('check-agents-md-collectors.js is clean on the real collector tree (baseline)', () => {
  const r = runGate();
  assert.equal(r.status, 0, `expected exit 0 on the unmodified tree; stderr: ${r.stderr}`);
  assert.match(r.stdout, /collectors enumerated correctly/);
});

test('classifyCollectors surfaces a require()-throwing module as a load error (not a silent drop)', () => {
  withTempCollectorDir(
    { 'broken-collector.js': '"use strict";\nthrow new Error("simulated load-time failure");\nmodule.exports = { collect() {} };\n' },
    (dir) => {
      const { loadErrors, collectorFiles } = classifyCollectors(dir);
      assert.equal(loadErrors.length, 1, 'a require-throwing module must be reported, never silently excluded');
      assert.match(loadErrors[0], /broken-collector\.js/);
      assert.equal(collectorFiles.length, 0, 'a throwing module is not counted as a collector');
    }
  );
});

test('a collector whose require() throws fails the gate with exit 2, not a silent pass', () => {
  // Drive the gate against a tempdir holding ONLY the throwing module — the
  // load-error short-circuits (exit 2) before the AGENTS.md count check, and
  // nothing is written into the real lib/collectors/.
  withTempCollectorDir(
    { 'broken-collector.js': '"use strict";\nthrow new Error("simulated load-time failure");\nmodule.exports = { collect() {} };\n' },
    (dir) => {
    const r = runGateOnDir(dir);
    // EXACT code: a require-time failure is a parse error (exit 2), not drift
    // (1) and never a silent pass (0). Asserting the exact code is what the
    // anti-coincidence rule requires.
    assert.equal(
      r.status, 2,
      `a require-throwing collector must surface (exit 2), not be silently dropped; ` +
      `got status ${r.status}, stdout: ${r.stdout}, stderr: ${r.stderr}`
    );
    assert.match(r.stderr, /cannot load/);
    assert.match(r.stderr, /broken-collector\.js/);
    // It must NOT report the clean "enumerated correctly" line — that would
    // mean the broken file was excluded from the checked set.
    assert.doesNotMatch(r.stdout, /enumerated correctly/);
    }
  );
});

test('the gate FORBIDS a reserved-prefix fixture in its collectors dir (exit 2, named), so a leak cannot ship', () => {
  // P2 leak-guard: a `__`-prefixed file in the validated collectors dir is
  // stray scaffolding that lib/-wholesale publishing would otherwise pack.
  // The gate must hard-fail and name it, distinct from a "cannot load" error.
  withTempCollectorDir(
    { '__leaked_fixture.js': '"use strict";\nthrow new Error("a leaked test fixture must not ship");\n' },
    (dir) => {
      const r = runGateOnDir(dir);
      assert.equal(r.status, 2, `a reserved-prefix fixture must fail the gate (exit 2); stderr: ${r.stderr}`);
      assert.match(r.stderr, /reserved-prefix file/);
      assert.match(r.stderr, /__leaked_fixture\.js/);
    }
  );
});

test('a __-prefixed file is ignored by classifyCollectors so a leaked fixture cannot poison enumeration', () => {
  // The reserved-prefix guard: even a THROWING __ fixture (the exact shape a
  // process-killed run used to leave in lib/collectors/) is skipped, never a
  // load error, and never counted — only the real collector is.
  withTempCollectorDir(
    {
      '__leaked_fixture.js': '"use strict";\nthrow new Error("a leaked test fixture must not poison the gate");\n',
      'real-collector.js': '"use strict";\nmodule.exports = { collect() {}, playbook_id: "x" };\n',
    },
    (dir) => {
      const { loadErrors, collectorFiles } = classifyCollectors(dir);
      assert.equal(loadErrors.length, 0, 'a __-prefixed throwing fixture must be skipped, not surfaced as a load error');
      assert.deepEqual(collectorFiles, ['lib/collectors/real-collector.js'], 'only the real collector is counted; the __ fixture is ignored');
    }
  );
});

test('a require-succeeds-without-collect helper is still excluded, not treated as a load error', () => {
  // Regression guard for the by-design exclusion: scan-excludes.js requires
  // cleanly but exports no collect(). It must remain a silent exclusion (not
  // counted, not a load error).
  withTempCollectorDir(
    { 'helper-no-collect.js': '"use strict";\nmodule.exports = { someHelper() { return 1; } };\n' },
    (dir) => {
      const { loadErrors, collectorFiles } = classifyCollectors(dir);
      assert.equal(loadErrors.length, 0, 'a clean helper must NOT be a load error');
      assert.equal(collectorFiles.length, 0, 'a module exporting no collect() is excluded from the collector count');
    }
  );
});

test('the silent require-throw catch is gone from the gate source', () => {
  const code = executableSource(GATE);
  // The pre-fix pattern was `catch { return false; }` inside the .filter()
  // that built the collector set. Its reintroduction reopens the silent-drop
  // path; this static guard fails before the gate can ship non-authoritative.
  assert.doesNotMatch(
    code, /catch\s*\{\s*return\s+false\s*;?\s*\}/,
    'a bare `catch { return false }` in the collector classifier silently drops ' +
    'a require-throwing module from the count + enumeration check; surface it as a load error instead'
  );
});
});
