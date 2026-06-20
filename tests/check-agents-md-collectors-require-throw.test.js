'use strict';

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
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const GATE = path.join(ROOT, 'scripts', 'check-agents-md-collectors.js');
const COLLECTOR_DIR = path.join(ROOT, 'lib', 'collectors');

function runGate() {
  return spawnSync(process.execPath, [GATE], { encoding: 'utf8', timeout: 30000 });
}

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

test('a collector whose require() throws fails the gate with exit 2, not a silent pass', () => {
  // Marked test artifact; created and removed inside this test only.
  const fixture = path.join(COLLECTOR_DIR, '__require_throw_fixture.js');
  fs.writeFileSync(
    fixture,
    '"use strict";\nthrow new Error("simulated load-time failure");\nmodule.exports = { collect() {} };\n'
  );
  try {
    const r = runGate();
    // EXACT code: a require-time failure is a parse error (exit 2), not drift
    // (1) and never a silent pass (0). Asserting the exact code is what the
    // anti-coincidence rule requires.
    assert.equal(
      r.status, 2,
      `a require-throwing collector must surface (exit 2), not be silently dropped; ` +
      `got status ${r.status}, stdout: ${r.stdout}, stderr: ${r.stderr}`
    );
    assert.match(r.stderr, /cannot load/);
    assert.match(r.stderr, /__require_throw_fixture\.js/);
    // It must NOT report the clean "enumerated correctly" line — that would
    // mean the broken file was excluded from the checked set.
    assert.doesNotMatch(r.stdout, /enumerated correctly/);
  } finally {
    fs.rmSync(fixture, { force: true });
  }
});

test('a require-succeeds-without-collect helper is still excluded, not treated as a load error', () => {
  // Regression guard for the by-design exclusion: scan-excludes.js requires
  // cleanly but exports no collect(). It must remain a silent exclusion (not
  // counted, not a load error), so the gate stays green at 14/14.
  const fixture = path.join(COLLECTOR_DIR, '__helper_no_collect_fixture.js');
  fs.writeFileSync(
    fixture,
    '"use strict";\nmodule.exports = { someHelper() { return 1; } };\n'
  );
  try {
    const r = runGate();
    // A pure helper neither inflates the count (which would flip exit 1 drift)
    // nor counts as a load error (exit 2). The tree stays clean.
    assert.equal(
      r.status, 0,
      `a helper exporting no collect() must be excluded silently, not flagged; ` +
      `got status ${r.status}, stderr: ${r.stderr}`
    );
    assert.doesNotMatch(r.stderr, /cannot load/);
  } finally {
    fs.rmSync(fixture, { force: true });
  }
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
