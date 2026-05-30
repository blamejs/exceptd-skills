'use strict';

/**
 * tests/codebase-patterns.test.js
 *
 * Pins the codebase-patterns gate (scripts/check-codebase-patterns.js): the
 * live tree is clean for the blocking classes, every detector both CATCHES a
 * planted violation and is SUPPRESSED by a correct allow-marker, the
 * allow-class registry matches the markable detectors, and the upstream
 * currency check is wired. Fixtures are written to a tempdir (unique path per
 * case so the line cache can't go stale), never into the source tree.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const gate = require('../scripts/check-codebase-patterns.js');
const currency = require('../scripts/check-codebase-patterns-currency.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-cbp-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });

let _n = 0;
function fixture(content) {
  const p = path.join(TMP, `fx-${_n++}.js`);
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

// ---- live tree is clean for every shipped class --------------------------

test('process-exit-after-stdout-write: live tree is clean (the stdout-flush-truncation class stays fixed)', () => {
  assert.equal(gate.detectProcessExitAfterStdout().length, 0,
    'a library function that writes to stdout then process.exit() must use safeExit + return');
});

test('dynamic-regex: live tree is clean (every site fixed or allow-marked)', () => {
  assert.equal(gate.detectDynamicRegex().length, 0,
    'every new RegExp(<non-literal>) is anchored/capped or carries an allow:dynamic-regex marker');
});

test('orphan-allow-class: live tree is clean (no typo\'d or reason-less allow markers)', () => {
  assert.equal(gate.detectOrphanAllowClass().length, 0,
    'every // allow:<class> names a registered class and carries a — reason');
});

// ---- registry matches the markable detectors -----------------------------

test('VALID_ALLOW_CLASSES holds exactly the markable detector classes', () => {
  // orphan-allow-class is the meta-guard, intentionally NOT markable; the
  // other two accept markers. A new markable detector without a registry
  // entry (or vice versa) would make its markers self-orphan.
  const markable = gate.CLASSES.filter(c => c.id !== 'orphan-allow-class').map(c => c.id).sort();
  assert.deepEqual(Object.keys(gate.VALID_ALLOW_CLASSES).sort(), markable,
    'VALID_ALLOW_CLASSES must equal the set of markable detector ids');
  // filesUnder is the shared source-walk the detectors share; it must return
  // a sorted array of repo-relative paths and exclude *.test.js.
  const libFiles = gate.filesUnder(['lib']);
  assert.ok(Array.isArray(libFiles) && libFiles.length > 0, 'filesUnder([lib]) returns a non-empty array');
  assert.ok(libFiles.every(f => !/\.test\.js$/.test(f)), 'filesUnder excludes *.test.js');
});

// ---- each detector catches a planted violation + is suppressed -----------

test('process-exit-after-stdout-write: catches a planted violation and a marker suppresses it', () => {
  const bad = fixture('function f() {\n  process.stdout.write("x");\n  process.exit(1);\n}\n');
  assert.equal(gate.detectProcessExitAfterStdout([bad]).length, 1, 'stdout-write then process.exit is flagged');

  const ok = fixture('function f() {\n  process.stdout.write("x");\n  process.exit(1); // allow:process-exit-after-stdout-write — fixture\n}\n');
  assert.equal(gate.detectProcessExitAfterStdout([ok]).length, 0, 'a same-line allow marker suppresses it');

  const noStdout = fixture('function f() {\n  doThing();\n  process.exit(1);\n}\n');
  assert.equal(gate.detectProcessExitAfterStdout([noStdout]).length, 0, 'process.exit with no preceding stdout write is not flagged');

  const inMain = fixture('if (require.main === module) {\n  process.stdout.write("x");\n  process.exit(1);\n}\n');
  assert.equal(gate.detectProcessExitAfterStdout([inMain]).length, 0, 'a require.main CLI-entry block is exempt');
});

test('dynamic-regex: catches new RegExp(<non-literal>) and a marker suppresses it', () => {
  const bad = fixture('const re = new RegExp(userInput);\n');
  assert.equal(gate.detectDynamicRegex([bad]).length, 1, 'new RegExp(identifier) is flagged');

  const literal = fixture('const re = new RegExp("^a+$");\n');
  assert.equal(gate.detectDynamicRegex([literal]).length, 0, 'a string-literal RegExp is static, not flagged');

  const ok = fixture('const re = new RegExp(userInput); // allow:dynamic-regex — fixture\n');
  assert.equal(gate.detectDynamicRegex([ok]).length, 0, 'an allow marker suppresses it');
});

test('orphan-allow-class: catches an unknown class and a reason-less marker', () => {
  const unknown = fixture('const x = 1; // allow:not-a-real-class — has a reason but bogus class\n');
  assert.equal(gate.detectOrphanAllowClass([unknown]).length, 1, 'an unregistered allow-class is flagged');

  const noReason = fixture('const x = 1; // allow:dynamic-regex\n');
  assert.equal(gate.detectOrphanAllowClass([noReason]).length, 1, 'a registered class without a — reason is flagged');

  const good = fixture('const x = 1; // allow:dynamic-regex — a real reason\n');
  assert.equal(gate.detectOrphanAllowClass([good]).length, 0, 'a registered class with a reason is fine');
});

// ---- currency check wiring ------------------------------------------------

test('currency check exports a non-empty triaged upstream set + parser', () => {
  assert.ok(Array.isArray(currency.UPSTREAM_TRIAGED), 'UPSTREAM_TRIAGED is an array');
  assert.ok(currency.UPSTREAM_TRIAGED.length >= 40, 'records the triaged upstream catalog');
  assert.equal(typeof currency.upstreamClasses, 'function', 'exports the registry parser');
  assert.equal(typeof currency.upstreamPatternsPath, 'function', 'exports the upstream-path resolver');
  assert.equal(typeof currency.upstreamPatternsPath(), 'string', 'resolves to a path string');
  // The two classes exceptd actually adopted must be in the triaged set.
  for (const adopted of ['process-exit', 'dynamic-regex']) {
    assert.ok(currency.UPSTREAM_TRIAGED.includes(adopted), `${adopted} is recorded as triaged`);
  }
});
