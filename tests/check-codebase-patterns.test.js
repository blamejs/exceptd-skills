'use strict';

/**
 * tests/check-codebase-patterns.test.js
 *
 * Subject coverage for scripts/check-codebase-patterns.js — the static
 * codebase-pattern gate. Three detectors are exercised:
 *
 *   requireMainRanges / detectProcessExitAfterStdout — the require.main block
 *     range is string/comment/template aware so a stray brace inside a string
 *     or comment can't over- or under-extend the range, and the backward
 *     stdout scan steps over control-flow openers (for/if/while/...) to reach
 *     the real stdout write before a process.exit().
 *   FUNCTION_START — matches genuine function/method/arrow openers but refuses
 *     control-flow openers.
 *   detectDynamicRegex — flags a `new RegExp(` whose pattern argument is a
 *     bare identifier or template on the SAME or the NEXT line, honors the
 *     `// allow:dynamic-regex` marker, and leaves static string-literal
 *     patterns unflagged.
 *
 * Fixtures live in isolated mkdtemp dirs; the repo tree is never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');

const patterns = require(path.join(ROOT, 'scripts', 'check-codebase-patterns.js'));

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egates-'));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, 'utf8');
  return { dir, p };
}

// --------------------------------------------------------------------------
// requireMainRanges is string/comment/template aware
// --------------------------------------------------------------------------

test('#23 an unbalanced `{` inside a STRING in the require.main block does not over-extend the range onto a later libFn', () => {
  const lines = [
    "if (require.main === module) {",            // 1
    "  console.log('open brace in a string: {');", // 2 — the stray `{` must NOT bump depth
    "}",                                          // 3 — block closes here
    "",                                           // 4
    "function libFn() {",                         // 5
    "  process.stdout.write('result\\n');",       // 6
    "  process.exit(1);",                         // 7 — must be FLAGGED (not in require.main range)
    "}",                                          // 8
  ];
  const ranges = patterns.requireMainRanges(lines);
  // The require.main block is exactly lines 1..3 — NOT extended down to libFn.
  assert.deepEqual(ranges, [[1, 3]]);

  const { dir, p } = tmpFile('reqmain-string.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 7);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a `}` inside a string does not truncate the range early (the genuine CLI-entry exit is NOT flagged)', () => {
  const lines = [
    "if (require.main === module) {",             // 1
    "  console.log('closing brace literal: }');", // 2 — stray `}` must NOT drop depth
    "  process.stdout.write('cli\\n');",          // 3
    "  process.exit(0);",                         // 4 — inside require.main: NOT flagged
    "}",                                          // 5 — real close
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 5]]);

  const { dir, p } = tmpFile('reqmain-close-string.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a `/* { */` block comment inside the require.main block does not skew the brace balance', () => {
  const lines = [
    "if (require.main === module) {",   // 1
    "  /* an opening brace { in a comment */", // 2
    "  doThing();",                     // 3
    "}",                                // 4
    "function later() {",               // 5
    "  console.log('x');",              // 6
    "  process.exit(2);",               // 7 — must be FLAGGED
    "}",                                // 8
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 4]]);

  const { dir, p } = tmpFile('reqmain-blockcomment.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 7);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a multi-line template literal containing braces does not skew the balance', () => {
  const lines = [
    "if (require.main === module) {",   // 1
    "  const t = `line one {",          // 2 — template body brace, not code
    "  still in template }`;",          // 3 — template body brace, not code
    "  run(t);",                        // 4
    "}",                                // 5
    "function after() {",              // 6
    "  console.log('done');",           // 7
    "  process.exit(3);",               // 8 — must be FLAGGED
    "}",                                // 9
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 5]]);

  const { dir, p } = tmpFile('reqmain-template.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 8);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 template interpolation `${ ... }` braces ARE counted as code', () => {
  // The interpolation expression is real code; its braces participate in
  // balance, but the `${` opener and the matching `}` are template punctuation.
  const lines = [
    "if (require.main === module) {",        // 1
    "  const s = `value: ${obj.k}`;",        // 2 — net code-brace delta 0
    "  go(s);",                              // 3
    "}",                                     // 4
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 4]]);
});

// --------------------------------------------------------------------------
// FUNCTION_START refuses control-flow openers
// --------------------------------------------------------------------------

test('#24 a for-loop between the stdout write and process.exit does not stop the backward scan', () => {
  const lines = [
    "function run() {",                  // 1
    "  console.log('summary');",         // 2 — stdout write
    "  for (const n of items) {",        // 3 — control-flow opener: must NOT stop the scan
    "    validate(n);",                  // 4
    "  }",                               // 5
    "  process.exit(1);",                // 6 — must be FLAGGED
    "}",                                 // 7
  ];
  const { dir, p } = tmpFile('ctrlflow-for.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 6);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#24 an if-block between the write and exit does not stop the scan; a separate earlier function is not cross-attributed', () => {
  const lines = [
    "function earlier() {",              // 1
    "  process.exit(9);",                // 2 — no stdout before it in THIS fn: NOT flagged
    "}",                                 // 3
    "function later() {",                // 4
    "  process.stdout.write('out\\n');", // 5 — stdout write
    "  if (cond) {",                     // 6 — control-flow opener
    "    tidy();",                       // 7
    "  }",                               // 8
    "  process.exit(2);",                // 9 — must be FLAGGED
    "}",                                 // 10
  ];
  const { dir, p } = tmpFile('ctrlflow-if.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 9);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#24 FUNCTION_START still matches genuine function/method/arrow openers but not control-flow', () => {
  const FS = patterns.FUNCTION_START;
  // Positives — real function-body openers.
  assert.equal(FS.test('function foo() {'), true);
  assert.equal(FS.test('async function bar() {'), true);
  assert.equal(FS.test('  myMethod(a, b) {'), true);
  assert.equal(FS.test('  process() {'), true); // a method literally named process
  assert.equal(FS.test('const f = (a) => {'), true);
  // Negatives — control-flow openers must NOT be treated as a new function.
  assert.equal(FS.test('  for (const n of items) {'), false);
  assert.equal(FS.test('  if (cond) {'), false);
  assert.equal(FS.test('  while (x) {'), false);
  assert.equal(FS.test('  switch (k) {'), false);
  assert.equal(FS.test('  catch (e) {'), false);
  assert.equal(FS.test('  } else if (x) {'), false);
});

// --------------------------------------------------------------------------
// detectDynamicRegex catches multi-line new RegExp(
// --------------------------------------------------------------------------

test('#25 a multi-line `new RegExp(` with a bare-identifier pattern on the next line is FLAGGED', () => {
  const lines = [
    "function build(pat) {",
    "  const re = new RegExp(",
    "    pat",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 2); // flagged at the `new RegExp(` line
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 a multi-line `new RegExp(` whose next line is a STRING literal is NOT flagged (static)', () => {
  const lines = [
    "function build() {",
    "  const re = new RegExp(",
    "    \"^[a-z]+$\"",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-static.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 a multi-line `new RegExp(` whose next line starts with a BACKTICK template IS flagged', () => {
  const lines = [
    "function build(tok) {",
    "  const re = new RegExp(",
    "    `prefix-${tok}`",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-template.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 the multi-line path honors the `// allow:dynamic-regex` marker', () => {
  const lines = [
    "function build(pat) {",
    "  const re = new RegExp( // allow:dynamic-regex — trusted bundled schema",
    "    pat",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-allow.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 the single-line dynamic-regex path is unchanged (bare identifier flagged, string literal not)', () => {
  const lines = [
    "const a = new RegExp(userPat);",   // 1 — dynamic, flagged
    "const b = new RegExp('^x$');",      // 2 — static, not flagged
  ];
  const { dir, p } = tmpFile('singleline-regex.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});


// ---- routed from codebase-patterns-readability-rules ----
require("node:test").describe("codebase-patterns-readability-rules", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/codebase-patterns-readability-rules.test.js
 *
 * Covers the two opt-in readability detectors added to
 * scripts/check-codebase-patterns.js (unsorted-marked-array,
 * misaligned-marked-run), the dynamic-regex severity pin, and the
 * doctor flag-allowlist drift guard. Anti-coincidence: each detector is
 * asserted to FIRE on a bad sample AND stay silent on a good/unmarked one,
 * so a future no-op refactor cannot pass these by accident.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const gate = require('../scripts/check-codebase-patterns.js');
const { VERB_FLAG_ALLOWLIST, flagsFor } = require('../lib/flag-suggest.js');

const ROOT = path.join(__dirname, '..');

// ---- unsorted-marked-array ----

// ---- misaligned-marked-run ----

// ---- detector wrappers (tree walk) ----

// ---- severity pins / registration ----

// ---- doctor flag-allowlist drift guard ----

test('unsorted-marked-array: fires on a // keep-sorted array that is out of order', () => {
  const lines = ['const X = [ // keep-sorted', "  'gamma', 'alpha', 'beta',", '];'];
  const hits = gate.scanUnsortedMarkedArray('synthetic.js', lines);
  assert.equal(hits.length, 1, 'must flag the out-of-order marked array');
  assert.match(hits[0].why, /alphabetical order/);
});

test('unsorted-marked-array: silent on a sorted marked array', () => {
  const lines = ['const X = [ // keep-sorted', "  'alpha', 'beta', 'gamma',", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});

test('unsorted-marked-array: opt-in — an UNmarked out-of-order array is not flagged', () => {
  const lines = ['const X = [', "  'gamma', 'alpha',", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});

test('unsorted-marked-array: skips non-flat arrays (object elements)', () => {
  const lines = ['const X = [ // keep-sorted', "  { id: 'z' }, { id: 'a' },", '];'];
  assert.equal(gate.scanUnsortedMarkedArray('synthetic.js', lines).length, 0);
});

test('misaligned-marked-run: fires when // keep-aligned columns differ', () => {
  const lines = ['  // keep-aligned', '  alpha = 1,', '  bb = 2,', ''];
  const hits = gate.scanMisalignedMarkedRun('synthetic.js', lines);
  assert.equal(hits.length, 1, 'must flag the misaligned run');
  assert.match(hits[0].why, /columns are not all equal/);
});

test('misaligned-marked-run: silent on an aligned run', () => {
  const lines = ['  // keep-aligned', '  alpha = 1,', '  bb    = 2,', ''];
  assert.equal(gate.scanMisalignedMarkedRun('synthetic.js', lines).length, 0);
});

test('misaligned-marked-run: opt-in — an UNmarked misaligned run is not flagged', () => {
  const lines = ['  alpha = 1,', '  bb = 2,', ''];
  assert.equal(gate.scanMisalignedMarkedRun('synthetic.js', lines).length, 0);
});

test('detectUnsortedMarkedArray / detectMisalignedMarkedRun scan the tree and return arrays', () => {
  assert.ok(Array.isArray(gate.detectUnsortedMarkedArray()), 'detectUnsortedMarkedArray returns an array');
  assert.ok(Array.isArray(gate.detectMisalignedMarkedRun()), 'detectMisalignedMarkedRun returns an array');
  // the engine file holds the detector + marker prose, so it self-skips → no hits
  assert.deepEqual(gate.detectUnsortedMarkedArray(['scripts/check-codebase-patterns.js']), []);
  assert.deepEqual(gate.detectMisalignedMarkedRun(['scripts/check-codebase-patterns.js']), []);
});

test('dynamic-regex is registered as a blocking class (warnOnly === false)', () => {
  const c = gate.CLASSES.find((x) => x.id === 'dynamic-regex');
  assert.ok(c, 'dynamic-regex class present');
  assert.equal(c.warnOnly, false, 'dynamic-regex must be blocking now that all sites carry markers');
});

test('the two new readability classes are registered and blocking', () => {
  for (const id of ['unsorted-marked-array', 'misaligned-marked-run']) {
    const c = gate.CLASSES.find((x) => x.id === id);
    assert.ok(c, `${id} registered`);
    assert.equal(c.warnOnly, false, `${id} blocking`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from codebase-patterns ----
require("node:test").describe("codebase-patterns", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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



// The process-exit-after-stdout detector must NOT scan a narrower root set than
// its sibling detectors. bin/exceptd.js (the CLI dispatch surface) and scripts/
// (gate/build/release tooling) are exactly where write-then-exit recurs, and a
// detector whose default scope omits them passes green while the class it guards
// ships unchecked there. These probes fail if the default ever narrows back to
// lib+orchestrator.

test('process-exit-after-stdout-write: live tree is clean (the stdout-flush-truncation class stays fixed)', () => {
  assert.equal(gate.detectProcessExitAfterStdout().length, 0,
    'a library function that writes to stdout then process.exit() must use safeExit + return');
});

test('dynamic-regex: live tree is clean (every site fixed or allow-marked)', () => {
  assert.equal(gate.detectDynamicRegex().length, 0,
    'every new RegExp(<non-literal>) is anchored/capped or carries an allow:dynamic-regex marker');
});

test('process-exit-after-stdout-write: default scope covers bin/exceptd.js and scripts/ (parity with sibling detectors)', () => {
  // Structural pin: the no-arg detector's default root list must literally name
  // bin/exceptd.js and scripts. Reading the function source is the only way to
  // assert WHICH roots the default walks (filesUnder takes the roots as an arg,
  // so a count-only probe over the clean live tree can't distinguish the narrow
  // default from the wide one — both yield 0). This catches a silent revert to
  // filesUnder(["lib","orchestrator"]).
  const src = gate.detectProcessExitAfterStdout.toString();
  const defaultRoots = src.match(/filesUnder\(\[([^\]]*)\]\)/);
  assert.ok(defaultRoots, 'detectProcessExitAfterStdout has a filesUnder default');
  const roots = defaultRoots[1];
  assert.match(roots, /["']bin\/exceptd\.js["']/,
    'default scope must include bin/exceptd.js — the CLI dispatch surface where version/path write-then-exit');
  assert.match(roots, /["']scripts["']/,
    'default scope must include scripts/ — gate/build/release tooling, the other home of write-then-exit');

  // Behavioural pin: a scripts/-shaped fixture with a stdout-write-then-exit is
  // flagged by the same per-file logic the default walk runs over scripts/.
  const planted = fixture('function run() {\n  process.stdout.write("summary\\n");\n  process.exit(1);\n}\nrun();\n');
  assert.equal(gate.detectProcessExitAfterStdout([planted]).length, 1,
    'a write-then-exit in a scripts/-shaped file is flagged');

  // The widened default must stay clean: every bin/+scripts/ site is either
  // remediated (safeExit + return) or carries a reviewed allow marker. This is
  // the assertion the original lib+orchestrator-only default could pass while
  // bin/+scripts/ shipped the class unflagged.
  assert.equal(gate.detectProcessExitAfterStdout().length, 0,
    'with bin/+scripts/ in default scope, every surfaced site is fixed or allow-marked');
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

  // A `//` inside a string literal (e.g. a URL) on the process.exit line must
  // NOT be treated as a comment — otherwise the line is truncated at `http:`
  // and the real process.exit is never seen by the detector.
  const urlLine = fixture('function f() {\n  process.stdout.write("x");\n  const u = "http://e.com/p"; process.exit(1);\n}\n');
  assert.equal(gate.detectProcessExitAfterStdout([urlLine]).length, 1,
    'a URL string containing // must not hide the trailing process.exit');
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

  // The file-level form (codebase-patterns:allow-file) is the broadest
  // exemption and must face the same validation, or a reason-less/typo'd
  // file-level marker would suppress every hit silently.
  const fileNoReason = fixture('// codebase-patterns:allow-file dynamic-regex\nconst x = 1;\n');
  assert.equal(gate.detectOrphanAllowClass([fileNoReason]).length, 1, 'a reason-less file-level marker is flagged');

  const fileUnknown = fixture('// codebase-patterns:allow-file not-a-real-class — reason\nconst x = 1;\n');
  assert.equal(gate.detectOrphanAllowClass([fileUnknown]).length, 1, 'an unknown-class file-level marker is flagged');

  const fileGood = fixture('// codebase-patterns:allow-file dynamic-regex — a real reason\nconst x = 1;\n');
  assert.equal(gate.detectOrphanAllowClass([fileGood]).length, 0, 'a valid file-level marker is fine');
});

test('bidi-codepoint-literal: live tree is clean (no raw Trojan-Source codepoints in source)', () => {
  assert.equal(gate.detectBidiCodepointLiteral().length, 0,
    'no raw bidi-override / zero-width / null codepoint literal in source (escape or vendor/blamejs/codepoint-class it)');
});

test('bidi-codepoint-literal: catches a raw bidi/zero-width/null literal; escape + marker exempt it', () => {
  // \u202E in the test SOURCE becomes the literal RLO char in the fixture FILE.
  const bidi = fixture('const x = "a\u202Eb";\n');
  assert.equal(gate.detectBidiCodepointLiteral([bidi]).length, 1, 'a raw bidi-override literal is flagged');
  const zw = fixture('const x = "a\u200Bb";\n');
  assert.equal(gate.detectBidiCodepointLiteral([zw]).length, 1, 'a raw zero-width literal is flagged');
  const nul = fixture('const x = "a' + String.fromCharCode(0) + 'b";\n');
  assert.equal(gate.detectBidiCodepointLiteral([nul]).length, 1, 'a raw null literal is flagged');
  // \\u202E in the test source writes the ESCAPE text (backslash-u-202E), not the char.
  const escaped = fixture('const x = "a\\u202Eb";\n');
  assert.equal(gate.detectBidiCodepointLiteral([escaped]).length, 0, 'a \\uXXXX escape is not a literal');
  const clean = fixture('const x = "plain ascii";\n');
  assert.equal(gate.detectBidiCodepointLiteral([clean]).length, 0, 'clean ASCII is not flagged');
  const marked = fixture('const x = "a\u202Eb"; // allow:bidi-codepoint-literal — fixture\n');
  assert.equal(gate.detectBidiCodepointLiteral([marked]).length, 0, 'an allow marker suppresses it');
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

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-E-gates ----
require("node:test").describe("hunt-fix-E-gates", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the E-gates cluster — six gate-script false-passes:
 *
 *   #22 check-test-count.js counts only `test(`, blind to `it()` BDD-style
 *       tests (~10% of the suite).
 *   #23 check-codebase-patterns requireMainRanges balances braces with no
 *       string/comment awareness — a `{` inside a string in the require.main
 *       block over-extends the computed range onto a later library function,
 *       whose process.exit() is then wrongly treated as a CLI-entry exit.
 *   #24 FUNCTION_START matches control-flow openers (`for/if/while/...`), so the
 *       backward stdout scan stops at the loop/conditional and never reaches the
 *       stdout write — the exit goes unflagged.
 *   #25 detectDynamicRegex misses a `new RegExp(` whose pattern arg is on the
 *       NEXT line (multi-line call) — a ReDoS sink ships unflagged.
 *   #26 VERSION_TAG_RE's trailing `(?![\d.])` also rejects a sentence-ending
 *       period, so `// fixed in 0.18.9.` residue is not counted.
 *   #27 check-sbom-currency completeness check expands the file allowlist
 *       against the SOURCE repo, ignoring the `--root` target tree.
 *
 * In-process: require the gate modules and call exported functions. Fixtures
 * live in isolated mkdtemp dirs; the repo tree is never mutated. Each case
 * fails on the pre-fix behavior and passes after, asserting EXACT values.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');

const { countTests } = require(path.join(ROOT, 'scripts', 'check-test-count.js'));
const patterns = require(path.join(ROOT, 'scripts', 'check-codebase-patterns.js'));
const { VERSION_TAG_RE } = require(path.join(ROOT, 'scripts', 'check-version-tags.js'));
const { checkSbomCurrency, expandAllowlistAt } = require(path.join(ROOT, 'scripts', 'check-sbom-currency.js'));

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egates-'));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, 'utf8');
  return { dir, p };
}

// --------------------------------------------------------------------------
// #22 — check-test-count counts both test() and it()
// --------------------------------------------------------------------------





// --------------------------------------------------------------------------
// #23 — requireMainRanges is string/comment/template aware
// --------------------------------------------------------------------------






// --------------------------------------------------------------------------
// #24 — FUNCTION_START refuses control-flow openers
// --------------------------------------------------------------------------




// --------------------------------------------------------------------------
// #25 — detectDynamicRegex catches multi-line new RegExp(
// --------------------------------------------------------------------------






// --------------------------------------------------------------------------
// #26 — VERSION_TAG_RE allows a sentence-ending period
// --------------------------------------------------------------------------




// --------------------------------------------------------------------------
// #27 — check-sbom-currency completeness honors --root
// --------------------------------------------------------------------------

// Build a self-contained, minimal --root target tree whose SBOM is complete and
// consistent, then add a target-only shipped file with NO file: component and
// assert the gate flags it. The pre-fix gate computed `expected` against the
// SOURCE repo (refresh-sbom's REPO_ROOT), so a target-only file was invisible.
function sha256(buf) {
  return require('crypto').createHash('sha256').update(buf).digest('hex');
}
function sha3_512(buf) {
  return require('crypto').createHash('sha3-512').update(buf).digest('hex');
}

function buildRootTree(extraFiles /* { rel: content } */, opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-root-'));
  // Minimal real files referenced by checkSbomCurrency.
  const files = {
    'manifest.json': JSON.stringify({ version: '9.9.9', skills: [] }),
    'lib/a.js': "console.log('a');\n",
    'README.md': '# target\n',
    ...extraFiles,
  };
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  // data/ dir with a catalog so readdirSync + jurisdiction/catalog logic work.
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  fs.writeFileSync(path.join(root, 'data', 'cve-catalog.json'), JSON.stringify({ _meta: {}, 'CVE-1': {} }));

  // package.json.files lists every shipped file (dirs expand recursively).
  const pkgFiles = opts.pkgFiles || ['manifest.json', 'lib', 'README.md'];
  fs.writeFileSync(path.join(root, 'package.json'),
    JSON.stringify({ name: 'x', version: '9.9.9', description: 'desc', files: pkgFiles }));

  // file: components for whichever files we want represented (default: only the
  // base set, deliberately omitting any extra so the completeness gate fires).
  const componentRels = opts.componentRels || ['manifest.json', 'lib/a.js', 'README.md'];
  const fileComps = componentRels.map((rel) => {
    const buf = fs.readFileSync(path.join(root, rel));
    return {
      'bom-ref': `file:${rel}`,
      type: 'file',
      name: rel,
      hashes: [
        { alg: 'SHA-256', content: sha256(buf) },
        { alg: 'SHA3-512', content: sha3_512(buf) },
      ],
    };
  });
  // Aggregate bundle digest over the (sorted) file comps, matching bundleDigest.
  const { bundleDigest } = require(path.join(ROOT, 'scripts', 'refresh-sbom.js'));
  const bundleSha = bundleDigest(fileComps);

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: {
      component: {
        description: '1 catalogs (1 CVEs) / 0 skills',
        hashes: [{ alg: 'SHA-256', content: bundleSha }],
      },
      properties: [
        { name: 'exceptd:catalog:count', value: '1' },
        { name: 'exceptd:skill:count', value: '0' },
      ],
    },
    components: fileComps,
  };
  fs.writeFileSync(path.join(root, 'sbom.cdx.json'), JSON.stringify(sbom));
  return root;
}

test('#23 an unbalanced `{` inside a STRING in the require.main block does not over-extend the range onto a later libFn', () => {
  const lines = [
    "if (require.main === module) {",            // 1
    "  console.log('open brace in a string: {');", // 2 — the stray `{` must NOT bump depth
    "}",                                          // 3 — block closes here
    "",                                           // 4
    "function libFn() {",                         // 5
    "  process.stdout.write('result\\n');",       // 6
    "  process.exit(1);",                         // 7 — must be FLAGGED (not in require.main range)
    "}",                                          // 8
  ];
  const ranges = patterns.requireMainRanges(lines);
  // The require.main block is exactly lines 1..3 — NOT extended down to libFn.
  assert.deepEqual(ranges, [[1, 3]]);

  const { dir, p } = tmpFile('reqmain-string.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 7);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a `}` inside a string does not truncate the range early (the genuine CLI-entry exit is NOT flagged)', () => {
  const lines = [
    "if (require.main === module) {",             // 1
    "  console.log('closing brace literal: }');", // 2 — stray `}` must NOT drop depth
    "  process.stdout.write('cli\\n');",          // 3
    "  process.exit(0);",                         // 4 — inside require.main: NOT flagged
    "}",                                          // 5 — real close
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 5]]);

  const { dir, p } = tmpFile('reqmain-close-string.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a `/* { */` block comment inside the require.main block does not skew the brace balance', () => {
  const lines = [
    "if (require.main === module) {",   // 1
    "  /* an opening brace { in a comment */", // 2
    "  doThing();",                     // 3
    "}",                                // 4
    "function later() {",               // 5
    "  console.log('x');",              // 6
    "  process.exit(2);",               // 7 — must be FLAGGED
    "}",                                // 8
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 4]]);

  const { dir, p } = tmpFile('reqmain-blockcomment.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 7);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 a multi-line template literal containing braces does not skew the balance', () => {
  const lines = [
    "if (require.main === module) {",   // 1
    "  const t = `line one {",          // 2 — template body brace, not code
    "  still in template }`;",          // 3 — template body brace, not code
    "  run(t);",                        // 4
    "}",                                // 5
    "function after() {",              // 6
    "  console.log('done');",           // 7
    "  process.exit(3);",               // 8 — must be FLAGGED
    "}",                                // 9
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 5]]);

  const { dir, p } = tmpFile('reqmain-template.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 8);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#23 template interpolation `${ ... }` braces ARE counted as code', () => {
  // The interpolation expression is real code; its braces participate in
  // balance, but the `${` opener and the matching `}` are template punctuation.
  const lines = [
    "if (require.main === module) {",        // 1
    "  const s = `value: ${obj.k}`;",        // 2 — net code-brace delta 0
    "  go(s);",                              // 3
    "}",                                     // 4
  ];
  const ranges = patterns.requireMainRanges(lines);
  assert.deepEqual(ranges, [[1, 4]]);
});

test('#24 a for-loop between the stdout write and process.exit does not stop the backward scan', () => {
  const lines = [
    "function run() {",                  // 1
    "  console.log('summary');",         // 2 — stdout write
    "  for (const n of items) {",        // 3 — control-flow opener: must NOT stop the scan
    "    validate(n);",                  // 4
    "  }",                               // 5
    "  process.exit(1);",                // 6 — must be FLAGGED
    "}",                                 // 7
  ];
  const { dir, p } = tmpFile('ctrlflow-for.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 6);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#24 an if-block between the write and exit does not stop the scan; a separate earlier function is not cross-attributed', () => {
  const lines = [
    "function earlier() {",              // 1
    "  process.exit(9);",                // 2 — no stdout before it in THIS fn: NOT flagged
    "}",                                 // 3
    "function later() {",                // 4
    "  process.stdout.write('out\\n');", // 5 — stdout write
    "  if (cond) {",                     // 6 — control-flow opener
    "    tidy();",                       // 7
    "  }",                               // 8
    "  process.exit(2);",                // 9 — must be FLAGGED
    "}",                                 // 10
  ];
  const { dir, p } = tmpFile('ctrlflow-if.js', lines.join('\n'));
  try {
    const hits = patterns.detectProcessExitAfterStdout([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 9);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#24 FUNCTION_START still matches genuine function/method/arrow openers but not control-flow', () => {
  const FS = patterns.FUNCTION_START;
  // Positives — real function-body openers.
  assert.equal(FS.test('function foo() {'), true);
  assert.equal(FS.test('async function bar() {'), true);
  assert.equal(FS.test('  myMethod(a, b) {'), true);
  assert.equal(FS.test('  process() {'), true); // a method literally named process
  assert.equal(FS.test('const f = (a) => {'), true);
  // Negatives — control-flow openers must NOT be treated as a new function.
  assert.equal(FS.test('  for (const n of items) {'), false);
  assert.equal(FS.test('  if (cond) {'), false);
  assert.equal(FS.test('  while (x) {'), false);
  assert.equal(FS.test('  switch (k) {'), false);
  assert.equal(FS.test('  catch (e) {'), false);
  assert.equal(FS.test('  } else if (x) {'), false);
});

test('#25 a multi-line `new RegExp(` with a bare-identifier pattern on the next line is FLAGGED', () => {
  const lines = [
    "function build(pat) {",
    "  const re = new RegExp(",
    "    pat",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 2); // flagged at the `new RegExp(` line
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 a multi-line `new RegExp(` whose next line is a STRING literal is NOT flagged (static)', () => {
  const lines = [
    "function build() {",
    "  const re = new RegExp(",
    "    \"^[a-z]+$\"",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-static.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 a multi-line `new RegExp(` whose next line starts with a BACKTICK template IS flagged', () => {
  const lines = [
    "function build(tok) {",
    "  const re = new RegExp(",
    "    `prefix-${tok}`",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-template.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 the multi-line path honors the `// allow:dynamic-regex` marker', () => {
  const lines = [
    "function build(pat) {",
    "  const re = new RegExp( // allow:dynamic-regex — trusted bundled schema",
    "    pat",
    "  );",
    "  return re;",
    "}",
  ];
  const { dir, p } = tmpFile('multiline-regex-allow.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#25 the single-line dynamic-regex path is unchanged (bare identifier flagged, string literal not)', () => {
  const lines = [
    "const a = new RegExp(userPat);",   // 1 — dynamic, flagged
    "const b = new RegExp('^x$');",      // 2 — static, not flagged
  ];
  const { dir, p } = tmpFile('singleline-regex.js', lines.join('\n'));
  try {
    const hits = patterns.detectDynamicRegex([p]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
