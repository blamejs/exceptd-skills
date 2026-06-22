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


// ---- routed from operator-leak-grep ----
require("node:test").describe("operator-leak-grep", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/operator-leak-grep.test.js
 *
 * Operator-facing strings must reference `exceptd <verb>` as the
 * canonical entry point, not `node lib/sign.js …` or
 * `node orchestrator/index.js …` which are contributor-checkout
 * implementation paths that are not on PATH after `npm install -g`.
 *
 * The contributor-checkout form `node $(exceptd path)/lib/…` is allowed
 * as a fallback for users who want to invoke the internal scripts
 * directly — that form is portable because it derives the install path
 * from the operator-facing binary.
 *
 * The class fix: a v0.12.40 finding caught one site; subsequent audits
 * surfaced ~10 more. This test refuses the bare `node lib/…` /
 * `node orchestrator/…` pattern anywhere a string is rendered to the
 * operator.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// Files whose string contents reach the operator.
// - bin/exceptd.js + lib/*.js + orchestrator/*.js: runtime strings.
// - orchestrator/README.md: ships in the tarball.
// - .github/workflows/*.yml: visible to PR reviewers + repo browsers.
// - scripts/*.js + scripts/check-test-coverage.README.md: ship in tarball.
// Documented exclusions:
// - lib/sign.js own --help / usage block (lines 60-73, 458, 478-481):
//   it IS the contributor-checkout entry point; its own --help legitimately
//   references its own invocation form.
function collectFiles() {
  const out = [];
  const dirs = [
    { dir: 'bin', exts: ['.js'] },
    { dir: 'lib', exts: ['.js'] },
    { dir: 'orchestrator', exts: ['.js', '.md'] },
    { dir: 'scripts', exts: ['.js', '.md'] },
  ];
  for (const { dir, exts } of dirs) {
    const abs = path.join(ROOT, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs, { withFileTypes: true })) {
      if (!name.isFile()) continue;
      if (!exts.some(e => name.name.endsWith(e))) continue;
      out.push(path.join(dir, name.name));
    }
  }
  // Add workflow files (one level deep).
  const wfDir = path.join(ROOT, '.github', 'workflows');
  if (fs.existsSync(wfDir)) {
    for (const name of fs.readdirSync(wfDir)) {
      if (name.endsWith('.yml') || name.endsWith('.yaml')) {
        out.push(path.join('.github', 'workflows', name));
      }
    }
  }
  return out;
}

// Match a leaked internal-path reference. The `$(exceptd path)/…` form
// is the documented contributor-checkout fallback; allow it through.
// Bare `node lib/sign.js` / `node orchestrator/index.js` is the leak.
const LEAK_RE = /\bnode\s+(lib|orchestrator)\/(sign|verify|index|playbook-runner|scoring)\.js\b/;

// Per-file allowlist:
// - lib/sign.js: its own usage / --help block is the contributor entry
//   point for that script; legitimately self-references.
// - lib/verify.js: same — its own header docs + CLI usage describe the
//   verify.js entry point. Operator-facing strings inside (warnings,
//   errors) are scrubbed separately via the line-level rules below.
// - .github/workflows/*.yml: workflows run in CI's source-tree checkout
//   where the `exceptd` binary isn't on PATH yet; `node orchestrator/…`
//   is the canonical contributor-checkout form there. Browse via
//   `gh workflow view` not via `npm install`.
const FILE_ALLOWLIST = new Set([
  'lib/sign.js',
  'lib/verify.js',
  '.github/workflows/atlas-currency.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/release.yml',
  '.github/workflows/refresh.yml',
  '.github/workflows/scorecard.yml',
]);

test('no internal `node lib/…` / `node orchestrator/…` paths in operator-facing strings', () => {
  const leaks = [];
  for (const rel of collectFiles()) {
    if (FILE_ALLOWLIST.has(rel.replace(/\\/g, '/'))) continue;
    const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip the `$(exceptd path)/…` form — that's the documented escape.
      if (/\$\(exceptd\s+path\)/.test(line)) continue;
      if (LEAK_RE.test(line)) {
        leaks.push(`${rel.replace(/\\/g, '/')}:${i + 1} — ${line.trim().slice(0, 140)}`);
      }
    }
  }
  assert.equal(leaks.length, 0,
    `Internal-path leaks in operator-facing strings (use \`exceptd <verb>\` or \`node $(exceptd path)/lib/…\` instead):\n  ${leaks.join('\n  ')}`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});

require("node:test").describe("check-codebase-patterns brace + regex helpers", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const { countCodeBraces, newBraceState, isStaticRegexFirstChar } = require("../scripts/check-codebase-patterns.js");
  test("newBraceState starts outside every string/template/comment context", () => {
    assert.deepEqual(newBraceState(), { inSingle: false, inDouble: false, inTemplate: false, inBlock: false, templateExpr: [] });
  });
  test("countCodeBraces nets code braces and ignores braces inside strings", () => {
    assert.equal(countCodeBraces("a { b {", newBraceState()), 2);
    assert.equal(countCodeBraces("if (x) { y(); }", newBraceState()), 0);
    assert.equal(countCodeBraces('const s = "a { b";', newBraceState()), 0);
  });
  test("isStaticRegexFirstChar is true only for a quote or slash literal start", () => {
    for (const c of ['"', "'", "/"]) assert.equal(isStaticRegexFirstChar(c), true, c);
    for (const c of ["a", "$", "(", "x"]) assert.equal(isStaticRegexFirstChar(c), false, c);
  });
});
