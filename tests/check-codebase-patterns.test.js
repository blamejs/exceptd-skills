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

require("node:test").describe("hand-rolled-sql detector (forward injection guard)", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const p = require("../scripts/check-codebase-patterns.js");
  test("the matchers flag a SQL driver import + statement/clause construction, not benign requires", () => {
    assert.ok(p.SQL_DRIVER_IMPORT.test('const db = require("better-sqlite3")("x.db")'));
    assert.ok(p.SQL_DRIVER_IMPORT.test('const { Pool } = require("pg")'));
    assert.ok(!p.SQL_DRIVER_IMPORT.test('const path = require("node:path")'));
    assert.ok(p.SQL_STMT_START.test('const q = "SELECT * FROM t WHERE id=" + id'));
    assert.ok(p.SQL_STMT_START.test('db.exec("DELETE FROM sessions")'));
    assert.ok(p.SQL_CLAUSE_FRAG.test('q = base + " WHERE id=" + id'));   // leading-+ concat
    assert.ok(p.SQL_CLAUSE_FRAG.test('q = " WHERE id=" + id'));          // trailing-+ concat
  });
  test("detector is inert on the real tree — no DB driver is imported, so prose like 'Update keys/…' is never flagged", () => {
    // Gates on the SQL-driver import: a SQL-looking string in a file with no
    // driver executes nothing, so remediation prose ("Update keys/EXPECTED_…")
    // must not be a hit. If the file gate were dropped this would fail.
    assert.deepEqual(p.detectHandRolledSql(), []);
  });
});

require("node:test").describe("hand-rolled-sql matcher gaps (round-2 hunt: F20 subpath, F21 embedded quote)", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const p = require("../scripts/check-codebase-patterns.js");
  test("F20: a subpath driver import (mysql2/promise, drizzle-orm/node-postgres, pg/lib) arms the gate", () => {
    assert.ok(p.SQL_DRIVER_IMPORT.test('const m = require("mysql2/promise")'));
    assert.ok(p.SQL_DRIVER_IMPORT.test('const { drizzle } = require("drizzle-orm/node-postgres")'));
    assert.ok(p.SQL_DRIVER_IMPORT.test('import { Client } from "pg/lib/client"'));
    assert.ok(p.SQL_DRIVER_IMPORT.test('require("pg")'), "bare driver still matches");
    assert.ok(!p.SQL_DRIVER_IMPORT.test('require("node:path")'), "a benign subpath-free non-driver does not arm the gate");
  });
  test("F21: a concatenated clause with an embedded SQL string-quote is flagged (trailing-+ form)", () => {
    assert.ok(p.SQL_CLAUSE_FRAG.test('q = base + " WHERE name = \'x\' " + id'), "embedded quote inside the clause must not defeat the trailing-+ match");
    assert.ok(p.SQL_CLAUSE_FRAG.test('q = " WHERE id=" + id'), "plain trailing-+ still matches");
    assert.ok(p.SQL_CLAUSE_FRAG.test('q = base + " WHERE id=" + id'), "leading-+ still matches");
  });
  test("the scan universe is non-empty — the gate must not report clean without scanning anything", () => {
    // main() fails closed when filesUnder([...]) is empty (the absent-input
    // false-pass class). Assert the trigger condition is reachable (a missing
    // root yields []) AND that the real roots yield a non-trivial universe.
    assert.equal(p.filesUnder(["does-not-exist-xyz"]).length, 0, "a missing root yields an empty list (the guard's trigger)");
    assert.ok(p.filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]).length > 20,
      "the real source roots must yield a substantial scan universe");
  });
});

require("node:test").describe("number-env-coerce and stream-chunk-string-decode detectors", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const p = require("../scripts/check-codebase-patterns.js");
  const fixture = (name, src) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "egates-"));
    const f = path.join(dir, name);
    fs.writeFileSync(f, src, "utf8");
    return f;
  };
  const lines = (hits) => hits.map((h) => h.line);

  test("number-env-coerce flags Number(process.env...) and nothing else", () => {
    const f = fixture("env.js", [
      "const cap = Number(process.env.CAP || Infinity);",       // 1 flagged
      "const n = Number( process.env.N );",                     // 2 flagged
      "const ok = parseInt(process.env.N, 10);",                // 3 not this class
      "// Number(process.env.X) in a comment",                  // 4 comment only
      "const s = 'Number(process.env.X)'.length; // text",      // 5 flagged: string text is code-shaped, marker it
      "const m = Number(argv.max); const e = process.env.CAP;", // 6 two separate reads
      "const cap2 = Number(process.env.CAP); // allow:number-env-coerce — validated below",
    ].join("\n"));
    assert.deepEqual(lines(p.detectNumberEnvCoerce([f])), [1, 2, 5]);
  });

  test("stream-chunk-string-decode flags a string-appending data handler with no setEncoding on that stream", () => {
    const f = fixture("stream.js", [
      "function a(r) {",                                                   // 1
      "  let b = \"\";",                                                   // 2
      "  r.on(\"data\", (c) => (b += c));",                                // 3 flagged
      "}",                                                                 // 4
      "function b(res) {",                                                 // 5
      "  res.setEncoding(\"utf8\");",                                      // 6
      "  let s = \"\";",                                                   // 7
      "  res.on(\"data\", (c) => (s += c));",                              // 8 clear: same receiver set the encoding
      "}",                                                                 // 9
      "function c(res) {",                                                 // 10
      "  const chunks = []; let total = 0;",                               // 11
      "  res.on(\"data\", (c) => { total += c.length; chunks.push(c); });", // 12 clear: Buffers collected
      "}",                                                                 // 13
      "function d(x, y) {",                                                // 14
      "  x.setEncoding(\"utf8\");",                                        // 15
      "  let s = \"\";",                                                   // 16
      "  y.on('data', function (d) { s += d; });",                         // 17 flagged: another stream set the encoding
      "}",                                                                 // 18
      "process.stdin.on(\"data\", (chunk) => {",                           // 19 flagged
      "  buf += chunk.toString();",                                        // 20
      "});",                                                               // 21
      "process.stdout.on(\"data\", chunk => { out += chunk; }); // allow:stream-chunk-string-decode — fixture",
    ].join("\n"));
    assert.deepEqual(lines(p.detectStreamChunkStringDecode([f])), [3, 17, 19]);
  });

  test("a setEncoding call more than 60 lines above the handler does not clear it", () => {
    const f = fixture("far.js", ["r.setEncoding(\"utf8\");"].concat(Array(61).fill("// filler"), ["r.on(\"data\", (c) => (b += c));"]).join("\n"));
    assert.deepEqual(lines(p.detectStreamChunkStringDecode([f])), [63]);
  });

  test("setEncoding clears a handler only on the whole receiver, dotted or not", () => {
    const f = fixture("recv.js", [
      "res.setEncoding(\"utf8\");",                                                         // 1
      "s.on(\"data\", (c) => (b += c));",                                                   // 2 flagged: res is not s
      "a.r.setEncoding(\"utf8\");",                                                         // 3
      "r.on(\"data\", (c) => (b += c));",                                                   // 4 flagged: a.r is not r
      "process.stdin.setEncoding(\"utf8\");",                                               // 5
      "process.stdin.on(\"data\", (chunk) => {",                                            // 6 clear: same dotted receiver
      "  buf += chunk.toString();",                                                         // 7
      "});",                                                                                // 8
      "process.stdin.on(\"data\", chunk => { process.stdin._allText += chunk.toString(); });", // 9 clear: same dotted receiver
      "q.on(\"data\", chunk => { q._allText += chunk.toString(); });",                      // 10 flagged: no setEncoding on q
    ].join("\n"));
    assert.deepEqual(lines(p.detectStreamChunkStringDecode([f])), [2, 4, 10]);
  });

  test("a setEncoding in an earlier top-level function does not clear a later handler, and a byteLength count is not an append", () => {
    const f = fixture("scope.js", [
      "function f1(res) {",                                                    // 1
      "  res.setEncoding(\"utf8\");",                                          // 2
      "  let s = \"\";",                                                       // 3
      "  res.on(\"data\", (c) => (s += c));",                                  // 4 clear: same function
      "}",                                                                     // 5
      "function f2(res) {",                                                    // 6
      "  let s = \"\";",                                                       // 7
      "  res.on(\"data\", (c) => (s += c));",                                  // 8 flagged: f1 set the encoding
      "}",                                                                     // 9
      "function f3(res) {",                                                    // 10
      "  const chunks = []; let total = 0;",                                   // 11
      "  res.on(\"data\", (c) => { total += c.byteLength; chunks.push(c); });", // 12 clear: Buffers collected
      "}",                                                                     // 13
    ].join("\n"));
    assert.deepEqual(lines(p.detectStreamChunkStringDecode([f])), [8]);
  });

  test("a block closed above the handler ends the setEncoding lookback, and a receiver on the line above counts", () => {
    const f = fixture("nested.js", [
      "module.exports = {",                       // 1
      "  fetchA(res) {",                          // 2
      "    res.setEncoding(\"utf8\");",           // 3
      "    let s = \"\";",                        // 4
      "    res.on(\"data\", (c) => (s += c));",   // 5 clear: same method
      "  },",                                     // 6
      "  fetchB(res) {",                          // 7
      "    let s = \"\";",                        // 8
      "    res.on(\"data\", (c) => (s += c));",   // 9 flagged: fetchA set the encoding
      "  },",                                     // 10
      "};",                                       // 11
      "function outer() {",                       // 12
      "  function a(res) {",                      // 13
      "    res.setEncoding(\"utf8\");",           // 14
      "    let s = \"\";",                        // 15
      "    res.on(\"data\", (c) => (s += c));",   // 16 clear: same function
      "  }",                                      // 17
      "  function b(res) {",                      // 18
      "    let s = \"\";",                        // 19
      "    res.on(\"data\", (c) => (s += c));",   // 20 flagged: a set the encoding
      "    if (x) {",                             // 21
      "      res.setEncoding(\"utf8\");",         // 22
      "    }",                                    // 23
      "    res",                                  // 24
      "      .on(\"data\", (c) => (s += c));",    // 25 clear: same function, receiver on line 24
      "  }",                                      // 26
      "}",                                        // 27
    ].join("\n"));
    assert.deepEqual(lines(p.detectStreamChunkStringDecode([f])), [9, 20]);
  });

  test("the shipped tree is clean on both", () => {
    assert.deepEqual(p.detectNumberEnvCoerce(), []);
    assert.deepEqual(p.detectStreamChunkStringDecode(), []);
  });

  test("NUMBER_ENV and DATA_HANDLER match the forms the detectors rely on", () => {
    assert.ok(p.NUMBER_ENV.test("Number(process.env.CAP)"));
    assert.ok(!p.NUMBER_ENV.test("parseInt(process.env.CAP, 10)"));
    assert.ok(!p.NUMBER_ENV.global && !p.NUMBER_ENV.sticky, "a stateful regex would skip every other line");
    const param = (s) => { const m = s.match(p.DATA_HANDLER); return m && (m[1] || m[2] || m[3]); };
    assert.equal(param("r.on(\"data\", (c) => (b += c));"), "c");
    assert.equal(param("r.on('data', chunk => { s += chunk; });"), "chunk");
    assert.equal(param("r.on(\"data\", function (d) { s += d; });"), "d");
    assert.equal(param("r.on(\"end\", (c) => {});"), null);
  });

  test("both classes accept allow markers and run as blocking classes", () => {
    for (const id of ["number-env-coerce", "stream-chunk-string-decode"]) {
      assert.equal(p.VALID_ALLOW_CLASSES[id], true, id);
      const c = p.CLASSES.find((x) => x.id === id);
      assert.ok(c && c.warnOnly === false, id);
    }
  });
});

require("node:test").describe("british-spelling detector", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const p = require("../scripts/check-codebase-patterns.js");
  const fixture = (name, src) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "egates-"));
    const f = path.join(dir, name);
    fs.writeFileSync(f, src, "utf8");
    return f;
  };
  const found = (hits) => hits.map((h) => `${h.line}:${h.why}`);

  test("flags British spellings in line comments, block comments, strings and template text", () => {
    const f = fixture("prose.js", [
      "// the behaviour of the catalogue",                                  // 1 flagged
      "/**",                                                                // 2
      " * Returns the normalised value.",                                   // 3 flagged
      " */",                                                                // 4
      "throw new Error(\"--operator failed NFC normalisation\");",          // 5 flagged
      "const help = `",                                                     // 6
      "  --attest-ownership   Attest written authorisation for the scan",   // 7 flagged
      "  operator's organisation URL`;",                                    // 8 flagged
      "const m = 'organisational allowlist of AI artefacts';",              // 9 flagged
      "const n = \"the logs were analysed\";",                              // 10 flagged
      "// waits for an acknowledgement from the paediatric unit",           // 11 flagged
    ].join("\n"));
    assert.deepEqual(found(p.detectBritishSpelling([f])), [
      "1:behaviour, catalogue", "3:normalised", "5:normalisation", "7:authorisation",
      "8:organisation", "9:organisational, artefacts", "10:analysed",
      "11:acknowledgement, paediatric",
    ]);
  });

  test("leaves identifiers, kept terms, backticked references and American spellings alone", () => {
    const f = fixture("code.js", [
      "const { recognised, normalised } = resolve(x);",                     // 1 code
      "if (!RECOGNISED_FACTOR_KEYS.has(k)) warn({ type: 'RwepFactorUnrecognised', code: 'RWEP_FACTOR_UNRECOGNISED' });", // 2 identifiers in strings
      "const flag = args[\"include-judgement-shaped\"];",                   // 3 kept flag
      "const note = \"12 judgement-shaped playbooks\";",                    // 4 kept term
      "// returns `recognised: true` for a known value",                    // 5 backticked key
      "const t = `${normalised} exploitation`;",                            // 6 interpolation is code
      "// we promise the advertised behavior; otherwise the analyses fail", // 7 American
      "const ok = \"exercising, revised, supervised, compromised\";",       // 8 American -ise
      "// quotes \"catalogue\" as matched text  // allow:british-spelling — the pattern matches both spellings", // 9 marker
    ].join("\n"));
    assert.deepEqual(found(p.detectBritishSpelling([f])), []);
  });

  test("a quoted string closes at the end of its line, so a stray quote does not carry into the next line", () => {
    const f = fixture("quote.js", [
      "const re = /it's/; const normalised = 1;",                           // 1 the regex quote opens a string that ends here
      "const recognised = normalised;",                                     // 2 code
    ].join("\n"));
    assert.deepEqual(found(p.detectBritishSpelling([f])), ["1:normalised"]);
  });

  test("proseOf keeps comment and string text and drops code, across lines", () => {
    const state = { inSingle: false, inDouble: false, inTemplate: false, inBlock: false, templateExpr: [] };
    assert.equal(p.proseOf("const recognised = 'behaviour'; // catalogue", state).replace(/\s+/g, " ").trim(), "behaviour catalogue");
    assert.equal(p.proseOf("const t = `organisation ${normalised}", state).replace(/\s+/g, " ").trim(), "organisation");
    assert.ok(state.inTemplate, "an unclosed template literal carries into the next line");
    assert.equal(p.proseOf("authorisation`; const x = normalised;", state).replace(/\s+/g, " ").trim(), "authorisation");
    assert.equal(state.inTemplate, false);
  });

  test("britishWordsIn returns the British words and skips identifiers, backticks and kept terms", () => {
    assert.deepEqual(p.britishWordsIn("the behaviour of the catalogue, organisational artefacts"), ["behaviour", "catalogue", "organisational", "artefacts"]);
    assert.deepEqual(p.britishWordsIn("RECOGNISED_FACTOR_KEYS RwepFactorUnrecognised `recognised: true` judgement-shaped"), []);
    assert.deepEqual(p.britishWordsIn("we promise the advertised behavior; otherwise the analyses run"), []);
  });

  test("the shipped tree is clean", () => {
    assert.deepEqual(p.detectBritishSpelling(), []);
  });

  test("the class accepts allow markers and runs as a warning", () => {
    assert.equal(p.VALID_ALLOW_CLASSES["british-spelling"], true);
    const c = p.CLASSES.find((x) => x.id === "british-spelling");
    assert.ok(c && c.warnOnly === true);
  });
});
