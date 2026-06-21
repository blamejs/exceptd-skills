'use strict';

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

test('#22 countTests counts 3 it() + 2 test() declarations as 5', () => {
  const src = [
    "const { test, it } = require('node:test');",
    "it('a', () => {});",
    "it.skip('b', () => {});",
    "it.only('c', () => {});",
    "test('d', () => {});",
    "test('e', () => {});",
  ].join('\n');
  const { dir, p } = tmpFile('count-it.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(typeof n, 'number');
    assert.equal(n, 5);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 an it() declaration inside a /* */ block is NOT counted (comment-strip still applies)', () => {
  const src = [
    "/* it('x', () => {}) */",
    "/*",
    "  it('y', () => {});",
    "*/",
  ].join('\n');
  const { dir, p } = tmpFile('count-it-comment.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(n, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 describe() is NOT counted as a test (containers, not tests)', () => {
  const src = [
    "describe('group', () => {",
    "  it('inner', () => {});",
    "});",
  ].join('\n');
  const { dir, p } = tmpFile('count-describe.test.js', src);
  try {
    // one it() inside the describe block; the describe itself does not count.
    const n = countTests(p);
    assert.equal(n, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 a test( mentioned inside a string is NOT counted', () => {
  const src = [
    "console.log('run the test( harness');",
    "it('real', () => {});",
  ].join('\n');
  const { dir, p } = tmpFile('count-string.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(n, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// --------------------------------------------------------------------------
// #23 — requireMainRanges is string/comment/template aware
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
// #24 — FUNCTION_START refuses control-flow openers
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
// #25 — detectDynamicRegex catches multi-line new RegExp(
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

// --------------------------------------------------------------------------
// #26 — VERSION_TAG_RE allows a sentence-ending period
// --------------------------------------------------------------------------

test('#26 VERSION_TAG_RE matches a version stamp that ends a sentence (trailing period)', () => {
  assert.equal(VERSION_TAG_RE.test('// fixed in 0.18.9.'), true);
});

test('#26 VERSION_TAG_RE matches v-prefixed and bare stamps', () => {
  assert.equal(VERSION_TAG_RE.test('v0.18.9'), true);
  assert.equal(VERSION_TAG_RE.test('0.18.9'), true);
  assert.equal(VERSION_TAG_RE.test('0.18.99'), true); // longer patch still matches
});

test('#26 VERSION_TAG_RE rejects an IPv4 address and a longer dotted-numeric run', () => {
  assert.equal(VERSION_TAG_RE.test('127.0.0.1'), false);
  assert.equal(VERSION_TAG_RE.test('1.2.0.18.9.3'), false);
  assert.equal(VERSION_TAG_RE.test('// build 0.18.9.42 nightly'), false);
});

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

test('#27 a target-only shipped file (absent from source) with no file: component fails the gate under --root', () => {
  // 'lib/target-only.js' exists in the target, is covered by package.json.files
  // (via the lib/ dir), but has NO file: component → completeness must flag it.
  const root = buildRootTree(
    { 'lib/target-only.js': "console.log('target only');\n" },
    {
      pkgFiles: ['manifest.json', 'lib', 'README.md'],
      componentRels: ['manifest.json', 'lib/a.js', 'README.md'], // omit target-only.js
    },
  );
  try {
    const r = checkSbomCurrency(root);
    assert.equal(r.ok, false);
    assert.equal(
      r.errors.some((e) => /Shipped file "lib\/target-only\.js".*no file: component/.test(e)),
      true,
      `expected completeness flag on lib/target-only.js; got ${JSON.stringify(r.errors)}`,
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('#27 a complete --root target (every shipped file has a component) does NOT raise a completeness error', () => {
  // Same target, but the extra file now HAS a component → no completeness flag.
  const root = buildRootTree(
    { 'lib/target-only.js': "console.log('target only');\n" },
    {
      pkgFiles: ['manifest.json', 'lib', 'README.md'],
      componentRels: ['manifest.json', 'lib/a.js', 'lib/target-only.js', 'README.md'],
    },
  );
  try {
    const r = checkSbomCurrency(root);
    const completenessErr = r.errors.filter((e) => /no file: component/.test(e));
    assert.deepEqual(completenessErr, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('#27 expandAllowlistAt walks the TARGET root, not the source repo, and applies the SBOM exclusions', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'expand-root-'));
  try {
    fs.mkdirSync(path.join(root, 'lib'), { recursive: true });
    fs.mkdirSync(path.join(root, 'data', '_indexes'), { recursive: true });
    fs.writeFileSync(path.join(root, 'lib', 'only-here.js'), 'x');
    fs.writeFileSync(path.join(root, 'sbom.cdx.json'), '{}');           // SELF_EXCLUDED
    fs.writeFileSync(path.join(root, 'data', '_indexes', 'cache.json'), '{}'); // DERIVABLE
    const expanded = expandAllowlistAt(['lib', 'sbom.cdx.json', 'data'], root);
    assert.equal(Array.isArray(expanded), true);
    assert.equal(expanded.includes('lib/only-here.js'), true);
    assert.equal(expanded.includes('sbom.cdx.json'), false);            // self excluded
    assert.equal(expanded.includes('data/_indexes/cache.json'), false); // derivable excluded
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
