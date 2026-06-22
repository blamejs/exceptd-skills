'use strict';

/**
 * tests/check-test-count.test.js
 *
 * Subject coverage for scripts/check-test-count.js — the no-shrinkage
 * test-count gate. countTests() strips comments/strings before counting and
 * recognizes both test() and it() declarations (skip/only variants), while
 * refusing describe() containers and any test( token that only appears inside
 * a string or block comment.
 *
 * Fixtures live in isolated mkdtemp dirs; the repo tree is never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const { countTests } = require(path.join(ROOT, 'scripts', 'check-test-count.js'));

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egates-'));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, 'utf8');
  return { dir, p };
}

// --------------------------------------------------------------------------
// check-test-count counts both test() and it()
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
// check-test-count CLI: structured-JSON envelope on the live test set.
// --------------------------------------------------------------------------

test('check-test-count.js exists and emits structured JSON', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-test-count.js'), '--json'], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `gate must pass on current state; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'gate must emit JSON when --json passed');
  assert.equal(body.verb, 'check-test-count');
  assert.equal(typeof body.observed, 'number');
  assert.equal(typeof body.baseline, 'number');
  assert.equal(typeof body.delta, 'number');
  assert.ok(['ok', 'grew_beyond_threshold_consider_bump'].includes(body.status),
    `status must be ok or grew_beyond_threshold; got ${body.status}`);
});


// ---- routed from gate-scripts-fs-race ----
require("node:test").describe("gate-scripts-fs-race", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/gate-scripts-fs-race.test.js
 *
 * The release/build gate scripts decide whether to read or create a file
 * (the test-count baseline, the manifest snapshot) and then act on the same
 * path. An existsSync(p)-then-read/write probe is a check-then-use window
 * (CodeQL js/file-system-race): the file the gate decides about may not be
 * the file it later touches. The scripts now read the path ONCE and branch
 * on the read result, with ENOENT as the "absent" signal and an exclusive
 * ('wx') create on the fresh-baseline path.
 *
 * These tests lock that in two ways:
 *   1. Static: the flagged existsSync(BASELINE_PATH/SNAPSHOT_PATH) probe is
 *      gone from the source — a re-introduction fails the suite before it
 *      can reach CodeQL.
 *   2. Behavioral: the ENOENT branches still produce the exact exit codes
 *      and side effects they did before (no behavior regression from the
 *      probe removal).
 *
 * Per the anti-coincidence rule: every assertion checks the EXACT exit code
 * / file content the fix produces, never notEqual(0) / ok(field).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CHECK_TEST_COUNT = path.join(ROOT, 'scripts', 'check-test-count.js');
const REFRESH_SNAPSHOT = path.join(ROOT, 'scripts', 'refresh-manifest-snapshot.js');

// ---------- 1. Static: the TOCTOU probe is gone ----------

// Strip comments + string literals so the assertion matches only EXECUTABLE
// code — the explanatory comments in these scripts describe the removed
// existsSync()-probe by name, and that prose must not trip the guard.
function executableSource(file) {
  let s = fs.readFileSync(file, 'utf8');
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');            // block comments
  s = s.replace(/(^|[^:])\/\/.*$/gm, '$1');          // line comments (not ://)
  s = s.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''"); // strings
  return s;
}



// ---------- 2. Behavioral: ENOENT branches preserved ----------

// check-test-count.js resolves BASELINE_PATH from its own __dirname/.. , so to
// exercise the ENOENT path without touching the repo's real baseline we copy
// the script + a minimal tests/ dir into a throwaway project root and run it
// from there.
function makeIsolatedCheckTestCount() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-fsrace-'));
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'tests'), { recursive: true });
  fs.copyFileSync(CHECK_TEST_COUNT, path.join(dir, 'scripts', 'check-test-count.js'));
  // Two declarations so the gate has a real count to record.
  fs.writeFileSync(
    path.join(dir, 'tests', 'sample.test.js'),
    "test('one', () => {});\ntest('two', () => {});\n",
    'utf8'
  );
  return dir;
}

test('check-test-count.js does not existsSync-probe the baseline path before reading it', () => {
  const code = executableSource(CHECK_TEST_COUNT);
  assert.doesNotMatch(
    code, /existsSync\(\s*BASELINE_PATH\s*\)/,
    'existsSync(BASELINE_PATH) probe reintroduces the js/file-system-race check-then-use window; ' +
    'read the path once and branch on ENOENT instead'
  );
  // The fresh-baseline create must be exclusive so it cannot clobber a
  // baseline a concurrent run wrote in the read→write window.
  assert.match(
    fs.readFileSync(CHECK_TEST_COUNT, 'utf8'), /flag:\s*'wx'/,
    'the initial-baseline write must use the exclusive (wx) flag'
  );
});

test('check-test-count.js: missing baseline without --update-baseline exits 2', () => {
  const dir = makeIsolatedCheckTestCount();
  try {
    const r = spawnSync(process.execPath, [path.join(dir, 'scripts', 'check-test-count.js')], {
      encoding: 'utf8', cwd: dir,
    });
    assert.equal(r.status, 2, `missing baseline must exit 2; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stderr, /baseline missing/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('check-test-count.js: missing baseline with --update-baseline exits 0 and writes the baseline exactly once', () => {
  const dir = makeIsolatedCheckTestCount();
  const baselinePath = path.join(dir, 'tests', '.test-count-baseline.json');
  try {
    assert.equal(fs.existsSync(baselinePath), false, 'precondition: baseline absent');
    const r = spawnSync(process.execPath, [path.join(dir, 'scripts', 'check-test-count.js'), '--update-baseline'], {
      encoding: 'utf8', cwd: dir,
    });
    assert.equal(r.status, 0, `--update-baseline on absent file must exit 0; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
    const written = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    assert.equal(written.baseline, 2, 'recorded baseline must equal the 2 test() declarations in the fixture');
    assert.equal(written.tolerance, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
