"use strict";

/**
 * tests/check-version-tags.test.js
 *
 * Pins the version-tag check itself:
 *   1. The baseline file exists and is well-formed JSON.
 *   2. Running the scan on the current tree produces no NEW
 *      regressions vs. the baseline (the standard predeploy gate).
 *   3. The scan correctly identifies a synthetic new violation
 *      when one is introduced in a tempfile.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-version-tags.js");
const BASELINE = path.join(ROOT, "tests", ".version-tag-baseline.json");

const { VERSION_TAG_RE } = require(SCRIPT);

test("baseline file exists and is well-formed JSON", () => {
  assert.ok(fs.existsSync(BASELINE), `expected baseline at ${path.relative(ROOT, BASELINE)}`);
  const body = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  assert.equal(typeof body.byFile, "object");
  assert.ok(Array.isArray(body.filenameViolations));
  assert.ok(typeof body.recorded_at === "string");
});

test("current tree has no new version-tag regressions vs. baseline", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
  assert.equal(r.status, 0,
    `check must pass on the current tree; stdout: ${r.stdout.slice(0, 400)}; stderr: ${r.stderr.slice(0, 400)}`);
  assert.match(r.stdout, /\[check-version-tags\] ok/);
});

test("a synthetic new version-tag comment in an unsanctioned file is caught", () => {
  // Drop a fake .js file under scripts/ with a version-tagged comment.
  // The check must FAIL because this is a new file (not in the baseline)
  // carrying a tag. The filename must NOT be git-ignored (the gate skips
  // ignored files): an untracked-but-shippable new file is exactly what it
  // guards. The literal is string-constructed so the scanner doesn't flag
  // THIS test file as a violation.
  const fakePath = path.join(ROOT, "scripts", "_fake_version_tag_probe.js");
  const fakeTag = "v" + "0." + "99." + "99";
  fs.writeFileSync(fakePath, `// ${fakeTag} fake comment\nmodule.exports = {};\n`);
  try {
    const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
    assert.equal(r.status, 1,
      `check must fail on a new version-tag comment; got status=${r.status}, stderr=${r.stderr.slice(0, 400)}`);
    assert.match(r.stderr, /scripts[\\/]_fake_version_tag_probe\.js/,
      "check must name the offending file path");
    assert.match(r.stderr, /version-tag line count grew|version-tag line\(s\)/,
      "check must explain WHY the violation matters");
  } finally {
    fs.unlinkSync(fakePath);
  }
});

// --------------------------------------------------------------------------
// VERSION_TAG_RE allows a sentence-ending period
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

test("a version literal inside a quoted string on a code line IS counted (whole-line contract)", () => {
  // The scan is deliberately whole-line, not comment-only: a 0.x stamp inside a
  // shipped string literal (CLI --help text, error message, test fixture) is
  // operator-readable residue and must be caught the same as a `//` comment.
  // This locks that contract so a future "comment-only" narrowing can't silently
  // stop catching version stamps in operator-facing strings.
  const fakePath = path.join(ROOT, "scripts", "_fake_version_string_probe.js");
  const fakeVer = "0." + "99." + "98";
  // No `//` on this line — the version stamp lives ONLY inside a string literal.
  fs.writeFileSync(fakePath, `module.exports = { version: "${fakeVer}" };\n`);
  try {
    const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
    assert.equal(r.status, 1,
      `a 0.x stamp inside a code-line string must trip the gate; got status=${r.status}, stderr=${r.stderr.slice(0, 400)}`);
    assert.match(r.stderr, /scripts[\\/]_fake_version_string_probe\.js/,
      "check must name the offending file path even when the stamp is in a string, not a comment");
  } finally {
    fs.unlinkSync(fakePath);
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
