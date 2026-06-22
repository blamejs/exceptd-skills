'use strict';

/**
 * tests/check-sbom-currency.test.js
 *
 * Subject coverage for scripts/check-sbom-currency.js — the SBOM-currency
 * gate that re-hashes the live shipped surface against sbom.cdx.json.
 *
 *   - checkSbomCurrency / expandAllowlistAt honor a --root target tree: a
 *     shipped file present in the TARGET (but absent from the source repo)
 *     with no file: component fails the completeness check, and the allowlist
 *     walk resolves against the target root with the SBOM self-reference and
 *     the derivable index cache excluded.
 *   - .gitattributes LF-coverage guard: every byte-hashed shipped file (the
 *     same inventory the SBOM gate re-hashes) must resolve to `eol=lf` via
 *     git's own attribute engine, so a Windows checkout can't record CRLF
 *     hashes that drift against Linux CI's LF blob.
 *
 * Fixtures live in isolated mkdtemp dirs; the repo tree is never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const { checkSbomCurrency, expandAllowlistAt } = require(path.join(ROOT, 'scripts', 'check-sbom-currency.js'));

// --------------------------------------------------------------------------
// check-sbom-currency completeness honors --root
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

// --------------------------------------------------------------------------
// .gitattributes LF-coverage guard for byte-hashed shipped files.
//
// Every shipped file is hashed byte-for-byte by the integrity chain:
// scripts/refresh-sbom.js records a per-file SHA-256 (+ SHA3-512) into
// sbom.cdx.json, scripts/check-sbom-currency.js re-hashes the live bytes
// and fails on drift, lib/validate-vendor.js does the same for vendored
// files via vendor/blamejs/_PROVENANCE.json, and lib/validate-indexes.js
// hashes the index inputs. None of those sites normalize line endings —
// they hash the raw on-disk bytes.
//
// That only stays cross-platform-stable because .gitattributes pins every
// shipped text extension to `eol=lf`. A shipped text file with NO eol rule
// is checked out as CRLF on a Windows clone with core.autocrlf=true; that
// checkout records a CRLF hash, while Linux CI re-hashes the LF blob and
// reports drift. This guard fails the build the moment a shipped text file
// type lacks an LF pin, so a new hashed surface can never ship un-normalized.
//
// Coverage is resolved through git's own attribute engine (`git check-attr
// eol`), not a re-implementation of .gitattributes glob matching, so the
// test asserts the EFFECTIVE rule the way every clone resolves it. Binary
// files (text: unset) are exempt — line-ending normalization does not apply.
// --------------------------------------------------------------------------

// Mirrors scripts/refresh-sbom.js: the shipped surface is package.json
// `files[]` expanded to concrete regular files, minus the SBOM self-
// reference and the derivable index cache (those are excluded from the
// per-file hash inventory there too).
const SELF_EXCLUDED = new Set(["sbom.cdx.json"]);
const DERIVABLE_PREFIXES = ["data/_indexes/"];

function isDerivable(rel) {
  return DERIVABLE_PREFIXES.some(
    (p) => rel === p.replace(/\/$/, "") || rel.startsWith(p)
  );
}

function toPosixRel(absPath) {
  return path.relative(ROOT, absPath).split(path.sep).join("/");
}

function walkFiles(absDir) {
  const out = [];
  for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(abs));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function shippedHashedFiles() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const abs = [];
  for (const entry of pkg.files || []) {
    const full = path.join(ROOT, entry);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) abs.push(...walkFiles(full));
    else if (stat.isFile()) abs.push(full);
  }
  return Array.from(new Set(abs.map(toPosixRel)))
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
}

// Resolve `text` + `eol` attributes for a batch of paths through git's
// own attribute engine. Returns Map<relPath, { text, eol }>.
function resolveAttrs(relPaths) {
  const out = execFileSync("git", ["check-attr", "--stdin", "text", "eol"], {
    cwd: ROOT,
    input: relPaths.join("\n"),
    encoding: "utf8",
  });
  const attrs = new Map();
  for (const line of out.split("\n")) {
    // Format: "<path>: <attr>: <value>"
    const m = line.match(/^(.*): (text|eol): (.*)$/);
    if (!m) continue;
    const [, file, attr, value] = m;
    if (!attrs.has(file)) attrs.set(file, {});
    attrs.get(file)[attr] = value;
  }
  return attrs;
}

test("every byte-hashed shipped file is covered by an eol=lf .gitattributes rule", () => {
  const files = shippedHashedFiles();
  // Anti-coincidence: the surface must be non-trivial, otherwise an empty
  // walk would make the assertion vacuously pass.
  assert.ok(
    files.length > 100,
    `expected a substantial shipped-file surface, walked only ${files.length}`
  );

  const attrs = resolveAttrs(files);
  const uncovered = [];
  for (const rel of files) {
    const a = attrs.get(rel) || {};
    // Binary files declare `text: unset` (.gitattributes `binary` macro) —
    // no line-ending normalization applies, so they need no eol rule.
    if (a.text === "unset") continue;
    // Any other shipped file is hashed by-byte and MUST resolve to eol=lf.
    if (a.eol !== "lf") {
      uncovered.push(`${rel} (text=${a.text}, eol=${a.eol})`);
    }
  }

  assert.deepEqual(
    uncovered,
    [],
    "shipped byte-hashed files lack an `eol=lf` rule in .gitattributes — a Windows checkout " +
      "would record CRLF hashes that drift against Linux CI's LF blob. Add an LF pin for each:\n  " +
      uncovered.join("\n  ")
  );
});

test("git check-attr resolves a known-covered file to eol=lf (guard self-check)", () => {
  // Proves the resolution mechanism actually reports `lf` rather than the
  // assertion passing because every value parsed as undefined.
  const attrs = resolveAttrs(["manifest.json"]);
  assert.equal(attrs.get("manifest.json").eol, "lf");
});


// ---- routed from predeploy-gates ----
require("node:test").describe("predeploy-gates", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/predeploy-gates.test.js
 *
 * Meta-tests for the predeploy gate runners. The pre-existing
 * tests/predeploy.test.js asserts the GATES list maps to ci.yml job
 * names — it does not exercise the gates themselves. This file fills
 * that gap: for each gate that ships a script under lib/ or scripts/,
 * stage a known-bad state in a per-test tempdir and assert the gate
 * actually fires (non-zero exit OR an error-shape return).
 *
 * Why these specific gates: tests/predeploy.test.js only checks the
 * mapping. Other tests cover the data the gates consume but not the
 * gate runners themselves. This file is the regression-prevention layer
 * for the gate runners — when a gate's "bad state" detection regresses
 * (the false-negative class that shipped invisible signature drift in
 * v0.11.x — v0.12.2), one of these tests fires.
 *
 * Isolation model:
 *
 *   - Every test mkdtempSync's its own working tree under os.tmpdir().
 *   - Every test copies the script-under-test (and its strict
 *     dependencies) into <tempdir>/lib/ or <tempdir>/scripts/ so the
 *     script's __dirname anchor resolves to <tempdir>/lib (or
 *     <tempdir>/scripts), and __dirname/.. resolves to <tempdir>.
 *   - No test mutates the real repo ROOT. ROOT is read-only; tempdirs
 *     are the only writable surface.
 *   - Tempdirs are removed in a try/finally even when assertions fail
 *     so a CI run that ends with N failing tests still leaves /tmp clean.
 *
 * No --dir / --root flag was added to any existing script as part of
 * this work — every gate is testable via the cwd + __dirname anchor
 * pattern, except scripts/check-sbom-currency.js which already accepted
 * --root (it was extracted out of an inline `node -e` block in
 * scripts/predeploy.js during this same change; the extracted script
 * is the gate-10 runner going forward).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

// ---------- tempdir helpers ----------

function mktmp(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "predeploy-gate-" + label + "-"));
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best effort — Windows file locks may keep a handle briefly */
  }
}

function writeFile(dir, rel, content) {
  const abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

function copyFile(srcAbs, dstAbs) {
  fs.mkdirSync(path.dirname(dstAbs), { recursive: true });
  fs.copyFileSync(srcAbs, dstAbs);
}

// Every staged lib validator now requires lib/exit-codes.js (for safeExit);
// stage it alongside so the mirrored script doesn't crash on require (which
// would yield empty stdout and a confusing content-assertion failure).
function copyExitCodes(tmp) {
  copyFile(path.join(ROOT, "lib", "exit-codes.js"), path.join(tmp, "lib", "exit-codes.js"));
}

// Generate an Ed25519 keypair in PEM form, matching lib/verify.js conventions.
function genKeypair() {
  return crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function signContent(content, privateKeyPem) {
  return crypto
    .sign(null, Buffer.from(content, "utf8"), {
      key: privateKeyPem,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64");
}

// ---------- Gate 1: Verify skill signatures (Ed25519) ----------


// ---------- Gate 7: Lint skill files ----------


// ---------- Gate 9: validate-catalog-meta ----------


// ---------- Audit G F2: SBOM gate catches renamed skill ----------



// ---------- Audit G F1: validate-indexes rejects empty source_hashes ----------


// ---------- Gate 10: SBOM currency ----------


// ---------- Gate 11: validate-indexes ----------


// ---------- Gate 12: validate-vendor ----------







// ---------- Gate 13: validate-package ----------


// ---------- Gate 14: verify-shipped-tarball ----------
//
// This is the gate that closed v0.12.4's signature regression. The bug
// class: lib/verify.js against the SOURCE tree passes 38/38, but a fresh
// `npm install` against the SHIPPED tarball produces 0/38. The cause is
// keys/public.pem being swapped between sign and pack (the test that
// did it lived in `tests/operator-bugs.test.js` and synchronously
// regenerated keys mid-suite — see the common-pitfalls list).
//
// The simulated regression here: sign the skill against PRIVATE_KEY_A
// (the original ceremony), then post-sign tamper the skill body but
// leave the signature unchanged. After `npm pack`, the extracted tarball
// will have the tampered body + the original signature, and the gate
// must fail.

test("Audit G F2: SBOM gate fires when a skill named in SBOM components is renamed in manifest", () => {
  const tmp = mktmp("sbom-rename");
  try {
    // Manifest declares skill "renamed-skill", SBOM still names the old one.
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "renamed-skill", version: "1.0.0", path: "skills/renamed-skill/skill.md" },
        ],
      })
    );
    writeFile(tmp, "data/x.json", "{}");
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "1" },
            { name: "exceptd:skill:count", value: "1" },
          ],
        },
        components: [
          {
            "bom-ref": "skill:original-skill",
            name: "original-skill",
            version: "1.0.0",
            type: "library",
          },
        ],
      })
    );

    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    assert.equal(
      r.status,
      1,
      `check-sbom-currency.js must exit 1 on a renamed skill not reflected in SBOM.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /not in manifest\.skills/,
      `SBOM gate should report the missing skill. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("Audit G F2: SBOM gate fires on a version-bumped skill", () => {
  const tmp = mktmp("sbom-vbump");
  try {
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "my-skill", version: "2.0.0", path: "skills/my-skill/skill.md" },
        ],
      })
    );
    writeFile(tmp, "data/x.json", "{}");
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "1" },
            { name: "exceptd:skill:count", value: "1" },
          ],
        },
        components: [
          {
            "bom-ref": "skill:my-skill",
            name: "my-skill",
            version: "1.0.0", // stale — manifest has 2.0.0
            type: "library",
          },
        ],
      })
    );

    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    assert.equal(r.status, 1, "SBOM gate must exit 1 on version skew");
    assert.match(
      r.stderr,
      /version 1\.0\.0 != manifest\.skills version 2\.0\.0/,
      `version-skew message expected; stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("gate 10: check-sbom-currency.js fires on drifted skill count", () => {
  const tmp = mktmp("sbom");
  try {
    // sbom.cdx.json claims one count, manifest.json reports another.
    // scripts/check-sbom-currency.js compares the two and exits 1 on drift.
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "a", path: "skills/a/skill.md" },
          { name: "b", path: "skills/b/skill.md" },
        ],
      })
    );
    // Two data/*.json files = 2 catalogs.
    writeFile(tmp, "data/one.json", "{}");
    writeFile(tmp, "data/two.json", "{}");
    // SBOM declares 99 skills + 99 catalogs — both wrong.
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "99" },
            { name: "exceptd:skill:count", value: "99" },
          ],
        },
      })
    );

    // Invoke the script with --root pointing at the tempdir — this flag
    // was introduced when the gate-10 logic was extracted from the inline
    // `node -e` block in scripts/predeploy.js to its own file in this
    // same change set.
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    // Exit-1 path: drift detected. The script prints
    // "SBOM skill count 99 != live 2" / "SBOM catalog count 99 != live 2".
    assert.equal(
      r.status,
      1,
      `check-sbom-currency.js must exit 1 when sbom.cdx.json drifts from manifest.json + data/.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /SBOM (skill|catalog) count 99 != live 2/,
      `check-sbom-currency.js should report the count mismatch. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
