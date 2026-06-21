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
