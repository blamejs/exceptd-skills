'use strict';

/**
 * tests/sbom-per-file-hash.test.js
 *
 * Cycle 9 audit fix — SBOM must carry:
 *   - metadata.component.hashes[]   bundle digest, SHA-256
 *   - components[].type === 'file'  one per shipped file with SHA-256
 *   - metadata.tools[0].name        not the legacy "hand-written" placeholder
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks the EXACT
 * value the fix produces (set-equality on the file allowlist, exact alg
 * string, exact tool name) — never `assert.ok(field)` or
 * `assert.notEqual(0)`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

// This test verifies the *SBOM-generation contract*: regenerate the SBOM
// in-process against the current working tree, then verify the freshly-
// computed bundle. We cannot read the shipped sbom.cdx.json directly and
// compare against on-disk files because other tests in the suite mutate
// files like data/_indexes/*.json + manifest.json signatures mid-run.
// The verify-shipped-tarball predeploy gate is the authoritative check
// for the ship-time SBOM-vs-tarball match.
const refresh = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'refresh-sbom.js')], {
  cwd: ROOT,
  encoding: 'utf8',
});
if (refresh.status !== 0) {
  throw new Error('scripts/refresh-sbom.js failed: ' + (refresh.stderr || refresh.stdout));
}
const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));

function walkFiles(absDir) {
  const out = [];
  const entries = fs.readdirSync(absDir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(abs));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function expandAllowlist(allowlist) {
  const abs = [];
  for (const entry of allowlist) {
    const full = path.join(ROOT, entry);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) abs.push(...walkFiles(full));
    else if (stat.isFile()) abs.push(full);
  }
  // Mirror the script's self-reference + derivable-cache exclusions.
  // sbom.cdx.json cannot hash itself stably; data/_indexes/ is the
  // regenerable cache mutated by build-incremental.test.js etc. If the
  // script's exclusion list grows, this set must follow.
  const SELF_EXCLUDED = new Set(['sbom.cdx.json']);
  const DERIVABLE_PREFIXES = ['data/_indexes/'];
  const isDerivable = (rel) =>
    DERIVABLE_PREFIXES.some((p) => rel === p.replace(/\/$/, '') || rel.startsWith(p));
  return Array.from(
    new Set(abs.map((a) => path.relative(ROOT, a).split(path.sep).join('/'))),
  )
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
}

test('metadata.component.hashes[] present and SHA-256', () => {
  const hashes = sbom.metadata.component.hashes;
  assert.ok(Array.isArray(hashes), 'hashes must be an array');
  assert.equal(hashes.length, 1, 'exactly one bundle digest expected');
  assert.equal(hashes[0].alg, 'SHA-256');
  assert.equal(typeof hashes[0].content, 'string');
  assert.equal(hashes[0].content.length, 64, 'SHA-256 hex digest is 64 chars');
  assert.match(hashes[0].content, /^[0-9a-f]{64}$/);
});

test('metadata.tools[0].name is not the literal "hand-written" placeholder', () => {
  const tool0 = sbom.metadata.tools[0];
  assert.notEqual(tool0.name, 'hand-written');
  // Positive shape assertion — the new value MUST point at the script.
  assert.equal(tool0.name, 'scripts/refresh-sbom.js');
  assert.equal(tool0.vendor, 'blamejs');
  assert.equal(tool0.version, pkg.version);
});

test('every file in package.json.files (recursively expanded) has a matching components[] entry with a SHA-256 hash', () => {
  const expected = expandAllowlist(pkg.files);
  const fileComps = sbom.components.filter((c) => c.type === 'file');
  const fileNames = fileComps.map((c) => c.name).sort();

  // Set-equality: every shipped file is present, no extras.
  assert.deepEqual(fileNames, expected,
    'components[type=file] names must equal the expanded files allowlist exactly');

  // Per-file: SHA-256 present and matches the on-disk content.
  for (const comp of fileComps) {
    assert.equal(comp['bom-ref'], `file:${comp.name}`);
    assert.equal(Array.isArray(comp.hashes), true);
    assert.equal(comp.hashes.length, 1);
    assert.equal(comp.hashes[0].alg, 'SHA-256');
    const onDisk = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(ROOT, comp.name)))
      .digest('hex');
    assert.equal(comp.hashes[0].content, onDisk,
      `file component "${comp.name}" hash must match on-disk SHA-256`);
  }
});

test('bundle digest is reproducible from the per-file components[] entries', () => {
  const fileComps = sbom.components
    .filter((c) => c.type === 'file')
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const hash = crypto.createHash('sha256');
  for (const c of fileComps) {
    hash.update(c.hashes[0].content);
    hash.update('\t');
    hash.update(c.name);
    hash.update('\n');
  }
  const recomputed = hash.digest('hex');
  assert.equal(recomputed, sbom.metadata.component.hashes[0].content,
    'bundle digest must equal SHA-256 over deterministic per-file digest stream');
});
