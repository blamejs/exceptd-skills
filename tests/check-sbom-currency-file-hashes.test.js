'use strict';

/**
 * tests/check-sbom-currency-file-hashes.test.js
 *
 * v0.13.9 regression pin for the per-file SHA-256 hash check added to
 * scripts/check-sbom-currency.js. Codex P2 on PR #48 flagged that
 * sbom.cdx.json had a recorded manifest.json hash that no longer matched
 * the signed-and-committed bytes — the previous check-sbom-currency
 * gate only validated counts + per-skill versions, not per-file content
 * hashes, so the drift surfaced only at downstream consumer verification
 * time. This test stages a deliberate drift in a temp repo layout and
 * confirms the gate refuses with the expected error shape + remediation
 * pointer.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const { checkSbomCurrency } = require(path.join(ROOT, 'scripts', 'check-sbom-currency.js'));

test('check-sbom-currency: baseline production tree passes (no hash drift)', () => {
  // Run the gate against the actual repo. If it fails here, every other
  // predeploy gate would have caught it — but pin the invariant anyway
  // so a future SBOM-generator regression that emits stale hashes
  // surfaces in the test suite, not just at the predeploy step.
  const result = checkSbomCurrency(ROOT);
  assert.equal(result.ok, true,
    `expected baseline production tree to pass; errors: ${JSON.stringify(result.errors)}`);
  assert.equal(typeof result.file_components_hash_checked, 'number');
  assert.ok(result.file_components_hash_checked > 0,
    'expected at least 1 file-hash entry validated in the production SBOM');
});

test('check-sbom-currency: hash drift on manifest.json fails with remediation pointer', () => {
  // Build a "shadow" repo: copy production sbom.cdx.json into a temp
  // dir, point the rest of the layout (manifest.json + data/) at the
  // real ROOT via symlinks, but mutate manifest.json's copy so its
  // SHA-256 no longer matches the recorded SBOM hash. This is the
  // exact failure mode codex caught on PR #48.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-drift-'));
  try {
    // Bring over the SBOM verbatim (must match production-tree refs).
    fs.copyFileSync(path.join(ROOT, 'sbom.cdx.json'), path.join(tmp, 'sbom.cdx.json'));
    // Stage a mutated manifest.json — different bytes, different hash.
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
    manifest._test_drift_marker = 'intentional-drift-for-regression-test';
    fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify(manifest, null, 2));
    // Symlink everything else the gate touches so file existence checks
    // pass for non-mutated paths. On Windows, fall back to copy if
    // symlink-create is denied (developer mode off).
    function bring(rel) {
      const src = path.join(ROOT, rel);
      const dst = path.join(tmp, rel);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? 'dir' : 'file'); }
      catch { fs.cpSync(src, dst, { recursive: true }); }
    }
    for (const rel of ['data', 'keys', 'agents', 'bin', 'lib', 'orchestrator', 'scripts', 'sources', 'vendor', 'skills',
                       'manifest-snapshot.json', 'manifest-snapshot.sha256',
                       'AGENTS.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CONTEXT.md',
                       'LICENSE', 'NOTICE', 'README.md', 'SECURITY.md']) {
      try { bring(rel); } catch { /* missing file is its own error path */ }
    }

    const result = checkSbomCurrency(tmp);
    assert.equal(result.ok, false, 'gate must refuse staged drift');
    const driftErr = result.errors.find((e) => e.includes('manifest.json') && e.includes('hash drift'));
    assert.ok(driftErr, `expected a manifest.json hash-drift error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    // The error must point operators to the canonical remediation order
    // using the project's operator-safe phrasing (no bare `node lib/…`).
    assert.match(driftErr, /sign-all/,
      'drift error must name sign-all (the canonical re-sign step)');
    assert.match(driftErr, /refresh-sbom/,
      'drift error must name refresh-sbom (the canonical regen step)');
    assert.match(driftErr, /AFTER the final sign/,
      'drift error must emphasise the sign-then-sbom ordering');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('check-sbom-currency: refuses bom-ref entries with ".." path-traversal segments', () => {
  // Codex P2 on PR #49: a tampered or carelessly-edited sbom.cdx.json
  // could declare `file:../outside.txt`. The earlier implementation
  // resolved that verbatim via path.join, which would read + hash a
  // file OUTSIDE the checkout — silently weakening the integrity
  // guarantee. The gate now refuses any ".." segment OR absolute path
  // in a bom-ref. Pin both rejection paths.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-traversal-'));
  try {
    // Build a minimal-but-valid SBOM with one ".." entry and one
    // absolute-path entry. The gate's other contracts (skill counts,
    // CycloneDX format) must still be satisfied, so steal the production
    // skeleton and inject the traversal entries.
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    sbom.components.push({
      'bom-ref': 'file:../escape-attempt.txt',
      type: 'file',
      name: '../escape-attempt.txt',
      hashes: [{ alg: 'SHA-256', content: 'a'.repeat(64) }],
    });
    sbom.components.push({
      'bom-ref': 'file:/etc/passwd',
      type: 'file',
      name: '/etc/passwd',
      hashes: [{ alg: 'SHA-256', content: 'b'.repeat(64) }],
    });
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
    // Symlink everything else through to the real ROOT.
    function bring(rel) {
      const src = path.join(ROOT, rel);
      const dst = path.join(tmp, rel);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? 'dir' : 'file'); }
      catch { fs.cpSync(src, dst, { recursive: true }); }
    }
    for (const rel of ['manifest.json', 'data', 'keys', 'agents', 'bin', 'lib', 'orchestrator', 'scripts',
                       'sources', 'vendor', 'skills', 'manifest-snapshot.json', 'manifest-snapshot.sha256',
                       'AGENTS.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CONTEXT.md',
                       'LICENSE', 'NOTICE', 'README.md', 'SECURITY.md']) {
      try { bring(rel); } catch { /* tolerated */ }
    }

    const result = checkSbomCurrency(tmp);
    const escapeErr = result.errors.find((e) => e.includes('../escape-attempt') && e.includes('path-traversal'));
    assert.ok(escapeErr, `expected ".." rejection error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    const absErr = result.errors.find((e) => e.includes('/etc/passwd') && e.includes('path-traversal'));
    assert.ok(absErr, `expected absolute-path rejection error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.equal(result.ok, false, 'gate must refuse SBOM containing path-traversal bom-ref entries');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('check-sbom-currency: hashes use SHA-256 (no MD5 / SHA-1 silently accepted)', () => {
  // Schema enforcement: every file: bom-ref in sbom.cdx.json must carry
  // a SHA-256 hash entry. A future SBOM generator that emits only MD5
  // or SHA-1 would be invisible without this assertion (the gate would
  // silently report 0 entries verified).
  const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
  const fileComps = (sbom.components || []).filter(
    (c) => typeof c['bom-ref'] === 'string' && c['bom-ref'].startsWith('file:'),
  );
  assert.ok(fileComps.length > 0, 'SBOM must declare at least one file: component');
  for (const c of fileComps) {
    const sha256 = (c.hashes || []).find((h) => h && h.alg === 'SHA-256');
    assert.ok(sha256, `file component ${c['bom-ref']} must carry a SHA-256 hash`);
    assert.match(sha256.content, /^[0-9a-f]{64}$/,
      `file component ${c['bom-ref']} SHA-256 must be 64 lowercase hex chars`);
  }

  // Sanity: the manifest.json component's recorded hash must equal the
  // crypto-derived hash of the live bytes. This is the same check the
  // gate runs, pinned here so a future refactor of the gate that drops
  // the check is caught by this test.
  const manifestComp = fileComps.find((c) => c['bom-ref'] === 'file:manifest.json');
  if (manifestComp) {
    const recorded = (manifestComp.hashes || []).find((h) => h.alg === 'SHA-256').content;
    const live = crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, 'manifest.json'))).digest('hex');
    assert.equal(recorded, live,
      'manifest.json recorded SHA-256 must equal live file hash (predeploy gate would otherwise have caught this)');
  }
});
