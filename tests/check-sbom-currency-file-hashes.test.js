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
    const driftErr = result.errors.find((e) => e.includes('manifest.json') && (e.includes('SHA-256 drift') || e.includes('hash drift')));
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

test('check-sbom-currency: every file component carries BOTH SHA-256 and SHA3-512 (PQ-aware dual-hash)', () => {
  // v0.13.12: SBOM emits SHA-256 (universal-tool contract) AND SHA3-512
  // (PQ-aware hedge, matches the lib/verify.js key-fingerprint pattern).
  // Both must be present on every file: component; a missing SHA3-512
  // on any entry signals an unintended downgrade from the dual-hash
  // baseline.
  const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
  const fileComps = (sbom.components || []).filter(
    (c) => typeof c['bom-ref'] === 'string' && c['bom-ref'].startsWith('file:'),
  );
  const missingSha3 = [];
  for (const c of fileComps) {
    const sha3 = (c.hashes || []).find((h) => h && h.alg === 'SHA3-512');
    if (!sha3) missingSha3.push(c['bom-ref']);
    else assert.match(sha3.content, /^[0-9a-f]{128}$/,
      `${c['bom-ref']} SHA3-512 must be 64 lowercase hex chars`);
  }
  assert.deepEqual(missingSha3, [],
    `every file: component must carry a SHA3-512 hash entry; missing on: ${missingSha3.slice(0, 5).join(', ')}`);

  // Sanity: live-bytes round-trip for the manifest.json SHA3-512.
  const manifestComp = fileComps.find((c) => c['bom-ref'] === 'file:manifest.json');
  if (manifestComp) {
    const recordedSha3 = (manifestComp.hashes || []).find((h) => h.alg === 'SHA3-512').content;
    const liveSha3 = crypto.createHash('sha3-512').update(fs.readFileSync(path.join(ROOT, 'manifest.json'))).digest('hex');
    assert.equal(recordedSha3, liveSha3,
      'manifest.json recorded SHA3-512 must equal live file hash');
  }
});

test('check-sbom-currency: SHA3-512 absence (downgrade attack) fails the gate', () => {
  // Codex P1 on PR #52: the dual-hash contract requires SHA3-512 to be
  // present on every file: component. An attacker that strips the
  // SHA3-512 column from sbom.cdx.json would have silently passed the
  // earlier optional-check implementation. This pin stages an SBOM with
  // SHA3-512 entries removed and confirms the gate refuses with the
  // canonical "dual-hash contract" error.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-sha3-absence-'));
  try {
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    for (const c of sbom.components || []) {
      if (typeof c['bom-ref'] === 'string' && c['bom-ref'].startsWith('file:')) {
        c.hashes = (c.hashes || []).filter((h) => h.alg !== 'SHA3-512');
      }
    }
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
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
    const absenceErr = result.errors.find((e) => e.includes('manifest.json') && e.includes('lacks a SHA3-512'));
    assert.ok(absenceErr, `expected SHA3-512-absence rejection error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.match(absenceErr, /dual-hash contract/,
      'absence error must name the dual-hash contract');
    assert.equal(result.ok, false);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function bringToTmp(tmp, rels) {
  for (const rel of rels) {
    const src = path.join(ROOT, rel);
    const dst = path.join(tmp, rel);
    try {
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? 'dir' : 'file'); }
      catch { fs.cpSync(src, dst, { recursive: true }); }
    } catch { /* missing file is its own error path */ }
  }
}

const SBOM_SUPPORT_REFS = [
  'manifest.json', 'data', 'keys', 'agents', 'bin', 'lib', 'orchestrator', 'scripts',
  'sources', 'vendor', 'skills', 'manifest-snapshot.json', 'manifest-snapshot.sha256',
  'AGENTS.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CONTEXT.md',
  'LICENSE', 'NOTICE', 'README.md', 'SECURITY.md',
];

test('check-sbom-currency: embedded description entry counts match the live catalogs', () => {
  // The SBOM ships per-catalog entry counts as free text in
  // metadata.component.description. The gate must now assert each token
  // equals the live catalog entry count, not just the catalog/skill
  // cardinality. Pin the production-tree pass so a future change that
  // drops the description check is caught here.
  const result = checkSbomCurrency(ROOT);
  const descErrs = result.errors.filter((e) => /description/.test(e));
  assert.deepEqual(descErrs, [],
    `live SBOM description must match the live catalog entry counts; got: ${JSON.stringify(descErrs)}`);
});

test('check-sbom-currency: a stale entry count in the description fails the gate', () => {
  // Mutate a catalog entry-count token in metadata.component.description
  // so it no longer matches the live catalog. Earlier the gate only
  // checked catalog/skill cardinality (file count + skill count), so a
  // per-catalog entry count baked into the description could silently
  // drift while the gate stayed green.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-desc-drift-'));
  try {
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    const desc = sbom.metadata.component.description;
    const m = desc.match(/(\d+)\s+CVEs\b/);
    assert.ok(m, 'production description must embed a CVE entry count to mutate');
    const wrong = String(Number(m[1]) + 1);
    sbom.metadata.component.description = desc.replace(/\d+\s+CVEs\b/, wrong + ' CVEs');
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
    bringToTmp(tmp, SBOM_SUPPORT_REFS);

    const result = checkSbomCurrency(tmp);
    const descErr = result.errors.find((e) => e.includes('description entry count for CVEs'));
    assert.ok(descErr,
      `expected a CVE description entry-count drift error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.match(descErr, /is \d+ but live .* has \d+/,
      'drift error must report both the stated and the live count');
    assert.match(descErr, /refresh-sbom/, 'drift error names the regen step');
    assert.equal(result.ok, false, 'gate must refuse a stale description entry count');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('check-sbom-currency: a stale skill count in the description fails the gate', () => {
  // The skill count is embedded in the same description free text
  // ("N skills"). A drift there must fail the gate too.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-desc-skill-'));
  try {
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    const desc = sbom.metadata.component.description;
    const m = desc.match(/(\d+)\s+skills\b/);
    assert.ok(m, 'production description must embed a skill count to mutate');
    const wrong = String(Number(m[1]) + 7);
    sbom.metadata.component.description = desc.replace(/\d+\s+skills\b/, wrong + ' skills');
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
    bringToTmp(tmp, SBOM_SUPPORT_REFS);

    const result = checkSbomCurrency(tmp);
    const skillErr = result.errors.find((e) => e.includes('description skill count'));
    assert.ok(skillErr,
      `expected a description skill-count drift error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.equal(result.ok, false, 'gate must refuse a stale description skill count');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('check-sbom-currency: a missing entry-count token in the description fails the gate', () => {
  // If a refresh drops a per-catalog token entirely (e.g. the SBOM
  // generator emits a description without the RFC count), the gate must
  // refuse rather than silently passing on a partial description.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-desc-missing-'));
  try {
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    const desc = sbom.metadata.component.description;
    assert.match(desc, /\d+\s+RFCs\b/, 'production description must embed an RFC token to remove');
    sbom.metadata.component.description = desc.replace(/\s*\/?\s*\d+\s+RFCs\b/, '');
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
    bringToTmp(tmp, SBOM_SUPPORT_REFS);

    const result = checkSbomCurrency(tmp);
    const missingErr = result.errors.find((e) => e.includes('missing the') && /rfc/i.test(e));
    assert.ok(missingErr,
      `expected a missing-RFC-token error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.equal(result.ok, false, 'gate must refuse a description with a missing entry-count token');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('check-sbom-currency: SHA3-512 drift fails the gate (not just SHA-256)', () => {
  // Stage an SBOM where SHA-256 is correct but SHA3-512 has been
  // deliberately changed. The gate must still refuse — a partial
  // downgrade attack (SHA-256 valid + SHA3-512 stale) is exactly the
  // shape this dual-hash design defends against.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-sha3-drift-'));
  try {
    const sbom = JSON.parse(fs.readFileSync(path.join(ROOT, 'sbom.cdx.json'), 'utf8'));
    const manifestComp = sbom.components.find((c) => c['bom-ref'] === 'file:manifest.json');
    const sha3Entry = manifestComp.hashes.find((h) => h.alg === 'SHA3-512');
    // Flip one nibble of the SHA3-512 entry so it can't match the live hash.
    sha3Entry.content = (sha3Entry.content[0] === '0' ? 'f' : '0') + sha3Entry.content.slice(1);
    fs.writeFileSync(path.join(tmp, 'sbom.cdx.json'), JSON.stringify(sbom));
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
    const sha3Err = result.errors.find((e) => e.includes('manifest.json') && e.includes('SHA3-512 drift'));
    assert.ok(sha3Err, `expected SHA3-512 drift error; got: ${JSON.stringify(result.errors.slice(0, 3))}`);
    assert.equal(result.ok, false);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
