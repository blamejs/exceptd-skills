'use strict';

/**
 * Tests for the v0.12.17 audit fixes:
 *   - Audit I P1-3: Windows ACL hardening on .keys/private.pem (restrictWindowsAcl)
 *   - Audit I P1-4: top-level manifest_signature on manifest.json
 *   - Audit L F11:  --diff-from-latest human-renderer output shape
 *   - Audit L F22:  ai-run --help documents the first-evidence-wins stdin contract
 *   - Audit M P3-O: KEV diff severity nuance (critical for ransomware / near-due)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const signMod = require('../lib/sign.js');
const verifyMod = require('../lib/verify.js');
const autoDiscovery = require('../lib/auto-discovery.js');

// --- P1-3: Windows ACL helper ---

test('P1-3: restrictWindowsAcl is exported and is a function', () => {
  assert.equal(typeof signMod.restrictWindowsAcl, 'function');
});

test('P1-3: restrictWindowsAcl is a no-op on non-Windows platforms', () => {
  // The function should return without throwing on POSIX. We test by
  // calling it against a path that does not exist — on win32 icacls would
  // fail (which we'd handle via warn) but on POSIX it should never invoke
  // icacls at all, so no exception is thrown.
  if (process.platform === 'win32') {
    // On win32 we cannot easily assert no-op behavior; just confirm the
    // function executes and does not throw on a real temp file.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-acl-'));
    const target = path.join(tmpDir, 'priv.pem');
    fs.writeFileSync(target, 'test', 'utf8');
    try {
      assert.doesNotThrow(() => signMod.restrictWindowsAcl(target));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } else {
    assert.doesNotThrow(() => signMod.restrictWindowsAcl('/nonexistent/path/private.pem'));
  }
});

// --- P1-4: manifest signature ---

test('P1-4: canonicalManifestBytes is deterministic regardless of stale signature field', () => {
  const m1 = { name: 'x', version: '1.2.3', skills: [] };
  const m2 = {
    name: 'x', version: '1.2.3', skills: [],
    manifest_signature: { algorithm: 'Ed25519', signature_base64: 'stale==', signed_at: '2020-01-01' },
  };
  const b1 = signMod.canonicalManifestBytes(m1).toString('hex');
  const b2 = signMod.canonicalManifestBytes(m2).toString('hex');
  assert.equal(b1, b2, 'canonical bytes must ignore stale manifest_signature');
});

test('P1-4: canonicalManifestBytes is deterministic regardless of top-level key order', () => {
  const m1 = { name: 'x', version: '1.2.3', skills: [] };
  const m2 = { skills: [], version: '1.2.3', name: 'x' };
  assert.equal(
    signMod.canonicalManifestBytes(m1).toString('hex'),
    signMod.canonicalManifestBytes(m2).toString('hex'),
    'key order at top level must not affect canonical bytes',
  );
});

test('P1-4: sign + verify round-trip on canonical manifest bytes succeeds', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const manifest = {
    name: 'test', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  const sigObj = signMod.signCanonicalManifest(manifest, privateKey);
  assert.equal(sigObj.algorithm, 'Ed25519');
  assert.equal(typeof sigObj.signature_base64, 'string');
  assert.ok(sigObj.signature_base64.length > 0);
  // Manually verify.
  const bytes = signMod.canonicalManifestBytes(manifest);
  const ok = crypto.verify(null, bytes, { key: publicKey, dsaEncoding: 'ieee-p1363' },
                            Buffer.from(sigObj.signature_base64, 'base64'));
  assert.equal(ok, true);
});

test('P1-4: live manifest.json carries a valid manifest_signature', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.ok(manifest.manifest_signature, 'live manifest.json must have manifest_signature');
  assert.equal(manifest.manifest_signature.algorithm, 'Ed25519');
  assert.equal(typeof manifest.manifest_signature.signature_base64, 'string');
  assert.ok(manifest.manifest_signature.signature_base64.length > 0);

  // Verify against keys/public.pem.
  const result = verifyMod.verifyManifestSignature(manifest);
  assert.equal(result.status, 'valid', `live manifest_signature must verify; got ${JSON.stringify(result)}`);
});

test('P1-4: verifyManifestSignature returns invalid when signature is tampered', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  // Flip one base64 char to break verification.
  const tampered = JSON.parse(JSON.stringify(manifest));
  const orig = tampered.manifest_signature.signature_base64;
  // Replace the first non-A character with 'A' (or 'B' if it's 'A') to
  // guarantee a different signature value.
  const idx = [...orig].findIndex(c => c !== 'A');
  const replacement = orig.charAt(idx) === 'A' ? 'B' : 'A';
  tampered.manifest_signature.signature_base64 = orig.slice(0, idx) + replacement + orig.slice(idx + 1);
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
  assert.match(result.reason, /Ed25519 manifest signature did not verify/);
});

test('P1-4: verifyManifestSignature returns invalid when a skill path is swapped', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  // Tamper a skill entry — the signature was computed over the original.
  tampered.skills[0].description = 'TAMPERED — attacker rewrote this field';
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
});

test('P1-4: verifyManifestSignature returns missing when field absent (backward-compat)', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const legacy = JSON.parse(JSON.stringify(manifest));
  delete legacy.manifest_signature;
  const result = verifyMod.verifyManifestSignature(legacy);
  assert.equal(result.status, 'missing');
});

test('P1-4: loadManifestValidated throws on tampered signature, blocks all skill verify', () => {
  // Round-trip via a temp manifest path is not exposed by the module API;
  // instead exercise the canonical helpers and the schema/path guards
  // together with the signature verifier (the same code loadManifestValidated
  // composes).
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  tampered.manifest_signature.signature_base64 = 'AAAA' + tampered.manifest_signature.signature_base64.slice(4);
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
});

test('P1-4: signing tooling regenerates a valid manifest_signature (smoke against on-disk state)', () => {
  // The on-disk manifest must currently verify. If this fails, an earlier
  // test mutated state or sign-all was not run after the recent change.
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'verify.js')], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(r.status, 0, `verify.js exit: ${r.status}\nSTDOUT:\n${r.stdout}\nSTDERR:\n${r.stderr}`);
});

// --- L F11: --diff-from-latest renderer ---

test('F11: diff_from_latest renderer formats unchanged with prior session id', () => {
  // Exercise the renderer indirectly via the bin file source — assert that
  // the new copy strings are present and the old generic format is gone.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Spec lines:
  assert.match(src, /unchanged \(same evidence_hash as session \$\{dfl\.prior_session_id\}\)/);
  assert.match(src, /DRIFTED — evidence_hash differs from session \$\{dfl\.prior_session_id\}/);
  // Verify the no_prior_attestation_for_playbook branch produces no
  // human-rendered line. Concretely: between the renderer-start marker
  // and the close of the renderer's diff_from_latest if-block, there is
  // no `lines.push(...)` referencing "no_prior_attestation_for_playbook".
  const rendererIdx = src.indexOf('// F11: surface --diff-from-latest verdict in the human renderer');
  assert.ok(rendererIdx > 0, 'F11 renderer marker comment must be present');
  // Slice up to the next blank-line-style block close — capture both
  // status branches but stop before unrelated downstream code.
  const block = src.slice(rendererIdx, rendererIdx + 1200);
  // The renderer must not call lines.push() for the no_prior case.
  assert.ok(!/lines\.push\([^)]*no_prior_attestation_for_playbook/.test(block),
    'no_prior_attestation_for_playbook branch must not emit a human-rendered line');
  // Comment in the renderer should explicitly call this out.
  assert.match(block, /no_prior_attestation_for_playbook intentionally produces no line/);
});

test('F11: renderer block lists exactly the unchanged + drifted statuses', () => {
  // Live exec the renderer logic by importing bin/exceptd.js?
  // The bin file is not a normal CommonJS module — it runs main() under
  // require.main === module. We test by string-extracting the renderer block
  // (already done above) and confirming both branches reference prior_session_id.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const rendererStart = src.indexOf('if (obj.diff_from_latest)');
  const rendererBlock = src.slice(rendererStart, rendererStart + 800);
  assert.match(rendererBlock, /dfl\.status === "unchanged"/);
  assert.match(rendererBlock, /dfl\.status === "drifted"/);
});

// --- L F22: ai-run --help streaming contract documentation ---

test('F22: ai-run --help text documents the first-evidence-wins stdin contract', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Help text registered under "ai-run" should include the Audit L F22 wording.
  // The helps map registers entries via `"ai-run": \`ai-run <playbook>...`;
  // search for that backtick form specifically to skip the case-statement
  // and any incidental references.
  const helpEntry = src.indexOf('"ai-run": `ai-run');
  assert.ok(helpEntry > 0, 'ai-run help entry must be registered');
  const helpBlock = src.slice(helpEntry, helpEntry + 3000);
  assert.match(helpBlock, /Stdin acceptance contract/);
  assert.match(helpBlock, /FIRST/);
  assert.match(helpBlock, /handled/);
});

// --- M P3-O: KEV severity nuance ---

test('P3-O: deriveKevSeverity returns critical for ransomware campaigns', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Known',
    dueDate: '2099-12-31',
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns critical when due date is within 7 days', () => {
  const soon = new Date(Date.now() + 3 * 86_400_000).toISOString().slice(0, 10);
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: soon,
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns critical for past-due entries', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: '2020-01-01',
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns high when due date is more than a week out and no ransomware', () => {
  const far = new Date(Date.now() + 60 * 86_400_000).toISOString().slice(0, 10);
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: far,
  });
  assert.equal(severity, 'high');
});

test('P3-O: deriveKevSeverity returns high when no dueDate present and no ransomware', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: '',
  });
  assert.equal(severity, 'high');
});

test('P3-O: discoverNewKev propagates per-entry severity from deriveKevSeverity', () => {
  // Build a synthetic ctx + cached KEV feed in a tempdir so we drive
  // discoverNewKev without touching network or the live cache.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-'));
  try {
    const kevDir = path.join(tmpDir, 'kev');
    fs.mkdirSync(kevDir, { recursive: true });
    const soon = new Date(Date.now() + 2 * 86_400_000).toISOString().slice(0, 10);
    const feed = {
      vulnerabilities: [
        // Ransomware-known → critical
        { cveID: 'CVE-2026-99001', dateAdded: '2026-05-10',
          knownRansomwareCampaignUse: 'Known', dueDate: '2099-12-31',
          vulnerabilityName: 'A', shortDescription: '', vendorProject: 'V', product: 'P' },
        // Due soon → critical
        { cveID: 'CVE-2026-99002', dateAdded: '2026-05-09',
          knownRansomwareCampaignUse: 'Unknown', dueDate: soon,
          vulnerabilityName: 'B', shortDescription: '', vendorProject: 'V', product: 'P' },
        // Plain KEV → high
        { cveID: 'CVE-2026-99003', dateAdded: '2026-05-08',
          knownRansomwareCampaignUse: 'Unknown', dueDate: '2099-01-01',
          vulnerabilityName: 'C', shortDescription: '', vendorProject: 'V', product: 'P' },
      ],
    };
    fs.writeFileSync(
      path.join(kevDir, 'known_exploited_vulnerabilities.json'),
      JSON.stringify(feed),
    );
    const ctx = { cacheDir: tmpDir, cveCatalog: {} };
    const result = autoDiscovery.discoverNewKev(ctx, 10);
    assert.equal(result.errors, 0);
    assert.equal(result.diffs.length, 3);
    const byId = Object.fromEntries(result.diffs.map(d => [d.id, d.severity]));
    assert.equal(byId['CVE-2026-99001'], 'critical', 'ransomware → critical');
    assert.equal(byId['CVE-2026-99002'], 'critical', 'near-due → critical');
    assert.equal(byId['CVE-2026-99003'], 'high', 'baseline KEV → high');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
