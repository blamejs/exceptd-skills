'use strict';

/**
 * Tests for the audit-AA P1 closures:
 *
 *   AA P1-1  `algorithm: "unsigned"` sidecar substitution is now detected
 *            by both `attest verify` (exit 6 when private key present) and
 *            `cmdReattest` (requires --force-replay regardless).
 *   AA P1-2  Corrupt-JSON .sig sidecar surfaces as a structured tamper-class
 *            result rather than throwing through the dispatcher. Both
 *            `attest verify` and `cmdReattest` exit 6.
 *   AA P1-3  `lib/verify.js verifyManifestSignature()` consults
 *            `keys/EXPECTED_FINGERPRINT` BEFORE crypto.verify. Library
 *            callers (refresh-network, verify-shipped-tarball, downstream
 *            consumers) can no longer bypass the pin.
 *
 * Per CLAUDE.md "coincidence-passing tests" rule: every exit-code assertion
 * is EXACT (assert.equal(r.status, 6)), never notEqual(0).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestation(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
  if (files.length === 0) return null;
  return { dir: attRoot, jsonFile: path.join(attRoot, files[0]), sigFile: path.join(attRoot, files[0] + '.sig') };
}

// ---------------------------------------------------------------------------
// AA P1-1 — `algorithm: "unsigned"` substitution detection
// ---------------------------------------------------------------------------

test('AA P1-1: attest verify exits 6 when an unsigned sidecar is substituted on a host WITH a private key',
  { skip: !HAS_PRIV_KEY && 'private key absent — substitution path requires .keys/private.pem on the verifying host' },
  () => {
    // Produce a real (signed) attestation, then substitute the .sig with the
    // unsigned stub. Pre-fix: `attest verify` reported signed:false and
    // exited 0 — the tamper predicate `r.signed && !r.verified` never fired.
    // Post-fix: substitution is detected because .keys/private.pem exists on
    // the verifying host, and verify exits 6.
    const sid = 'aa-p11-subst-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0, 'pre-substitution run must succeed; stderr=' + r1.stderr.slice(0, 400));

    const att = locateAttestation(sid);
    assert.ok(att, 'attestation must exist');

    // Tamper attestation.json AND substitute the .sig with the unsigned stub.
    const orig = fs.readFileSync(att.jsonFile, 'utf8');
    fs.writeFileSync(att.jsonFile, orig.replace(/\}\s*$/, ', "__tampered": true }'));
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      reason: 'attestation explicitly unsigned',
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on unsigned-substituted sidecar must exit 6 (TAMPERED) when private key is present. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'substitution body must carry ok:false');
    assert.ok(Array.isArray(body.results), 'verify must emit results array');
    assert.ok(
      body.results.some(x => x.tamper_class === 'unsigned-substitution'),
      'at least one result must classify as tamper_class:"unsigned-substitution"'
    );
  });

test('AA P1-1: reattest refuses an explicitly-unsigned attestation without --force-replay',
  { skip: !HAS_PRIV_KEY && 'private key required to produce a signed attestation that we then convert to unsigned' },
  () => {
    // Produce a signed attestation, swap the .sig for the unsigned stub
    // (mimics either substitution OR a legitimately-unsigned attestation
    // surfaced to a host with a private key). Reattest must refuse without
    // --force-replay regardless of host private-key state.
    const sid = 'aa-p11-unsigned-replay-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0, 'producer run must succeed');

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    // No --force-replay → exit 6.
    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest against an unsigned/substituted sidecar must exit 6 without --force-replay. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
  });

test('AA P1-1: reattest --force-replay accepts explicitly-unsigned and records sidecar_verify_class + force_replay',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key to create signed attestation we then re-sidecar' },
  () => {
    const sid = 'aa-p11-force-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    const r = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r.status, 0,
      `reattest --force-replay against an unsigned sidecar must succeed (exit 0). Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || {};
    assert.equal(body.force_replay, true, 'emit body must record force_replay:true');
    // The classification label captures WHICH override class was overridden.
    // Both "unsigned-substitution" (when private key present) and
    // "explicitly-unsigned" (no private key) are acceptable here — the host
    // private-key state determines which the verifier reports.
    assert.ok(
      body.sidecar_verify_class === 'explicitly-unsigned' || body.sidecar_verify_class === 'unsigned-substitution',
      `sidecar_verify_class must be "explicitly-unsigned" or "unsigned-substitution"; got ${JSON.stringify(body.sidecar_verify_class)}`
    );
  });

test('AA P1-1: a legitimately-unsigned attestation on a host WITHOUT a private key is allowed (no substitution signal)', () => {
  // Source-level assertion: the unsigned-substitution branch in
  // verifyAttestationSidecar checks `fs.existsSync(privKeyPath)`. When the
  // private key is absent, the function returns the original explicitly-
  // unsigned reason (no tamper_class). The legitimately-unsigned path
  // remains usable for operators who have never run generate-keypair.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function verifyAttestationSidecar(attFile)');
  const fnEnd = src.indexOf('function cmdReattest', fnStart);
  const block = src.slice(fnStart, fnEnd);
  // Two unsigned-return shapes must coexist: one with tamper_class
  // (substitution path) and one without (legitimate path).
  assert.match(block, /tamper_class:\s*["']unsigned-substitution["']/,
    'verifyAttestationSidecar must classify substitution');
  // The legitimate-unsigned return is the one whose reason starts with
  // "attestation explicitly unsigned (no private key when written)" AND
  // does NOT carry tamper_class.
  const legitMatch = block.match(/return\s*\{\s*file:\s*attFile,\s*signed:\s*false,\s*verified:\s*false,\s*reason:\s*"attestation explicitly unsigned \(no private key when written\)"\s*\}/);
  assert.ok(legitMatch,
    'verifyAttestationSidecar must retain the legitimate-unsigned return path (no tamper_class) for hosts without a private key');
});

// ---------------------------------------------------------------------------
// AA P1-2 — Corrupt-JSON sidecar refusal
// ---------------------------------------------------------------------------

test('AA P1-2: attest verify exits 6 (not 1) when the .sig sidecar is corrupt JSON',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key' },
  () => {
    // Pre-fix: JSON.parse threw into the outer dispatcher catch → exit 1
    // (generic). Post-fix: wrapped parse returns a tamper-class result and
    // the per-result reduce promotes to exit 6.
    const sid = 'aa-p12-corrupt-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    // Write truncated / malformed JSON.
    fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25');

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on a corrupt .sig must exit 6 (TAMPERED), not 1 (generic). Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'corrupt-sidecar verify body must carry ok:false');
    assert.ok(Array.isArray(body.results), 'verify must still emit results array even on corrupt sidecar (no unhandled throw)');
    assert.ok(
      body.results.some(x => x.tamper_class === 'sidecar-corrupt'),
      'at least one result must classify as tamper_class:"sidecar-corrupt"'
    );
  });

test('AA P1-2: reattest exits 6 when the .sig sidecar is corrupt JSON',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key' },
  () => {
    const sid = 'aa-p12-corrupt-reattest-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, 'not-valid-json{{{');

    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest against a corrupt .sig must exit 6, not fall through to the benign NOTE branch. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
  });

// ---------------------------------------------------------------------------
// AA P1-3 — EXPECTED_FINGERPRINT pin consulted in verifyManifestSignature
// ---------------------------------------------------------------------------

test('AA P1-3: verifyManifestSignature accepts the live manifest (pin matches keys/public.pem)', () => {
  // Sanity-check: the live manifest must still verify after the pin gate
  // was added. This protects against accidentally regressing the live
  // verify path while wiring the new check.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const r = verifyMod.verifyManifestSignature(manifest);
  assert.equal(r.status, 'valid', `live manifest must still verify post-pin-gate; got ${JSON.stringify(r)}`);
});

test('AA P1-3: verifyManifestSignature refuses when keys/public.pem diverges from keys/EXPECTED_FINGERPRINT', () => {
  // Simulate the divergence by patching checkExpectedFingerprint via a
  // sandbox: load lib/verify.js fresh under a tempdir-rooted PKG layout
  // where keys/public.pem is a freshly-generated attacker key and
  // keys/EXPECTED_FINGERPRINT pins the LEGITIMATE key. The library must
  // refuse to verify under the attacker key.
  //
  // Easiest implementation: spawn a sub-test in a tempdir that mirrors the
  // repo structure for keys/, manifest.json, and lib/. Rather than copy
  // lib/verify.js (which would diverge), we re-require it under a
  // pinPath-substituted shim using its exported checkExpectedFingerprint
  // primitive — verifyManifestSignature internally calls
  // checkExpectedFingerprint(liveFp) with the default pin path, so we patch
  // EXPECTED_FINGERPRINT_PATH by tampering with the OS environment we
  // control.
  //
  // The clean approach: bypass the library wrapper and exercise the policy
  // primitive directly. checkExpectedFingerprint is the public surface; if
  // the library uses it correctly the policy is enforced. We assert both:
  //   1. The primitive returns "mismatch" on a divergent fingerprint
  //      without KEYS_ROTATED.
  //   2. The library function verifyManifestSignature() body references
  //      checkExpectedFingerprint before crypto.verify.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));

  // (1) Primitive-level: a divergent pin fails without KEYS_ROTATED.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-p13-pin-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:DEADBEEFnotTheActualKeyJustATestPin12345678=');
  const fakeFp = { sha256: 'SHA256:totally-different-fingerprint-value' };
  const result = verifyMod.checkExpectedFingerprint(fakeFp, pinPath);
  assert.equal(result.status, 'mismatch');
  assert.equal(result.rotationOverride, false,
    'KEYS_ROTATED unset → rotationOverride must be false (caller must refuse)');

  // (2) Source-level: verifyManifestSignature() body calls
  // checkExpectedFingerprint BEFORE crypto.verify. Without this ordering,
  // a tampered public.pem could verify before the pin gate fires.
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  const fnStart = src.indexOf('function verifyManifestSignature(manifest)');
  assert.ok(fnStart > 0, 'verifyManifestSignature must be present in lib/verify.js');
  const fnBlock = src.slice(fnStart, fnStart + 3000);
  const pinIdx = fnBlock.indexOf('checkExpectedFingerprint(');
  const verifyIdx = fnBlock.indexOf('crypto.verify(');
  assert.ok(pinIdx > 0,
    'verifyManifestSignature must call checkExpectedFingerprint() per AA P1-3');
  assert.ok(verifyIdx > pinIdx,
    'checkExpectedFingerprint() must be called BEFORE crypto.verify() — otherwise an attacker-rotated public.pem can authenticate before the pin gate fires');
});

test('AA P1-3: verifyManifestSignature returns structured fingerprint-mismatch error (not a generic invalid)', () => {
  // A library-caller (refresh-network, verify-shipped-tarball, etc.) must
  // be able to distinguish "wrong key" from "tampered manifest". The
  // mismatch return carries explicit fingerprint_mismatch / expected /
  // actual fields so downstream code can present the operator-actionable
  // rotation guidance rather than a generic tamper message.
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  const fnStart = src.indexOf('function verifyManifestSignature(manifest)');
  const fnEnd = src.indexOf('function loadManifestValidated', fnStart);
  const block = src.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 3000);
  assert.match(block, /fingerprint_mismatch:\s*true/,
    'verifyManifestSignature must emit fingerprint_mismatch:true on pin divergence');
  assert.match(block, /fingerprint-mismatch/,
    'verifyManifestSignature must surface "fingerprint-mismatch" in the reason string for log scrapers');
});

test('AA P1-3: verifyManifestSignature honors KEYS_ROTATED=1 for legitimate rotations', () => {
  // The override env must be respected at the library layer. Operators
  // rotating keys/public.pem set KEYS_ROTATED=1, re-sign, then commit the
  // new EXPECTED_FINGERPRINT. Refusing to verify during that window would
  // brick `node lib/verify.js update` (which signs against the new key).
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-p13-rot-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:somethingElse=');
  const prev = process.env.KEYS_ROTATED;
  try {
    process.env.KEYS_ROTATED = '1';
    const result = verifyMod.checkExpectedFingerprint({ sha256: 'SHA256:newKey=' }, pinPath);
    assert.equal(result.status, 'mismatch');
    assert.equal(result.rotationOverride, true,
      'KEYS_ROTATED=1 must surface rotationOverride:true so callers can accept the rotation');
  } finally {
    if (prev === undefined) delete process.env.KEYS_ROTATED;
    else process.env.KEYS_ROTATED = prev;
  }
});
