'use strict';

/**
 * Audit-AA trust-boundary fixes — assertions over the three policy gates
 * that guard the attestation/manifest signature chain:
 *
 *   AA P1-3  EXPECTED_FINGERPRINT pin consulted INSIDE verifyManifestSignature
 *            so library callers (refresh-network, verify-shipped-tarball,
 *            downstream consumers) cannot bypass the pin via direct API use.
 *   AA P1-2  Corrupt-JSON .sig sidecars surface as a tamper class — refused
 *            by both `attest verify` (exit 6 + structured body) and
 *            `reattest` (exit 6 without --force-replay; persists
 *            sidecar_verify + force_replay with it).
 *   AA P1-1  `algorithm: "unsigned"` sidecar substitution is detected when
 *            the verifying host has .keys/private.pem present. `reattest`
 *            ALWAYS requires --force-replay for explicitly-unsigned input,
 *            regardless of host private-key state.
 *
 * All exit-code assertions are EXACT (assert.equal(r.status, 6)), never
 * notEqual(0) — per CLAUDE.md's coincidence-passing-tests rule. Every
 * field-presence check is paired with a content-shape check.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-trust-');
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
  return {
    dir: attRoot,
    jsonFile: path.join(attRoot, files[0]),
    sigFile: path.join(attRoot, files[0] + '.sig'),
  };
}

// ---------------------------------------------------------------------------
// Fix 1 — AA P1-3 — EXPECTED_FINGERPRINT pin at verifyManifestSignature.
// ---------------------------------------------------------------------------

test('Fix 1 — library-direct call to verifyManifestSignature accepts the live manifest', () => {
  // Baseline: the gate must not regress the legitimate path. If this fails
  // the pin gate has been wired with a fingerprint mismatch against the
  // shipped key — every downstream consumer would refuse.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const r = verifyMod.verifyManifestSignature(manifest);
  assert.equal(r.status, 'valid',
    `live manifest must still verify under the pin gate; got ${JSON.stringify(r)}`);
});

test('Fix 1 — checkExpectedFingerprint reports mismatch on a tampered pin (no KEYS_ROTATED)', () => {
  // The primitive is the surface verifyManifestSignature consults. If this
  // returns "match" on a divergent pin the library cannot detect tampered
  // public-key swaps.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-trust-pin-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:tamperedPinValueDoesNotMatchActualKey=\n');

  const prev = process.env.KEYS_ROTATED;
  try {
    delete process.env.KEYS_ROTATED;
    const r = verifyMod.checkExpectedFingerprint({ sha256: 'SHA256:liveKeyDifferent=' }, pinPath);
    assert.equal(r.status, 'mismatch',
      'divergent pin must surface status:"mismatch"');
    assert.equal(r.rotationOverride, false,
      'without KEYS_ROTATED, rotationOverride must be false so callers refuse');
    assert.equal(typeof r.expected, 'string',
      'expected fingerprint must be a string the caller can show to the operator');
    assert.equal(typeof r.actual, 'string',
      'actual fingerprint must be a string the caller can show to the operator');
  } finally {
    if (prev === undefined) delete process.env.KEYS_ROTATED;
    else process.env.KEYS_ROTATED = prev;
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test('Fix 1 — checkExpectedFingerprint honors KEYS_ROTATED=1 for legitimate rotations', () => {
  // Rotation window: the operator has rolled keys/public.pem but not yet
  // committed the new pin. Setting KEYS_ROTATED=1 must surface
  // rotationOverride:true so the library accepts the rotation.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-trust-rot-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:oldPinValue=\n');

  const prev = process.env.KEYS_ROTATED;
  try {
    process.env.KEYS_ROTATED = '1';
    const r = verifyMod.checkExpectedFingerprint({ sha256: 'SHA256:rotatedKey=' }, pinPath);
    assert.equal(r.status, 'mismatch');
    assert.equal(r.rotationOverride, true,
      'KEYS_ROTATED=1 must flip rotationOverride to true so callers accept rotation');
  } finally {
    if (prev === undefined) delete process.env.KEYS_ROTATED;
    else process.env.KEYS_ROTATED = prev;
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test('Fix 1 — verifyManifestSignature calls checkExpectedFingerprint BEFORE crypto.verify', () => {
  // Ordering matters: if crypto.verify runs first, a tampered public.pem
  // authenticates the manifest before the pin gate fires — defeating the
  // pin's purpose. Source-level assertion is the cleanest way to lock the
  // ordering invariant (a runtime test would need to swap public.pem on
  // disk, which races with the rest of the suite).
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  const fnStart = src.indexOf('function verifyManifestSignature(manifest)');
  assert.ok(fnStart > 0, 'verifyManifestSignature must exist in lib/verify.js');
  const fnEnd = src.indexOf('\nfunction ', fnStart + 1);
  const block = src.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 3000);
  const pinIdx = block.indexOf('checkExpectedFingerprint(');
  const verifyIdx = block.indexOf('crypto.verify(');
  assert.ok(pinIdx > 0,
    'verifyManifestSignature must call checkExpectedFingerprint() — library callers must not bypass the pin');
  assert.ok(verifyIdx > pinIdx,
    'checkExpectedFingerprint() must precede crypto.verify(); reversed ordering lets a swapped public.pem authenticate before the pin gate fires');
  // Mismatch must surface a structured shape — generic "invalid" hides the
  // operator-actionable rotation guidance.
  assert.match(block, /fingerprint_mismatch:\s*true/,
    'mismatch return must include fingerprint_mismatch:true so downstream callers can render the rotation hint');
  assert.match(block, /fingerprint-mismatch/,
    'mismatch return must surface "fingerprint-mismatch" in the reason string for log scrapers');
});

// ---------------------------------------------------------------------------
// Fix 2 — AA P1-2 — Corrupt-sidecar bypass refusal.
// ---------------------------------------------------------------------------

test('Fix 2(a) — reattest refuses a corrupt-JSON sidecar without --force-replay (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const sid = 'aa-trust-corrupt-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0,
      `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

    const att = locateAttestation(sid);
    assert.ok(att, 'attestation must exist after producer run');
    fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25');  // truncated JSON

    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest against a corrupt-JSON sidecar must exit 6 (TAMPERED), not fall through to the benign NOTE branch. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    // The structured refusal body is emitted on stderr alongside the exit.
    const body = tryJson(r.stderr.split('\n').filter(l => l.trim().startsWith('{')).pop() || '') || {};
    assert.equal(body.ok, false,
      'corrupt-sidecar refusal body must carry ok:false (not just an exit code)');
    assert.equal(body.verb, 'reattest');
    assert.equal(body.session_id, sid);
    assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
      'refusal body must include the full sidecar_verify object for audit');
    assert.equal(body.sidecar_verify.tamper_class, 'sidecar-corrupt',
      'sidecar_verify.tamper_class must be "sidecar-corrupt" — substring matching on the reason is fragile');
  });

test('Fix 2(a) — reattest --force-replay accepts a corrupt sidecar and persists sidecar_verify + force_replay',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'aa-trust-corrupt-force-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, 'not-valid-json{{{');

    const r = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r.status, 0,
      `reattest --force-replay must succeed (exit 0) against a corrupt sidecar so the override is audit-visible. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);

    const body = tryJson(r.stdout) || {};
    assert.equal(body.ok, true, 'replay body must carry ok:true after --force-replay');
    assert.equal(body.verb, 'reattest');
    assert.equal(body.force_replay, true,
      'emitted body must record force_replay:true so the override is audit-visible');
    assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
      'emitted body must persist the full sidecar_verify object');
    assert.equal(body.sidecar_verify.tamper_class, 'sidecar-corrupt',
      'sidecar_verify.tamper_class must be preserved through the --force-replay branch so auditors can see what was overridden');
    assert.equal(body.sidecar_verify_class, 'sidecar-corrupt',
      'sidecar_verify_class one-token label must be "sidecar-corrupt"');
  });

test('Fix 2(b) — attest verify exits 6 with structured body on corrupt sidecar (not generic exit 1)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // Pre-fix the JSON.parse throw fell through the outer dispatcher catch
    // and exited 1 with no `results` array — operators saw "command failed"
    // with no tamper signal. Post-fix the parse is wrapped, the per-result
    // tamper predicate fires, and exit is 6.
    const sid = 'aa-trust-verify-corrupt-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25519"');  // unterminated JSON

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on a corrupt sidecar must exit 6 (TAMPERED), not 1 (generic). Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false,
      'corrupt-sidecar verify body must carry ok:false');
    assert.equal(body.verb, 'attest verify');
    assert.ok(Array.isArray(body.results),
      'verify must still emit a results array on corrupt sidecar (no unhandled throw)');
    assert.ok(body.results.length >= 1, 'results must be non-empty');
    const corruptResult = body.results.find(x => x.tamper_class === 'sidecar-corrupt');
    assert.ok(corruptResult,
      'at least one result must classify as tamper_class:"sidecar-corrupt"');
    assert.equal(corruptResult.verified, false,
      'corrupt-sidecar result must explicitly carry verified:false');
    assert.equal(corruptResult.signed, false,
      'corrupt-sidecar result must explicitly carry signed:false');
    assert.equal(typeof corruptResult.reason, 'string',
      'corrupt-sidecar result must carry a human-readable reason string');
    assert.match(corruptResult.reason, /sidecar parse error:/,
      'reason must start with "sidecar parse error:" for log scrapers');
  });

// ---------------------------------------------------------------------------
// Fix 3 — AA P1-1 — algorithm:"unsigned" substitution detection.
// ---------------------------------------------------------------------------

test('Fix 3 — attest verify exits 6 when an unsigned sidecar is substituted on a host WITH .keys/private.pem',
  { skip: !HAS_PRIV_KEY && 'substitution detection requires .keys/private.pem on the verifying host (see R-F1 skip pattern)' },
  () => {
    // Produce a signed attestation, then tamper attestation.json and
    // overwrite the sidecar with the unsigned stub. On a host with a
    // private key, the unsigned stub is impossible to have been written
    // legitimately by maybeSignAttestation() — it's a substitution.
    const sid = 'aa-trust-subst-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0,
      `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

    const att = locateAttestation(sid);
    assert.ok(att);

    // Tamper attestation.json — break the Ed25519 binding.
    const orig = fs.readFileSync(att.jsonFile, 'utf8');
    fs.writeFileSync(att.jsonFile, orig.replace(/\}\s*$/, ', "__tampered": true }'));
    // Substitute the .sig with the unsigned stub — the substitution attack.
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      reason: 'attestation explicitly unsigned',
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on an unsigned-substituted sidecar must exit 6 (TAMPERED) when .keys/private.pem is present. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false,
      'substitution body must carry ok:false');
    assert.equal(body.verb, 'attest verify');
    assert.ok(Array.isArray(body.results),
      'verify must emit a results array');
    const substResult = body.results.find(x => x.tamper_class === 'unsigned-substitution');
    assert.ok(substResult,
      'at least one result must classify as tamper_class:"unsigned-substitution"');
    assert.equal(substResult.verified, false,
      'substitution result must carry verified:false');
    assert.equal(substResult.signed, false,
      'substitution result must carry signed:false');
  });

test('Fix 3 — reattest --force-replay records sidecar_verify class for explicitly-unsigned + force_replay:true',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // cmdReattest must ALWAYS require --force-replay for an unsigned
    // attestation (regardless of host private-key state). The persisted
    // body must carry the verdict class so auditors can filter override
    // events without parsing the reason string.
    const sid = 'aa-trust-replay-explicit-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    // Replace the legitimate signed sidecar with the unsigned stub.
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    // First: confirm refusal without --force-replay.
    const r0 = cli(['reattest', sid, '--json']);
    assert.equal(r0.status, 6,
      `reattest must refuse an explicitly-unsigned sidecar without --force-replay (exit 6). Got status=${r0.status}. stderr=${r0.stderr.slice(0, 400)}`);

    // Then: --force-replay must succeed and record the override in the body.
    const r = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r.status, 0,
      `reattest --force-replay must succeed against an explicitly-unsigned sidecar. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || {};
    assert.equal(body.ok, true);
    assert.equal(body.force_replay, true,
      'emit body must record force_replay:true');
    // On a host WITH a private key, an explicitly-unsigned sidecar is
    // classified as unsigned-substitution. On a host WITHOUT one it's
    // explicitly-unsigned. Both are valid sidecar_verify_class values for
    // the --force-replay override path; the test must accept either.
    assert.ok(
      body.sidecar_verify_class === 'explicitly-unsigned' ||
      body.sidecar_verify_class === 'unsigned-substitution',
      `sidecar_verify_class must be "explicitly-unsigned" or "unsigned-substitution"; got ${JSON.stringify(body.sidecar_verify_class)}`
    );
    assert.ok(body.sidecar_verify && typeof body.sidecar_verify === 'object',
      'full sidecar_verify object must be persisted alongside the one-token class label');
    assert.equal(body.sidecar_verify.signed, false,
      'sidecar_verify.signed must be false on the unsigned path');
    assert.equal(body.sidecar_verify.verified, false,
      'sidecar_verify.verified must be false on the unsigned path');
    assert.equal(typeof body.sidecar_verify.reason, 'string',
      'sidecar_verify.reason must be a string operators can read');
  });
