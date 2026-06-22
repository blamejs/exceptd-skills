"use strict";

// ---- routed from attestation-signature-roundtrip ----
;(() => {
/**
 * Audit-VV trust-boundary fixes (KK P1-1..P1-5 + MM P1-D).
 *
 * Each test pins an EXACT exit code (assert.equal(r.status, N)) and pairs
 * every field-presence check with a content-shape check, per the project's
 * coincidence-passing-tests rule. notEqual(r.status, 0) is forbidden — a
 * coincidence-passing test blocks future regressions while letting the
 * current one through.
 *
 * Fixes covered:
 *   KK P1-1  Sidecar shape no longer carries `signed_at` / `signs_path` /
 *            `signs_sha256`. The Ed25519 signature covers ONLY the
 *            attestation file bytes — fields in the sidecar that aren't in
 *            the signed message are replay-rewrite trivial.
 *   KK P1-2  cmdReattest persists `replay-<isoZ>.json` under the session
 *            directory whenever a replay produced a verdict (force-replay
 *            or otherwise). `attest verify <sid>` surfaces both the
 *            original + the replay in its results array.
 *   KK P1-3  Sidecar verifier rejects any algorithm field that isn't
 *            exactly "Ed25519" or "unsigned" (downgrade-bait substitution)
 *            with tamper_class:"algorithm-unsupported" and exit 6.
 *   KK P1-4  hasReadableStdin Windows fallback requires isTTY === false
 *            STRICTLY — not falsy. isTTY === undefined no longer routes
 *            through readFileSync(0) and blocks on wrapped duplexer test
 *            harnesses.
 *   KK P1-5  Pin loader strips leading UTF-8 BOM (Notepad with
 *            files.encoding=utf8bom) + ignores comment / empty lines.
 *            All four sites converge on the shared helper.
 *   MM P1-D  sanitizeOperatorText (library-side guard for direct
 *            buildEvidenceBundle callers) NFC-normalises, strips \p{C}
 *            (Cc/Cf/Cs/Co/Cn), caps at 256 codepoints, returns null on
 *            empty-after-strip so callers route through the
 *            bundle_publisher_unclaimed fallback.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestationFiles(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find((p) => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot);
  const jsonFiles = files.filter((f) => f.endsWith('.json') && !f.endsWith('.sig'));
  return {
    dir: attRoot,
    files: jsonFiles,
    primaryJson: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json')
      : path.join(attRoot, jsonFiles[0]),
    primarySig: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json.sig')
      : path.join(attRoot, jsonFiles[0] + '.sig'),
  };
}

// ---------------------------------------------------------------------------
// KK P1-1 — sidecar `signed_at` is no longer present; rewriting it is a
// no-op for verify. Conversely the attestation file `captured_at` is
// signed; rewriting that field invalidates the signature.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-2 — force-replay persists a replay-*.json record on disk.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-3 — strict algorithm check.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-4 — hasReadableStdin Windows fallback strict isTTY===false.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-5 — pin loader strips BOM + tolerates CRLF + comments.
// ---------------------------------------------------------------------------







// ---------------------------------------------------------------------------
// MM P1-D — sanitizeOperatorText library-side guard.
// ---------------------------------------------------------------------------

test('KK P1-5 — loadExpectedFingerprintFirstLine strips a leading UTF-8 BOM', () => {
  const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-pin-bom-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  // Notepad saving as `files.encoding=utf8bom` prepends U+FEFF (EF BB BF).
  fs.writeFileSync(pinPath, '﻿SHA256:ExpectedFingerprintValue=\n');
  try {
    const out = loadExpectedFingerprintFirstLine(pinPath);
    assert.equal(out, 'SHA256:ExpectedFingerprintValue=',
      `leading BOM must be stripped; got ${JSON.stringify(out)}`);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test('KK P1-5 — loadExpectedFingerprintFirstLine tolerates CRLF line endings', () => {
  const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-pin-crlf-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:ExpectedFingerprintValue=\r\n# trailing comment\r\n');
  try {
    const out = loadExpectedFingerprintFirstLine(pinPath);
    assert.equal(out, 'SHA256:ExpectedFingerprintValue=',
      `CRLF + trailing comment must be tolerated; got ${JSON.stringify(out)}`);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test('KK P1-5 — loadExpectedFingerprintFirstLine skips leading comment + blank lines', () => {
  const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-pin-comment-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, '# header comment\n\n  \n# another\nSHA256:RealFp=\n');
  try {
    const out = loadExpectedFingerprintFirstLine(pinPath);
    assert.equal(out, 'SHA256:RealFp=',
      `comment + blank lines must be skipped; got ${JSON.stringify(out)}`);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test('KK P1-5 — loadExpectedFingerprintFirstLine returns null on missing file', () => {
  const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, 'lib', 'verify.js'));
  const out = loadExpectedFingerprintFirstLine(path.join(os.tmpdir(), 'nonexistent-' + Date.now()));
  assert.equal(out, null, 'missing file must return null (not throw, not "")');
});

test('KK P1-5 — all four pin-loader call sites route through loadExpectedFingerprintFirstLine', () => {
  // Static source-level invariant: every pin-loading site MUST require the
  // shared helper. If a future change inlines the loader at one site
  // (re-introducing the BOM regression), this catches it.
  const sites = [
    { name: 'lib/verify.js#checkExpectedFingerprint', file: 'lib/verify.js' },
    { name: 'lib/refresh-network.js', file: 'lib/refresh-network.js' },
    { name: 'scripts/verify-shipped-tarball.js', file: 'scripts/verify-shipped-tarball.js' },
    { name: 'bin/exceptd.js#assertExpectedFingerprint', file: 'bin/exceptd.js' },
  ];
  for (const s of sites) {
    const src = fs.readFileSync(path.join(ROOT, s.file), 'utf8');
    assert.ok(
      src.includes('loadExpectedFingerprintFirstLine'),
      `${s.name} must reference loadExpectedFingerprintFirstLine (the shared BOM-stripping helper)`
    );
  }
});

test('KK P1-5 — all four pin loaders produce byte-identical output on BOM + CRLF fuzz', () => {
  // The lib/verify export is the canonical helper; the other three sites
  // delegate to it (per the previous static check). Verify functional
  // equality across a representative corpus by exercising the canonical
  // helper directly — every call site routes through it, so a regression
  // at any one site would surface as a unit-test miss only if the site
  // re-inlined a divergent loader. The static check above closes that gap;
  // this test closes the functional gap.
  const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, 'lib', 'verify.js'));
  const CORPUS = [
    { label: 'plain', input: 'SHA256:abc=\n', expected: 'SHA256:abc=' },
    { label: 'BOM + LF', input: '﻿SHA256:abc=\n', expected: 'SHA256:abc=' },
    { label: 'BOM + CRLF', input: '﻿SHA256:abc=\r\n', expected: 'SHA256:abc=' },
    { label: 'CRLF only', input: 'SHA256:abc=\r\n', expected: 'SHA256:abc=' },
    { label: 'comment first', input: '# header\nSHA256:abc=\n', expected: 'SHA256:abc=' },
    { label: 'BOM + comment + value', input: '﻿# header\r\nSHA256:abc=\r\n', expected: 'SHA256:abc=' },
    { label: 'empty', input: '', expected: null },
    { label: 'only comments', input: '# a\n# b\n', expected: null },
  ];
  for (const item of CORPUS) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-pin-fuzz-'));
    const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
    fs.writeFileSync(pinPath, item.input);
    try {
      const out = loadExpectedFingerprintFirstLine(pinPath);
      assert.equal(out, item.expected,
        `corpus "${item.label}" must produce ${JSON.stringify(item.expected)}; got ${JSON.stringify(out)}`);
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }
});
})();

// ---- routed from attestation-trust-boundary ----
;(() => {
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
 * notEqual(0) — per the coincidence-passing-tests rule. Every
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





// ---------------------------------------------------------------------------
// Fix 2 — AA P1-2 — Corrupt-sidecar bypass refusal.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Fix 3 — AA P1-1 — algorithm:"unsigned" substitution detection.
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
})();
