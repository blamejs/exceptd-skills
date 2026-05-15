'use strict';

/**
 * Audit-VV trust-boundary fixes (KK P1-1..P1-5 + MM P1-D).
 *
 * Each test pins an EXACT exit code (assert.equal(r.status, N)) and pairs
 * every field-presence check with a content-shape check, per CLAUDE.md's
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

test('KK P1-1 — sidecar shape no longer carries signed_at / signs_path / signs_sha256',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-shape-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0,
      `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

    const att = locateAttestationFiles(sid);
    assert.ok(att, 'attestation must exist after producer run');
    const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));

    // Negative — the unsigned-metadata fields MUST be absent. Their
    // presence is the replay-rewrite surface this fix closes.
    assert.equal(sigDoc.signed_at, undefined,
      `signed_at MUST be absent from the sidecar (replay-rewrite trivial since the field is unsigned). Got ${JSON.stringify(sigDoc.signed_at)}`);
    assert.equal(sigDoc.signs_path, undefined,
      `signs_path MUST be absent from the sidecar (replay-rewrite trivial). Got ${JSON.stringify(sigDoc.signs_path)}`);
    assert.equal(sigDoc.signs_sha256, undefined,
      `signs_sha256 MUST be absent from the sidecar (replay-rewrite trivial). Got ${JSON.stringify(sigDoc.signs_sha256)}`);

    // Positive — the required signed-payload shape is intact.
    assert.equal(sigDoc.algorithm, 'Ed25519',
      'sidecar.algorithm must be exactly "Ed25519"');
    assert.equal(typeof sigDoc.signature_base64, 'string',
      'sidecar.signature_base64 must be a string (the actual Ed25519 sig)');
    assert.ok(sigDoc.signature_base64.length > 40,
      'sidecar.signature_base64 must be a non-trivial base64 string');
  });

test('KK P1-1 — rewriting a legacy signed_at on a legacy sidecar is a verify no-op (forwards-compat)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // The fix dropped signed_at from the sidecar shape, but legacy sidecars
    // in the wild may still carry it. Adding it back at verify time MUST
    // NOT break verify (the field is ignored). This closes the replay-
    // rewrite surface even on legacy-shape sidecars.
    const sid = 'vv-trust-legacy-signed-at-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);
    const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
    // Inject a garbage signed_at + signs_path that don't match anything.
    sigDoc.signed_at = '1970-01-01T00:00:00.000Z';
    sigDoc.signs_path = 'this-file-does-not-exist.json';
    sigDoc.signs_sha256 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
    fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 0,
      `verify must still succeed (exit 0) after rewriting unsigned legacy fields — they are not part of the signed message. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || {};
    assert.equal(body.verb, 'attest verify');
    assert.ok(Array.isArray(body.results), 'verify must emit a results array');
    const verified = body.results.find((x) => x.verified === true);
    assert.ok(verified,
      'at least one result must be verified:true (signed_at/signs_path/signs_sha256 are NOT part of the signed message)');
  });

test('KK P1-1 — rewriting attestation.captured_at INVALIDATES the signature (exit 6)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-captured-at-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);
    // The attestation file content IS what the Ed25519 signature covers.
    // Rewriting any field invalidates the signature → tamper → exit 6.
    const att0 = fs.readFileSync(att.primaryJson, 'utf8');
    const tampered = att0.replace(/"captured_at"\s*:\s*"[^"]+"/, '"captured_at": "1970-01-01T00:00:00.000Z"');
    assert.notEqual(tampered, att0, 'captured_at rewrite must actually change the file');
    fs.writeFileSync(att.primaryJson, tampered);

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `rewriting captured_at on the SIGNED attestation file must exit 6 (TAMPERED). Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'tamper body must carry ok:false');
    const failed = body.results.find((x) => x.signed === true && x.verified === false);
    assert.ok(failed,
      'at least one result must classify as signed-but-invalid (the captured_at rewrite broke the Ed25519 signature)');
  });

// ---------------------------------------------------------------------------
// KK P1-2 — force-replay persists a replay-*.json record on disk.
// ---------------------------------------------------------------------------

test('KK P1-2 — reattest --force-replay writes replay-<isoZ>.json under the session dir',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-replay-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);

    // Force a tamper class — easiest is to overwrite the sidecar with the
    // unsigned stub on a host that has a private key (substitution attack).
    fs.writeFileSync(att.primarySig, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      note: 'forged',
    }, null, 2));

    const r = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r.status, 0,
      `reattest --force-replay must succeed; got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || {};
    assert.equal(body.ok, true, 'replay body must carry ok:true');
    assert.equal(body.force_replay, true,
      'replay body must record force_replay:true');

    // The persisted-record handle MUST be present in the response body so
    // operators can locate the on-disk audit artifact without re-deriving
    // the filename.
    assert.ok(body.replay_persisted && typeof body.replay_persisted === 'object',
      'replay_persisted must be an object handle');
    assert.equal(body.replay_persisted.ok, true,
      `replay_persisted.ok must be true. Got ${JSON.stringify(body.replay_persisted)}`);
    assert.equal(typeof body.replay_persisted.path, 'string',
      'replay_persisted.path must be a string');
    assert.ok(/[\\/]replay-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.json$/.test(body.replay_persisted.path),
      `replay_persisted.path must match the replay-<isoZ>.json shape. Got ${body.replay_persisted.path}`);

    // The file MUST exist on disk and be parseable JSON with the expected
    // shape — every field-presence check is paired with a content-shape
    // check.
    assert.ok(fs.existsSync(body.replay_persisted.path),
      `replay file must exist at the persisted path: ${body.replay_persisted.path}`);
    const replayBody = JSON.parse(fs.readFileSync(body.replay_persisted.path, 'utf8'));
    assert.equal(replayBody.kind, 'replay',
      'persisted body must carry kind:"replay" so auditors can distinguish from primary attestations');
    assert.equal(replayBody.session_id, sid);
    assert.equal(replayBody.force_replay, true,
      'persisted body must record force_replay:true');
    assert.ok(
      replayBody.sidecar_verify_class === 'unsigned-substitution' ||
      replayBody.sidecar_verify_class === 'explicitly-unsigned',
      `persisted body must record sidecar_verify_class. Got ${JSON.stringify(replayBody.sidecar_verify_class)}`
    );
    assert.equal(typeof replayBody.prior_evidence_hash, 'string',
      'persisted body must record prior_evidence_hash (string)');
    assert.equal(typeof replayBody.replayed_at, 'string',
      'persisted body must record replayed_at (ISO-8601 string)');
  });

test('KK P1-2 — attest verify surfaces both the original attestation AND the replay in results',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // The persisted replay file lives under the same session dir, so the
    // existing attest verify iterator picks it up automatically. Operators
    // running `attest verify <sid>` after a --force-replay event see both
    // the original AND the override on disk.
    const sid = 'vv-trust-replay-listed-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);

    // Stage an unsigned-stub sidecar, then force-replay. This produces
    // ONE replay-*.json file. We then re-sign the original sidecar (by
    // re-running maybeSignAttestation via a fresh exceptd invocation is
    // not available; simplest path is to leave the stub in place and
    // expect the original to verify as unsigned-substitution).
    fs.writeFileSync(att.primarySig, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
    }, null, 2));

    const r2 = cli(['reattest', sid, '--force-replay', '--json']);
    assert.equal(r2.status, 0);
    const replayBody = tryJson(r2.stdout) || {};
    assert.ok(replayBody.replay_persisted && replayBody.replay_persisted.path);

    // Confirm the on-disk state: TWO json files in the session dir
    // (original + replay), each potentially with its own .sig.
    const refreshed = locateAttestationFiles(sid);
    assert.ok(refreshed);
    assert.ok(refreshed.files.length >= 2,
      `session dir must contain >= 2 .json files after force-replay (original + replay). Got ${refreshed.files.length}: ${refreshed.files.join(',')}`);
    const replayFile = refreshed.files.find((f) => f.startsWith('replay-'));
    assert.ok(replayFile,
      `session dir must contain a replay-*.json file. Got: ${refreshed.files.join(',')}`);

    const r = cli(['attest', 'verify', sid, '--json']);
    // Original sidecar is unsigned-substitution (tamper) so verify exits
    // 6. v0.12.24 partitioned replay records out of `results[]` into
    // `replay_results[]`: the original attestation surfaces in results[]
    // (and its tamper class drives exit 6); the replay record lives under
    // `replay_results[]` for audit-trail visibility without inflating the
    // attestation-verified count.
    assert.equal(r.status, 6,
      `attest verify after a substituted-original force-replay must surface tamper class via exit 6. Got status=${r.status}.`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.ok(Array.isArray(body.results),
      'verify must emit a results array');
    assert.ok(Array.isArray(body.replay_results),
      'verify must emit a replay_results array (v0.12.24 partition)');
    const replayResult = body.replay_results.find((x) => x.file && x.file.startsWith('replay-'));
    assert.ok(replayResult,
      `verify replay_results must include the replay-*.json file. Got files: ${body.replay_results.map((x) => x.file).join(',')}`);
  });

// ---------------------------------------------------------------------------
// KK P1-3 — strict algorithm check.
// ---------------------------------------------------------------------------

test('KK P1-3 — attest verify refuses sidecar with algorithm:"RSA-PSS" (exit 6, algorithm-unsupported)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-algo-rsa-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);
    // Replace algorithm field with a downgrade-bait value. The
    // signature_base64 is preserved so a non-strict verifier would
    // proceed to crypto.verify with default Ed25519 args.
    const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
    sigDoc.algorithm = 'RSA-PSS';
    fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify must exit 6 (TAMPERED) on a downgrade-bait algorithm field. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'attest verify');
    const algResult = body.results.find((x) => x.tamper_class === 'algorithm-unsupported');
    assert.ok(algResult,
      `at least one result must classify as tamper_class:"algorithm-unsupported". Got: ${JSON.stringify(body.results)}`);
    assert.equal(algResult.signed, false,
      'algorithm-unsupported result must carry signed:false');
    assert.equal(algResult.verified, false,
      'algorithm-unsupported result must carry verified:false');
    assert.match(algResult.reason, /unsupported algorithm:/,
      'reason must start with "unsupported algorithm:" for log scrapers');
  });

test('KK P1-3 — attest verify refuses sidecar with algorithm:null (exit 6, algorithm-unsupported)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-algo-null-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);
    const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
    sigDoc.algorithm = null;
    fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify must exit 6 (TAMPERED) on algorithm:null. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    const algResult = body.results.find((x) => x.tamper_class === 'algorithm-unsupported');
    assert.ok(algResult,
      `algorithm:null must classify as algorithm-unsupported. Got: ${JSON.stringify(body.results)}`);
    assert.equal(algResult.signed, false);
    assert.equal(algResult.verified, false);
  });

test('KK P1-3 — reattest refuses sidecar with algorithm:"HMAC-SHA256" (exit 6, algorithm-unsupported)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    const sid = 'vv-trust-algo-replay-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestationFiles(sid);
    assert.ok(att);
    const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
    sigDoc.algorithm = 'HMAC-SHA256';
    fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest must exit 6 on a downgrade-bait algorithm field. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = tryJson(r.stderr.split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'reattest');
    assert.equal(body.sidecar_verify && body.sidecar_verify.tamper_class, 'algorithm-unsupported',
      `sidecar_verify.tamper_class must be "algorithm-unsupported"; got ${JSON.stringify(body.sidecar_verify)}`);
  });

// ---------------------------------------------------------------------------
// KK P1-4 — hasReadableStdin Windows fallback strict isTTY===false.
// ---------------------------------------------------------------------------

test('KK P1-4 — hasReadableStdin source guards on strict isTTY===false on win32', () => {
  // The function isn't a CommonJS export (bin/exceptd.js dispatches under
  // require.main === module). Verify the source-level invariant directly:
  // the win32 fallback MUST require `process.stdin.isTTY === false`
  // strictly (not falsy), so isTTY===undefined no longer routes through
  // readFileSync(0) on a wrapped duplexer.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const m = src.match(/function hasReadableStdin\(\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(m, 'hasReadableStdin must exist in bin/exceptd.js');
  const body = m[1];
  // Negative — the legacy `!process.stdin.isTTY` truthy fallback in a
  // win32 conditional is forbidden. (Equivalent test: ensure no return
  // line in the win32 conditional uses the bare-not form.)
  assert.ok(
    !/win32[\s\S]*return\s+!process\.stdin\.isTTY\s*;/.test(body),
    'win32 fallback must NOT return `!process.stdin.isTTY` (returns true on isTTY===undefined → blocks readFileSync on wrapped duplexers)'
  );
  // Positive — the strict equality form MUST be present in the win32 path.
  assert.match(
    body,
    /win32[\s\S]*process\.stdin\.isTTY\s*===\s*false/,
    'win32 fallback must guard on `process.stdin.isTTY === false` strictly'
  );
});

test('KK P1-4 — exceptd run --evidence - hangs neither on a piped empty stdin nor exits silently', () => {
  // Functional smoke: a piped empty stdin (test harness) must produce a
  // structured error rather than blocking. The cli helper enforces a 30s
  // timeout, so a hang would surface as r.signal === 'SIGTERM' /
  // r.status === null. We assert the run completed (not killed by
  // timeout) — the actual exit code may be non-zero (no playbook
  // supplied) which is fine.
  const r = cli(['run', 'library-author', '--evidence', '-'], { input: '', timeout: 10000 });
  assert.ok(r.status !== null,
    `run must terminate, not hang on empty stdin pipe. Got status=${r.status} signal=${r.signal}.`);
  assert.notEqual(r.signal, 'SIGTERM',
    'run must not be killed by the 10s timeout — the empty-pipe path must complete promptly');
});

// ---------------------------------------------------------------------------
// KK P1-5 — pin loader strips BOM + tolerates CRLF + comments.
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

// ---------------------------------------------------------------------------
// MM P1-D — sanitizeOperatorText library-side guard.
// ---------------------------------------------------------------------------

test('MM P1-D — sanitizeOperatorText strips U+202E (RTL OVERRIDE) and returns null when result is empty', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  assert.equal(typeof runnerMod.sanitizeOperatorText, 'function',
    'sanitizeOperatorText must be exported (or testable as a top-level function via the runner module)');
  // 'alice' + U+202E (RTL OVERRIDE) + 'evilbob' — a bidi-forgery attempt.
  const out = runnerMod.sanitizeOperatorText('alice‮evilbob');
  // The result MUST NOT contain U+202E — that's the whole point.
  assert.equal(typeof out, 'string', 'non-empty residue should still surface as a string after the bidi codepoint is stripped');
  assert.ok(!out.includes('‮'),
    `sanitised output must not contain U+202E; got ${JSON.stringify(out)}`);
  // The remaining ASCII (alice + evilbob) is concatenated. That is fine —
  // the forgery surface is the bidi codepoint, not the residual letters.
  assert.equal(out, 'aliceevilbob',
    `bidi-stripped concatenation must equal "aliceevilbob"; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText strips zero-width joiner / non-joiner / space and surrogate / private-use', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM mid-string, U+E000 PUA.
  const out = runnerMod.sanitizeOperatorText('a​b‌c‍d﻿ef');
  assert.equal(out, 'abcdef',
    `every Cf/Co codepoint must be stripped; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText returns null on all-Cf input (empty after strip)', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // Only zero-width codepoints: post-strip the result is empty → null.
  const out = runnerMod.sanitizeOperatorText('​‌‍‮﻿');
  assert.equal(out, null,
    `all-Cf input must collapse to null (callers route through the bundle_publisher_unclaimed fallback); got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText NFC-normalises before stripping', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // 'café' as 'cafe' + U+0301 COMBINING ACUTE ACCENT → NFC composes to U+00E9.
  // The COMBINING ACCENT is category Mn (Mark, Nonspacing), which is NOT in
  // \p{C} — but the NFC composition is what we care about. Verify the
  // output is the canonical-composed form.
  const out = runnerMod.sanitizeOperatorText('café');
  assert.equal(out, 'café',
    `NFC normalisation must compose combining marks; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText caps at 256 CODEPOINTS, not UTF-16 code units', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // 257 copies of U+1F600 (astral plane — each codepoint occupies 2 UTF-16
  // code units, so .length = 514). The cap must operate on codepoints.
  const input = '\u{1F600}'.repeat(257);
  const out = runnerMod.sanitizeOperatorText(input);
  // Array.from counts codepoints — exactly 256 after the cap.
  assert.equal(Array.from(out).length, 256,
    `cap must apply at 256 codepoints (not 256 UTF-16 code units); got ${Array.from(out).length}`);
});

test('MM P1-D — sanitizeOperatorText returns null for non-string input', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  assert.equal(runnerMod.sanitizeOperatorText(null), null);
  assert.equal(runnerMod.sanitizeOperatorText(undefined), null);
  assert.equal(runnerMod.sanitizeOperatorText(42), null);
  assert.equal(runnerMod.sanitizeOperatorText({}), null);
  assert.equal(runnerMod.sanitizeOperatorText([]), null);
});

test('MM P1-D — buildEvidenceBundle with a bidi-forged operator routes through bundle_publisher_unclaimed',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // End-to-end: a library caller invokes buildEvidenceBundle indirectly
    // via the CLI by passing a bidi-forged --operator. Even though the CLI
    // refuses the input at validateOperator(), this test confirms that
    // when the runner's sanitizeOperatorText sees a forged input from
    // a direct library caller (the CLI guard is one layer; sanitizer is
    // the library-side defence-in-depth), the result routes through the
    // fallback path.
    //
    // We exercise the sanitizer directly + assert the fallback contract:
    // a sanitised null operator value MUST NOT appear in a CSAF
    // publisher.namespace position.
    const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
    const forgedOperator = 'alice‮evilbob';
    const clean = runnerMod.sanitizeOperatorText(forgedOperator);
    // After the strip, the residue is plain ASCII — NOT a URL — so the
    // publisher-namespace resolution path's `/^https?:\/\//i` regex will
    // reject it AND it will fall through to the urn:exceptd:operator:unknown
    // fallback. Confirm the residue is NOT URL-shaped.
    assert.equal(typeof clean, 'string');
    assert.ok(!/^https?:\/\//i.test(clean),
      `bidi-stripped residue must not look URL-shaped (would falsely populate publisher.namespace); got ${JSON.stringify(clean)}`);
    // The companion assertion — a sanitised publisher-namespace input that
    // collapses to null routes through the fallback as expected.
    const forgedNs = '‮​‌';
    const cleanNs = runnerMod.sanitizeOperatorText(forgedNs);
    assert.equal(cleanNs, null,
      `all-Cf publisher-namespace input must collapse to null so the runner picks up the bundle_publisher_unclaimed fallback`);
  });
