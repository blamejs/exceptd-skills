'use strict';

/**
 * tests/v0_12_41-fixes.test.js
 *
 * Per-fix regression pins for the v0.12.41 release. Each test reads the
 * source byte-for-byte or invokes a unit under test against a known
 * input and asserts the exact post-fix shape.
 *
 * Fixes covered:
 *   F1 — lib/sign.js generateKeypair refuses to overwrite an existing
 *        keys/public.pem without --rotate (prevents the v0.11.x signature
 *        regression class where doctor --fix orphans shipped signatures).
 *   F2 — bin/exceptd.js sidecar .sig writes use mode 0o600 + restrictWindowsAcl
 *        (analogue of v0.12.38 attestation.json hardening).
 *   F3 — bin/exceptd.js doctor --fix chains sign-all after key generation
 *        AND refuses if keys/public.pem exists without matching privkey.
 *   F4 — bin/exceptd.js attest unknown subverb emits did_you_mean array
 *        (closes the v0.12.37 typo-suggestion class for the attest dispatcher).
 *   F5 — bin/exceptd.js attest diff guards against empty attestations[]
 *        (TypeError on session dirs containing only replay records).
 *   F6 — bin/exceptd.js cmdAsk honors --pretty as an implicit --json opt-in
 *        (alignment with discover/doctor convention).
 *   F7 — lib/scoring.js compare() surfaces "no scoring signal" distinctly
 *        from "broadly aligned" when both rwep and cvss are zero/null
 *        (coincidence-passing fix per CLAUDE.md pitfall).
 *   F8 — lib/playbook-runner.js normalizeSubmission clones submission
 *        before pushing to _runErrors (prevents TypeError on frozen input).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', cwd: ROOT, ...opts });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// ---------- F1 — sign.js generate-keypair public-key overwrite refusal ----------

test('F1: lib/sign.js generateKeypair() guards keys/public.pem overwrite', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'sign.js'), 'utf8');
  // The fix must check PUBLIC_KEY_PATH existence + refuse without --rotate
  // BEFORE writing PRIVATE_KEY_PATH. Pin both the existence check AND the
  // operator-facing refusal message so a future refactor that drops one
  // doesn't slip through.
  assert.match(src, /fs\.existsSync\(PUBLIC_KEY_PATH\).*!rotate/s,
    'lib/sign.js generateKeypair must guard against existing public key without --rotate');
  assert.match(src, /Refusing to overwrite the public key/,
    'lib/sign.js must surface the refusal reason to the operator');
});

// ---------- F2 — sidecar .sig 0o600 + Windows ACL ----------

test('F2: bin/exceptd.js sidecar + body writes use mode 0o600 and ACL-harden the sidecar', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // The atomic-write refactor writes the body + sidecar to fsync'd tmp files
  // via a shared writeFsync helper that opens each with mode 0o600
  // (openSync(p, "w", 0o600)); the mode survives the rename into place. The
  // 0o600 protection must still be present, and restrictWindowsAcl must still
  // be applied to the sidecar path (Windows multi-tenant hardening).
  assert.match(src, /fs\.openSync\([^,]+,\s*"w",\s*0o600\)/,
    'attestation writes must create files with mode 0o600 (via openSync)');
  assert.match(src, /restrictWindowsAcl\(sigPath\)/,
    'bin/exceptd.js must call restrictWindowsAcl on the .sig sidecar (Windows multi-tenant hardening)');
});

// ---------- F3 — doctor --fix chains sign-all + refuses on pubkey mismatch ----------

test('F3: bin/exceptd.js doctor --fix refuses when keys/public.pem present without privkey', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /pubKeyExists/, 'doctor --fix must check pubkey existence before generating');
  assert.match(src, /ed25519_keypair_generation_declined/,
    'doctor --fix must surface a distinct decline reason when pubkey exists without privkey');
  assert.match(src, /sign-all/, 'doctor --fix must chain sign-all after generate-keypair succeeds');
});

test('F3b: doctor --fix detects post-rotate stale signatures and chains sign-all (codex P2)', () => {
  // codex P2 v0.12.41: after `generate-keypair --rotate` the private key
  // IS present, so the missing-key remediation path never fires.
  // doctor --fix must ALSO detect signatures-failing-while-key-present
  // and chain sign-all so the post-rotate flow converges to verified.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /skills_resigned_against_current_keypair/,
    'doctor --fix must support the post-rotation re-sign path');
  // Pin the precondition: only fires when key IS present AND signatures
  // check failed AND no earlier --fix path already ran.
  assert.match(src, /checks\.signing\.private_key_present[\s\S]{0,200}checks\.signatures[\s\S]{0,50}ok === false/,
    'post-rotate sign-all path must gate on private_key_present && signatures.ok === false');
});

// ---------- F4 — attest unknown subverb did-you-mean ----------

test('F4: attest unknown subverb returns did_you_mean[] in JSON body', () => {
  const r = cli(['attest', 'verfy', 'some-sid', '--json']);
  // Exit 1 (GENERIC_FAILURE) is the canonical code for unknown-subverb
  // usage errors via emitError(). The JSON body lands on stderr (per
  // emitError contract).
  assert.equal(r.status, 1, `attest verfy should exit 1; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false, `expected ok:false body; got ${r.stderr.slice(0, 200)}`);
  assert.ok(Array.isArray(body.did_you_mean), `expected did_you_mean[] array; got ${typeof body.did_you_mean}`);
  assert.ok(body.did_you_mean.includes('verify'),
    `expected did_you_mean to include "verify" for input "verfy"; got ${JSON.stringify(body.did_you_mean)}`);
  assert.ok(Array.isArray(body.accepted_subverbs), 'accepted_subverbs[] must be present');
  // Pin the canonical subverb set so a future addition/removal updates
  // the test consciously.
  assert.deepEqual(body.accepted_subverbs.slice().sort(), ['diff', 'export', 'list', 'prune', 'show', 'verify']);
});

// ---------- F6 — cmdAsk honors --pretty ----------

test('F6: cmdAsk --pretty emits JSON output (not human text)', () => {
  const r = cli(['ask', 'kernel privilege escalation', '--pretty']);
  // --pretty alone (without --json) should produce parseable JSON.
  assert.equal(r.status, 0, `ask --pretty should exit 0; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout);
  assert.ok(body, `expected JSON body on stdout; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'ask');
  assert.equal(typeof body.question, 'string');
  assert.ok(Array.isArray(body.routed_to));
});

// ---------- F7 — scoring compare() no-signal branch ----------

test('F7: lib/scoring.js compare() surfaces "no scoring signal" when rwep+cvss are zero', () => {
  const { compare } = require('../lib/scoring.js');
  // compare() takes the catalog map directly (cveId -> entry).
  const stubCatalog = {
    'CVE-TEST-NO-SIGNAL': {
      cvss_score: 0,
      rwep_score: 0,
      rwep_factors: {},
      cisa_kev: false,
      poc_available: false,
      ai_discovered: false,
      active_exploitation: 'none',
      patch_available: false,
    },
  };
  const r = compare('CVE-TEST-NO-SIGNAL', stubCatalog);
  assert.ok(r, 'compare() must return a result');
  assert.match(r.explanation, /No scoring signal/i,
    `expected "no scoring signal" branch; got: ${r.explanation}`);
});

// ---------- F8 — normalizeSubmission clones before _runErrors push ----------

test('F8: lib/playbook-runner.js normalizeSubmission accepts frozen submissions', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'playbook-runner.js'), 'utf8');
  // The fix must build a fresh carry array from the original (or empty)
  // and pass it INTO the spread, not mutate the input in place. Pin
  // both the pattern shape AND the absence of the pre-fix in-place
  // mutation.
  assert.match(src, /const carry = Array\.isArray\(submission\._runErrors\) \? submission\._runErrors\.slice\(\) : \[\];/,
    'normalizeSubmission must clone _runErrors before pushing');
  assert.ok(!src.includes('if (!submission._runErrors) submission._runErrors = [];\n    pushRunError(submission._runErrors'),
    'pre-fix in-place mutation pattern must not return');
});

// ---------- Additional regression pins ----------

test('attest diff guards against empty attestations[]', () => {
  // Build a temp session dir with ONLY a replay record (no attestation
  // proper) and verify cmdAttest diff returns ok:false rather than
  // throwing TypeError on `self.captured_at`.
  const os = require('node:os');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-attest-diff-empty-'));
  try {
    // EXCEPTD_HOME is the parent; attestations live under
    // <EXCEPTD_HOME>/attestations/<sid>/ per the resolver convention.
    const attDir = path.join(tmp, 'attestations');
    fs.mkdirSync(attDir, { recursive: true });
    const sid = 'test-sid-empty-' + Date.now();
    const sessionDir = path.join(attDir, sid);
    fs.mkdirSync(sessionDir, { recursive: true });
    // Replay record only — no attestation.json.
    fs.writeFileSync(path.join(sessionDir, 'replay-001.json'), JSON.stringify({
      kind: 'replay',
      session_id: sid,
      captured_at: new Date().toISOString(),
    }));
    // Create a second session to diff against.
    const sid2 = 'test-sid-other-' + Date.now();
    const otherDir = path.join(attDir, sid2);
    fs.mkdirSync(otherDir, { recursive: true });
    fs.writeFileSync(path.join(otherDir, 'attestation.json'), JSON.stringify({
      session_id: sid2,
      captured_at: new Date().toISOString(),
      evidence_hash: 'sha256:abc',
      submission: { artifacts: {}, signal_overrides: {} },
    }));
    const r = cli(['attest', 'diff', sid, '--against', sid2, '--json'], { env: { ...process.env, EXCEPTD_HOME: tmp } });
    // Exit 1 (emitError sets exitCode=1); body on stderr.
    assert.equal(r.status, 1, `attest diff on empty-attestations should exit 1; got ${r.status}. stdout: ${r.stdout.slice(0, 200)} stderr: ${r.stderr.slice(0, 200)}`);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false, `expected ok:false body; got: ${(r.stderr || r.stdout).slice(0, 200)}`);
    assert.match(body.error || '', /no attestation/i,
      'error message must point at the missing attestation, not throw TypeError');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Note: orchestrator exit-code harmonization (framework-gap, report,
// watchlist usage errors collide with DETECTED_ESCALATE on exit 2) is
// pinned by operator-contract tests today. Splitting that envelope is
// a v0.13 minor-bump change requiring explicit confirmation per the
// project's cadence rule. Tracked in CHANGELOG forward-watch.
