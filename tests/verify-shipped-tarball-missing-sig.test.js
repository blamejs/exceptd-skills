'use strict';

/**
 * tests/verify-shipped-tarball-missing-sig.test.js
 *
 * The shipped-tarball verify gate iterates every manifest skill entry and
 * verifies its Ed25519 signature. A skill entry MAY legally omit the
 * `signature` field — it is not in the manifest schema's skillEntry.required
 * set (lib/schemas/manifest.schema.json). A freshly-added skill, or one
 * skipped during a partial sign-all (lib/verify.js signAll() `continue`s a
 * skill whose .md file is absent), leaves the entry with no `signature`,
 * while the manifest envelope is still validly re-signed over that
 * field-absent state — so the manifest_signature gate passes.
 *
 * Before the guard, the per-skill loop fed `Buffer.from(s.signature,
 * 'base64')` with `s.signature === undefined`, throwing
 * `TypeError: The first argument must be of type string ... Received
 * undefined`. That TypeError is not the ABORT sentinel, so the body's
 * `catch (e) { if (e !== ABORT) throw e; }` re-throws it as an uncaught
 * exception + stack trace — turning a should-be-structured "missing
 * signature" FAIL into a crash, AND (because process.exitCode was never set
 * before the throw) the finally{} block deletes the temp dir it intends to
 * PRESERVE on failure. The gate still failed closed (exit 1 from the
 * uncaught throw) so it was not a verification bypass, but the diagnostic
 * was a raw stack instead of `'{skill}: no Ed25519 signature in manifest'`.
 *
 * verifySkillSignatureOutcome() now mirrors lib/verify.js verifySkill()'s
 * missing_sig branch. These tests assert the EXACT structured outcomes
 * (status strings), and specifically that a missing/empty/null signature
 * does NOT throw.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const {
  verifySkillSignatureOutcome,
  normalizeSkillBytes,
} = require(path.join(__dirname, '..', 'scripts', 'verify-shipped-tarball.js'));

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const body = normalizeSkillBytes(Buffer.from('# skill\nbody content\n'));
const validSig = crypto
  .sign(null, body, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  .toString('base64');

test('missing signature field yields a structured miss, not a TypeError', () => {
  let outcome;
  assert.doesNotThrow(() => {
    outcome = verifySkillSignatureOutcome({ name: 'kernel-lpe' }, body, publicKey);
  }, 'a skill entry with no signature field must not throw Buffer.from(undefined,base64)');
  assert.deepEqual(outcome, { status: 'missing' });
});

test('null signature yields a structured miss, not a TypeError', () => {
  let outcome;
  assert.doesNotThrow(() => {
    outcome = verifySkillSignatureOutcome({ name: 'x', signature: null }, body, publicKey);
  });
  assert.equal(outcome.status, 'missing');
});

test('empty-string signature yields a structured miss', () => {
  const outcome = verifySkillSignatureOutcome({ name: 'x', signature: '' }, body, publicKey);
  assert.equal(outcome.status, 'missing');
});

test('valid signature over matching content yields pass', () => {
  const outcome = verifySkillSignatureOutcome({ name: 'x', signature: validSig }, body, publicKey);
  assert.equal(outcome.status, 'pass');
});

test('valid signature over tampered content yields fail', () => {
  const tampered = normalizeSkillBytes(Buffer.from('# skill\nTAMPERED\n'));
  const outcome = verifySkillSignatureOutcome({ name: 'x', signature: validSig }, tampered, publicKey);
  assert.equal(outcome.status, 'fail');
});

test('a manifest with one signature-absent skill counts as miss in the loop math', () => {
  // Simulate the gate's per-skill accounting (lines around the loop) to
  // assert the field-absent entry increments miss, not crash, and the
  // overall result is a structured FAIL (pass !== total).
  const skills = [
    { name: 'signed', signature: validSig },
    { name: 'unsigned' }, // schema-valid: no signature
  ];
  let pass = 0, miss = 0, fail_count = 0;
  const failures = [];
  for (const s of skills) {
    const outcome = verifySkillSignatureOutcome(s, body, publicKey);
    if (outcome.status === 'missing') {
      miss++;
      failures.push(`${s.name}: no Ed25519 signature in manifest`);
      continue;
    }
    if (outcome.status === 'pass') pass++;
    else fail_count++;
  }
  assert.equal(pass, 1);
  assert.equal(miss, 1);
  assert.equal(fail_count, 0);
  assert.ok(
    failures.some((f) => f.includes('unsigned: no Ed25519 signature in manifest')),
    'the missing-signature skill must produce the structured failure string',
  );
  // The gate's PASS condition is fail_count===0 && miss===0 && pass===total.
  // A single miss must therefore drive the FAIL branch (exit 1), structured.
  assert.ok(!(fail_count === 0 && miss === 0 && pass === skills.length));
});
