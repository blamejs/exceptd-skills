"use strict";


// ---- routed from verify-shipped-tarball-missing-sig ----
require("node:test").describe("verify-shipped-tarball-missing-sig", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
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
});


// ---- routed from verify-shipped-tarball-wrapper ----
require("node:test").describe("verify-shipped-tarball-wrapper", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/verify-shipped-tarball-wrapper.test.js
 *
 * Run scripts/verify-shipped-tarball.js inside `npm test` rather than
 * only inside the predeploy gate. A contributor running `npm test`
 * locally would otherwise miss the class of regression that broke 5
 * releases of signatures (v0.11.x through v0.12.2) — verifying the
 * source-tree signatures says nothing about whether `npm pack`'s
 * extracted output verifies.
 *
 * The script is invoked via a child process so the contract is the
 * same as the predeploy gate: exit 0 = pass, non-zero = fail. Skipped
 * when .keys/private.pem is absent (sign-all couldn't run, so the
 * gate is meaningless) — same skip-condition pattern as
 * tests/attest-verify-* tests use.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const PRIVATE_KEY = path.join(ROOT, '.keys', 'private.pem');
const SCRIPT = path.join(ROOT, 'scripts', 'verify-shipped-tarball.js');
const HAS_PRIV = fs.existsSync(PRIVATE_KEY);

test('shipped tarball verifies against its embedded public key', { skip: !HAS_PRIV && '.keys/private.pem absent — sign-all cannot run, so verify-shipped-tarball is meaningless' }, () => {
  const leaked = () => fs.readdirSync(os.tmpdir()).filter(n => n.startsWith('verify-shipped-'));
  const before = leaked();
  const r = spawnSync(process.execPath, [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 120000,
  });
  // Pin exact exit code (0 = pass). Pre-anti-coincidence-rule "coincidence-passing"
  // rule a notEqual(0) would have silently absorbed an exit 2 from the
  // npm-pack step.
  assert.equal(r.status, 0,
    `verify-shipped-tarball must exit 0 (signature verify against extracted tarball). Got status=${r.status}.\nstdout:\n${(r.stdout || '').slice(0, 800)}\nstderr:\n${(r.stderr || '').slice(0, 800)}`);
  // The cleanup finally{} must run on success — it must not sit behind a
  // process.exit(), which preempts it and leaks the npm-pack temp dir (tarball
  // + extraction tree) on every predeploy and `npm test` run. Assert no net new
  // verify-shipped-* dir, and that the dir the script announced is gone.
  const after = leaked();
  assert.equal(after.length, before.length,
    `verify-shipped-tarball leaked a temp dir (before=${before.length} after=${after.length}); cleanup finally{} must run on success.`);
  const m = (r.stdout || '').match(/packing into (\S+)/);
  assert.ok(m, 'expected the script to announce its temp dir on stdout');
  assert.equal(fs.existsSync(m[1]), false, `announced temp dir ${m[1]} should be removed on success`);
});
});
