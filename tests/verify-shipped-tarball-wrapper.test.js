'use strict';

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
