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
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const PRIVATE_KEY = path.join(ROOT, '.keys', 'private.pem');
const SCRIPT = path.join(ROOT, 'scripts', 'verify-shipped-tarball.js');
const HAS_PRIV = fs.existsSync(PRIVATE_KEY);

test('shipped tarball verifies against its embedded public key', { skip: !HAS_PRIV && '.keys/private.pem absent — sign-all cannot run, so verify-shipped-tarball is meaningless' }, () => {
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
});
