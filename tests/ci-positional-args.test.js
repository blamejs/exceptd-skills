'use strict';

/**
 * tests/ci-positional-args.test.js
 *
 * Cycle 11 F1 fix (v0.12.31): `exceptd ci <playbook>` previously ignored
 * positional arguments and silently ran the cwd-autodetected playbook set
 * instead. An operator typing `exceptd ci kernel` got a PASS verdict for
 * `containers, crypto-codebase, library-author, secrets` — the kernel
 * playbook never ran but the operator never knew.
 *
 * The fix treats positional args as an inline --required, with the same
 * unknown-id refusal. This test pins the contract.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks the EXACT
 * playbooks_run array or EXACT exit code, never `assert.ok(includes)`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  return r;
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

test('ci <playbook> runs exactly the named playbook, not the cwd-autodetected set', () => {
  const r = cli(['ci', 'kernel']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci kernel must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run, ['kernel'], 'ci kernel must run exactly [kernel] and not the autodetected set');
});

test('ci <multiple-playbooks> runs every named playbook', () => {
  const r = cli(['ci', 'kernel', 'cred-stores']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci kernel cred-stores must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run.sort(), ['cred-stores', 'kernel']);
});

test('ci <unknown-playbook> refuses with structured error + exit 1, listing known IDs', () => {
  const r = cli(['ci', 'this-playbook-does-not-exist']);
  assert.equal(r.status, 1, `unknown positional must exit 1; got ${r.status}`);
  const err = tryJson(r.stderr);
  assert.ok(err, 'stderr must be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(Array.isArray(err.unknown), true);
  assert.equal(err.unknown.includes('this-playbook-does-not-exist'), true);
  assert.equal(Array.isArray(err.accepted), true);
  assert.equal(err.accepted.length > 10, true, 'accepted list should include the full playbook catalog');
});

test('ci --required <list> still works (existing contract preserved)', () => {
  const r = cli(['ci', '--required', 'kernel,cred-stores']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci --required must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run.sort(), ['cred-stores', 'kernel']);
});
