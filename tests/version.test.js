'use strict';

/**
 * Subject coverage for the `version` CLI verb (bin/exceptd.js): the bare-semver
 * stdout contract and the --version / -v aliases.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('bin-dispatcher', () => {
  const fs = require('fs');
  const path = require('path');
  const { spawnSync } = require('child_process');

  const ROOT = path.join(__dirname, '..');
  const BIN = path.join(ROOT, 'bin', 'exceptd.js');

  function run(args) {
    return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', cwd: ROOT });
  }

  test('bin/exceptd.js: version prints the package.json version', () => {
    const r = run(['version']);
    assert.equal(r.status, 0);
    const pkgVersion = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
    assert.equal(r.stdout.trim(), pkgVersion);
  });

  test('bin/exceptd.js: --version and -v aliases work', () => {
    for (const flag of ['--version', '-v']) {
      const r = run([flag]);
      assert.equal(r.status, 0, `${flag} should exit 0`);
      const v = r.stdout.trim();
      assert.match(v, /^\d+\.\d+\.\d+/, `${flag} should print a semver, got "${v}"`);
    }
  });
});

// ===========================================================================
test.describe('cli-output-envelope-shape', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, ...(opts.env || {}), EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
  }

  test('exceptd version: trivial scalar contract (proves harness)', () => {
    const r = cli(['version']);
    assert.equal(r.status, 0);
    // Stdout is a bare semver newline, NOT JSON. The contract is that
    // `version` always returns ONE token on stdout that semver-parses.
    const v = r.stdout.trim();
    assert.match(v, /^\d+\.\d+\.\d+$/, `version must be a bare semver; got: ${JSON.stringify(v)}`);
  });
});
