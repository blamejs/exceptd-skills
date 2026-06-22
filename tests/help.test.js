'use strict';

/**
 * Subject coverage for the `help` CLI verb (bin/exceptd.js): the top-level
 * help listing and the --help / -h aliases.
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

  test('bin/exceptd.js: help exits 0 and lists the documented subcommands', () => {
    const r = run(['help']);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /exceptd —/);
    for (const cmd of ['path', 'prefetch', 'refresh', 'build-indexes', 'scan', 'currency', 'validate-cves', 'validate-rfcs', 'verify']) {
      assert.match(r.stdout, new RegExp('\\b' + cmd + '\\b'), `help is missing "${cmd}"`);
    }
  });

  test('bin/exceptd.js: --help and -h aliases work', () => {
    for (const flag of ['--help', '-h']) {
      const r = run([flag]);
      assert.equal(r.status, 0, `${flag} should exit 0`);
      assert.match(r.stdout, /exceptd —/);
    }
  });
});
