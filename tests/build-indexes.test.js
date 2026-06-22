'use strict';

/**
 * Subject suite for the `exceptd build-indexes` CLI verb (the dispatcher
 * smoke that --quiet --only stale-content exits 0). Deeper index-builder
 * behavior lives in the build-incremental / indexes module suites.
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// ===================================================================
// Source: bin-dispatcher.test.js
// ===================================================================
describe('bin-dispatcher.test.js', () => {
  const ROOT = path.join(__dirname, '..');
  const BIN = path.join(ROOT, 'bin', 'exceptd.js');
  function run(args) {
    return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', cwd: ROOT });
  }

  test('bin/exceptd.js: build-indexes --quiet --only stale-content exits 0', () => {
    const r = run(['build-indexes', '--quiet', '--only', 'stale-content']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  });
});
