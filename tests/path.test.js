'use strict';

/**
 * Subject suite for the `exceptd path` CLI verb — prints the absolute,
 * readable install directory that contains the shipped AGENTS.md.
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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

  test('bin/exceptd.js: path prints an absolute, readable directory', () => {
    const r = run(['path']);
    assert.equal(r.status, 0);
    const printed = r.stdout.trim();
    assert.ok(path.isAbsolute(printed), `expected absolute path, got "${printed}"`);
    assert.ok(fs.existsSync(path.join(printed, 'AGENTS.md')), 'path output should contain AGENTS.md');
  });
});
