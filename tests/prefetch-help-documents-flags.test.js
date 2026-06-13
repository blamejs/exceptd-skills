'use strict';

/**
 * prefetch --help must document every flag it actually accepts.
 *
 * --max-errors is fully implemented (parsed, validated, and consumed by the
 * exit-code logic) but was missing from the --help Options block, so a flag
 * that changes CI exit-code semantics was invisible to anyone reading --help.
 * These assertions pin the help text to the implementation in both directions:
 * the flag is documented AND it stays wired to real parse logic.
 *
 * Offline only: --help and parseArgs never touch the network.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PREFETCH = path.join(ROOT, 'lib', 'prefetch.js');

test('prefetch --help documents --max-errors', () => {
  const r = spawnSync(process.execPath, [PREFETCH, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `--help must exit 0; stderr=${r.stderr}`);
  assert.match(r.stdout, /--max-errors/, '--help must list the --max-errors flag');
});

test('the documented --max-errors flag stays wired to real parse logic', () => {
  const { parseArgs, parseErrorThreshold } = require('../lib/prefetch');
  // Accepted (not unknown-rejected) and parsed to its numeric budget.
  const out = parseArgs(['node', 'prefetch.js', '--max-errors', '5']);
  assert.equal(out.maxErrors, 5);
  assert.equal(out._argError, undefined);
  // A percentage form round-trips through parseErrorThreshold.
  assert.equal(parseErrorThreshold('5%'), '5%');
  // A malformed value is a usage error, not a silent unbounded tolerance.
  const bad = parseArgs(['node', 'prefetch.js', '--max-errors', 'notanumber']);
  assert.ok(bad._argError, 'a malformed --max-errors must record _argError');
});
