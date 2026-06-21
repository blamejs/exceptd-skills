'use strict';

/**
 * tests/check-test-count.test.js
 *
 * Subject coverage for scripts/check-test-count.js — the no-shrinkage
 * test-count gate. countTests() strips comments/strings before counting and
 * recognizes both test() and it() declarations (skip/only variants), while
 * refusing describe() containers and any test( token that only appears inside
 * a string or block comment.
 *
 * Fixtures live in isolated mkdtemp dirs; the repo tree is never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const { countTests } = require(path.join(ROOT, 'scripts', 'check-test-count.js'));

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egates-'));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, 'utf8');
  return { dir, p };
}

// --------------------------------------------------------------------------
// check-test-count counts both test() and it()
// --------------------------------------------------------------------------

test('#22 countTests counts 3 it() + 2 test() declarations as 5', () => {
  const src = [
    "const { test, it } = require('node:test');",
    "it('a', () => {});",
    "it.skip('b', () => {});",
    "it.only('c', () => {});",
    "test('d', () => {});",
    "test('e', () => {});",
  ].join('\n');
  const { dir, p } = tmpFile('count-it.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(typeof n, 'number');
    assert.equal(n, 5);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 an it() declaration inside a /* */ block is NOT counted (comment-strip still applies)', () => {
  const src = [
    "/* it('x', () => {}) */",
    "/*",
    "  it('y', () => {});",
    "*/",
  ].join('\n');
  const { dir, p } = tmpFile('count-it-comment.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(n, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 describe() is NOT counted as a test (containers, not tests)', () => {
  const src = [
    "describe('group', () => {",
    "  it('inner', () => {});",
    "});",
  ].join('\n');
  const { dir, p } = tmpFile('count-describe.test.js', src);
  try {
    // one it() inside the describe block; the describe itself does not count.
    const n = countTests(p);
    assert.equal(n, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('#22 a test( mentioned inside a string is NOT counted', () => {
  const src = [
    "console.log('run the test( harness');",
    "it('real', () => {});",
  ].join('\n');
  const { dir, p } = tmpFile('count-string.test.js', src);
  try {
    const n = countTests(p);
    assert.equal(n, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// --------------------------------------------------------------------------
// check-test-count CLI: structured-JSON envelope on the live test set.
// --------------------------------------------------------------------------

test('check-test-count.js exists and emits structured JSON', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-test-count.js'), '--json'], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `gate must pass on current state; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'gate must emit JSON when --json passed');
  assert.equal(body.verb, 'check-test-count');
  assert.equal(typeof body.observed, 'number');
  assert.equal(typeof body.baseline, 'number');
  assert.equal(typeof body.delta, 'number');
  assert.ok(['ok', 'grew_beyond_threshold_consider_bump'].includes(body.status),
    `status must be ok or grew_beyond_threshold; got ${body.status}`);
});
