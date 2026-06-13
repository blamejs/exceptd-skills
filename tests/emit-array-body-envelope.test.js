'use strict';

/**
 * Regression: emit() must not spread an array body into an object. Pre-fix the
 * envelope-injection branch (`!('ok' in obj)`) matched arrays — `typeof [] ===
 * "object"` and `'ok' in []` is false — so an array body became
 * { "0":v0, "1":v1, …, ok:true }: numeric string keys plus a spurious envelope.
 * Array bodies (SARIF results / OpenVEX statements) must pass through verbatim.
 * The object happy path and the ok:false exit-code contract must be unchanged.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { _emit: emit } = require('../bin/exceptd.js');

function captureEmit(fn) {
  const out = [];
  const orig = process.stdout.write;
  process.stdout.write = (s) => { out.push(s); return true; };
  const savedExit = process.exitCode;
  try { fn(); } finally { process.stdout.write = orig; }
  const restoredExit = process.exitCode;
  // Reset so a captured ok:false body doesn't leak a non-zero exit to the runner.
  process.exitCode = savedExit;
  return { text: out.join(''), exitCode: restoredExit };
}

test('emit([...]) passes the array through verbatim — no numeric-key object, no injected ok', () => {
  const { text } = captureEmit(() => emit([1, 2, 3]));
  const parsed = JSON.parse(text.trim());
  // Pre-fix, spreading the array into an object literal produced
  // {"0":1,"1":2,"2":3,"ok":true} — a plain object, NOT an array. The
  // discriminator is therefore Array.isArray + the absence of the ok envelope.
  assert.ok(Array.isArray(parsed), 'array body must serialize back to an array, not a numeric-key object');
  assert.deepEqual(parsed, [1, 2, 3], 'array elements must be preserved in order');
  assert.equal(parsed.ok, undefined, 'no ok envelope should be injected into an array body');
});

test('emit({...}) still injects the ok:true envelope on the object happy path', () => {
  const { text } = captureEmit(() => emit({ verb: 'x' }));
  const parsed = JSON.parse(text.trim());
  assert.deepEqual(parsed, { ok: true, verb: 'x' }, 'object body must gain ok:true and keep its fields');
});

test('emit({ok:false}) sets exitCode=1 and does not double-wrap', () => {
  const before = process.exitCode;
  process.exitCode = 0;
  const { text, exitCode } = captureEmit(() => emit({ ok: false, error: 'e' }));
  const parsed = JSON.parse(text.trim());
  assert.deepEqual(parsed, { ok: false, error: 'e' }, 'ok:false body must not be re-wrapped');
  assert.equal(exitCode, 1, 'ok:false must set process.exitCode = 1');
  process.exitCode = before;
});
