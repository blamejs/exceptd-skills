'use strict';

/**
 * Regression for the exported deepMerge utility (lib/playbook-runner.js
 * _deepMerge). deepMerge powers phase-override resolution; its `override`
 * comes from the Ed25519-signed catalog today, but the function is exported
 * and is the classic prototype-pollution-utility shape — a `__proto__` /
 * `constructor` / `prototype` key in the merged object must be skipped, never
 * assigned (an `out['__proto__'] = …` would invoke the prototype-rebinding
 * setter). These tests pin the guard so a future refactor can't drop it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));
const deepMerge = runner._deepMerge;

test('deepMerge does not pollute Object.prototype through a __proto__ key', () => {
  // JSON.parse keeps __proto__ as an OWN enumerable data property, so it
  // reaches Object.entries() — exactly the operator-input shape to defend.
  const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
  const out = deepMerge({ a: 1 }, malicious);
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(out.a, 1, 'unrelated keys still merge');
  assert.equal(Object.prototype.hasOwnProperty.call(out, '__proto__'), false,
    '__proto__ is skipped, not copied as an own property either');
});

test('deepMerge skips constructor and prototype keys', () => {
  const out = deepMerge({}, JSON.parse('{"constructor": {"x": 1}, "prototype": {"y": 2}}'));
  assert.equal(typeof out.constructor, 'function',
    'constructor resolves to the Object constructor, not an overwritten object');
  assert.equal(Object.prototype.hasOwnProperty.call(out, 'prototype'), false);
});

test('deepMerge still deep-merges ordinary nested keys', () => {
  const out = deepMerge({ a: { b: 1 }, c: 3 }, { a: { d: 2 } });
  assert.deepEqual(out, { a: { b: 1, d: 2 }, c: 3 });
});
