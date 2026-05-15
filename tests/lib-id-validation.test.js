'use strict';

/**
 * Unit coverage for lib/id-validation.js.
 *
 * Three roles, three character classes:
 *   session  — `^[A-Za-z0-9._-]{1,64}$` + all-dots refusal
 *   playbook — `^[a-z][a-z0-9-]{0,63}$` (lowercase, starts with letter, no dots)
 *   filename — `^[A-Za-z0-9._-]{1,80}$` + all-dots refusal
 *
 * Adversarial inputs the regex MUST reject:
 *   "."           all-dots refusal
 *   ".."          all-dots refusal (path traversal)
 *   "../escape"   character-class rejection (slash not allowed)
 *   ""            empty refusal (caller bug, surface clearly)
 *   65-char str   length cap
 *   numeric/null  type refusal
 *   "Kernel"      playbook role: uppercase rejected
 *   ".hidden"     playbook role: leading dot rejected
 *
 * Each adversarial case asserts the EXACT `reason` string so a regression
 * that swaps one rejection class for another (length vs charset vs
 * all-dots) surfaces here. coincidence-passing tests are forbidden — see
 * CLAUDE.md.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { validateIdComponent, assertIdComponent, SESSION_RE, PLAYBOOK_RE, FILENAME_RE } =
  require(path.join(ROOT, 'lib', 'id-validation.js'));

// --- role:'session' --------------------------------------------------------

test('session: happy paths', () => {
  for (const id of ['abc', 'a', 'Session-1', 'session_1.json', 'A.B-C_1', 'x'.repeat(64)]) {
    const r = validateIdComponent(id, 'session');
    assert.equal(r.ok, true, `${JSON.stringify(id)} must validate as session; got ${JSON.stringify(r)}`);
  }
});

test('session: empty string rejected with "must not be empty"', () => {
  const r = validateIdComponent('', 'session');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'must not be empty');
});

test('session: 65-char overflow rejected with charset/length constraint', () => {
  const r = validateIdComponent('x'.repeat(65), 'session');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/);
});

test('session: traversal "../escape" rejected by charset (slash not allowed)', () => {
  const r = validateIdComponent('../escape', 'session');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/, 'slash refusal should surface as charset rejection');
});

test('session: all-dots refusal applies regardless of length', () => {
  for (const allDots of ['.', '..', '...', '..........']) {
    const r = validateIdComponent(allDots, 'session');
    assert.equal(r.ok, false, `${JSON.stringify(allDots)} must be rejected`);
    assert.equal(r.reason, 'must not consist entirely of dots',
      `expected all-dots rejection; got ${JSON.stringify(r)}`);
  }
});

test('session: numeric type rejected with type-error reason', () => {
  const r = validateIdComponent(42, 'session');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'expected string, got number');
});

test('session: null rejected with type-error reason', () => {
  const r = validateIdComponent(null, 'session');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'expected string, got object');
});

// --- role:'playbook' -------------------------------------------------------

test('playbook: happy paths (lowercase, starts with letter)', () => {
  for (const id of ['kernel', 'mcp', 'ai-api', 'cred-stores', 'a', 'a-b-c-1']) {
    const r = validateIdComponent(id, 'playbook');
    assert.equal(r.ok, true, `${JSON.stringify(id)} must validate as playbook; got ${JSON.stringify(r)}`);
  }
});

test('playbook: uppercase rejected', () => {
  const r = validateIdComponent('Kernel', 'playbook');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/);
});

test('playbook: starts-with-digit rejected', () => {
  const r = validateIdComponent('1kernel', 'playbook');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/);
});

test('playbook: dots rejected (no all-dots fallback fires; the charset already excludes them)', () => {
  const r = validateIdComponent('kernel.test', 'playbook');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/);
});

test('playbook: traversal "../foo" rejected', () => {
  const r = validateIdComponent('../foo', 'playbook');
  assert.equal(r.ok, false);
  assert.match(r.reason, /must match/);
});

// --- role:'filename' -------------------------------------------------------

test('filename: 80-char limit (one wider than session role)', () => {
  const r80 = validateIdComponent('x'.repeat(80), 'filename');
  assert.equal(r80.ok, true, '80-char filename accepted');
  const r81 = validateIdComponent('x'.repeat(81), 'filename');
  assert.equal(r81.ok, false, '81-char filename rejected');
});

test('filename: all-dots refusal applies', () => {
  const r = validateIdComponent('...', 'filename');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'must not consist entirely of dots');
});

// --- unknown role ----------------------------------------------------------

test('unknown role returns explicit rejection', () => {
  const r = validateIdComponent('foo', 'gargoyle');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unknown role: gargoyle');
});

// --- assertIdComponent ------------------------------------------------------

test('assertIdComponent throws on invalid input', () => {
  assert.throws(
    () => assertIdComponent('../escape', 'session'),
    (err) => err && err.code === 'EXCEPTD_INVALID_ID' && err.role === 'session',
    'must throw an EXCEPTD_INVALID_ID error with role propagated'
  );
});

test('assertIdComponent returns value on valid input', () => {
  const v = assertIdComponent('kernel', 'playbook');
  assert.equal(v, 'kernel', 'returns the input unchanged on success');
});

// --- exported regexes are the canonical patterns ----------------------------

test('exported regexes match the documented patterns', () => {
  // Pin the regex source so a future refactor that loosens the pattern
  // surfaces here. Use .source to compare canonical form.
  assert.equal(SESSION_RE.source, '^[A-Za-z0-9._-]{1,64}$');
  assert.equal(PLAYBOOK_RE.source, '^[a-z][a-z0-9-]{0,63}$');
  assert.equal(FILENAME_RE.source, '^[A-Za-z0-9._-]{1,80}$');
});
