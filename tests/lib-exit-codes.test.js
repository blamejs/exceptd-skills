'use strict';

/**
 * Unit coverage for lib/exit-codes.js.
 *
 * EXIT_CODES is the canonical map of per-verb exit codes. The map MUST:
 *   - export every code the CLI table in printGlobalHelp() advertises
 *     (0..9, ten total entries);
 *   - never duplicate a numeric code (two semantic names sharing one
 *     code is the v0.12.23 collision class — RAN_NO_EVIDENCE / SESSION_ID_COLLISION
 *     both at 3 prior to v0.12.24);
 *   - expose a frozen object so a stray `EXIT_CODES.BLOCKED = 99`
 *     reassignment at runtime cannot drift the contract.
 *
 * listExitCodes() is the data feed for `exceptd doctor --exit-codes`. Each
 * entry must carry { code, name, summary } so the human-readable dump can
 * render without follow-on lookups.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { EXIT_CODES, EXIT_CODE_DESCRIPTIONS, exitCodeName, listExitCodes } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

test('EXIT_CODES exposes the canonical exit-code constants', () => {
  assert.equal(EXIT_CODES.SUCCESS, 0, 'SUCCESS pinned to 0');
  assert.equal(EXIT_CODES.GENERIC_FAILURE, 1, 'GENERIC_FAILURE pinned to 1');
  assert.equal(EXIT_CODES.DETECTED_ESCALATE, 2, 'DETECTED_ESCALATE pinned to 2');
  assert.equal(EXIT_CODES.RAN_NO_EVIDENCE, 3, 'RAN_NO_EVIDENCE pinned to 3');
  assert.equal(EXIT_CODES.BLOCKED, 4, 'BLOCKED pinned to 4');
  assert.equal(EXIT_CODES.JURISDICTION_CLOCK_STARTED, 5, 'JURISDICTION_CLOCK_STARTED pinned to 5');
  assert.equal(EXIT_CODES.TAMPERED, 6, 'TAMPERED pinned to 6');
  assert.equal(EXIT_CODES.SESSION_ID_COLLISION, 7, 'SESSION_ID_COLLISION pinned to 7');
  assert.equal(EXIT_CODES.LOCK_CONTENTION, 8, 'LOCK_CONTENTION pinned to 8');
  assert.equal(EXIT_CODES.STORAGE_EXHAUSTED, 9, 'STORAGE_EXHAUSTED pinned to 9');
});

test('EXIT_CODES is frozen — runtime mutation must not silently succeed', () => {
  // Object.freeze() makes assignment a silent no-op (strict mode would
  // throw, but the module is loaded under the test's strict mode and the
  // assignment occurs inside this function's scope). Either outcome —
  // throw or no-op — must leave the original value intact.
  let threw = false;
  try { EXIT_CODES.BLOCKED = 99; } catch { threw = true; }
  // After the (failed) write, the canonical value still holds.
  assert.equal(EXIT_CODES.BLOCKED, 4,
    `EXIT_CODES.BLOCKED must remain 4 even after attempted reassignment (threw=${threw})`);
});

test('listExitCodes() returns exactly 11 entries with name + summary', () => {
  // Cycle 9 B1 (v0.12.29): added UNKNOWN_COMMAND (10) to split dispatcher
  // refusals from DETECTED_ESCALATE (2). When new exit codes land, bump
  // this count to match — the explicit-count assertion is the contract
  // that catches accidental additions.
  const list = listExitCodes();
  assert.ok(Array.isArray(list), 'listExitCodes returns an array');
  assert.equal(list.length, 11, `expected 11 exit-code entries; got ${list.length}`);
  for (const entry of list) {
    assert.equal(typeof entry.code, 'number', 'each entry has numeric code');
    assert.equal(typeof entry.name, 'string', 'each entry has string name');
    assert.equal(typeof entry.summary, 'string', 'each entry has string summary');
    assert.ok(entry.name.length > 0, `name must be non-empty for code ${entry.code}`);
    assert.ok(entry.summary.length > 0, `summary must be non-empty for code ${entry.code}`);
  }
});

test('listExitCodes() never duplicates a code (v0.12.23 collision class)', () => {
  const codes = listExitCodes().map((e) => e.code);
  const seen = new Set();
  for (const c of codes) {
    assert.ok(!seen.has(c), `duplicate exit code detected: ${c}. Two semantic names sharing one code is the regression class v0.12.24 closed.`);
    seen.add(c);
  }
});

test('listExitCodes() never duplicates a name (single name per semantic class)', () => {
  const names = listExitCodes().map((e) => e.name);
  const seen = new Set();
  for (const n of names) {
    assert.ok(!seen.has(n), `duplicate exit-code name detected: ${n}`);
    seen.add(n);
  }
});

test('exitCodeName() returns the canonical name for known codes', () => {
  assert.equal(exitCodeName(0), 'SUCCESS');
  assert.equal(exitCodeName(8), 'LOCK_CONTENTION');
  assert.equal(exitCodeName(9), 'STORAGE_EXHAUSTED');
});

test('exitCodeName() returns UNKNOWN for codes not in the table', () => {
  // 137 (128 + SIGKILL) is a node-runtime exit not in the canonical table.
  assert.equal(exitCodeName(137), 'UNKNOWN');
  assert.equal(exitCodeName(255), 'UNKNOWN');
  assert.equal(exitCodeName(-1), 'UNKNOWN');
});

test('EXIT_CODE_DESCRIPTIONS keys match the EXIT_CODES values exactly', () => {
  // Ensures the two structures stay in sync — every EXIT_CODES value has a
  // descriptor and vice versa. A future addition that drops one would
  // leave operators with a code that has no help-text entry.
  const codeValues = Object.values(EXIT_CODES).map(Number).sort((a, b) => a - b);
  const descKeys = Object.keys(EXIT_CODE_DESCRIPTIONS).map(Number).sort((a, b) => a - b);
  assert.deepEqual(descKeys, codeValues,
    'EXIT_CODE_DESCRIPTIONS keys must equal EXIT_CODES values');
});
