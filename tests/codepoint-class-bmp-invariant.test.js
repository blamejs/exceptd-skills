'use strict';

/**
 * tests/codepoint-class-bmp-invariant.test.js
 *
 * The vendored codepoint compiler escapes each table endpoint with hex4(),
 * which emits a fixed-width "\\uXXXX" (exactly four hex digits). That escape
 * only addresses the Basic Multilingual Plane. An astral codepoint (> U+FFFF)
 * produces five hex digits, which a non-`u`-flag char class reads as a BMP
 * character followed by a literal digit — silently wrong range membership.
 *
 * These tests pin the encoding contract and the table-content invariant the
 * compiler depends on, so adding an astral codepoint to any classification
 * table fails loudly here instead of mis-compiling a regex at runtime.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const cc = require(path.join(__dirname, '..', 'vendor', 'blamejs', 'codepoint-class.js'));

function endpoints(table) {
  const out = [];
  table.forEach((r) => {
    if (Array.isArray(r)) { out.push(r[0], r[1]); } else { out.push(r); }
  });
  return out;
}

test('every classification-table endpoint is in the BMP (hex4 is 4-digit-only)', () => {
  const named = {
    BIDI_RANGES: cc.BIDI_RANGES,
    C0_CTRL_RANGES: cc.C0_CTRL_RANGES,
    ZERO_WIDTH_RANGES: cc.ZERO_WIDTH_RANGES,
  };
  for (const [name, table] of Object.entries(named)) {
    for (const ep of endpoints(table)) {
      assert.ok(
        ep <= 0xFFFF,
        `${name} endpoint U+${ep.toString(16).toUpperCase()} exceeds U+FFFF; ` +
          'hex4() emits exactly 4 hex digits, so an astral endpoint mis-compiles ' +
          'into the regex char class (use \\u{...} + the u flag if astral coverage is needed)',
      );
    }
  }
});

test('every SCRIPT_RANGES endpoint is in the BMP', () => {
  const sr = cc.SCRIPT_RANGES;
  for (const k of Object.keys(sr)) {
    for (const ep of endpoints(sr[k])) {
      assert.ok(
        ep <= 0xFFFF,
        `SCRIPT_RANGES.${k} endpoint U+${ep.toString(16).toUpperCase()} exceeds U+FFFF`,
      );
    }
  }
});

test('hex4 emits exactly four hex digits for BMP input', () => {
  assert.equal(cc.hex4(0x0000), '\\u0000');
  assert.equal(cc.hex4(0x200E), '\\u200E');
  assert.equal(cc.hex4(0xFEFF), '\\uFEFF');
});

test('hex4 over-emits for astral input — documents the latent encoding limit', () => {
  // An astral codepoint produces five hex digits. In a non-u-flag char class
  // "[\\u1F600]" is parsed as the BMP char U+1F60 plus a literal "0", NOT the
  // intended U+1F600. This assertion pins the current (incorrect-for-astral)
  // behavior so any future hex4 change (e.g. a \u{...} upgrade) updates it
  // deliberately rather than silently.
  assert.equal(cc.hex4(0x1F600), '\\u1F600');
  const reSource = '[' + cc.hex4(0x1F600) + ']';
  const re = new RegExp(reSource);
  assert.equal(re.test(String.fromCharCode(0x1F60)), true, 'mis-compiled class matches the BMP char U+1F60');
  assert.equal(re.test('0'), true, 'mis-compiled class matches the literal trailing digit');
  assert.equal(re.test(String.fromCodePoint(0x1F600)), false, 'mis-compiled class does NOT match the intended astral codepoint');
});
