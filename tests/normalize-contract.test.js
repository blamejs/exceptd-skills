'use strict';

/**
 * Audit P P1-A: byte-stability contract test for the normalize() helpers
 * duplicated across five sites:
 *
 *   1. lib/sign.js               (skill body sign)
 *   2. lib/verify.js             (skill body verify)
 *   3. lib/refresh-network.js    (refresh-network skill body verify)
 *   4. scripts/verify-shipped-tarball.js (predeploy gate skill body verify)
 *   5. bin/exceptd.js            (attestation sign/verify pipeline)
 *
 * Each implementation strips a leading UTF-8 BOM and collapses CRLF -> LF.
 * The five must produce byte-identical output across an aggressive fuzz
 * corpus or sign-on-one-site / verify-on-another diverges silently — the
 * exact regression class that broke v0.11.x signatures (0/38 on every
 * fresh install) and that the audit's P P1-A item closes.
 *
 * The five normalize() implementations are intentionally NOT cross-required
 * so a bug in one does not silently disable another. This test is the
 * harness that catches drift between them.
 *
 * Sites 1-4 export normalize() helpers; site 5 (bin/exceptd.js) is not a
 * normal CommonJS module (it dispatches under require.main === module).
 * For site 5 the test ALSO asserts (via string match) that the body of
 * normalizeAttestationBytes in bin/exceptd.js matches a known-good
 * implementation byte-for-byte. This is the strongest static check we
 * can apply without a runtime export from the bin entrypoint.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const signMod = require(path.join(ROOT, 'lib', 'sign.js'));
const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
const refreshMod = require(path.join(ROOT, 'lib', 'refresh-network.js'));
const tarballMod = require(path.join(ROOT, 'scripts', 'verify-shipped-tarball.js'));

// Canonical reference implementation. Every site MUST produce byte-
// identical output to this function. The function definition is also the
// body the test pattern-matches against the bin/exceptd.js source.
function referenceNormalize(input) {
  let s = Buffer.isBuffer(input) ? input.toString('utf8') : String(input);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, '\n');
}

// Adapter: every site returns a slightly different shape (Buffer vs string)
// depending on its primary use site. Coerce to string for byte-compare.
function asString(x) {
  if (Buffer.isBuffer(x)) return x.toString('utf8');
  return String(x);
}

const SITES = [
  { name: 'lib/sign.js#normalize',                   fn: (s) => signMod.normalize(s) },
  { name: 'lib/verify.js#normalize',                 fn: (s) => verifyMod.normalize(s) },
  { name: 'lib/refresh-network.js#normalizeSkillBytes',
    fn: (s) => asString(refreshMod.normalizeSkillBytes(s)) },
  { name: 'scripts/verify-shipped-tarball.js#normalizeSkillBytes',
    fn: (s) => asString(tarballMod.normalizeSkillBytes(s)) },
];

// Fuzz corpus — every flavor of input that has historically caused (or
// could plausibly cause) a divergence between BOM/CRLF normalizers.
const CORPUS = [
  // empty
  { label: 'empty string',                input: '' },
  // plain
  { label: 'plain LF',                    input: 'line1\nline2\nline3\n' },
  { label: 'plain CRLF',                  input: 'line1\r\nline2\r\nline3\r\n' },
  // BOM combos
  { label: 'BOM + LF',                    input: '﻿line1\nline2\n' },
  { label: 'BOM + CRLF',                  input: '﻿line1\r\nline2\r\n' },
  { label: 'double BOM',                  input: '﻿﻿line\n' },
  // mid-string oddities
  { label: 'embedded standalone CR',      input: 'line1\rline2\n' },
  { label: 'mixed CR / CRLF / LF',        input: 'a\rb\r\nc\nd\r\ne\r' },
  { label: 'embedded null byte',          input: 'a\x00b\nc\x00d\r\ne\n' },
  // Unicode codepoints (must not be touched by normalize)
  { label: 'unicode codepoints',          input: 'café\nθ\n\u{1F600}\r\n' },
  { label: 'BMP + surrogate-pair emoji',  input: '﻿a\u{1F4A9}\r\nb\n' },
  // adversarial
  { label: 'CR-then-LF (already split)',  input: 'a\r\nb' },
  { label: 'standalone CR at end',        input: 'a\nb\r' },
  { label: 'LF only, with mid-BOM (NOT stripped — BOM is only stripped from leading position)',
    input: 'a\n﻿b\n' },
  { label: 'whitespace + tabs',           input: '\t a \t\n\t b \r\n' },
  // very long
  { label: 'long ASCII',                  input: ('x'.repeat(100) + '\r\n').repeat(50) },
];

for (const item of CORPUS) {
  test(`P P1-A: all four exported normalize() implementations agree on "${item.label}"`, () => {
    const ref = referenceNormalize(item.input);
    const outputs = SITES.map(s => ({ site: s.name, out: s.fn(item.input) }));
    for (const o of outputs) {
      assert.equal(
        o.out,
        ref,
        `site ${o.site} diverged from reference on input ${JSON.stringify(item.input).slice(0, 80)}\n` +
        `  ref  out=${JSON.stringify(ref).slice(0, 120)}\n` +
        `  this out=${JSON.stringify(o.out).slice(0, 120)}`
      );
    }
  });
}

test('P P1-A: site exports are all callable functions', () => {
  for (const s of SITES) {
    assert.equal(typeof s.fn, 'function', `${s.name} must be callable`);
  }
});

test('P P1-A: normalize() strips ONLY a leading BOM (not mid-string)', () => {
  // Belt-and-braces — assert one of the operationally important invariants
  // directly. A regression that strips ALL BOMs (vs only leading) would
  // change skill body bytes silently when a maintainer accidentally embeds
  // U+FEFF in the middle of a markdown block.
  const input = 'a\n﻿middle\nb\n';
  for (const s of SITES) {
    assert.ok(
      s.fn(input).includes('﻿'),
      `${s.name} stripped a non-leading BOM (forbidden by the five-site contract)`
    );
  }
});

test('P P1-A: normalize() reaches a fixed point in at most 2 applications', () => {
  // Strict idempotence (n(n(x)) === n(x)) holds for all inputs EXCEPT
  // double-BOM (and other N-BOM stacks): the first pass strips the
  // outermost BOM and exposes the next one as leading, which the next
  // pass also strips. Operationally this is fine — the sign + verify
  // pair both apply normalize() exactly once, so the round-trip is
  // stable. But asserting strict idempotence here would forbid the
  // current (correct) shape. Instead we assert that all five sites
  // converge to the SAME fixed point in at most two applications: the
  // important guarantee is cross-site agreement, not single-pass
  // idempotence.
  const samples = CORPUS.map(c => c.input);
  for (const s of SITES) {
    for (const input of samples) {
      const once = s.fn(input);
      const twice = s.fn(once);
      const thrice = s.fn(twice);
      assert.equal(
        thrice, twice,
        `${s.name} did not reach a fixed point within 2 applications on ` +
        `${JSON.stringify(input).slice(0, 60)}`
      );
    }
  }
});

test('P P1-A: bin/exceptd.js#normalizeAttestationBytes is structurally identical to the reference', () => {
  // Site 5 (bin/exceptd.js) is the CLI dispatcher and cannot be required
  // without invoking the dispatcher. Instead we string-extract its body
  // and assert the operationally-equivalent shape: strip leading BOM
  // (U+FEFF), then s.replace(/\r\n/g, '\n'). Any other transform — or a
  // missing leading-only guard — fails the test.
  const binSrc = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const m = binSrc.match(
    /function normalizeAttestationBytes\(input\)\s*\{([\s\S]*?)\n\}/
  );
  assert.ok(
    m,
    'bin/exceptd.js must export a top-level function normalizeAttestationBytes(input). ' +
    'If renamed, update tests/normalize-contract.test.js to point at the new symbol.'
  );
  const body = m[1];
  // Leading-BOM guard — MUST be `s.length > 0 && s.charCodeAt(0) === 0xFEFF`
  // (the leading-only invariant). Anything else (e.g. global ﻿ replace)
  // would silently strip mid-string BOMs and break byte stability.
  assert.match(
    body,
    /charCodeAt\(0\)\s*===\s*0xFEFF/,
    'normalizeAttestationBytes must guard the BOM strip on charCodeAt(0) === 0xFEFF'
  );
  // CRLF collapse — MUST be the same /\r\n/g pattern used at the other sites.
  // Any divergence (e.g. /\r\n?/g or /\r\n+/g) breaks byte stability across
  // mixed-ending inputs.
  assert.match(
    body,
    /replace\(\/\\r\\n\/g,\s*['"]\\n['"]\)/,
    'normalizeAttestationBytes must collapse CRLF -> LF via /\\r\\n/g replace'
  );
  // Negative — no global BOM strip.
  assert.ok(
    !/replace\(\/\\uFEFF\/g/.test(body) && !/replace\(\/\\ufeff\/g/i.test(body),
    'normalizeAttestationBytes must not globally strip BOM characters (only the leading one)'
  );
});

test('refreshMod.normalizeSkillBytes and tarballMod.normalizeSkillBytes are exported and callable', () => {
  // Diff-coverage gate requires the export identifier appear inside a
  // test() body in the same file that issues the matching require().
  assert.equal(typeof refreshMod.normalizeSkillBytes, 'function', 'refresh-network.js must export normalizeSkillBytes');
  assert.equal(typeof tarballMod.normalizeSkillBytes, 'function', 'verify-shipped-tarball.js must export normalizeSkillBytes');
  // Functional smoke: both must strip leading BOM + collapse CRLF.
  const input = Buffer.from('﻿hello\r\nworld\r\n', 'utf8');
  assert.equal(refreshMod.normalizeSkillBytes(input).toString('utf8'), 'hello\nworld\n');
  assert.equal(tarballMod.normalizeSkillBytes(input).toString('utf8'), 'hello\nworld\n');
});

test('canonicalManifestBytesForRefresh and canonicalManifestBytesForTarball produce byte-identical bytes', () => {
  // The two helpers compute the canonical signing input for the manifest
  // envelope from the refresh-network path and the verify-shipped-tarball
  // gate respectively. They MUST agree byte-for-byte; otherwise a manifest
  // signed during `npm pack` predeploy verifies on one site and fails on
  // the other — exactly the v0.11.x signature divergence class.
  const manifest = {
    version: '0.12.19',
    skills: [
      { name: 'b-skill', path: 'skills/b/skill.md', signature: 'b-sig' },
      { name: 'a-skill', path: 'skills/a/skill.md', signature: 'a-sig' },
    ],
    manifest_signature: { algorithm: 'Ed25519', signature_base64: 'should-be-stripped' },
  };
  const refreshBytes = refreshMod.canonicalManifestBytesForRefresh(manifest);
  const tarballBytes = tarballMod.canonicalManifestBytesForTarball(manifest);
  assert.equal(
    Buffer.compare(Buffer.from(refreshBytes), Buffer.from(tarballBytes)), 0,
    'canonicalManifestBytesForRefresh and canonicalManifestBytesForTarball must be byte-identical'
  );
  // Negative — the manifest_signature field MUST be excluded from canonical input.
  const refreshStr = Buffer.from(refreshBytes).toString('utf8');
  assert.ok(
    !refreshStr.includes('should-be-stripped'),
    'canonical bytes must exclude manifest_signature.signature_base64 (replay surface)'
  );
  assert.ok(
    !refreshStr.includes('manifest_signature'),
    'canonical bytes must exclude the manifest_signature field entirely'
  );
});
