'use strict';

/**
 * tests/j-readme-image-paths.test.js
 *
 * README.md ships in the npm tarball and renders on the npm package page, but
 * public/ is not in package.json files[], so any image referenced by a
 * tarball-relative public/ path is a broken image once installed. This pins
 * every README <img>/srcset reference to an absolute (http) URL so the package
 * page render always resolves.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function imageRefs() {
  const refs = [];
  const re = /(?:src|srcset)\s*=\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(README)) !== null) refs.push(m[1]);
  return refs;
}

test('public/ is not in the npm files[] allowlist (assumption this gate guards)', () => {
  assert.ok(Array.isArray(pkg.files));
  assert.ok(
    !pkg.files.includes('public/') && !pkg.files.includes('public'),
    'public/ is now shipped — if so this image-path gate can be relaxed'
  );
});

test('README image references do not use tarball-excluded public/ relative paths', () => {
  const offenders = imageRefs().filter((r) => /(^|\/)public\//.test(r) && !/^https?:\/\//.test(r));
  assert.deepEqual(
    offenders,
    [],
    `README image refs point at tarball-excluded public/ paths: ${offenders.join(', ')}`
  );
});

test('README logo images resolve to absolute http URLs', () => {
  const logoRefs = imageRefs().filter((r) => /logo/.test(r));
  assert.ok(logoRefs.length >= 1, 'expected at least one logo image reference');
  for (const r of logoRefs) {
    assert.match(r, /^https?:\/\//, `logo image ref is not an absolute URL: ${r}`);
  }
});
