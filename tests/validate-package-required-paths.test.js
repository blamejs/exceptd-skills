'use strict';

/**
 * tests/validate-package-required-paths.test.js
 *
 * lib/validate-package.js REQUIRED_PATHS must cover every module that
 * bin/exceptd.js require()s unconditionally at module top — those load on
 * every CLI invocation, so dropping any of them from the publish tarball
 * bricks `node bin/exceptd.js <anything>` with a module-not-found at launch.
 * The packaging gate is the only thing that can catch a files[] allowlist
 * edit that removes such a file, so the list must stay in lockstep with the
 * bin's top-level require graph.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { REQUIRED_PATHS } = require(path.join(ROOT, 'lib', 'validate-package.js'));

// Parse bin/exceptd.js for top-level (brace-depth-0) requires of the form
//   const X = require(path.join(PKG_ROOT, "a", "b.js"));
// returning each as a forward-slash PKG_ROOT-relative path. Requires nested
// inside a function body (lazy loads) are excluded — only the unconditional
// module-top ones brick the CLI at launch.
function topLevelPkgRootRequires() {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const lines = src.split('\n');
  let depth = 0;
  const found = [];
  for (const line of lines) {
    const m = line.match(
      /^(?:const|var|let)\s+.*=\s*require\(path\.join\(PKG_ROOT,\s*("[^"]+"(?:\s*,\s*"[^"]+")*)\s*\)\)/
    );
    if (m && depth === 0) {
      const parts = m[1].match(/"[^"]+"/g).map((s) => s.slice(1, -1));
      found.push(parts.join('/'));
    }
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
  }
  return found;
}

test('REQUIRED_PATHS covers every top-level require() in bin/exceptd.js', () => {
  const requires = topLevelPkgRootRequires();
  // Sanity: the parser must actually find the launch-critical set, or the
  // assertion below would pass vacuously.
  assert.ok(requires.length >= 4,
    `expected >=4 top-level PKG_ROOT requires in bin/exceptd.js, found ${requires.length}: ${requires.join(', ')}`);
  const pinned = new Set(REQUIRED_PATHS);
  const missing = requires.filter((r) => !pinned.has(r));
  assert.deepEqual(missing, [],
    `bin/exceptd.js loads these at module top but they are absent from REQUIRED_PATHS: ${missing.join(', ')}`);
});

test('the four launch-critical bin dependencies are pinned in REQUIRED_PATHS', () => {
  // Explicit floor so a refactor of the parser above can't quietly stop
  // covering the modules the CLI cannot start without.
  for (const f of [
    'lib/exit-codes.js',
    'lib/id-validation.js',
    'lib/flag-suggest.js',
    'vendor/blamejs/codepoint-class.js',
  ]) {
    assert.ok(REQUIRED_PATHS.includes(f), `REQUIRED_PATHS must pin ${f}`);
    // And the file must exist on disk — a REQUIRED_PATHS entry that names a
    // nonexistent file would make the live packaging gate fail outright.
    assert.ok(fs.existsSync(path.join(ROOT, f)), `${f} must exist on disk`);
  }
});
