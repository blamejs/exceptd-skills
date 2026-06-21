'use strict';

/**
 * upstream-check regression suite (lib/upstream-check-cli.js + lib/upstream-check.js).
 *
 * The CLI must catch any unexpected throw and emit one parseable JSON envelope
 * on stdout (exit 0 — offline is not an error), not surface an unhandled
 * rejection with a raw stack trace.
 *
 * Discipline: assert EXACT exit codes (never notEqual(0)); pair every
 * field-presence check with a value/type assertion. The spawned CLI runs with a
 * preload module written into an isolated tempdir so the repo tree is never
 * mutated and the network is never touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const UPSTREAM_CLI = path.join(ROOT, 'lib', 'upstream-check-cli.js');

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function makeIsolatedDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ===================================================================
// upstream-check-cli.js catches unexpected throws -> JSON envelope
// ===================================================================

test('#49 upstream-check-cli emits a parseable ok:false envelope on an unexpected throw (no unhandled rejection)', () => {
  const dir = makeIsolatedDir('k49-');
  try {
    // Preload module that monkeypatches fetchLatestPublished to throw. The throw
    // propagates out of the awaited call into the IIFE; pre-fix that surfaced as
    // an unhandled rejection (raw stack on stderr, non-zero exit). Post-fix the
    // .catch() emits one JSON line on stdout and exits 0.
    const preload = path.join(dir, 'preload.js');
    fs.writeFileSync(
      preload,
      'const u = require(' + JSON.stringify(path.join(ROOT, 'lib', 'upstream-check.js')) + ');\n' +
      'u.fetchLatestPublished = async () => { throw new Error("forced-throw-for-test"); };\n',
    );
    const out = spawnSync(process.execPath, ['-r', preload, UPSTREAM_CLI], { encoding: 'utf8' });
    assert.equal(out.status, 0, `expected exit 0 (offline != error); got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be parseable JSON, never a raw stack trace; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(typeof body.source, 'string');
    assert.equal(body.source, 'upstream-check');
    assert.equal(body.error, 'forced-throw-for-test');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
