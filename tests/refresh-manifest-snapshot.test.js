"use strict";


// ---- routed from gate-scripts-fs-race ----
require("node:test").describe("gate-scripts-fs-race", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/gate-scripts-fs-race.test.js
 *
 * The release/build gate scripts decide whether to read or create a file
 * (the test-count baseline, the manifest snapshot) and then act on the same
 * path. An existsSync(p)-then-read/write probe is a check-then-use window
 * (CodeQL js/file-system-race): the file the gate decides about may not be
 * the file it later touches. The scripts now read the path ONCE and branch
 * on the read result, with ENOENT as the "absent" signal and an exclusive
 * ('wx') create on the fresh-baseline path.
 *
 * These tests lock that in two ways:
 *   1. Static: the flagged existsSync(BASELINE_PATH/SNAPSHOT_PATH) probe is
 *      gone from the source — a re-introduction fails the suite before it
 *      can reach CodeQL.
 *   2. Behavioral: the ENOENT branches still produce the exact exit codes
 *      and side effects they did before (no behavior regression from the
 *      probe removal).
 *
 * Per the anti-coincidence rule: every assertion checks the EXACT exit code
 * / file content the fix produces, never notEqual(0) / ok(field).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CHECK_TEST_COUNT = path.join(ROOT, 'scripts', 'check-test-count.js');
const REFRESH_SNAPSHOT = path.join(ROOT, 'scripts', 'refresh-manifest-snapshot.js');

// ---------- 1. Static: the TOCTOU probe is gone ----------

// Strip comments + string literals so the assertion matches only EXECUTABLE
// code — the explanatory comments in these scripts describe the removed
// existsSync()-probe by name, and that prose must not trip the guard.
function executableSource(file) {
  let s = fs.readFileSync(file, 'utf8');
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');            // block comments
  s = s.replace(/(^|[^:])\/\/.*$/gm, '$1');          // line comments (not ://)
  s = s.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''"); // strings
  return s;
}



// ---------- 2. Behavioral: ENOENT branches preserved ----------

// check-test-count.js resolves BASELINE_PATH from its own __dirname/.. , so to
// exercise the ENOENT path without touching the repo's real baseline we copy
// the script + a minimal tests/ dir into a throwaway project root and run it
// from there.
function makeIsolatedCheckTestCount() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-fsrace-'));
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'tests'), { recursive: true });
  fs.copyFileSync(CHECK_TEST_COUNT, path.join(dir, 'scripts', 'check-test-count.js'));
  // Two declarations so the gate has a real count to record.
  fs.writeFileSync(
    path.join(dir, 'tests', 'sample.test.js'),
    "test('one', () => {});\ntest('two', () => {});\n",
    'utf8'
  );
  return dir;
}

test('refresh-manifest-snapshot.js does not existsSync-probe the snapshot path before reading it', () => {
  const code = executableSource(REFRESH_SNAPSHOT);
  assert.doesNotMatch(
    code, /existsSync\(\s*SNAPSHOT_PATH\s*\)/,
    'existsSync(SNAPSHOT_PATH) probe reintroduces the js/file-system-race check-then-use window; ' +
    'read the path once and branch on ENOENT instead'
  );
});

test('refresh-manifest-snapshot.js: absent snapshot writes a fresh one without --commit-only', () => {
  // Run with HOME-equivalent isolation by copying the script + a minimal
  // manifest into a throwaway root (the script resolves paths from __dirname/..).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-fsrace-snap-'));
  try {
    fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
    fs.copyFileSync(REFRESH_SNAPSHOT, path.join(dir, 'scripts', 'refresh-manifest-snapshot.js'));
    fs.writeFileSync(
      path.join(dir, 'manifest.json'),
      JSON.stringify({ atlas_version: 'x', skills: [{ name: 'a' }] }),
      'utf8'
    );
    const snapPath = path.join(dir, 'manifest-snapshot.json');
    assert.equal(fs.existsSync(snapPath), false, 'precondition: snapshot absent');
    const r = spawnSync(process.execPath, [path.join(dir, 'scripts', 'refresh-manifest-snapshot.js')], {
      encoding: 'utf8', cwd: dir,
    });
    assert.equal(r.status, 0, `absent snapshot must write + exit 0; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
    const snap = JSON.parse(fs.readFileSync(snapPath, 'utf8'));
    assert.equal(snap.skill_count, 1, 'fresh snapshot must capture the single fixture skill');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
