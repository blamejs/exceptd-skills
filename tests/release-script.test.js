'use strict';

/**
 * tests/release-script.test.js
 *
 * Coverage for scripts/release.js — the phased release orchestrator. The
 * mutating subcommands (prepare/commit/push/merge/tag/release) are NOT
 * exercised here (they push, merge, and publish); this pins the safe
 * surface — help, unknown-subcommand dispatch, exit codes — and asserts the
 * dispatch table + the load-bearing GUARD logic at the source level, so a
 * refactor can't silently drop a phase or weaken the tag guard.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts', 'release.js');
const SRC = fs.readFileSync(SCRIPT, 'utf8');

const SUBCOMMANDS = ['prepare', 'gates', 'commit', 'push', 'watch', 'merge', 'tag', 'release', 'all', 'status'];

function runRelease(args) {
  return spawnSync(process.execPath, [SCRIPT].concat(args || []), {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
  });
}

test('release.js parses and `help` exits 0 listing every subcommand', () => {
  const r = runRelease(['help']);
  assert.equal(r.status, 0, 'help exits 0');
  const out = r.stdout || '';
  assert.match(out, /orchestrated exceptd release flow/, 'prints the banner');
  for (const sub of SUBCOMMANDS) {
    assert.match(out, new RegExp('\\b' + sub + '\\b'), `help lists "${sub}"`);
  }
});

test('release.js with no argument prints help and exits 0', () => {
  const r = runRelease([]);
  assert.equal(r.status, 0, 'no-arg defaults to help, exit 0');
  assert.match(r.stdout || '', /orchestrated exceptd release flow/);
});

test('release.js rejects an unknown subcommand with exit 1', () => {
  const r = runRelease(['definitely-not-a-subcommand']);
  assert.equal(r.status, 1, 'unknown subcommand exits exactly 1');
  assert.match((r.stdout || '') + (r.stderr || ''), /unknown subcommand/, 'names the problem');
});

test('every advertised subcommand has a dispatch case wired to a handler', () => {
  // Dispatch completeness: a help entry with no `case` would be a dead
  // promise; a `case` with no handler would throw at runtime.
  for (const sub of SUBCOMMANDS) {
    assert.match(SRC, new RegExp('case\\s+"' + sub + '":'), `dispatch has case "${sub}"`);
  }
  for (const fn of ['cmdPrepare', 'cmdGates', 'cmdCommit', 'cmdPush', 'cmdWatch', 'cmdMerge', 'cmdTag', 'cmdRelease', 'cmdStatus']) {
    assert.match(SRC, new RegExp('function ' + fn + '\\b'), `handler ${fn} defined`);
  }
});

test('tag GUARD enforces HEAD==origin/main, the 3-version match, and no-existing-tag', () => {
  // The GUARD is the protection against tag-on-stale-HEAD. Pin its three
  // checks at the source level so a refactor can't quietly drop one.
  const tagFn = SRC.slice(SRC.indexOf('function cmdTag'), SRC.indexOf('function cmdRelease'));
  assert.match(tagFn, /local\s*!==\s*origin/, 'compares local HEAD to origin/main');
  assert.match(tagFn, /version skew/, 'checks the three-version invariant');
  assert.match(tagFn, /already exists locally/, 'refuses an existing local tag');
  assert.match(tagFn, /already exists on origin/, 'refuses an existing remote tag');
  assert.match(tagFn, /index\.lock/, 'clears a stale git index lock first');
});

test('patch is the default bump; --minor is opt-in only', () => {
  // The project default is patch-only; minor must be an explicit flag.
  assert.match(SRC, /minor:\s*process\.argv[^\n]*indexOf\("--minor"\)/, '--minor is parsed as an explicit opt-in');
  assert.match(SRC, /opts\.minor\s*\?\s*"minor"\s*:\s*"patch"/, 'absence of --minor means patch');
});

test('merge re-checks unresolved review threads right before merging (codex gate)', () => {
  const mergeFn = SRC.slice(SRC.indexOf('function cmdMerge'), SRC.indexOf('function cmdTag'));
  assert.match(mergeFn, /_unresolvedThreads/, 'merge consults unresolved review threads');
  assert.match(mergeFn, /refusing to merge/, 'refuses with unresolved threads');
  assert.match(mergeFn, /CLEAN/, 'requires mergeStateStatus CLEAN');
});
