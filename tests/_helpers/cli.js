'use strict';

/**
 * Shared CLI invocation harness for the test suite.
 *
 * Every test that shells out to bin/exceptd.js routes through cli() so the
 * sandbox shape (EXCEPTD_HOME, deprecation suppression, raw-json mode) stays
 * consistent. Without the shared sandbox, attestations from `run` / `ci` /
 * `attest` invocations accumulate in the maintainer's real ~/.exceptd/ on
 * every `npm test` run and never get cleaned up — resolveAttestationRoot()
 * honors EXCEPTD_HOME first.
 *
 * One suite-scoped tempdir is sufficient because tests run sequentially
 * (--test-concurrency=1) and attest-diff / attest-verify deliberately read
 * across sessions written by sibling tests in the same suite.
 */

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

/**
 * Allocate a per-suite EXCEPTD_HOME tempdir and register a cleanup hook on
 * process exit. Call once at suite import time; pass the returned path into
 * makeCli() so every subsequent cli() call routes attestations through it.
 */
function makeSuiteHome(prefix = 'exceptd-test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  process.on('exit', () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* non-fatal */ }
  });
  return dir;
}

/**
 * Build a cli() function bound to a specific EXCEPTD_HOME. Returns a function
 * with the same signature as the inline `cli()` helper that operator-bugs.test.js
 * used pre-factoring:
 *
 *   cli(args, opts = {})
 *     args: string[]                positional + flag tokens after bin/exceptd.js
 *     opts.input: string|undefined  stdin payload (raw)
 *     opts.env:   object|undefined  env overrides; merged onto defaults
 *     opts.timeout: number          default 30000ms
 *
 * Defaults to a 30 second timeout. Returns the raw spawnSync result so callers
 * keep access to status / stdout / stderr / signal.
 */
function makeCli(suiteHome) {
  return function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      input: opts.input,
      env: {
        ...process.env,
        EXCEPTD_DEPRECATION_SHOWN: '1',
        EXCEPTD_UNSIGNED_WARNED: '1',
        EXCEPTD_RAW_JSON: '1',
        EXCEPTD_HOME: suiteHome,
        ...opts.env,
      },
      timeout: opts.timeout ?? 30000,
    });
  };
}

/** Try to parse `s` as JSON; return null on failure. */
function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

module.exports = { ROOT, CLI, makeSuiteHome, makeCli, tryJson };
