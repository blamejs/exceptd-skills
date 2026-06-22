"use strict";


// ---- routed from help-verb-attest-list-deprecation ----
require("node:test").describe("help-verb-attest-list-deprecation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/help-verb-attest-list-deprecation.test.js
 *
 * Cycle 11 P2/P3 fixes (v0.12.32):
 *
 *   F4 — `exceptd help <verb>` now routes through printPlaybookVerbHelp()
 *        so operators get verb-specific help regardless of whether they
 *        type `exceptd help run` or `exceptd run --help`. Pre-fix it
 *        dropped the verb argument and printed the top-level help.
 *
 *   F5 — `attest list` empty-state human renderer surfaces `roots_evaluated`
 *        showing every candidate root + whether it existed (`[scanned-empty]`
 *        vs `[not-present]`). Pre-fix it said `(no attestations under )`
 *        with an empty path list when no roots existed at all. JSON output
 *        also carries a structured `roots_evaluated[]` array.
 *
 *   F7 — Legacy-verb deprecation banner now persists suppression across
 *        invocations via an OS-tempdir marker keyed by exceptd version.
 *        Pre-fix the env-var guard reset on every fresh node process so
 *        operators saw the same banner on every `exceptd plan` invocation.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (status code, string presence/absence, array shape).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// F4 ------------------------------------------------------------------------



// F5 ------------------------------------------------------------------------



// F7 v0.13.0 update --------------------------------------------------------
//
// v0.13.0 honored the long-advertised legacy-verb removal. The pre-v0.13
// deprecation-banner mechanism (soft banner + tempdir marker for once-per-
// version display) was replaced by a hard refusal with a replacement hint.
// The two prior F7 tests asserted banner+suppress semantics; both are
// replaced with refusal-shape assertions below.

test('F7: removed legacy verbs (plan/govern/direct/look/ingest) are refused with replacement hint', () => {
  // Exhaustive across the 5 removed verbs so a regression that re-routes
  // one of them silently is caught. (reattest and list-attestations are
  // preserved as canonical short-form routings — they remain operationally
  // useful and v0.13 does not remove them.)
  const removedPairs = [
    ['plan', 'brief --all'],
    ['govern', 'brief <pb> --phase govern'],
    ['direct', 'brief <pb> --phase direct'],
    ['look', 'brief <pb> --phase look'],
    ['ingest', 'run'],
  ];
  for (const [removed, replacement] of removedPairs) {
    const r = cli([removed]);
    assert.equal(r.status, 1, `${removed}: expected exit 1; got ${r.status}`);
    const body = JSON.parse(r.stderr.trim());
    assert.equal(body.ok, false, `${removed}: body must be ok:false`);
    assert.equal(body.verb, removed, `${removed}: body.verb must echo input`);
    assert.equal(body.removed_in, '0.13.0', `${removed}: removed_in must be "0.13.0"`);
    assert.equal(body.replacement, replacement,
      `${removed}: replacement must be "${replacement}"; got "${body.replacement}"`);
    assert.match(body.error, new RegExp(`'${removed}' was removed in v0\\.13\\.0\\. Use .exceptd ${replacement.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&')}.`),
      `${removed}: error string must point at the replacement command`);
  }
});

test('F7: removal refusal carries deprecation_history field for operator audit', () => {
  const r = cli(['plan']);
  const body = JSON.parse(r.stderr.trim());
  assert.equal(typeof body.deprecation_history, 'string');
  assert.match(body.deprecation_history, /v0\.11\.0/);
  assert.match(body.deprecation_history, /v0\.13\.0/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
