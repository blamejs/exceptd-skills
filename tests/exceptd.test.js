"use strict";


// ---- routed from cycle17-ux-fixes ----
require("node:test").describe("cycle17-ux-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/cycle17-ux-fixes.test.js
 *
 * Cycle 17 fixes (v0.12.37):
 *
 *   S4 — `--evidence -` with empty stdin now emits a stderr nudge.
 *        Pre-fix the empty payload was silently accepted as {} and the
 *        run looked successful. Cycle 15 flagged; cycle 17 verified
 *        still open. The fix preserves the legitimate "posture-only
 *        walk" use case (the run still proceeds with {}) but surfaces
 *        a stderr `[exceptd] note: ...` message so the operator at
 *        least knows.
 *
 *   S13 — unknown verb with Levenshtein-1 typo now suggests the
 *         intended verb. `exceptd discoer` → `discover`,
 *         `exceptd attst` → `attest`. Includes transposition detection
 *         so `disocver` also resolves to `discover`. Unknown verbs
 *         outside edit-distance 1 still get the generic hint.
 *
 *   F1/F2 — operator-misleading skill prose about CVE-2024-3094
 *         (xz-utils). Pre-fix 2 skills said "not in current cve-catalog
 *         — pre-scope incident" while the catalog actually carries the
 *         entry; a 3rd skill quoted RWEP 95 against the catalog's 70
 *         plus drifted ai_discovered and active_exploitation. This
 *         test pins the corrected prose.
 *
 *   F3 — Volt-Typhoon hyphenation drift (cosmetic). Two skills used
 *         `Volt-Typhoon-aligned` / `Volt-Typhoon-style`. All others use
 *         unhyphenated `Volt Typhoon`. Test pins single canonical form.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (string match, deepEqual, or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// S4 — empty-stdin nudge ---------------------------------------------------



// S13 — did-you-mean for unknown verbs -------------------------------------




// F1/F2 — CVE-2024-3094 prose corrections ----------------------------------

test('S13: unknown verb within Levenshtein-1 of a real verb returns did_you_mean[]', () => {
  for (const [typo, expected] of [['discoer', 'discover'], ['attst', 'attest'], ['disocver', 'discover']]) {
    const r = cli([typo]);
    assert.equal(r.status, 10, `${typo} must exit UNKNOWN_COMMAND (10); got ${r.status}`);
    const err = tryJson(r.stderr);
    assert.ok(err, `${typo} stderr must be JSON`);
    assert.equal(Array.isArray(err.did_you_mean), true);
    assert.equal(err.did_you_mean.includes(expected), true,
      `${typo} should suggest "${expected}"; got: ${JSON.stringify(err.did_you_mean)}`);
    assert.match(err.hint, /Did you mean/, 'hint must surface the suggestion');
  }
});

test('S13: did_you_mean[] deduplicates across overlapping verb sources (codex P2 v0.12.37 follow-up)', () => {
  // `scan` lives in both COMMANDS and ORCHESTRATOR_PASSTHROUGH; pre-fix
  // the union produced ["scan", "scan"] and the human hint read
  // "Did you mean `scan` or `scan`?". Now deduped via Set.
  const r = cli(['scn']);
  assert.equal(r.status, 10);
  const err = tryJson(r.stderr);
  assert.ok(err, 'stderr must be JSON');
  assert.equal(Array.isArray(err.did_you_mean), true);
  // Set semantics: same verb appears at most once.
  const seen = new Set(err.did_you_mean);
  assert.equal(seen.size, err.did_you_mean.length,
    `did_you_mean must contain unique verbs; got duplicates: ${JSON.stringify(err.did_you_mean)}`);
  assert.equal(err.did_you_mean.includes('scan'), true);
});

test('S13: unknown verb beyond Levenshtein-1 returns empty did_you_mean[] (no false suggestions)', () => {
  const r = cli(['xyzzyzzz']);
  assert.equal(r.status, 10);
  const err = tryJson(r.stderr);
  assert.deepEqual(err.did_you_mean, [], 'distant typo must NOT trigger a suggestion');
  assert.equal(/Did you mean/.test(err.hint), false);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
