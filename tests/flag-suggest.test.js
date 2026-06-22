'use strict';

/**
 * Subject coverage for lib/flag-suggest.js — the per-verb flag allowlist
 * (flagsFor) and the typo-suggestion resolver (suggestFlag).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

test.describe("cli-surface-drift", () => {
  const { flagsFor, suggestFlag } = require("../lib/flag-suggest.js");

  test("flagsFor('run') includes --directive/--explain/--signal-list and typos resolve", () => {
    const flags = flagsFor("run");
    for (const f of ["directive", "explain", "signal-list"]) {
      assert.ok(flags.includes(f), `run must accept --${f}`);
    }
    assert.equal(suggestFlag("explan", flags), "explain", "a --explain typo must resolve");
    assert.equal(suggestFlag("directiv", flags), "directive", "a --directive typo must resolve");
  });
});


// ---- routed from codebase-patterns-readability-rules ----
require("node:test").describe("codebase-patterns-readability-rules", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/codebase-patterns-readability-rules.test.js
 *
 * Covers the two opt-in readability detectors added to
 * scripts/check-codebase-patterns.js (unsorted-marked-array,
 * misaligned-marked-run), the dynamic-regex severity pin, and the
 * doctor flag-allowlist drift guard. Anti-coincidence: each detector is
 * asserted to FIRE on a bad sample AND stay silent on a good/unmarked one,
 * so a future no-op refactor cannot pass these by accident.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const gate = require('../scripts/check-codebase-patterns.js');
const { VERB_FLAG_ALLOWLIST, flagsFor } = require('../lib/flag-suggest.js');

const ROOT = path.join(__dirname, '..');

// ---- unsorted-marked-array ----

// ---- misaligned-marked-run ----

// ---- detector wrappers (tree walk) ----

// ---- severity pins / registration ----

// ---- doctor flag-allowlist drift guard ----

test('VERB_FLAG_ALLOWLIST.doctor stays in sync with bin KNOWN_DOCTOR_FLAGS', () => {
  const bin = fs.readFileSync(path.join(ROOT, 'bin/exceptd.js'), 'utf8');
  const m = bin.match(/KNOWN_DOCTOR_FLAGS\s*=\s*new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, 'KNOWN_DOCTOR_FLAGS Set literal found in bin/exceptd.js');
  const known = new Set([...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]));
  // Globals + parser-internal keys that KNOWN_DOCTOR_FLAGS carries beyond the
  // doctor-specific surface (documented here so the comparison is exact).
  const NON_VERB = new Set(['json', 'pretty', 'quiet', 'verbose', '_', 'json-stdout-only', '_jsonMode']);
  const knownVerbFlags = [...known].filter((f) => !NON_VERB.has(f)).sort();
  const allowlistDoctor = [...VERB_FLAG_ALLOWLIST.doctor].sort();
  assert.deepEqual(knownVerbFlags, allowlistDoctor,
    'doctor-specific flags in bin KNOWN_DOCTOR_FLAGS must set-equal VERB_FLAG_ALLOWLIST.doctor — ' +
    'add the flag to BOTH or the suggester and the parser disagree');
  // Every allowlisted doctor flag must actually be accepted by the parser.
  for (const f of VERB_FLAG_ALLOWLIST.doctor) {
    assert.ok(known.has(f), `doctor flag "${f}" is allowlisted but missing from KNOWN_DOCTOR_FLAGS (parser would reject it)`);
  }
  // flagsFor includes globals; doctor flags are a subset.
  for (const f of VERB_FLAG_ALLOWLIST.doctor) assert.ok(flagsFor('doctor').includes(f));
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from lib-flag-suggest ----
require("node:test").describe("lib-flag-suggest", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Unit coverage for lib/flag-suggest.js.
 *
 * suggestFlag() returns the closest allowlisted flag at Levenshtein
 * distance ≤ min(2, floor(flag.length / 2)). The distance cap prevents
 * "did you mean: --help" suggestions on flags too short to share useful
 * structure with the allowlist.
 *
 * Per-verb allowlists are exported via flagsFor(verb). Adding a flag to
 * the CLI surface MUST land here too; the dispatch + this allowlist are
 * the two parallel sources of truth.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { editDistance, suggestFlag, flagsFor, VERB_FLAG_ALLOWLIST } =
  require(path.join(ROOT, 'lib', 'flag-suggest.js'));

test('--evidnce suggests "evidence" (single-char insertion)', () => {
  const s = suggestFlag('evidnce', flagsFor('run'));
  assert.equal(s, 'evidence', `expected "evidence"; got ${JSON.stringify(s)}`);
});

test('--csaf-stats suggests "csaf-status" (transposition + substitution)', () => {
  const s = suggestFlag('csaf-stats', flagsFor('run'));
  assert.equal(s, 'csaf-status', `expected "csaf-status"; got ${JSON.stringify(s)}`);
});

test('--xyzzy returns null — too far from any allowlisted flag', () => {
  const s = suggestFlag('xyzzy', flagsFor('run'));
  assert.equal(s, null, `expected null (distance > floor(5/2)=2); got ${JSON.stringify(s)}`);
});

test('--ack matches itself exactly (distance 0)', () => {
  const s = suggestFlag('ack', flagsFor('run'));
  assert.equal(s, 'ack');
});

test('short typos cap suggestion distance at floor(len/2)', () => {
  // For a 3-char input, cap = floor(3/2) = 1. "hep" → "help" (distance 1).
  const s1 = suggestFlag('hep', flagsFor('run'));
  assert.equal(s1, 'help');
  // For a 2-char input, cap = 1; "ja" is distance 2 from "json" → no suggestion.
  const s2 = suggestFlag('ja', flagsFor('run'));
  assert.equal(s2, null,
    'short inputs must reject suggestions whose distance exceeds floor(len/2)');
});

test('flagsFor(verb) prepends global flags before verb-specific', () => {
  const runFlags = flagsFor('run');
  for (const g of VERB_FLAG_ALLOWLIST._global) {
    assert.ok(runFlags.includes(g), `global flag ${g} must appear in flagsFor('run')`);
  }
});

test('per-verb scoping: --operator typo on `brief` is rejected (brief does not consume --operator)', () => {
  // VERB_FLAG_ALLOWLIST.brief is ['all','scope','directives','flat','phase'] —
  // no 'operator'. flagsFor('brief') returns those plus the global flags.
  // suggestFlag('opetator', brief-scope) must NOT suggest 'operator' because
  // the verb does not consume it.
  const briefFlags = flagsFor('brief');
  assert.ok(!briefFlags.includes('operator'),
    'brief verb must not list operator in its allowlist');
  const s = suggestFlag('opetator', briefFlags);
  assert.equal(s, null,
    'suggestion against brief-scoped allowlist must not resolve to "operator" (verb does not accept it)');
});

test('per-verb scoping: --operator on `run` IS suggested (run consumes it)', () => {
  const runFlags = flagsFor('run');
  assert.ok(runFlags.includes('operator'), 'run accepts operator');
  const s = suggestFlag('opetator', runFlags);
  assert.equal(s, 'operator',
    'run-scoped allowlist resolves typo to "operator"');
});

test('editDistance: identity, insertion, deletion, substitution', () => {
  assert.equal(editDistance('foo', 'foo'), 0, 'identical strings → distance 0');
  assert.equal(editDistance('foo', 'fooo'), 1, 'single insertion');
  assert.equal(editDistance('foo', 'fo'), 1, 'single deletion');
  assert.equal(editDistance('foo', 'fox'), 1, 'single substitution');
  assert.equal(editDistance('foo', ''), 3, 'empty target = length of source');
  assert.equal(editDistance('', 'bar'), 3, 'empty source = length of target');
});

test('suggestFlag handles empty allowlist and non-string inputs gracefully', () => {
  assert.equal(suggestFlag('foo', []), null, 'empty allowlist → null');
  assert.equal(suggestFlag('', ['help']), null, 'empty input → null');
  assert.equal(suggestFlag(null, ['help']), null, 'non-string input → null');
  assert.equal(suggestFlag('foo', null), null, 'non-array allowlist → null');
});

test('removed verbs have no allowlist entry (no dead/stale flag surface)', () => {
  // `ingest` is a removed verb; its allowlist block was dead (flagsFor only
  // runs for live PLAYBOOK_VERBS) and stale. plan/govern/direct/look likewise
  // have no entry — flagsFor returns globals for any unknown verb.
  for (const removed of ['ingest', 'plan', 'govern', 'direct', 'look']) {
    assert.equal(VERB_FLAG_ALLOWLIST[removed], undefined,
      `${removed} is a removed verb and must not carry a flag allowlist entry`);
  }
});

test('run allowlist includes --format; typo resolves + missing-value guard can fire', () => {
  // run documents --format and cmdRun acts on it, but the allowlist omitted
  // it — so `run --formt` got no suggestion and `run --format` (no value)
  // silently proceeded (format IS in REQUIRES_VALUE). Both now covered.
  assert.ok(flagsFor('run').includes('format'), 'run must accept --format');
  assert.equal(suggestFlag('formt', flagsFor('run')), 'format', 'a --format typo resolves');
});

test('collect allowlist includes --air-gap (documented + consumed, was missing)', () => {
  assert.ok(flagsFor('collect').includes('air-gap'), 'collect must accept --air-gap');
  assert.equal(suggestFlag('air-gp', flagsFor('collect')), 'air-gap', 'an --air-gap typo resolves on collect');
});

test('doctor allowlist includes --air-gap (kept in sync with KNOWN_DOCTOR_FLAGS in bin)', () => {
  // The doctor allowlist here and the KNOWN_DOCTOR_FLAGS set in
  // bin/exceptd.js are two operator-facing lists for the same verb; they
  // drifted on --air-gap (a real doctor flag). Pin the shared flag so
  // `doctor --bogus` and `doctor --evidence x` list the same accepted set.
  assert.ok(flagsFor('doctor').includes('air-gap'),
    'doctor must accept --air-gap (real flag; was missing from this allowlist)');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
