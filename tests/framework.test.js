"use strict";


// ---- routed from framework-feeds-into-blast-radius ----
require("node:test").describe("framework-feeds-into-blast-radius", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
// Regression: the framework playbook is the compliance-theater correlator whose
// whole purpose is to chain other playbooks' findings forward. Its only
// feeds_into target is `sbom`, gated on
//   "any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4"
//
// Two defects made that chain dead, both producing a silent `false` rather than
// an error:
//   1. close()'s feeds_into eval context exposed `analyze.blast_radius_score`
//      and `analyze.compliance_theater_check.verdict` but NOT the BARE tokens
//      `blast_radius_score` / `compliance_theater_check` the catalog condition
//      references. resolvePath returned null, so `null >= 4` was false
//      regardless of the engine-computed blast radius — while the SAME bare
//      token fired in the escalation context (where the key was present).
//   2. evalCondition had no handling for the `any `/`all ` quantifier prefix, so
//      `any compliance_theater_check.verdict == 'theater'` was unparseable and
//      fell through to false.
//
// These assert the EXACT feeds_into array membership (not just truthiness) for
// the firing case, the gating case, and the poison-resistance case.

const test = require('node:test');
const it = test.test;
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const PB = 'framework';
const DIR = 'correlate-all-upstream-findings';

function chain(closeSignals, analyzeSignals = closeSignals) {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, analyzeSignals);
  const v = runner.validate(PB, DIR, an, {});
  return runner.close(PB, DIR, an, v, closeSignals);
}

test('framework feeds_into → sbom chain (bare blast_radius_score + any quantifier)', () => {
  it('chains into sbom when theater verdict fires AND blast_radius_score >= 4', () => {
    const c = chain({ blast_radius_score: 5, theater_verdict: 'theater' });
    assert.deepEqual(c.feeds_into, ['sbom'],
      'framework→sbom feeds_into must fire when verdict==theater and blast_radius_score>=4');
  });

  it('does NOT chain when blast_radius_score < 4 (gate holds)', () => {
    const c = chain({ blast_radius_score: 2, theater_verdict: 'theater' });
    assert.deepEqual(c.feeds_into, [],
      'framework→sbom must not fire below the blast_radius_score>=4 threshold');
  });

  it('engine-computed blast radius wins over a suppressing operator signal in close()', () => {
    // analyze sees blast_radius_score:5 (engine value). A later close() call that
    // passes blast_radius_score:0 (an operator suppression attempt) must NOT
    // suppress the chain — feedsCtx spreads ...agentSignals FIRST, then the
    // engine keys, so the engine value is authoritative.
    const c = chain(
      { blast_radius_score: 0, theater_verdict: 'theater' }, // close signals (poison)
      { blast_radius_score: 5, theater_verdict: 'theater' }  // analyze signals (engine truth)
    );
    assert.deepEqual(c.feeds_into, ['sbom'],
      'a submitted blast_radius_score:0 must not override the engine-computed 5');
  });
});

test('framework escalation → sbom trigger (any quantifier + bare compliance_theater_check)', () => {
  it('fires the trigger_playbook:sbom escalation when verdict==theater and blast_radius_score>=3', () => {
    const det = runner.detect(PB, DIR, {});
    const an = runner.analyze(PB, DIR, det, { blast_radius_score: 5, theater_verdict: 'theater' });
    const sbomEsc = (an.escalations || []).find(e => e.target_playbook === 'sbom');
    assert.ok(sbomEsc, 'the framework analyze phase must fire the trigger_playbook:sbom escalation');
    assert.equal(sbomEsc.condition,
      "analyze.compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 3");
  });
});

test('evalCondition quantifier prefix handling', () => {
  const ev = runner._evalCondition;

  it('scalar-path "any" is prose emphasis and evaluates the bare comparison', () => {
    assert.equal(
      ev("any compliance_theater_check.verdict == 'theater'",
        { compliance_theater_check: { verdict: 'theater' } }, {}),
      true);
  });

  it('array-path "any" is existential across elements', () => {
    const ctx = { matched_cve: [{ attack_class: 'x' }, { attack_class: 'kernel-lpe' }] };
    assert.equal(ev("any matched_cve.attack_class == 'kernel-lpe'", ctx, {}), true);
    assert.equal(ev("any matched_cve.attack_class == 'mcp-supply-chain'", ctx, {}), false);
  });

  it('array-path "all" is universal across elements', () => {
    assert.equal(
      ev("all matched_cve.attack_class == 'kernel-lpe'",
        { matched_cve: [{ attack_class: 'kernel-lpe' }, { attack_class: 'x' }] }, {}),
      false);
    assert.equal(
      ev("all matched_cve.attack_class == 'kernel-lpe'",
        { matched_cve: [{ attack_class: 'kernel-lpe' }] }, {}),
      true);
  });
});
});


// ---- routed from framework-gaps-theater-test-coverage ----
require("node:test").describe("framework-gaps-theater-test-coverage", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/framework-gaps-theater-test-coverage.test.js
 *
 * Hard Rule #6 coverage: every entry in data/framework-control-gaps.json
 * MUST carry a populated theater_test block that distinguishes paper
 * compliance from actual security.
 *
 * Schema (per AGENTS.md Hard Rule #6):
 *   theater_test: {
 *     claim:                 non-empty string (the audit-language sentence),
 *     test:                  non-empty string (a falsifiable check),
 *     evidence_required:     non-empty array of strings (1+ artifacts),
 *     verdict_when_failed:   exact literal "compliance-theater"
 *   }
 *
 * Per the project anti-coincidence rule: assertions test EXACT shape and
 * type, not just presence. A future regression that emits an empty array,
 * an empty string, or a typo'd verdict will fail here, not silently pass.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CATALOG_PATH = path.join(ROOT, 'data', 'framework-control-gaps.json');
const CATALOG = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));

const ENTRY_KEYS = Object.keys(CATALOG).filter((k) => k !== '_meta');

const REQUIRED_VERDICT = 'compliance-theater';

test('framework-control-gaps.json: catalog has at least 109 control-gap entries', () => {
  // Lower-bound assertion. New entries are additive and must continue to
  // satisfy the per-entry shape below; this guard catches accidental
  // truncation of the file.
  assert.ok(
    ENTRY_KEYS.length >= 109,
    `expected >= 109 entries, found ${ENTRY_KEYS.length}`
  );
});

test('framework-control-gaps.json: every entry has a populated theater_test', () => {
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const entry = CATALOG[key];
    const tt = entry.theater_test;

    if (tt === undefined || tt === null) {
      failures.push(`${key}: theater_test is missing`);
      continue;
    }

    if (typeof tt !== 'object' || Array.isArray(tt)) {
      failures.push(`${key}: theater_test is not an object`);
      continue;
    }

    // claim: non-empty string
    if (typeof tt.claim !== 'string') {
      failures.push(`${key}: theater_test.claim is not a string (got ${typeof tt.claim})`);
    } else if (tt.claim.trim().length === 0) {
      failures.push(`${key}: theater_test.claim is empty`);
    } else if (tt.claim.length < 30) {
      // Paper-compliance claims worth testing read like real audit language.
      // A 30-char minimum stops one-word stub claims from regressing in.
      failures.push(`${key}: theater_test.claim is too short (${tt.claim.length} chars)`);
    }

    // test: non-empty string with discriminating content
    if (typeof tt.test !== 'string') {
      failures.push(`${key}: theater_test.test is not a string (got ${typeof tt.test})`);
    } else if (tt.test.trim().length === 0) {
      failures.push(`${key}: theater_test.test is empty`);
    } else if (tt.test.length < 80) {
      // A falsifiability check needs enough text to describe the query
      // and the binary verdict. 80 chars is a low floor.
      failures.push(`${key}: theater_test.test is too short (${tt.test.length} chars)`);
    }

    // evidence_required: array, length >= 1, all non-empty strings
    if (!Array.isArray(tt.evidence_required)) {
      failures.push(`${key}: theater_test.evidence_required is not an array`);
    } else if (tt.evidence_required.length < 1) {
      failures.push(`${key}: theater_test.evidence_required has zero entries`);
    } else {
      for (let i = 0; i < tt.evidence_required.length; i++) {
        const item = tt.evidence_required[i];
        if (typeof item !== 'string' || item.trim().length === 0) {
          failures.push(`${key}: theater_test.evidence_required[${i}] is not a non-empty string`);
        }
      }
    }

    // verdict_when_failed: exact literal "compliance-theater"
    assert.equal(
      tt.verdict_when_failed,
      REQUIRED_VERDICT,
      `${key}: theater_test.verdict_when_failed must equal "${REQUIRED_VERDICT}", got ${JSON.stringify(tt.verdict_when_failed)}`
    );
  }

  assert.equal(
    failures.length,
    0,
    `theater_test schema failures:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test contains a falsifiability marker', () => {
  // Soft check: the test string should contain at least one of the words
  // that signal a binary verdict ("Theater verdict", "verdict if", "fail",
  // "must", "confirm"). This is not a proof of falsifiability but it
  // catches drafting accidents where the field reads like prose without
  // any pass/fail trigger.
  const verdictMarkers = /(theater verdict|verdict if|confirm|missing|absent|exceeds|fails|fail if)/i;
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    if (!verdictMarkers.test(tt.test)) {
      failures.push(`${key}: theater_test.test lacks any verdict marker`);
    }
  }
  assert.equal(
    failures.length,
    0,
    `entries without verdict markers:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test strings are not literal duplicates', () => {
  // Per AGENTS.md: distinct controls cannot share the literal same test
  // string (pattern-shaped tests are fine; copy-paste is not). Group by
  // exact-string equality and surface any group with > 1 distinct entry.
  const byTest = new Map();
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    const trimmed = tt.test.trim();
    if (!byTest.has(trimmed)) byTest.set(trimmed, []);
    byTest.get(trimmed).push(key);
  }
  const dupes = [];
  for (const [text, keys] of byTest.entries()) {
    if (keys.length > 1) {
      dupes.push(`shared by ${keys.join(', ')}: ${text.slice(0, 80)}...`);
    }
  }
  assert.equal(
    dupes.length,
    0,
    `theater_test.test strings duplicated verbatim across distinct controls:\n  - ${dupes.join('\n  - ')}`
  );
});
});
