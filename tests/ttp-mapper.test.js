'use strict';

/**
 * Tests for lib/ttp-mapper.js — control-to-TTP/CVE mapping.
 *
 * NOTE (spec vs. code): The job description asked for "ATLAS TTPs (e.g., AML.T0051)
 * and ATT&CK TTPs (e.g., T1068) resolve to expected skills". The actual lib exports
 * (`map`, `gapsFor`, `coverage`, `universalGaps`) do not map TTPs to skill names —
 * that is the responsibility of the orchestrator/manifest layer. These tests target
 * the actual API surface and document the gap. ATT&CK IDs (e.g., T1068) are not
 * present in data/atlas-ttps.json (which is ATLAS-scoped), so `coverage(...)` for
 * T1068 returns { found: false } — covered below.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const mapper = require('../lib/ttp-mapper.js');
const controlGaps = require('../data/framework-control-gaps.json');
const atlasCatalog = require('../data/atlas-ttps.json');

const { map, gapsFor, coverage, universalGaps } = mapper;

// ---------- map(controlId, gapCatalog) ----------

test('map() resolves a known framework control id', () => {
  const r = map('NIST-800-53-SI-2', controlGaps);
  assert.equal(r.found, true);
  assert.equal(r.control_id, 'NIST-800-53-SI-2');
  assert.equal(typeof r.framework, 'string');
  assert.equal(typeof r.control_name, 'string');
  assert.ok(Array.isArray(r.misses) && r.misses.length > 0);
  assert.equal(r.status, 'open');
  assert.ok(Array.isArray(r.evidence_cves));
  assert.ok(r.evidence_cves.includes('CVE-2026-31431'),
    `expected SI-2 to reference Copy Fail; got ${JSON.stringify(r.evidence_cves)}`);
});

test('map() returns a clear not-found result for unknown control id', () => {
  const r = map('FAKE-CONTROL-9999', controlGaps);
  assert.equal(r.found, false);
  assert.equal(r.control_id, 'FAKE-CONTROL-9999');
  assert.match(r.message, /not in gap catalog/i);
});

test('map() resolves the prompt-injection-as-access-control universal gap', () => {
  const r = map('ALL-PROMPT-INJECTION-ACCESS-CONTROL', controlGaps);
  assert.equal(r.found, true);
  assert.equal(r.framework, 'ALL');
});

// ---------- gapsFor(attackPattern, gapCatalog, atlasCatalog) ----------

test('gapsFor() finds controls whose misses mention the attack pattern', () => {
  const r = gapsFor('prompt injection', controlGaps, atlasCatalog);
  assert.equal(r.attack_pattern, 'prompt injection');
  assert.equal(r.found_gaps, true);
  assert.ok(Array.isArray(r.controls_with_gap));
  assert.ok(r.controls_with_gap.length >= 1, 'expected at least one control with a prompt-injection gap');
  for (const c of r.controls_with_gap) {
    assert.equal(typeof c.control_id, 'string');
    assert.equal(typeof c.control_name, 'string');
    assert.ok(Array.isArray(c.gap));
  }
});

test('gapsFor() returns a found_gaps=false explanation when nothing matches', () => {
  const r = gapsFor('this-pattern-does-not-exist-anywhere', controlGaps, atlasCatalog);
  assert.equal(r.found_gaps, false);
  assert.match(r.message, /No documented gaps/i);
});

test('gapsFor() does not return entries from metadata keys (underscore-prefixed)', () => {
  const stub = {
    '_meta': { misses: ['prompt injection'], framework: 'meta', control_name: 'meta' },
    'REAL-CONTROL-1': { misses: ['prompt injection'], framework: 'X', control_name: 'real' }
  };
  const r = gapsFor('prompt injection', stub, atlasCatalog);
  assert.equal(r.found_gaps, true);
  assert.equal(r.controls_with_gap.length, 1);
  assert.equal(r.controls_with_gap[0].control_id, 'REAL-CONTROL-1');
});

// ---------- coverage(frameworkId, ttpId, gapCatalog, atlasCatalog) ----------

test('coverage() resolves a known ATLAS TTP (AML.T0051 — LLM Prompt Injection)', () => {
  const r = coverage('NIST-800-53', 'AML.T0051', controlGaps, atlasCatalog);
  assert.notEqual(r.found, false, `expected AML.T0051 to be present in atlas-ttps.json; got ${JSON.stringify(r)}`);
  assert.equal(r.ttp_id, 'AML.T0051');
  assert.equal(typeof r.ttp_name, 'string');
  assert.equal(r.framework, 'NIST-800-53');
  assert.equal(r.has_gap, true);
  // NIST appears in controls_that_partially_help for AML.T0051 → partially_covered_by should be populated
  assert.ok(r.partially_covered_by, `expected partially_covered_by for NIST; got ${r.partially_covered_by}`);
});

test('coverage() reports an unknown TTP cleanly without throwing', () => {
  const r = coverage('NIST-800-53', 'AML.T9999', controlGaps, atlasCatalog);
  assert.equal(r.found, false);
  assert.equal(r.ttp_id, 'AML.T9999');
});

test('coverage() — ATT&CK TTP T1068 is NOT in atlas-ttps.json (ATLAS-scoped catalog)', () => {
  // NOTE: T1068 appears in CVE-2026-31431.attack_refs but data/atlas-ttps.json only catalogs ATLAS
  // (AML.*) techniques. Resolving ATT&CK IDs to skills would need a separate catalog or a manifest-
  // level mapping. This test documents the current shape rather than aspirational behavior.
  const r = coverage('NIST-800-53', 'T1068', controlGaps, atlasCatalog);
  assert.equal(r.found, false);
});

test('coverage() framework prefix matching is case-insensitive and substring-based', () => {
  // Use a stub so the test does not depend on data layout
  const atlasStub = {
    'AML.TEST': {
      name: 'Test',
      framework_gap: true,
      controls_that_partially_help: ['NIST-800-53-X', 'iso-27001-y'],
      controls_that_dont_help: ['soc2-z'],
      framework_gap_detail: 'detail',
      detection: 'none'
    }
  };
  const a = coverage('NIST-800-53', 'AML.TEST', {}, atlasStub);
  assert.equal(a.partially_covered_by, 'NIST-800-53-X');

  const b = coverage('ISO-27001-2022', 'AML.TEST', {}, atlasStub);
  assert.equal(b.partially_covered_by, 'iso-27001-y');

  const c = coverage('SOC2-CC6', 'AML.TEST', {}, atlasStub);
  assert.equal(c.not_covered_by, 'soc2-z');
});

// ---------- universalGaps() ----------

test('universalGaps() returns a fixed list with the expected structure', () => {
  const r = universalGaps();
  assert.ok(Array.isArray(r));
  assert.ok(r.length >= 5, `expected several universal gaps; got ${r.length}`);
  for (const g of r) {
    assert.equal(typeof g.gap, 'string');
    assert.equal(g.no_framework_coverage, true);
  }
});

test('universalGaps() includes core AI/MCP/PQC items', () => {
  const r = universalGaps();
  const allText = r.map(g => g.gap).join(' | ');
  assert.match(allText, /AI pipeline/i);
  assert.match(allText, /MCP/i);
  assert.match(allText, /prompt injection/i);
  assert.match(allText, /quantum/i);
});

// ---------------------------------------------------------------------------
// Finding #34 — coverage() input guard + token-boundary framework match.
// ---------------------------------------------------------------------------

const atlasStub = {
  'AML.TEST': {
    name: 'Test',
    framework_gap: true,
    controls_that_partially_help: ['NIST-800-53-X', 'iso-27001-y'],
    controls_that_dont_help: ['soc2-z'],
    framework_gap_detail: 'detail',
    detection: 'none',
  },
};

test('#34 empty-string frameworkId no longer universal-matches — partially_covered_by is null', () => {
  const r = mapper.coverage('', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
  assert.equal(r.found, false);
  assert.equal(r.error, 'frameworkId required');
});

test('#34 a short prefix "IS" must NOT match "NIST-..." via token boundary', () => {
  const r = mapper.coverage('IS', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 null / undefined frameworkId returns found:false WITHOUT throwing', () => {
  const rn = mapper.coverage(null, 'AML.TEST', {}, atlasStub);
  assert.equal(rn.found, false);
  assert.equal(rn.error, 'frameworkId required');
  const ru = mapper.coverage(undefined, 'AML.TEST', {}, atlasStub);
  assert.equal(ru.found, false);
  assert.equal(ru.error, 'frameworkId required');
});

test('#34 hyphen-led "-X" (empty first segment) fails closed, not universal-match', () => {
  const r = mapper.coverage('-X', 'AML.TEST', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 legitimate loose framework matching still works (token-boundary, case-insensitive)', () => {
  assert.equal(mapper.coverage('NIST-800-53', 'AML.TEST', {}, atlasStub).partially_covered_by, 'NIST-800-53-X');
  assert.equal(mapper.coverage('ISO-27001-2022', 'AML.TEST', {}, atlasStub).partially_covered_by, 'iso-27001-y');
  assert.equal(mapper.coverage('SOC2-CC6', 'AML.TEST', {}, atlasStub).not_covered_by, 'soc2-z');
});

test('#34 unknown TTP still returns found:false cleanly (guard runs first, no throw)', () => {
  const r = mapper.coverage('NIST-800-53', 'AML.NOPE', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.ttp_id, 'AML.NOPE');
});

// ---------------------------------------------------------------------------
// map()/coverage() must not treat inherited Object.prototype keys as real
// catalog entries — found:true is reserved for OWN catalog members. A bare
// gapCatalog[controlId] / atlasCatalog[ttpId] deref resolves '__proto__',
// 'toString', 'constructor', etc. to the prototype chain and falsely reports
// found:true. The hasOwnProperty guard fails them closed.
// ---------------------------------------------------------------------------

test('map() treats inherited prototype keys as not-found (found:false)', () => {
  for (const k of ['__proto__', 'toString', 'constructor', 'hasOwnProperty', 'valueOf']) {
    const r = mapper.map(k, {});
    assert.equal(r.found, false, `map(${k}) must be found:false, not an inherited prototype hit`);
    assert.equal(r.control_id, k);
    assert.match(r.message, /not in gap catalog/i);
  }
});

test('map() still resolves an own catalog control id (guard does not break real lookups)', () => {
  const stub = { 'REAL-CTRL-1': { framework: 'X', control_name: 'real', misses: ['m'], status: 'open', evidence_cves: [] } };
  const r = mapper.map('REAL-CTRL-1', stub);
  assert.equal(r.found, true);
  assert.equal(r.control_id, 'REAL-CTRL-1');
  assert.equal(r.framework, 'X');
});

test('coverage() treats inherited prototype TTP keys as not-found (found:false)', () => {
  for (const k of ['__proto__', 'toString', 'constructor', 'hasOwnProperty', 'valueOf']) {
    const r = mapper.coverage('NIST-800-53', k, {}, {});
    assert.equal(r.found, false, `coverage(NIST-800-53, ${k}) must be found:false, not an inherited prototype hit`);
    assert.equal(r.ttp_id, k);
    // ttp_name (sourced from the would-be inherited member) must NOT leak.
    assert.equal(r.ttp_name, undefined);
  }
});

test('coverage() still resolves an own ATLAS technique (guard does not break real lookups)', () => {
  const r = mapper.coverage('NIST-800-53', 'AML.TEST', {}, atlasStub);
  assert.equal(r.found, undefined); // present technique returns no `found` key
  assert.equal(r.ttp_id, 'AML.TEST');
  assert.equal(r.partially_covered_by, 'NIST-800-53-X');
});


// ---- routed from hunt-fix-G-parsers ----
require("node:test").describe("hunt-fix-G-parsers", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hunt-fix-G-parsers.test.js
 *
 * Regression coverage for the G-parsers cluster:
 *   #31 lib/xml-tokenizer.js — unescaped '<' in a leaf field (title/body)
 *        corrupted the field and silently dropped a title-only CVE.
 *   #32 lib/source-advisories.js — the tokenizer loud-error contract was
 *        opt-in and the live RSS/Atom path never opted in, so parse errors
 *        were silently discarded ('0 new CVEs' instead of 'feed unparsable').
 *   #33 lib/xml-tokenizer.js — Atom multi-<link> capture took the LAST href
 *        regardless of rel; advisory_url could point at rel=self/replies.
 *   #34 lib/ttp-mapper.js — coverage() with an empty/short/non-string
 *        frameworkId matched EVERY control via includes('') (and threw on
 *        null/undefined).
 *
 * Each case fails on the pre-fix behavior and passes after the root-cause fix.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const T = require(path.join(__dirname, '..', 'lib', 'xml-tokenizer.js'));
const SA = require(path.join(__dirname, '..', 'lib', 'source-advisories.js'));
const mapper = require(path.join(__dirname, '..', 'lib', 'ttp-mapper.js'));

// ---------------------------------------------------------------------------
// Finding #31 — stray unescaped '<' in a leaf field no longer drops the field.
// Three lead chars after '<': space, digit, letter.
// ---------------------------------------------------------------------------









// ---------------------------------------------------------------------------
// Finding #33 — rel-aware Atom <link> selection (first-alternate-wins).
// ---------------------------------------------------------------------------






// ---------------------------------------------------------------------------
// Finding #32 — parse errors surface on the LIVE checkFeed/fetchDiff path.
// ---------------------------------------------------------------------------

function allFixtures(overrides) {
  const fx = {};
  for (const f of SA.FEEDS) {
    fx[f.name] = f.kind === 'csaf-index' ? 'rhsa-2026_0001.json\n'
      : f.kind === 'gitlab-activity' ? '<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
      : '<rss><channel></channel></rss>';
  }
  return Object.assign(fx, overrides || {});
}




// ---------------------------------------------------------------------------
// Finding #34 — coverage() input guard + token-boundary framework match.
// ---------------------------------------------------------------------------

const atlasStub = {
  'AML.TEST': {
    name: 'Test',
    framework_gap: true,
    controls_that_partially_help: ['NIST-800-53-X', 'iso-27001-y'],
    controls_that_dont_help: ['soc2-z'],
    framework_gap_detail: 'detail',
    detection: 'none',
  },
};

test('#34 empty-string frameworkId no longer universal-matches — partially_covered_by is null', () => {
  const r = mapper.coverage('', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
  assert.equal(r.found, false);
  assert.equal(r.error, 'frameworkId required');
});

test('#34 a short prefix "IS" must NOT match "NIST-..." via token boundary', () => {
  const r = mapper.coverage('IS', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 null / undefined frameworkId returns found:false WITHOUT throwing', () => {
  const rn = mapper.coverage(null, 'AML.TEST', {}, atlasStub);
  assert.equal(rn.found, false);
  assert.equal(rn.error, 'frameworkId required');
  const ru = mapper.coverage(undefined, 'AML.TEST', {}, atlasStub);
  assert.equal(ru.found, false);
  assert.equal(ru.error, 'frameworkId required');
});

test('#34 hyphen-led "-X" (empty first segment) fails closed, not universal-match', () => {
  const r = mapper.coverage('-X', 'AML.TEST', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 legitimate loose framework matching still works (token-boundary, case-insensitive)', () => {
  assert.equal(mapper.coverage('NIST-800-53', 'AML.TEST', {}, atlasStub).partially_covered_by, 'NIST-800-53-X');
  assert.equal(mapper.coverage('ISO-27001-2022', 'AML.TEST', {}, atlasStub).partially_covered_by, 'iso-27001-y');
  assert.equal(mapper.coverage('SOC2-CC6', 'AML.TEST', {}, atlasStub).not_covered_by, 'soc2-z');
});

test('#34 unknown TTP still returns found:false cleanly (guard runs first, no throw)', () => {
  const r = mapper.coverage('NIST-800-53', 'AML.NOPE', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.ttp_id, 'AML.NOPE');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
