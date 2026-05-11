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
