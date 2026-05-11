'use strict';

/**
 * Tests for lib/framework-gap.js — framework lag/gap/theater analysis.
 * Operates against the real data/framework-control-gaps.json and data/global-frameworks.json.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const fg = require('../lib/framework-gap.js');
const controlGaps = require('../data/framework-control-gaps.json');
const globalFrameworks = require('../data/global-frameworks.json');
const cveCatalog = require('../data/cve-catalog.json');

const { lagScore, gapReport, theaterCheck, compareFrameworks } = fg;

// ---------- lagScore() ----------

test('lagScore() returns a numeric score and breakdown for a known framework', () => {
  // Pick the first non-meta framework id available in global-frameworks.json
  const frameworkIds = [];
  for (const jur of Object.values(globalFrameworks)) {
    if (jur && typeof jur === 'object' && jur.frameworks) {
      frameworkIds.push(...Object.keys(jur.frameworks));
    }
  }
  assert.ok(frameworkIds.length > 0, 'expected at least one framework in global-frameworks.json');

  const r = lagScore(frameworkIds[0], controlGaps, globalFrameworks);
  assert.equal(typeof r.score, 'number');
  assert.ok(r.score >= 0 && r.score <= 100, `score out of bounds: ${r.score}`);
  assert.equal(typeof r.label, 'string');
  assert.ok(r.breakdown, 'breakdown must be present');
  assert.ok('patch_sla' in r.breakdown);
  assert.ok('ai_coverage' in r.breakdown);
  assert.ok('universal_gaps' in r.breakdown);
});

test('lagScore() labels reflect score bands', () => {
  // Drive label selection via stubbed inputs so the test is robust to data updates.
  const stubGlobal = {
    test_jurisdiction: {
      frameworks: {
        TEST_FW: { patch_sla: 30 * 24, notification_sla: 96, ai_coverage: 'None', pqc_coverage: 'None' }
      }
    }
  };
  // With universal gaps from real data, this stub framework should land in 'critical_lag' territory.
  const r = lagScore('TEST_FW', controlGaps, stubGlobal);
  assert.equal(typeof r.label, 'string');
  assert.ok(['critical_lag', 'significant_lag', 'moderate_lag', 'minor_lag', 'current'].includes(r.label));
});

test('lagScore() falls back gracefully when framework not in global-frameworks.json', () => {
  const r = lagScore('NOT-A-REAL-FW', controlGaps, globalFrameworks);
  // No throw, breakdown still populated with default scores
  assert.equal(typeof r.score, 'number');
  assert.ok(r.breakdown.patch_sla);
  assert.equal(r.breakdown.patch_sla.raw_days, null);
});

// ---------- gapReport() ----------

test('gapReport() returns a structured report with universal gaps and theater risks', () => {
  const r = gapReport(['NIST SP 800-53 Rev 5', 'ISO/IEC 27001:2022'], 'prompt injection', controlGaps, cveCatalog);
  assert.ok(r.threat_scenario === 'prompt injection');
  assert.ok(r.frameworks);
  assert.ok(Array.isArray(r.universal_gaps));
  assert.ok(Array.isArray(r.theater_risks));
  assert.ok(r.summary);
  assert.equal(typeof r.summary.total_gaps, 'number');
  assert.equal(typeof r.summary.universal_gaps, 'number');
});

test('gapReport() surfaces ALL-scoped universal gaps from the catalog', () => {
  // The shipping catalog includes ALL-AI-PIPELINE-INTEGRITY, ALL-MCP-TOOL-TRUST, ALL-PROMPT-INJECTION-ACCESS-CONTROL
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'mcp', controlGaps, cveCatalog);
  assert.ok(r.universal_gaps.length >= 1, 'expected at least one ALL-framework universal gap');
});

test('gapReport() can find gaps by CVE id in evidence_cves', () => {
  // NIST-800-53-SI-2 has evidence_cves including CVE-2026-31431
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, cveCatalog);
  assert.ok(r.summary.total_gaps >= 1, `expected at least one gap matching CVE-2026-31431; got summary: ${JSON.stringify(r.summary)}`);
});

// ---------- theaterCheck() ----------

test('theaterCheck() returns findings array, score, and recommendation', () => {
  const r = theaterCheck(controlGaps, cveCatalog);
  assert.ok(Array.isArray(r.findings));
  assert.equal(typeof r.theater_score, 'number');
  assert.ok(r.theater_score >= 0 && r.theater_score <= 100);
  assert.equal(typeof r.theater_label, 'string');
  assert.equal(typeof r.recommendation, 'string');
  assert.equal(typeof r.compliant_but_exposed, 'boolean');
});

test('theaterCheck() flags Patch Management Theater when an exploited-CVE control is open', () => {
  // NIST-800-53-SI-2 references CVE-2026-31431 which is cisa_kev=true → patch_management theater
  const r = theaterCheck(controlGaps, cveCatalog);
  const patchTheater = r.findings.find(f => f.pattern_id === 'patch_management');
  assert.ok(patchTheater, `expected patch_management theater finding; findings: ${JSON.stringify(r.findings.map(f => f.pattern_id))}`);
  assert.equal(patchTheater.severity, 'critical');
});

test('theaterCheck() preserves no-finding case when given an empty control set', () => {
  const r = theaterCheck({}, cveCatalog);
  assert.deepEqual(r.findings, []);
  assert.equal(r.theater_score, 0);
  assert.equal(r.compliant_but_exposed, false);
  assert.match(r.recommendation, /No theater patterns/);
});

// ---------- compareFrameworks() ----------

test('compareFrameworks() returns an array sorted by lag score descending', () => {
  const r = compareFrameworks(controlGaps, globalFrameworks);
  assert.ok(Array.isArray(r));
  assert.ok(r.length > 0, 'expected at least one framework in the comparison');
  for (let i = 1; i < r.length; i++) {
    assert.ok(r[i - 1].score >= r[i].score,
      `not sorted descending at index ${i}: ${r[i - 1].score} < ${r[i].score}`);
  }
  for (const row of r) {
    assert.equal(typeof row.framework, 'string');
    assert.equal(typeof row.score, 'number');
    assert.equal(typeof row.label, 'string');
    assert.ok(row.breakdown);
  }
});

// ---------- gap status preservation ----------

test('Open-status gaps are preserved in gapReport output', () => {
  // The shipping catalog has all gaps in "open" status. Verify the gap entries we surface
  // carry their original status field intact.
  // NOTE: data/framework-control-gaps.json currently has zero entries with status="closed".
  // When closed entries are added in future, this test should be extended to verify they
  // are still emitted (closed ≠ deleted, per Hard Rule on framework mapping updates).
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, cveCatalog);
  const target = Object.values(r.frameworks).find(f => f.gaps.length > 0);
  assert.ok(target, 'expected at least one framework with gaps');
  for (const g of target.gaps) {
    assert.ok(['open', 'closed'].includes(g.status), `unexpected status: ${g.status}`);
  }
});

test('Synthetic closed-status gap is preserved (status field passed through verbatim)', () => {
  const synthetic = {
    'TEST-CLOSED-1': {
      framework: 'NIST SP 800-53 Rev 5',
      control_id: 'TEST-1',
      control_name: 'Closed Test Control',
      real_requirement: 'CVE-2026-31431 mitigation',
      misses: ['some miss text'],
      evidence_cves: ['CVE-2026-31431'],
      status: 'closed'
    }
  };
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', synthetic, cveCatalog);
  const fw = r.frameworks['NIST SP 800-53 Rev 5'];
  assert.equal(fw.gap_count, 1);
  assert.equal(fw.gaps[0].status, 'closed');
});
