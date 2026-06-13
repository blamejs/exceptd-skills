'use strict';

/**
 * Tests for the VEX disposition prose in analyze() (lib/playbook-runner.js).
 *
 * Runs under: node --test --test-concurrency=1
 *
 * The drop-note explains WHY a CVE was removed from analyze. It is keyed on the
 * drop set only — CycloneDX not_affected / false_positive and OpenVEX
 * not_affected. A vendor-fixed disposition (CycloneDX state:'resolved' /
 * OpenVEX status:'fixed') is a KEEP disposition: the CVE stays in matched_cves
 * annotated vex_status:'fixed'. The note must therefore NOT cite that keep
 * disposition as a drop reason, and the kept-fixed set must be surfaced so the
 * two dispositions are distinguishable.
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));

// ai-api enumerates these two CVEs in domain.cve_refs.
const AIAPI = 'ai-api';
const AIAPI_DIR = 'all-ai-api-and-credential-exposure';
const DROP_CVE = 'CVE-2026-30615';   // marked not_affected → drop
const FIXED_CVE = 'CVE-2026-42208';  // marked resolved/fixed → keep

function analyzeWithVex(sets) {
  return runner.analyze(AIAPI, AIAPI_DIR,
    { indicators: [], classification: 'detected' },
    { vex_filter: sets, vex_fixed: sets.fixed }, {});
}

describe('VEX drop-note (CycloneDX)', () => {
  const doc = {
    vulnerabilities: [
      { id: DROP_CVE, analysis: { state: 'not_affected' } },
      { id: FIXED_CVE, analysis: { state: 'resolved' } },
    ],
  };

  it('routes not_affected → drop and resolved → fixed', () => {
    const sets = runner.vexFilterFromDoc(doc);
    assert.deepEqual([...sets], [DROP_CVE]);
    assert.deepEqual([...sets.fixed], [FIXED_CVE]);
  });

  it('drops only the not_affected CVE; the resolved CVE is kept', () => {
    const sets = runner.vexFilterFromDoc(doc);
    const out = analyzeWithVex(sets);
    assert.equal(out.vex.dropped_cve_count, 1);
    assert.deepEqual(out.vex.dropped_cves, [DROP_CVE]);
    // The vendor-fixed CVE never enters the drop set.
    assert.ok(!out.vex.dropped_cves.includes(FIXED_CVE));
  });

  it('surfaces the kept-fixed set distinctly from the drop set', () => {
    const sets = runner.vexFilterFromDoc(doc);
    const out = analyzeWithVex(sets);
    assert.equal(out.vex.fixed_cve_count, 1);
    assert.deepEqual(out.vex.fixed_cves, [FIXED_CVE]);
  });

  it('the drop note does NOT cite a keep disposition as a drop reason', () => {
    const sets = runner.vexFilterFromDoc(doc);
    const out = analyzeWithVex(sets);
    // "resolved" (CycloneDX) is a KEEP disposition and must not appear as a
    // drop reason in the note.
    assert.ok(!/resolved/.test(out.vex.note), `drop note still lists a keep disposition: ${out.vex.note}`);
    // The note still names the actual drop dispositions.
    assert.match(out.vex.note, /not_affected/);
    assert.match(out.vex.note, /false_positive/);
  });
});

describe('VEX drop-note (OpenVEX)', () => {
  const doc = {
    statements: [
      { vulnerability: { name: DROP_CVE }, status: 'not_affected' },
      { vulnerability: { name: FIXED_CVE }, status: 'fixed' },
    ],
  };

  it('mirrors the CycloneDX split: not_affected drops, fixed is kept', () => {
    const sets = runner.vexFilterFromDoc(doc);
    assert.deepEqual([...sets], [DROP_CVE]);
    assert.deepEqual([...sets.fixed], [FIXED_CVE]);
    const out = analyzeWithVex(sets);
    assert.equal(out.vex.dropped_cve_count, 1);
    assert.deepEqual(out.vex.dropped_cves, [DROP_CVE]);
    assert.deepEqual(out.vex.fixed_cves, [FIXED_CVE]);
    assert.ok(!/resolved/.test(out.vex.note));
  });
});
