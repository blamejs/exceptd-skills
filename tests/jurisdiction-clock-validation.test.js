'use strict';

/**
 * Tests for the jurisdictional-clock input handling in lib/playbook-runner.js.
 *
 * Runs under: node --test --test-concurrency=1
 *
 * Three behaviors are covered:
 *
 *   1. A malformed operator-supplied clock_started_at_<event> ISO string must
 *      NOT crash close()/run(). It degrades to the pending-clock branch
 *      (deadline 'pending_clock_start_event', clock_started_at null) and
 *      surfaces an invalid_clock_value runtime error naming the offending key.
 *
 *   2. A zone-less timestamp ('2026-06-12T10:00:00' or its space-separated
 *      form) is interpreted as UTC deterministically, regardless of the host
 *      timezone, so a statutory deadline does not shift by the host's UTC
 *      offset. An explicit-Z value is unchanged.
 *
 *   3. analyze_complete / validate_complete clocks auto-start under operator
 *      acknowledgement (--ack) once their engine phase has run, and report
 *      clock_pending_ack without it.
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));

// mcp declares EU/DORA Art.19 (4h) and EU/NIS2 Art.23 (24h), both
// clock_starts:'detect_confirmed'. ai-api additionally declares
// analyze_complete and validate_complete obligations.
const MCP = 'mcp';
const MCP_DIR = 'all-mcp-servers-trust-audit';
const AIAPI = 'ai-api';
const AIAPI_DIR = 'all-ai-api-and-credential-exposure';

function findRunErrors(result) {
  // The shared runtime-error accumulator is snapshotted onto the analyze
  // phase's runtime_errors after every phase (including close) has run.
  return (result && result.phases && result.phases.analyze && result.phases.analyze.runtime_errors) || [];
}

describe('jurisdictional clock — malformed operator timestamp', () => {
  it('run() does not throw on an unparseable clock value and degrades to pending', () => {
    let result;
    assert.doesNotThrow(() => {
      result = runner.run(MCP, MCP_DIR, {
        signals: { clock_started_at_detect_confirmed: 'not-a-date', detection_classification: 'detected' },
        artifacts: {},
      }, { operator_consent: { explicit: true } });
    });
    assert.equal(result.ok, true);
    const nis2 = result.phases.close.jurisdiction_notifications.find(
      n => /NIS2/.test(n.obligation_ref) && n.clock_start_event === 'detect_confirmed');
    assert.ok(nis2, 'NIS2 detect_confirmed notification present');
    assert.equal(nis2.deadline, 'pending_clock_start_event');
    assert.equal(nis2.clock_started_at, null);
  });

  it('surfaces an invalid_clock_value runtime error naming the offending key', () => {
    const result = runner.run(MCP, MCP_DIR, {
      signals: { clock_started_at_detect_confirmed: 'not-a-date', detection_classification: 'detected' },
      artifacts: {},
    }, { operator_consent: { explicit: true } });
    const errs = findRunErrors(result);
    const bad = errs.find(e => e.kind === 'invalid_clock_value');
    assert.ok(bad, 'invalid_clock_value runtime error present');
    assert.equal(bad.key, 'clock_started_at_detect_confirmed');
    assert.equal(bad.clock_event, 'detect_confirmed');
  });

  it('close() does not throw on a month-13 garbage value (analyze_complete path)', () => {
    const errs = [];
    // computeClockStart returns null for an unparseable value, never an
    // Invalid Date, so the downstream deadline math cannot reach toISOString().
    const d = runner._computeClockStart('analyze_complete',
      { clock_started_at_analyze_complete: '2026-13-99' }, { _runErrors: errs });
    assert.equal(d, null);
    assert.equal(errs.filter(e => e.kind === 'invalid_clock_value').length, 1);

    const d2 = runner._computeClockStart('validate_complete',
      { clock_started_at_validate_complete: '2026-13-99' }, { _runErrors: errs });
    assert.equal(d2, null);
  });
});

describe('jurisdictional clock — timezone determinism', () => {
  it('a zone-less timestamp is read as UTC, not the host timezone', () => {
    const saved = process.env.TZ;
    process.env.TZ = 'America/Los_Angeles';
    try {
      const out = runner.close(MCP, MCP_DIR,
        { matched_cves: [], rwep: { adjusted: 0 }, blast_radius_score: null, framework_gap_mapping: [], _detect_indicators: [], _detect_classification: 'detected', compliance_theater_check: { verdict: 'present' } },
        { regression_next_run: null },
        { clock_started_at_detect_confirmed: '2026-06-12T10:00:00', detection_classification: 'detected' },
        { session_id: 'abcdef0123456789', operator_consent: { explicit: true } });
      const dora = out.jurisdiction_notifications.find(n => /DORA/.test(n.obligation_ref));
      assert.ok(dora, 'DORA 4h obligation present');
      // 10:00 UTC, not the host-shifted 17:00Z that new Date() would produce.
      assert.equal(dora.clock_started_at, '2026-06-12T10:00:00.000Z');
      // DORA's 4h window lands at 14:00 UTC, not 21:00 UTC.
      assert.equal(dora.deadline, '2026-06-12T14:00:00.000Z');
    } finally {
      if (saved === undefined) delete process.env.TZ; else process.env.TZ = saved;
    }
  });

  it('the space-separated form normalizes identically to the T-separated UTC value', () => {
    const saved = process.env.TZ;
    process.env.TZ = 'America/Los_Angeles';
    try {
      // Drive through the exported computeClockStart for an exact-instant check.
      const d = runner._computeClockStart('detect_confirmed',
        { clock_started_at_detect_confirmed: '2026-06-12 10:00:00' }, { _runErrors: [] });
      assert.ok(d instanceof Date);
      assert.equal(d.toISOString(), '2026-06-12T10:00:00.000Z');
    } finally {
      if (saved === undefined) delete process.env.TZ; else process.env.TZ = saved;
    }
  });

  it('an explicit-Z timestamp is unchanged and emits no assumed-UTC warning', () => {
    const saved = process.env.TZ;
    process.env.TZ = 'America/Los_Angeles';
    try {
      const errs = [];
      const d = runner._computeClockStart('detect_confirmed',
        { clock_started_at_detect_confirmed: '2026-06-12T10:00:00Z' }, { _runErrors: errs });
      assert.equal(d.toISOString(), '2026-06-12T10:00:00.000Z');
      assert.equal(errs.filter(e => e.kind === 'clock_timezone_assumed_utc').length, 0);
    } finally {
      if (saved === undefined) delete process.env.TZ; else process.env.TZ = saved;
    }
  });

  it('a zone-less value surfaces a clock_timezone_assumed_utc runtime error', () => {
    const errs = [];
    runner._computeClockStart('detect_confirmed',
      { clock_started_at_detect_confirmed: '2026-06-12T10:00:00' }, { _runErrors: errs });
    const warn = errs.find(e => e.kind === 'clock_timezone_assumed_utc');
    assert.ok(warn, 'clock_timezone_assumed_utc runtime error present');
    assert.equal(warn.key, 'clock_started_at_detect_confirmed');
  });
});

describe('jurisdictional clock — analyze_complete / validate_complete auto-start', () => {
  it('auto-starts analyze_complete and validate_complete clocks under --ack once their phase ran', () => {
    const result = runner.run(AIAPI, AIAPI_DIR, {
      signals: { detection_classification: 'detected' }, artifacts: {},
    }, { operator_consent: { explicit: true } });
    const notifs = result.phases.close.jurisdiction_notifications;

    const ac = notifs.find(n => n.clock_start_event === 'analyze_complete');
    assert.ok(ac, 'analyze_complete obligation present');
    assert.equal(typeof ac.clock_started_at, 'string');
    assert.notEqual(ac.deadline, 'pending_clock_start_event');
    // deadline === clock_started_at + window_hours.
    const expectedAc = new Date(new Date(ac.clock_started_at).getTime() + ac.window_hours * 3600 * 1000).toISOString();
    assert.equal(ac.deadline, expectedAc);

    const vc = notifs.find(n => n.clock_start_event === 'validate_complete');
    assert.ok(vc, 'validate_complete obligation present');
    assert.equal(typeof vc.clock_started_at, 'string');
    const expectedVc = new Date(new Date(vc.clock_started_at).getTime() + vc.window_hours * 3600 * 1000).toISOString();
    assert.equal(vc.deadline, expectedVc);
  });

  it('analyze_complete / validate_complete auto-start clocks root in the frozen epoch under deterministic mode', () => {
    const EPOCH = '2021-06-01T00:00:00.000Z';
    const runOpts = { operator_consent: { explicit: true }, bundleDeterministic: true, bundleEpoch: EPOCH };
    const run = () => runner.run(AIAPI, AIAPI_DIR, {
      signals: { detection_classification: 'detected' }, artifacts: {},
    }, runOpts);

    const a = run();
    const acA = a.phases.close.jurisdiction_notifications.find(n => n.clock_start_event === 'analyze_complete');
    const vcA = a.phases.close.jurisdiction_notifications.find(n => n.clock_start_event === 'validate_complete');
    assert.equal(acA.clock_started_at, EPOCH, 'analyze_complete clock must be the frozen epoch, not wall-clock now');
    assert.equal(vcA.clock_started_at, EPOCH, 'validate_complete clock must be the frozen epoch, not wall-clock now');

    // Reproducibility: a second deterministic run over the same evidence emits
    // identical clock_started_at and deadline values.
    const b = run();
    const acB = b.phases.close.jurisdiction_notifications.find(n => n.clock_start_event === 'analyze_complete');
    assert.equal(acB.clock_started_at, acA.clock_started_at, 'two deterministic runs must agree on clock_started_at');
    assert.equal(acB.deadline, acA.deadline, 'two deterministic runs must agree on the deadline');
  });

  it('without --ack the analyze_complete clock reports pending + clock_pending_ack', () => {
    const result = runner.run(AIAPI, AIAPI_DIR, {
      signals: { detection_classification: 'detected' }, artifacts: {},
    }, {});
    const ac = result.phases.close.jurisdiction_notifications.find(n => n.clock_start_event === 'analyze_complete');
    assert.ok(ac, 'analyze_complete obligation present');
    assert.equal(ac.deadline, 'pending_clock_start_event');
    assert.equal(ac.clock_started_at, null);
    assert.equal(ac.clock_pending_ack, true);
  });

  it('manual clocks never auto-start even under --ack', () => {
    const d = runner._computeClockStart('manual', {},
      { operator_consent: { explicit: true }, _runErrors: [] }, 'detected',
      { analyze_complete: true, validate_complete: true });
    assert.equal(d, null);
  });
});
