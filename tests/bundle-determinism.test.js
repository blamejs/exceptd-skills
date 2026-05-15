'use strict';

/**
 * v0.12.27: opt-in deterministic bundle emit. When
 * runOpts.bundleDeterministic === true, CSAF / OpenVEX / close-envelope
 * timestamps freeze to a single epoch, the auto-generated session_id
 * derives from sha256(playbook + submission_digest + engine_version), and
 * vulnerabilities[] / OpenVEX statements[] sort ascending by primary id.
 *
 * Default mode (no flag) MUST remain byte-identical to pre-v0.12.27
 * output — these tests pin both directions.
 *
 * Run under: node --test --test-concurrency=1 tests/
 */

const test = require('node:test');
const { describe, it, before } = test;
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'exceptd.js');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// Shared submission (kernel playbook, one indicator forced to hit so the
// run produces a real CSAF / OpenVEX body with vulnerabilities and
// statements to inspect).
function baselineSubmission() {
  return {
    signal_overrides: { 'kver-in-affected-range': 'hit' },
    signals: {
      _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0'],
      patch_available: false,
      blast_radius_score: 3,
    },
  };
}

// kernel playbook gates on linux-platform; tests run on any host so the
// precondition is pre-stamped via runOpts.precondition_checks (engine
// supports the override + records it as `runOpts` provenance).
const KERNEL_PC_OVERRIDES = {
  'linux-platform': true,
  'uname-available': true,
};

function runOnce(runOpts) {
  const runner = loadRunner();
  const merged = Object.assign({}, runOpts || {}, {
    precondition_checks: Object.assign(
      {}, KERNEL_PC_OVERRIDES, (runOpts && runOpts.precondition_checks) || {}
    ),
  });
  return runner.run('kernel', 'all-catalogued-kernel-cves', baselineSubmission(), merged);
}

describe('v0.12.27 deterministic bundle emit', () => {
  it('Test 1: two deterministic runs with the same epoch produce byte-identical bundles', () => {
    const opts = { bundleDeterministic: true, bundleEpoch: '2026-01-01T00:00:00Z' };
    const r1 = runOnce(opts);
    const r2 = runOnce(opts);
    assert.equal(r1.ok, true);
    assert.equal(r2.ok, true);
    // Sanity: session_ids are the same too (deterministic derivation).
    assert.equal(r1.session_id, r2.session_id);
    const csaf1 = r1.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const csaf2 = r2.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(JSON.stringify(csaf1), JSON.stringify(csaf2));
    const vex1 = r1.phases.close.evidence_package.bundles_by_format['openvex-0.2.0'];
    const vex2 = r2.phases.close.evidence_package.bundles_by_format['openvex-0.2.0'];
    assert.equal(JSON.stringify(vex1), JSON.stringify(vex2));
    // CSAF tracking timestamps frozen to the supplied epoch.
    assert.equal(csaf1.document.tracking.initial_release_date, '2026-01-01T00:00:00.000Z');
    assert.equal(csaf1.document.tracking.current_release_date, '2026-01-01T00:00:00.000Z');
    assert.equal(csaf1.document.tracking.generator.date, '2026-01-01T00:00:00.000Z');
    assert.equal(csaf1.document.tracking.revision_history[0].date, '2026-01-01T00:00:00.000Z');
    // OpenVEX timestamps frozen.
    assert.equal(vex1.timestamp, '2026-01-01T00:00:00.000Z');
    for (const stmt of vex1.statements) {
      assert.equal(stmt.timestamp, '2026-01-01T00:00:00.000Z');
    }
  });

  it('Test 2: different --bundle-epoch values produce different bundle bytes', () => {
    const r1 = runOnce({ bundleDeterministic: true, bundleEpoch: '2026-01-01T00:00:00Z' });
    const r2 = runOnce({ bundleDeterministic: true, bundleEpoch: '2026-06-01T00:00:00Z' });
    const csaf1 = r1.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const csaf2 = r2.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf1.document.tracking.initial_release_date, '2026-01-01T00:00:00.000Z');
    assert.equal(csaf2.document.tracking.initial_release_date, '2026-06-01T00:00:00.000Z');
    assert.equal(csaf1.document.tracking.current_release_date, '2026-01-01T00:00:00.000Z');
    assert.equal(csaf2.document.tracking.current_release_date, '2026-06-01T00:00:00.000Z');
    // Vulnerabilities[] content is identical (same evidence).
    assert.equal(
      JSON.stringify(csaf1.vulnerabilities),
      JSON.stringify(csaf2.vulnerabilities)
    );
  });

  it('Test 3: deterministic + different evidence keeps timestamps frozen but vulnerability set differs', () => {
    const opts = {
      bundleDeterministic: true,
      bundleEpoch: '2026-01-01T00:00:00Z',
      precondition_checks: KERNEL_PC_OVERRIDES,
    };
    // Baseline: one indicator hit, no synthetic CVE filter.
    const runner = loadRunner();
    const subA = baselineSubmission();
    const subB = baselineSubmission();
    // Force a different signal verdict to change matched_cves count.
    subB.signal_overrides['kver-in-affected-range'] = 'miss';
    const rA = runner.run('kernel', 'all-catalogued-kernel-cves', subA, opts);
    const rB = runner.run('kernel', 'all-catalogued-kernel-cves', subB, opts);
    const csafA = rA.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const csafB = rB.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    // Timestamps still frozen across runs.
    assert.equal(csafA.document.tracking.initial_release_date, '2026-01-01T00:00:00.000Z');
    assert.equal(csafB.document.tracking.initial_release_date, '2026-01-01T00:00:00.000Z');
    // Different evidence → different content (typically different vuln
    // counts when an indicator flips hit→miss).
    assert.notEqual(
      JSON.stringify(csafA.vulnerabilities),
      JSON.stringify(csafB.vulnerabilities)
    );
  });

  it('Test 4: default mode (no flag) keeps timestamps wall-clock-driven', () => {
    const r1 = runOnce({});
    // A 5ms gap before the second run guarantees `Date.now()` advances
    // even on Windows' coarse-ish clock (15ms granularity is the worst
    // case; the runner builds three full phases between runs so the
    // sub-15ms collision is improbable). Re-loading the runner module is
    // synchronous + cheap, so the wait is the only delay needed.
    const start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    const r2 = runOnce({});
    const csaf1 = r1.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const csaf2 = r2.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    // The deterministic path is opt-in; without the flag, two runs must
    // diverge on tracking.initial_release_date.
    assert.notEqual(
      csaf1.document.tracking.initial_release_date,
      csaf2.document.tracking.initial_release_date
    );
  });

  it('Test 5: --bundle-epoch invalid ISO refuses at the CLI with structured error', () => {
    const r = spawnSync(process.execPath, [
      CLI_PATH, 'run', 'kernel',
      '--bundle-deterministic', '--bundle-epoch', 'not-a-real-date',
      '--json',
    ], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    // stderr carries the structured ok:false body (emitError pattern).
    const body = JSON.parse(r.stderr.trim().split('\n').filter(Boolean).pop());
    assert.equal(body.ok, false);
    assert.match(body.error, /bundle-epoch.*ISO/);
    assert.equal(body.verb, 'run');
    assert.equal(body.flag, 'bundle-epoch');
  });

  it('Test 6: --bundle-deterministic without --bundle-epoch falls back to playbook last_threat_review', () => {
    const runner = loadRunner();
    const pb = runner.loadPlaybook('kernel');
    const ltr = pb._meta.last_threat_review;
    assert.ok(typeof ltr === 'string' && ltr.length > 0,
      'kernel playbook must declare last_threat_review for this test to be meaningful');
    const r = runOnce({ bundleDeterministic: true });
    assert.equal(r.ok, true);
    const csaf = r.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const expected = new Date(ltr).toISOString();
    assert.equal(csaf.document.tracking.initial_release_date, expected);
    assert.equal(csaf.document.tracking.current_release_date, expected);
  });

  it('Test 7: deterministic mode sorts vulnerabilities[] ascending by primary id', () => {
    // kernel playbook surfaces every catalogued kernel CVE when
    // `kver-in-affected-range` fires hit. With deterministic mode on,
    // the resulting CSAF vulnerabilities[] array must be sorted ascending
    // by cve_id / ids[0].text regardless of catalog enumeration order.
    const r = runOnce({ bundleDeterministic: true, bundleEpoch: '2026-01-01T00:00:00Z' });
    assert.equal(r.ok, true);
    const csaf = r.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const ids = csaf.vulnerabilities.map(v =>
      (typeof v.cve === 'string' && v.cve) ||
      (Array.isArray(v.ids) && v.ids[0] && v.ids[0].text) || ''
    );
    // ≥ 2 entries is the smallest set where the sort assertion can bite.
    assert.ok(ids.length >= 2,
      `kernel run must surface ≥ 2 vulnerabilities for the sort assertion to bite (got ${ids.length})`);
    const sorted = ids.slice().sort((a, b) => a.localeCompare(b));
    assert.deepEqual(ids, sorted);
  });
});
