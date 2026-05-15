'use strict';

/**
 * Regression tests for audit BB P1+P2 fixes:
 *
 *   BB P1-1  — `'clean'`     override blocked when FP-downgraded
 *   BB P1-2  — `'not_detected'` override blocked when FP-downgraded
 *              (regression: `'detected'` override remains blocked)
 *   BB P1-3  — `--vex` CLI propagates vex_fixed end-to-end through to
 *              CSAF product_status.fixed + OpenVEX status:'fixed'
 *   BB P1-4  — normalizeSubmission flat-path forwards _runErrors so
 *              analyze.runtime_errors[] surfaces signal_overrides_invalid
 *   BB P2-1  — off-allowlist detection_classification surfaces a
 *              runtime_error and is not honored
 *   BB P2-2  — runtime_error redacts FP-check check-names (count only)
 *   BB P2-4  — Proxy attestation with throwing getter does NOT crash
 *              detect(); fp_attestation_threw recorded; all required
 *              checks treated as unsatisfied
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const RUNNER_PATH = path.resolve(ROOT, 'lib', 'playbook-runner.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-bb-p1-');
const cli = makeCli(SUITE_HOME);

function freshRunner(playbookDir) {
  if (playbookDir) process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  else delete process.env.EXCEPTD_PLAYBOOK_DIR;
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-bb-${label}-`));
}

function writePlaybook(dir, id, body) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body, null, 2));
}

function synthPlaybook(overrides = {}) {
  const base = {
    _meta: {
      id: 'synth',
      version: '0.1.0',
      last_threat_review: '2026-05-14',
      threat_currency_score: 95,
      changelog: [{ version: '0.1.0', date: '2026-05-14', summary: 'synthetic test playbook' }],
      owner: '@blamejs/test',
      air_gap_mode: false,
      preconditions: [],
      mutex: [],
      feeds_into: [],
    },
    domain: {
      name: 'synth domain', attack_class: 'kernel-lpe',
      atlas_refs: [], attack_refs: [], cve_refs: [], cwe_refs: [], d3fend_refs: [],
      frameworks_in_scope: ['nist-800-53'],
    },
    phases: {
      govern: { jurisdiction_obligations: [], theater_fingerprints: [], framework_context: {}, skill_preload: [] },
      direct: { threat_context: 'x', rwep_threshold: { escalate: 90, monitor: 70, close: 30 }, framework_lag_declaration: 'x', skill_chain: [], token_budget: {} },
      look: { artifacts: [], collection_scope: {}, environment_assumptions: [], fallback_if_unavailable: [] },
      detect: { indicators: [], false_positive_profile: [], minimum_signal: { detected: 'x', inconclusive: 'x', not_detected: 'x' } },
      analyze: { rwep_inputs: [], blast_radius_model: { scope_question: '?', scoring_rubric: [] }, compliance_theater_check: null, framework_gap_mapping: [], escalation_criteria: [] },
      validate: { remediation_paths: [], validation_tests: [], residual_risk_statement: null, evidence_requirements: [], regression_trigger: [] },
      close: { evidence_package: null, learning_loop: { enabled: false }, notification_actions: [], exception_generation: null, regression_schedule: null },
    },
    directives: [{ id: 'default', title: 'default directive', applies_to: { always: true } }],
  };
  return deepMerge(base, overrides);
}

function deepMerge(a, b) {
  if (b === null || b === undefined) return a;
  if (Array.isArray(b)) return b;
  if (typeof b !== 'object') return b;
  const out = { ...a };
  for (const k of Object.keys(b)) {
    if (k in out && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k]) && b[k] && typeof b[k] === 'object' && !Array.isArray(b[k])) {
      out[k] = deepMerge(out[k], b[k]);
    } else {
      out[k] = b[k];
    }
  }
  return out;
}

function indicatorWithFpChecks() {
  return {
    id: 'sig',
    type: 'log_pattern',
    value: 'x',
    description: 'd',
    confidence: 'high',
    deterministic: false,
    false_positive_checks_required: ['check-A', 'check-B'],
  };
}

// =========================================================================
// BB P1-1 — 'clean' override blocked when FP-downgraded
// =========================================================================

test("BB P1-1: 'clean' override is refused when an indicator was FP-downgraded", () => {
  const dir = tmpDir('p1-1');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [indicatorWithFpChecks()] } },
    }));
    const runner = freshRunner(dir);
    const runErrors = [];
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit' }, // no fp_checks attestation → FP-downgrade fires
      signals: { detection_classification: 'clean' }, // operator tries to hide
    }, { _runErrors: runErrors });
    assert.equal(det.classification, 'inconclusive',
      "'clean' override must be substituted to 'inconclusive' when any indicator was FP-downgraded");
    const blocked = runErrors.find(e => e.kind === 'classification_override_blocked');
    assert.ok(blocked, 'runtime_errors must include classification_override_blocked record');
    assert.equal(blocked.attempted, 'clean',
      'runtime_error.attempted must record the LITERAL override the operator submitted');
    assert.equal(blocked.substituted, 'inconclusive');
    assert.ok(Array.isArray(blocked.indicators_with_unsatisfied_fp_checks));
    assert.equal(blocked.indicators_with_unsatisfied_fp_checks.length, 1);
    // BB P2-2: redact FP check names — only count + indicator id is recorded.
    const entry = blocked.indicators_with_unsatisfied_fp_checks[0];
    assert.equal(entry.id, 'sig');
    assert.equal(typeof entry.fp_checks_unsatisfied_count, 'number');
    assert.equal(entry.fp_checks_unsatisfied_count, 2);
    assert.equal(entry.fp_checks_unsatisfied, undefined,
      'literal FP-check names must NOT appear inside the runtime_error (BB P2-2)');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P1-2 — 'not_detected' override blocked when FP-downgraded
// =========================================================================

test("BB P1-2: 'not_detected' override is refused when an indicator was FP-downgraded", () => {
  const dir = tmpDir('p1-2');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [indicatorWithFpChecks()] } },
    }));
    const runner = freshRunner(dir);
    const runErrors = [];
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit' },
      signals: { detection_classification: 'not_detected' },
    }, { _runErrors: runErrors });
    assert.equal(det.classification, 'inconclusive',
      "'not_detected' override must be substituted to 'inconclusive' when any indicator was FP-downgraded");
    const blocked = runErrors.find(e => e.kind === 'classification_override_blocked');
    assert.ok(blocked, 'runtime_errors must include classification_override_blocked record');
    assert.equal(blocked.attempted, 'not_detected');
    assert.equal(blocked.substituted, 'inconclusive');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P1-2 regression — 'detected' override still blocked when FP-downgraded
// =========================================================================

test("BB P1-2 (regression): 'detected' override remains blocked when FP-downgraded", () => {
  const dir = tmpDir('p1-2-reg');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [indicatorWithFpChecks()] } },
    }));
    const runner = freshRunner(dir);
    const runErrors = [];
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit' },
      signals: { detection_classification: 'detected' },
    }, { _runErrors: runErrors });
    assert.equal(det.classification, 'inconclusive');
    const blocked = runErrors.find(e => e.kind === 'classification_override_blocked');
    assert.ok(blocked);
    assert.equal(blocked.attempted, 'detected');
    assert.equal(blocked.substituted, 'inconclusive');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P1-4 — normalizeSubmission flat-path forwards _runErrors
// =========================================================================

test('BB P1-4: signal_overrides_invalid on a FLAT submission reaches analyze.runtime_errors[]', () => {
  const dir = tmpDir('p1-4');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [{
        id: 'sig', type: 'log_pattern', value: 'x', description: 'd',
        confidence: 'high', deterministic: false,
      }] } },
    }));
    const runner = freshRunner(dir);
    // Flat submission shape — `observations` triggers the flat-branch in
    // normalizeSubmission. signal_overrides is intentionally a non-object
    // string so normalizeSubmission's invalid-shape guard fires.
    const result = runner.run('p', 'default', {
      observations: {},
      verdict: { theater: 'actual_security' },
      signal_overrides: 'garbage',
    }, { airGap: true });
    assert.ok(result.phases, `run() must produce phases; got ${JSON.stringify(result).slice(0, 200)}`);
    const rtErrors = (result.phases.analyze && result.phases.analyze.runtime_errors) || [];
    const invalid = rtErrors.find(e => e.kind === 'signal_overrides_invalid');
    assert.ok(invalid,
      `analyze.runtime_errors[] must contain signal_overrides_invalid for FLAT submission; got: ${JSON.stringify(rtErrors)}`);
    assert.equal(invalid.supplied_type, 'string');
    assert.equal(typeof invalid.reason, 'string');
    assert.ok(invalid.reason.length > 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P2-1 — off-allowlist classification override surfaces a runtime error
// =========================================================================

test('BB P2-1: off-allowlist detection_classification value is refused and recorded', () => {
  const dir = tmpDir('p2-1');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [{
        id: 'sig', type: 'log_pattern', value: 'x', description: 'd',
        confidence: 'high', deterministic: false,
      }] } },
    }));
    const runner = freshRunner(dir);
    for (const bad of ['present', 'unknown', '', '  detected  ', 'Detected', 'DETECTED']) {
      const runErrors = [];
      const det = runner.detect('p', 'default', {
        signal_overrides: { sig: 'hit' },
        signals: { detection_classification: bad },
      }, { _runErrors: runErrors });
      const invalid = runErrors.find(e => e.kind === 'classification_override_invalid');
      assert.ok(invalid, `must record classification_override_invalid for ${JSON.stringify(bad)}`);
      assert.equal(invalid.supplied, bad,
        `runtime_error.supplied must echo the offending value exactly`);
      assert.ok(Array.isArray(invalid.allowed));
      assert.deepEqual(invalid.allowed.slice().sort(),
        ['clean', 'detected', 'inconclusive', 'not_detected']);
      // The override must NOT have driven the result.
      assert.equal(det.classification_override_applied, null,
        'classification_override_applied must be null when the override was rejected');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P2-4 — Proxy attestation with throwing getter does not crash detect()
// =========================================================================

test('BB P2-4: throwing Proxy attestation downgrades verdict + records fp_attestation_threw', () => {
  const dir = tmpDir('p2-4');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: { detect: { indicators: [indicatorWithFpChecks()] } },
    }));
    const runner = freshRunner(dir);
    // Build a Proxy whose `get` throws on every property read — simulates a
    // hostile or buggy attestation surface that JavaScript permits.
    const hostile = new Proxy({}, {
      get() { throw new Error('boom: hostile attestation getter'); },
      has() { return true; },
    });
    const runErrors = [];
    let det;
    assert.doesNotThrow(() => {
      det = runner.detect('p', 'default', {
        signal_overrides: { sig: 'hit', sig__fp_checks: hostile },
      }, { _runErrors: runErrors });
    }, 'detect() must NOT throw on a Proxy attestation with throwing getters');
    const ind = det.indicators.find(i => i.id === 'sig');
    assert.equal(ind.verdict, 'inconclusive',
      'throwing attestation must downgrade verdict to inconclusive');
    assert.ok(Array.isArray(ind.fp_checks_unsatisfied));
    assert.equal(ind.fp_checks_unsatisfied.length, 2,
      'EVERY required check must be treated as unsatisfied when attestation read throws');
    const threw = runErrors.find(e => e.kind === 'fp_attestation_threw');
    assert.ok(threw, 'runtime_errors must include fp_attestation_threw');
    assert.equal(threw.indicator_id, 'sig');
    assert.equal(typeof threw.message, 'string');
    assert.ok(threw.message.length > 0);
    assert.match(threw.message, /boom/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// BB P1-3 — --vex CLI propagates vex_fixed end-to-end through bundle emit
// =========================================================================

test('BB P1-3: --vex with OpenVEX status:fixed reaches CSAF product_status.fixed + OpenVEX status:fixed', () => {
  // Use the shipped kernel playbook because it has live-patchable matched
  // CVEs whose VEX-fixed promotion is exactly what bundle-correctness covers
  // for the analyze() direct path. This test exercises the CLI path the
  // operator actually runs.
  //
  // Prior tests above call freshRunner(dir) which sets
  // process.env.EXCEPTD_PLAYBOOK_DIR to a tmp dir; the CLI invocation below
  // inherits process.env, so the override has to be cleared before spawning
  // bin/exceptd.js or the CLI will look up `kernel` in the tmp dir and miss.
  delete process.env.EXCEPTD_PLAYBOOK_DIR;
  delete require.cache[RUNNER_PATH];
  const runner = require(RUNNER_PATH);
  // Pick the first kernel CVE so we have a real ID the analyze() pipeline
  // will correlate against.
  const kernelPb = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'playbooks', 'kernel.json'), 'utf8'));
  const cveId = kernelPb.domain.cve_refs[0];
  assert.ok(/^CVE-\d{4}-\d+$/.test(cveId), `fixture: kernel playbook must declare a CVE id; got ${cveId}`);

  // Build an OpenVEX statement marking this CVE as fixed.
  const vexPath = path.join(os.tmpdir(), `bb-p1-3-vex-${Date.now()}.json`);
  fs.writeFileSync(vexPath, JSON.stringify({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': 'https://example.invalid/vex/bb-p1-3',
    statements: [{
      vulnerability: { '@id': cveId, name: cveId },
      products: [{ '@id': 'pkg:generic/kernel' }],
      status: 'fixed',
    }],
  }, null, 2));

  // Submit evidence that correlates an indicator hit to this CVE via
  // attack_ref. The kernel playbook's `kver-in-affected-range` indicator is
  // pre-attested in this submission so no FP-downgrade fires. Request
  // multi-format bundle emission so both CSAF and OpenVEX appear.
  const submission = {
    // Kernel playbook is gated on a Linux platform precondition. Tests run on
    // any platform CI/maintainer machine — declare the preconditions
    // explicitly so the preflight gate doesn't refuse the run.
    precondition_checks: {
      'linux-platform': true,
      'uname-available': true,
    },
    signal_overrides: { 'kver-in-affected-range': 'hit' },
    signals: {
      patch_available: true,
      blast_radius_score: 3,
      _bundle_formats: ['csaf-2.0', 'openvex-0.2.0'],
    },
  };
  const sessionId = 'bb-p1-3-' + Date.now();
  try {
    // Don't use --format flags — the CLI's --format path substitutes the
    // bundle body for the run result, which would shadow the nested
    // phases.* tree this test asserts against. Submit
    // signals._bundle_formats inside the submission instead.
    const r = cli([
      'run', 'kernel', '--evidence', '-', '--vex', vexPath,
      '--session-id', sessionId, '--json',
    ], { input: JSON.stringify(submission) });
    const data = tryJson(r.stdout);
    assert.ok(data, `--vex CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.ok, true, `run must succeed; got ${JSON.stringify(data).slice(0, 400)}`);
    // BB P1-3 SHAPE assertion 1: signals.vex_fixed must have been threaded
    // through. The most authoritative downstream signal is the matched_cves
    // entry carrying vex_status:'fixed'.
    const matched = (data.phases.analyze.matched_cves || []).find(c => c.cve_id === cveId);
    assert.ok(matched, `analyze.matched_cves must include ${cveId} so vex_status can be annotated`);
    assert.equal(matched.vex_status, 'fixed',
      `matched_cves[${cveId}].vex_status must be 'fixed' (vex_fixed propagated end-to-end through the CLI)`);
    // BB P1-3 SHAPE assertion 2: the CSAF bundle must reflect product_status.fixed.
    const bundles = data.phases.close.evidence_package && data.phases.close.evidence_package.bundles_by_format;
    assert.ok(bundles, 'phases.close.evidence_package.bundles_by_format must be present');
    const csaf = bundles['csaf-2.0'];
    assert.ok(csaf, 'CSAF 2.0 bundle must be emitted when requested');
    const csafVuln = (csaf.vulnerabilities || []).find(v => v.cve === cveId);
    assert.ok(csafVuln, `CSAF vulnerabilities[] must contain ${cveId}`);
    assert.ok(csafVuln.product_status, 'CSAF vuln must carry product_status');
    assert.ok(Array.isArray(csafVuln.product_status.fixed) || csafVuln.product_status.fixed,
      `CSAF product_status.fixed must be present for ${cveId}; got ${JSON.stringify(csafVuln.product_status)}`);
    // Field-present AND content shape: must be a non-empty array.
    if (Array.isArray(csafVuln.product_status.fixed)) {
      assert.ok(csafVuln.product_status.fixed.length > 0,
        'CSAF product_status.fixed must be non-empty');
    }
    // BB P1-3 SHAPE assertion 3: OpenVEX statement must carry status:'fixed'.
    const ovex = bundles['openvex-0.2.0'];
    assert.ok(ovex, 'OpenVEX 0.2.0 bundle must be emitted when requested');
    const ovexStmt = (ovex.statements || []).find(s => s.vulnerability && (s.vulnerability.name === cveId || s.vulnerability['@id'] === cveId));
    assert.ok(ovexStmt, `OpenVEX statements[] must contain ${cveId}`);
    assert.equal(ovexStmt.status, 'fixed',
      `OpenVEX statement for ${cveId} must carry status:'fixed' (vex_fixed propagated end-to-end through the CLI)`);
  } finally {
    try { fs.unlinkSync(vexPath); } catch { /* non-fatal */ }
  }
});
