'use strict';

/**
 * Scheduler INT32 overflow guard.
 *
 * Node coerces setTimeout / setInterval delays to a signed 32-bit integer.
 * Any delay above 2^31 - 1 ms (~24.8 days) is silently clamped to 1 ms,
 * which causes the handler to fire ~1000×/sec — a stdout flood that
 * exhausts the event loop. `scheduleEvery` wraps the underlying timer
 * with a bounded tick interval and compares wall-clock elapsed time
 * against the requested interval, so over-INT32 delays behave correctly.
 *
 * These tests verify:
 *   1. A delay above SAFE_MAX_MS does NOT emit Node's TimeoutOverflowWarning.
 *   2. The handler does NOT fire more than once within real wall time
 *      shorter than the requested interval.
 *   3. The unschedule callback stops further firings.
 *   4. A short interval still fires repeatedly as expected (sanity).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { scheduleEvery, SAFE_MAX_MS } = require('../orchestrator/scheduler');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

test('scheduleEvery: SAFE_MAX_MS + 1 emits no TimeoutOverflowWarning and does not fire spuriously', async () => {
  const warnings = [];
  const onWarning = (w) => {
    if (w && w.name === 'TimeoutOverflowWarning') warnings.push(w);
  };
  process.on('warning', onWarning);

  let fired = 0;
  const off = scheduleEvery(SAFE_MAX_MS + 1, () => { fired += 1; });

  try {
    // Real wall time is ~300 ms; the requested interval is ~24.8 days +
    // 1 ms. The handler must not fire even once in that window.
    await sleep(300);
    assert.equal(fired, 0, 'handler must not fire within 300 ms when interval is > SAFE_MAX_MS');
    assert.equal(warnings.length, 0, 'no TimeoutOverflowWarning must be emitted for over-INT32 intervals');
  } finally {
    off();
    process.off('warning', onWarning);
  }
});

test('scheduleEvery: short interval fires repeatedly', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => { fired += 1; });
  try {
    await sleep(150);
    assert.ok(fired >= 3, `expected handler to fire at least 3 times in 150 ms with 20 ms interval, got ${fired}`);
  } finally {
    off();
  }
});

test('scheduleEvery: returned unschedule callback stops further firings', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => { fired += 1; });
  await sleep(80);
  const firedAtStop = fired;
  off();
  await sleep(120);
  // Allow at most one extra fire that may have been in-flight at the
  // moment off() ran; any larger growth means the timer kept ticking.
  assert.ok(
    fired - firedAtStop <= 1,
    `handler kept firing after unschedule: ${firedAtStop} -> ${fired}`
  );
});

test('scheduleEvery: handler errors are caught and do not break the timer', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => {
    fired += 1;
    throw new Error('boom');
  });
  // Silence the console.error noise from the catch block; the test
  // listener is enough.
  const origErr = console.error;
  console.error = () => {};
  try {
    await sleep(120);
    assert.ok(fired >= 2, `timer must keep ticking after handler throws (fired=${fired})`);
  } finally {
    console.error = origErr;
    off();
  }
});


// ---- routed from playbook-schema-validation ----
require("node:test").describe("playbook-schema-validation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression tests for the v0.12.20 audit S+T+U+Z P1 fixes.
 *
 *   S P1-A — Array attestation must NOT bypass the FP-check gate.
 *   S P1-B — `signals.detection_classification: 'detected'` override must be
 *            refused when ANY indicator was downgraded due to unattested FP
 *            checks; a runtime_error documents the refusal.
 *   U REG-1 — `signal_overrides_invalid` errors pushed by normalizeSubmission
 *            must reach analyze.runtime_errors[] (F20 contract).
 *   T P1-1 — withCatalogLock / withIndexLock must reclaim a lockfile whose
 *            PID is dead (ESRCH) without waiting STALE_LOCK_MS.
 *   T P1-2 — persistAttestation --force-overwrite must serialize concurrent
 *            writers so the prior_evidence_hash chain does not lose
 *            intermediate writers.
 *   T P1-3 — prefetch must NOT leave a payload on disk with no index entry
 *            when withIndexLock fails.
 *   T P1-4 — scheduleEvery must throw RangeError on 0 / negative / NaN /
 *            Infinity intervals.
 *
 * Concurrency tests use real subprocess invocation + race contention.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync, fork } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const RUNNER_PATH = path.resolve(ROOT, 'lib', 'playbook-runner.js');

// --- helpers --------------------------------------------------------------

function freshRunner(playbookDir) {
  if (playbookDir) process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  else delete process.env.EXCEPTD_PLAYBOOK_DIR;
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-stuz-${label}-`));
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

// =========================================================================
// S P1-A — Array attestation bypasses FP-check gate
// =========================================================================


// =========================================================================
// S P1-B — `detection_classification: 'detected'` override cannot bypass FP downgrade
// =========================================================================



// =========================================================================
// U REG-1 — signal_overrides_invalid must reach analyze.runtime_errors[]
// =========================================================================


// =========================================================================
// T P1-1 — PID-liveness check on stale lockfiles
// =========================================================================


// =========================================================================
// T P1-2 — persistAttestation force-overwrite serializes concurrent writers
// =========================================================================


// =========================================================================
// T P1-3 — prefetch must NOT orphan a payload on lock failure
// =========================================================================


// =========================================================================
// T P1-4 — scheduleEvery lower-bound guard
// =========================================================================

test('T P1-4: scheduleEvery rejects 0 / negative / NaN / Infinity intervals', () => {
  // Re-require with cache drop so the new guard is in effect.
  delete require.cache[require.resolve('../orchestrator/scheduler.js')];
  const { scheduleEvery } = require('../orchestrator/scheduler.js');

  for (const bad of [0, -1, -100, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(
      () => scheduleEvery(bad, () => {}),
      (err) => err instanceof RangeError && /positive finite number/.test(err.message),
      `scheduleEvery(${bad}) must throw RangeError`
    );
  }
  // Sanity: a valid interval still returns an unscheduler.
  const off = scheduleEvery(10_000, () => {});
  assert.equal(typeof off, 'function');
  off();
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
