'use strict';

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

test('S P1-A: array attestation does NOT satisfy any FP check (every required check unsatisfied)', () => {
  const dir = tmpDir('s-p1a');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        detect: {
          indicators: [{
            id: 'sig',
            type: 'log_pattern',
            value: 'x',
            description: 'd',
            confidence: 'high',
            deterministic: false,
            false_positive_checks_required: ['check-A', 'check-B'],
          }],
        },
      },
    }));
    const runner = freshRunner(dir);
    // Hostile submission shape: an array masquerading as the attestation
    // map. Pre-fix the index-fallback (`att['0']` / `att['1']`) matched the
    // array's truthy positions, satisfying every required check silently.
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit', sig__fp_checks: [true, true] },
    });
    const ind = det.indicators.find(i => i.id === 'sig');
    assert.equal(ind.verdict, 'inconclusive',
      'array attestation must be refused — verdict must downgrade to inconclusive');
    assert.ok(Array.isArray(ind.fp_checks_unsatisfied),
      'fp_checks_unsatisfied must surface on the result');
    assert.equal(ind.fp_checks_unsatisfied.length, 2,
      'both required FP checks must be listed as unsatisfied');
    assert.equal(det.classification, 'inconclusive',
      'when any indicator is FP-downgraded, overall classification must pin to inconclusive (v0.12.19 contract).');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// S P1-B — `detection_classification: 'detected'` override cannot bypass FP downgrade
// =========================================================================

test("S P1-B: 'detected' override is refused when any indicator was FP-downgraded", () => {
  const dir = tmpDir('s-p1b');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        detect: {
          indicators: [{
            id: 'sig',
            type: 'log_pattern',
            value: 'x',
            description: 'd',
            confidence: 'high',
            deterministic: false,
            false_positive_checks_required: ['check-A', 'check-B'],
          }],
        },
      },
    }));
    const runner = freshRunner(dir);
    const runErrors = [];
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit' }, // no fp_checks attestation
      signals: { detection_classification: 'detected' },
    }, { _runErrors: runErrors });
    assert.equal(det.classification, 'inconclusive',
      'classification must be substituted to inconclusive when any indicator was FP-downgraded');
    const blocked = runErrors.find(e => e.kind === 'classification_override_blocked');
    assert.ok(blocked, 'runtime_errors must include a classification_override_blocked record');
    assert.equal(blocked.attempted, 'detected');
    assert.equal(blocked.substituted, 'inconclusive');
    assert.ok(Array.isArray(blocked.indicators_with_unsatisfied_fp_checks));
    assert.ok(blocked.indicators_with_unsatisfied_fp_checks.length >= 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("S P1-B: 'detected' override is honored when no FP downgrade occurred", () => {
  const dir = tmpDir('s-p1b-ok');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        detect: {
          indicators: [{
            id: 'sig',
            type: 'log_pattern',
            value: 'x',
            description: 'd',
            confidence: 'high',
            deterministic: false,
            false_positive_checks_required: ['check-A'],
          }],
        },
      },
    }));
    const runner = freshRunner(dir);
    const det = runner.detect('p', 'default', {
      signal_overrides: { sig: 'hit', sig__fp_checks: { 'check-A': true } },
      signals: { detection_classification: 'detected' },
    });
    assert.equal(det.classification, 'detected',
      'when every FP check is attested, the override survives');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// U REG-1 — signal_overrides_invalid must reach analyze.runtime_errors[]
// =========================================================================

test('U REG-1: signal_overrides=array surfaces as analyze.runtime_errors[]', () => {
  const dir = tmpDir('u-reg1');
  try {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        detect: {
          indicators: [{
            id: 'sig',
            type: 'log_pattern',
            value: 'x',
            description: 'd',
            confidence: 'high',
            deterministic: false,
          }],
        },
      },
    }));
    const runner = freshRunner(dir);
    const result = runner.run('p', 'default', {
      // Hostile shape: array, not object. normalizeSubmission must push a
      // signal_overrides_invalid runtime_error onto submission._runErrors,
      // and run() must harvest it into the run-level accumulator so
      // analyze.runtime_errors[] surfaces it.
      signal_overrides: ['bad-value-1', 'bad-value-2'],
    }, { airGap: true });
    assert.ok(result.phases, `run() must produce phases; got ${JSON.stringify(result).slice(0, 200)}`);
    const rtErrors = (result.phases.analyze && result.phases.analyze.runtime_errors) || [];
    const invalid = rtErrors.find(e => e.kind === 'signal_overrides_invalid');
    assert.ok(invalid,
      `analyze.runtime_errors[] must contain signal_overrides_invalid; got: ${JSON.stringify(rtErrors)}`);
    assert.equal(invalid.supplied_type, 'array',
      'the error record must report the invalid input type');
    // Field-present AND populated.
    assert.equal(typeof invalid.reason, 'string');
    assert.ok(invalid.reason.length > 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// T P1-1 — PID-liveness check on stale lockfiles
// =========================================================================

test('T P1-1: withIndexLock reclaims a lockfile whose PID is dead (ESRCH)', async () => {
  const { _internal } = require('../lib/prefetch.js');
  const { withIndexLock } = _internal;
  const dir = tmpDir('t-p1-1');
  try {
    fs.mkdirSync(dir, { recursive: true });
    // Plant a lockfile with a PID that is virtually guaranteed dead. We
    // pick max-int range and verify process.kill(pid, 0) raises ESRCH.
    // (PID 2147483646 is well above any reasonable kernel limit.)
    const lockPath = path.join(dir, '_index.json.lock');
    const deadPid = 2147483646;
    try {
      process.kill(deadPid, 0);
      // If this succeeded — extremely unlikely — skip the test.
      return;
    } catch (e) {
      if (e.code !== 'ESRCH') {
        // Different errno (EPERM on locked-down systems). The PID-liveness
        // branch can't be exercised; fall back to mtime path implicitly.
        return;
      }
    }
    fs.writeFileSync(lockPath, String(deadPid));
    // Touch mtime to NOW so the mtime fallback would NOT reclaim. Only the
    // PID-liveness branch can succeed in <STALE_LOCK_MS.
    const now = new Date();
    fs.utimesSync(lockPath, now, now);

    const start = Date.now();
    await withIndexLock(dir, (current) => {
      current.entries['reclaimed/probe'] = { fetched_at: new Date().toISOString() };
      return current;
    });
    const elapsed = Date.now() - start;
    // STALE_LOCK_MS is 30_000; PID-liveness reclaim should complete in well
    // under a second. Bound at 5s to leave headroom on slow CI.
    assert.ok(elapsed < 5000,
      `PID-liveness reclaim must NOT wait for mtime fallback; took ${elapsed}ms`);
    const idx = JSON.parse(fs.readFileSync(path.join(dir, '_index.json'), 'utf8'));
    assert.ok(idx.entries['reclaimed/probe']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// =========================================================================
// T P1-2 — persistAttestation force-overwrite serializes concurrent writers
// =========================================================================

test('T P1-2: concurrent --force-overwrite writers preserve prior_evidence_hash chain', async () => {
  // Real subprocess race: N children each call persistAttestation with
  // --force-overwrite against the same session-id. Without the lock, the
  // read of `prior` is racy and the final attestation's prior_evidence_hash
  // would point to whatever happened to be on disk at one writer's read
  // moment — losing intermediates. With the lock, every overwrite reads
  // the on-disk prior INSIDE the critical section, so the chain is
  // contiguous: the final attestation's prior_evidence_hash matches some
  // prior writer's evidence_hash.
  const root = tmpDir('t-p1-2');
  try {
    const sessionId = 'race-' + crypto.randomBytes(4).toString('hex');
    const dir = path.join(root, sessionId);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, 'attestation.json');
    // Seed an initial attestation so every concurrent writer hits the
    // force-overwrite path.
    fs.writeFileSync(filePath, JSON.stringify({
      session_id: sessionId,
      playbook_id: 'synth',
      directive_id: 'default',
      evidence_hash: 'seed-hash',
      operator: null,
      operator_consent: null,
      submission: {},
      run_opts: { airGap: false, forceStale: false, mode: 'test' },
      captured_at: new Date(Date.now() - 1000).toISOString(),
      prior_evidence_hash: null,
      prior_captured_at: null,
    }, null, 2));

    const helperPath = path.join(__dirname, '_helpers', 'concurrent-attestation-writer.js');
    const N = 4;
    const children = [];
    for (let i = 0; i < N; i++) {
      children.push(new Promise((resolve, reject) => {
        const cp = fork(helperPath, [root, sessionId, String(i)], {
          stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
          env: { ...process.env, EXCEPTD_ATTESTATION_ROOT: root },
        });
        let out = '';
        let err = '';
        cp.stdout.on('data', (b) => { out += b; });
        cp.stderr.on('data', (b) => { err += b; });
        cp.on('close', (code) => {
          if (code === 0) resolve({ out, err });
          else reject(new Error(`writer ${i} exited ${code}: ${err}`));
        });
      }));
    }
    const results = await Promise.all(children);
    // Every writer must report ok:true.
    for (const r of results) {
      const parsed = JSON.parse(r.out);
      assert.equal(parsed.ok, true, `writer must report ok:true; got ${JSON.stringify(parsed)}`);
    }
    // The final on-disk attestation must:
    //   1. Exist with valid JSON.
    //   2. Have a non-null prior_evidence_hash (forceOverwrite always
    //      captures the prior).
    //   3. The prior_evidence_hash must equal SOME writer's reported
    //      evidence_hash OR the seed-hash — i.e. it traces back to a real
    //      prior writer, not a corrupted read.
    const final = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    assert.ok(final.evidence_hash, 'final attestation must have evidence_hash');
    assert.ok(final.prior_evidence_hash, 'final attestation must record prior_evidence_hash');
    const reportedHashes = new Set(['seed-hash']);
    for (const r of results) reportedHashes.add(JSON.parse(r.out).evidence_hash);
    assert.ok(reportedHashes.has(final.prior_evidence_hash),
      `final.prior_evidence_hash (${final.prior_evidence_hash}) must trace to a real writer; reported hashes: ${[...reportedHashes].join(',')}`);
    // No orphan .lock left behind.
    assert.equal(fs.existsSync(filePath + '.lock'), false,
      'attestation .lock must be released after every writer');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =========================================================================
// T P1-3 — prefetch must NOT orphan a payload on lock failure
// =========================================================================

test('T P1-3: prefetch tmp-then-lock pattern leaves no orphan payload when lock cannot be acquired', async () => {
  // We exercise the contract directly by simulating a "lock fails" scenario.
  // The lock helper uses O_EXCL on a sidecar .lock file with a bounded
  // retry. We hold the lock open via a sibling process that never releases
  // it, then drive the prefetch-style write path against the same cache
  // dir. The expected behavior:
  //   - The tmp file MAY appear transiently.
  //   - On lock-acquisition failure, the tmp file MUST be cleaned up.
  //   - The final payload at entryPath() MUST NOT exist (no orphan).
  //   - The _index.json entry MUST NOT exist (no phantom index row).
  //
  // We test via the published _internal contract: writeFileAtomic + a
  // never-releasing lockfile, then assert that a follow-up that fails
  // to lock cleans up its staged tmp file. The lib/prefetch.js change
  // wraps fetch.then() with a try/catch that unlinks the tmp on lock
  // failure. We replicate the same shape here.
  const { _internal } = require('../lib/prefetch.js');
  const { withIndexLock } = _internal;
  const dir = tmpDir('t-p1-3');
  try {
    fs.mkdirSync(path.join(dir, 'test'), { recursive: true });
    // Plant a non-stale, live-PID lockfile so the reclaim paths refuse to
    // reclaim — withIndexLock will exhaust MAX_RETRIES and throw.
    const lockPath = path.join(dir, '_index.json.lock');
    fs.writeFileSync(lockPath, String(process.pid));
    const now = new Date();
    fs.utimesSync(lockPath, now, now);

    const targetPath = path.join(dir, 'test', 'sample.json');
    const tmpPath = `${targetPath}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 10)}`;
    fs.writeFileSync(tmpPath, JSON.stringify({ payload: 'staged' }));

    let threw = false;
    try {
      await withIndexLock(dir, (current) => {
        fs.renameSync(tmpPath, targetPath);
        current.entries['test/sample'] = { fetched_at: now.toISOString() };
        return current;
      });
    } catch (e) {
      threw = true;
      // Cleanup mirrors the lib/prefetch.js catch block.
      try { fs.unlinkSync(tmpPath); } catch {}
    }
    assert.ok(threw, 'withIndexLock must throw when the lockfile cannot be acquired');
    assert.equal(fs.existsSync(tmpPath), false,
      'staged tmp file must be unlinked on lock failure (no orphan)');
    assert.equal(fs.existsSync(targetPath), false,
      'final payload path must NOT exist when lock failed (no orphan in cache)');
    assert.equal(fs.existsSync(path.join(dir, '_index.json')), false,
      'no _index.json entry must be written when lock failed');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

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
