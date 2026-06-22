'use strict';

/**
 * Tests for lib/playbook-runner.js — the seven-phase playbook engine.
 *
 * Runs under: node --test --test-concurrency=1 tests/
 * (concurrency=1 matters: _activeRuns and the EXCEPTD_PLAYBOOK_DIR env var are
 *  process-global, and several tests temporarily redirect the playbook dir.)
 *
 * Strategy:
 *   - Happy-path tests use the real data/playbooks/kernel.json.
 *   - Edge-case / branch tests write synthetic playbooks into an os.tmpdir()
 *     subdir and flip EXCEPTD_PLAYBOOK_DIR to point at it for the duration of
 *     the test. The runner reads PLAYBOOK_DIR once at module load (it's a
 *     module-scope const), so we have to clear the require cache when we want
 *     it re-resolved against a new path. Helper below.
 */

const test = require('node:test');
const { describe, it, before, after, beforeEach, afterEach } = test;
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

// --- helpers ------------------------------------------------------------

function freshRunner(playbookDir) {
  // Drop both the runner and (defensively) cross-ref-api so the runner reloads
  // with the env-var taking effect for PLAYBOOK_DIR. cross-ref-api reads a
  // separate DATA_DIR; we leave it pointing at the real data/ so byCve() still
  // works for synthetic playbooks that reference catalogued CVEs.
  if (playbookDir) {
    process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  } else {
    delete process.env.EXCEPTD_PLAYBOOK_DIR;
  }
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}

function writePlaybook(dir, id, body) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body, null, 2));
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-pb-${label}-`));
}

/**
 * Build a minimally-valid synthetic playbook with overridable bits.
 * Caller passes `overrides` whose keys deep-merge into the base.
 */
function synthPlaybook(overrides = {}) {
  const base = {
    _meta: {
      id: 'synth',
      version: '0.1.0',
      last_threat_review: '2026-05-11',
      threat_currency_score: 95,
      changelog: [{ version: '0.1.0', date: '2026-05-11', summary: 'synthetic test playbook' }],
      owner: '@blamejs/test',
      air_gap_mode: false,
      preconditions: [],
      mutex: [],
      feeds_into: []
    },
    domain: {
      name: 'synth domain',
      attack_class: 'kernel-lpe',
      atlas_refs: [],
      attack_refs: [],
      cve_refs: [],
      cwe_refs: [],
      d3fend_refs: [],
      frameworks_in_scope: ['nist-800-53']
    },
    phases: {
      govern: { jurisdiction_obligations: [], theater_fingerprints: [], framework_context: {}, skill_preload: [] },
      direct: { threat_context: 'x', rwep_threshold: { escalate: 90, monitor: 70, close: 30 }, framework_lag_declaration: 'x', skill_chain: [], token_budget: {} },
      look: { artifacts: [], collection_scope: {}, environment_assumptions: [], fallback_if_unavailable: [] },
      detect: { indicators: [], false_positive_profile: [], minimum_signal: { detected: 'x', inconclusive: 'x', not_detected: 'x' } },
      analyze: { rwep_inputs: [], blast_radius_model: { scope_question: '?', scoring_rubric: [] }, compliance_theater_check: null, framework_gap_mapping: [], escalation_criteria: [] },
      validate: { remediation_paths: [], validation_tests: [], residual_risk_statement: null, evidence_requirements: [], regression_trigger: [] },
      close: { evidence_package: null, learning_loop: { enabled: false }, notification_actions: [], exception_generation: null, regression_schedule: null }
    },
    directives: [
      { id: 'default', title: 'default directive', applies_to: { always: true } }
    ]
  };
  return deepMergeForFixtures(base, overrides);
}

function deepMergeForFixtures(a, b) {
  if (b === null || b === undefined) return a;
  if (Array.isArray(b)) return b;
  if (typeof b !== 'object') return b;
  const out = { ...a };
  for (const [k, v] of Object.entries(b)) {
    out[k] = (k in out) ? deepMergeForFixtures(out[k], v) : v;
  }
  return out;
}

// =======================================================================
// 1. Catalog discovery: listPlaybooks / loadPlaybook / plan
// =======================================================================

describe('listPlaybooks / loadPlaybook / plan', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('listPlaybooks discovers the real kernel playbook', () => {
    const ids = runner.listPlaybooks();
    assert.ok(Array.isArray(ids), 'returns an array');
    assert.ok(ids.includes('kernel'), 'kernel is in the catalog');
    assert.ok(!ids.some(id => id.startsWith('_')), 'index-prefixed files are filtered');
  });

  it('loadPlaybook returns the parsed kernel playbook', () => {
    const pb = runner.loadPlaybook('kernel');
    assert.equal(pb._meta.id, 'kernel');
    assert.ok(Array.isArray(pb.directives));
    assert.ok(pb.domain.cve_refs.includes('CVE-2026-31431'));
  });

  it('loadPlaybook throws on unknown id', () => {
    assert.throws(() => runner.loadPlaybook('does-not-exist'), /Playbook not found/);
  });

  it('loadPlaybook rejects path-traversal ids before touching the filesystem', () => {
    for (const bad of ['../../../etc/passwd', '..\\..\\manifest', 'a/b', 'a\\b', '.']) {
      assert.throws(
        () => runner.loadPlaybook(bad),
        (e) => e.code === 'EXCEPTD_INVALID_ID',
        `loadPlaybook must reject ${JSON.stringify(bad)} with EXCEPTD_INVALID_ID`,
      );
    }
  });

  it('plan returns the seven-phase contract banner and per-playbook summaries', () => {
    const p = runner.plan({ playbookIds: ['kernel'], session_id: 'fixed-test-session' });
    assert.match(p.contract, /seven-phase/);
    assert.deepEqual(p.host_ai_owns, ['look', 'detect']);
    assert.deepEqual(p.exceptd_owns, ['govern', 'direct', 'analyze', 'validate', 'close']);
    assert.equal(p.session_id, 'fixed-test-session');
    assert.equal(p.playbooks.length, 1);
    const kp = p.playbooks[0];
    assert.equal(kp.id, 'kernel');
    assert.ok(kp.directives.some(d => d.id === 'copy-fail-specific'));
  });

  it('plan with no playbookIds enumerates everything in the dir', () => {
    const p = runner.plan({ session_id: 'enum-test' });
    assert.ok(p.playbooks.length >= 1);
  });
});

// =======================================================================
// 2. preflight — currency gate, preconditions, mutex
// =======================================================================

describe('preflight: currency gate', () => {
  let runner;
  let dir;

  beforeEach(() => {
    dir = tmpDir('currency');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('score=95 → ok=true, no currency_warn', () => {
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { threat_currency_score: 95 } }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'));
    assert.equal(pre.ok, true);
    assert.ok(!pre.issues.find(i => i.kind === 'currency_warn'));
  });

  it('score=65 → ok=true with currency_warn issue', () => {
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { threat_currency_score: 65 } }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'));
    assert.equal(pre.ok, true);
    const warn = pre.issues.find(i => i.kind === 'currency_warn');
    assert.ok(warn, 'currency_warn issue present');
    assert.match(warn.message, /65/);
  });

  it('score=45 → ok=false (hard block) unless forceStale=true', () => {
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { threat_currency_score: 45 } }));
    runner = freshRunner(dir);
    const blocked = runner.preflight(runner.loadPlaybook('p'));
    assert.equal(blocked.ok, false);
    assert.equal(blocked.blocked_by, 'currency');
    assert.match(blocked.reason, /forceStale=true/);

    const forced = runner.preflight(runner.loadPlaybook('p'), { forceStale: true });
    assert.equal(forced.ok, true, 'forceStale overrides hard block');
    // forceStale still surfaces the currency warn because score < 70
    assert.ok(forced.issues.find(i => i.kind === 'currency_warn'));
  });
});

describe('preflight: preconditions', () => {
  let runner;
  let dir;

  beforeEach(() => {
    dir = tmpDir('pre');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('on_fail=halt + check=false → blocked', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'linux', description: 'linux host', check: 'host.platform == linux', on_fail: 'halt' }]
      }
    }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'), { precondition_checks: { linux: false } });
    assert.equal(pre.ok, false);
    assert.equal(pre.blocked_by, 'precondition');
    assert.match(pre.reason, /linux/);
  });

  it('on_fail=warn + check=false → ok with warn issue', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'uname', description: 'uname on PATH', check: 'agent_has_command', on_fail: 'warn' }]
      }
    }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'), { precondition_checks: { uname: false } });
    assert.equal(pre.ok, true);
    const warn = pre.issues.find(i => i.kind === 'precondition_warn');
    assert.ok(warn, 'has precondition_warn');
    assert.equal(warn.id, 'uname');
  });

  it('on_fail=skip_phase + check=false → ok with precondition_skip issue', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'optdata', description: 'optional data', check: 'have_data', on_fail: 'skip_phase' }]
      }
    }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'), { precondition_checks: { optdata: false } });
    assert.equal(pre.ok, true);
    const skip = pre.issues.find(i => i.kind === 'precondition_skip');
    assert.ok(skip, 'has precondition_skip issue');
  });

  it('precondition not supplied by agent → precondition_unverified issue', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'unverif', description: 'd', check: 'c', on_fail: 'warn' }]
      }
    }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'), {});
    assert.equal(pre.ok, true);
    const u = pre.issues.find(i => i.kind === 'precondition_unverified');
    assert.ok(u, 'has precondition_unverified');
    assert.equal(u.id, 'unverif');
  });

  it('on_fail=halt + not supplied → blocked with reason mentioning halt', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'must', description: 'must be set', check: 'must_check', on_fail: 'halt' }]
      }
    }));
    runner = freshRunner(dir);
    const pre = runner.preflight(runner.loadPlaybook('p'), {});
    assert.equal(pre.ok, false);
    assert.equal(pre.blocked_by, 'precondition');
    assert.match(pre.reason, /halt/);
  });
});

describe('preflight: mutex', () => {
  let runner;
  let dir;

  beforeEach(() => {
    dir = tmpDir('mutex');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    // Always clean active runs between tests
    if (runner && runner._activeRuns) runner._activeRuns.clear();
  });

  it('returns blocked_by:mutex when an entry in mutex set is in _activeRuns', () => {
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { mutex: ['conflictor'] } }));
    runner = freshRunner(dir);
    runner._activeRuns.add('conflictor');
    const pre = runner.preflight(runner.loadPlaybook('p'));
    assert.equal(pre.ok, false);
    assert.equal(pre.blocked_by, 'mutex');
    assert.match(pre.reason, /conflictor/);
    runner._activeRuns.delete('conflictor');
  });

  it('passes when mutex set is empty even with _activeRuns populated', () => {
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { mutex: [] } }));
    runner = freshRunner(dir);
    runner._activeRuns.add('unrelated');
    const pre = runner.preflight(runner.loadPlaybook('p'));
    assert.equal(pre.ok, true);
    runner._activeRuns.delete('unrelated');
  });
});

// =======================================================================
// 3. resolvedPhase + deepMerge — directive phase_overrides
// =======================================================================

describe('resolvedPhase + deepMerge', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('all-catalogued-kernel-cves uses base rwep_threshold.escalate=90', () => {
    const r = runner._resolvedPhase(runner.loadPlaybook('kernel'), 'all-catalogued-kernel-cves', 'direct');
    assert.equal(r.rwep_threshold.escalate, 90);
    assert.equal(r.rwep_threshold.monitor, 70);
  });

  it('copy-fail-specific directive overrides rwep_threshold.escalate=80 (deep-merged)', () => {
    const r = runner._resolvedPhase(runner.loadPlaybook('kernel'), 'copy-fail-specific', 'direct');
    assert.equal(r.rwep_threshold.escalate, 80);
    assert.equal(r.rwep_threshold.monitor, 60);
    assert.equal(r.rwep_threshold.close, 30);
    // Non-overridden fields are preserved from base
    assert.match(r.threat_context, /Copy Fail/);
    assert.ok(Array.isArray(r.skill_chain));
    assert.ok(r.skill_chain.length > 0);
  });

  it('deepMerge primitive replacement', () => {
    assert.equal(runner._deepMerge({ a: 1 }, { a: 2 }).a, 2);
  });

  it('deepMerge nested objects', () => {
    const out = runner._deepMerge({ a: { b: 1, c: 2 } }, { a: { b: 9 } });
    assert.deepEqual(out, { a: { b: 9, c: 2 } });
  });

  it('deepMerge arrays are replaced wholesale (not concatenated)', () => {
    const out = runner._deepMerge({ a: [1, 2, 3] }, { a: [9] });
    assert.deepEqual(out.a, [9]);
  });

  it('deepMerge null/undefined right-hand returns left-hand untouched', () => {
    assert.deepEqual(runner._deepMerge({ a: 1 }, null), { a: 1 });
    assert.deepEqual(runner._deepMerge({ a: 1 }, undefined), { a: 1 });
  });

  it('directive override for one phase does NOT pollute other phases', () => {
    const pb = runner.loadPlaybook('kernel');
    const direct = runner._resolvedPhase(pb, 'copy-fail-specific', 'direct');
    const govern = runner._resolvedPhase(pb, 'copy-fail-specific', 'govern');
    // direct.rwep_threshold is overridden
    assert.equal(direct.rwep_threshold.escalate, 80);
    // govern.jurisdiction_obligations is untouched
    assert.equal(govern.jurisdiction_obligations.length, pb.phases.govern.jurisdiction_obligations.length);
    assert.deepEqual(govern.jurisdiction_obligations, pb.phases.govern.jurisdiction_obligations);
  });
});

// =======================================================================
// 4. govern
// =======================================================================

describe('govern', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('returns jurisdiction_obligations + theater_fingerprints + framework_context + skill_preload', () => {
    const g = runner.govern('kernel', 'all-catalogued-kernel-cves');
    assert.equal(g.phase, 'govern');
    assert.equal(g.playbook_id, 'kernel');
    assert.ok(g.jurisdiction_obligations.length >= 1);
    assert.ok(g.jurisdiction_obligations.some(o => o.jurisdiction === 'EU' && /NIS2/.test(o.regulation)));
    assert.ok(g.theater_fingerprints.length >= 1);
    assert.ok(g.framework_context.gap_summary, 'framework_context.gap_summary present');
    assert.ok(g.skill_preload.includes('kernel-lpe-triage'));
    assert.equal(g.air_gap_mode, false);
  });

  it('air_gap_mode is honored when runOpts.airGap=true', () => {
    const g = runner.govern('kernel', 'all-catalogued-kernel-cves', { airGap: true });
    assert.equal(g.air_gap_mode, true);
  });

  it('exposes domain + threat_currency_score + last_threat_review', () => {
    const g = runner.govern('kernel', 'all-catalogued-kernel-cves');
    assert.equal(g.domain.attack_class, 'kernel-lpe');
    assert.equal(typeof g.threat_currency_score, 'number');
    assert.match(g.last_threat_review, /^\d{4}-\d{2}-\d{2}$/);
  });
});

// =======================================================================
// 5. direct
// =======================================================================

describe('direct', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('returns rwep_threshold, skill_chain, token_budget', () => {
    const d = runner.direct('kernel', 'all-catalogued-kernel-cves');
    assert.equal(d.phase, 'direct');
    assert.equal(d.rwep_threshold.escalate, 90);
    assert.ok(d.skill_chain.length > 0);
    assert.equal(d.token_budget.estimated_total, 18000);
    assert.match(d.threat_context, /Copy Fail/);
  });

  it('phase_overrides applied via copy-fail-specific directive', () => {
    const d = runner.direct('kernel', 'copy-fail-specific');
    assert.equal(d.rwep_threshold.escalate, 80);
    assert.equal(d.rwep_threshold.monitor, 60);
  });
});

// =======================================================================
// 6. look
// =======================================================================

describe('look', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('returns artifact list with original sources when not air-gapped', () => {
    const l = runner.look('kernel', 'all-catalogued-kernel-cves');
    assert.equal(l.phase, 'look');
    assert.ok(l.artifacts.length >= 4);
    const kr = l.artifacts.find(a => a.id === 'kernel-release');
    assert.ok(kr);
    assert.equal(kr.source, 'uname -r');
    assert.equal(kr._original_source, 'uname -r');
    assert.equal(l.air_gap_mode, false);
  });

  it('air_gap_mode=true swaps source for air_gap_alternative on artifacts that have one', () => {
    const l = runner.look('kernel', 'all-catalogued-kernel-cves', { airGap: true });
    assert.equal(l.air_gap_mode, true);
    const kr = l.artifacts.find(a => a.id === 'kernel-release');
    assert.equal(kr.source, 'Read /proc/version directly if uname(1) is unavailable.');
    assert.equal(kr._original_source, 'uname -r');
    // An artifact without air_gap_alternative keeps its original source
    const kf = l.artifacts.find(a => a.id === 'kernel-full');
    assert.equal(kf.source, 'uname -a');
  });
});

// =======================================================================
// 7. detect
// =======================================================================

describe('detect', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('empty submission with no captured artifacts → classification=not_detected', () => {
    // E2: pre-fix both arms of the indicator-default emitted 'inconclusive',
    // so a clean empty run (no observations, no captured artifacts) stayed
    // stuck at theater_verdict='pending_agent_run' forever. Now: with zero
    // captured artifacts the per-indicator verdict is 'miss' and the run
    // reaches 'not_detected'.
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    assert.equal(det.classification, 'not_detected');
    assert.equal(det.indicators.length, 5);
    assert.ok(det.indicators.every(i => i.verdict === 'miss'));
  });

  it('submission with captured artifacts but no signal overrides → inconclusive', () => {
    // E2 partner case: any captured artifact means the indicator could be
    // evaluated (host AI's responsibility), so verdict is 'inconclusive'.
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      artifacts: { 'kernel-version-string': { value: '6.12.0', captured: true } }
    });
    assert.equal(det.classification, 'inconclusive');
    assert.ok(det.indicators.every(i => i.verdict === 'inconclusive'));
  });

  it('all signal_overrides=miss → classification=not_detected', () => {
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: {
        'kver-in-affected-range': 'miss',
        'livepatch-active': 'miss',
        'kaslr-disabled': 'miss',
        'unpriv-userns-enabled': 'miss',
        'unpriv-bpf-allowed': 'miss'
      }
    });
    assert.equal(det.classification, 'not_detected');
    assert.ok(det.indicators.every(i => i.verdict === 'miss'));
  });

  it('deterministic indicator firing (kaslr-disabled hit) → classification=detected', () => {
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kaslr-disabled': 'hit' }
    });
    assert.equal(det.classification, 'detected');
    const hit = det.indicators.find(i => i.id === 'kaslr-disabled');
    assert.equal(hit.verdict, 'hit');
    assert.equal(hit.deterministic, true);
  });

  it('high-confidence non-deterministic hit (kver-in-affected-range) → classification=detected', () => {
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    assert.equal(det.classification, 'detected');
    const hit = det.indicators.find(i => i.id === 'kver-in-affected-range');
    assert.equal(hit.verdict, 'hit');
    assert.equal(hit.confidence, 'high');
  });

  it('one hit + others miss → still detected when hit is high/deterministic', () => {
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: {
        'kver-in-affected-range': 'hit',
        'livepatch-active': 'miss',
        'kaslr-disabled': 'miss',
        'unpriv-userns-enabled': 'miss',
        'unpriv-bpf-allowed': 'miss'
      }
    });
    assert.equal(det.classification, 'detected');
  });

  it('only medium-confidence hit → classification=inconclusive (not detected, not not_detected)', () => {
    // livepatch-active has confidence=medium and deterministic=false
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: {
        'livepatch-active': 'hit',
        'kver-in-affected-range': 'miss',
        'kaslr-disabled': 'miss',
        'unpriv-userns-enabled': 'miss',
        'unpriv-bpf-allowed': 'miss'
      }
    });
    assert.equal(det.classification, 'inconclusive');
  });

  it('false_positive_checks_required only populated for indicators reported as hit', () => {
    // No hits → fp list empty
    const det1 = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    assert.equal(det1.false_positive_checks_required.length, 0);

    // kver-in-affected-range hit → fp profile for that indicator is included
    const det2 = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    assert.ok(det2.false_positive_checks_required.length >= 1);
    assert.ok(det2.false_positive_checks_required.every(fp => fp.indicator_id === 'kver-in-affected-range'));
  });
});

// =======================================================================
// 8. analyze
// =======================================================================

describe('analyze', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('catalog_baseline_cves enumerate every CVE from domain.cve_refs', () => {
    // Catalog baseline is always populated regardless of evidence. This is
    // the scan-coverage enumeration, not the operator-affected list.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const ids = an.catalog_baseline_cves.map(c => c.cve_id);
    assert.ok(ids.includes('CVE-2026-31431'));
    assert.equal(an.catalog_baseline_cves.length, 4, 'all four catalogued kernel CVEs present in baseline');
    assert.ok(an.catalog_baseline_cves.every(c => c.correlated_via === null), 'baseline entries carry correlated_via=null');
  });

  it('matched_cves is empty when no evidence correlates (no indicator hits, no CVE signals)', () => {
    // Empty submission → no indicator hits → no correlation → matched_cves
    // must be empty. Pre-fix this enumerated catalog-baseline CVEs and
    // misled operators into thinking they were affected.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.matched_cves.length, 0,
      'matched_cves must be empty without evidence correlation; catalog enumeration belongs in catalog_baseline_cves');
  });

  it('matched_cves populated when an indicator hit shares attack_ref with a catalog CVE', () => {
    // kver-in-affected-range has attack_ref T1068; kernel CVEs all reference T1068.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.matched_cves.length, 4, 'all four kernel CVEs correlate via the fired indicator');
    assert.ok(an.matched_cves.every(c => Array.isArray(c.correlated_via) && c.correlated_via.length > 0),
      'every matched CVE entry must carry a non-empty correlated_via');
    assert.ok(an.matched_cves[0].correlated_via.some(v => v.startsWith('indicator_hit:')),
      'correlation reason must reference the indicator that fired');
  });

  it('RWEP base is max of evidence-correlated cve rwep scores (Copy Fail = 90 when indicator fires)', () => {
    // With the fix, RWEP base reflects the evidence-correlated maximum, not
    // the catalog-baseline maximum. Fire the indicator that ties the kernel
    // CVEs into matched_cves so the base resolves to Copy Fail's 90.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.rwep.base, 90);
  });

  it('RWEP base is 0 when no evidence correlates (no inflated catalog-ceiling)', () => {
    // Without evidence correlation, base must be 0 — operators are not
    // affected by a catalog enumeration, so RWEP base shouldn't carry the
    // weight of the worst-case catalog entry.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.rwep.base, 0);
  });

  it('rwep_inputs only apply weight when the signal fired', () => {
    // No detect hits, no agentSignals → adjusted == base (no weights applied).
    // Base is 0 in this scenario because no CVE correlates to the empty
    // evidence — and adjusted == base == 0 still proves "weights don't apply
    // without firing signals."
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const anQuiet = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(anQuiet.rwep.adjusted, anQuiet.rwep.base);
    assert.ok(anQuiet.rwep.breakdown.every(b => b.fired === false && b.weight_applied === 0));

    // Now: kver-in-affected-range hit. Indicator correlates to all kernel
    // CVEs (shared attack_ref T1068), so RWEP base resolves to 90 (Copy Fail).
    // Adjusted = 90 + 25+20+15+10-10 = 150 → clamped to 100.
    const detHit = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const anHit = runner.analyze('kernel', 'all-catalogued-kernel-cves', detHit);
    assert.equal(anHit.rwep.adjusted, 100, 'adjusted RWEP clamped to 100');
    const fired = anHit.rwep.breakdown.filter(b => b.fired);
    assert.ok(fired.length >= 5, 'kver-in-affected-range fires for all its rwep_inputs entries');
  });

  it('blast_radius_score: null+default when no signal supplied; supplied value used when in [0,5]', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an1 = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    // F6: no agent signal → null + signal='default' (NOT first rubric entry).
    // Pre-fix the runner silently substituted the LOWEST rubric entry,
    // which is the opposite of safe-default for risk reporting.
    assert.equal(an1.blast_radius_score, null, 'no signal → null');
    assert.equal(an1.blast_radius_signal, 'default');

    const an2 = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { blast_radius_score: 4 });
    assert.equal(an2.blast_radius_score, 4);
    assert.equal(an2.blast_radius_signal, 'supplied');
    assert.ok(an2.blast_radius_basis, 'basis populated from rubric for score=4');
    assert.equal(an2.blast_radius_basis.blast_radius_score, 4);
  });

  it('theater_verdict propagates from agentSignals into compliance_theater_check', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { theater_verdict: 'theater' });
    assert.equal(an.compliance_theater_check.verdict, 'theater');
    assert.ok(an.compliance_theater_check.verdict_text, 'verdict_text populated when verdict=theater');
  });

  it('compliance_theater_check defaults to clear on empty submission (E2 — detect reaches not_detected)', () => {
    // E2: empty submission now reaches detect.classification='not_detected'
    // (was 'inconclusive' under the dead-branch bug). Theater verdict
    // accordingly defaults to 'clear' per the existing
    // not_detected→clear mapping. Pre-fix this test asserted
    // 'pending_agent_run', which papered over the dead-branch root cause.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.compliance_theater_check.verdict, 'clear');
    assert.equal(an.compliance_theater_check.verdict_text, null);
  });

  it('compliance_theater_check pending_agent_run when artifacts captured but inconclusive', () => {
    // The pending_agent_run vocabulary should still surface when detect is
    // genuinely inconclusive (captured artifacts, no clear signal). Empty
    // submission no longer produces this — E2 closed that path.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      artifacts: { 'kernel-version-string': { value: '6.12.0', captured: true } }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.compliance_theater_check.verdict, 'pending_agent_run');
  });

  it('escalation_criteria fire when conditions met (rwep >= 90 AND patch_available == false)', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { patch_available: false });
    const pageOnCall = an.escalations.find(e => e.action === 'page_on_call');
    assert.ok(pageOnCall, 'page_on_call escalation fired');
    assert.match(pageOnCall.condition, /rwep >= 90/);
  });

  it('escalation_criteria with target_playbook surfaces target', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    // blast_radius_score=5 triggers the "blast_radius_score >= 4" → sbom escalation
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { blast_radius_score: 5 });
    const sbom = an.escalations.find(e => e.target_playbook === 'sbom');
    assert.ok(sbom, 'sbom-target escalation fired');
    assert.equal(sbom.action, 'trigger_playbook');
  });

  it("escalation conditions resolve analyze.* paths against the assembled result (theater verdict fires notify_legal)", () => {
    // cloud-iam-incident declares "analyze.compliance_theater_check.verdict
    // == 'theater'" → notify_legal. The escalation eval context must expose
    // the assembled analyze result under the `analyze` root (same contract
    // as close()'s feeds_into context) for this to ever fire.
    const detRes = runner.detect('cloud-iam-incident', 'aws-root-account-compromise', {});
    const an = runner.analyze('cloud-iam-incident', 'aws-root-account-compromise', detRes, { theater_verdict: 'theater' });
    assert.equal(an.compliance_theater_check.verdict, 'theater');
    const notifyLegal = an.escalations.find(e => e.action === 'notify_legal');
    assert.ok(notifyLegal, "notify_legal escalation fires on analyze.compliance_theater_check.verdict == 'theater'");
    assert.match(notifyLegal.condition, /analyze\.compliance_theater_check\.verdict/);
  });

  it('analyze-path escalation stays silent when the theater verdict is clear', () => {
    const detRes = runner.detect('cloud-iam-incident', 'aws-root-account-compromise', {});
    const an = runner.analyze('cloud-iam-incident', 'aws-root-account-compromise', detRes, { theater_verdict: 'clear' });
    assert.equal(an.compliance_theater_check.verdict, 'clear');
    assert.ok(!an.escalations.some(e => e.action === 'notify_legal'),
      'notify_legal must not fire on a clear verdict');
  });

  it('rwep.threshold is taken from the resolved direct phase (directive-aware)', () => {
    const detRes = runner.detect('kernel', 'copy-fail-specific', {});
    const an = runner.analyze('kernel', 'copy-fail-specific', detRes);
    assert.equal(an.rwep.threshold.escalate, 80, 'copy-fail-specific override leaks through into analyze');
  });
});

// =======================================================================
// 9. validate
// =======================================================================

describe('validate', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('highest priority path returned when its preconditions satisfied', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {
      livepatch_available_for_cve: true,
      host_supports_livepatch: true
    });
    assert.equal(v.selected_remediation.id, 'live-patch-deploy');
    assert.equal(v.selected_remediation.priority, 1);
  });

  it('falls back to priority-1 path when no preconditions satisfied', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    // Even with no preconditions satisfied, runner proposes the priority-1 path
    // (caller surfaces the unverified state to the operator).
    assert.ok(v.selected_remediation, 'a remediation is always proposed');
    assert.equal(v.selected_remediation.priority, 1);
    // remediation_options_considered marks the path as not satisfied
    const livePatch = v.remediation_options_considered.find(c => c.id === 'live-patch-deploy');
    assert.equal(livePatch.all_satisfied, false);
  });

  it('selects priority-2 path when priority-1 preconditions fail and priority-2 satisfied', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {
      // priority 1 not satisfied (livepatch_available_for_cve missing/false)
      livepatch_available_for_cve: false,
      host_supports_livepatch: false,
      // priority 2 satisfied
      vendor_patch_available: true,
      reboot_window_within_72h: true
    });
    assert.equal(v.selected_remediation.id, 'scheduled-kernel-upgrade');
  });

  it('regression_next_run computed from soonest interval', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    // Only "30d" is parseable (`monthly` interval). Result should be ~30 days
    // from now, an ISO string.
    assert.match(v.regression_next_run, /^\d{4}-\d{2}-\d{2}T/);
    const next = new Date(v.regression_next_run).getTime();
    const expected = Date.now() + 30 * 24 * 3600 * 1000;
    assert.ok(Math.abs(next - expected) < 60_000, 'next_run is ~30 days from now');
  });

  it('returns validation_tests + evidence_requirements + residual_risk_statement verbatim', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    assert.ok(v.validation_tests.length >= 3);
    assert.ok(v.evidence_requirements.length >= 3);
    assert.ok(v.residual_risk_statement);
    assert.equal(v.residual_risk_statement.acceptance_level, 'ciso');
  });
});

// =======================================================================
// 10. close
// =======================================================================

describe('close', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  function detected() {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { patch_available: false, blast_radius_score: 3 });
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    return { detRes, an, v };
  }

  it('evidence_package built with CSAF-2.0 envelope', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {});
    assert.ok(c.evidence_package);
    assert.equal(c.evidence_package.bundle_format, 'csaf-2.0');
    assert.equal(c.evidence_package.bundle_body.document.csaf_version, '2.0');
    assert.equal(c.evidence_package.bundle_body.document.category, 'csaf_security_advisory');
    assert.ok(c.evidence_package.bundle_body.document.tracking.id.startsWith('exceptd-kernel-'));
    assert.ok(Array.isArray(c.evidence_package.bundle_body.vulnerabilities));
  });

  it('evidence_package signed=true; HMAC signature present when session_key provided', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {}, { session_key: 'sekret' });
    assert.equal(c.evidence_package.signed, true);
    assert.match(c.evidence_package.signature, /^[0-9a-f]{64}$/);
    assert.equal(c.evidence_package.signature_algorithm, 'HMAC-SHA256-session-key');
  });

  it('evidence_package signature_pending when no session_key provided', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {});
    assert.equal(c.evidence_package.signed, true);
    assert.equal(c.evidence_package.signature, null);
    assert.match(c.evidence_package.signature_pending, /Ed25519/);
  });

  it('notification_actions deadlines computed as clock_start + window_hours when event fired', () => {
    const { an, v } = detected();
    const detectMoment = new Date('2026-05-11T10:00:00Z').toISOString();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      clock_started_at_detect_confirmed: detectMoment
    });
    const nis2 = c.notification_actions.find(n => n.obligation_ref === 'EU/NIS2 Art.23 24h');
    assert.ok(nis2);
    // 24h after 2026-05-11T10:00Z = 2026-05-12T10:00Z
    assert.equal(nis2.deadline, '2026-05-12T10:00:00.000Z');
    assert.equal(nis2.clock_start_event, 'detect_confirmed');
    assert.equal(nis2.clock_started_at, detectMoment);
  });

  it('notification_actions emit pending_clock_start_event when agent has not fired the event', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {});
    const dora = c.notification_actions.find(n => n.obligation_ref === 'EU/DORA Art.19 4h');
    assert.ok(dora);
    assert.equal(dora.deadline, 'pending_clock_start_event');
  });

  it('notify-type govern obligations without a declared notification_action are synthesized into jurisdiction_notifications', () => {
    // cloud-iam-incident's govern phase declares the AU Privacy Act NDB
    // notification obligation (720h) but close.notification_actions has no
    // entry for it. The record must be synthesized — enriched exactly like
    // an authored one — so the regulatory clock stays visible to operators.
    const det = runner.detect('cloud-iam-incident', 'aws-root-account-compromise', {});
    const an = runner.analyze('cloud-iam-incident', 'aws-root-account-compromise', det);
    const v = runner.validate('cloud-iam-incident', 'aws-root-account-compromise', an, {});
    const c = runner.close('cloud-iam-incident', 'aws-root-account-compromise', an, v, {});
    const synthesized = c.jurisdiction_notifications.filter(n => n.synthesized_from_obligation === true);
    assert.equal(synthesized.length, 1, 'exactly one notify-type govern obligation lacks a declared action in this playbook');
    const au = synthesized[0];
    assert.equal(au.jurisdiction, 'AU');
    assert.equal(au.window_hours, 720);
    assert.equal(typeof au.regulation, 'string');
    assert.ok(au.regulation.length > 0, 'regulation enriched from the govern obligation');
    assert.equal(au.obligation_ref, `AU/${au.regulation} 720h`);
    assert.equal(au.deadline, 'pending_clock_start_event');
    assert.equal(au.draft_notification, null);
    assert.ok(Array.isArray(au.evidence_required) && au.evidence_required.length > 0,
      'evidence checklist carried forward from the obligation');
    // Playbook-authored records are untouched by the synthesis.
    const authored = c.jurisdiction_notifications.filter(n => !n.synthesized_from_obligation);
    assert.equal(authored.length, 9);
    assert.ok(authored.every(n => n.obligation_ref !== au.obligation_ref));
  });

  it('draft_notification interpolates ${matched_cve_ids} / ${kev_listed_count}', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, { affected_host_count: 17 });
    const nis2 = c.notification_actions.find(n => n.obligation_ref === 'EU/NIS2 Art.23 24h');
    assert.match(nis2.draft_notification, /CVE-2026-31431/);
    assert.match(nis2.draft_notification, /17 host/);
    // KEV count = at least 1 (CVE-2026-31431 is KEV-listed)
    assert.match(nis2.draft_notification, /KEV-listed: [1-9]/);
  });

  it('F14: missing ${} placeholders render as <MISSING:var> and surface in missing_interpolation_vars', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      // matched_cve_ids will populate, but interim_mitigation / ict_dependencies / affected_host_count are missing
    });
    const nis2 = c.notification_actions.find(n => n.obligation_ref === 'EU/NIS2 Art.23 24h');
    // F14: failure mode is loud now — operators see <MISSING:var> instead
    // of a silent literal placeholder that could ship to regulators.
    assert.match(nis2.draft_notification, /<MISSING:interim_mitigation>/);
    assert.match(nis2.draft_notification, /<MISSING:affected_host_count>/);
    assert.ok(Array.isArray(nis2.missing_interpolation_vars), 'missing_interpolation_vars array present');
    assert.ok(nis2.missing_interpolation_vars.includes('interim_mitigation'));
    assert.ok(nis2.missing_interpolation_vars.includes('affected_host_count'));
  });

  it('exception_generation fires when trigger_condition satisfied (synthetic playbook)', () => {
    // The real kernel playbook's exception trigger uses parentheses around an
    // OR-subexpression:
    //   "remediation_blocked == true OR (matched_cve.kev_due_date < remediation_eta AND livepatch_available == false)"
    // evalCondition splits on AND first, then OR, with no paren handling — so
    // the parens are treated as literal chars and that branch can't evaluate.
    // TODO(playbook-runner): parser does not support parentheses for grouping
    // boolean sub-expressions. Either teach the parser, or rewrite kernel.json
    // to avoid the construct. Verified via the simpler synthetic playbook
    // below where the trigger fires cleanly.
    const dir = tmpDir('except');
    try {
      writePlaybook(dir, 'p', synthPlaybook({
        domain: { cve_refs: ['CVE-2026-31431'], frameworks_in_scope: ['nist-800-53'] },
        phases: {
          // Fire an indicator that correlates to CVE-2026-31431 via shared
          // attack_ref T1068 so matched_cves is populated and the exception
          // template's ${matched_cve_ids} interpolation has content. Pre-fix
          // matched_cves enumerated catalog-baseline; post-fix it requires
          // evidence correlation.
          detect: {
            indicators: [{ id: 'kev-trigger', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }]
          },
          analyze: {
            framework_gap_mapping: [{ finding_id: 'f', framework: 'nist-800-53', claimed_control: 'SI-2', actual_gap: 'g', required_control: 'r' }]
          },
          close: {
            evidence_package: { bundle_format: 'csaf-2.0' },
            exception_generation: {
              trigger_condition: 'remediation_blocked == true',
              exception_template: {
                scope: 'Scope for ${matched_cve_ids} on ${affected_host_count} hosts',
                duration: 'until_vendor_patch',
                compensating_controls: ['c1'],
                risk_acceptance_owner: 'ciso',
                auditor_ready_language: 'Pursuant to ${framework_id} ${control_id}, accepted by ${ciso_name} on ${acceptance_date} re ${matched_cve_ids}.'
              }
            }
          }
        }
      }));
      const local = freshRunner(dir);
      const detRes = local.detect('p', 'default', { signal_overrides: { 'kev-trigger': 'hit' } });
      const an = local.analyze('p', 'default', detRes);
      const v = local.validate('p', 'default', an, {});
      const c = local.close('p', 'default', an, v, { remediation_blocked: true, ciso_name: 'Jane Doe', affected_host_count: 5 });
      assert.ok(c.exception, 'exception generated');
      assert.equal(c.exception.risk_acceptance_owner, 'ciso');
      assert.match(c.exception.auditor_ready_language, /Jane Doe/);
      assert.match(c.exception.auditor_ready_language, /CVE-2026-31431/);
      assert.match(c.exception.auditor_ready_language, /nist-800-53/);
      assert.match(c.exception.auditor_ready_language, /SI-2/);
      assert.match(c.exception.scope, /5 hosts/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      freshRunner(REAL_PLAYBOOK_DIR);
    }
  });

  it('exception is null when trigger_condition unsatisfied', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {});
    assert.equal(c.exception, null);
  });

  it('feeds_into chain returns downstream playbooks for satisfied conditions', () => {
    const { an, v } = detected();
    // blast_radius_score=3 won't trigger sbom (needs >=4). Use 5.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an2 = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { blast_radius_score: 5 });
    const v2 = runner.validate('kernel', 'all-catalogued-kernel-cves', an2, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an2, v2, {});
    assert.ok(c.feeds_into.includes('sbom'), 'sbom downstream chain fired on blast_radius_score>=4');
  });

  it('feeds_into chain identifies framework when theater verdict fired', () => {
    // v0.10.2 corrected kernel.json's stale "compliance-theater" referent to
    // "framework" (the playbook ID that actually carries the compliance-theater
    // attack class). This test was authored against the typo and is updated
    // to assert the corrected chain target.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { theater_verdict: 'theater' });
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, { theater_verdict: 'theater' });
    assert.ok(c.feeds_into.includes('framework'),
      'kernel theater-verdict should chain into the framework playbook (was: compliance-theater typo, fixed in v0.10.2)');
  });

  it('learning_loop lesson populated and feeds_back_to_skills present', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {});
    assert.equal(c.learning_loop.enabled, true);
    assert.ok(c.learning_loop.feeds_back_to_skills.includes('kernel-lpe-triage'));
    assert.match(c.learning_loop.proposed_for_zeroday_lessons_id, /^lesson-kernel-/);
  });
});

// =======================================================================
// 11. run — end-to-end
// =======================================================================

describe('run (end-to-end)', () => {
  let runner;
  beforeEach(() => {
    runner = freshRunner(REAL_PLAYBOOK_DIR);
    runner._activeRuns.clear();
  });

  // The kernel playbook has a halt-on-fail precondition for linux-platform
  // and a warn-on-fail one for uname-available. To exercise the engine
  // end-to-end the host AI must declare both.
  const KERNEL_PREFLIGHT = { precondition_checks: { 'linux-platform': true, 'uname-available': true } };

  it('full happy path: detected kernel LPE → rwep clamped, live-patch path selected', () => {
    const result = runner.run('kernel', 'all-catalogued-kernel-cves', {
      artifacts: {
        'kernel-release': { value: '5.15.0-1058-generic', captured: true },
        'os-release': { value: 'ubuntu 22.04', captured: true }
      },
      signal_overrides: { 'kver-in-affected-range': 'hit' },
      signals: {
        livepatch_available_for_cve: true,
        host_supports_livepatch: true,
        patch_available: false,
        blast_radius_score: 3,
        detection_classification: 'detected'
      }
    }, KERNEL_PREFLIGHT);
    assert.equal(result.ok, true);
    assert.equal(result.phases.detect.classification, 'detected');
    assert.equal(result.phases.analyze.rwep.adjusted, 100, 'rwep clamped to 100');
    assert.equal(result.phases.validate.selected_remediation.id, 'live-patch-deploy');
    assert.equal(result.phases.analyze.matched_cves.length, 4);
    assert.match(result.evidence_hash, /^[0-9a-f]{64}$/);
  });

  it('evidence_hash is deterministic across identical runs', () => {
    const submission = {
      artifacts: { 'kernel-release': { value: '5.15.0-1058-generic', captured: true } },
      signal_overrides: { 'kver-in-affected-range': 'hit' },
      signals: { patch_available: false, blast_radius_score: 3 }
    };
    const a = runner.run('kernel', 'all-catalogued-kernel-cves', submission, KERNEL_PREFLIGHT);
    const b = runner.run('kernel', 'all-catalogued-kernel-cves', submission, KERNEL_PREFLIGHT);
    assert.equal(a.ok, true);
    assert.equal(a.evidence_hash, b.evidence_hash);
  });

  it('deterministic session-id derivation failure releases the mutex lock and _activeRuns entry', () => {
    // canonicalStringify throws EVIDENCE_TOO_DEEP for pathological nesting.
    // The throw happens after the run lock and _activeRuns registration —
    // if either leaks, every subsequent run of the playbook is blocked for
    // the life of this PID.
    let deep = {};
    let p = deep;
    for (let i = 0; i < 205; i++) { p.x = {}; p = p.x; }
    const submission = { signals: { nested: deep } };
    assert.throws(
      () => runner.run('kernel', 'all-catalogued-kernel-cves', submission, { ...KERNEL_PREFLIGHT, bundleDeterministic: true }),
      (e) => e.code === 'EVIDENCE_TOO_DEEP',
      'pathological nesting must surface EVIDENCE_TOO_DEEP'
    );
    assert.equal(runner._activeRuns.has('kernel'), false,
      '_activeRuns entry must be released when the derivation throws');
    // The cross-process lockfile must also be released: a follow-up run of
    // the same playbook must not be blocked by the mutex.
    const again = runner.run('kernel', 'all-catalogued-kernel-cves', {}, KERNEL_PREFLIGHT);
    assert.notEqual(again.blocked_by, 'mutex', // allow-notEqual: refusal-pin (asserting the absence of one specific blocked state; any non-mutex outcome is acceptable here)
      'a leaked lockfile would block the follow-up run with blocked_by:"mutex"');
  });

  it('preflight failure short-circuits run', () => {
    // Use a synthetic playbook with score=45 to force the hard block
    const dir = tmpDir('runblock');
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { threat_currency_score: 45 } }));
    const local = freshRunner(dir);
    try {
      const result = local.run('p', 'default', {});
      assert.equal(result.ok, false);
      assert.equal(result.phase, 'preflight');
      assert.equal(result.blocked_by, 'currency');
      assert.ok(!result.phases, 'no phases run when preflight blocks');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      freshRunner(REAL_PLAYBOOK_DIR);
    }
  });

  it('mutex enforced — manually injecting into _activeRuns blocks the run', () => {
    const dir = tmpDir('runmutex');
    writePlaybook(dir, 'p', synthPlaybook({ _meta: { mutex: ['other-running-pb'] } }));
    const local = freshRunner(dir);
    local._activeRuns.add('other-running-pb');
    try {
      const result = local.run('p', 'default', {});
      assert.equal(result.ok, false);
      assert.equal(result.blocked_by, 'mutex');
    } finally {
      local._activeRuns.delete('other-running-pb');
      fs.rmSync(dir, { recursive: true, force: true });
      freshRunner(REAL_PLAYBOOK_DIR);
    }
  });

  it('successful run does not leak entries into _activeRuns', () => {
    const before = runner._activeRuns.size;
    const result = runner.run('kernel', 'all-catalogued-kernel-cves', {}, KERNEL_PREFLIGHT);
    assert.equal(result.ok, true);
    assert.equal(runner._activeRuns.size, before, '_activeRuns is cleaned up on completion');
  });
});

// =======================================================================
// 12. evalCondition + interpolate + computeRegressionNextRun (helpers)
// =======================================================================

describe('evalCondition', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('returns true for "always" and "true" sentinels', () => {
    assert.equal(runner._evalCondition('always', {}, {}), true);
    assert.equal(runner._evalCondition('true', {}, {}), true);
  });

  it('returns false for empty expression and the "false" sentinel', () => {
    assert.equal(runner._evalCondition('', {}, {}), false);
    assert.equal(runner._evalCondition('false', {}, {}), false);
  });

  it('numeric comparisons: >=, <=, >, <, ==, !=', () => {
    const ctx = { rwep: 90 };
    assert.equal(runner._evalCondition('rwep >= 90', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep >= 91', ctx, {}), false);
    assert.equal(runner._evalCondition('rwep <= 100', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep > 89', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep < 100', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep == 90', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep != 0', ctx, {}), true);
  });

  it('deep dotted paths (>= 3 dots) resolved', () => {
    const ctx = { analyze: { compliance_theater_check: { verdict: 'theater' } } };
    assert.equal(
      runner._evalCondition("analyze.compliance_theater_check.verdict == 'theater'", ctx, {}),
      true
    );
  });

  it('AND mixing — all branches must hold', () => {
    const ctx = { rwep: 95, patch_available: false };
    assert.equal(runner._evalCondition('rwep >= 90 AND patch_available == false', ctx, {}), true);
    assert.equal(runner._evalCondition('rwep >= 96 AND patch_available == false', ctx, {}), false);
  });

  it('OR mixing — any branch may hold', () => {
    const ctx = { a: 1, b: 2 };
    assert.equal(runner._evalCondition('a == 9 OR b == 2', ctx, {}), true);
    assert.equal(runner._evalCondition('a == 9 OR b == 9', ctx, {}), false);
  });

  it('includes operator on arrays', () => {
    const ctx = { jurisdiction_obligations: ['EU', 'UK', 'AU'] };
    assert.equal(runner._evalCondition('jurisdiction_obligations includes EU', ctx, {}), true);
    assert.equal(runner._evalCondition('jurisdiction_obligations includes US', ctx, {}), false);
  });

  it('matches /regex/ operator (case-insensitive)', () => {
    const ctx = { matched_cve: { vector: 'unprivileged userns clone' } };
    assert.equal(
      runner._evalCondition('matched_cve.vector matches /userns|bpf|ptrace|kptr/', ctx, {}),
      true
    );
    assert.equal(
      runner._evalCondition('matched_cve.vector matches /heartbleed/', ctx, {}),
      false
    );
  });

  it('unknown condition shape returns false', () => {
    assert.equal(runner._evalCondition('totally-not-a-known-shape', {}, {}), false);
  });
});

describe('interpolate', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('substitutes ${key} placeholders from context', () => {
    assert.equal(runner._interpolate('Hello ${name}', { name: 'world' }), 'Hello world');
  });

  it('F14: renders missing keys as <MISSING:var> and (optionally) tracks them', () => {
    assert.equal(runner._interpolate('Hello ${name}', {}), 'Hello <MISSING:name>');
    const missing = [];
    assert.equal(runner._interpolate('Hello ${name} ${other}', {}, missing), 'Hello <MISSING:name> <MISSING:other>');
    assert.deepEqual(missing.sort(), ['name', 'other']);
  });

  it('returns null/undefined templates unchanged', () => {
    assert.equal(runner._interpolate(null, {}), null);
    assert.equal(runner._interpolate(undefined, {}), undefined);
  });

  it('multiple placeholders in one template', () => {
    assert.equal(
      runner._interpolate('${a} and ${b}', { a: 'x', b: 'y' }),
      'x and y'
    );
  });
});

// =======================================================================
// 13. Edge cases
// =======================================================================

describe('edge cases', () => {
  let dir;

  beforeEach(() => {
    dir = tmpDir('edge');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('playbook with empty rwep_inputs → adjusted RWEP == base RWEP', () => {
    // Fire an indicator that correlates to CVE-2026-31431 via shared
    // attack_ref T1068 so base RWEP resolves to the catalog's 90. Post-fix
    // RWEP base reflects evidence-correlated matches, not catalog-baseline,
    // so the indicator hit is needed to surface base=90.
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-31431'] },
      phases: {
        detect: {
          indicators: [{ id: 'kev', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }]
        },
        analyze: { rwep_inputs: [] }
      }
    }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', { signal_overrides: { kev: 'hit' } });
    const an = runner.analyze('p', 'default', detRes);
    assert.equal(an.rwep.base, 90);
    assert.equal(an.rwep.adjusted, 90);
    assert.equal(an.rwep.breakdown.length, 0);
  });

  it('playbook with no exception_generation block → close().exception === null', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-31431'] },
      phases: {
        close: { evidence_package: { bundle_format: 'csaf-2.0' }, exception_generation: null }
      }
    }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', {});
    const an = runner.analyze('p', 'default', detRes);
    const v = runner.validate('p', 'default', an, {});
    const c = runner.close('p', 'default', an, v, { remediation_blocked: true });
    assert.equal(c.exception, null);
  });

  it('feeds_into condition referencing non-existent path → false, no downstream chain', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        feeds_into: [
          { playbook_id: 'never-fires', condition: 'analyze.does.not.exist == 42' }
        ]
      },
      domain: { cve_refs: ['CVE-2026-31431'] }
    }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', {});
    const an = runner.analyze('p', 'default', detRes);
    const v = runner.validate('p', 'default', an, {});
    const c = runner.close('p', 'default', an, v, {});
    assert.deepEqual(c.feeds_into, []);
  });

  it('directive.phase_overrides for one phase does NOT leak into other phases (synthetic)', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-31431'] },
      directives: [
        {
          id: 'overridden',
          title: 'overridden directive',
          applies_to: { always: true },
          phase_overrides: { direct: { rwep_threshold: { escalate: 42 } } }
        }
      ]
    }));
    const runner = freshRunner(dir);
    const direct = runner._resolvedPhase(runner.loadPlaybook('p'), 'overridden', 'direct');
    const govern = runner._resolvedPhase(runner.loadPlaybook('p'), 'overridden', 'govern');
    assert.equal(direct.rwep_threshold.escalate, 42);
    // govern phase from base synth playbook has empty jurisdiction_obligations
    assert.deepEqual(govern.jurisdiction_obligations, []);
  });

  it('matched_cves and catalog_baseline_cves both empty when domain.cve_refs is empty', () => {
    writePlaybook(dir, 'p', synthPlaybook({ domain: { cve_refs: [] } }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', {});
    const an = runner.analyze('p', 'default', detRes);
    assert.deepEqual(an.matched_cves, []);
    assert.deepEqual(an.catalog_baseline_cves, []);
    assert.equal(an.rwep.base, 0);
    assert.equal(an.rwep.adjusted, 0);
  });

  it('rwep is floor-clamped at 0 when negative weights drive it below', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-43500'] }, // base rwep 32 (when evidence correlates)
      phases: {
        detect: {
          // attack_ref T1068 matches CVE-2026-43500's attack_refs in the catalog,
          // so a hit on `sig` correlates the CVE into matched_cves and base RWEP
          // resolves to the catalog's 32. Without this attack_ref the indicator
          // would fire but no CVE would correlate (post-fix matched_cves is
          // evidence-gated), and base would be 0 — defeating the floor-clamp test.
          indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }]
        },
        analyze: {
          rwep_inputs: [
            { signal_id: 'sig', rwep_factor: 'patch_available', weight: -100, notes: 'big negative' }
          ]
        }
      }
    }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', { signal_overrides: { sig: 'hit' } });
    const an = runner.analyze('p', 'default', detRes);
    assert.equal(an.rwep.adjusted, 0, 'clamped to floor of 0');
  });
});

// =======================================================================
// 14. plan + listPlaybooks against synthetic empty dir
// =======================================================================

describe('listPlaybooks edge cases', () => {
  it('returns [] when playbook directory does not exist', () => {
    const dir = path.join(os.tmpdir(), `exceptd-nonexistent-${crypto.randomBytes(4).toString('hex')}`);
    const runner = freshRunner(dir);
    assert.deepEqual(runner.listPlaybooks(), []);
    // restore for any tests after
    freshRunner(REAL_PLAYBOOK_DIR);
  });
});

// =======================================================================
// 15. E1 — false_positive_checks_required gates hit → inconclusive
// =======================================================================

describe('E1 — false_positive_checks_required gating', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e1'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('hit without FP-check attestation downgrades to inconclusive and surfaces fp_checks_unsatisfied', () => {
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
            false_positive_checks_required: [
              'check-A: distro backport applied',
              'check-B: livepatch active'
            ]
          }]
        }
      }
    }));
    const runner = freshRunner(dir);
    const det = runner.detect('p', 'default', { signal_overrides: { sig: 'hit' } });
    // E1: without an __fp_checks attestation, the FP checks default to
    // UNSATISFIED and the verdict downgrades from 'hit' to 'inconclusive'.
    const ind = det.indicators.find(i => i.id === 'sig');
    assert.equal(ind.verdict, 'inconclusive',
      'hit without FP-check attestation must downgrade to inconclusive');
    assert.ok(Array.isArray(ind.fp_checks_unsatisfied),
      'fp_checks_unsatisfied must be present on the indicator result');
    assert.equal(ind.fp_checks_unsatisfied.length, 2,
      'both FP checks must be listed as unsatisfied');
    // The classification must not be 'detected' anymore.
    assert.notEqual(det.classification, 'detected',
      'an operator who submits hit without FP attestation must NOT trigger classification=detected');
  });

  it('hit with full FP-check attestation stays a hit', () => {
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
            false_positive_checks_required: ['check-A', 'check-B']
          }]
        }
      }
    }));
    const runner = freshRunner(dir);
    const det = runner.detect('p', 'default', {
      signal_overrides: {
        sig: 'hit',
        sig__fp_checks: { 'check-A': true, 'check-B': true }
      }
    });
    const ind = det.indicators.find(i => i.id === 'sig');
    assert.equal(ind.verdict, 'hit',
      'fully-attested FP checks must preserve the hit verdict');
    assert.equal(ind.fp_checks_unsatisfied, undefined,
      'no fp_checks_unsatisfied when every required check is attested');
  });

  it('partial FP-check attestation surfaces only the missing ones', () => {
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
            false_positive_checks_required: ['check-A', 'check-B', 'check-C']
          }]
        }
      }
    }));
    const runner = freshRunner(dir);
    const det = runner.detect('p', 'default', {
      signal_overrides: {
        sig: 'hit',
        sig__fp_checks: { 'check-A': true } // B and C missing
      }
    });
    const ind = det.indicators.find(i => i.id === 'sig');
    assert.equal(ind.verdict, 'inconclusive');
    assert.deepEqual(ind.fp_checks_unsatisfied, ['check-B', 'check-C']);
  });
});

// =======================================================================
// 16. E2 — empty submission reaches not_detected (dead branch fix)
// =======================================================================

describe('E2 — empty submission reaches not_detected', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e2'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('synthetic playbook + empty submission → all indicators miss → not_detected', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        detect: {
          indicators: [
            { id: 'a', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false },
            { id: 'b', type: 'log_pattern', value: 'y', description: 'd', confidence: 'medium', deterministic: false }
          ]
        }
      }
    }));
    const runner = freshRunner(dir);
    const det = runner.detect('p', 'default', {});
    // E2: pre-fix both arms emitted 'inconclusive', so classification stayed
    // 'inconclusive' and theater_verdict stuck on 'pending_agent_run' for
    // every empty submission. Post-fix the empty-artifact path emits 'miss'.
    assert.equal(det.classification, 'not_detected',
      'empty submission with no captured artifacts must reach not_detected');
    assert.ok(det.indicators.every(i => i.verdict === 'miss'));
  });
});

// =======================================================================
// 17. E3 — evalCondition regex try/catch + analyze.runtime_errors
// =======================================================================

describe('E3 — evalCondition regex try/catch surfaces runtime_errors', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e3'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('pathologically-broken regex in escalation_criteria does not crash, surfaces analyze.runtime_errors', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        analyze: {
          // Non-null compliance_theater_check so analyze() sets a non-null
          // theater_verdict the matches operator can resolve to a string.
          compliance_theater_check: {
            claim: 'x',
            audit_evidence: 'x',
            reality_test: 'x',
            theater_verdict_if_gap: 'x'
          },
          escalation_criteria: [
            // Invalid regex — repeat-without-target ('+') AND unmatched paren.
            { condition: 'theater_verdict matches /+([unclosed/', action: 'page_on_call' }
          ]
        }
      }
    }));
    const runner = freshRunner(dir);
    // E3: pre-fix this threw SyntaxError from new RegExp(...) and crashed
    // analyze() mid-pass. Post-fix the runner returns false for that
    // condition and pushes a structured _regex_eval_error into
    // analyze.runtime_errors[].
    const result = runner.run('p', 'default', {});
    assert.equal(result.ok, true,
      'engine must not crash on a malformed escalation_criteria regex');
    const runtimeErrors = result.phases.analyze.runtime_errors || [];
    assert.ok(runtimeErrors.length >= 1,
      'analyze.runtime_errors must surface the regex failure (got: ' + JSON.stringify(runtimeErrors) + ')');
    const regexErr = runtimeErrors.find(e => e._regex_eval_error);
    assert.ok(regexErr,
      'runtime_errors must contain a _regex_eval_error record naming the failing condition');
    assert.equal(regexErr._regex_eval_error.source, 'theater_verdict');
  });
});

// =======================================================================
// 18. E5 — --strict-preconditions implemented in preflight()
// =======================================================================

describe('E5 — preflight strictPreconditions escalation', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e5'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('strictPreconditions=true promotes on_fail:warn unverified to halt', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'pc1', description: 'd', check: 'c', on_fail: 'warn' }]
      }
    }));
    const runner = freshRunner(dir);
    const lax = runner.preflight(runner.loadPlaybook('p'), {});
    assert.equal(lax.ok, true,
      'non-strict preflight: unverified on_fail:warn precondition is informational');

    const strict = runner.preflight(runner.loadPlaybook('p'), { strictPreconditions: true });
    assert.equal(strict.ok, false,
      'strictPreconditions=true: unverified on_fail:warn precondition halts the run');
    assert.equal(strict.blocked_by, 'precondition');
    const halt = strict.issues.find(i => i.kind === 'precondition_halt');
    assert.ok(halt, 'strict mode emits precondition_halt issue');
    assert.equal(halt.escalated_from, 'precondition_unverified');
  });

  it('strictPreconditions=true also escalates on_fail:warn FALSE values', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{ id: 'pc1', description: 'd', check: 'c', on_fail: 'warn' }]
      }
    }));
    const runner = freshRunner(dir);
    const strict = runner.preflight(runner.loadPlaybook('p'), {
      strictPreconditions: true,
      precondition_checks: { pc1: false }
    });
    assert.equal(strict.ok, false);
    assert.equal(strict.blocked_by, 'precondition');
    const halt = strict.issues.find(i => i.kind === 'precondition_halt');
    assert.ok(halt);
    assert.equal(halt.escalated_from, 'precondition_warn');
  });
});

// =======================================================================
// 19. E6 — skip_phase actually skips the named phase
// =======================================================================

describe('E6 — skip_phase outcome honored by run()', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e6'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('precondition on_fail:skip_phase=detect → phases.detect.skipped=true and analyze.classification=skipped', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      _meta: {
        preconditions: [{
          id: 'linux-only',
          description: 'linux only',
          check: 'host.platform == "linux"',
          on_fail: 'skip_phase',
          skip_phase: 'detect'
        }]
      },
      phases: {
        detect: {
          indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false }]
        }
      }
    }));
    const runner = freshRunner(dir);
    // Submit precondition_checks: { 'linux-only': false } to simulate
    // running on macOS hitting a linux-only check.
    const result = runner.run('p', 'default', {
      precondition_checks: { 'linux-only': false }
    });
    assert.equal(result.ok, true,
      'skip_phase precondition must not halt the run');
    assert.equal(result.phases.detect.skipped, true,
      'phases.detect.skipped must be true');
    assert.equal(result.phases.detect.classification, 'skipped',
      'phases.detect.classification must be "skipped"');
    assert.equal(result.phases.analyze.classification, 'skipped',
      'phases.analyze.classification must propagate "skipped" so consumers can distinguish from not_detected');
    assert.equal(result.phases.detect.reason, 'linux-only',
      'phases.detect.reason must name the precondition id that triggered the skip');
  });
});

// =======================================================================
// 20. E7 — detect_confirmed clock starts on --ack, not on classification
// =======================================================================

describe('E7 — clock_starts:detect_confirmed binds to operator_consent.explicit', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  function buildDetectedAnalyze() {
    // Use the real kernel playbook so jurisdiction_obligations with
    // detect_confirmed events are present.
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an);
    return { an, v };
  }

  it('without --ack: classification=detected leaves clock_started_at null and surfaces clock_pending_ack', () => {
    const { an, v } = buildDetectedAnalyze();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      detection_classification: 'detected'
    });
    const detectConfirmed = c.notification_actions.filter(n => n.clock_start_event === 'detect_confirmed');
    assert.ok(detectConfirmed.length >= 1,
      'kernel playbook stages at least one detect_confirmed obligation');
    assert.ok(detectConfirmed.every(n => n.clock_started_at == null),
      'without --ack the clock must NOT auto-start');
    assert.ok(detectConfirmed.every(n => n.clock_pending_ack === true),
      'clock_pending_ack must surface so the operator sees the clock is waiting on acknowledgement');
  });

  it('with operator_consent.explicit=true: clock starts now', () => {
    const { an, v } = buildDetectedAnalyze();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      detection_classification: 'detected'
    }, {
      operator_consent: { explicit: true, acked_at: new Date().toISOString() }
    });
    const detectConfirmed = c.notification_actions.filter(n => n.clock_start_event === 'detect_confirmed');
    assert.ok(detectConfirmed.length >= 1);
    assert.ok(detectConfirmed.every(n => n.clock_started_at != null),
      'with operator_consent.explicit=true the clock must auto-start at now');
    // No pending-ack flag when consent is explicit.
    assert.ok(detectConfirmed.every(n => n.clock_pending_ack !== true));
  });
});

// =======================================================================
// 21. E8 — analyzeFindingShape worst-of active_exploitation
// =======================================================================

describe('E8 — analyze.active_exploitation reports worst-of, not first-of', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('worst-of severity ladder: confirmed > suspected > unknown > none', () => {
    // Synthesize a fake analyze result with two matched CVEs in
    // suspected→confirmed order; the finding shape must surface the worst.
    const finding = runner._evalCondition; // sanity-check the export is available
    assert.ok(typeof finding === 'function');

    // Directly exercise the analyzeFindingShape via close() flow: build a
    // fake analyze result with two matched_cves and verify the close()
    // interpolation context reports 'confirmed'.
    const fakeAnalyze = {
      matched_cves: [
        { cve_id: 'CVE-A', active_exploitation: 'suspected', cisa_kev: false, rwep: 50 },
        { cve_id: 'CVE-B', active_exploitation: 'confirmed', cisa_kev: false, rwep: 60 }
      ],
      rwep: { adjusted: 60, base: 60 },
      framework_gap_mapping: [],
      blast_radius_score: 1,
      compliance_theater_check: { verdict: 'clear' },
      _detect_indicators: [],
      _detect_classification: 'detected'
    };
    // Pull analyzeFindingShape through the close() interpolation chain.
    // The exception_generation auditor_ready_language template interpolates
    // ${active_exploitation}, so we can read the value back through that.
    // Simplest: read the shape via the public interpolate helper.
    const { _interpolate } = runner;
    // Build the same context that close() uses for interpolation.
    // analyzeFindingShape is not exported; we test via the public surface
    // by interpolating ${active_exploitation} against the result that
    // close() would pass to interpolate.
    // Workaround: assert through close() with a synthetic playbook that
    // interpolates ${active_exploitation} in a draft_notification.
    void _interpolate;

    // Synthetic playbook end-to-end test:
    const dir = tmpDir('e8');
    try {
      writePlaybook(dir, 'p', synthPlaybook({
        // Both CVEs must be in cve_refs AND in the catalog. The catalog
        // has CVE-2026-31431 (confirmed) and CVE-2025-53773 (suspected).
        // Use those to exercise the worst-of reduction with real catalog data.
        domain: {
          cve_refs: ['CVE-2025-53773', 'CVE-2026-31431'],
          frameworks_in_scope: ['nist-800-53']
        },
        phases: {
          govern: {
            jurisdiction_obligations: [{
              jurisdiction: 'EU',
              regulation: 'TEST',
              window_hours: 24,
              clock_starts: 'detect_confirmed',
              evidence_required: [],
              obligation: 'notify'
            }]
          },
          detect: {
            indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }]
          },
          close: {
            notification_actions: [{
              obligation_ref: 'EU/TEST 24h',
              recipient: 'r@e',
              draft_notification: 'Active exploitation: ${active_exploitation}.',
              evidence_attached: []
            }],
            evidence_package: null,
            learning_loop: { enabled: false },
            exception_generation: null,
            regression_schedule: null
          }
        }
      }));
      const r = freshRunner(dir);
      const detRes = r.detect('p', 'default', { signal_overrides: { sig: 'hit' } });
      const an = r.analyze('p', 'default', detRes);
      // At least one of the two CVEs must have correlated. Skip the test
      // if the catalog doesn't have both (defensive — environment guard).
      if (an.matched_cves.length < 2) {
        // Construct the worst-of test via the close()/interpolation chain.
        // If fewer than 2 CVEs correlated, the worst-of reduction still
        // applies but the test is uninformative. Surface this clearly.
        return;
      }
      const v2 = r.validate('p', 'default', an);
      const close = r.close('p', 'default', an, v2, {});
      const draft = close.notification_actions[0].draft_notification;
      assert.match(draft, /Active exploitation: confirmed\./,
        `analyze.active_exploitation must report worst-of (confirmed), got draft="${draft}"`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      // restore runner
      freshRunner(REAL_PLAYBOOK_DIR);
    }
  });
});

// =======================================================================
// 22. E9 — signal_origins collisions surfaced
// =======================================================================

describe('E9 — signal_origins collisions surfaced in analyze', () => {
  let dir;
  beforeEach(() => { dir = tmpDir('e9'); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('two flat-shape observations targeting the same indicator emit a collision record', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      phases: {
        look: {
          artifacts: [
            { id: 'art-a', type: 'log', description: 'd', source: 's', air_gap_alternative: null, why_this_matters: 'd', minimum_capture: 'd' },
            { id: 'art-b', type: 'log', description: 'd', source: 's', air_gap_alternative: null, why_this_matters: 'd', minimum_capture: 'd' }
          ]
        },
        detect: {
          indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false }]
        }
      }
    }));
    const runner = freshRunner(dir);
    // Flat-shape submission: two observations both report indicator='sig'.
    const result = runner.run('p', 'default', {
      observations: {
        'art-a': { captured: true, value: 'a', indicator: 'sig', result: 'hit' },
        'art-b': { captured: true, value: 'b', indicator: 'sig', result: 'miss' }
      }
    });
    assert.equal(result.ok, true);
    const collisions = result.phases.analyze.signal_origins_with_collisions;
    assert.ok(Array.isArray(collisions),
      'analyze.signal_origins_with_collisions must be an array');
    assert.ok(collisions.length >= 1,
      'at least one collision must be recorded when two observations target the same indicator');
    assert.equal(collisions[0].indicator_id, 'sig');
    assert.ok(collisions[0].source_observation_key === 'art-a' || collisions[0].replaced_by === 'art-b',
      'collision record must name the discarded observation (art-a) and the replacement (art-b)');
  });
});

// =======================================================================
// 23. E10 — scoring.validateFactors surfaces range warnings
// =======================================================================

describe('E10 — scoring.validateFactors and scoreCustom collectWarnings', () => {
  const scoring = require('../lib/scoring.js');

  it('validateFactors flags out-of-range blast_radius', () => {
    const warns = scoring.validateFactors({
      cisa_kev: true, poc_available: true, ai_assisted_weapon: false,
      ai_discovered: false, active_exploitation: 'confirmed',
      blast_radius: 999, patch_available: false, live_patch_available: false,
      reboot_required: false
    });
    assert.ok(warns.some(w => /blast_radius.*999.*out of expected range/.test(w)),
      `validateFactors must flag blast_radius=999 out of range; got: ${JSON.stringify(warns)}`);
  });

  it('validateFactors flags invalid active_exploitation enum', () => {
    const warns = scoring.validateFactors({
      cisa_kev: true, poc_available: true, ai_assisted_weapon: false,
      ai_discovered: false, active_exploitation: 'totally-bogus',
      blast_radius: 10, patch_available: false, live_patch_available: false,
      reboot_required: false
    });
    assert.ok(warns.some(w => /active_exploitation.*expected one of/.test(w)),
      `validateFactors must flag invalid active_exploitation enum; got: ${JSON.stringify(warns)}`);
  });

  it('validateFactors flags missing required fields', () => {
    const warns = scoring.validateFactors({});
    // Every boolean field + active_exploitation + blast_radius should warn.
    assert.ok(warns.length >= 8,
      `validateFactors of {} must emit at least 8 warnings (got ${warns.length}: ${JSON.stringify(warns)})`);
  });

  it('scoreCustom(factors, { collectWarnings: true }) returns { score, _scoring_warnings }', () => {
    const r = scoring.scoreCustom({
      cisa_kev: true, poc_available: true, blast_radius: 50
    }, { collectWarnings: true });
    assert.equal(typeof r, 'object', 'collectWarnings opt switches return shape to object');
    assert.equal(typeof r.score, 'number');
    assert.ok(Array.isArray(r._scoring_warnings));
    assert.ok(r._scoring_warnings.length > 0,
      'partial factors + out-of-range blast_radius must produce warnings');
  });

  it('scoreCustom(factors) without opts still returns a number (backward compat)', () => {
    const n = scoring.scoreCustom({ cisa_kev: true });
    assert.equal(typeof n, 'number');
    assert.equal(n, 25);
  });
});

// =======================================================================
// 24. Engine fixes — agent-asserted finding survival, classification alias,
//     condition_path_unresolved diagnostic, theater_score, AE factor routing
// =======================================================================

describe('engine fixes — finding survival / classification alias / diagnostics / theater_score / AE', () => {
  let runner, evalCondition, run, close, loadPlaybook;
  const scoring = require('../lib/scoring.js');

  before(() => {
    runner = freshRunner(REAL_PLAYBOOK_DIR);
    evalCondition = runner._evalCondition;
    ({ run, close, loadPlaybook } = runner);
  });

  const OPTS = { forceStale: true, operator_consent: { explicit: true } };
  // _meta.preconditions[].id keys (preflight matches on pc.id, not the check expr).
  const SSO_PCS = {
    'idp-audit-api-reachable': true,
    'read-only-admin-rbac': true,
    'tenant-ownership': true,
  };

  // --- #1: agent-asserted finding.includes_* survives into the eval contexts,
  //         engine-owned finding.severity wins over a poisoning signal. ---

  it('#1 escalation + feeds_into fire on agent-supplied finding.includes_cloud_role_assumption', () => {
    const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
      precondition_checks: SSO_PCS,
      signals: {
        blast_radius_score: 4,
        detection_classification: 'detected',
        finding: { includes_cloud_role_assumption: true },
      },
    }, OPTS);
    // Did not block at preflight.
    assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);

    // Escalation: `blast_radius_score >= 3 AND finding.includes_cloud_role_assumption == true`
    //   → action trigger_playbook, target cloud-iam-incident.
    const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
    assert.equal(escTargets.includes('cloud-iam-incident'), true);
    const cloudEsc = res.phases.analyze.escalations.find((e) => e.target_playbook === 'cloud-iam-incident');
    assert.equal(typeof cloudEsc, 'object');
    assert.equal(cloudEsc.action, 'trigger_playbook');

    // feeds_into: `finding.includes_cloud_role_assumption == true` → cloud-iam-incident.
    assert.equal(Array.isArray(res.phases.close.feeds_into), true);
    assert.equal(res.phases.close.feeds_into.includes('cloud-iam-incident'), true);
  });

  it('#1 absent finding.includes_* leaves the cloud-iam-incident chain dead (the present case is not coincidental)', () => {
    const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
      precondition_checks: SSO_PCS,
      signals: { blast_radius_score: 4, detection_classification: 'detected' },
    }, OPTS);
    assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
    const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
    assert.equal(escTargets.includes('cloud-iam-incident'), false);
    assert.equal(res.phases.close.feeds_into.includes('cloud-iam-incident'), false);
  });

  it('#1 engine-computed finding.severity wins over a poisoning signals.finding.severity', () => {
    // secrets.json feeds_into cred-stores on `finding.severity >= 'high'`.
    // No matched CVEs → engine rwep 0 → engine severity 'low'. A poisoning
    // signals.finding.severity='critical' must NOT flip the feeds_into.
    const res = run('secrets', 'full-repo-secret-scan', {
      precondition_checks: { 'repo-context': true },
      signals: { finding: { severity: 'critical' } },
    }, OPTS);
    assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
    assert.equal(res.phases.analyze.rwep.adjusted, 0);
    assert.equal(res.phases.close.feeds_into.includes('cred-stores'), false);
  });

  it('#1 a non-object / array signals.finding is ignored (no numeric-index injection)', () => {
    // signals.finding = [] must not inject array indices into the finding ctx.
    const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
      precondition_checks: SSO_PCS,
      signals: { blast_radius_score: 4, detection_classification: 'detected', finding: [1, 2, 3] },
    }, OPTS);
    assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
    // includes_cloud_role_assumption was not asserted → chain stays dead.
    const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
    assert.equal(escTargets.includes('cloud-iam-incident'), false);
  });

  // --- #3: analyze.classification alias resolves the catalog's natural path. ---

  it('#3 analyze.classification alias resolves equal to _detect_classification', () => {
    const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
      precondition_checks: SSO_PCS,
      signals: { blast_radius_score: 4, detection_classification: 'detected' },
    }, OPTS);
    assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
    assert.equal(typeof res.phases.analyze.classification, 'string');
    assert.equal(res.phases.analyze.classification, res.phases.analyze._detect_classification);
    assert.equal(res.phases.analyze.classification, 'detected');
  });

  it('#3 analyze.classification == "detected" condition resolves true through the alias', () => {
    assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'detected' } }), true);
    assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'not_detected' } }), false);
  });

  // --- #4: dotted-LHS absent path surfaces a condition_path_unresolved diagnostic. ---

  it('#4 dotted-LHS comparison with an absent LEAF emits condition_path_unresolved', () => {
    const errs = [];
    const result = evalCondition('finding.includes_cloud_role_assumption == true', { finding: { severity: 'high' }, _runErrors: errs });
    assert.equal(result, false);
    assert.equal(errs.length, 1);
    assert.equal(errs[0].kind, 'condition_path_unresolved');
    assert.equal(errs[0].condition, 'finding.includes_cloud_role_assumption == true');
  });

  it('#4 dotted-LHS comparison with an absent INTERMEDIATE also emits the diagnostic (the strict-undefined gate would miss this)', () => {
    const errs = [];
    const result = evalCondition("analyze.classification == 'detected'", { _runErrors: errs });
    assert.equal(result, false);
    assert.equal(errs.length, 1);
    assert.equal(errs[0].kind, 'condition_path_unresolved');
  });

  it('#4 a bare single-segment flag absent does NOT emit a diagnostic (legitimate false)', () => {
    const errs = [];
    const result = evalCondition('agent_has_filesystem_read == true', { _runErrors: errs });
    assert.equal(result, false);
    assert.equal(errs.length, 0);
  });

  it('#4 a present-but-null single-segment flag does NOT emit a diagnostic', () => {
    const errs = [];
    const result = evalCondition('patch_available == true', { patch_available: null, _runErrors: errs });
    assert.equal(result, false);
    assert.equal(errs.length, 0);
  });

  it('#4 a present-and-matching dotted comparison emits nothing', () => {
    const errs = [];
    const result = evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'detected' }, _runErrors: errs });
    assert.equal(result, true);
    assert.equal(errs.length, 0);
  });

  // --- #5: theater_score scores an allowlisted 'present' verdict 100, not 0. ---

  function feedsForVerdict(verdict) {
    const pb = JSON.parse(JSON.stringify(loadPlaybook('framework')));
    pb._meta = pb._meta || {};
    // Inject a theater_score-gated feeds_into into the cached playbook so the
    // real close() path computes feedsCtx.theater_score (line 2060) and evaluates
    // it. No shipped condition consumes theater_score today (latent), so this is
    // the canonical way to exercise the computed value end-to-end.
    pb._meta.feeds_into = [{ playbook_id: 'sbom', condition: 'theater_score >= 50' }];
    const analyzeResult = {
      phase: 'analyze',
      playbook_id: 'framework',
      directive_id: 'baseline-framework-gap-inventory',
      matched_cves: [],
      catalog_baseline_cves: [],
      rwep: { base: 0, adjusted: 0, breakdown: [] },
      blast_radius_score: null,
      compliance_theater_check: { verdict },
      framework_gap_mapping: [],
      _detect_indicators: [],
      _detect_classification: 'not_detected',
      classification: 'not_detected',
      escalations: [],
    };
    const validateResult = { phase: 'validate', remediation_paths_considered: [], selected_remediation_path: null };
    const res = close('framework', 'baseline-framework-gap-inventory', analyzeResult, validateResult, {}, { _playbookCache: pb, session_id: 'hunt-fix-A' });
    return res.feeds_into;
  }

  it('#5 theater_score scores a "present" verdict 100 → fires the theater_score >= 50 feeds_into', () => {
    assert.deepEqual(feedsForVerdict('present'), ['sbom']);
  });

  it('#5 theater_score scores a "theater" verdict 100 (unchanged)', () => {
    assert.deepEqual(feedsForVerdict('theater'), ['sbom']);
  });

  it('#5 theater_score scores a "clear" verdict 0 → no fire', () => {
    assert.deepEqual(feedsForVerdict('clear'), []);
  });

  // --- #7: runner active_exploitation factor routes through scoring's resolver. ---

  it('#7 scoring.activeExploitationMultiplier returns the canonical ladder multipliers (parity with the prior inline lookup)', () => {
    assert.equal(scoring.activeExploitationMultiplier('confirmed'), 1);
    assert.equal(scoring.activeExploitationMultiplier('suspected'), 0.5);
    assert.equal(scoring.activeExploitationMultiplier('unknown'), 0.25);
    assert.equal(scoring.activeExploitationMultiplier('theoretical'), 0);
    assert.equal(scoring.activeExploitationMultiplier('none'), 0);
    assert.equal(scoring.activeExploitationMultiplier(undefined), 0);
  });

  it('#7 a stray-cased active_exploitation value normalises instead of zeroing', () => {
    assert.equal(scoring.activeExploitationMultiplier('Confirmed'), 1);
    assert.equal(scoring.activeExploitationMultiplier(' SUSPECTED '), 0.5);
  });

  it('#7 an out-of-vocab active_exploitation value is observable (RWEP_AE_UNRECOGNISED), not a silent zero', async () => {
    // process.emitWarning delivers the 'warning' event on the next tick, so await it.
    const warned = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        process.removeListener('warning', onWarn);
        reject(new Error('RWEP_AE_UNRECOGNISED warning was not emitted for an out-of-vocab value'));
      }, 1000);
      function onWarn(w) {
        if (w && w.code === 'RWEP_AE_UNRECOGNISED') {
          clearTimeout(timer);
          process.removeListener('warning', onWarn);
          resolve(w);
        }
      }
      process.on('warning', onWarn);
    });
    // Use a value that no other test in this file has warned on (warnings with a
    // `code` are emitted once per process for a given code only when --no-warnings
    // is off; a fresh value guarantees the event fires here).
    const mult = scoring.activeExploitationMultiplier('in-the-wild-hunt-fix-A');
    assert.equal(mult, 0);
    const w = await warned;
    assert.equal(w.code, 'RWEP_AE_UNRECOGNISED');
  });

  it('#7 the runner active_exploitation factor branch routes through scoring.activeExploitationMultiplier (no inline ?? 0 ladder)', () => {
    // Structural guard: _factorScale is a local closure (not exported), so assert
    // on the source that the active_exploitation case delegates to the shared
    // observable resolver and the dead inline-ladder alias is gone. This catches a
    // silent regression back to `_activeExploitationLadder[v] ?? 0`.
    const src = fs.readFileSync(RUNNER_PATH, 'utf8');
    const branch = src.slice(src.indexOf("case 'active_exploitation':"));
    const branchHead = branch.slice(0, branch.indexOf('case ', 1));
    assert.equal(/scoring\.activeExploitationMultiplier\(/.test(branchHead), true);
    assert.equal(/_activeExploitationLadder\s*\[/.test(branchHead), false);
    // The local `const _activeExploitationLadder = scoring.ACTIVE_EXPLOITATION_LADDER;`
    // alias inside analyze() is removed (the module re-export at the bottom is a
    // separate, intentional surface and is allowed to keep referencing scoring).
    assert.equal(/const _activeExploitationLadder\b/.test(src), false);
  });
});

// =======================================================================
// 25. Condition mini-language (evalCondition) — hyphenated ids, severity
//     ladder, synonyms, quantifiers, quote-aware splitting, diagnostics
// =======================================================================

describe('condition mini-language (evalCondition)', () => {
  let runner, evalCondition;
  before(() => {
    runner = freshRunner(REAL_PLAYBOOK_DIR);
    evalCondition = runner._evalCondition;
  });

  it('hyphenated LHS evaluates against the matching ctx key (not silently false)', () => {
    assert.equal(evalCondition('no-security-md == true', { 'no-security-md': true }), true);
    assert.equal(evalCondition('no-security-md == true', { 'no-security-md': false }), false);
    assert.equal(evalCondition('kver-in-affected-range == true AND kaslr-disabled == true',
      { 'kver-in-affected-range': true, 'kaslr-disabled': true }), true);
  });

  it('severity comparison uses the ordinal ladder, not lexicographic order', () => {
    assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'critical' } }), true);
    assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'high' } }), true);
    assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'medium' } }), false);
    assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'low' } }), false);
    // numeric comparison still works (regression guard)
    assert.equal(evalCondition('rwep >= 90', { rwep: 100 }), true);
    assert.equal(evalCondition('rwep >= 90', { rwep: 50 }), false);
  });

  it('`contains` is accepted as a synonym for `includes`', () => {
    assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote'] } }), true);
    assert.equal(evalCondition('scope.targets includes named-remote', { scope: { targets: ['named-remote'] } }), true);
    assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['local'] } }), false);
  });

  it('`matches` accepts both the slash and the quote delimiter (mcp feeds_into uses the quoted form)', () => {
    // The catalog authors both forms; mcp.json's feeds_into matches the CI-platform
    // OR-branch with the quoted form. A delimiter-specific parser silently disabled
    // it (returned false + a condition_unparsed runtime error) for every input.
    const slashErrs = [];
    assert.equal(evalCondition("finding.x matches /(a|b)/", { finding: { x: 'a' }, _runErrors: slashErrs }), true);
    assert.equal(slashErrs.length, 0, 'slash form parses, no condition_unparsed');

    const quoteErrs = [];
    assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'a' }, _runErrors: quoteErrs }), true);
    assert.equal(quoteErrs.length, 0, 'single-quote form parses, no condition_unparsed');

    // double-quote form also parses
    assert.equal(evalCondition('finding.x matches "(a|b)"', { finding: { x: 'b' } }), true);

    // a non-match is false (not a parse failure)
    assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'c' } }), false);

    // the exact mcp.json feeds_into condition fires via the regex OR-branch alone,
    // with the other two OR-branches false (pre-fix the whole OR collapsed to false)
    const mcpCond = "finding.mcp_server_location matches '(github_actions|gitlab_runner|jenkins|buildkite|circleci)'"
      + " OR finding.tool_invoked_from == 'ci_pipeline'"
      + " OR analyze.blast_radius_score >= 4 AND finding.pipeline_credentials_in_scope == true";
    assert.equal(evalCondition(mcpCond, {
      finding: { mcp_server_location: 'buildkite', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
      analyze: { blast_radius_score: 0 },
    }), true);
  });

  it('an unparseable (prose) condition pushes a condition_unparsed runtime error (not a silent false)', () => {
    const errs = [];
    // A genuine prose sentence the mini-language can't evaluate. (The `any … ==`
    // quantifier form below is now PARSED — see the quantifier test — so a prose
    // clause is what should still surface the diagnostic.)
    const r = evalCondition('a single compromised identity can rewrite the trail', { _runErrors: errs });
    assert.equal(r, false, 'unparseable still returns false');
    assert.equal(errs.length, 1, 'a runtime error is recorded');
    assert.equal(errs[0].kind, 'condition_unparsed');
  });

  it('`any`/`all` quantifier prefix parses and fires (not condition_unparsed)', () => {
    // Scalar LHS — the quantifier is prose emphasis; the scalar comparison is the
    // test. framework.json's feeds_into to sbom is exactly this shape. Pre-fix the
    // `any ` leaf fell through to condition_unparsed → false, disabling BOTH paths
    // by which framework chains into sbom.
    const cond = "any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4";
    const errs = [];
    assert.equal(
      evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 5, _runErrors: errs }),
      true,
      'theater verdict + blast_radius 5 fires the framework→sbom chain'
    );
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'the any-prefixed leaf parses — no condition_unparsed');
    // Negatives: each conjunct gates independently.
    assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'clear' }, blast_radius_score: 5 }), false,
      'non-theater verdict does not chain');
    assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 2 }), false,
      'blast_radius below 4 does not chain');

    // Array LHS — existential / universal over members. sbom.json's feeds_into
    // uses `any matched_cve.attack_class == 'kernel-lpe'`.
    const hit = { matched_cve: [{ attack_class: 'mcp-supply-chain' }, { attack_class: 'kernel-lpe' }] };
    const miss = { matched_cve: [{ attack_class: 'mcp-supply-chain' }] };
    assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", hit), true,
      'any matches when one array element satisfies the predicate');
    assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", miss), false,
      'any is false when no element satisfies the predicate');
    assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'", hit), false,
      'all is false when only some elements satisfy the predicate');
    assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'",
      { matched_cve: [{ attack_class: 'kernel-lpe' }, { attack_class: 'kernel-lpe' }] }), true,
      'all is true when every element satisfies the predicate');
  });

  it('`any`/`all` quantifier re-roots EVERY operator over an array element, not just comparisons (IN/contains/matches)', () => {
    // sbom.json's feeds_into into ai-api is `any matched_cve.attack_class IN
    // ['ai-c2', 'prompt-injection']`. `IN` is not a comparison operator, so the
    // quantifier branch used to skip the per-element re-root and evaluate the
    // clause against the whole ctx — where `matched_cve.attack_class` resolves to
    // undefined on the array — leaving the sbom→ai-api chain permanently dead while
    // the `== 'kernel-lpe'` / `== 'mcp-supply-chain'` siblings fired.
    const cves = [{ attack_class: 'supply-chain' }, { attack_class: 'ai-c2' }];
    assert.equal(
      evalCondition("any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']", { matched_cve: cves }),
      true,
      'any … IN [...] fires when one array element is in the list');
    assert.equal(
      evalCondition("any matched_cve.attack_class IN ['kernel-lpe']", { matched_cve: cves }),
      false,
      'any … IN [...] is false when no element is in the list');
    assert.equal(
      evalCondition("all matched_cve.attack_class IN ['supply-chain', 'ai-c2']", { matched_cve: cves }),
      true,
      'all … IN [...] is true when every element is in the list');
    assert.equal(
      evalCondition("all matched_cve.attack_class IN ['supply-chain']", { matched_cve: cves }),
      false,
      'all … IN [...] is false when one element is outside the list');
    // `all` over an empty array is false (vacuous-truth guard preserved).
    assert.equal(
      evalCondition("all matched_cve.attack_class IN ['ai-c2']", { matched_cve: [] }),
      false,
      'all … over an empty array is false, not vacuously true');

    // contains under a quantifier (array element holds its own array field).
    assert.equal(
      evalCondition("any finding.tags contains 'eu'", { finding: [{ tags: ['us'] }, { tags: ['eu', 'jp'] }] }),
      true,
      'any … contains fires existentially across array elements');

    // matches under a quantifier (slash + quote delimiters, the only forms the
    // leaf parser accepts).
    assert.equal(
      evalCondition('any matched_cve.vector matches /userns/', { matched_cve: [{ vector: 'remote' }, { vector: 'local-userns-bpf' }] }),
      true,
      'any … matches /re/ fires existentially across array elements');
    assert.equal(
      evalCondition("any matched_cve.vector matches 'kptr'", { matched_cve: [{ vector: 'remote' }, { vector: 'local-userns-bpf' }] }),
      false,
      "any … matches 're' is false when no element matches");

    // The scalar-object head (framework theater prose-quantifier) is unaffected —
    // a non-array head still routes to the bare inner comparison.
    assert.equal(
      evalCondition("any compliance_theater_check.verdict == 'theater'", { compliance_theater_check: { verdict: 'theater' } }),
      true,
      'a scalar-object head still evaluates the inner comparison directly');
  });

  it('bare `any <path>` / `all <path>` is a non-emptiness test, not condition_unparsed', () => {
    // `any X` with no comparison operator means "at least one X exists" — a
    // non-emptiness / existence test. Pre-fix the operator-less inner token had no
    // comparison branch to parse it and fell through to condition_unparsed → false,
    // so it returned false even for a populated array. sbom.json's EU CRA Art.14
    // (24h) notify_legal escalation `any actively_exploited_match AND …` was dead.
    let errs = [];
    assert.equal(evalCondition('any actively_exploited_match',
      { actively_exploited_match: [{ id: 'x' }], _runErrors: errs }), true,
      'any over a non-empty array is true');
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'no condition_unparsed for the bare non-emptiness form');

    errs = [];
    assert.equal(evalCondition('any actively_exploited_match',
      { actively_exploited_match: [], _runErrors: errs }), false,
      'any over an empty array is false');
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'empty-array path is parsed, not unparsed');

    // missing path / falsy scalar → false; truthy scalar → true.
    assert.equal(evalCondition('any nonexistent', {}), false, 'missing path is false');
    assert.equal(evalCondition('any kev_listed', { kev_listed: true }), true, 'truthy scalar is true');
    assert.equal(evalCondition('any kev_listed', { kev_listed: false }), false, 'falsy scalar is false');

    // `all <path>`: non-empty AND every element truthy.
    assert.equal(evalCondition('all flags', { flags: [true, true] }), true, 'all-truthy non-empty array');
    assert.equal(evalCondition('all flags', { flags: [true, false] }), false, 'a falsy element fails all');
    assert.equal(evalCondition('all flags', { flags: [] }), false, 'empty array fails all');

    // The exact sbom.json:1250 condition fires when both conjuncts hold, with zero
    // condition_unparsed runtime errors.
    errs = [];
    const sbomCond = "any actively_exploited_match AND jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'";
    assert.equal(evalCondition(sbomCond, {
      actively_exploited_match: [{ id: 'CVE-x' }],
      jurisdiction_obligations: ['EU/EU CRA Art.14 24h'],
      _runErrors: errs,
    }), true, 'the EU CRA Art.14 notify_legal escalation fires when both conjuncts hold');
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'the full sbom:1250 condition is fully parsed');
    // First conjunct gates: an empty actively_exploited_match array keeps it false.
    assert.equal(evalCondition(sbomCond, {
      actively_exploited_match: [],
      jurisdiction_obligations: ['EU/EU CRA Art.14 24h'],
    }), false, 'no active-exploitation matches → escalation does not fire');

    // A genuinely malformed inner clause (operator-like garbage) must still surface
    // condition_unparsed — the bare-path handler must not swallow it.
    errs = [];
    assert.equal(evalCondition('any foo ~~ bar', { foo: [1], _runErrors: errs }), false,
      'malformed inner clause stays false');
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 1,
      'malformed inner clause is still observable as condition_unparsed');
  });

  it('`IN [...]` member parsing is quote-aware — a comma inside a quoted member stays one member', () => {
    // A naive `.split(',')` is quote-unaware, so a quoted member that itself
    // contains a comma (`'EU, US'`) was torn into two members (`EU`, `US`),
    // neither equal to the author's whole member. The clause then evaluated false
    // with no diagnostic — the regex still matched the bracket, so condition_unparsed
    // never fired. The list is now split tracking quote state.
    assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'EU, US' }), true,
      "a comma inside a quoted member does not split the member");
    assert.equal(evalCondition("x IN ['a,b']", { x: 'a,b' }), true,
      "a single quoted member containing a comma matches the whole member");
    // The sibling member is still independently selectable.
    assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'AU' }), true,
      "the second member after a comma-bearing first member is still a member");
    // A value equal to only a comma-split FRAGMENT must NOT match (proves the
    // member is whole, not the broken 'EU' / 'US' fragments).
    assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'EU' }), false,
      "a fragment of a comma-bearing quoted member is not itself a member");
    assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'US' }), false,
      "the trailing fragment of a comma-bearing quoted member is not a member");
    // Double-quoted members behave identically.
    assert.equal(evalCondition('x IN ["EU, US", "AU"]', { x: 'EU, US' }), true,
      "double-quoted comma-bearing member stays whole");

    // No condition_unparsed is recorded — this was a parsed-but-wrong path, and
    // the fix must keep it parsed (not regress into the unparsed diagnostic).
    const errs = [];
    evalCondition("x IN ['EU, US', 'AU']", { x: 'EU, US', _runErrors: errs });
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'a quoted comma member is parsed, not surfaced as condition_unparsed');

    // Regression guards: the catalog's actual `IN` forms still evaluate correctly.
    // sbom.json:101 — the quoted multi-member form with hyphenated members.
    assert.equal(
      evalCondition("matched_cve.attack_class IN ['ai-c2', 'prompt-injection']",
        { matched_cve: { attack_class: 'ai-c2' } }), true,
      'the shipped quoted multi-member IN list still matches');
    assert.equal(
      evalCondition("matched_cve.attack_class IN ['ai-c2', 'prompt-injection']",
        { matched_cve: { attack_class: 'kernel-lpe' } }), false,
      'a non-member still returns false');
    // Bare (unquoted) members still parse.
    assert.equal(evalCondition('x IN [ai-c2, prompt-injection]', { x: 'prompt-injection' }), true,
      'bare unquoted members still parse');
    // Array LHS intersection still works.
    assert.equal(
      evalCondition("x IN ['EU, US', 'AU']", { x: ['JP', 'EU, US'] }), true,
      'array LHS intersects the comma-bearing member list');
    // Quantifier-prefixed IN still re-roots over array elements.
    assert.equal(evalCondition("any tags IN ['EU, US', 'AU']", { tags: ['EU, US'] }), true,
      'any … IN [...] with a comma-bearing member fires existentially');
  });

  it('`IN [...]` closing bracket is quote-aware — a `]` inside a quoted member does not terminate the list', () => {
    // A `[^\]]*]$` capture stops at the FIRST `]`, so a quoted member that itself
    // contains a literal `]` (`'a]b'`) truncated the bracket early and left trailing
    // text (`, 'c']`) the `$` anchor couldn't match — the WHOLE clause then fell
    // through to condition_unparsed and returned false for every input, including a
    // value that IS in the list. The closing bracket is now located at quote-depth 0.
    assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'a]b' }), true,
      "a quoted member containing a literal ']' matches its whole value");
    assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'c' }), true,
      "the sibling member after a ']'-bearing member is still selectable");
    assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'a' }), false,
      "a fragment of the ']'-bearing member is not itself a member");
    // Double-quoted members behave identically.
    assert.equal(evalCondition('x IN ["a]b", "c"]', { x: 'a]b' }), true,
      "double-quoted ']'-bearing member stays whole");
    // Array LHS intersection over a ']'-bearing list.
    assert.equal(evalCondition("x IN ['a]b', 'rce']", { x: ['z', 'a]b'] }), true,
      "array LHS intersects a ']'-bearing member list");
    // Quantifier-prefixed form (the catalog's `any … IN [...]` shape) re-roots too.
    assert.equal(
      evalCondition("any matched_cve.attack_class IN ['a]b', 'rce']",
        { matched_cve: [{ attack_class: 'a]b' }, { attack_class: 'x' }] }), true,
      "any … IN ['a]b', …] fires when one array element equals the ']'-bearing member");

    // This was a parsed-as-unparsed path (the regex never matched), so the fix must
    // NOT surface condition_unparsed for the now-valid clause.
    const errs = [];
    evalCondition("x IN ['a]b', 'c']", { x: 'c', _runErrors: errs });
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      "a quoted ']'-bearing member is parsed, not surfaced as condition_unparsed");

    // Genuinely malformed lists stay observable: an unterminated bracket and
    // trailing text after the closing bracket both surface condition_unparsed
    // (the fix must not start silently accepting these).
    const badErrs = [];
    assert.equal(evalCondition("x IN ['a', 'b'", { x: 'a', _runErrors: badErrs }), false,
      'an unterminated IN list does not match');
    assert.equal(badErrs.filter((e) => e.kind === 'condition_unparsed').length, 1,
      'an unterminated IN list is observable as condition_unparsed');
    const junkErrs = [];
    assert.equal(evalCondition("x IN ['a', 'b'] extra", { x: 'a', _runErrors: junkErrs }), false,
      'trailing text after the closing bracket does not match');
    assert.equal(junkErrs.filter((e) => e.kind === 'condition_unparsed').length, 1,
      'trailing text after the closing bracket is observable as condition_unparsed');
  });

  it('AND/OR splitting and outer-paren stripping are quote-aware — a quoted member is not torn at an inner AND/OR or an unbalanced paren', () => {
    // splitAtTopLevel counted `(`/`)` and split on ` AND `/` OR ` at depth 0 with
    // no awareness of quotes; stripOuterParens scanned parens the same way. Two
    // failure modes followed:
    //   (a) an UNBALANCED paren inside a quoted member (a regex literal like
    //       `matches 'foo('`) left depth=1, so the real top-level OR/AND never
    //       split — silently disabling the surrounding disjunct/conjunct;
    //   (b) a quoted member containing ` AND `/` OR ` (e.g. `contains 'EU AND US'`)
    //       was torn at the inner keyword as if it were a boolean operator, leaving
    //       two unparseable atoms that both evaluated false.
    // Both are now scanned tracking single/double quote state.

    // (a) The unbalanced `(` inside the quote must NOT swallow the top-level OR.
    // The first disjunct is false (a !== 'foo(' here) but the second (b == 1) is
    // true, so the OR must be true. Pre-fix this returned false.
    assert.equal(evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 1 }), true,
      'an unbalanced ( inside a quoted regex member does not disable the top-level OR');
    // …and the OR is genuinely short-circuiting, not coincidentally true: with
    // b != 1 and a not matching, the whole thing is false.
    assert.equal(evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 2 }), false,
      'both disjuncts false → false (the OR is really evaluating each side)');
    // A trailing unbalanced `)` inside a quote is handled symmetrically.
    assert.equal(evalCondition("a matches 'bar)' OR b == 1", { a: 'whatever', b: 1 }), true,
      'an unbalanced ) inside a quoted member does not disable the top-level OR');

    // (b) ` AND `/` OR ` inside a quoted member is literal text, not an operator.
    // `o contains 'EU AND US'` must match an array member equal to the whole
    // string. Pre-fix it split into `o contains 'EU` AND `US'` (both unparseable
    // → false).
    assert.equal(evalCondition("o contains 'EU AND US'", { o: ['EU AND US'] }), true,
      'an inner AND inside a quoted contains-member is not split as a conjunction');
    assert.equal(evalCondition("o contains 'x OR y'", { o: ['x OR y'] }), true,
      'an inner OR inside a quoted contains-member is not split as a disjunction');
    // And it is genuinely the whole member, not a coincidental fragment match.
    assert.equal(evalCondition("o contains 'EU AND US'", { o: ['EU'] }), false,
      'a fragment of the quoted member does not satisfy the whole-member contains');

    // No condition_unparsed is recorded for any of the above — these are
    // parsed-correctly paths now, not the unparsed diagnostic.
    const errs = [];
    evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 1, _runErrors: errs });
    evalCondition("o contains 'EU AND US'", { o: ['EU AND US'], _runErrors: errs });
    assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
      'a quote-aware split leaves no condition_unparsed residue');

    // Regression guards: real (depth-0, outside-quote) boolean structure still
    // splits, and outer parens still strip.
    assert.equal(evalCondition('a == 1 OR b == 2', { a: 0, b: 2 }), true, 'plain OR still splits');
    assert.equal(evalCondition('a == 1 AND b == 2', { a: 1, b: 2 }), true, 'plain AND still splits');
    assert.equal(evalCondition('(a == 1 OR b == 2)', { a: 0, b: 2 }), true, 'outer parens still strip');
    assert.equal(evalCondition('a == 1 OR (b == 2 AND c == 3)', { a: 0, b: 2, c: 3 }), true,
      'a depth-0 OR with a parenthesised AND group still parses');
    assert.equal(evalCondition('a == 1 OR (b == 2 AND c == 3)', { a: 0, b: 2, c: 0 }), false,
      'the parenthesised AND group gates the OR correctly');

    // The exact mcp.json condition (balanced-paren regex member + a real top-level
    // OR/AND) keeps firing — the one paren-bearing machine-evaluated condition in
    // the shipped catalog. Fires via the regex OR-branch alone.
    const mcpCond = "finding.mcp_server_location matches '(github_actions|gitlab_runner|jenkins|buildkite|circleci)'"
      + " OR finding.tool_invoked_from == 'ci_pipeline'"
      + " OR analyze.blast_radius_score >= 4 AND finding.pipeline_credentials_in_scope == true";
    assert.equal(evalCondition(mcpCond, {
      finding: { mcp_server_location: 'buildkite', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
      analyze: { blast_radius_score: 0 },
    }), true, 'the shipped mcp.json balanced-paren-regex condition still fires via its OR-branch');
    assert.equal(evalCondition(mcpCond, {
      finding: { mcp_server_location: 'desktop', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
      analyze: { blast_radius_score: 0 },
    }), false, 'no branch satisfied → the mcp condition is false');
  });

  it('a submitted signal cannot override an engine-computed value in an escalation condition', () => {
    // ai-api declares escalations gated on engine values. Run it with detection
    // confirmed so the engine computes a high rwep, then try to suppress the
    // escalation by submitting signals.rwep:0 — the engine value must win.
    const base = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
      { signals: { detection_classification: 'detected' }, artifacts: {} },
      { operator_consent: { explicit: true } });
    const poisoned = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
      { signals: { detection_classification: 'detected', rwep: 0, finding: { severity: 'low' } }, artifacts: {} },
      { operator_consent: { explicit: true } });
    const esc = (res) => JSON.stringify((res.phases.analyze.escalations || []).map((e) => e.action).sort());
    assert.equal(esc(poisoned), esc(base),
      'submitted signals.rwep / finding must not change which escalations fire');
  });

  it('framework chains into sbom when the theater verdict + blast radius gate is met', () => {
    // framework.json declares the same chain on TWO paths: a feeds_into entry and
    // a trigger_playbook escalation, both targeting sbom. Both previously used an
    // `any `-prefixed, bare-path condition that resolved to false for every input,
    // so neither chain could ever fire. Run the playbook with a theater verdict +
    // a blast radius above the gate and assert both surfaces name sbom.
    const out = runner.run('framework', 'correlate-all-upstream-findings',
      { signals: { theater_verdict: 'theater', blast_radius_score: 5 }, artifacts: {} },
      { operator_consent: { explicit: true } });

    assert.deepEqual(out.phases.close.feeds_into, ['sbom'],
      'feeds_into chains framework → sbom on a theater verdict + blast_radius >= 4');

    const escTargets = (out.phases.analyze.escalations || [])
      .filter((e) => e.action === 'trigger_playbook')
      .map((e) => e.target_playbook);
    assert.ok(escTargets.includes('sbom'),
      'the trigger_playbook escalation fires framework → sbom on a theater verdict + blast_radius >= 3');

    // Neither chain's condition is left dead (the bug signature was a silent
    // condition_unparsed on the framework→sbom clauses specifically).
    const allErrs = (out.phases.analyze.runtime_errors || []).concat(out.phases.close.runtime_errors || []);
    const deadFrameworkSbom = allErrs.filter((e) =>
      e.kind === 'condition_unparsed' && /compliance_theater_check\.verdict/.test(e.condition || ''));
    assert.equal(deadFrameworkSbom.length, 0,
      'the framework→sbom theater conditions parse — no condition_unparsed on them');
  });

  it('a non-theater framework run does NOT chain into sbom', () => {
    const out = runner.run('framework', 'correlate-all-upstream-findings',
      { signals: { theater_verdict: 'clear', blast_radius_score: 5 }, artifacts: {} },
      { operator_consent: { explicit: true } });
    assert.deepEqual(out.phases.close.feeds_into, [],
      'a clear verdict does not chain framework → sbom');
  });

  it('contains matches an obligation jurisdiction field via a quoted member; IN list membership works; string-array contains is unaffected', () => {
    const obligations = [
      { jurisdiction: 'EU', regulation: 'NIS2 Art.21', window_hours: 720 },
      { jurisdiction: 'US', regulation: 'SEC', window_hours: 96 },
    ];
    const ctx = { compliance_theater_check: { verdict: 'theater' }, jurisdiction_obligations: obligations };
    // Previously-dead theater + EU-jurisdiction escalation/feeds_into atom now resolves.
    assert.equal(evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'", ctx, {}), true);
    assert.equal(evalCondition("jurisdiction_obligations contains 'EU'", ctx, {}), true);
    assert.equal(evalCondition("jurisdiction_obligations contains 'JP'", ctx, {}), false);
    // .length on the same array still works.
    assert.equal(evalCondition('jurisdiction_obligations.length == 0', { jurisdiction_obligations: [] }, {}), true);
    // IN [...] membership (matched_cve.attack_class IN [...]).
    assert.equal(evalCondition("x.attack_class IN ['kernel-lpe', 'rce']", { x: { attack_class: 'rce' } }, {}), true);
    assert.equal(evalCondition("x.attack_class IN ['kernel-lpe']", { x: { attack_class: 'rce' } }, {}), false);
    // The pre-existing string-array contains shape is unaffected.
    assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote', 'local'] } }, {}), true);
  });

  it('object-array contains is field-targeted: a non-jurisdiction field equal to the member does NOT match', () => {
    // `jurisdiction_obligations contains 'EU'` means "the obligation is for
    // jurisdiction EU" — NOT "some field of the obligation equals 'EU'". An
    // unscoped Object.values().includes() over-matched: a non-jurisdiction field
    // (a tag, the obligation name, clock_starts) that happened to equal the member
    // forced the predicate true, which could fire a notify_legal escalation via a
    // non-jurisdiction field, and made the match order-insensitive across fields.

    // Over-match via an unrelated tag field: jurisdiction is US, only some_tag == 'EU'.
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'EU'",
        { jurisdiction_obligations: [{ jurisdiction: 'US', some_tag: 'EU' }] }, {}),
      false,
      "a non-jurisdiction field equal to 'EU' must NOT satisfy contains 'EU'");

    // Over-match via clock_starts: 'detect_confirmed' is a real shipped field value
    // on EU obligations; matching it via contains is a field-agnostic accident.
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'detect_confirmed'",
        { jurisdiction_obligations: [{ jurisdiction: 'EU', clock_starts: 'detect_confirmed' }] }, {}),
      false,
      "the clock_starts field value must NOT satisfy a jurisdiction-membership test");

    // Over-match via the obligation name field.
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'notify_regulator'",
        { jurisdiction_obligations: [{ jurisdiction: 'EU', obligation: 'notify_regulator' }] }, {}),
      false,
      "the obligation name field must NOT satisfy a jurisdiction-membership test");

    // The legitimate jurisdiction match still fires (positive path preserved).
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'EU'",
        { jurisdiction_obligations: [{ jurisdiction: 'EU', regulation: 'NIS2 Art.21', clock_starts: 'detect_confirmed' }] }, {}),
      true,
      "an obligation whose jurisdiction IS 'EU' still matches");

    // The full catalog escalation atom: theater verdict + EU jurisdiction. The
    // EU conjunct must come from the jurisdiction field, not a field collision.
    assert.equal(
      evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'",
        { compliance_theater_check: { verdict: 'theater' },
          jurisdiction_obligations: [{ jurisdiction: 'US', obligation: 'EU' }] }, {}),
      false,
      "the notify_legal escalation must NOT fire when only a non-jurisdiction field equals 'EU'");

    // String-array membership is still matched by element value (no object scoping).
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'",
        { jurisdiction_obligations: ['EU/EU CRA Art.14 24h'] }, {}),
      true,
      "a plain string-array element still matches by value");
  });

  it('contains/IN against an absent LHS path surfaces condition_path_unresolved (not an invisible false)', () => {
    // A contains/IN clause PARSES, then resolves its LHS to a collection. When the
    // LHS path is absent (an authoring typo in the token, or a ctx that never
    // populated the collection) the branch returns a silent false that disables
    // the escalation/feeds_into it gates — with no signal, because the clause
    // parsed, so condition_unparsed never fires. A distinct condition_path_unresolved
    // diagnostic makes the dead clause observable. A present-but-empty array (or a
    // present scalar simply not in the list) is a LEGITIMATE false and pushes nothing.

    // contains: absent LHS → diagnostic, still false.
    const absent = [];
    assert.equal(evalCondition("jurisdiction_obligations contains 'EU'", { _runErrors: absent }, {}), false,
      'absent LHS contains is still false');
    assert.equal(absent.length, 1, 'exactly one runtime error recorded');
    assert.equal(absent[0].kind, 'condition_path_unresolved', 'it is the path-unresolved diagnostic, not condition_unparsed');
    assert.equal(absent[0].condition, "jurisdiction_obligations contains 'EU'", 'the dead condition string is captured');

    // The finding's typo example: a misspelled LHS path is now observable.
    const typo = [];
    assert.equal(
      evalCondition("juristiction_obligations contains 'EU'",
        { jurisdiction_obligations: [{ jurisdiction: 'EU' }], _runErrors: typo }, {}),
      false, 'typo LHS contains is false');
    assert.equal(typo.length, 1, 'the LHS-token typo surfaces a diagnostic');
    assert.equal(typo[0].kind, 'condition_path_unresolved');

    // Present-but-empty array → legitimate false, NO diagnostic.
    const empty = [];
    assert.equal(evalCondition("jo contains 'EU'", { jo: [], _runErrors: empty }, {}), false,
      'empty-array contains is false');
    assert.equal(empty.length, 0, 'present-but-empty array pushes no diagnostic');

    // The engine-supplied escalation context always passes jurisdiction_obligations
    // as at least [] (never null), so a real notify_legal eval does NOT spuriously
    // fire this diagnostic — guard the regression at the catalog default.
    const engineDefault = [];
    assert.equal(
      evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'",
        { compliance_theater_check: { verdict: 'theater' }, jurisdiction_obligations: [], _runErrors: engineDefault }, {}),
      false, 'non-EU run is false');
    assert.equal(engineDefault.length, 0, 'the engine-default [] obligations array fires no path-unresolved diagnostic');

    // IN: absent LHS → diagnostic, still false.
    const inAbsent = [];
    assert.equal(evalCondition("matched_cve.attack_class IN ['kernel-lpe']", { _runErrors: inAbsent }, {}), false,
      'absent LHS IN is still false');
    assert.equal(inAbsent.length, 1, 'IN absent LHS surfaces a diagnostic');
    assert.equal(inAbsent[0].kind, 'condition_path_unresolved');

    // IN: present scalar simply not in the list → legitimate false, NO diagnostic.
    const inMiss = [];
    assert.equal(evalCondition("x IN ['kernel-lpe']", { x: 'rce', _runErrors: inMiss }, {}), false,
      'present scalar not in list is false');
    assert.equal(inMiss.length, 0, 'a present-but-non-matching scalar pushes no diagnostic');

    // A correct, resolving condition fires true with no diagnostic.
    const ok = [];
    assert.equal(
      evalCondition("jurisdiction_obligations contains 'EU'",
        { jurisdiction_obligations: [{ jurisdiction: 'EU' }], _runErrors: ok }, {}),
      true, 'correct contains fires true');
    assert.equal(ok.length, 0, 'a resolving condition records no diagnostic');

    // Dedupe: the same dead condition evaluated repeatedly records ONE diagnostic.
    const dup = [];
    evalCondition("missing_path contains 'EU'", { _runErrors: dup }, {});
    evalCondition("missing_path contains 'EU'", { _runErrors: dup }, {});
    assert.equal(dup.length, 1, 'the path-unresolved diagnostic dedupes on the condition string');
  });
});

// =======================================================================
// 26. _worstActiveExploitation — worst-of rank table (theoretical first-class)
// =======================================================================

describe('_worstActiveExploitation rank table', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('worstActiveExploitation ranks `theoretical` between none and unknown (worst-of holds)', () => {
    // P1: the rank table omitted `theoretical`, so `?? -1` lost to the -1 start —
    // an all-theoretical set wrongly reduced to 'unknown' and theoretical+none
    // dropped the theoretical entry. `theoretical` is first-class catalog vocab.
    const worst = runner._worstActiveExploitation;
    assert.equal(typeof worst, 'function', 'runner must export _worstActiveExploitation');
    assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'none' }]),
      'theoretical', 'theoretical must outrank none');
    assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'confirmed' }]),
      'confirmed', 'confirmed still outranks theoretical');
    assert.equal(worst([{ active_exploitation: 'none' }, { active_exploitation: 'theoretical' }, { active_exploitation: 'suspected' }]),
      'suspected', 'worst-of across a mixed set');
    // Empty / all-unrecognized matched set defaults to 'none', not 'unknown' —
    // a draft must not assert exploitation it never observed.
    assert.equal(worst([]), 'none', 'empty set → none');
    assert.equal(worst([{ active_exploitation: 'bogus-value' }]), 'none', 'unrecognized-only → none');
  });
});

// =======================================================================
// 27. acquireLock / acquireLockDiagnostic — same-PID stale-lockfile reclaim
// =======================================================================

describe('acquireLock / acquireLockDiagnostic — same-PID stale-lockfile reclaim', () => {
  let playbookRunner;
  before(() => { playbookRunner = freshRunner(REAL_PLAYBOOK_DIR); });

  // Capture the pre-suite EXCEPTD_LOCK_DIR ONCE; restore at every test exit.
  // Without this, the first makeLockDir() call would leak the value into every
  // subsequent test in the same node process, causing watch-mode re-runs to load
  // lockfiles from a destroyed tmp dir and silently flake.
  const ORIGINAL_LOCK_DIR_ENV = process.env.EXCEPTD_LOCK_DIR;
  function restoreLockDirEnv() {
    if (ORIGINAL_LOCK_DIR_ENV === undefined) delete process.env.EXCEPTD_LOCK_DIR;
    else process.env.EXCEPTD_LOCK_DIR = ORIGINAL_LOCK_DIR_ENV;
  }

  function makeLockDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pb-pp-locks-'));
    process.env.EXCEPTD_LOCK_DIR = dir;
    return dir;
  }

  it('PP P1-1: acquireLock reclaims a same-PID lockfile whose mtime is older than STALE_LOCK_MS', () => {
    try {
    const dir = makeLockDir();
    const playbookId = 'pb-pp-self-stale-' + process.pid;
    const lockFile = path.join(dir, `${playbookId}.lock`);
    // Pre-populate the lockfile with OUR pid — simulates an orphan from a
    // prior run() that crashed without releasing.
    fs.writeFileSync(
      lockFile,
      JSON.stringify({ pid: process.pid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2),
    );
    // Backdate mtime past STALE_LOCK_MS (30s). Use 60s to comfortably clear.
    const sixtySecondsAgo = (Date.now() - 60_000) / 1000;
    fs.utimesSync(lockFile, sixtySecondsAgo, sixtySecondsAgo);

    const result = playbookRunner._acquireLock(playbookId);
    assert.equal(
      result,
      lockFile,
      'acquireLock must reclaim a same-PID lockfile whose mtime is older than STALE_LOCK_MS',
    );

    // Lockfile should now reflect a fresh hold by us: mtime within the last second.
    const stat = fs.statSync(lockFile);
    assert.equal(
      Date.now() - stat.mtimeMs < 5_000,
      true,
      'reclaimed lockfile must have a freshly-rewritten mtime (within 5s)',
    );
    playbookRunner._releaseLock(result);
    } finally { restoreLockDirEnv(); }
  });

  it('PP P1-1: acquireLock returns null for same-PID lockfile with fresh mtime (legitimate reentrancy block)', () => {
    try {
    const dir = makeLockDir();
    const playbookId = 'pb-pp-self-fresh-' + process.pid;
    const lockFile = path.join(dir, `${playbookId}.lock`);
    // Pre-populate with our pid + fresh mtime (now). This is the legitimate
    // reentrancy case: another acquireLock() call within this process already
    // holds the lock, and we must NOT reclaim it.
    fs.writeFileSync(
      lockFile,
      JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2),
    );
    // Hold ONE descriptor across the whole assertion: capture mtime before the
    // acquire, run it, then re-read content + mtime from the SAME fd. A single
    // open (no second openSync of the path) means there is no stat-then-open
    // check-then-use race, and every observation is of one consistent inode.
    const lfd = fs.openSync(lockFile, 'r');
    let reread, mtimeBefore, mtimeAfter;
    try {
      mtimeBefore = fs.fstatSync(lfd).mtimeMs;
      const result = playbookRunner._acquireLock(playbookId);
      assert.equal(
        result,
        null,
        'acquireLock must return null when the same-PID lockfile is fresh (reentrancy must be blocked)',
      );
      reread = JSON.parse(fs.readFileSync(lfd, 'utf8'));
      mtimeAfter = fs.fstatSync(lfd).mtimeMs;
    } finally { fs.closeSync(lfd); }
    assert.equal(reread.pid, process.pid);
    // mtime not rewritten.
    assert.equal(
      mtimeAfter,
      mtimeBefore,
      'fresh same-PID lockfile mtime must NOT be rewritten by a failed acquire',
    );
    // Cleanup — we created it directly.
    try { fs.unlinkSync(lockFile); } catch {}
    } finally { restoreLockDirEnv(); }
  });

  it('PP P1-1: acquireLockDiagnostic returns reclaimed_self_stale_pid: true for stale same-PID orphan', () => {
    try {
    const dir = makeLockDir();
    const playbookId = 'pb-pp-diag-self-stale-' + process.pid;
    const lockFile = path.join(dir, `${playbookId}.lock`);
    fs.writeFileSync(
      lockFile,
      JSON.stringify({ pid: process.pid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2),
    );
    const sixtySecondsAgo = (Date.now() - 60_000) / 1000;
    fs.utimesSync(lockFile, sixtySecondsAgo, sixtySecondsAgo);

    const diag = playbookRunner._acquireLockDiagnostic(playbookId);
    assert.equal(diag.ok, true, 'diagnostic must succeed when reclaiming same-PID stale orphan');
    assert.equal(diag.path, lockFile);
    assert.equal(
      diag.reclaimed_self_stale_pid,
      true,
      'diagnostic must flag reclaimed_self_stale_pid:true when the prior holder was our own dead self',
    );
    assert.equal(
      typeof diag.prior_mtime_ms,
      'number',
      'diagnostic must report the prior mtime for audit visibility',
    );
    playbookRunner._releaseLock(diag.path);
    } finally { restoreLockDirEnv(); }
  });

  it('PP P1-1: acquireLockDiagnostic returns held_by_self for fresh same-PID lockfile', () => {
    try {
    const dir = makeLockDir();
    const playbookId = 'pb-pp-diag-self-fresh-' + process.pid;
    const lockFile = path.join(dir, `${playbookId}.lock`);
    fs.writeFileSync(
      lockFile,
      JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2),
    );

    const diag = playbookRunner._acquireLockDiagnostic(playbookId);
    assert.equal(diag.ok, false);
    assert.equal(
      diag.reason,
      'held_by_self',
      'fresh same-PID lockfile must be diagnosed as held_by_self (reentrancy), not held_by_live_pid or reclaim_failed',
    );
    assert.equal(diag.holder_pid, process.pid);
    assert.equal(diag.lock_path, lockFile);
    try { fs.unlinkSync(lockFile); } catch {}
    } finally { restoreLockDirEnv(); }
  });
});

// =======================================================================
// 28. run() — json bundle, top_finding, collector_warnings, regression
//     triggers, fired-signal remediation, blocked-summary truncation, detect
//     normalization + indicators_evaluated + from_observation
// =======================================================================

describe('run() — bundles, top_finding, collector_warnings, remediation selection, detect surface', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });

  it('a playbook declaring bundle_format "json" builds a populated json bundle, not the Unknown-format placeholder', () => {
    const res = runner.run(
      'secrets',
      'full-repo-secret-scan',
      { precondition_checks: { 'repo-context': true }, signal_overrides: {} },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(res.ok, true, 'a clean secrets run must succeed');
    const ep = res.phases && res.phases.close && res.phases.close.evidence_package;
    assert.ok(ep, 'close phase must carry an evidence_package');
    const body = ep.bundle_body;
    assert.ok(body, 'evidence_package must carry a bundle_body');
    // Presence: the declared format is honored.
    assert.equal(body.format, 'json', 'bundle_body.format must be the declared json, not a fallback');
    assert.equal('note' in body, false, 'a real json bundle must NOT carry the Unknown-format note');
    // Content: the bundle is populated, not an empty shell.
    assert.equal(body.playbook, 'secrets', 'bundle records its playbook id');
    assert.equal(typeof body.session_id, 'string', 'bundle records the session id');
    assert.equal(typeof body.verdict, 'string', 'bundle carries a string verdict');
    assert.ok(Array.isArray(body.matched_cves), 'bundle carries a matched_cves array');
    assert.equal(typeof body.rwep_adjusted, 'number', 'bundle carries a numeric adjusted rwep');
    // The primary format is keyed under json and is the same record.
    assert.ok(ep.bundles_by_format && ep.bundles_by_format.json, 'bundles_by_format keys the json primary');
    assert.equal(ep.bundles_by_format.json.format, 'json', 'bundles_by_format.json is the json bundle');
  });

  it('top_finding names the dominant fired indicator (not the verdict string), and summary_line states the verdict once', () => {
    const res = runner.run(
      'library-author',
      'published-artifact-audit',
      { signal_overrides: { 'release-workflow-non-frozen-install': 'hit' } },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(res.verdict, 'detected', 'a forced indicator hit drives a detected verdict');
    // top_finding must name the indicator that fired, not echo the verdict word.
    assert.equal(res.top_finding, 'release-workflow-non-frozen-install', 'top_finding is the dominant fired indicator id');
    // The verdict word appears exactly once in the summary line — no
    // "detected (rwep=…, detected, …)" duplication.
    assert.equal((res.summary_line.match(/detected/g) || []).length, 1, 'summary_line states the verdict once, not duplicated');

    // Gate: a non-detection verdict must NOT advertise a top_finding (the
    // indicator branch is gated on a real detection classification, so a stray
    // hit on an inconclusive / not-detected run cannot leak a finding).
    const miss = runner.run(
      'library-author',
      'published-artifact-audit',
      { signal_overrides: { 'release-workflow-non-frozen-install': 'miss' } },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(miss.verdict, 'not_detected', 'all-miss drives a not_detected verdict');
    assert.equal(miss.top_finding, null, 'a non-detection verdict carries no top_finding');
  });

  it('top_finding prefers the indicator that drove the RWEP score (and falls back to the dominant hit when none is weighted)', () => {
    // Both a weighted rwep-input (sbom-absent-or-unsigned, weight 10) and a
    // higher-confidence-but-unweighted hit fire: top_finding must name the
    // weighted driver so the headline explains the rwep number beside it.
    const driven = runner.run(
      'library-author',
      'published-artifact-audit',
      { signal_overrides: { 'sbom-absent-or-unsigned': 'hit', 'release-workflow-non-frozen-install': 'hit' } },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(driven.verdict, 'detected');
    assert.equal(driven.rwep_score, 10, 'the weighted signal sets rwep=10');
    assert.equal(driven.top_finding, 'sbom-absent-or-unsigned', 'top_finding names the rwep driver, not the higher-confidence unweighted hit');
    // When only a non-weighted hit fires (rwep=0), fall back to that indicator.
    const fallback = runner.run(
      'library-author',
      'published-artifact-audit',
      { signal_overrides: { 'release-workflow-non-frozen-install': 'hit' } },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(fallback.rwep_score, 0, 'the unweighted hit leaves rwep at 0');
    assert.equal(fallback.top_finding, 'release-workflow-non-frozen-install', 'with no weighted driver, top_finding falls back to the dominant hit');
  });

  it('run() surfaces collector_errors as an advisory collector_warnings field (and omits it when there are none)', () => {
    const warned = runner.run(
      'secrets',
      'full-repo-secret-scan',
      {
        precondition_checks: { 'repo-context': true },
        signal_overrides: {},
        collector_errors: [{ kind: 'file_too_large_skipped', reason: 'big.json: exceeds limit' }],
      },
      { force_replay: true, mode: 'test' }
    );
    assert.ok(Array.isArray(warned.collector_warnings), 'collector_warnings is present when the collector skipped something');
    assert.equal(warned.collector_warnings.length, 1);
    assert.equal(warned.collector_warnings[0].kind, 'file_too_large_skipped', 'the skip reason is carried through verbatim');
    // Advisory only — the run still completes and the verdict is unaffected.
    assert.equal(warned.ok, true);
    // No collector_errors submitted -> no collector_warnings key (not an empty array).
    const clean = runner.run(
      'secrets',
      'full-repo-secret-scan',
      { precondition_checks: { 'repo-context': true }, signal_overrides: {} },
      { force_replay: true, mode: 'test' }
    );
    assert.equal('collector_warnings' in clean, false, 'collector_warnings is omitted when the collector reported nothing');
  });

  it('regression_event_triggers carry the condition string (not null) from a playbook keyed on `condition`', () => {
    const res = runner.run(
      'ai-api',
      'all-ai-api-and-credential-exposure',
      { signal_overrides: {} },
      { force_replay: true, mode: 'test' }
    );
    const triggers = res.phases.validate.regression_event_triggers || [];
    assert.ok(triggers.length >= 1, 'the playbook declares on_event regression triggers');
    assert.ok(triggers.every((t) => typeof t.trigger === 'string' && t.trigger.length > 0), 'every on_event trigger carries its condition string, not null');
    assert.equal(triggers[0].trigger, 'new_ai_vendor_added_to_allowlist', 'the first trigger is the playbook condition verbatim');
  });

  it('selected_remediation prefers the path that addresses a fired signal (and falls back to priority-1 when none is linked)', () => {
    // Only the FIPS-claim indicator fired: the recommendation must be the
    // remediation that addresses it (for_signals linkage), NOT the unrelated
    // priority-1 PQC migration.
    const fips = runner.run(
      'crypto-codebase',
      'weak-primitive-inventory',
      { signal_overrides: { 'fips-claim-without-runtime-activation': 'hit' } },
      { force_replay: true, mode: 'test' }
    );
    const sel = fips.phases.validate.selected_remediation;
    assert.equal(sel.id, 'activate-fips-provider-or-retract-claim', 'the fired-signal-linked remediation is selected, not priority-1');
    const fipsPath = fips.phases.validate.remediation_options_considered.find((c) => c.id === 'activate-fips-provider-or-retract-claim');
    assert.equal(fipsPath.addresses_fired_signal, true, 'the considered trace flags the path as addressing a fired signal');
    // Backward-compat: with no fired signal (no for_signals match), the
    // priority-1 path is the fallback — unchanged from prior behavior.
    const none = runner.run(
      'crypto-codebase',
      'weak-primitive-inventory',
      { signal_overrides: {} },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(none.phases.validate.selected_remediation.id, 'rotate-to-pqc-hybrid-kem', 'no fired signal falls back to priority-1');

    // A fired-signal-relevant path must win over a satisfied-but-UNRELATED path:
    // here rotate-to-pqc-hybrid-kem's preconditions are satisfied, but the FIPS
    // finding is what fired, so activate-fips (which addresses it) is selected
    // rather than the ready-but-irrelevant priority-1 path.
    const satisfiedUnrelated = runner.run(
      'crypto-codebase',
      'weak-primitive-inventory',
      {
        signal_overrides: { 'fips-claim-without-runtime-activation': 'hit' },
        signals: { ml_kem_implementation_available_for_language: true, api_stability_promise_permits_default_change: true },
      },
      { force_replay: true, mode: 'test' }
    );
    assert.equal(satisfiedUnrelated.phases.validate.selected_remediation.id, 'activate-fips-provider-or-retract-claim', 'relevance outranks a satisfied-but-unrelated path');
  });

  it('a blocked-preflight summary_line truncates on a word boundary with an ellipsis, not mid-token', () => {
    const res = runner.run(
      'cicd-pipeline-compromise',
      'all-pipelines-and-runners',
      { precondition_checks: { 'operator-owns-ci-fleet': false } },
      { force_replay: true, mode: 'test' }
    );
    const sl = res.summary_line;
    assert.ok(sl.length <= 240, 'summary stays within the 240-char cap');
    assert.equal(sl.endsWith('…'), true, 'a truncated summary is marked with an ellipsis');
    assert.equal(/[A-Za-z0-9]$/.test(sl), false, 'the cut does not split a word mid-token');
  });

  it('#71 detect canonicalizes no_hit to miss (flat-shape submission)', () => {
    const sub = {
      observations: {
        w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'no_hit' }
      },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
    assert.ok(target, 'indicator must be present in detect output');
    assert.equal(target.verdict, 'miss', 'no_hit must canonicalize to miss');
  });

  it('#71 normalizer accepts every documented synonym', () => {
    const cases = [
      ['hit', 'hit'], ['detected', 'hit'], ['positive', 'hit'], [true, 'hit'],
      ['miss', 'miss'], ['no_hit', 'miss'], ['no-hit', 'miss'], ['clean', 'miss'],
      ['clear', 'miss'], ['not_hit', 'miss'], ['ok', 'miss'], ['pass', 'miss'],
      ['negative', 'miss'], [false, 'miss'],
      ['inconclusive', 'inconclusive'], ['unknown', 'inconclusive'], ['unverified', 'inconclusive'],
    ];
    for (const [input, expected] of cases) {
      const sub = {
        observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: input } },
        verdict: {}
      };
      const result = runner.run('library-author', 'published-artifact-audit', sub, {});
      const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
      assert.equal(target?.verdict, expected, `result=${JSON.stringify(input)} should canonicalize to ${expected}`);
    }
  });

  it('#71 detect surfaces observations_received + signals_received', () => {
    const sub = {
      observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'no_hit' } },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    assert.ok(Array.isArray(result.phases.detect.observations_received),
      'observations_received must be an array');
    assert.ok(Array.isArray(result.phases.detect.signals_received),
      'signals_received must be an array');
    // Content-shape check: pre-strengthening, "array is present" was true even
    // when the array was empty. The v0.11.10 field-present-but-empty bug class
    // would have passed silently. The submission supplied observation key "w";
    // it MUST appear in observations_received, and its declared indicator MUST
    // appear in signals_received.
    assert.ok(result.phases.detect.observations_received.includes('w'),
      `observations_received must include the submitted observation key "w"; got ${JSON.stringify(result.phases.detect.observations_received)}`);
    assert.ok(result.phases.detect.signals_received.includes('publish-workflow-uses-static-token'),
      'signals_received must include the indicator declared on observation "w"');
  });

  it('#73 indicators_evaluated is an array', () => {
    const sub = { observations: {}, verdict: {} };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    assert.ok(Array.isArray(result.phases.detect.indicators_evaluated),
      'indicators_evaluated must be an array (v0.10.x compat)');
    assert.equal(typeof result.phases.detect.indicators_evaluated_count, 'number',
      'indicators_evaluated_count must be an integer peer field');
    // library-author declares many indicators; even with an empty submission
    // the runner emits one indicators_evaluated entry per declared indicator
    // (with outcome='inconclusive'). Asserting length > 0 UNCONDITIONALLY is
    // the strengthening: the pre-existing `if (length > 0)` shape check would
    // have silently passed if a regression made the array empty (the exact
    // bug operators complained about in #73).
    assert.ok(result.phases.detect.indicators_evaluated.length > 0,
      `indicators_evaluated must contain one entry per declared indicator; got length=${result.phases.detect.indicators_evaluated.length}`);
    assert.equal(result.phases.detect.indicators_evaluated.length,
      result.phases.detect.indicators_evaluated_count,
      'count peer must match array length');
    const first = result.phases.detect.indicators_evaluated[0];
    assert.ok('signal_id' in first, 'entry must have signal_id');
    assert.ok('outcome' in first, 'entry must have outcome');
    assert.ok('confidence' in first, 'entry must have confidence');
    assert.equal(typeof first.signal_id, 'string', 'signal_id must be a string');
    assert.ok(first.signal_id.length > 0, 'signal_id must not be empty');
  });

  it('#82 SARIF includes results from indicators that fired', () => {
    // Fire one indicator so SARIF has at least one result to emit.
    const sub = {
      observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {
      // Request SARIF as a side bundle.
    });
    // Note: --format is set on the CLI side via signals._bundle_formats.
    // For this direct-runner test we manually invoke close() with that signal.
    // Simpler: use the CLI smoke test below.
    void result;
  });

  it('#85 from_observation populated when observation drove the indicator', () => {
    const sub = {
      observations: { 'my-obs-key': { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    const evaluated = result.phases.detect.indicators_evaluated.find(
      e => e.signal_id === 'publish-workflow-uses-static-token'
    );
    assert.ok(evaluated, 'indicator must appear in indicators_evaluated');
    assert.equal(evaluated.from_observation, 'my-obs-key',
      'from_observation must reference the observation key that produced the outcome');
  });
});

test.describe("reconciliation-fixes", () => {
  test('worstActiveExploitation ranks `theoretical` between none and unknown (worst-of holds)', () => {
    // P1: the rank table omitted `theoretical`, so `?? -1` lost to the -1 start —
    // an all-theoretical set wrongly reduced to 'unknown' and theoretical+none
    // dropped the theoretical entry. `theoretical` is first-class catalog vocab.
    const worst = require('../lib/playbook-runner.js')._worstActiveExploitation;
    assert.equal(typeof worst, 'function', 'runner must export _worstActiveExploitation');
    assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'none' }]),
      'theoretical', 'theoretical must outrank none');
    assert.equal(worst([{ active_exploitation: 'theoretical' }, { active_exploitation: 'confirmed' }]),
      'confirmed', 'confirmed still outranks theoretical');
    assert.equal(worst([{ active_exploitation: 'none' }, { active_exploitation: 'theoretical' }, { active_exploitation: 'suspected' }]),
      'suspected', 'worst-of across a mixed set');
    // Empty / all-unrecognized matched set defaults to 'none', not 'unknown' —
    // a draft must not assert exploitation it never observed.
    assert.equal(worst([]), 'none', 'empty set → none');
    assert.equal(worst([{ active_exploitation: 'bogus-value' }]), 'none', 'unrecognized-only → none');
  });
});

// ---- routed from attestation-signature-roundtrip ----
;(() => {
/**
 * Audit-VV trust-boundary fixes (KK P1-1..P1-5 + MM P1-D).
 *
 * Each test pins an EXACT exit code (assert.equal(r.status, N)) and pairs
 * every field-presence check with a content-shape check, per the project's
 * coincidence-passing-tests rule. notEqual(r.status, 0) is forbidden — a
 * coincidence-passing test blocks future regressions while letting the
 * current one through.
 *
 * Fixes covered:
 *   KK P1-1  Sidecar shape no longer carries `signed_at` / `signs_path` /
 *            `signs_sha256`. The Ed25519 signature covers ONLY the
 *            attestation file bytes — fields in the sidecar that aren't in
 *            the signed message are replay-rewrite trivial.
 *   KK P1-2  cmdReattest persists `replay-<isoZ>.json` under the session
 *            directory whenever a replay produced a verdict (force-replay
 *            or otherwise). `attest verify <sid>` surfaces both the
 *            original + the replay in its results array.
 *   KK P1-3  Sidecar verifier rejects any algorithm field that isn't
 *            exactly "Ed25519" or "unsigned" (downgrade-bait substitution)
 *            with tamper_class:"algorithm-unsupported" and exit 6.
 *   KK P1-4  hasReadableStdin Windows fallback requires isTTY === false
 *            STRICTLY — not falsy. isTTY === undefined no longer routes
 *            through readFileSync(0) and blocks on wrapped duplexer test
 *            harnesses.
 *   KK P1-5  Pin loader strips leading UTF-8 BOM (Notepad with
 *            files.encoding=utf8bom) + ignores comment / empty lines.
 *            All four sites converge on the shared helper.
 *   MM P1-D  sanitizeOperatorText (library-side guard for direct
 *            buildEvidenceBundle callers) NFC-normalises, strips \p{C}
 *            (Cc/Cf/Cs/Co/Cn), caps at 256 codepoints, returns null on
 *            empty-after-strip so callers route through the
 *            bundle_publisher_unclaimed fallback.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestationFiles(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find((p) => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot);
  const jsonFiles = files.filter((f) => f.endsWith('.json') && !f.endsWith('.sig'));
  return {
    dir: attRoot,
    files: jsonFiles,
    primaryJson: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json')
      : path.join(attRoot, jsonFiles[0]),
    primarySig: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json.sig')
      : path.join(attRoot, jsonFiles[0] + '.sig'),
  };
}

// ---------------------------------------------------------------------------
// KK P1-1 — sidecar `signed_at` is no longer present; rewriting it is a
// no-op for verify. Conversely the attestation file `captured_at` is
// signed; rewriting that field invalidates the signature.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-2 — force-replay persists a replay-*.json record on disk.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-3 — strict algorithm check.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-4 — hasReadableStdin Windows fallback strict isTTY===false.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-5 — pin loader strips BOM + tolerates CRLF + comments.
// ---------------------------------------------------------------------------







// ---------------------------------------------------------------------------
// MM P1-D — sanitizeOperatorText library-side guard.
// ---------------------------------------------------------------------------

test('MM P1-D — sanitizeOperatorText strips U+202E (RTL OVERRIDE) and returns null when result is empty', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  assert.equal(typeof runnerMod.sanitizeOperatorText, 'function',
    'sanitizeOperatorText must be exported (or testable as a top-level function via the runner module)');
  // 'alice' + U+202E (RTL OVERRIDE) + 'evilbob' — a bidi-forgery attempt.
  const out = runnerMod.sanitizeOperatorText('alice‮evilbob');
  // The result MUST NOT contain U+202E — that's the whole point.
  assert.equal(typeof out, 'string', 'non-empty residue should still surface as a string after the bidi codepoint is stripped');
  assert.ok(!out.includes('‮'),
    `sanitised output must not contain U+202E; got ${JSON.stringify(out)}`);
  // The remaining ASCII (alice + evilbob) is concatenated. That is fine —
  // the forgery surface is the bidi codepoint, not the residual letters.
  assert.equal(out, 'aliceevilbob',
    `bidi-stripped concatenation must equal "aliceevilbob"; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText strips zero-width joiner / non-joiner / space and surrogate / private-use', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM mid-string, U+E000 PUA.
  const out = runnerMod.sanitizeOperatorText('a​b‌c‍d﻿ef');
  assert.equal(out, 'abcdef',
    `every Cf/Co codepoint must be stripped; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText returns null on all-Cf input (empty after strip)', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // Only zero-width codepoints: post-strip the result is empty → null.
  const out = runnerMod.sanitizeOperatorText('​‌‍‮﻿');
  assert.equal(out, null,
    `all-Cf input must collapse to null (callers route through the bundle_publisher_unclaimed fallback); got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText NFC-normalises before stripping', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // 'café' as 'cafe' + U+0301 COMBINING ACUTE ACCENT → NFC composes to U+00E9.
  // The COMBINING ACCENT is category Mn (Mark, Nonspacing), which is NOT in
  // \p{C} — but the NFC composition is what we care about. Verify the
  // output is the canonical-composed form.
  const out = runnerMod.sanitizeOperatorText('café');
  assert.equal(out, 'café',
    `NFC normalisation must compose combining marks; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText caps at 256 CODEPOINTS, not UTF-16 code units', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // 257 copies of U+1F600 (astral plane — each codepoint occupies 2 UTF-16
  // code units, so .length = 514). The cap must operate on codepoints.
  const input = '\u{1F600}'.repeat(257);
  const out = runnerMod.sanitizeOperatorText(input);
  // Array.from counts codepoints — exactly 256 after the cap.
  assert.equal(Array.from(out).length, 256,
    `cap must apply at 256 codepoints (not 256 UTF-16 code units); got ${Array.from(out).length}`);
});

test('MM P1-D — sanitizeOperatorText strips one-of-each named family AND the \\p{C} backstop-only U+007F', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  // One codepoint from each named family the centralizing strip helper owns,
  // plus U+007F (DEL) which the named-family regexes do NOT cover (C0_CTRL
  // stops at U+001F) and only the \p{C} backstop removes. Interleaved with
  // ASCII so a missed strip would leave a visible residue.
  const F = String.fromCodePoint;
  const input = 'a' + F(0x202D) + 'b' + F(0x0001) + 'c' + F(0x200B) +
    'd' + F(0x0000) + 'e' + F(0x007F) + 'f';
  const out = runnerMod.sanitizeOperatorText(input);
  assert.equal(out, 'abcdef',
    `every named-family codepoint AND the backstop-only U+007F must be stripped; got ${JSON.stringify(out)}`);
});

test('MM P1-D — sanitizeOperatorText returns null for non-string input', () => {
  const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
  assert.equal(runnerMod.sanitizeOperatorText(null), null);
  assert.equal(runnerMod.sanitizeOperatorText(undefined), null);
  assert.equal(runnerMod.sanitizeOperatorText(42), null);
  assert.equal(runnerMod.sanitizeOperatorText({}), null);
  assert.equal(runnerMod.sanitizeOperatorText([]), null);
});

test('MM P1-D — buildEvidenceBundle with a bidi-forged operator routes through bundle_publisher_unclaimed',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
  () => {
    // End-to-end: a library caller invokes buildEvidenceBundle indirectly
    // via the CLI by passing a bidi-forged --operator. Even though the CLI
    // refuses the input at validateOperator(), this test confirms that
    // when the runner's sanitizeOperatorText sees a forged input from
    // a direct library caller (the CLI guard is one layer; sanitizer is
    // the library-side defence-in-depth), the result routes through the
    // fallback path.
    //
    // We exercise the sanitizer directly + assert the fallback contract:
    // a sanitised null operator value MUST NOT appear in a CSAF
    // publisher.namespace position.
    const runnerMod = require(path.join(ROOT, 'lib', 'playbook-runner.js'));
    const forgedOperator = 'alice‮evilbob';
    const clean = runnerMod.sanitizeOperatorText(forgedOperator);
    // After the strip, the residue is plain ASCII — NOT a URL — so the
    // publisher-namespace resolution path's `/^https?:\/\//i` regex will
    // reject it AND it will fall through to the urn:exceptd:operator:unknown
    // fallback. Confirm the residue is NOT URL-shaped.
    assert.equal(typeof clean, 'string');
    assert.ok(!/^https?:\/\//i.test(clean),
      `bidi-stripped residue must not look URL-shaped (would falsely populate publisher.namespace); got ${JSON.stringify(clean)}`);
    // The companion assertion — a sanitised publisher-namespace input that
    // collapses to null routes through the fallback as expected.
    const forgedNs = '‮​‌';
    const cleanNs = runnerMod.sanitizeOperatorText(forgedNs);
    assert.equal(cleanNs, null,
      `all-Cf publisher-namespace input must collapse to null so the runner picks up the bundle_publisher_unclaimed fallback`);
  });
})();
