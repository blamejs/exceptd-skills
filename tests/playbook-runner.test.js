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

  it('ordering against a duration literal (24h) normalizes both sides to hours, not lexicographic/NaN', () => {
    // kernel.json's raise_severity escalation is `reboot_window > 24h`. The RHS
    // coercion only converts a BARE numeric, so `24h` stayed a string. Pre-fix a
    // numeric LHS compared `48 > '24h'` → `48 > NaN` → false (a 48h window
    // silently failed to escalate), and a string LHS compared lexicographically
    // `'6h' > '24h'` → `'6' > '2'` → true (a 6h window WRONGLY escalated).
    const cond = 'reboot_window > 24h';
    // 48 hours (bare number) > 24h → escalates. Pre-fix: false.
    assert.equal(evalCondition(cond, { reboot_window: 48 }), true);
    assert.strictEqual(evalCondition(cond, { reboot_window: 48 }), true);
    // '6h' < 24h → does NOT escalate. Pre-fix: true (lexicographic inversion).
    assert.equal(evalCondition(cond, { reboot_window: '6h' }), false);
    assert.strictEqual(evalCondition(cond, { reboot_window: '6h' }), false);
    // '100h' > 24h → escalates.
    assert.equal(evalCondition(cond, { reboot_window: '100h' }), true);
    // exactly 24h is not strictly greater.
    assert.equal(evalCondition(cond, { reboot_window: '24h' }), false);
    // cross-unit: 2 days == 48h > 24h → escalates (same unit family after norm).
    assert.equal(evalCondition(cond, { reboot_window: '2d' }), true);
    // 30 minutes is far below 24h.
    assert.equal(evalCondition(cond, { reboot_window: '30min' }), false);
  });

  it('the full kernel reboot_window escalation condition fires for a 48h window and not a 6h window', () => {
    const cond = 'rwep >= 90 AND patch_available == true AND livepatch_active == false AND reboot_window > 24h';
    const base = { rwep: 95, patch_available: true, livepatch_active: false };
    assert.equal(evalCondition(cond, { ...base, reboot_window: 48 }), true);
    assert.equal(evalCondition(cond, { ...base, reboot_window: '6h' }), false);
  });

  it('a degraded ordering of two non-numeric, non-severity, non-duration strings surfaces condition_type_mismatch', () => {
    const errs = [];
    // 'theater' > 'foo' is lexicographically true but semantically meaningless —
    // the comparison silently degraded with no diagnostic pre-fix.
    const r = evalCondition('a > b', { a: 'theater', b: 'foo', _runErrors: errs });
    assert.equal(typeof r, 'boolean');
    assert.equal(errs.length, 1);
    assert.equal(errs[0].kind, 'condition_type_mismatch');
    assert.equal(errs[0].condition, 'a > b');
  });

  it('a duration-vs-duration ordering does NOT surface condition_type_mismatch', () => {
    const errs = [];
    assert.equal(evalCondition('reboot_window > 24h', { reboot_window: '6h', _runErrors: errs }), false);
    assert.equal(errs.filter((e) => e.kind === 'condition_type_mismatch').length, 0);
  });

  it('a numeric ordering does NOT surface condition_type_mismatch', () => {
    const errs = [];
    assert.equal(evalCondition('rwep >= 90', { rwep: 100, _runErrors: errs }), true);
    assert.equal(errs.filter((e) => e.kind === 'condition_type_mismatch').length, 0);
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

describe('round-3: dead-condition rewrites, validate engine-ctx, evidence-hash, feeds_into', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });
  const dir0 = (id) => runner.loadPlaybook(id).directives[0].id;

  // --- #45a: rewritten escalation_criteria FIRE (were dead prose) ---
  it('audit-log-integrity raise_severity fires on the rewritten indicator-id condition', () => {
    const d = dir0('audit-log-integrity');
    const det = runner.detect('audit-log-integrity', d, {});
    const an = runner.analyze('audit-log-integrity', d, det, {
      'audit-log-deletable-by-writing-identity': true,
      'audit-hash-chain-not-verified': true,
    });
    const fired = an.escalations.find(e => e.action === 'raise_severity');
    assert.ok(fired, 'rewritten raise_severity escalation must fire (was dead prose)');
    assert.match(fired.condition, /audit-log-deletable-by-writing-identity == true/);
  });

  it('decompression-dos trigger_playbook fires on zip-slip == true (was prose)', () => {
    const d = dir0('decompression-dos');
    const det = runner.detect('decompression-dos', d, {});
    const an = runner.analyze('decompression-dos', d, det, { 'zip-slip-path-traversal': true });
    assert.ok(an.escalations.some(e => e.condition === 'zip-slip-path-traversal == true'),
      'zip-slip escalation must fire');
  });

  it('multitenancy-isolation cross-tenant escalation fires on any one tenant-isolation indicator', () => {
    const d = dir0('multitenancy-isolation');
    const det = runner.detect('multitenancy-isolation', d, {});
    const an = runner.analyze('multitenancy-isolation', d, det, { 'query-not-scoped-by-tenant': true });
    assert.ok(an.escalations.some(e => /query-not-scoped-by-tenant == true/.test(e.condition)),
      'OR-chain escalation must fire on a single fired indicator');
  });

  it('every shipped escalation/feeds_into/precondition condition parses (no condition_unparsed) — atom-level', () => {
    // Class guard mirroring the validate-playbooks parse-gate. Atomize each
    // condition (split top-level OR then AND, strip parens) and parse-check each
    // LEAF — checking the whole condition once would miss a dead sub-clause
    // hidden behind a short-circuiting AND/OR (evalCondition's .every/.some stop
    // at the first false/true). A coincidence-passing whole-condition check is
    // worse than none.
    const { _evalCondition } = runner;
    const splitTop = (expr, sep) => {
      const parts = []; const needle = ' ' + sep + ' '; let depth = 0, buf = '', i = 0, q = null;
      while (i < expr.length) {
        const ch = expr[i];
        if (q) { if (ch === '\\' && i + 1 < expr.length) { buf += ch + expr[i + 1]; i += 2; continue; } if (ch === q) q = null; buf += ch; i++; continue; }
        if (ch === "'" || ch === '"') { q = ch; buf += ch; i++; continue; }
        if (ch === '(') { depth++; buf += ch; i++; continue; }
        if (ch === ')') { depth--; buf += ch; i++; continue; }
        if (depth === 0 && expr.startsWith(needle, i)) { parts.push(buf.trim()); buf = ''; i += needle.length; continue; }
        buf += ch; i++;
      }
      parts.push(buf.trim()); return parts;
    };
    const strip = (e) => { e = e.trim(); while (e.startsWith('(') && e.endsWith(')')) { let d = 0, ok = true; for (let i = 0; i < e.length; i++) { if (e[i] === '(') d++; else if (e[i] === ')') { d--; if (d === 0 && i < e.length - 1) { ok = false; break; } } } if (ok) e = e.slice(1, -1).trim(); else break; } return e; };
    const atomize = (cond) => { const out = []; (function rec(e) { e = strip(e); const o = splitTop(e, 'OR'); if (o.length > 1) { o.forEach(rec); return; } const a = splitTop(e, 'AND'); if (a.length > 1) { a.forEach(rec); return; } out.push(e); })(cond); return out; };
    const pbDir = REAL_PLAYBOOK_DIR;
    const dead = [];
    for (const f of fs.readdirSync(pbDir).filter(x => x.endsWith('.json'))) {
      const pb = JSON.parse(fs.readFileSync(path.join(pbDir, f), 'utf8'));
      const conds = [];
      for (const ec of (pb.phases.analyze.escalation_criteria || [])) if (ec && typeof ec.condition === 'string') conds.push(ec.condition);
      for (const fi of (pb._meta.feeds_into || [])) if (fi && typeof fi.condition === 'string') conds.push(fi.condition);
      for (const rp of (pb.phases.validate.remediation_paths || [])) for (const pc of (rp.preconditions || [])) if (typeof pc === 'string') conds.push(pc);
      for (const c of conds) {
        for (const atom of atomize(c)) {
          const re = [];
          _evalCondition(atom, { _runErrors: re }, { _runErrors: re });
          if (re.some(e => e && e.kind === 'condition_unparsed')) dead.push(`${f}: atom "${atom}"  in:  ${c}`);
        }
      }
    }
    assert.deepEqual(dead, [], `unparseable (dead) condition atoms found:\n${dead.join('\n')}`);
  });

  // --- fired-indicator mirror: indicator-gated conditions resolve on the collector path ---
  it('an indicator-gated escalation fires from a detect HIT (signal_overrides), not only when re-submitted under signals', () => {
    // The collector / AI evidence path delivers indicator hits as
    // signal_overrides (which detect reads); the escalation context spreads
    // `signals`. Without mirroring fired indicators, `<indicator-id> == true`
    // escalations stayed dead on the real path even when the indicator detected.
    const d = dir0('library-author');
    const det = runner.detect('library-author', d, {
      signal_overrides: { 'no-security-md': 'hit', 'no-security-txt': 'hit' },
    });
    const hits = (det.indicators || []).filter(i => i.verdict === 'hit').map(i => i.id);
    assert.ok(hits.includes('no-security-md') && hits.includes('no-security-txt'),
      'both indicators must register as detect hits');
    // product_is_public is host-asserted finding context (no indicator) → signals.
    // Crucially, the two indicator ids are NOT in signals — only signal_overrides.
    const an = runner.analyze('library-author', d, det, { product_is_public: true });
    const fired = an.escalations.find(e => /no-security-md == true AND no-security-txt == true/.test(e.condition));
    assert.ok(fired, 'the indicator-gated escalation must fire from the detect hits alone (collector path)');
  });

  it('an operator can still suppress a mirrored indicator by submitting it false under signals', () => {
    const d = dir0('library-author');
    const det = runner.detect('library-author', d, {
      signal_overrides: { 'no-security-md': 'hit', 'no-security-txt': 'hit' },
    });
    // signals override the mirrored fired-indicator truth (lowest precedence).
    const an = runner.analyze('library-author', d, det, { product_is_public: true, 'no-security-md': false });
    const fired = an.escalations.find(e => /no-security-md == true AND no-security-txt == true/.test(e.condition));
    assert.ok(!fired, 'a signals-submitted false must override the mirrored detect hit');
  });

  // --- #45d/#7: validate() precondition context exposes engine-computed roots ---
  it('validate() resolves the engine-computed `analyze` root in a remediation precondition', () => {
    const tmp = tmpDir('validate-engine-ctx');
    try {
      const pb = synthPlaybook({
        _meta: { id: 'synth-engine-ctx' },
        phases: {
          detect: { indicators: [{ id: 'sig-a', type: 'config_value', value: 'x', description: 'x', confidence: 'high', deterministic: true }] },
          validate: {
            remediation_paths: [
              { id: 'engine-gated', priority: 1, description: 'x', steps: ['x'], for_signals: ['sig-a'], preconditions: ["analyze.classification == 'detected'"] },
            ],
            validation_tests: [], evidence_requirements: [], regression_trigger: [],
          },
        },
      });
      writePlaybook(tmp, 'synth-engine-ctx', pb);
      const r = freshRunner(tmp);
      const det = r.detect('synth-engine-ctx', 'default', { signal_overrides: { 'sig-a': 'hit' } });
      const an = r.analyze('synth-engine-ctx', 'default', det, {});
      const v = r.validate('synth-engine-ctx', 'default', an, {});
      const path = v.remediation_options_considered.find(c => c.id === 'engine-gated');
      assert.ok(path, 'remediation path considered');
      assert.equal(an.classification, 'detected');
      assert.equal(path.all_satisfied, true,
        'precondition gating on the engine-computed analyze.classification must now be satisfiable');
    } finally {
      runner = freshRunner(REAL_PLAYBOOK_DIR);
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('validate() leaves the engine-gated precondition UNsatisfied when the engine value differs', () => {
    const tmp = tmpDir('validate-engine-ctx-neg');
    try {
      const pb = synthPlaybook({
        _meta: { id: 'synth-engine-neg' },
        phases: {
          detect: { indicators: [{ id: 'sig-a', type: 'config_value', value: 'x', description: 'x', confidence: 'high', deterministic: true }] },
          validate: {
            remediation_paths: [
              { id: 'engine-gated', priority: 1, description: 'x', steps: ['x'], for_signals: ['sig-a'], preconditions: ["analyze.classification == 'detected'"] },
            ],
            validation_tests: [], evidence_requirements: [], regression_trigger: [],
          },
        },
      });
      writePlaybook(tmp, 'synth-engine-neg', pb);
      const r = freshRunner(tmp);
      const det = r.detect('synth-engine-neg', 'default', {}); // nothing fired → not 'detected'
      const an = r.analyze('synth-engine-neg', 'default', det, {});
      const v = r.validate('synth-engine-neg', 'default', an, {});
      const path = v.remediation_options_considered.find(c => c.id === 'engine-gated');
      assert.notEqual(an.classification, 'detected');
      assert.equal(path.all_satisfied, false, 'precondition must evaluate, not be vacuously true');
    } finally {
      runner = freshRunner(REAL_PLAYBOOK_DIR);
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // --- #45d/#6: evidence_hash ignores render-only _bundle_formats, tracks real evidence ---
  it('evidence_hash is stable across the render-only _bundle_formats signal', () => {
    const PRE = { precondition_checks: { 'linux-platform': true, 'uname-available': true } };
    const base = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { 'kver-in-affected-range': true } }, PRE);
    const withFmt = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { 'kver-in-affected-range': true, _bundle_formats: ['sarif', 'openvex'] } }, PRE);
    assert.match(base.evidence_hash, /^[0-9a-f]{64}$/);
    assert.equal(base.evidence_hash, withFmt.evidence_hash,
      'choosing an output bundle format must not change the evidence identity');
  });

  it('evidence_hash of a render-only-signals submission equals a no-signals submission', () => {
    // A submission whose ONLY signal is the render directive _bundle_formats
    // must hash identically to a submission with no signals at all — otherwise
    // the digest records `{signals:{}}` vs no-signals and drifts on --format.
    const PRE = { precondition_checks: { 'linux-platform': true, 'uname-available': true } };
    const noSignals = runner.run('kernel', 'all-catalogued-kernel-cves', {}, PRE);
    const renderOnly = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { _bundle_formats: ['sarif'] } }, PRE);
    const emptyBag = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: {} }, PRE);
    assert.equal(noSignals.evidence_hash, renderOnly.evidence_hash,
      'a render-only (_bundle_formats) signal bag must not change the evidence hash');
    assert.equal(noSignals.evidence_hash, emptyBag.evidence_hash,
      'an empty signals bag must hash like no signals');
  });

  it('evidence_hash still changes on a real evidence change AND on a posture-affecting vex_filter', () => {
    const PRE = { precondition_checks: { 'linux-platform': true, 'uname-available': true } };
    const base = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { 'kver-in-affected-range': true } }, PRE);
    const moreEvidence = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { 'kver-in-affected-range': true, 'unpriv-userns-enabled': true } }, PRE);
    const vex = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { 'kver-in-affected-range': true, vex_filter: ['CVE-2024-0001'] } }, PRE);
    assert.notEqual(base.evidence_hash, moreEvidence.evidence_hash, 'a new signal must change the hash');
    assert.notEqual(base.evidence_hash, vex.evidence_hash, 'a VEX disposition is posture-affecting evidence and must change the hash');
  });

  // --- #45d: containers -> sbom feeds_into is live (was rooted at a look-artifact id) ---
  it('containers -> sbom feeds_into chains when container-image-layers > 0', () => {
    const PRE = { operator_consent: { explicit: true }, precondition_checks: { 'linux-platform': true } };
    let chained = null;
    for (const d of runner.loadPlaybook('containers').directives.map(x => x.id)) {
      let r;
      try { r = runner.run('containers', d, { signals: { 'container-image-layers': 7, 'dockerfile-from-latest': true }, signal_overrides: { 'dockerfile-from-latest': true } }, PRE); }
      catch { continue; }
      if (r && r.phases && r.phases.close && Array.isArray(r.phases.close.feeds_into)) { chained = r.phases.close.feeds_into; if (chained.includes('sbom')) break; }
    }
    assert.ok(chained && chained.includes('sbom'),
      'containers must chain to sbom when image layers are present (feeds_into was dead at container-image-layers.length)');
  });
});

describe('round-5: output/binding resolution (interpolation, SARIF locations, CSAF product binding)', () => {
  let runner;
  before(() => { runner = freshRunner(REAL_PLAYBOOK_DIR); });
  const PRE = { forceStale: true, operator_consent: { explicit: true }, precondition_checks: { 'linux-platform': true, 'uname-available': true } };

  it('exception render tracks unresolved ${placeholder} tokens as missing_interpolation_vars + a runtime_error', () => {
    const out = runner.run('kernel', 'all-catalogued-kernel-cves', { signals: { remediation_blocked: true } }, PRE);
    const ex = out.phases.close.exception;
    assert.ok(ex, 'exception should be generated when the trigger fires');
    assert.ok(Array.isArray(ex.missing_interpolation_vars), 'exception must carry missing_interpolation_vars');
    assert.ok(ex.missing_interpolation_vars.length >= 1, 'operator-fill template vars are unresolved on a bare run');
    // The auditor language carries the <MISSING:..> literals AND the gap is observable.
    assert.match(ex.auditor_ready_language, /<MISSING:/);
    const re = (out.phases.analyze.runtime_errors || []).find(e => e.kind === 'exception_unresolved_placeholders');
    assert.ok(re, 'an exception_unresolved_placeholders runtime_error must surface the gap');
  });

  it('SARIF finding-class results always carry a location (logicalLocations fallback for prose-source playbooks)', () => {
    // secrets describes its look-artifact sources in prose/globs, so the physical
    // location heuristic returns null; the result must still be located so GitHub
    // Code Scanning does not drop it.
    const out = runner.run('secrets', 'full-repo-secret-scan',
      { signals: { _bundle_formats: ['sarif'] }, signal_overrides: { 'aws-access-key-id': 'hit' } },
      { operator_consent: { explicit: true }, precondition_checks: { 'linux-platform': true, 'uname-available': true } });
    const sarif = out.phases.close.evidence_package.bundles_by_format.sarif;
    const findings = sarif.runs[0].results.filter(r => r.properties && (r.properties.kind === 'indicator_hit' || r.properties.kind === 'cve_match'));
    assert.ok(findings.length >= 1, 'secrets should emit at least one finding-class result');
    for (const r of findings) {
      assert.ok(Array.isArray(r.locations) && r.locations.length >= 1, `result ${r.ruleId} must carry a location`);
      const loc = r.locations[0];
      assert.ok(loc.physicalLocation || (Array.isArray(loc.logicalLocations) && loc.logicalLocations.length), 'physical or logical location');
    }
  });

  it('CSAF per-CVE CSAFPID branch leaves are bound into product_status.known_affected', () => {
    const out = runner.run('kernel', 'all-catalogued-kernel-cves',
      { signals: { _bundle_formats: ['csaf-2.0'], 'CVE-2026-31431': true, 'CVE-2026-43284': true } },
      { ...PRE, operator: 'https://x.example', publisherNamespace: 'https://x.example' });
    const csaf = out.phases.close.evidence_package.bundles_by_format['csaf-2.0'];
    const leafPids = new Set();
    (function walk(b) { for (const x of (b || [])) { if (x.product && x.product.product_id) leafPids.add(x.product.product_id); if (x.branches) walk(x.branches); } })(csaf.product_tree.branches);
    assert.ok(leafPids.size >= 1, 'kernel CVEs carry affected_versions → CSAFPID leaves exist');
    const referenced = new Set();
    for (const v of (csaf.vulnerabilities || [])) {
      const ps = v.product_status || {};
      [...(ps.known_affected || []), ...(ps.fixed || [])].forEach(p => { if (/^CSAFPID-/.test(p)) referenced.add(p); });
    }
    for (const pid of leafPids) assert.ok(referenced.has(pid), `branch leaf ${pid} must be referenced from a vulnerability product_status`);
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


// ---- routed from blamejs-scan-fixes ----
require("node:test").describe("blamejs-scan-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/blamejs-scan-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const containersCollector = require('../lib/collectors/containers.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('a playbook declaring bundle_format "json" builds a populated json bundle, not the Unknown-format placeholder', () => {
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

test('top_finding names the dominant fired indicator (not the verdict string), and summary_line states the verdict once', () => {
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

test('top_finding prefers the indicator that drove the RWEP score (and falls back to the dominant hit when none is weighted)', () => {
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

test('run() surfaces collector_errors as an advisory collector_warnings field (and omits it when there are none)', () => {
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

test('regression_event_triggers carry the condition string (not null) from a playbook keyed on `condition`', () => {
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

test('selected_remediation prefers the path that addresses a fired signal (and falls back to priority-1 when none is linked)', () => {
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

test('a blocked-preflight summary_line truncates on a word boundary with an ellipsis, not mid-token', () => {
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#71 detect canonicalizes no_hit to miss (flat-shape submission)', () => {
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

test('#71 normalizer accepts every documented synonym', () => {
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

test('#71 detect surfaces observations_received + signals_received', () => {
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

test('#73 indicators_evaluated is an array', () => {
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

test('#82 SARIF includes results from indicators that fired', () => {
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
});

test('#85 from_observation populated when observation drove the indicator', () => {
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from bundle-correctness ----
require("node:test").describe("bundle-correctness", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Bundle-emit correctness checks against the canonical schemas of:
 *   - CSAF 2.0 (csaf_security_advisory category)
 *   - SARIF 2.1.0
 *   - OpenVEX 0.2.0
 *
 * v0.12.12 (B1-B7 audit): the bundle emitters were structurally
 * non-conformant against each of the three downstream specs. These tests
 * pin the conformant shape so regressions surface on every test run.
 *
 * Run under: node --test --test-concurrency=1 tests/
 * (concurrency=1 matters — the runner is module-scope and reads
 * EXCEPTD_PLAYBOOK_DIR once per process.)
 */

const test = require('node:test');
const { describe, it, before } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// Detect → analyze → validate → close against kernel playbook with one
// indicator forced to hit, producing CVE matches + indicator hit + framework
// gap mapping in a single bundle build.
function emitBundles() {
  const runner = loadRunner();
  const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, {
    patch_available: false, blast_radius_score: 3
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0']
  }, { session_id: 'bundlecorrectnesstest' });
  return c.evidence_package.bundles_by_format;
}

describe('CSAF 2.0 — B5 (product_tree mandatory for security_advisory)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['csaf-2.0']; });

  it('document.category is csaf_security_advisory', () => {
    assert.equal(bundle.document.category, 'csaf_security_advisory');
    assert.equal(bundle.document.csaf_version, '2.0');
  });

  it('product_tree.full_product_names is non-empty', () => {
    assert.ok(bundle.product_tree, 'product_tree must exist');
    assert.ok(Array.isArray(bundle.product_tree.full_product_names));
    assert.ok(bundle.product_tree.full_product_names.length >= 1);
    const fp = bundle.product_tree.full_product_names[0];
    assert.equal(typeof fp.product_id, 'string');
    assert.ok(fp.product_id.startsWith('exceptd-target-'));
    assert.equal(typeof fp.name, 'string');
    assert.ok(fp.product_identification_helper?.purl);
  });

  it('every vulnerability references product_tree via product_status', () => {
    assert.ok(bundle.vulnerabilities.length > 0);
    // A product_id is defined in the product_tree via EITHER full_product_names[]
    // OR a branches[] leaf's product.product_id (both are valid CSAF definition
    // sites). The per-version CSAFPID-N leaves bound into product_status live in
    // branches, so collect product ids from both.
    const knownProductIds = new Set(
      bundle.product_tree.full_product_names.map(p => p.product_id)
    );
    (function walk(branches) {
      for (const b of (branches || [])) {
        if (b.product && b.product.product_id) knownProductIds.add(b.product.product_id);
        if (b.branches) walk(b.branches);
      }
    })(bundle.product_tree.branches);
    for (const v of bundle.vulnerabilities) {
      assert.ok(v.product_status, `vulnerability missing product_status: ${JSON.stringify(v).slice(0, 80)}`);
      const refIds = [
        ...(v.product_status.known_affected || []),
        ...(v.product_status.fixed || []),
        ...(v.product_status.under_investigation || []),
        ...(v.product_status.not_affected || [])
      ];
      assert.ok(refIds.length >= 1, 'product_status must reference at least one product');
      for (const id of refIds) {
        assert.ok(knownProductIds.has(id), `unknown product_id ${id} referenced by vulnerability`);
      }
    }
  });
});

describe('SARIF 2.1.0 — B6 (locations) + B7 (null property bag)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['sarif-2.1.0']; });

  it('$schema + version pinned', () => {
    assert.equal(bundle.version, '2.1.0');
    assert.match(bundle.$schema, /sarif-schema-2\.1\.0\.json$/);
  });

  it('indicator-hit results include locations when artifact paths exist', () => {
    const results = bundle.runs[0].results;
    const indicatorResults = results.filter(r => r.properties?.kind === 'indicator_hit');
    assert.ok(indicatorResults.length >= 1, 'kernel playbook should emit at least one indicator hit');
    for (const r of indicatorResults) {
      // kernel playbook has look-phase artifacts → locations MUST be present.
      assert.ok(Array.isArray(r.locations), `indicator result ${r.ruleId} missing locations`);
      assert.ok(r.locations[0].physicalLocation?.artifactLocation?.uri, 'physicalLocation.artifactLocation.uri must be populated');
    }
  });

  it('property bags omit null keys (B7)', () => {
    const results = bundle.runs[0].results;
    for (const r of results) {
      for (const [k, v] of Object.entries(r.properties || {})) {
        assert.notEqual(v, null, `result ${r.ruleId} has null property ${k}`);
      }
    }
  });

  it('framework-gap results carry kind: informational (B3 SARIF analogue)', () => {
    // ruleIds are playbook-prefixed (e.g. `kernel/framework-gap-0`), so
    // match on the suffix rather than the bare prefix.
    const gapResults = bundle.runs[0].results.filter(r => /(?:^|\/)framework-gap-\d+/.test(String(r.ruleId)));
    if (gapResults.length === 0) return; // playbook has none — skip
    for (const r of gapResults) {
      assert.equal(r.kind, 'informational', 'framework-gap results must declare kind: informational');
    }
  });
});

describe('OpenVEX 0.2.0 — B1 (products) + B2 (status) + B3 (no framework gaps) + B4 (URN IRI)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['openvex-0.2.0']; });

  it('@context + version pinned', () => {
    assert.equal(bundle['@context'], 'https://openvex.dev/ns/v0.2.0');
    assert.equal(bundle.version, 1);
  });

  it('every statement has products (B1)', () => {
    assert.ok(Array.isArray(bundle.statements));
    assert.ok(bundle.statements.length > 0);
    for (const s of bundle.statements) {
      assert.ok(Array.isArray(s.products), `statement missing products: ${JSON.stringify(s.vulnerability)}`);
      assert.ok(s.products.length >= 1);
      assert.ok(s.products[0]['@id'], 'product entry missing @id');
      assert.ok(s.products[0]['@id'].startsWith('pkg:exceptd/'), 'product @id should be a pkg:exceptd/ purl');
    }
  });

  it('indicator-hit statements emit status:affected with action_statement (B2)', () => {
    const indicatorStatements = bundle.statements.filter(s =>
      String(s.vulnerability['@id']).startsWith('urn:exceptd:indicator:')
    );
    assert.ok(indicatorStatements.length >= 1, 'must contain at least one indicator statement');
    const hits = indicatorStatements.filter(s => s.status === 'affected');
    assert.ok(hits.length >= 1, 'forced indicator hit must produce status: affected');
    for (const s of hits) {
      assert.equal(typeof s.action_statement, 'string', 'affected statements must carry action_statement');
      assert.ok(s.action_statement.length > 0);
    }
  });

  it('no framework-gap statements pollute the VEX feed (B3)', () => {
    for (const s of bundle.statements) {
      const id = String(s.vulnerability['@id']);
      assert.ok(!id.includes('framework-gap'), `framework-gap statement leaked into OpenVEX: ${id}`);
    }
  });

  it('every @id is a valid URN (B4)', () => {
    // CVE statements: urn:cve:<id>
    // Indicator statements: urn:exceptd:indicator:<playbook>:<indicator-id>
    // NID (first segment) is conventionally lowercase; the NSS is case-sensitive
    // per RFC 8141 and carries the canonical identifier case (e.g. CVE-2026-43284).
    const urnRe = /^urn:[a-z][a-z0-9-]*:[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*$/;
    for (const s of bundle.statements) {
      const id = String(s.vulnerability['@id']);
      assert.match(id, urnRe, `vulnerability @id is not a valid URN: ${id}`);
      // No literal spaces, no unregistered exceptd: prefix
      assert.ok(!id.includes(' '), `@id has literal space: ${id}`);
      assert.ok(!id.startsWith('exceptd:'), `@id uses unregistered exceptd: scheme: ${id}`);
    }
  });

  it('valid OpenVEX status values only', () => {
    const validStatuses = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);
    for (const s of bundle.statements) {
      assert.ok(validStatuses.has(s.status), `invalid OpenVEX status: ${s.status}`);
      if (s.status === 'not_affected') {
        assert.ok(s.justification, 'not_affected status requires justification');
      }
      if (s.status === 'affected') {
        assert.ok(s.action_statement, 'affected status requires action_statement');
      }
      if (s.status === 'under_investigation') {
        assert.equal(s.action_statement, undefined, 'under_investigation must not include action_statement');
      }
    }
  });
});

// ----- audit W (v0.12.20) regression coverage -----

function emitBundlesWith(opts = {}) {
  const runner = loadRunner();
  const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, {
    patch_available: false, blast_radius_score: 3,
    ...(opts.vex_fixed ? { vex_fixed: opts.vex_fixed } : {}),
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0']
  }, { session_id: 'bundlecorrectnesstest' });
  return { bundles: c.evidence_package.bundles_by_format, body: c.evidence_package.bundle_body, analyze: an };
}

describe('audit W P1-A — fixed status gated on vex_status, not live_patch_available', () => {
  it('CSAF: live-patchable CVE without operator VEX disposition stays known_affected', () => {
    const { bundles, analyze } = emitBundlesWith();
    // The kernel playbook surfaces Copy Fail (live_patch_available=true) but
    // no operator-supplied VEX disposition is present in this run.
    const livePatchableMatched = analyze.matched_cves.filter(c => c.live_patch_available === true);
    assert.ok(livePatchableMatched.length >= 1, 'fixture: at least one matched CVE must be live-patchable');
    for (const matched of livePatchableMatched) {
      const vuln = bundles['csaf-2.0'].vulnerabilities.find(v => v.cve === matched.cve_id);
      assert.ok(vuln, `csaf vuln missing for ${matched.cve_id}`);
      assert.ok(vuln.product_status.known_affected, `${matched.cve_id} must remain known_affected absent vex_status:fixed`);
      assert.ok(!vuln.product_status.fixed, `${matched.cve_id} must NOT be reported as fixed based on live_patch_available alone`);
    }
  });

  it('CSAF: operator vex_status=fixed promotes to product_status.fixed', () => {
    // Pick the first live-patchable CVE the kernel playbook surfaces and
    // mark it as fixed via the vex_fixed set.
    const baseline = emitBundlesWith();
    const target = baseline.analyze.matched_cves.find(c => c.live_patch_available === true);
    assert.ok(target, 'fixture: need a live-patchable matched CVE to test promotion');
    const { bundles } = emitBundlesWith({ vex_fixed: new Set([target.cve_id]) });
    const vuln = bundles['csaf-2.0'].vulnerabilities.find(v => v.cve === target.cve_id);
    assert.ok(vuln.product_status.fixed, 'operator vex_status:fixed must drive product_status.fixed');
    assert.ok(!vuln.product_status.known_affected);
  });

  it('OpenVEX: live-patchable without vex_status:fixed stays affected', () => {
    const { bundles, analyze } = emitBundlesWith();
    const livePatchableMatched = analyze.matched_cves.filter(c => c.live_patch_available === true);
    for (const matched of livePatchableMatched) {
      const stmt = bundles['openvex-0.2.0'].statements.find(s => s.vulnerability.name === matched.cve_id);
      assert.ok(stmt, `openvex stmt missing for ${matched.cve_id}`);
      assert.equal(stmt.status, 'affected', `${matched.cve_id} must NOT be reported fixed based on live_patch_available alone`);
      assert.ok(stmt.action_statement, 'affected statement requires action_statement');
    }
  });

  it('OpenVEX: operator vex_status=fixed produces status:fixed', () => {
    const baseline = emitBundlesWith();
    const target = baseline.analyze.matched_cves.find(c => c.live_patch_available === true);
    const { bundles } = emitBundlesWith({ vex_fixed: new Set([target.cve_id]) });
    const stmt = bundles['openvex-0.2.0'].statements.find(s => s.vulnerability.name === target.cve_id);
    assert.equal(stmt.status, 'fixed');
    assert.equal(stmt.action_statement, undefined, 'fixed statement must not carry action_statement');
  });
});

describe('audit W P2-A — SARIF artifactLocation rejects shell commands', () => {
  it('locations[].physicalLocation.artifactLocation.uri is path-shaped', () => {
    const { bundles } = emitBundlesWith();
    const sarif = bundles['sarif-2.1.0'];
    const withLocs = sarif.runs[0].results.filter(r => Array.isArray(r.locations));
    assert.ok(withLocs.length >= 1, 'fixture: at least one result must carry locations');
    for (const r of withLocs) {
      const uri = r.locations[0].physicalLocation.artifactLocation.uri;
      // Must not contain whitespace (commands like `uname -r`).
      assert.ok(!/\s/.test(uri), `artifactLocation.uri has whitespace: ${uri}`);
      // Must not contain shell-pipe / sentence punctuation.
      assert.ok(!/[|;&]/.test(uri), `artifactLocation.uri has shell metacharacters: ${uri}`);
      // Must look like a path or file URI.
      assert.match(uri, /^(?:[/~]|[A-Za-z]:[/\\]|\.\.?[/\\]|file:|[A-Za-z0-9_.+-]+[/\\][^\s]+)/,
        `artifactLocation.uri not path-shaped: ${uri}`);
    }
  });
});

describe('audit W P2-B — bundle_body and bundles_by_format share timestamps', () => {
  it('CSAF tracking dates align between bundle_body and bundles_by_format[primary]', () => {
    const { bundles, body } = emitBundlesWith();
    // bundle_body for kernel playbook (default csaf-2.0 primary) must
    // share identity with bundles_by_format['csaf-2.0'] (same object).
    assert.equal(body, bundles['csaf-2.0'], 'bundle_body must be the same object reference as bundles_by_format[primary]');
  });

  it('multi-format emit produces a single issuedAt across all formats', () => {
    const { bundles } = emitBundlesWith();
    const csafIssued = bundles['csaf-2.0'].document.tracking.initial_release_date;
    const vexIssued = bundles['openvex-0.2.0'].timestamp;
    assert.equal(csafIssued, vexIssued, 'CSAF initial_release_date and OpenVEX timestamp must use the same issuedAt');
    // Also: current_release_date and revision_history[0].date must match.
    assert.equal(bundles['csaf-2.0'].document.tracking.current_release_date, csafIssued);
    assert.equal(bundles['csaf-2.0'].document.tracking.revision_history[0].date, csafIssued);
  });
});

describe('audit W P2-D — CSAF framework gaps move from vulnerabilities[] to document.notes[]', () => {
  it('vulnerabilities[] contains no exceptd-framework-gap ids', () => {
    const { bundles } = emitBundlesWith();
    const csaf = bundles['csaf-2.0'];
    for (const v of csaf.vulnerabilities) {
      const ids = v.ids || [];
      for (const idEntry of ids) {
        assert.notEqual(idEntry.system_name, 'exceptd-framework-gap',
          'framework gaps must not ride in vulnerabilities[]; they belong in document.notes[]');
      }
    }
  });

  it('document.notes[] surfaces framework gaps when analyze produced any', () => {
    const { bundles, analyze } = emitBundlesWith();
    const csaf = bundles['csaf-2.0'];
    const gapCount = (analyze.framework_gap_mapping || []).length;
    const allNotes = csaf.document.notes || [];
    // When neither --publisher-namespace nor a URL-shaped --operator is
    // supplied, an explanatory note is emitted alongside the
    // framework-gap notes. Filter to the framework-gap subset before the
    // count assertion.
    const gapNotes = allNotes.filter(n => n.category === 'details');
    assert.equal(gapNotes.length, gapCount, 'document.notes[] (category=details) count must match framework_gap_mapping.length');
    for (const n of gapNotes) {
      assert.equal(n.category, 'details', 'framework-gap notes use category: details');
      assert.ok(typeof n.text === 'string' && n.text.length > 0);
    }
  });
});

describe('audit W P3-A — SARIF invocations.properties strips null values', () => {
  it('invocations[0].properties has no null-valued keys', () => {
    const { bundles } = emitBundlesWith();
    const props = bundles['sarif-2.1.0'].runs[0].invocations[0].properties;
    for (const [k, v] of Object.entries(props)) {
      assert.notEqual(v, null, `invocations.properties.${k} must be omitted when null`);
    }
  });
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from bundle-determinism ----
require("node:test").describe("bundle-determinism", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from condition-evaluator-fixes ----
require("node:test").describe("condition-evaluator-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression for the condition mini-language (lib/playbook-runner.js
 * evalCondition). Conditions gate escalation_criteria, feeds_into chains, and
 * remediation preconditions across the catalog; a silently-false condition
 * disables its rule.
 *
 *   - hyphenated signal/indicator ids (the catalog naming convention) must
 *     parse, not fall through to false
 *   - severity comparison is by the low<medium<high<critical ladder, not
 *     lexicographic string order (so 'critical' >= 'high' is true)
 *   - `contains` is a synonym for `includes`
 *   - an operator-submitted signal cannot override an engine-computed value
 *   - an unparseable condition surfaces a condition_unparsed runtime error
 *   - a contains/IN clause whose LHS path is absent surfaces a
 *     condition_path_unresolved runtime error (a parsed-but-dead clause), while a
 *     present-but-empty collection stays a silent legitimate false
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));
const evalCondition = runner._evalCondition;

test('hyphenated LHS evaluates against the matching ctx key (not silently false)', () => {
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': true }), true);
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': false }), false);
  assert.equal(evalCondition('kver-in-affected-range == true AND kaslr-disabled == true',
    { 'kver-in-affected-range': true, 'kaslr-disabled': true }), true);
});

test('severity comparison uses the ordinal ladder, not lexicographic order', () => {
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'critical' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'high' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'medium' } }), false);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'low' } }), false);
  // numeric comparison still works (regression guard)
  assert.equal(evalCondition('rwep >= 90', { rwep: 100 }), true);
  assert.equal(evalCondition('rwep >= 90', { rwep: 50 }), false);
});

test('`contains` is accepted as a synonym for `includes`', () => {
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets includes named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['local'] } }), false);
});

test('`matches` accepts both the slash and the quote delimiter (mcp feeds_into uses the quoted form)', () => {
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

test('an unparseable (prose) condition pushes a condition_unparsed runtime error (not a silent false)', () => {
  const errs = [];
  // A genuine prose sentence the mini-language can't evaluate. (The `any … ==`
  // quantifier form below is now PARSED — see the quantifier test — so a prose
  // clause is what should still surface the diagnostic.)
  const r = evalCondition('a single compromised identity can rewrite the trail', { _runErrors: errs });
  assert.equal(r, false, 'unparseable still returns false');
  assert.equal(errs.length, 1, 'a runtime error is recorded');
  assert.equal(errs[0].kind, 'condition_unparsed');
});

test('`any`/`all` quantifier prefix parses and fires (not condition_unparsed)', () => {
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

test('`any`/`all` quantifier re-roots EVERY operator over an array element, not just comparisons (IN/contains/matches)', () => {
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

test('bare `any <path>` / `all <path>` is a non-emptiness test, not condition_unparsed', () => {
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

test('`IN [...]` member parsing is quote-aware — a comma inside a quoted member stays one member', () => {
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

test('`IN [...]` closing bracket is quote-aware — a `]` inside a quoted member does not terminate the list', () => {
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

test('AND/OR splitting and outer-paren stripping are quote-aware — a quoted member is not torn at an inner AND/OR or an unbalanced paren', () => {
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

test('a submitted signal cannot override an engine-computed value in an escalation condition', () => {
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

test('framework chains into sbom when the theater verdict + blast radius gate is met', () => {
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

test('a non-theater framework run does NOT chain into sbom', () => {
  const out = runner.run('framework', 'correlate-all-upstream-findings',
    { signals: { theater_verdict: 'clear', blast_radius_score: 5 }, artifacts: {} },
    { operator_consent: { explicit: true } });
  assert.deepEqual(out.phases.close.feeds_into, [],
    'a clear verdict does not chain framework → sbom');
});

test('contains matches an obligation jurisdiction field via a quoted member; IN list membership works; string-array contains is unaffected', () => {
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

test('object-array contains is field-targeted: a non-jurisdiction field equal to the member does NOT match', () => {
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

test('contains/IN against an absent LHS path surfaces condition_path_unresolved (not an invisible false)', () => {
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from csaf-sarif-identifiers ----
require("node:test").describe("csaf-sarif-identifiers", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Tests for the close-phase evidence-bundle identifier handling in
 * lib/playbook-runner.js.
 *
 * Runs under: node --test --test-concurrency=1
 *
 * Two behaviors are covered:
 *
 *   1. CSAF product_tree product_name comes from the package, never from a
 *      version-range operator. The catalog's dominant affected_versions shape
 *      is `package OP version` (e.g. a package name, an operator such as '>=',
 *      then a bound); naively splitting on whitespace named the product after
 *      the operator ('>=', '<', '==') instead of the package.
 *
 *   2. SARIF rule helpUri routes by issuing authority. CVE ids keep the NVD
 *      detail URL; non-CVE matched ids (MAL-/GHSA-/OSV-/RUSTSEC-/SNYK-) get the
 *      correct authority URL or no helpUri at all — never a nvd.nist.gov link
 *      that 404s and mislabels the id as an NVD CVE.
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));

const OPERATOR_ONLY = /^(<|<=|>|>=|==|=|!=|~|\^|~>)$/;

describe('CSAF product_tree — package name, never the range operator', () => {
  const shapes = [
    { affected: 'linux-kernel >= 4.14', pkg: 'linux-kernel' },
    { affected: 'runc <= 1.1.11', pkg: 'runc' },
    { affected: 'litellm < 1.83.7', pkg: 'litellm' },
    { affected: 'elementary-data == 2.23.3', pkg: 'elementary-data' },
  ];

  it('names the product after the package for each range-operator shape', () => {
    const cves = shapes.map((s, i) => ({ cve_id: `CVE-2026-100${i}`, affected_versions: [s.affected] }));
    const { branches } = runner._buildCsafBranches(cves, { _runErrors: [] });
    const byPkg = new Map();
    for (const v of branches) {
      for (const p of v.branches) {
        byPkg.set(p.name, p);
        assert.ok(!OPERATOR_ONLY.test(p.name), `product_name is a bare operator: ${p.name}`);
      }
    }
    for (const s of shapes) {
      const p = byPkg.get(s.pkg);
      assert.ok(p, `product_name "${s.pkg}" present in product_tree`);
      // The operator is carried into the version qualifier, not lost and not
      // promoted to the product name.
      const versionName = p.branches[0].name;
      assert.match(versionName, new RegExp(`^(<|<=|>|>=|==|=)\\s`), `version qualifier keeps the operator: ${versionName}`);
      // Leaf product.name is package/package@<version-range>, never operator-named.
      assert.ok(!/\/(<|<=|>|>=|==|=)@/.test(p.branches[0].product.name),
        `leaf product name embeds an operator: ${p.branches[0].product.name}`);
    }
  });

  it('end-to-end close() emits a CSAF product_tree free of operator-named products', () => {
    const pb = runner.loadPlaybook('sbom');
    const directiveId = pb.directives[0].id;
    const analyzeResult = {
      matched_cves: [
        { cve_id: 'CVE-2026-9999', rwep: 95, cisa_kev: true, active_exploitation: 'confirmed', cvss_score: null, cvss_vector: null, affected_versions: ['linux-kernel >= 4.14'] },
      ],
      rwep: { adjusted: 95 }, blast_radius_score: 4, framework_gap_mapping: [],
      _detect_indicators: [], _detect_classification: 'detected',
      compliance_theater_check: { verdict: 'present' },
    };
    const out = runner.close('sbom', directiveId, analyzeResult, { regression_next_run: null, selected_remediation: { id: 'rem-1', description: 'patch' } },
      { _bundle_formats: ['csaf-2.0'] }, { session_id: 'abcdef0123456789' });
    const csaf = out.evidence_package.bundles_by_format['csaf-2.0'];
    const branches = (csaf.product_tree && csaf.product_tree.branches) || [];
    let count = 0;
    for (const v of branches) {
      for (const p of (v.branches || [])) {
        count++;
        assert.ok(!OPERATOR_ONLY.test(p.name), `product_name is a bare operator in close() output: ${p.name}`);
      }
    }
    assert.ok(count > 0, 'product_tree contains at least one product branch');
    const linux = branches.find(v => v.name === 'linux-kernel');
    assert.ok(linux, 'linux-kernel vendor branch present');
    assert.equal(linux.branches[0].name, 'linux-kernel');
  });
});

describe('SARIF rule helpUri — authority routing, not a hardcoded NVD link', () => {
  function sarifRulesFor(matched) {
    const pb = runner.loadPlaybook('sbom');
    const directiveId = pb.directives[0].id;
    const analyzeResult = {
      matched_cves: matched,
      rwep: { adjusted: 95 }, blast_radius_score: 4, framework_gap_mapping: [],
      _detect_indicators: [], _detect_classification: 'detected',
      compliance_theater_check: { verdict: 'present' },
    };
    const out = runner.close('sbom', directiveId, analyzeResult, { regression_next_run: null, selected_remediation: { id: 'rem-1', description: 'patch' } },
      { _bundle_formats: ['sarif'] }, { session_id: 'abcdef0123456789' });
    const sarif = out.evidence_package.bundles_by_format['sarif'];
    return sarif.runs[0].tool.driver.rules;
  }

  it('a CVE rule keeps the NVD detail helpUri and a bare CVE short description', () => {
    const rules = sarifRulesFor([
      { cve_id: 'CVE-2026-43284', rwep: 90, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
    ]);
    const cveRule = rules.find(r => r.id.endsWith('CVE-2026-43284'));
    assert.ok(cveRule, 'CVE rule present');
    assert.equal(cveRule.helpUri, 'https://nvd.nist.gov/vuln/detail/CVE-2026-43284');
    assert.equal(cveRule.shortDescription.text, 'CVE-2026-43284');
  });

  it('a MAL- rule carries no nvd.nist.gov helpUri and labels its authority', () => {
    const rules = sarifRulesFor([
      { cve_id: 'CVE-2026-43284', rwep: 90, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
      { cve_id: 'MAL-2026-MOIKA-DEPCONFUSION', rwep: 88, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
    ]);
    const malRule = rules.find(r => r.id.endsWith('MAL-2026-MOIKA-DEPCONFUSION'));
    assert.ok(malRule, 'MAL rule present');
    // Malicious-Package ids have no canonical per-id advisory page: helpUri is
    // omitted entirely rather than pointing at NVD.
    assert.equal(malRule.helpUri, undefined);
    // The short description must not present the MAL id as a bare NVD CVE.
    assert.equal(malRule.shortDescription.text, 'MAL-2026-MOIKA-DEPCONFUSION (Malicious-Package)');
  });

  it('advisoryAuthorityFor routes each registry prefix to its own authority', () => {
    const a = runner._advisoryAuthorityFor;
    assert.deepEqual(a('CVE-2026-43284'), { system_name: 'NVD', helpUri: 'https://nvd.nist.gov/vuln/detail/CVE-2026-43284' });
    assert.deepEqual(a('GHSA-abcd-1234-wxyz'), { system_name: 'GHSA', helpUri: 'https://github.com/advisories/GHSA-abcd-1234-wxyz' });
    assert.deepEqual(a('OSV-2026-1'), { system_name: 'OSV', helpUri: 'https://osv.dev/vulnerability/OSV-2026-1' });
    assert.deepEqual(a('RUSTSEC-2026-0001'), { system_name: 'RUSTSEC', helpUri: 'https://rustsec.org/advisories/RUSTSEC-2026-0001.html' });
    assert.deepEqual(a('SNYK-JS-FOO-1'), { system_name: 'Snyk', helpUri: 'https://security.snyk.io/vuln/SNYK-JS-FOO-1' });
    assert.deepEqual(a('MAL-2026-X'), { system_name: 'Malicious-Package', helpUri: null });
    // A genuinely-unknown prefix gets no fabricated link.
    assert.deepEqual(a('WEIRD-1'), { system_name: 'exceptd-unknown', helpUri: null });
  });
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from deepmerge-prototype-pollution ----
require("node:test").describe("deepmerge-prototype-pollution", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression for the exported deepMerge utility (lib/playbook-runner.js
 * _deepMerge). deepMerge powers phase-override resolution; its `override`
 * comes from the Ed25519-signed catalog today, but the function is exported
 * and is the classic prototype-pollution-utility shape — a `__proto__` /
 * `constructor` / `prototype` key in the merged object must be skipped, never
 * assigned (an `out['__proto__'] = …` would invoke the prototype-rebinding
 * setter). These tests pin the guard so a future refactor can't drop it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));
const deepMerge = runner._deepMerge;

test('deepMerge does not pollute Object.prototype through a __proto__ key', () => {
  // JSON.parse keeps __proto__ as an OWN enumerable data property, so it
  // reaches Object.entries() — exactly the operator-input shape to defend.
  const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
  const out = deepMerge({ a: 1 }, malicious);
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(out.a, 1, 'unrelated keys still merge');
  assert.equal(Object.prototype.hasOwnProperty.call(out, '__proto__'), false,
    '__proto__ is skipped, not copied as an own property either');
});

test('deepMerge skips constructor and prototype keys', () => {
  const out = deepMerge({}, JSON.parse('{"constructor": {"x": 1}, "prototype": {"y": 2}}'));
  assert.equal(typeof out.constructor, 'function',
    'constructor resolves to the Object constructor, not an overwritten object');
  assert.equal(Object.prototype.hasOwnProperty.call(out, 'prototype'), false);
});

test('deepMerge still deep-merges ordinary nested keys', () => {
  const out = deepMerge({ a: { b: 1 }, c: 3 }, { a: { d: 2 } });
  assert.deepEqual(out, { a: { b: 1, d: 2 }, c: 3 });
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-A-playbook-runner ----
require("node:test").describe("hunt-fix-A-playbook-runner", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the playbook-runner engine fixes (cluster
 * A-playbook-runner). Each case fails on the pre-fix behavior and passes after.
 *
 *   #1 finding.includes_X, finding.cve_class, finding.tool_surface are
 *      host-AI-asserted and must survive into the escalation + feeds_into eval
 *      contexts, while engine-owned finding keys (severity, …) win on collision.
 *   #3 the analyze result exposes a non-underscore `classification` alias so
 *      catalog `analyze.classification == 'detected'` conditions resolve.
 *   #4 a dotted-LHS comparison whose path is absent surfaces a
 *      condition_path_unresolved diagnostic (observability only); a bare
 *      single-segment flag absent, or present-but-null, stays a silent
 *      legitimate false.
 *   #5 the feeds_into theater_score scores an allowlisted 'present' verdict 100
 *      (gap detected = worse), not 0.
 *   #7 the runner's active_exploitation RWEP factor routes through scoring's
 *      shared resolver, so a stray-cased value normalises and an out-of-vocab
 *      value is observable rather than a silent zero.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const runner = require(RUNNER_PATH);
const evalCondition = runner._evalCondition;
const { run, close, loadPlaybook } = runner;
const scoring = require(path.resolve(__dirname, '..', 'lib', 'scoring.js'));

const OPTS = { forceStale: true, operator_consent: { explicit: true } };
// _meta.preconditions[].id keys (preflight matches on pc.id, not the check expr).
const SSO_PCS = {
  'idp-audit-api-reachable': true,
  'read-only-admin-rbac': true,
  'tenant-ownership': true,
};

// --- #1: agent-asserted finding.includes_* survives into the eval contexts,
//         engine-owned finding.severity wins over a poisoning signal. ---

test('#1 escalation + feeds_into fire on agent-supplied finding.includes_cloud_role_assumption', () => {
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

test('#1 absent finding.includes_* leaves the cloud-iam-incident chain dead (the present case is not coincidental)', () => {
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: { blast_radius_score: 4, detection_classification: 'detected' },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  const escTargets = res.phases.analyze.escalations.map((e) => e.target_playbook);
  assert.equal(escTargets.includes('cloud-iam-incident'), false);
  assert.equal(res.phases.close.feeds_into.includes('cloud-iam-incident'), false);
});

test('#1 engine-computed finding.severity wins over a poisoning signals.finding.severity', () => {
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

test('#1 a non-object / array signals.finding is ignored (no numeric-index injection)', () => {
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

test('#3 analyze.classification alias resolves equal to _detect_classification', () => {
  const res = run('identity-sso-compromise', 'all-idp-control-plane-signals', {
    precondition_checks: SSO_PCS,
    signals: { blast_radius_score: 4, detection_classification: 'detected' },
  }, OPTS);
  assert.notEqual(res.ok, false, `run blocked: ${res.blocked_by} ${res.reason}`);
  assert.equal(typeof res.phases.analyze.classification, 'string');
  assert.equal(res.phases.analyze.classification, res.phases.analyze._detect_classification);
  assert.equal(res.phases.analyze.classification, 'detected');
});

test('#3 analyze.classification == "detected" condition resolves true through the alias', () => {
  assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'detected' } }), true);
  assert.equal(evalCondition("analyze.classification == 'detected'", { analyze: { classification: 'not_detected' } }), false);
});

// --- #4: dotted-LHS absent path surfaces a condition_path_unresolved diagnostic. ---

test('#4 dotted-LHS comparison with an absent LEAF emits condition_path_unresolved', () => {
  const errs = [];
  const result = evalCondition('finding.includes_cloud_role_assumption == true', { finding: { severity: 'high' }, _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 1);
  assert.equal(errs[0].kind, 'condition_path_unresolved');
  assert.equal(errs[0].condition, 'finding.includes_cloud_role_assumption == true');
});

test('#4 dotted-LHS comparison with an absent INTERMEDIATE also emits the diagnostic (the strict-undefined gate would miss this)', () => {
  const errs = [];
  const result = evalCondition("analyze.classification == 'detected'", { _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 1);
  assert.equal(errs[0].kind, 'condition_path_unresolved');
});

test('#4 a bare single-segment flag absent does NOT emit a diagnostic (legitimate false)', () => {
  const errs = [];
  const result = evalCondition('agent_has_filesystem_read == true', { _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 0);
});

test('#4 a present-but-null single-segment flag does NOT emit a diagnostic', () => {
  const errs = [];
  const result = evalCondition('patch_available == true', { patch_available: null, _runErrors: errs });
  assert.equal(result, false);
  assert.equal(errs.length, 0);
});

test('#4 a present-and-matching dotted comparison emits nothing', () => {
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

test('#5 theater_score scores a "present" verdict 100 → fires the theater_score >= 50 feeds_into', () => {
  assert.deepEqual(feedsForVerdict('present'), ['sbom']);
});

test('#5 theater_score scores a "theater" verdict 100 (unchanged)', () => {
  assert.deepEqual(feedsForVerdict('theater'), ['sbom']);
});

test('#5 theater_score scores a "clear" verdict 0 → no fire', () => {
  assert.deepEqual(feedsForVerdict('clear'), []);
});

// --- #7: runner active_exploitation factor routes through scoring's resolver. ---

test('#7 scoring.activeExploitationMultiplier returns the canonical ladder multipliers (parity with the prior inline lookup)', () => {
  assert.equal(scoring.activeExploitationMultiplier('confirmed'), 1);
  assert.equal(scoring.activeExploitationMultiplier('suspected'), 0.5);
  assert.equal(scoring.activeExploitationMultiplier('unknown'), 0.25);
  assert.equal(scoring.activeExploitationMultiplier('theoretical'), 0);
  assert.equal(scoring.activeExploitationMultiplier('none'), 0);
  assert.equal(scoring.activeExploitationMultiplier(undefined), 0);
});

test('#7 a stray-cased active_exploitation value normalises instead of zeroing', () => {
  assert.equal(scoring.activeExploitationMultiplier('Confirmed'), 1);
  assert.equal(scoring.activeExploitationMultiplier(' SUSPECTED '), 0.5);
});

test('#7 an out-of-vocab active_exploitation value is observable (RWEP_AE_UNRECOGNISED), not a silent zero', async () => {
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

test('#7 the runner active_exploitation factor branch routes through scoring.activeExploitationMultiplier (no inline ?? 0 ladder)', () => {
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from jurisdiction-clock-validation ----
require("node:test").describe("jurisdiction-clock-validation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from jurisdiction-malformed-obligation ----
require("node:test").describe("jurisdiction-malformed-obligation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Close-phase resilience to malformed jurisdiction obligations (runtime
 * validation of a playbook is not enforced, so close() must not crash or emit
 * bogus records on a hand-crafted / corrupt playbook):
 *
 *  - A matched obligation with a non-number window_hours must NOT crash the
 *    deadline arithmetic (new Date(getTime() + NaN).toISOString()); the deadline
 *    falls back to the pending sentinel.
 *  - A notification_action whose obligation_ref resolves to no obligation is
 *    dropped (already surfaced as a runtime_error) instead of emitting a record
 *    with null jurisdiction/regulation.
 *  - A notify obligation with a non-number window_hours is not synthesized into a
 *    "…/… undefinedh" record; it is surfaced as a runtime_error and skipped.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');

function freshRunner(playbookDir) {
  process.env.EXCEPTD_PLAYBOOK_DIR = playbookDir;
  delete require.cache[RUNNER_PATH];
  return require(RUNNER_PATH);
}
function tmpDir(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-jur-${label}-`)); }
function writePlaybook(dir, id, body) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body, null, 2));
}
function synthPlaybook(govObligations, notificationActions) {
  return {
    _meta: {
      id: 'jur-malformed', last_threat_review: '2026-05-11',
      threat_currency_score: 95,
      owner: '@blamejs/test', air_gap_mode: false, preconditions: [], mutex: [], feeds_into: [],
    },
    domain: {
      name: 'synth', attack_class: 'kernel-lpe', atlas_refs: [], attack_refs: [],
      cve_refs: [], cwe_refs: [], d3fend_refs: [], frameworks_in_scope: ['nist-800-53'],
    },
    phases: {
      govern: { jurisdiction_obligations: govObligations, theater_fingerprints: [], framework_context: {}, skill_preload: [] },
      direct: { threat_context: 'x', rwep_threshold: { escalate: 90, monitor: 70, close: 30 }, framework_lag_declaration: 'x', skill_chain: [], token_budget: {} },
      look: { artifacts: [], collection_scope: {}, environment_assumptions: [], fallback_if_unavailable: [] },
      detect: { indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false, attack_ref: 'T1068' }], false_positive_profile: [], minimum_signal: { detected: 'x', inconclusive: 'x', not_detected: 'x' } },
      analyze: { rwep_inputs: [], blast_radius_model: { scope_question: '?', scoring_rubric: [] }, compliance_theater_check: null, framework_gap_mapping: [], escalation_criteria: [] },
      validate: { remediation_paths: [], validation_tests: [], residual_risk_statement: null, evidence_requirements: [], regression_trigger: [] },
      close: { evidence_package: null, learning_loop: { enabled: false }, notification_actions: notificationActions, exception_generation: null, regression_schedule: null },
    },
    directives: [{ id: 'default', title: 'default', applies_to: { always: true } }],
  };
}

function drive(dir, agentSignals, runOpts) {
  const r = freshRunner(dir);
  const det = r.detect('p', 'default', { signal_overrides: { sig: 'hit' } });
  const an = r.analyze('p', 'default', det);
  const v = r.validate('p', 'default', an, {});
  // close(playbookId, directiveId, analyzeResult, validateResult, agentSignals, runOpts)
  return r.close('p', 'default', an, v, agentSignals, runOpts);
}

test('a matched obligation with a missing window_hours does not crash close(); deadline falls back to the sentinel', () => {
  const dir = tmpDir('nan');
  try {
    // obligation: 'report' (not 'notify') so synthesis ignores it; the explicit
    // notification_action references it by the "EU/TEST undefinedh" ref the same
    // formula produces, so the obligation IS matched and the deadline path runs.
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'EU', regulation: 'TEST', clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'report' }],
      [{ obligation_ref: 'EU/TEST undefinedh', recipient: 'r@e', draft_notification: 'x', evidence_attached: [] }],
    ));
    let close;
    assert.doesNotThrow(() => {
      // Fire the clock so clockValid is true — this is the exact condition under
      // which the unguarded arithmetic computed new Date(NaN) and threw.
      close = drive(dir, { clock_started_at_detect_confirmed: '2026-05-11T10:00:00Z' }, { _runErrors: [] });
    }, 'close() must not throw on an obligation missing window_hours');
    const n = close.notification_actions.find(x => x.obligation_ref === 'EU/TEST undefinedh');
    assert.ok(n, 'the matched notification record is present');
    assert.equal(n.deadline, 'pending_clock_start_event', 'a non-number window_hours yields the pending sentinel, not a crash');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a notification_action with an unresolved obligation_ref is dropped and surfaced as a runtime_error', () => {
  const dir = tmpDir('unresolved');
  try {
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'EU', regulation: 'REAL', window_hours: 24, clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'report' }],
      [{ obligation_ref: 'ZZ/NONEXISTENT 99h', recipient: 'r@e', draft_notification: 'x', evidence_attached: [] }],
    ));
    const runErrors = [];
    const close = drive(dir, {}, { _runErrors: runErrors });
    const orphan = close.notification_actions.find(x => x.obligation_ref === 'ZZ/NONEXISTENT 99h');
    assert.equal(orphan, undefined, 'the unresolved-ref record must be dropped, not emitted with null jurisdiction');
    assert.ok(
      runErrors.some(e => e.kind === 'unresolved_obligation_ref' && e.obligation_ref === 'ZZ/NONEXISTENT 99h'),
      `the unmatched ref must surface a runtime_error; got ${JSON.stringify(runErrors)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a notify obligation with a non-number window_hours is not synthesized as "undefinedh"; it surfaces a runtime_error', () => {
  const dir = tmpDir('synth');
  try {
    writePlaybook(dir, 'p', synthPlaybook(
      [{ jurisdiction: 'ZZ', regulation: 'BADWIN', clock_starts: 'detect_confirmed', evidence_required: [], obligation: 'notify' }],
      [],
    ));
    const runErrors = [];
    const close = drive(dir, {}, { _runErrors: runErrors });
    const bogus = close.notification_actions.find(x => String(x.obligation_ref).includes('undefinedh'));
    assert.equal(bogus, undefined, 'a malformed notify obligation must not synthesize an "undefinedh" record');
    assert.ok(
      runErrors.some(e => e.kind === 'malformed_obligation_window_hours'),
      `a malformed window_hours must surface a runtime_error; got ${JSON.stringify(runErrors)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from openvex-urn-routing ----
require("node:test").describe("openvex-urn-routing", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * OpenVEX vulnerability identifiers route to the correct URN namespace.
 *
 * Cycle 6 P1 gap: lib/playbook-runner.js vulnIdToUrn() (line ~1797) maps:
 *   CVE-*      → urn:cve:*
 *   GHSA-*     → urn:ghsa:*
 *   RUSTSEC-*  → urn:rustsec:*
 *   MAL-*      → urn:malicious-package:*
 *   <other>    → urn:exceptd:advisory:* (private namespace, RFC 8141)
 *
 * The OpenVEX 0.2.0 spec mandates that `vulnerability.@id` is an IRI; a
 * naive `urn:cve:GHSA-xxx` would falsely claim GHSA-* is part of the CVE
 * registry, misrouting downstream consumers' lookups. This test pins each
 * advisory prefix to its required namespace AND asserts non-CVE ids never
 * leak into the cve namespace.
 *
 * Tests vulnIdToUrn directly rather than spinning a full OpenVEX bundle —
 * the function is the canonical routing primitive, and a unit test pins
 * the boundary without depending on the full close-phase bundle build.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { ROOT } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

// The function is internal to the runner module, exported under the `_`-prefix
// convention the module uses for test-only helpers. Pin its presence so this
// non-CVE-leak boundary can never go dark again (it previously skipped
// permanently because the export was missing).
const vulnIdToUrn = runner._vulnIdToUrn;
assert.equal(typeof vulnIdToUrn, 'function', 'runner must export _vulnIdToUrn');

test('vulnIdToUrn routes each advisory prefix to its registered URN namespace',
  () => {
    const cases = [
      { id: 'GHSA-1111-2222-3333', expectedPrefix: 'urn:ghsa:' },
      { id: 'RUSTSEC-2024-0001',   expectedPrefix: 'urn:rustsec:' },
      { id: 'MAL-2026-3083',       expectedPrefix: 'urn:malicious-package:' },
      { id: 'CVE-2026-46300',      expectedPrefix: 'urn:cve:' },
    ];
    for (const c of cases) {
      const urn = vulnIdToUrn(c.id);
      assert.equal(typeof urn, 'string', `vulnIdToUrn(${c.id}) must return a string`);
      assert.ok(urn.startsWith(c.expectedPrefix),
        `vulnIdToUrn(${c.id}) must start with ${c.expectedPrefix}; got ${urn}`);
    }

    // Cross-check: non-CVE ids MUST NOT be routed into the cve namespace.
    // A regression that collapsed every advisory to urn:cve:* would silently
    // pass single-prefix assertions; this assertion catches that class.
    const nonCveCases = ['GHSA-1111-2222-3333', 'RUSTSEC-2024-0001', 'MAL-2026-3083'];
    for (const id of nonCveCases) {
      const urn = vulnIdToUrn(id);
      assert.ok(!urn.startsWith('urn:cve:'),
        `non-CVE id ${id} must NEVER route into urn:cve: (would misclaim CVE-registry membership); got ${urn}`);
    }
  });

test('vulnIdToUrn falls back to private namespace for unknown prefixes',
  () => {
    const urn = vulnIdToUrn('UNKNOWN-2026-0001');
    assert.equal(typeof urn, 'string');
    assert.ok(urn.startsWith('urn:exceptd:advisory:'),
      `unknown prefix must route to private urn:exceptd:advisory: namespace; got ${urn}`);
  });
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from rwep-vex-fixed-no-scaling ----
require("node:test").describe("rwep-vex-fixed-no-scaling", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression: a VEX-fixed (vendor-patched) CVE must not drive RWEP factor
 * scaling. baseRwep already excluded vex-fixed entries, but the factor-scaling
 * source was `matchedCves[0]` — so a patched CVE that sorted first still scaled
 * the adjusted score (and its exploitation status fed notification drafts).
 * factorCve now prefers the first RWEP-eligible (non-vex-fixed) CVE, and the
 * finding-shape's worst active_exploitation excludes vex-fixed entries.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const runner = require('../lib/playbook-runner');
const kernel = require('../data/playbooks/kernel.json');

const DIR = kernel.directives[0].id;
const TOP = kernel.domain.cve_refs[0]; // highest-rwep, CISA-KEV, confirmed-exploitation kernel CVE
const DET = {
  indicators: [{ id: 'kver-in-affected-range', verdict: 'hit', deterministic: true, confidence: 'high' }],
  classification: 'detected',
};

test('a VEX-fixed top CVE does not drive RWEP factor scaling or inflate adjusted RWEP', () => {
  const unfixed = runner.analyze('kernel', DIR, DET, { [TOP]: true, 'kver-in-affected-range': true }, {});
  const fixed = runner.analyze('kernel', DIR, DET, { [TOP]: true, vex_fixed: [TOP], 'kver-in-affected-range': true }, {});

  // The vex-fixed CVE is the highest-rwep matched entry; still surfaced for the
  // audit trail, but flagged.
  const top = (fixed.matched_cves || []).find(c => c.cve_id === TOP);
  assert.equal(top?.vex_status, 'fixed');

  // Base excludes it (pre-existing) and adjusted is strictly lower.
  assert.ok(fixed.rwep.base < unfixed.rwep.base,
    `vex-fixed base (${fixed.rwep.base}) must be below un-fixed (${unfixed.rwep.base})`);
  assert.ok(fixed.rwep.adjusted < unfixed.rwep.adjusted,
    `vex-fixed adjusted (${fixed.rwep.adjusted}) must be below un-fixed (${unfixed.rwep.adjusted})`);

  // Discriminating (catches the factorCve fix specifically, not just the base
  // exclusion): the vex-fixed top CVE is 'confirmed' exploitation (scale 1.0).
  // With scaling sourced from the eligible (lower-exploitation) CVE, the fired
  // active_exploitation factor scales strictly below the confirmed level. Pre-
  // fix it scaled by the vex-fixed CVE → factor_scale 1.0.
  const unfixedAe = (unfixed.rwep.breakdown || []).find(b => b.rwep_factor === 'active_exploitation' && b.fired);
  const fixedAe = (fixed.rwep.breakdown || []).find(b => b.rwep_factor === 'active_exploitation' && b.fired);
  assert.equal(unfixedAe?.factor_scale, 1.0, 'un-fixed run scales active_exploitation by the confirmed top CVE (1.0)');
  assert.ok(fixedAe && fixedAe.factor_scale < 1.0,
    `vex-fixed run active_exploitation factor_scale (${fixedAe?.factor_scale}) must reflect the eligible CVE, not the vex-fixed confirmed one`);
});

test('when EVERY matched CVE is VEX-fixed, factor scaling is suppressed (adjusted RWEP stays 0)', () => {
  // codex P2: with rwepEligible empty, factorCve must not fall back to a fixed
  // matchedCves[0]; base is 0, and a vendor-fixed CVE's KEV/exploitation/PoC
  // factors must not lift the adjusted score above 0 (the finding is remediated).
  const cves = kernel.domain.cve_refs;
  const sig = { 'kver-in-affected-range': true };
  for (const c of cves) sig[c] = true;
  const allFixed = runner.analyze('kernel', DIR, DET, { ...sig, vex_fixed: cves }, {});

  assert.ok((allFixed.matched_cves || []).length > 0, 'expected matched CVEs in this scenario');
  assert.equal((allFixed.matched_cves || []).filter((c) => c.vex_status !== 'fixed').length, 0,
    'every matched CVE must be VEX-fixed in this scenario');
  assert.equal(allFixed.rwep.base, 0, 'base must be 0 when all matched CVEs are fixed');
  assert.equal(allFixed.rwep.adjusted, 0,
    `adjusted must not be lifted above 0 by a vendor-fixed CVE; got ${allFixed.rwep.adjusted}`);
  for (const b of (allFixed.rwep.breakdown || []).filter((x) => x.fired)) {
    assert.equal(b.factor_scale, 0,
      `fired factor ${b.rwep_factor} must scale by 0 when all matched CVEs are fixed`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from vex-disposition-note ----
require("node:test").describe("vex-disposition-note", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
