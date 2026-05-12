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

  it('empty submission → classification=inconclusive', () => {
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    assert.equal(det.classification, 'inconclusive');
    assert.equal(det.indicators.length, 5);
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

  it('matched_cves resolved from domain.cve_refs via cross-ref-api', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    const ids = an.matched_cves.map(c => c.cve_id);
    assert.ok(ids.includes('CVE-2026-31431'));
    assert.equal(an.matched_cves.length, 3, 'all three catalogued kernel CVEs matched');
  });

  it('RWEP base is max of matched cve rwep scores (Copy Fail = 90)', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.rwep.base, 90);
  });

  it('rwep_inputs only apply weight when the signal fired', () => {
    // No detect hits, no agentSignals → adjusted == base (no weights applied)
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const anQuiet = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(anQuiet.rwep.adjusted, anQuiet.rwep.base);
    assert.ok(anQuiet.rwep.breakdown.every(b => b.fired === false && b.weight_applied === 0));

    // Now: kver-in-affected-range hit. Adjusted = 90 + 25+20+15+10-10 = 150 → clamped to 100.
    const detHit = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const anHit = runner.analyze('kernel', 'all-catalogued-kernel-cves', detHit);
    assert.equal(anHit.rwep.adjusted, 100, 'adjusted RWEP clamped to 100');
    const fired = anHit.rwep.breakdown.filter(b => b.fired);
    assert.ok(fired.length >= 5, 'kver-in-affected-range fires for all its rwep_inputs entries');
  });

  it('blast_radius_score comes from agentSignals when supplied; otherwise rubric default', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an1 = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an1.blast_radius_score, 1, 'default to first rubric entry (score=1)');

    const an2 = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { blast_radius_score: 4 });
    assert.equal(an2.blast_radius_score, 4);
    assert.ok(an2.blast_radius_basis, 'basis populated from rubric for score=4');
    assert.equal(an2.blast_radius_basis.blast_radius_score, 4);
  });

  it('theater_verdict propagates from agentSignals into compliance_theater_check', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, { theater_verdict: 'theater' });
    assert.equal(an.compliance_theater_check.verdict, 'theater');
    assert.ok(an.compliance_theater_check.verdict_text, 'verdict_text populated when verdict=theater');
  });

  it('compliance_theater_check defaults to pending_agent_run when no verdict supplied', () => {
    const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {});
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes);
    assert.equal(an.compliance_theater_check.verdict, 'pending_agent_run');
    assert.equal(an.compliance_theater_check.verdict_text, null);
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

  it('draft_notification interpolates ${matched_cve_ids} / ${kev_listed_count}', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, { affected_host_count: 17 });
    const nis2 = c.notification_actions.find(n => n.obligation_ref === 'EU/NIS2 Art.23 24h');
    assert.match(nis2.draft_notification, /CVE-2026-31431/);
    assert.match(nis2.draft_notification, /17 host/);
    // KEV count = at least 1 (CVE-2026-31431 is KEV-listed)
    assert.match(nis2.draft_notification, /KEV-listed: [1-9]/);
  });

  it('${} placeholders are left intact when context lacks the value', () => {
    const { an, v } = detected();
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      // matched_cve_ids will populate, but interim_mitigation / ict_dependencies / affected_host_count are missing
    });
    const nis2 = c.notification_actions.find(n => n.obligation_ref === 'EU/NIS2 Art.23 24h');
    // Untouched placeholders survive
    assert.match(nis2.draft_notification, /\$\{interim_mitigation\}/);
    assert.match(nis2.draft_notification, /\$\{affected_host_count\}/);
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
      const detRes = local.detect('p', 'default', {});
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
    assert.equal(result.phases.analyze.matched_cves.length, 3);
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

  it('leaves ${...} intact when context lacks the value', () => {
    assert.equal(runner._interpolate('Hello ${name}', {}), 'Hello ${name}');
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
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-31431'] },
      phases: { analyze: { rwep_inputs: [] } }
    }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', {});
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

  it('matched_cves empty when domain.cve_refs is empty', () => {
    writePlaybook(dir, 'p', synthPlaybook({ domain: { cve_refs: [] } }));
    const runner = freshRunner(dir);
    const detRes = runner.detect('p', 'default', {});
    const an = runner.analyze('p', 'default', detRes);
    assert.deepEqual(an.matched_cves, []);
    assert.equal(an.rwep.base, 0);
    assert.equal(an.rwep.adjusted, 0);
  });

  it('rwep is floor-clamped at 0 when negative weights drive it below', () => {
    writePlaybook(dir, 'p', synthPlaybook({
      domain: { cve_refs: ['CVE-2026-43500'] }, // base rwep 32
      phases: {
        detect: {
          indicators: [{ id: 'sig', type: 'log_pattern', value: 'x', description: 'd', confidence: 'high', deterministic: false }]
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
