'use strict';

/**
 * Playbook runner — executes the seven-phase investigation contract defined in
 * lib/schemas/playbook.schema.json:
 *
 *   1. govern    exceptd. Loads GRC context: jurisdiction obligations, theater
 *                fingerprints, framework gaps, skills to preload. Sets the
 *                compliance lens before any investigation runs.
 *   2. direct    exceptd. Scopes the investigation: threat context with current
 *                CVE/TTP citations, RWEP thresholds, framework lag declaration,
 *                skill chain, token budget.
 *   3. look      host AI. Collects typed artifacts (logs/files/processes/
 *                network/etc.) per artifact spec, with air-gap fallbacks.
 *   4. detect    host AI. Evaluates artifacts against typed indicators, applies
 *                false-positive profile, classifies as detected | inconclusive
 *                | not_detected.
 *   5. analyze   exceptd. Computes RWEP from rwep_inputs, scores blast radius,
 *                runs compliance_theater_check, generates framework_gap_mapping
 *                entries, fires escalation_criteria.
 *   6. validate  exceptd. Picks remediation_path by priority + preconditions,
 *                emits validation_tests, renders residual_risk_statement, lists
 *                evidence_requirements, computes regression schedule.
 *   7. close     exceptd. Closes the GRC loop: assembles evidence_package
 *                (signed by default), drafts learning_loop lesson, computes
 *                notification_actions deadlines from govern.jurisdiction_obligations
 *                clock_starts + window_hours, evaluates exception_generation
 *                trigger and renders auditor-ready language, finalizes
 *                regression_schedule.next_run.
 *
 * Currency gate: _meta.threat_currency_score < 50 hard-blocks execution unless
 * the caller passes { forceStale: true }. Below 70 warns. The schema declares
 * the score; the runner enforces.
 *
 * Preconditions: each _meta.preconditions entry has on_fail = halt|warn|skip_phase.
 * Engine evaluates the (host AI-supplied) check value and reacts accordingly.
 *
 * Mutex: an in-process Set tracks active playbook runs. Engine refuses to start
 * a playbook whose _meta.mutex intersects active runs.
 *
 * feeds_into: close() returns a list of downstream playbook IDs whose
 * conditions are satisfied by this run's finding — the agent decides whether
 * to chain into them.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const xref = require('./cross-ref-api');

const ROOT = path.join(__dirname, '..');
const PLAYBOOK_DIR = process.env.EXCEPTD_PLAYBOOK_DIR || path.join(ROOT, 'data', 'playbooks');

// In-process mutex tracker. Survives only the current Node process.
// Persistent cross-process coordination is out of scope — that's for the GRC
// platform integration, not the runner.
const _activeRuns = new Set();

// --- catalog access ---

function listPlaybooks() {
  if (!fs.existsSync(PLAYBOOK_DIR)) return [];
  return fs.readdirSync(PLAYBOOK_DIR)
    .filter(f => f.endsWith('.json') && !f.startsWith('_'))
    .map(f => f.replace(/\.json$/, ''));
}

function loadPlaybook(playbookId) {
  const p = path.join(PLAYBOOK_DIR, `${playbookId}.json`);
  if (!fs.existsSync(p)) throw new Error(`Playbook not found: ${playbookId} (expected ${p})`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function findDirective(playbook, directiveId) {
  const d = playbook.directives.find(x => x.id === directiveId);
  if (!d) throw new Error(`Directive not found: ${directiveId} in playbook ${playbook._meta.id}`);
  return d;
}

// --- phase-resolution: merge playbook.phases with directive.phase_overrides ---

function resolvedPhase(playbook, directiveId, phaseName) {
  const base = playbook.phases[phaseName] || {};
  const directive = playbook.directives.find(x => x.id === directiveId);
  const override = directive?.phase_overrides?.[phaseName];
  if (!override) return base;
  return deepMerge(base, override);
}

function deepMerge(a, b) {
  if (b === null || b === undefined) return a;
  if (typeof b !== 'object' || Array.isArray(b)) return b;
  const out = { ...a };
  for (const [k, v] of Object.entries(b)) {
    out[k] = (k in out) ? deepMerge(out[k], v) : v;
  }
  return out;
}

// --- pre-flight: currency + preconditions + mutex ---

function preflight(playbook, runOpts = {}) {
  const issues = [];
  const meta = playbook._meta;

  // 1. Currency gate
  const score = meta.threat_currency_score;
  if (score < 50 && !runOpts.forceStale) {
    return {
      ok: false,
      blocked_by: 'currency',
      reason: `threat_currency_score = ${score} (< 50). Hard-blocked. Pass forceStale=true to override.`,
      issues
    };
  }
  if (score < 70) {
    issues.push({ kind: 'currency_warn', message: `threat_currency_score = ${score} (< 70). Threat model is stale — recommend running the skill-update-loop before relying on findings.` });
  }

  // 2. Preconditions
  for (const pc of meta.preconditions || []) {
    const submitted = runOpts.precondition_checks?.[pc.id];
    if (submitted === undefined) {
      const submission_hint = `Submit precondition_checks in your evidence JSON, e.g. { "precondition_checks": { "${pc.id}": true } }. The runner lifts this into runOpts before the gate evaluates.`;
      issues.push({ kind: 'precondition_unverified', id: pc.id, check: pc.check, on_fail: pc.on_fail, submission_hint });
      if (pc.on_fail === 'halt') {
        return {
          ok: false,
          blocked_by: 'precondition',
          reason: `Precondition ${pc.id} (${pc.check}) not verified by host AI; on_fail=halt.`,
          remediation: submission_hint,
          issues
        };
      }
      continue;
    }
    if (submitted === false) {
      if (pc.on_fail === 'halt') {
        return { ok: false, blocked_by: 'precondition', reason: `Precondition ${pc.id} failed: ${pc.description}`, issues };
      }
      issues.push({ kind: pc.on_fail === 'skip_phase' ? 'precondition_skip' : 'precondition_warn', id: pc.id, message: pc.description });
    }
  }

  // 3. Mutex — both intra-process (in-memory Set) AND cross-process
  // (filesystem lockfile under .exceptd/locks/<playbook>.lock). v0.11.0 only
  // enforced intra-process; v0.11.1 adds cross-process so two parallel CLI
  // invocations of mutex-conflicting playbooks correctly race-detect.
  for (const conflictId of meta.mutex || []) {
    if (_activeRuns.has(conflictId)) {
      return { ok: false, blocked_by: 'mutex', reason: `Mutex conflict (intra-process): playbook ${conflictId} is currently active and listed in this playbook's mutex set.`, issues };
    }
    const lockPath = lockFilePath(conflictId);
    if (lockPath && fs.existsSync(lockPath)) {
      // Stale-lock detection: if the recorded PID is dead, ignore the lock.
      try {
        const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        if (lock.pid && !pidAlive(lock.pid)) {
          fs.unlinkSync(lockPath); // GC stale
        } else {
          return {
            ok: false,
            blocked_by: 'mutex',
            reason: `Mutex conflict (cross-process): playbook ${conflictId} has an active lock at ${lockPath} (pid ${lock.pid}, started ${lock.started_at}).`,
            issues,
          };
        }
      } catch { /* malformed lockfile — treat as stale and remove */
        try { fs.unlinkSync(lockPath); } catch {}
      }
    }
  }

  return { ok: true, issues };
}

function lockDir() {
  const dir = path.join(process.cwd(), '.exceptd', 'locks');
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  return dir;
}

function lockFilePath(playbookId) {
  try { return path.join(lockDir(), `${playbookId}.lock`); }
  catch { return null; }
}

function acquireLock(playbookId) {
  const p = lockFilePath(playbookId);
  if (!p) return null;
  try {
    fs.writeFileSync(p, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2), { flag: 'wx' });
    return p;
  } catch { return null; /* already locked or unwritable */ }
}

function releaseLock(lockPath) {
  if (!lockPath) return;
  try { fs.unlinkSync(lockPath); } catch {}
}

function pidAlive(pid) {
  if (typeof pid !== 'number') return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code !== 'ESRCH'; }
}

// --- phase 1: govern ---

/**
 * Load GRC context for the agent. Returns jurisdiction obligations (with
 * window_hours + clock_starts so close() can compute deadlines later), theater
 * fingerprints, framework gap summary, and skills to preload.
 */
function govern(playbookId, directiveId, runOpts = {}) {
  const playbook = loadPlaybook(playbookId);
  const g = resolvedPhase(playbook, directiveId, 'govern');
  return {
    phase: 'govern',
    playbook_id: playbookId,
    directive_id: directiveId,
    domain: playbook.domain,
    threat_currency_score: playbook._meta.threat_currency_score,
    last_threat_review: playbook._meta.last_threat_review,
    air_gap_mode: !!playbook._meta.air_gap_mode || !!runOpts.airGap,
    jurisdiction_obligations: g.jurisdiction_obligations || [],
    theater_fingerprints: g.theater_fingerprints || [],
    framework_context: g.framework_context || {},
    skill_preload: g.skill_preload || []
  };
}

// --- phase 2: direct ---

function direct(playbookId, directiveId) {
  const playbook = loadPlaybook(playbookId);
  const d = resolvedPhase(playbook, directiveId, 'direct');
  return {
    phase: 'direct',
    playbook_id: playbookId,
    directive_id: directiveId,
    threat_context: d.threat_context,
    rwep_threshold: d.rwep_threshold,
    framework_lag_declaration: d.framework_lag_declaration,
    skill_chain: d.skill_chain || [],
    token_budget: d.token_budget || {}
  };
}

// --- phase 3: look (engine emits, agent executes) ---

function look(playbookId, directiveId, runOpts = {}) {
  const playbook = loadPlaybook(playbookId);
  const l = resolvedPhase(playbook, directiveId, 'look');
  const airGap = !!playbook._meta.air_gap_mode || !!runOpts.airGap;
  return {
    phase: 'look',
    playbook_id: playbookId,
    directive_id: directiveId,
    air_gap_mode: airGap,
    // Preconditions are surfaced here so the host AI can verify them with its
    // own probes (Bash:test -f /proc/version, etc.) and declare the results
    // back through submission.precondition_checks. Without this list, the AI
    // is blind to the gate and run() will halt with a precondition_unverified
    // failure the AI can't diagnose. See AGENTS.md Hard Rule context.
    preconditions: (playbook._meta.preconditions || []).map(pc => ({
      id: pc.id,
      description: pc.description,
      check: pc.check,
      on_fail: pc.on_fail
    })),
    precondition_submission_shape: {
      hint: 'Include precondition_checks: { "<precondition-id>": true|false } in your submission JSON. The runner lifts it into runOpts before evaluating the gate.',
      example: { precondition_checks: { 'linux-platform': true, 'uname-available': true } }
    },
    artifacts: (l.artifacts || []).map(a => ({
      ...a,
      // Surface the air-gap alternative as the primary source when air_gap_mode
      // is active, so the agent doesn't accidentally hit the network.
      source: airGap && a.air_gap_alternative ? a.air_gap_alternative : a.source,
      _original_source: a.source
    })),
    collection_scope: l.collection_scope,
    environment_assumptions: l.environment_assumptions || [],
    fallback_if_unavailable: l.fallback_if_unavailable || []
  };
}

// --- phase 4: detect ---

/**
 * Evaluate artifacts the agent submitted against the playbook's typed
 * indicators. Returns a per-indicator hit/miss/inconclusive verdict plus a
 * minimum_signal classification (detected | inconclusive | not_detected).
 *
 * The agent submits `artifacts` as { artifact_id: { value, captured: true|false, reason? } }
 * and (optionally) `signal_overrides` as { indicator_id: 'hit'|'miss'|'inconclusive' } to
 * record an indicator outcome the agent computed using its own pattern matching.
 */
function detect(playbookId, directiveId, agentSubmission = {}) {
  const playbook = loadPlaybook(playbookId);
  const det = resolvedPhase(playbook, directiveId, 'detect');
  const artifacts = agentSubmission.artifacts || {};
  const overrides = agentSubmission.signal_overrides || {};

  const indicatorResults = (det.indicators || []).map(ind => {
    const override = overrides[ind.id];
    let verdict;
    if (override === 'hit' || override === 'miss' || override === 'inconclusive') {
      verdict = override;
    } else {
      // Without an explicit override, treat any captured artifact as evidence
      // the indicator could be evaluated. Mark inconclusive if no related
      // artifact was captured — engine doesn't pattern-match raw artifact
      // content; the host AI is responsible for that.
      const anyCaptured = Object.values(artifacts).some(a => a && a.captured);
      verdict = anyCaptured ? 'inconclusive' : 'inconclusive';
    }
    return {
      id: ind.id, type: ind.type, confidence: ind.confidence,
      deterministic: ind.deterministic, atlas_ref: ind.atlas_ref || null,
      attack_ref: ind.attack_ref || null, verdict
    };
  });

  // false-positive profile — engine highlights which FP tests the agent
  // should still run against any indicator the agent reported as 'hit'.
  const fpChecksRequired = (det.false_positive_profile || []).filter(fp =>
    indicatorResults.find(r => r.id === fp.indicator_id && r.verdict === 'hit')
  );

  const hits = indicatorResults.filter(r => r.verdict === 'hit');
  const hasDeterministicHit = hits.some(r => r.deterministic);
  const hasHighConfHit = hits.some(r => r.confidence === 'high' || r.confidence === 'deterministic');

  // Agent override: if signals.detection_classification is explicitly set to
  // one of the four legal values, honor it. Engine computes its own
  // classification as a fallback. Use the override when the agent has run the
  // full false_positive_profile checks and reached an explicit verdict —
  // engine-computed classification can't represent "I saw the indicators and
  // confirmed they're all benign" without this override.
  const override = (agentSubmission.signals && agentSubmission.signals.detection_classification);
  const validOverrides = new Set(['detected', 'inconclusive', 'not_detected', 'clean']);

  let classification;
  if (override && validOverrides.has(override)) {
    classification = override === 'clean' ? 'not_detected' : override;
  } else if (hasDeterministicHit || hasHighConfHit) {
    classification = 'detected';
  } else if (hits.length === 0 && indicatorResults.every(r => r.verdict === 'miss')) {
    classification = 'not_detected';
  } else {
    classification = 'inconclusive';
  }

  return {
    phase: 'detect',
    playbook_id: playbookId,
    directive_id: directiveId,
    indicators: indicatorResults,
    false_positive_checks_required: fpChecksRequired,
    classification,
    minimum_signal_basis: det.minimum_signal?.[classification === 'detected' ? 'detected' : classification === 'not_detected' ? 'not_detected' : 'inconclusive'],
    // v0.11.3 #71: surface what detect actually consumed. Operators reading
    // the detect output now see whether their flat-shape observations + the
    // signal_overrides + the classification override all reached the runner.
    // Pre-0.11.3 detect's output was opaque — "inconclusive" with no
    // explanation gave operators no signal about what went wrong.
    observations_received: Object.keys(agentSubmission.artifacts || {}),
    signals_received: Object.keys(agentSubmission.signal_overrides || {}),
    indicators_evaluated: indicatorResults.length,
    classification_override_applied: validOverrides.has(override) ? (override === 'clean' ? 'not_detected' : override) : null,
    submission_shape_seen: agentSubmission._original_shape || (agentSubmission.artifacts ? 'nested (v0.10.x)' : 'empty')
  };
}

// --- phase 5: analyze ---

/**
 * RWEP composition + blast-radius scoring + theater check + framework gap
 * mapping + escalation evaluation. Inputs are the detect result + any
 * agent-submitted signal_values (e.g. blast_radius classification).
 */
function analyze(playbookId, directiveId, detectResult, agentSignals = {}) {
  const playbook = loadPlaybook(playbookId);
  const an = resolvedPhase(playbook, directiveId, 'analyze');
  const directive = findDirective(playbook, directiveId);

  // Match catalogued CVEs from the domain.cve_refs list. The agent submits
  // signal values; engine joins to the catalog for RWEP context.
  // VEX filter (agentSignals.vex_filter): a set of CVE IDs the operator
  // has formally declared not_affected via a CycloneDX/OpenVEX statement.
  // We drop those from matched_cves before scoring, and surface them
  // separately so the analyze response still records the disposition.
  const cveRefs = playbook.domain.cve_refs || [];
  const vexFilter = agentSignals.vex_filter instanceof Set ? agentSignals.vex_filter
    : (Array.isArray(agentSignals.vex_filter) ? new Set(agentSignals.vex_filter) : null);
  const allMatches = cveRefs.map(id => xref.byCve(id)).filter(r => r.found);
  const matchedCves = vexFilter
    ? allMatches.filter(c => !vexFilter.has(c.cve_id))
    : allMatches;
  const vexDropped = vexFilter
    ? allMatches.filter(c => vexFilter.has(c.cve_id)).map(c => c.cve_id)
    : [];

  // RWEP composition: start from the catalogue's per-CVE rwep_score (already
  // baked from KEV + PoC + AI-disc + active-exploitation + blast-radius), then
  // adjust by playbook's rwep_inputs based on detect hits + agent signals.
  const baseRwep = matchedCves.length ? Math.max(...matchedCves.map(c => c.rwep_score)) : 0;
  let adjustedRwep = baseRwep;
  const rwepBreakdown = [];
  for (const input of an.rwep_inputs || []) {
    const indicator = detectResult.indicators?.find(i => i.id === input.signal_id);
    const fired = indicator?.verdict === 'hit' || agentSignals[input.signal_id] === true;
    if (fired) {
      adjustedRwep += input.weight;
      rwepBreakdown.push({ signal_id: input.signal_id, rwep_factor: input.rwep_factor, weight_applied: input.weight, fired: true });
    } else {
      rwepBreakdown.push({ signal_id: input.signal_id, rwep_factor: input.rwep_factor, weight_applied: 0, fired: false });
    }
  }
  adjustedRwep = Math.max(0, Math.min(100, adjustedRwep));

  // blast_radius
  const blastRubric = an.blast_radius_model?.scoring_rubric || [];
  const blastRadiusScore = agentSignals.blast_radius_score || (blastRubric[0]?.blast_radius_score ?? null);

  // compliance_theater_check — engine surfaces the test; agent runs it; we
  // accept the verdict in agentSignals.theater_verdict. When agent didn't
  // submit a verdict but the detect phase reached a clear classification,
  // derive one rather than leaving the field stuck in 'pending_agent_run':
  //   detect.classification = not_detected → theater_verdict = clear
  //   detect.classification = detected     → theater_verdict = pending_agent_run
  //                                          (agent still must run reality_test)
  //   detect.classification = inconclusive → theater_verdict = pending_agent_run
  // Aliases 'clean' / 'no_theater' map to 'clear' for ergonomics.
  let theaterVerdict = agentSignals.theater_verdict;
  if (theaterVerdict === 'clean' || theaterVerdict === 'no_theater') theaterVerdict = 'clear';
  if (!theaterVerdict && an.compliance_theater_check) {
    const cls = detectResult.classification;
    theaterVerdict = cls === 'not_detected' ? 'clear' : 'pending_agent_run';
  }
  theaterVerdict = theaterVerdict || (an.compliance_theater_check ? 'pending_agent_run' : null);

  // framework_gap_mapping — engine emits the mapping verbatim; analyze does
  // not compute new gaps here, just attaches the playbook-declared ones.
  const frameworkGaps = an.framework_gap_mapping || [];

  // escalation criteria
  const escalations = [];
  for (const ec of an.escalation_criteria || []) {
    if (evalCondition(ec.condition, { rwep: adjustedRwep, blast_radius_score: blastRadiusScore, theater_verdict: theaterVerdict, ...agentSignals }, playbook)) {
      escalations.push({ condition: ec.condition, action: ec.action, target_playbook: ec.target_playbook || null });
    }
  }

  return {
    phase: 'analyze',
    playbook_id: playbookId,
    directive_id: directiveId,
    // Hard Rule #1 (AGENTS.md): every CVE reference must carry CVSS + KEV +
    // PoC + AI-discovery + active-exploitation + patch/live-patch availability.
    // Pull every required field from the catalog entry; null is only emitted
    // when the catalog itself lacks the value, never when we just forgot to
    // forward it. EPSS is included because validate-cves --live populates it.
    matched_cves: matchedCves.map(c => ({
      cve_id: c.cve_id,
      rwep: c.rwep_score,
      cvss_score: c.entry?.cvss_score ?? null,
      cvss_vector: c.entry?.cvss_vector ?? null,
      cisa_kev: c.cisa_kev,
      cisa_kev_date: c.entry?.cisa_kev_date ?? null,
      cisa_kev_due_date: c.entry?.cisa_kev_due_date ?? null,
      poc_available: c.entry?.poc_available ?? null,
      ai_discovered: c.ai_discovered,
      ai_assisted_weaponization: c.entry?.ai_assisted_weaponization ?? null,
      active_exploitation: c.active_exploitation,
      patch_available: c.entry?.patch_available ?? null,
      patch_required_reboot: c.entry?.patch_required_reboot ?? null,
      live_patch_available: c.entry?.live_patch_available ?? null,
      epss_score: c.entry?.epss_score ?? null,
      epss_date: c.entry?.epss_date ?? null,
      atlas_refs: c.atlas_refs,
      attack_refs: c.attack_refs,
      affected_versions: c.entry?.affected_versions ?? null,
    })),
    rwep: { base: baseRwep, adjusted: adjustedRwep, breakdown: rwepBreakdown, threshold: directive ? resolvedPhase(playbook, directiveId, 'direct').rwep_threshold : null },
    blast_radius_score: blastRadiusScore,
    blast_radius_basis: blastRubric.find(r => r.blast_radius_score === blastRadiusScore) || null,
    compliance_theater_check: {
      claim: an.compliance_theater_check?.claim,
      audit_evidence: an.compliance_theater_check?.audit_evidence,
      reality_test: an.compliance_theater_check?.reality_test,
      verdict: theaterVerdict,
      verdict_text: theaterVerdict === 'theater' ? an.compliance_theater_check?.theater_verdict_if_gap : null
    },
    framework_gap_mapping: frameworkGaps,
    escalations,
    vex: vexFilter ? {
      filter_applied: true,
      dropped_cve_count: vexDropped.length,
      dropped_cves: vexDropped,
      note: vexDropped.length
        ? `${vexDropped.length} CVE(s) dropped from analyze because the operator-supplied VEX statement marks them not_affected / resolved / false_positive. They remain in cve-catalog.json; the disposition lives in the VEX file.`
        : "VEX filter supplied; zero matches dropped (no CVEs in domain.cve_refs matched the VEX not-affected set)."
    } : null
  };
}

/**
 * Extract a set of "not affected" CVE IDs from a VEX document. Supports
 * CycloneDX VEX (analysis.state in {not_affected, resolved, false_positive})
 * and OpenVEX (statements[].status === "not_affected"). Returns a Set<string>.
 */
function vexFilterFromDoc(doc) {
  const out = new Set();
  if (!doc || typeof doc !== 'object') return out;

  // CycloneDX shape
  for (const v of (doc.vulnerabilities || [])) {
    const state = v.analysis && v.analysis.state;
    if (state === 'not_affected' || state === 'resolved' || state === 'false_positive') {
      if (v.id) out.add(v.id);
    }
  }
  // OpenVEX shape
  for (const s of (doc.statements || [])) {
    if (s.status === 'not_affected' || s.status === 'fixed') {
      const id = s.vulnerability && (s.vulnerability['@id'] || s.vulnerability.name || s.vulnerability);
      if (typeof id === 'string') out.add(id);
    }
  }
  return out;
}

// --- phase 6: validate ---

function validate(playbookId, directiveId, analyzeResult, agentSignals = {}) {
  const playbook = loadPlaybook(playbookId);
  const v = resolvedPhase(playbook, directiveId, 'validate');

  // Pick the highest-priority remediation_path whose preconditions are all
  // either satisfied by agentSignals or marked unverified=allow.
  const paths = (v.remediation_paths || []).slice().sort((a, b) => a.priority - b.priority);
  let selected = null;
  const considered = [];
  for (const p of paths) {
    const pcResult = (p.preconditions || []).map(expr => ({
      expr,
      satisfied: evalCondition(expr, agentSignals, playbook),
      submitted: agentSignals[expressionKey(expr)] !== undefined
    }));
    const allSatisfied = pcResult.every(x => x.satisfied);
    considered.push({ id: p.id, priority: p.priority, all_satisfied: allSatisfied, preconditions: pcResult });
    if (allSatisfied && !selected) selected = p;
  }
  // Always at least propose the highest-priority path even if preconditions
  // weren't verified — the agent can surface that to the operator.
  if (!selected && paths.length) selected = paths[0];

  // Compute regression schedule next_run (engine sets a single soonest run).
  const triggers = v.regression_trigger || [];
  const nextRun = computeRegressionNextRun(triggers);

  return {
    phase: 'validate',
    playbook_id: playbookId,
    directive_id: directiveId,
    selected_remediation: selected,
    remediation_options_considered: considered,
    validation_tests: v.validation_tests || [],
    residual_risk_statement: v.residual_risk_statement || null,
    evidence_requirements: v.evidence_requirements || [],
    regression_trigger: triggers,
    regression_next_run: nextRun
  };
}

function computeRegressionNextRun(triggers) {
  const now = new Date();
  let soonest = null;
  for (const t of triggers) {
    const m = (t.interval || '').match(/^(\d+)d$/);
    if (m) {
      const d = new Date(now.getTime() + parseInt(m[1], 10) * 24 * 3600 * 1000);
      if (!soonest || d < soonest) soonest = d;
    }
  }
  return soonest ? soonest.toISOString() : null;
}

// --- phase 7: close ---

/**
 * Assemble the closure artifacts:
 *   - evidence_package (CSAF-2.0 shaped if requested; signed if signing key present)
 *   - learning_loop lesson template populated with current finding context
 *   - notification_actions with computed ISO 8601 deadlines from clock_starts + window_hours
 *   - exception_generation auditor-ready language if trigger fires
 *   - regression_schedule.next_run from validate.regression_next_run
 *   - feeds_into chaining suggestions
 */
function close(playbookId, directiveId, analyzeResult, validateResult, agentSignals = {}, runOpts = {}) {
  const playbook = loadPlaybook(playbookId);
  const c = resolvedPhase(playbook, directiveId, 'close');
  const g = resolvedPhase(playbook, directiveId, 'govern');
  const sessionId = runOpts.session_id || crypto.randomBytes(8).toString('hex');

  // notification_actions — compute ISO deadlines from clock_starts events.
  const notificationActions = (c.notification_actions || []).map(na => {
    const obligation = (g.jurisdiction_obligations || []).find(o =>
      `${o.jurisdiction}/${o.regulation} ${o.window_hours}h` === na.obligation_ref
    );
    const clockStart = obligation ? computeClockStart(obligation.clock_starts, agentSignals) : null;
    const deadline = obligation && clockStart
      ? new Date(clockStart.getTime() + obligation.window_hours * 3600 * 1000).toISOString()
      : 'pending_clock_start_event';
    return {
      ...na,
      deadline,
      clock_start_event: obligation?.clock_starts,
      clock_started_at: clockStart?.toISOString() || null,
      draft_notification: interpolate(na.draft_notification, { ...agentSignals, ...analyzeFindingShape(analyzeResult) })
    };
  });

  // exception_generation — evaluate trigger.
  let exception = null;
  if (c.exception_generation) {
    const triggered = evalCondition(c.exception_generation.trigger_condition, agentSignals, playbook);
    if (triggered) {
      const t = c.exception_generation.exception_template;
      exception = {
        scope: interpolate(t.scope, { ...agentSignals, ...analyzeFindingShape(analyzeResult) }),
        duration: t.duration,
        compensating_controls: t.compensating_controls,
        risk_acceptance_owner: t.risk_acceptance_owner,
        auditor_ready_language: interpolate(t.auditor_ready_language, {
          ...agentSignals,
          ...analyzeFindingShape(analyzeResult),
          framework_id: playbook.domain.frameworks_in_scope[0] || 'unspecified',
          control_id: analyzeResult.framework_gap_mapping?.[0]?.claimed_control || 'unspecified',
          ciso_name: agentSignals.ciso_name || '<CISO NAME>',
          acceptance_date: new Date().toISOString().slice(0, 10),
          duration_expiry: agentSignals.duration_expiry || 'until vendor patch'
        })
      };
    }
  }

  // evidence_package — playbook declares one primary bundle_format; the
  // operator may request additional formats via agentSignals._bundle_formats
  // (e.g. SARIF for GitHub Code Scanning + OpenVEX for supply-chain tooling
  // alongside the CSAF default).
  const primaryFormat = c.evidence_package?.bundle_format || 'csaf-2.0';
  const extraFormats = Array.isArray(agentSignals._bundle_formats)
    ? agentSignals._bundle_formats.filter(f => f !== primaryFormat)
    : [];
  const evidencePackage = c.evidence_package ? {
    bundle_format: primaryFormat,
    contents: c.evidence_package.contents || [],
    destination: c.evidence_package.destination || 'local_only',
    signed: c.evidence_package.signed !== false,
    bundle_body: buildEvidenceBundle(primaryFormat, playbook, analyzeResult, validateResult, agentSignals),
    bundles_by_format: extraFormats.length ? Object.fromEntries(
      [primaryFormat, ...extraFormats].map(f => [f, buildEvidenceBundle(f, playbook, analyzeResult, validateResult, agentSignals)])
    ) : null,
  } : null;

  if (evidencePackage && evidencePackage.signed && runOpts.session_key) {
    const body = JSON.stringify(evidencePackage.bundle_body);
    evidencePackage.signature = crypto
      .createHmac('sha256', runOpts.session_key)
      .update(body)
      .digest('hex');
    evidencePackage.signature_algorithm = 'HMAC-SHA256-session-key';
  } else if (evidencePackage && evidencePackage.signed) {
    evidencePackage.signature = null;
    evidencePackage.signature_pending = 'No session_key provided. Sign with Ed25519 via `node lib/sign.js sign-evidence <bundle.json>` post-emit.';
  }

  // learning_loop lesson
  const lesson = c.learning_loop?.enabled ? {
    enabled: true,
    attack_vector: interpolate(c.learning_loop.lesson_template.attack_vector, analyzeFindingShape(analyzeResult)),
    control_gap: c.learning_loop.lesson_template.control_gap,
    framework_gap: c.learning_loop.lesson_template.framework_gap,
    new_control_requirement: c.learning_loop.lesson_template.new_control_requirement,
    feeds_back_to_skills: c.learning_loop.feeds_back_to_skills || [],
    proposed_for_zeroday_lessons_id: `lesson-${playbook._meta.id}-${sessionId}`
  } : { enabled: false };

  // regression_schedule
  const regressionSchedule = c.regression_schedule ? {
    next_run: validateResult.regression_next_run,
    trigger: c.regression_schedule.trigger,
    notify_on_skip: c.regression_schedule.notify_on_skip !== false
  } : null;

  // feeds_into chaining — full analyze result is exposed so conditions can
  // reference `analyze.compliance_theater_check.verdict` etc.
  const feedsCtx = {
    rwep: analyzeResult.rwep?.adjusted,
    theater_score: analyzeResult.compliance_theater_check?.verdict === 'theater' ? 0 : 100,
    analyze: analyzeResult,
    validate: validateResult,
    finding: analyzeFindingShape(analyzeResult),
    ...agentSignals
  };
  const feeds = (playbook._meta.feeds_into || [])
    .filter(f => evalCondition(f.condition, feedsCtx, playbook))
    .map(f => f.playbook_id);

  return {
    phase: 'close',
    playbook_id: playbookId,
    directive_id: directiveId,
    evidence_package: evidencePackage,
    learning_loop: lesson,
    notification_actions: notificationActions,
    exception: exception,
    regression_schedule: regressionSchedule,
    feeds_into: feeds
  };
}

function analyzeFindingShape(a) {
  return {
    matched_cve_ids: (a.matched_cves || []).map(c => c.cve_id).join(', '),
    matched_cve_count: (a.matched_cves || []).length,
    kev_listed_count: (a.matched_cves || []).filter(c => c.cisa_kev).length,
    active_exploitation: (a.matched_cves || []).find(c => c.active_exploitation)?.active_exploitation || 'unknown',
    rwep_adjusted: a.rwep?.adjusted ?? 0,
    rwep_base: a.rwep?.base ?? 0,
    blast_radius_score: a.blast_radius_score ?? 0,
    framework_id_first: a.framework_gap_mapping?.[0]?.framework || null,
    control_id_first: a.framework_gap_mapping?.[0]?.claimed_control || null
  };
}

function buildEvidenceBundle(format, playbook, analyze, validate, agentSignals) {
  // CSAF-2.0 shape — minimal valid envelope; production GRC submission would
  // need full distribution + product_tree population, deferred to the GRC
  // integration layer.
  if (format === 'csaf-2.0') {
    return {
      document: {
        category: 'csaf_security_advisory',
        csaf_version: '2.0',
        publisher: { category: 'vendor', name: 'exceptd', namespace: 'https://exceptd.com' },
        title: `exceptd finding: ${playbook.domain.name} (${analyze.matched_cves.length} catalogued CVEs)`,
        tracking: {
          id: `exceptd-${playbook._meta.id}-${Date.now()}`,
          status: 'final',
          version: playbook._meta.version,
          initial_release_date: new Date().toISOString(),
          revision_history: [{ number: '1', date: new Date().toISOString(), summary: 'Initial finding emission' }]
        }
      },
      vulnerabilities: analyze.matched_cves.map(c => ({
        cve: c.cve_id,
        scores: [{ products: [], cvss_v3: { base_score: c.cvss_score || 0 } }],
        threats: c.active_exploitation === 'confirmed' ? [{ category: 'exploit_status', details: 'Active exploitation confirmed (CISA KEV).' }] : [],
        remediations: [{ category: 'vendor_fix', details: validate.selected_remediation?.description || 'See selected remediation path.' }]
      })),
      exceptd_extension: {
        rwep: analyze.rwep,
        blast_radius_score: analyze.blast_radius_score,
        compliance_theater: analyze.compliance_theater_check,
        framework_gap_mapping: analyze.framework_gap_mapping,
        evidence_requirements: validate.evidence_requirements,
        residual_risk_statement: validate.residual_risk_statement
      }
    };
  }

  // SARIF 2.1.0 — GitHub Code Scanning / VS Code SARIF Viewer / Azure DevOps
  // and most static analysis tooling. One run per playbook directive, one
  // result per matched CVE. Each result references a rule (cve_id) and ties
  // back to the directive as the "tool" producer.
  if (format === 'sarif' || format === 'sarif-2.1.0') {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'exceptd',
            version: playbook._meta.version,
            informationUri: 'https://exceptd.com',
            rules: analyze.matched_cves.map(c => ({
              id: c.cve_id,
              shortDescription: { text: c.cve_id },
              fullDescription: { text: `RWEP ${c.rwep} · KEV=${c.cisa_kev} · active_exploitation=${c.active_exploitation} · PoC=${c.poc_available}` },
              defaultConfiguration: { level: c.rwep >= 90 ? 'error' : c.rwep >= 70 ? 'warning' : 'note' },
              helpUri: `https://nvd.nist.gov/vuln/detail/${c.cve_id}`,
            }))
          }
        },
        results: analyze.matched_cves.map(c => ({
          ruleId: c.cve_id,
          level: c.rwep >= 90 ? 'error' : c.rwep >= 70 ? 'warning' : 'note',
          message: { text: `${c.cve_id}: RWEP ${c.rwep}, blast_radius ${analyze.blast_radius_score}. ${validate.selected_remediation?.description || ''}` },
          properties: {
            rwep: c.rwep,
            cisa_kev: c.cisa_kev,
            cisa_kev_due_date: c.cisa_kev_due_date,
            active_exploitation: c.active_exploitation,
            ai_discovered: c.ai_discovered,
            blast_radius_score: analyze.blast_radius_score,
            framework_gaps: analyze.framework_gap_mapping?.length || 0,
          }
        }))
      }]
    };
  }

  // OpenVEX 0.2.0 — supply-chain VEX statements. Each matched CVE becomes a
  // statement with status derived from confidence + RWEP. Downstream tools
  // (sigstore, in-toto, GUAC) consume this directly.
  if (format === 'openvex' || format === 'openvex-0.2.0') {
    const issued = new Date().toISOString();
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': `https://exceptd.com/vex/${playbook._meta.id}/${Date.now()}`,
      author: 'exceptd',
      timestamp: issued,
      version: 1,
      statements: analyze.matched_cves.map(c => ({
        vulnerability: { '@id': c.cve_id, name: c.cve_id },
        status: c.active_exploitation === 'confirmed' ? 'under_investigation' : (c.live_patch_available ? 'fixed' : 'affected'),
        timestamp: issued,
        action_statement: validate.selected_remediation?.description || null,
        impact_statement: `RWEP ${c.rwep}. Blast radius ${analyze.blast_radius_score}/5.`
      }))
    };
  }

  // v0.11.0 redesign #39: --format summary emits a 5-line digest for CI gates
  // and human triage. Drops everything except verdict + RWEP + blast +
  // feeds_into + jurisdiction clock count.
  if (format === 'summary') {
    return {
      format: 'summary',
      summary: {
        playbook: playbook._meta.id,
        verdict: analyze.compliance_theater_check?.verdict || 'pending',
        matched_cves: analyze.matched_cves.length,
        rwep_adjusted: analyze.rwep?.adjusted || 0,
        rwep_threshold_escalate: analyze.rwep?.threshold?.escalate || null,
        blast_radius_score: analyze.blast_radius_score || 0,
        feeds_into: null,  // populated by close()
        jurisdiction_clocks_active: null,  // populated by close()
        remediation_recommended: validate.selected_remediation?.id || null,
      }
    };
  }

  if (format === 'markdown') {
    const lines = [
      `# exceptd finding: ${playbook.domain.name}`,
      `**Playbook:** ${playbook._meta.id} v${playbook._meta.version}`,
      `**Matched CVEs:** ${analyze.matched_cves.length}`,
      `**Top RWEP:** ${analyze.rwep?.adjusted || 0}`,
      `**Blast radius:** ${analyze.blast_radius_score || 'unknown'}/5`,
      `**Theater verdict:** ${analyze.compliance_theater_check?.verdict || 'n/a'}`,
      `\n## Matched CVEs`,
      ...analyze.matched_cves.map(c => `- **${c.cve_id}** RWEP ${c.rwep} · KEV=${c.cisa_kev} · ${c.active_exploitation}`),
      `\n## Selected remediation`,
      validate.selected_remediation ? `${validate.selected_remediation.id} (priority ${validate.selected_remediation.priority}): ${validate.selected_remediation.description}` : 'No remediation path selected.',
      `\n## Residual risk`,
      validate.residual_risk_statement ? `${validate.residual_risk_statement.risk}\n\n_Acceptance level: ${validate.residual_risk_statement.acceptance_level}_` : 'None recorded.',
    ];
    return { format: 'markdown', body: lines.join('\n') };
  }

  return { format, note: 'Unknown format — supported: csaf-2.0, sarif, openvex, markdown.', analyze, validate };
}

// --- orchestrate: full run in one call ---

/**
 * v0.11.0 flat submission shape → v0.10.x nested shape. The flat shape is:
 *
 *   {
 *     observations: {
 *       <artifact-id>: { captured, value, indicator?, result? } | "<precondition-value>",
 *     },
 *     verdict: { theater, classification, blast_radius }
 *   }
 *
 * Already-nested submissions pass through unchanged.
 */
function normalizeSubmission(submission, playbook) {
  if (!submission || typeof submission !== "object") return submission || {};

  // v0.11.3 #71 fix: the CLI may inject `signals._bundle_formats` before
  // calling normalize (for --format <fmt> support). Pre-0.11.3 normalize
  // detected the injected `signals` key and bailed, leaving the flat
  // `observations` / `verdict` untranslated and breaking detect. The shape
  // detector now treats `observations` or `verdict` as authoritative for
  // "this is flat" — even when nested keys also exist — and merges any
  // pre-existing nested keys into the normalized result.
  const hasFlat = submission.observations || submission.verdict;

  if (!hasFlat) {
    // Truly already-nested. Mark shape and return.
    if (!submission._original_shape) submission._original_shape = 'nested (v0.10.x)';
    return submission;
  }

  const out = {
    artifacts: { ...(submission.artifacts || {}) },
    signal_overrides: { ...(submission.signal_overrides || {}) },
    signals: { ...(submission.signals || {}) },
    precondition_checks: { ...(submission.precondition_checks || {}) },
    _original_shape: 'flat (v0.11.0)',
  };
  const knownPreconditions = new Set((playbook?._meta?.preconditions || []).map(p => p.id));
  const knownArtifacts = new Set((playbook?.phases?.look?.artifacts || []).map(a => a.id));

  for (const [key, val] of Object.entries(submission.observations || {})) {
    if (knownPreconditions.has(key)) {
      out.precondition_checks[key] = val === "ok" || val === true || val === "true";
      continue;
    }
    if (typeof val === "object" && val !== null) {
      const aid = knownArtifacts.has(key) ? key : (val.artifact || key);
      out.artifacts[aid] = { value: val.value, captured: val.captured !== false };
      if (val.indicator && val.result) out.signal_overrides[val.indicator] = val.result;
    }
  }

  const v = submission.verdict || {};
  if (v.theater) out.signals.theater_verdict = v.theater === "actual_security" ? "clear" : v.theater;
  if (v.classification) out.signals.detection_classification = v.classification;
  if (v.blast_radius !== undefined) out.signals.blast_radius_score = v.blast_radius;

  // Carry over precondition_checks if the operator supplied them at the top
  // level even in the flat shape.
  if (submission.precondition_checks) Object.assign(out.precondition_checks, submission.precondition_checks);

  return out;
}

/**
 * Smart precondition auto-detect (redesign #9). Some preconditions are
 * mechanically answerable by the runner itself — host platform, cwd
 * readability, command-on-PATH. The AI shouldn't have to declare these;
 * we resolve them ourselves and only escalate to AI declaration when the
 * check requires intent (e.g. "operator authorized this scan").
 */
function autoDetectPreconditions(submission, playbook) {
  const fs = require('fs');
  const out = { ...(submission || {}) };
  out.precondition_checks = { ...(submission?.precondition_checks || {}) };
  for (const pc of (playbook?._meta?.preconditions || [])) {
    if (out.precondition_checks[pc.id] !== undefined) continue; // operator already supplied
    const check = (pc.check || '').toLowerCase();
    if (check.includes("host.platform == 'linux'") || check.includes("host.platform == \"linux\"")) {
      out.precondition_checks[pc.id] = process.platform === 'linux';
    } else if (check.includes("host.platform == 'darwin'") || check.includes("host.platform == \"darwin\"")) {
      out.precondition_checks[pc.id] = process.platform === 'darwin';
    } else if (check.includes("cwd_readable")) {
      try { fs.readdirSync(process.cwd()); out.precondition_checks[pc.id] = true; }
      catch { out.precondition_checks[pc.id] = false; }
    } else if (check.includes("agent_has_filesystem_read")) {
      out.precondition_checks[pc.id] = true; // Node has fs by definition
    } else if (check.match(/agent_has_command\(['"]([^'"]+)['"]\)/)) {
      const cmdName = check.match(/agent_has_command\(['"]([^'"]+)['"]\)/)[1];
      const { spawnSync } = require('child_process');
      const probe = spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmdName], { stdio: 'ignore' });
      out.precondition_checks[pc.id] = probe.status === 0;
    }
    // Intent-requiring checks (e.g. "operator_authorized == true") are NOT
    // auto-resolved — the AI / operator still declares them. We leave them
    // undefined and the preflight gate handles missing values per on_fail.
  }
  return out;
}

function run(playbookId, directiveId, agentSubmission = {}, runOpts = {}) {
  const playbook = loadPlaybook(playbookId);

  // v0.11.0: accept flat submission shape (observations + verdict). Normalize
  // to the engine's internal nested shape before preflight/detect. Smart
  // precondition auto-detect (redesign #9) fires here when the cwd is readable
  // / the host platform matches — the runner can answer those itself rather
  // than blocking on AI declaration.
  agentSubmission = normalizeSubmission(agentSubmission, playbook);
  agentSubmission = autoDetectPreconditions(agentSubmission, playbook);

  const pre = preflight(playbook, { ...runOpts, precondition_checks: { ...(agentSubmission.precondition_checks || {}), ...(runOpts.precondition_checks || {}) } });
  if (!pre.ok) {
    return { ok: false, phase: 'preflight', blocked_by: pre.blocked_by, reason: pre.reason, issues: pre.issues };
  }

  _activeRuns.add(playbookId);
  // Cross-process mutex lock for this run. preflight verified no other lock
  // exists; we acquire ours and release in the finally block.
  const lockPath = acquireLock(playbookId);
  try {
    const phases = {
      govern:   govern(playbookId, directiveId, runOpts),
      direct:   direct(playbookId, directiveId),
      look:     look(playbookId, directiveId, runOpts),
      detect:   detect(playbookId, directiveId, agentSubmission),
    };
    phases.analyze  = analyze(playbookId, directiveId, phases.detect, agentSubmission.signals || {});
    phases.validate = validate(playbookId, directiveId, phases.analyze, agentSubmission.signals || {});
    phases.close    = close(playbookId, directiveId, phases.analyze, phases.validate, agentSubmission.signals || {}, runOpts);

    const sessionId = runOpts.session_id || crypto.randomBytes(8).toString('hex');
    const evidenceHash = crypto.createHash('sha256')
      .update(JSON.stringify({
        playbookId, directiveId,
        cves: phases.analyze.matched_cves.map(c => c.cve_id),
        rwep: phases.analyze.rwep.adjusted,
        classification: phases.detect.classification
      }))
      .digest('hex');

    return {
      ok: true,
      playbook_id: playbookId,
      directive_id: directiveId,
      session_id: sessionId,
      evidence_hash: evidenceHash,
      preflight_issues: pre.issues,
      phases
    };
  } finally {
    _activeRuns.delete(playbookId);
    releaseLock(lockPath);
  }
}

// --- helpers ---

function evalCondition(expr, ctx, playbook) {
  if (!expr) return false;
  expr = expr.trim();
  expr = stripOuterParens(expr);
  if (expr === 'always') return true;
  if (expr === 'true') return true;
  if (expr === 'false') return false;

  // Honor operator precedence: OR is lower precedence than AND, so split on OR
  // first. splitAtTopLevel walks the expression depth-aware so parens correctly
  // group sub-expressions — i.e. `A OR (B AND C)` parses with B,C as one AND
  // group rather than splitting at the inner AND.
  const orParts = splitAtTopLevel(expr, 'OR');
  if (orParts.length > 1) return orParts.some(s => evalCondition(s, ctx, playbook));

  const andParts = splitAtTopLevel(expr, 'AND');
  if (andParts.length > 1) return andParts.every(s => evalCondition(s, ctx, playbook));

  // "rwep >= 90"
  let m = expr.match(/^(\w+(?:\.\w+)*)\s*(>=|<=|==|=|<|>|!=)\s*(['"]?)([^'"]+)\3$/);
  if (m) {
    const [, lhs, op, quote, rhsRaw] = m;
    const lv = resolvePath(ctx, lhs);
    let rv = rhsRaw;
    if (quote) {
      // Explicit quoted string literal — keep as-is.
    } else if (rv === 'true') rv = true;
    else if (rv === 'false') rv = false;
    else if (!isNaN(parseFloat(rv)) && /^-?\d+(\.\d+)?$/.test(rv.trim())) rv = parseFloat(rv);
    else if (/^[a-z_][\w.]*$/i.test(rv.trim())) {
      // Unquoted identifier — treat as a context path. Falls through to the
      // raw string if resolution returns undefined (matches the prior behavior
      // for literals like `theater` that aren't quoted).
      const resolved = resolvePath(ctx, rv.trim());
      if (resolved !== undefined && resolved !== null) rv = resolved;
    }
    switch (op) {
      case '==': case '=': return lv == rv;
      case '!=': return lv != rv;
      case '>=': return lv >= rv;
      case '<=': return lv <= rv;
      case '>':  return lv > rv;
      case '<':  return lv < rv;
    }
  }

  // "scope.targets includes named_remote"
  m = expr.match(/^(\w+(?:\.\w+)*)\s+includes\s+(\w+)$/);
  if (m) {
    const arr = resolvePath(ctx, m[1]);
    return Array.isArray(arr) && arr.includes(m[2]);
  }

  // "matched_cve.vector matches /regex/"
  m = expr.match(/^(\w+(?:\.\w+)*)\s+matches\s+\/(.+)\/$/);
  if (m) {
    const val = resolvePath(ctx, m[1]);
    if (typeof val !== 'string') return false;
    return new RegExp(m[2], 'i').test(val);
  }

  if (process.env.EXCEPTD_DEBUG) console.warn(`[runner] unknown condition: ${expr}`);
  return false;
}

function resolvePath(obj, dot) {
  return dot.split('.').reduce((acc, k) => acc == null ? null : acc[k], obj);
}

/**
 * Depth-aware splitter — split `expr` at occurrences of ` <sep> ` (with
 * surrounding spaces) that are at parenthesis depth 0. Returns the (trimmed)
 * sub-expression list. Used by evalCondition so `A OR (B AND C)` splits into
 * [`A`, `(B AND C)`] on OR, instead of naively splitting at the inner AND.
 */
function splitAtTopLevel(expr, sep) {
  const parts = [];
  const needle = ' ' + sep + ' ';
  let depth = 0, buf = '', i = 0;
  while (i < expr.length) {
    const ch = expr[i];
    if (ch === '(') { depth++; buf += ch; i++; continue; }
    if (ch === ')') { depth--; buf += ch; i++; continue; }
    if (depth === 0 && expr.startsWith(needle, i)) {
      parts.push(buf.trim());
      buf = '';
      i += needle.length;
      continue;
    }
    buf += ch;
    i++;
  }
  parts.push(buf.trim());
  return parts;
}

/**
 * Strip a balanced pair of outer parens, if and only if the very first and last
 * characters are matching parens at the same depth boundary. `(A) AND (B)` keeps
 * its parens; `((A AND B))` peels one layer.
 */
function stripOuterParens(expr) {
  while (expr.length >= 2 && expr[0] === '(' && expr[expr.length - 1] === ')') {
    let depth = 0;
    let outerMatches = true;
    for (let i = 0; i < expr.length - 1; i++) {
      if (expr[i] === '(') depth++;
      else if (expr[i] === ')') depth--;
      if (depth === 0 && i < expr.length - 1) { outerMatches = false; break; }
    }
    if (outerMatches) expr = expr.slice(1, -1).trim();
    else break;
  }
  return expr;
}

function computeClockStart(eventName, agentSignals) {
  // The agent submits clock_started_at_<event> ISO strings as it progresses.
  const key = `clock_started_at_${eventName}`;
  if (agentSignals[key]) return new Date(agentSignals[key]);
  // Fallback: use the standard 'detect_confirmed' default of "now" for the
  // most common case so notification deadlines aren't always pending.
  if (eventName === 'detect_confirmed' && agentSignals.detection_classification === 'detected') {
    return new Date();
  }
  return null;
}

function expressionKey(expr) {
  // For agentSignals precondition lookups — strip operators/values to leave key.
  const m = expr.match(/^(\w+(?:\.\w+)*)/);
  return m ? m[1] : expr;
}

function interpolate(tpl, ctx) {
  if (!tpl || typeof tpl !== 'string') return tpl;
  return tpl.replace(/\$\{(\w+)\}/g, (_, key) => {
    const v = ctx[key];
    return v !== undefined && v !== null ? String(v) : `\${${key}}`;
  });
}

// --- pre-run discovery API: list all directives across all playbooks ---

function plan(opts = {}) {
  const ids = opts.playbookIds || listPlaybooks();
  return {
    contract: 'seven-phase: govern → direct → look → detect → analyze → validate → close',
    host_ai_owns: ['look', 'detect'],
    exceptd_owns: ['govern', 'direct', 'analyze', 'validate', 'close'],
    generated_at: new Date().toISOString(),
    session_id: opts.session_id || crypto.randomBytes(8).toString('hex'),
    playbooks: ids.map(id => {
      const pb = loadPlaybook(id);
      const baseDirect = pb.phases?.direct || {};
      return {
        id,
        domain: pb.domain,
        scope: pb._meta.scope || null,
        threat_currency_score: pb._meta.threat_currency_score,
        air_gap_mode: !!pb._meta.air_gap_mode,
        directives: pb.directives.map(d => {
          const overrideDirect = d.phase_overrides?.direct || {};
          const threatContext = overrideDirect.threat_context || baseDirect.threat_context || null;
          // Bug #46: include description by default (not just under --directives).
          // Operators picking a directive need operator-facing prose.
          const desc = d.description
            || (threatContext ? (threatContext.split(/(?<=[.!?])\s+/)[0] || "").slice(0, 240) : null)
            || pb.domain?.name
            || null;
          return { id: d.id, title: d.title, description: desc, applies_to: d.applies_to };
        })
      };
    })
  };
}

module.exports = {
  listPlaybooks,
  loadPlaybook,
  plan,
  preflight,
  govern,
  direct,
  look,
  detect,
  analyze,
  validate,
  close,
  run,
  vexFilterFromDoc,
  normalizeSubmission,
  autoDetectPreconditions,
  // internal helpers exposed for tests
  _resolvedPhase: resolvedPhase,
  _deepMerge: deepMerge,
  _evalCondition: evalCondition,
  _interpolate: interpolate,
  _activeRuns: _activeRuns,
};
