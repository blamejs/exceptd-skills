'use strict';

/**
 * Playbook runner — executes the seven-phase contract declared in
 * lib/schemas/playbook.schema.json. The engine owns govern, direct, analyze,
 * validate and close; the host AI owns look and detect.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const scoring = require('./scoring');
const { assertIdComponent } = require('./id-validation');
const codepointClass = require('../vendor/blamejs/codepoint-class.js');

// cross-ref-api swallows a corrupt cve-catalog.json into an empty stub and
// records the failure in getLoadErrors(), which run() probes before analyze.
let xref;
let _xrefLoadError = null;
let _xrefProbed = false;
try {
  xref = require('./cross-ref-api');
} catch (e) {
  _xrefLoadError = (e && e.message) ? String(e.message) : String(e);
  xref = {
    byCve: () => ({ found: false, _error: _xrefLoadError }),
    _error: _xrefLoadError,
  };
  _xrefProbed = true; // require itself failed; nothing left to probe
}

// Lazy and memoized: only a verb that analyzes pays the ~2.6MB catalog parse.
function getXrefLoadError() {
  if (_xrefProbed) return _xrefLoadError;
  _xrefProbed = true;
  try {
    try { xref.byCve('__exceptd-probe__'); } catch { /* force the lazy catalog load */ }
    if (typeof xref.getLoadErrors === 'function') {
      const errs = xref.getLoadErrors();
      if (errs && errs.length) {
        _xrefLoadError = `${errs.length} catalog/index load error(s): ${errs.map(e => `${e.file}: ${e.error}`).join('; ')}`;
      }
    }
  } catch (e) {
    _xrefLoadError = (e && e.message) ? String(e.message) : String(e);
  }
  return _xrefLoadError;
}

const ROOT = path.join(__dirname, '..');
const PLAYBOOK_DIR = process.env.EXCEPTD_PLAYBOOK_DIR || path.join(ROOT, 'data', 'playbooks');

// In-process mutex tracker; survives only the current Node process.
const _activeRuns = new Set();

// Bounded push into a runtime_errors array: opts.cap (100) per kind,
// opts.totalCap (1000) overall, opts.dedupeKey(entry) collapsing same-(kind,
// key) pushes. A capped push records a `_truncated` sentinel instead, and
// returns false — true means the entry was pushed.
function pushRunError(arr, entry, opts) {
  if (!Array.isArray(arr) || !entry || typeof entry !== 'object') return false;
  opts = opts || {};
  const cap = typeof opts.cap === 'number' ? opts.cap : 100;
  const totalCap = typeof opts.totalCap === 'number' ? opts.totalCap : 1000;
  const kind = entry.kind;
  if (typeof opts.dedupeKey === 'function' && kind) {
    const dk = opts.dedupeKey(entry);
    if (arr.some(e => e && e.kind === kind && opts.dedupeKey(e) === dk)) {
      return false;
    }
  }
  const total = arr.length;
  const kindCount = kind ? arr.filter(e => e && e.kind === kind).length : 0;
  const overTotal = total >= totalCap;
  const overKind = kind && kindCount >= cap;
  if (overTotal || overKind) {
    const reason = overKind ? 'per-kind-cap' : 'total-cap';
    const existing = arr.find(e => e && e.kind === '_truncated' && e.truncated_kind === (kind || null) && e.reason === reason);
    if (existing) {
      existing.dropped = (existing.dropped || 0) + 1;
    } else {
      arr.push({ kind: '_truncated', truncated_kind: kind || null, dropped: 1, reason });
    }
    return false;
  }
  arr.push(entry);
  return true;
}

// Flatten a `_regex_eval_error` record into the fields pushRunError dedupes on.
function _regexErrorPayload(rec) {
  if (rec && typeof rec === 'object' && rec._regex_eval_error) {
    const { source, expr, message } = rec._regex_eval_error;
    return { source, expr, message, _regex_eval_error: rec._regex_eval_error };
  }
  return { _regex_eval_error: rec };
}

function listPlaybooks() {
  if (!fs.existsSync(PLAYBOOK_DIR)) return [];
  return fs.readdirSync(PLAYBOOK_DIR)
    .filter(f => f.endsWith('.json') && !f.startsWith('_'))
    .map(f => f.replace(/\.json$/, ''));
}

function loadPlaybook(playbookId) {
  // Traversal defense sits with the path.join so every caller gets it, not
  // only the CLI dispatcher.
  assertIdComponent(playbookId, 'playbook');
  const p = path.join(PLAYBOOK_DIR, `${playbookId}.json`);
  if (!fs.existsSync(p)) throw new Error(`Playbook not found: ${playbookId} (expected ${p})`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function findDirective(playbook, directiveId) {
  const d = playbook.directives.find(x => x.id === directiveId);
  if (!d) throw new Error(`Directive not found: ${directiveId} in playbook ${playbook._meta.id}`);
  return d;
}

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
    // `out[k]=` on k='__proto__' invokes the prototype-rebinding setter, and
    // deepMerge is exported (_deepMerge) so it may see parsed operator input.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = (k in out) ? deepMerge(out[k], v) : v;
  }
  return out;
}

/**
 * Pre-flight gate over currency, preconditions and mutex.
 * runOpts.strictPreconditions escalates every warn-level precondition outcome
 * to a halt; an on_fail='skip_phase' failure instead emits an issue carrying
 * skip_phase (default 'detect'), which run() routes to a skipped placeholder.
 */
function preflight(playbook, runOpts = {}) {
  const issues = [];
  const meta = playbook._meta;
  const strict = runOpts.strictPreconditions === true;

  const score = meta.threat_currency_score;
  // No usable score is the most-stale state: `undefined < 50` is false, which
  // would bypass the gate on exactly the broken metadata.
  const scoreUsable = typeof score === 'number' && !Number.isNaN(score);
  if ((!scoreUsable || score < 50) && !runOpts.forceStale) {
    return {
      ok: false,
      blocked_by: 'currency',
      reason: scoreUsable
        ? `threat_currency_score = ${score} (< 50). Hard-blocked. Pass forceStale=true to override.`
        : `threat_currency_score is absent or non-numeric (${JSON.stringify(score)}). Hard-blocked — a playbook without a usable currency score is treated as stale. Fix _meta.threat_currency_score, or pass forceStale=true to override.`,
      issues
    };
  }
  if (scoreUsable && score < 70) {
    issues.push({ kind: 'currency_warn', message: `threat_currency_score = ${score} (< 70). Threat model is stale — recommend running the skill-update-loop before relying on findings.` });
  }

  for (const pc of meta.preconditions || []) {
    const submitted = runOpts.precondition_checks?.[pc.id];
    if (submitted === undefined) {
      const submission_hint = `Submit precondition_checks in your evidence JSON, e.g. { "precondition_checks": { "${pc.id}": true } }. Pass via --evidence <file.json> or pipe to stdin with --evidence -. The runner lifts precondition_checks into runOpts before the gate evaluates.`;
      if (strict) {
        issues.push({ kind: 'precondition_halt', id: pc.id, check: pc.check, on_fail: pc.on_fail, submission_hint, escalated_from: 'precondition_unverified' });
        return {
          ok: false,
          blocked_by: 'precondition',
          reason: `Precondition ${pc.id} (${pc.check}) not verified by host AI; strict-preconditions enabled.`,
          remediation: submission_hint,
          issues
        };
      }
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
        return {
          ok: false,
          blocked_by: 'precondition',
          reason: `Precondition ${pc.id} failed: ${pc.description}`,
          // Its own remediation, so the renderer prefers it to the generic
          // platform-gate hint: an ownership gate is not a platform mismatch.
          remediation: `Precondition ${pc.id} was submitted as false: ${pc.description} Attest it as true and re-run — submit precondition_checks {"${pc.id}": true} in your evidence JSON, or pass the owning collector's attestation flag at collect time (for example: collect cicd-pipeline-compromise --attest-ownership).`,
          issues
        };
      }
      if (strict) {
        issues.push({ kind: 'precondition_halt', id: pc.id, message: pc.description, escalated_from: pc.on_fail === 'skip_phase' ? 'precondition_skip' : 'precondition_warn' });
        return {
          ok: false,
          blocked_by: 'precondition',
          reason: `Precondition ${pc.id} (${pc.check}) failed; strict-preconditions enabled.`,
          issues
        };
      }
      if (pc.on_fail === 'skip_phase') {
        issues.push({ kind: 'precondition_skip', id: pc.id, message: pc.description, skip_phase: pc.skip_phase || 'detect' });
      } else {
        issues.push({ kind: 'precondition_warn', id: pc.id, message: pc.description });
      }
    }
  }

  // Both the in-process Set and the lockfile, so two parallel CLI invocations
  // of conflicting playbooks race-detect.
  for (const conflictId of meta.mutex || []) {
    if (_activeRuns.has(conflictId)) {
      return { ok: false, blocked_by: 'mutex', reason: `Mutex conflict (intra-process): playbook ${conflictId} is currently active and listed in this playbook's mutex set.`, issues };
    }
    const lockPath = lockFilePath(conflictId);
    if (lockPath && fs.existsSync(lockPath)) {
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

// EXCEPTD_LOCK_DIR, then (EXCEPTD_HOME || ~/.exceptd)/locks/<platform>, then
// os.tmpdir() when the home is non-writable. The path must not depend on the
// working directory, or two invocations see different lock sets and both run
// unchallenged. The platform segment separates PIDs on a shared networked FS.
function resolveLockDir() {
  if (process.env.EXCEPTD_LOCK_DIR) return process.env.EXCEPTD_LOCK_DIR;
  const home = process.env.EXCEPTD_HOME || (os.homedir() && path.join(os.homedir(), '.exceptd'));
  if (home) {
    const dir = path.join(home, 'locks', process.platform);
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      // A home that mkdirs but cannot be written must fall through to tmpdir
      // rather than no-op every lock write.
      const probe = path.join(dir, `.write-probe-${process.pid}`);
      fs.writeFileSync(probe, '');
      fs.unlinkSync(probe);
      return dir;
    } catch { /* home non-writable — fall through to tmpdir */ }
  }
  return path.join(os.tmpdir(), `exceptd-locks-${process.platform}`);
}

function lockDir() {
  const dir = resolveLockDir();
  // Owner-only: another local user must not list or tamper with this lock set.
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { /* exists / EACCES — non-fatal */ }
  return dir;
}

function lockFilePath(playbookId) {
  try { return path.join(lockDir(), `${playbookId}.lock`); }
  catch { return null; }
}

// Same-PID stale-lockfile threshold, matching lib/refresh-external.js and
// lib/prefetch.js. No legitimate playbook hold reaches 30s.
const STALE_LOCK_MS = 30_000;

// Exclusive owner-only create ('wx', 0o600). The file NAME is predictable by
// design — it IS the mutex — and safety comes from the exclusive create, which
// throws EEXIST/EPERM on a preplanted file or symlink rather than following it.
function writeLockFile(p, playbookId) {
  const fd = fs.openSync(p, 'wx', 0o600);
  try {
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: playbookId }, null, 2));
  } finally {
    fs.closeSync(fd);
  }
}

function acquireLock(playbookId) {
  const p = lockFilePath(playbookId);
  if (!p) return null;
  const writePayload = () => writeLockFile(p, playbookId);
  try {
    writePayload();
    return p;
  } catch (e) {
    // Stale-PID reclaim: without it a crashed process's lockfile leaves every
    // later invocation running UNLOCKED. ESRCH means dead; EPERM means alive
    // under another user, and the lock stands.
    if (e && (e.code === 'EEXIST' || e.code === 'EPERM')) {
      try {
        const raw = fs.readFileSync(p, 'utf8');
        let pid = null;
        try { pid = JSON.parse(raw).pid; }
        catch {
          const n = Number.parseInt(String(raw).trim(), 10);
          pid = Number.isInteger(n) && n > 0 ? n : null;
        }
        if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && !pidAlive(pid)) {
          try { fs.unlinkSync(p); } catch {}
          try { writePayload(); return p; } catch { /* fall through */ }
        }
        // Same-PID reclaim goes by mtime: a fresh lockfile is legitimate
        // reentrancy and stays held, while an older one is an orphan that
        // would deny this process the lock for the rest of its lifetime.
        if (Number.isInteger(pid) && pid === process.pid) {
          try {
            const stat = fs.statSync(p);
            if (Date.now() - stat.mtimeMs > STALE_LOCK_MS) {
              try { fs.unlinkSync(p); } catch {}
              try { writePayload(); return p; } catch { /* fall through */ }
            }
          } catch { /* stat failed — treat as held */ }
        }
      } catch { /* unreadable lockfile — treat as held by a live process */ }
    }
    // Null on failure — the contract every call site tests as `if (!lockPath)`.
    return null;
  }
}

// acquireLock, but separating "held by a live process" from an unexpected
// error: { ok:true, path } or { ok:false, reason, lock_path?, holder_pid? }.
function acquireLockDiagnostic(playbookId) {
  const p = lockFilePath(playbookId);
  if (!p) return { ok: false, reason: 'no_lock_path' };
  try {
    writeLockFile(p, playbookId);
    return { ok: true, path: p };
  } catch (e) {
    if (e && (e.code === 'EEXIST' || e.code === 'EPERM')) {
      let pid = null;
      try {
        const raw = fs.readFileSync(p, 'utf8');
        try { pid = JSON.parse(raw).pid; }
        catch {
          const n = Number.parseInt(String(raw).trim(), 10);
          pid = Number.isInteger(n) && n > 0 ? n : null;
        }
      } catch {}
      if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && !pidAlive(pid)) {
        try { fs.unlinkSync(p); } catch {}
        try {
          writeLockFile(p, playbookId);
          return { ok: true, path: p, reclaimed_from_pid: pid };
        } catch (e2) {
          return { ok: false, reason: 'reclaim_failed', error: e2.message, lock_path: p, holder_pid: pid };
        }
      }
      // Same-PID reclaim, same mtime semantics as acquireLock.
      if (Number.isInteger(pid) && pid === process.pid) {
        let mtimeMs = null;
        try { mtimeMs = fs.statSync(p).mtimeMs; } catch {}
        if (mtimeMs !== null && (Date.now() - mtimeMs) > STALE_LOCK_MS) {
          try { fs.unlinkSync(p); } catch {}
          try {
            writeLockFile(p, playbookId);
            return { ok: true, path: p, reclaimed_self_stale_pid: true, prior_mtime_ms: mtimeMs };
          } catch (e3) {
            return { ok: false, reason: 'reclaim_failed', error: e3.message, lock_path: p, holder_pid: pid };
          }
        }
        return { ok: false, reason: 'held_by_self', lock_path: p, holder_pid: pid };
      }
      return { ok: false, reason: 'held_by_live_pid', lock_path: p, holder_pid: pid };
    }
    return { ok: false, reason: 'fs_error', error: e && e.message, lock_path: p };
  }
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

// Phase 1. GRC context for the agent. Jurisdiction obligations carry
// window_hours + clock_starts because close() computes deadlines from them.
function govern(playbookId, directiveId, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const g = resolvedPhase(playbook, directiveId, 'govern');
  // Ascending window_hours: the tightest clock heads the list.
  const obligations = (g.jurisdiction_obligations || []).slice().sort((a, b) => {
    const aw = (a && typeof a.window_hours === 'number') ? a.window_hours : Number.POSITIVE_INFINITY;
    const bw = (b && typeof b.window_hours === 'number') ? b.window_hours : Number.POSITIVE_INFINITY;
    return aw - bw;
  });
  return {
    phase: 'govern',
    playbook_id: playbookId,
    directive_id: directiveId,
    domain: playbook.domain,
    threat_currency_score: playbook._meta.threat_currency_score,
    last_threat_review: playbook._meta.last_threat_review,
    air_gap_mode: !!playbook._meta.air_gap_mode || !!runOpts.airGap,
    jurisdiction_obligations: obligations,
    theater_fingerprints: g.theater_fingerprints || [],
    framework_context: g.framework_context || {},
    skill_preload: g.skill_preload || [],
    // --ack acknowledges the obligations surfaced here; null when not passed.
    operator_consent: runOpts.operator_consent || null
  };
}

function direct(playbookId, directiveId, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
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

function look(playbookId, directiveId, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const l = resolvedPhase(playbook, directiveId, 'look');
  const airGap = !!playbook._meta.air_gap_mode || !!runOpts.airGap;
  return {
    phase: 'look',
    playbook_id: playbookId,
    directive_id: directiveId,
    air_gap_mode: airGap,
    // The host AI probes these itself and declares the results through
    // submission.precondition_checks; without the list it is blind to the gate.
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
      source: airGap && a.air_gap_alternative ? a.air_gap_alternative : a.source,
      _original_source: a.source,
      // An artifact with no alternative keeps its possibly network-bound
      // source, so the flag marks it not-offline-verified.
      ...(airGap && !a.air_gap_alternative ? { air_gap_alternative_missing: true } : {}),
    })),
    collection_scope: l.collection_scope,
    environment_assumptions: l.environment_assumptions || [],
    fallback_if_unavailable: l.fallback_if_unavailable || []
  };
}

/**
 * Phase 4. Evaluates submitted artifacts against the playbook's typed
 * indicators: a per-indicator hit/miss/inconclusive verdict plus a
 * minimum_signal classification (detected | inconclusive | not_detected).
 * The agent submits `artifacts` as { artifact_id: { value, captured, reason? } }
 * and optionally `signal_overrides` as { indicator_id: verdict }.
 */
function detect(playbookId, directiveId, agentSubmission = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const det = resolvedPhase(playbook, directiveId, 'detect');
  const artifacts = agentSubmission.artifacts || {};
  const overrides = agentSubmission.signal_overrides || {};

  // Operators submit the CI/security vocabulary ("no_hit", "clean", "ok"); the
  // engine speaks hit | miss | inconclusive.
  const canonicalize = (v) => {
    if (v === true || v === 'hit' || v === 'detected' || v === 'positive') return 'hit';
    if (v === false || v === 'miss' || v === 'no_hit' || v === 'no-hit' || v === 'clean' || v === 'clear' || v === 'not_hit' || v === 'ok' || v === 'pass' || v === 'negative') return 'miss';
    if (v === 'inconclusive' || v === 'unknown' || v === 'unverified' || v === null) return 'inconclusive';
    return null; // truly unknown — fall through
  };

  // `evidence_locations: { "<indicator-id>": ["path", {uri,startLine}] }`,
  // threaded onto each firing indicator so the SARIF renderer can fill
  // results[].locations — GitHub code-scanning drops a location-less result.
  const _evLocs = (agentSubmission && typeof agentSubmission.evidence_locations === 'object'
    && agentSubmission.evidence_locations !== null && !Array.isArray(agentSubmission.evidence_locations))
    ? agentSubmission.evidence_locations : {};
  const indicatorResults = (det.indicators || []).map(ind => {
    const rawOverride = overrides[ind.id];
    const override = canonicalize(rawOverride);
    let verdict;
    let fpChecksUnsatisfied = null;
    if (override === 'hit' || override === 'miss' || override === 'inconclusive') {
      verdict = override;
      // A 'hit' is gated on the indicator's false_positive_checks_required,
      // attested through a sibling signal_overrides key '<id>__fp_checks'. No
      // attestation leaves every check UNSATISFIED and downgrades the verdict.
      if (verdict === 'hit' && Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length) {
        // A Proxy attestation whose getters throw must not abort the run: on
        // throw every check is unsatisfied — never honor an unreadable one.
        try {
          const attestation = overrides[`${ind.id}__fp_checks`];
          // An array satisfies `typeof === 'object'` but is not an attestation
          // map: `[true, true]` would match through the index fallback below
          // and bypass every FP-check requirement.
          const safeAtt = Array.isArray(attestation) ? null : attestation;
          const att = (safeAtt && typeof safeAtt === 'object') ? safeAtt : {};
          const unsatisfied = ind.false_positive_checks_required.filter(fpName => {
            // The entries are free text, not ids, so an operator may attest by
            // the literal string or by index. Anything else is unsatisfied.
            if (att[fpName] === true) return false;
            const idx = ind.false_positive_checks_required.indexOf(fpName);
            if (idx !== -1 && att[String(idx)] === true) return false;
            return true;
          });
          if (unsatisfied.length > 0) {
            verdict = 'inconclusive';
            fpChecksUnsatisfied = unsatisfied;
          }
        } catch (e) {
          verdict = 'inconclusive';
          fpChecksUnsatisfied = ind.false_positive_checks_required.slice();
          if (runOpts && Array.isArray(runOpts._runErrors)) {
            pushRunError(runOpts._runErrors, {
              kind: 'fp_attestation_threw',
              indicator_id: ind.id,
              message: (e && e.message) ? String(e.message) : String(e),
            }, { dedupeKey: e => e.indicator_id || '' });
          }
        }
      }
    } else {
      // An override that did not canonicalize ("maybe", a number). Dropping it
      // silently turns an asserted result into a false not_detected.
      if (rawOverride !== undefined && runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'signal_override_unrecognized',
          indicator_id: ind.id,
          supplied_value: (typeof rawOverride === 'object') ? JSON.stringify(rawOverride).slice(0, 80) : String(rawOverride).slice(0, 80),
          message: `signal_overrides["${ind.id}"] value was not recognized (expected hit/miss/inconclusive or a boolean); the signal was ignored.`,
        }, { dedupeKey: e => e.indicator_id || '' });
      }
      // The engine does not pattern-match raw artifact content, so a captured
      // artifact means only that the indicator COULD be evaluated. Nothing
      // captured is an empty submission, which 'miss' lets reach not_detected.
      const anyCaptured = Object.values(artifacts).some(a => a && a.captured);
      verdict = anyCaptured ? 'inconclusive' : 'miss';
    }
    const indLocs = (verdict === 'hit' && Array.isArray(_evLocs[ind.id]) && _evLocs[ind.id].length) ? _evLocs[ind.id] : null;
    return {
      id: ind.id, type: ind.type, confidence: ind.confidence,
      deterministic: ind.deterministic, atlas_ref: ind.atlas_ref || null,
      attack_ref: ind.attack_ref || null, verdict,
      ...(indLocs ? { evidence_locations: indLocs } : {}),
      ...(fpChecksUnsatisfied ? { fp_checks_unsatisfied: fpChecksUnsatisfied } : {})
    };
  });

  // The FP tests the agent still owes for each indicator it reported as 'hit'.
  const fpChecksRequired = (det.false_positive_profile || []).filter(fp =>
    indicatorResults.find(r => r.id === fp.indicator_id && r.verdict === 'hit')
  );

  const hits = indicatorResults.filter(r => r.verdict === 'hit');
  const hasDeterministicHit = hits.some(r => r.deterministic);
  const hasHighConfHit = hits.some(r => r.confidence === 'high' || r.confidence === 'deterministic');

  // The agent's own verdict after running the full false_positive_profile: the
  // engine classification cannot express "I saw these and they are all benign".
  const rawOverride = (agentSubmission.signals && agentSubmission.signals.detection_classification);
  const validOverrides = new Set(['detected', 'inconclusive', 'not_detected', 'clean']);
  // Matching is exact — case-sensitive, unpadded. A near-miss surfaces a
  // runtime_error and is then treated as absent.
  const overrideIsString = typeof rawOverride === 'string';
  const overrideIsInAllowlist = overrideIsString && validOverrides.has(rawOverride);
  if (rawOverride !== undefined && rawOverride !== null && !overrideIsInAllowlist) {
    if (runOpts && Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, {
        kind: 'classification_override_invalid',
        supplied: rawOverride,
        allowed: [...validOverrides],
        reason: 'signals.detection_classification must be one of the allowlist values exactly (case-sensitive, no surrounding whitespace). Override ignored; engine-computed classification used.',
      }, { dedupeKey: e => String(e.supplied) });
    }
  }
  const override = overrideIsInAllowlist ? rawOverride : undefined;

  // Every classification override is refused once any indicator was
  // FP-downgraded. The runtime_error records indicator ids and an unsatisfied
  // count only: the literal check names are an attestation-bypass hint.
  const anyFpDowngrade = indicatorResults.some(r => Array.isArray(r.fp_checks_unsatisfied) && r.fp_checks_unsatisfied.length > 0);

  let classification;
  // A refused override must not be reported as applied.
  let overrideEffective = !!override;
  if (override) {
    classification = override === 'clean' ? 'not_detected' : override;
    if (anyFpDowngrade) {
      const substituted = 'inconclusive';
      const attempted = override; // what the operator submitted, not the mapped form
      classification = substituted;
      overrideEffective = false;
      if (runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'classification_override_blocked',
          attempted,
          substituted,
          reason: 'FP-check downgrade: one or more indicators downgraded to inconclusive because false_positive_checks_required entries were not attested. Agent classification override refused.',
          indicators_with_unsatisfied_fp_checks: indicatorResults
            .filter(r => Array.isArray(r.fp_checks_unsatisfied) && r.fp_checks_unsatisfied.length > 0)
            .map(r => ({ id: r.id, fp_checks_unsatisfied_count: r.fp_checks_unsatisfied.length })),
        }, { dedupeKey: e => String(e.attempted) });
      }
    } else if (classification === 'not_detected' && hasDeterministicHit) {
      // A deterministic hit cannot be buried under not_detected/clean — a
      // worse false negative than an inconclusive run. Probabilistic hits stay
      // overridable; that is the legitimate "these are benign" path.
      classification = 'inconclusive';
      overrideEffective = false;
      if (runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'classification_override_masks_deterministic_hit',
          attempted: override,
          substituted: 'inconclusive',
          reason: 'A not_detected/clean classification override was refused because one or more deterministic indicators fired. A deterministic hit cannot be downgraded to not_detected.',
          deterministic_hit_indicators: hits.filter(r => r.deterministic).map(r => r.id),
        }, { dedupeKey: e => String(e.attempted) });
      }
    }
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
    // What detect consumed, so an operator can see what reached the runner.
    observations_received: Object.keys(agentSubmission.artifacts || {}),
    signals_received: Object.keys(agentSubmission.signal_overrides || {}),
    // An array — indicators_evaluated_count carries the integer.
    indicators_evaluated: indicatorResults.map(i => ({
      signal_id: i.id,
      outcome: i.verdict,
      confidence: i.confidence,
      // The observation behind this outcome; null on the engine default.
      from_observation: agentSubmission._signal_origins?.[i.id] || null,
    })),
    indicators_evaluated_count: indicatorResults.length,
    // Null for a refused override, which would contradict the verdict.
    classification_override_applied: (override && overrideEffective) ? (override === 'clean' ? 'not_detected' : override) : null,
    submission_shape_seen: agentSubmission._original_shape || (agentSubmission.artifacts ? 'nested (v0.10.x)' : 'empty'),
    // Republished by analyze() as analyze.signal_origins_with_collisions.
    _signal_origins_collisions: Array.isArray(agentSubmission._signal_origins_collisions) ? agentSubmission._signal_origins_collisions.slice() : []
  };
}

// Mirror the fired detect indicators into a flat `{ <indicator-id>: true }` map
// for the escalation / feeds_into / precondition contexts, which spread
// `signals` and not `signal_overrides`. Only verdict 'hit' mirrors: an
// 'inconclusive' indicator is unconfirmed and must not fire an escalation.
// Spread at the LOWEST precedence, so engine values still win.
function firedIndicatorSignals(detectIndicators) {
  const out = {};
  for (const ind of (detectIndicators || [])) {
    if (ind && ind.verdict === 'hit' && typeof ind.id === 'string') out[ind.id] = true;
  }
  return out;
}

// Phase 5. RWEP composition, blast-radius scoring, theater check, framework gap
// mapping and escalation evaluation, from the detect result plus agent signals.
function analyze(playbookId, directiveId, detectResult, agentSignals = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const an = resolvedPhase(playbook, directiveId, 'analyze');
  const directive = findDirective(playbook, directiveId);
  // A direct analyze() call carries no accumulator, and without a local one
  // blast_radius / theater / xref errors never reach analyze.runtime_errors.
  if (!Array.isArray(runOpts._runErrors)) {
    runOpts = { ...runOpts, _runErrors: [] };
  }

  // domain.cve_refs enumerates the playbook's scan coverage, never a claim that
  // the operator is affected. catalogBaselineCves is all of it with
  // correlated_via null; matchedCves is the subset the evidence correlates to,
  // and correlated_via names what tied them. agentSignals.vex_filter removes
  // entries from BOTH arrays.
  const cveRefs = playbook.domain.cve_refs || [];
  const vexFilter = agentSignals.vex_filter instanceof Set ? agentSignals.vex_filter
    : (Array.isArray(agentSignals.vex_filter) ? new Set(agentSignals.vex_filter) : null);
  // not_affected / false_positive drop entirely; fixed / resolved are kept and
  // annotated. The CLI populates vex_fixed from the VEX doc.
  const vexFixed = agentSignals.vex_fixed instanceof Set ? agentSignals.vex_fixed
    : (Array.isArray(agentSignals.vex_fixed) ? new Set(agentSignals.vex_fixed) : null);
  // A corrupt catalog or missing index becomes a runtime_error, not a crash.
  const _byCveSafe = (id) => {
    try { return xref.byCve(id); }
    catch (e) {
      if (Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, { kind: 'xref', cve_id: id, message: (e && e.message) ? String(e.message) : String(e) }, { dedupeKey: e => e.cve_id || '' });
      }
      return { found: false, cve_id: id };
    }
  };
  const allCves = cveRefs.map(id => _byCveSafe(id)).filter(r => r.found);
  const catalogBaselineCves = vexFilter
    ? allCves.filter(c => !vexFilter.has(c.cve_id))
    : allCves;
  const vexDropped = vexFilter
    ? allCves.filter(c => vexFilter.has(c.cve_id)).map(c => c.cve_id)
    : [];
  // From the post-vexFilter survivors, not allCves: a CVE marked BOTH
  // not_affected and fixed would land in fixed_cves and nowhere else.
  const vexFixedIds = vexFixed
    ? catalogBaselineCves.filter(c => vexFixed.has(c.cve_id)).map(c => c.cve_id)
    : [];

  // cve_id -> array of "indicator_hit:<id>" / "signal:<id>" reasons.
  const correlationsByCve = new Map();
  const addCorrelation = (cveId, reason) => {
    if (!correlationsByCve.has(cveId)) correlationsByCve.set(cveId, []);
    const arr = correlationsByCve.get(cveId);
    if (!arr.includes(reason)) arr.push(reason);
  };
  const playbookDetect = resolvedPhase(playbook, directiveId, 'detect');
  const indicatorRefs = new Map(); // indicator.id -> { attack_ref, atlas_ref }
  for (const ind of (playbookDetect.indicators || [])) {
    indicatorRefs.set(ind.id, { attack_ref: ind.attack_ref || null, atlas_ref: ind.atlas_ref || null });
  }
  const firedIndicators = (detectResult.indicators || []).filter(i => i.verdict === 'hit');
  for (const fired of firedIndicators) {
    const refs = indicatorRefs.get(fired.id) || { attack_ref: fired.attack_ref || null, atlas_ref: fired.atlas_ref || null };
    if (!refs.attack_ref && !refs.atlas_ref) continue;
    for (const c of catalogBaselineCves) {
      const attackHit = refs.attack_ref && Array.isArray(c.attack_refs) && c.attack_refs.includes(refs.attack_ref);
      const atlasHit = refs.atlas_ref && Array.isArray(c.atlas_refs) && c.atlas_refs.includes(refs.atlas_ref);
      if (attackHit || atlasHit) addCorrelation(c.cve_id, `indicator_hit:${fired.id}`);
    }
  }
  for (const c of catalogBaselineCves) {
    const sig = agentSignals[c.cve_id];
    if (sig === true || sig === 'hit' || sig === 'detected' || sig === 'affected') {
      addCorrelation(c.cve_id, `signal:${c.cve_id}`);
    }
  }

  // An indicator's own cve_ref (string or string[]), correlated as
  // 'indicator_cve_ref:<indicator-id>'. This reaches CVEs domain.cve_refs
  // never enumerated, which join the working set for the filter below.
  const extraCatalogCves = [];
  const seenCatalogIds = new Set(catalogBaselineCves.map(c => c.cve_id));
  for (const fired of firedIndicators) {
    const indicator = (playbookDetect.indicators || []).find(i => i.id === fired.id);
    if (!indicator) continue;
    const raw = indicator.cve_ref;
    const refs = Array.isArray(raw) ? raw : (typeof raw === 'string' && raw ? [raw] : []);
    for (const cveId of refs) {
      if (vexFilter && vexFilter.has(cveId)) continue;
      let cveEntry = catalogBaselineCves.find(c => c.cve_id === cveId);
      if (!cveEntry) {
        const looked = _byCveSafe(cveId);
        if (!looked || !looked.found) continue; // CVE not in catalog — skip
        if (!seenCatalogIds.has(looked.cve_id)) {
          extraCatalogCves.push(looked);
          seenCatalogIds.add(looked.cve_id);
        }
      }
      addCorrelation(cveId, `indicator_cve_ref:${fired.id}`);
    }
  }
  const workingCatalogCves = catalogBaselineCves.concat(extraCatalogCves);

  const matchedCves = workingCatalogCves.filter(c => correlationsByCve.has(c.cve_id));

  // One shape for both arrays, so consumers iterate either without branching.
  const cveShape = (c, correlatedVia) => {
    // VEX-fixed CVEs stay in matched_cves so the audit trail keeps them.
    const vexStatus = (vexFixed && vexFixed.has(c.cve_id)) ? 'fixed' : null;
    return {
      cve_id: c.cve_id,
      // What the sbom → deep-dive feeds_into rules quantify over. The catalog
      // entry's explicit attack_class only — never inferred from the free-form
      // `type`, so an unclassified CVE stays null and the chain does not fire.
      attack_class: c.entry?.attack_class ?? null,
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
      correlated_via: correlatedVia,
      ...(vexStatus ? { vex_status: vexStatus } : {}),
    };
  };

  const matchedCveEntries = matchedCves.map(c => cveShape(c, correlationsByCve.get(c.cve_id)));
  const catalogBaselineEntries = workingCatalogCves.map(c => ({
    ...cveShape(c, null),
    note: 'Catalog-baseline entry — this CVE is in the playbook\'s scan coverage but no submitted evidence correlated to it. Not a statement that the operator is affected.',
  }));

  // Evidence-correlated matches only, reduced with max: RWEP is a worst-case
  // priority, so the most-exploitable CVE sets the base and summing bases would
  // double-count overlapping risk. A vex_status='fixed' CVE never drives it.
  const rwepEligible = matchedCves.filter(c => !(vexFixed && vexFixed.has(c.cve_id)));
  const baseRwep = rwepEligible.length ? Math.max(...rwepEligible.map(c => c.rwep_score)) : 0;

  // Each rwep_input.weight scales by a [0, 1] factor from the matched CVE's
  // catalog attributes. Negative weights keep their sign, so a patched CVE
  // deducts in full. `public_poc` and `ai_weaponization` are catalog aliases for
  // `poc_available` and `ai_factor`; both spellings resolve.
  const _factorScale = (factorName, cve, blastScore) => {
    if (!cve) return 0;
    switch (factorName) {
      case 'cisa_kev':
        return cve.cisa_kev === true ? 1 : 0;
      case 'active_exploitation': {
        const v = cve.active_exploitation || (cve.entry && cve.entry.active_exploitation);
        // The shared resolver, not an inline `ladder[v] ?? 0`: a stray-cased
        // value scales as the catalog scorer scales it, and an out-of-vocabulary
        // one raises RWEP_AE_UNRECOGNISED instead of silently zeroing.
        return scoring.activeExploitationMultiplier(v);
      }
      case 'poc_available':
      case 'public_poc': {
        const v = cve.entry?.poc_available ?? cve.poc_available;
        return v === true ? 1 : 0;
      }
      case 'ai_factor':
      case 'ai_weaponization': {
        const aiDisc = cve.ai_discovered === true || cve.entry?.ai_discovered === true;
        const aiWeap = cve.entry?.ai_assisted_weaponization === true;
        if (aiDisc && aiWeap) return 1.0;
        if (aiDisc || aiWeap) return 0.5;
        return 0;
      }
      case 'patch_available':
        return cve.entry?.patch_available === true ? 1 : 0;
      case 'live_patch_available':
        return cve.entry?.live_patch_available === true ? 1 : 0;
      case 'reboot_required':
        return cve.entry?.patch_required_reboot === true ? 1 : 0;
      case 'blast_radius': {
        if (typeof blastScore !== 'number' || blastScore < 0) return 0;
        return Math.min(1, blastScore / 5);
      }
      default:
        // An unrecognised factor fires binary, so a playbook shipping a novel
        // rwep_factor string does not silently zero out.
        return 1;
    }
  };

  // blast_radius_score: in-range is 'supplied', absent is null + 'default',
  // out of [0,5] is null + 'rejected' + runtime_error. Never a rubric entry —
  // the rubric's lowest row is the LOWEST-blast one, so a guess understates.
  const blastRubric = an.blast_radius_model?.scoring_rubric || [];
  let blastRadiusScore = null;
  let blastRadiusSignal = 'default';
  if (agentSignals.blast_radius_score !== undefined && agentSignals.blast_radius_score !== null) {
    const raw = agentSignals.blast_radius_score;
    const num = typeof raw === 'number' ? raw : parseFloat(raw);
    if (Number.isFinite(num) && num >= 0 && num <= 5) {
      blastRadiusScore = num;
      blastRadiusSignal = 'supplied';
    } else {
      blastRadiusSignal = 'rejected';
      if (Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, { kind: 'blast_radius_invalid', supplied: raw, reason: 'expected number in [0, 5]' }, { dedupeKey: e => String(e.supplied) });
      }
    }
  }
  // Factor scaling reads one CVE, resolved in order and annotated as
  // factor_cve_source: 'evidence' (an RWEP-eligible match), 'domain' (the
  // highest-rwep entry from domain.cve_refs), or 'none'.
  let factorCveSource = 'none';
  // Never fall back to matchedCves[0]: when every correlated CVE is VEX-fixed
  // the finding is remediated, and a patched CVE's KEV / exploitation / PoC
  // multipliers would lift the adjusted score above its base of 0.
  const allMatchedVexFixed = matchedCves.length > 0 && rwepEligible.length === 0;
  let factorCve = rwepEligible[0] || null;
  if (factorCve) {
    factorCveSource = 'evidence';
  } else if (!allMatchedVexFixed && workingCatalogCves.length > 0) {
    factorCve = workingCatalogCves.reduce((worst, c) =>
      (typeof c.rwep_score === 'number' && (!worst || c.rwep_score > worst.rwep_score)) ? c : worst,
    null);
    if (factorCve) factorCveSource = 'domain';
  }
  // A class-of-vulnerability playbook ships an empty domain.cve_refs, so
  // neither rung above yields a factorCve and every indicator would scale to
  // zero. Those apply the declared weight as-is, annotated 'class'.
  const _classScaleFallback = !factorCve && !allMatchedVexFixed;
  let adjustedRwep = baseRwep;
  const rwepBreakdown = [];
  for (const input of an.rwep_inputs || []) {
    const indicator = detectResult.indicators?.find(i => i.id === input.signal_id);
    const fired = indicator?.verdict === 'hit' || agentSignals[input.signal_id] === true;
    if (!fired) {
      rwepBreakdown.push({ signal_id: input.signal_id, rwep_factor: input.rwep_factor, weight_applied: 0, fired: false, factor_scale: 0 });
      continue;
    }
    // An operator-supplied blast score is honored in either mode.
    let scale, factorCveSourceForBreakdown;
    if (_classScaleFallback) {
      if (input.rwep_factor === 'blast_radius' && typeof blastRadiusScore === 'number') {
        scale = Math.min(1, blastRadiusScore / 5);
      } else {
        scale = 1;
      }
      factorCveSourceForBreakdown = 'class';
    } else {
      scale = _factorScale(input.rwep_factor, factorCve, blastRadiusScore);
      factorCveSourceForBreakdown = factorCveSource;
    }
    const applied = input.weight * scale;
    adjustedRwep += applied;
    rwepBreakdown.push({
      signal_id: input.signal_id,
      rwep_factor: input.rwep_factor,
      weight_applied: applied,
      weight_declared: input.weight,
      factor_scale: scale,
      factor_cve_source: factorCveSourceForBreakdown,
      fired: true,
    });
  }
  adjustedRwep = Math.max(0, Math.min(100, adjustedRwep));

  // The engine surfaces the theater test, the agent runs it, and the verdict
  // arrives as agentSignals.theater_verdict. The allowlist keeps free text out
  // of the CSAF / SARIF / OpenVEX bundles.
  const _theaterAllowlist = new Set(['clear', 'present', 'theater', 'pending_agent_run', 'unknown']);
  let theaterVerdict = agentSignals.theater_verdict;
  if (theaterVerdict === 'clean' || theaterVerdict === 'no_theater') theaterVerdict = 'clear';
  if (theaterVerdict !== undefined && theaterVerdict !== null && !_theaterAllowlist.has(theaterVerdict)) {
    if (Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, {
        kind: 'theater_verdict_invalid',
        supplied: theaterVerdict,
        allowed: Array.from(_theaterAllowlist),
      }, { dedupeKey: e => String(e.supplied) });
    }
    theaterVerdict = undefined;
  }
  if (!theaterVerdict && an.compliance_theater_check) {
    const cls = detectResult.classification;
    theaterVerdict = cls === 'not_detected' ? 'clear' : 'pending_agent_run';
  }
  theaterVerdict = theaterVerdict || (an.compliance_theater_check ? 'pending_agent_run' : null);

  // The playbook-declared gaps, emitted verbatim; analyze computes none.
  const frameworkGaps = an.framework_gap_mapping || [];

  // Escalation criteria evaluate below the result literal so their conditions
  // can reference `analyze.*` and `finding.*`.
  const escalations = [];
  const runtimeErrors = [];
  const evalCtxRoot = { _runErrors: runOpts._runErrors || runtimeErrors };

  const result = {
    phase: 'analyze',
    playbook_id: playbookId,
    directive_id: directiveId,
    // Every CVE entry carries CVSS, KEV, PoC, AI-discovery, active-exploitation
    // and patch state (AGENTS.md Hard Rule #1) from the catalog: a null means
    // the catalog lacks the value, never that the runner dropped it.
    matched_cves: matchedCveEntries,
    // Scan coverage, not an affected list; correlated_via is null throughout.
    catalog_baseline_cves: catalogBaselineEntries,
    rwep: { base: baseRwep, adjusted: adjustedRwep, breakdown: rwepBreakdown, threshold: directive ? resolvedPhase(playbook, directiveId, 'direct').rwep_threshold : null, _rwep_base_strategy: 'max' },
    blast_radius_score: blastRadiusScore,
    // 'supplied' | 'default' (none given, no rubric guess) | 'rejected'
    // (out of range; treated as default and surfaced as a runtime_error).
    blast_radius_signal: blastRadiusSignal,
    blast_radius_basis: blastRubric.find(r => r.blast_radius_score === blastRadiusScore) || null,
    compliance_theater_check: {
      claim: an.compliance_theater_check?.claim,
      audit_evidence: an.compliance_theater_check?.audit_evidence,
      reality_test: an.compliance_theater_check?.reality_test,
      verdict: theaterVerdict,
      // 'present' is a playbook synonym for 'theater'; both render the text.
      verdict_text: (theaterVerdict === 'theater' || theaterVerdict === 'present')
        ? an.compliance_theater_check?.theater_verdict_if_gap
        : null
    },
    framework_gap_mapping: frameworkGaps,
    escalations,
    // Underscore marks these render-internal: close()'s bundle builders read
    // them to emit SARIF results / OpenVEX statements / CSAF notes.
    _detect_indicators: detectResult.indicators || [],
    _detect_classification: detectResult.classification,
    // The path catalog feeds_into / escalation conditions actually write —
    // without the alias they resolve undefined and are silently dead.
    classification: detectResult.classification,
    vex: vexFilter ? {
      filter_applied: true,
      dropped_cve_count: vexDropped.length,
      dropped_cves: vexDropped,
      // A keep disposition — these stay in matched_cves, never in vexDropped.
      fixed_cves: vexFixedIds,
      fixed_cve_count: vexFixedIds.length,
      note: vexDropped.length
        ? `${vexDropped.length} CVE(s) dropped from analyze because the operator-supplied VEX statement marks them not_affected / false_positive. Vendor-fixed CVEs are NOT dropped — they remain in matched_cves with vex_status:'fixed'. The dropped CVEs remain in cve-catalog.json; the disposition lives in the VEX file.`
        : "VEX filter supplied; zero matches dropped (no CVEs in domain.cve_refs matched the VEX not-affected / false_positive set)."
    } : null,
    // The run-wide accumulator: every non-fatal anomaly, without the run dying.
    runtime_errors: (runOpts._runErrors && runOpts._runErrors.length) ? runOpts._runErrors.slice() : (runtimeErrors.length ? runtimeErrors.slice() : []),
    // Two flat-shape observations that targeted the same indicator id.
    signal_origins_with_collisions: Array.isArray(agentSignals?._signal_origins_collisions) ? agentSignals._signal_origins_collisions.slice() : (Array.isArray(detectResult?._signal_origins_collisions) ? detectResult._signal_origins_collisions.slice() : [])
  };

  // Wrapped so a malformed analyze result cannot abort escalation handling.
  let findingShape;
  try { findingShape = analyzeFindingShape(result); }
  catch (e) {
    if (Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, { kind: 'analyze_shape', message: (e && e.message) ? String(e.message) : String(e) }, { dedupeKey: x => x.message || '' });
    }
    findingShape = {};
  }
  for (const ec of an.escalation_criteria || []) {
    if (evalCondition(ec.condition, { ...firedIndicatorSignals(detectResult.indicators), ...agentSignals, ...evalCtxRoot, rwep: adjustedRwep, blast_radius_score: blastRadiusScore, theater_verdict: theaterVerdict, compliance_theater_check: result.compliance_theater_check, jurisdiction_obligations: (playbook.phases && playbook.phases.govern && playbook.phases.govern.jurisdiction_obligations) || [], analyze: result, matched_cve: result.matched_cves || [],
        // finding.* is two-sourced: analyzeFindingShape computes the
        // CVE/severity keys, while the descriptive ones the catalog gates on
        // (finding.includes_*, cve_class, tool_surface) are host-AI-asserted.
        // Agent fields merge UNDER the engine shape; !Array.isArray rejects an
        // array's numeric-index noise.
        finding: { ...(agentSignals.finding && typeof agentSignals.finding === 'object' && !Array.isArray(agentSignals.finding) ? agentSignals.finding : {}), ...findingShape } }, playbook)) {
      escalations.push({ condition: ec.condition, action: ec.action, target_playbook: ec.target_playbook || null });
    }
  }
  // Escalation evaluation may have appended diagnostics; refresh the snapshot.
  result.runtime_errors = (runOpts._runErrors && runOpts._runErrors.length) ? runOpts._runErrors.slice() : (runtimeErrors.length ? runtimeErrors.slice() : []);
  return result;
}

// The VEX disposition sets of a CycloneDX/OpenVEX document, which must not
// collapse into one "drop" set: not_affected / false_positive drop from
// matched_cves, while fixed / resolved are KEPT and annotated. Returns the drop
// set as a Set with the fixed set attached as its own `.fixed` property.
function vexFilterFromDoc(doc) {
  const out = new Set();
  const fixed = new Set();
  if (!doc || typeof doc !== 'object') {
    out.fixed = fixed;
    return out;
  }

  for (const v of (doc.vulnerabilities || [])) {
    const state = v.analysis && v.analysis.state;
    if (state === 'not_affected' || state === 'false_positive') {
      if (v.id) out.add(v.id);
    } else if (state === 'resolved') {
      if (v.id) fixed.add(v.id);
    }
  }
  for (const s of (doc.statements || [])) {
    const id = s.vulnerability && (s.vulnerability['@id'] || s.vulnerability.name || s.vulnerability);
    if (typeof id !== 'string') continue;
    if (s.status === 'not_affected') out.add(id);
    else if (s.status === 'fixed') fixed.add(id);
  }
  out.fixed = fixed;
  return out;
}

// Cap on a word boundary and mark the cut, so a truncated line reads as
// truncated. The full text stays in the envelope's reason / remediation.
function capSummary(s, max = 240) {
  if (typeof s !== 'string' || s.length <= max) return s;
  const slice = s.slice(0, max - 1);
  const lastSpace = slice.lastIndexOf(' ');
  const base = lastSpace > max - 40 ? slice.slice(0, lastSpace) : slice;
  return base.replace(/[\s—.,;:-]+$/, '') + '…';
}

function validate(playbookId, directiveId, analyzeResult, agentSignals = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  // Remediation-path preconditions run through the same evalCondition as
  // analyze and close, so this context must expose the same engine-computed
  // roots: one gating on `rwep`, `finding.severity` or `matched_cve.*`
  // otherwise resolves null and can never be satisfied. agentSignals spread
  // FIRST so engine values win on collision.
  const govern = (playbook.phases && playbook.phases.govern) || {};
  let findingShape = {};
  try { findingShape = analyzeFindingShape(analyzeResult || {}); } catch { findingShape = {}; }
  const evalCtx = {
    // Lowest precedence, so an indicator id resolves on the collector path.
    ...firedIndicatorSignals(analyzeResult && analyzeResult._detect_indicators),
    ...agentSignals,
    rwep: analyzeResult && analyzeResult.rwep ? analyzeResult.rwep.adjusted : undefined,
    blast_radius_score: analyzeResult ? analyzeResult.blast_radius_score : undefined,
    theater_verdict: analyzeResult && analyzeResult.compliance_theater_check ? analyzeResult.compliance_theater_check.verdict : undefined,
    compliance_theater_check: analyzeResult ? analyzeResult.compliance_theater_check : undefined,
    jurisdiction_obligations: govern.jurisdiction_obligations || [],
    matched_cve: (analyzeResult && analyzeResult.matched_cves) || [],
    analyze: analyzeResult,
    finding: { ...(agentSignals.finding && typeof agentSignals.finding === 'object' && !Array.isArray(agentSignals.finding) ? agentSignals.finding : {}), ...findingShape },
    ...(runOpts._runErrors ? { _runErrors: runOpts._runErrors } : {}),
  };
  const v = resolvedPhase(playbook, directiveId, 'validate');

  // Lower priority number sorts first, per the schema convention.
  const paths = (v.remediation_paths || []).slice().sort((a, b) => a.priority - b.priority);
  // The indicators that fired, so a remediation linked to one through
  // for_signals can outrank the bare priority-1 default.
  const firedSignalIds = new Set(
    (analyzeResult._detect_indicators || []).filter(i => i.verdict === 'hit').map(i => i.id)
  );
  const addressesFired = (p) =>
    Array.isArray(p.for_signals) && p.for_signals.some(s => firedSignalIds.has(s));
  const considered = [];
  const satisfiedIds = new Set();
  for (const p of paths) {
    const pcResult = (p.preconditions || []).map(expr => ({
      expr,
      satisfied: evalCondition(expr, evalCtx, playbook),
      submitted: agentSignals[expressionKey(expr)] !== undefined
    }));
    const allSatisfied = pcResult.every(x => x.satisfied);
    if (allSatisfied) satisfiedIds.add(p.id);
    considered.push({ id: p.id, priority: p.priority, all_satisfied: allSatisfied, addresses_fired_signal: addressesFired(p), preconditions: pcResult });
  }
  // paths is priority-sorted, so each `find` takes the highest-priority match.
  // Relevance to a fired indicator outranks a satisfied-but-unrelated path. The
  // last rung is priority-1, so something is always proposed.
  const selected =
    paths.find(p => addressesFired(p) && satisfiedIds.has(p.id))
    || paths.find(addressesFired)
    || paths.find(p => satisfiedIds.has(p.id))
    || paths[0]
    || null;

  // regression_next_run stays the plain ISO string CSAF and attestation
  // consumers read; the structured form sits alongside it.
  const triggers = v.regression_trigger || [];
  const regressionResult = computeRegressionNextRun(triggers);

  let nextRunReason = null;
  if (!regressionResult.next_run) {
    if (triggers.length === 0) nextRunReason = 'no_regression_triggers_declared';
    else if (regressionResult.event_triggers.length && !regressionResult.unparseable.length) {
      nextRunReason = 'all_triggers_event_driven';
    } else if (regressionResult.unparseable.length && !regressionResult.event_triggers.length) {
      nextRunReason = 'all_triggers_unparseable';
    } else {
      nextRunReason = 'no_calendar_interval_resolved';
    }
  }

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
    regression_next_run: regressionResult.next_run,
    regression_next_run_reason: nextRunReason,
    regression_event_triggers: regressionResult.event_triggers,
    regression_unparseable_triggers: regressionResult.unparseable,
  };
}

// `<N>d`, `<N>wk`, `<N>mo` and `<N>yr` return a date, months and years by
// Date.setMonth / setFullYear semantics. `on_event` computes no date and
// surfaces in regression_event_triggers[]; anything else is { unparseable }.
function parseInterval(intervalStr, now) {
  if (!intervalStr || typeof intervalStr !== 'string') return null;
  const s = intervalStr.trim();
  if (s === 'on_event') return { event: true };
  let m = s.match(/^(\d+)d$/);
  if (m) return { date: new Date(now.getTime() + parseInt(m[1], 10) * 24 * 3600 * 1000) };
  m = s.match(/^(\d+)wk$/);
  if (m) return { date: new Date(now.getTime() + parseInt(m[1], 10) * 7 * 24 * 3600 * 1000) };
  m = s.match(/^(\d+)mo$/);
  if (m) {
    const d = new Date(now.getTime());
    d.setMonth(d.getMonth() + parseInt(m[1], 10));
    return { date: d };
  }
  m = s.match(/^(\d+)yr$/);
  if (m) {
    const d = new Date(now.getTime());
    d.setFullYear(d.getFullYear() + parseInt(m[1], 10));
    return { date: d };
  }
  return { unparseable: s };
}

function computeRegressionNextRun(triggers) {
  const now = new Date();
  let soonest = null;
  const eventTriggers = [];
  const unparseable = [];
  for (const t of triggers) {
    const parsed = parseInterval(t.interval, now);
    if (!parsed) continue;
    if (parsed.event) {
      // Shipped playbooks key the trigger string as `condition`; `trigger` and
      // `event` are the spellings external submissions and fixtures use.
      eventTriggers.push({ interval: t.interval, trigger: t.trigger || t.event || t.condition || null });
      continue;
    }
    if (parsed.unparseable) {
      unparseable.push({ interval: parsed.unparseable, trigger: t.trigger || t.event || t.condition || null });
      continue;
    }
    if (parsed.date && (!soonest || parsed.date < soonest)) soonest = parsed.date;
  }
  return {
    next_run: soonest ? soonest.toISOString() : null,
    event_triggers: eventTriggers,
    unparseable: unparseable,
  };
}

// Phase 7. The closure artifacts: the evidence_package (signed when a session
// key is present), the learning_loop lesson, notification_actions with deadlines
// from clock_starts + window_hours, the auditor-ready exception language, the
// regression schedule and the feeds_into chaining suggestions.
function close(playbookId, directiveId, analyzeResult, validateResult, agentSignals = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const c = resolvedPhase(playbook, directiveId, 'close');
  const g = resolvedPhase(playbook, directiveId, 'govern');
  // run() mints session_id once and threads it here, so CSAF tracking.id, the
  // OpenVEX @id and the on-disk attestation name are one identifier.
  const sessionId = runOpts.session_id || crypto.randomBytes(8).toString('hex');

  // One frozen epoch for every timestamp surface below, so notification_actions,
  // regression_schedule and the bundle emitter agree on the same instant.
  const deterministic = runOpts.bundleDeterministic === true;
  const frozenEpoch = deterministic ? resolveFrozenEpoch(runOpts, playbook) : null;

  // A playbook's notification_actions entry carries only obligation_ref,
  // recipient and draft_notification; jurisdiction, regulation, window_hours
  // and evidence_required merge in from the govern obligation below. The
  // analyze_complete and validate_complete clocks auto-start only when a
  // populated result proves their phase ran in this pass.
  const phaseFlags = {
    analyze_complete: !!(analyzeResult && typeof analyzeResult === 'object'),
    validate_complete: !!(validateResult && typeof validateResult === 'object'),
  };

  // Nothing downstream guards the analyze result's container shape: every
  // bundle format maps over `analyze.matched_cves` directly, and so does
  // analyzeFindingShape, so a non-object result or a non-array matched_cves
  // throws before phase 7 produces any output at all. Normalizing once, here,
  // is what makes the whole phase survive it — the run still emits an evidence
  // bundle and the shape failure is readable on runtime_errors. The container
  // and its elements are both normalized: every bundle builder dereferences an
  // element, so one null inside an otherwise well-formed array aborts the phase
  // exactly as a non-array container does.
  const shapeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
  const analyzeIsObject = !!analyzeResult && typeof analyzeResult === 'object' && !Array.isArray(analyzeResult);
  if (!analyzeIsObject || !Array.isArray(analyzeResult.matched_cves)) {
    pushRunError(runOpts._runErrors, {
      kind: 'analyze_shape',
      message: analyzeIsObject
        ? `analyze.matched_cves is ${shapeOf(analyzeResult.matched_cves)}, expected an array; treated as empty`
        : `analyze result is ${shapeOf(analyzeResult)}, expected an object; treated as empty`,
    }, { dedupeKey: x => x.message || '' });
    // A copy, so close() reports the caller's malformed result without
    // rewriting it underneath them.
    analyzeResult = { ...(analyzeIsObject ? analyzeResult : {}), matched_cves: [] };
  } else {
    // Dropped rather than repaired: a consumer cannot read a CVE id off a null,
    // and inventing a placeholder entry would put a finding in the evidence
    // bundle that the analyze phase never produced.
    const usable = (e) => !!e && typeof e === 'object' && !Array.isArray(e);
    const dropped = analyzeResult.matched_cves.filter((e) => !usable(e));
    if (dropped.length) {
      pushRunError(runOpts._runErrors, {
        kind: 'analyze_shape',
        message: `analyze.matched_cves holds ${dropped.length} malformed element(s) (${[...new Set(dropped.map(shapeOf))].join(', ')}); they are dropped and the remaining ${analyzeResult.matched_cves.length - dropped.length} are used`,
      }, { dedupeKey: x => x.message || '' });
      analyzeResult = { ...analyzeResult, matched_cves: analyzeResult.matched_cves.filter(usable) };
    }
  }

  // The residual guard for the four sites that interpolate the finding shape —
  // the notification draft, the auditor-ready exception language, the
  // learning-loop lesson and the feeds_into finding context. The normalization
  // above removes the shapes analyzeFindingShape is known to throw on; this
  // catches anything it still throws on, degrading those four fields to
  // `<MISSING:…>` and putting the throw on runtime_errors rather than aborting
  // the phase.
  const safeFindingShape = () => {
    try { return analyzeFindingShape(analyzeResult); }
    catch (e) {
      pushRunError(runOpts._runErrors,
        { kind: 'analyze_shape', message: (e && e.message) ? String(e.message) : String(e) },
        { dedupeKey: x => x.message || '' });
      return {};
    }
  };

  const enrichNotification = (na) => {
    const obligation = (g.jurisdiction_obligations || []).find(o =>
      o && typeof o === 'object' &&
      `${o.jurisdiction}/${o.regulation} ${o.window_hours}h` === na.obligation_ref
    );
    // An unresolved obligation_ref would leave the record's fields all null.
    if (!obligation && na && typeof na.obligation_ref === 'string' && na.obligation_ref &&
        Array.isArray(runOpts && runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, { kind: 'unresolved_obligation_ref', obligation_ref: na.obligation_ref }, { dedupeKey: x => x.obligation_ref || '' });
    }
    // computeClockStart checks operator_consent.explicit before auto-stamping,
    // and takes the engine classification so an engine-confirmed detection
    // starts the clock without a separately submitted one.
    const engineClassification = analyzeResult?._detect_classification || null;
    const clockStart = obligation
      ? computeClockStart(obligation.clock_starts, agentSignals, runOpts, engineClassification, phaseFlags, frozenEpoch)
      : null;
    // Guarded independently of computeClockStart so no path reaches
    // new Date(NaN).toISOString() and crashes the close phase.
    const clockValid = clockStart instanceof Date && !Number.isNaN(clockStart.getTime());
    // An auto-startable event that fired without --ack leaves the record
    // visibly waiting on acknowledgement rather than silently stalled.
    const autoStartEvent = obligation
      && (obligation.clock_starts === 'detect_confirmed'
        || obligation.clock_starts === 'analyze_complete'
        || obligation.clock_starts === 'validate_complete');
    const eventReady = obligation && (
      (obligation.clock_starts === 'detect_confirmed'
        && (agentSignals?.detection_classification === 'detected' || engineClassification === 'detected'))
      || (obligation.clock_starts === 'analyze_complete' && phaseFlags.analyze_complete)
      || (obligation.clock_starts === 'validate_complete' && phaseFlags.validate_complete)
    );
    const clockPendingAck = !clockValid
      && autoStartEvent
      && eventReady
      && !(runOpts && runOpts.operator_consent && runOpts.operator_consent.explicit === true);
    // The playbook is not schema-validated at runtime, and a non-number
    // window_hours computes `getTime() + NaN`, crashing close().
    const windowValid = obligation && typeof obligation.window_hours === 'number' && Number.isFinite(obligation.window_hours);
    const deadline = obligation && clockValid && windowValid
      ? new Date(clockStart.getTime() + obligation.window_hours * 3600 * 1000).toISOString()
      : 'pending_clock_start_event';
    // Already a runtime_error above; the record is dropped rather than
    // polluting the deadline list with a null-jurisdiction entry.
    if (!obligation && na && typeof na.obligation_ref === 'string' && na.obligation_ref) {
      return null;
    }
    return {
      ...na,
      // Each entry must stand alone: deadline, routing, evidence checklist.
      jurisdiction: obligation?.jurisdiction || null,
      regulation: obligation?.regulation || null,
      obligation_type: obligation?.obligation || null,
      window_hours: obligation?.window_hours ?? null,
      clock_start_event: obligation?.clock_starts || null,
      // clockValid, not optional chaining: `?.` only short-circuits
      // null/undefined, so an Invalid Date would still reach .toISOString().
      clock_started_at: clockValid ? clockStart.toISOString() : null,
      ...(clockPendingAck ? { clock_pending_ack: true } : {}),
      deadline,
      // Alias matching compliance-team vocabulary.
      notification_deadline: deadline,
      // What the regulator expects attached, per the obligation.
      evidence_required: obligation?.evidence_required || na.evidence_attached || [],
      // Which template vars failed to resolve; empty when all rendered.
      ...(function () {
        const missing = [];
        // safeFindingShape, not analyzeFindingShape: a malformed analyze result
        // must not bring down close(); the failure surfaces on runtime_errors.
        const findingShape = safeFindingShape();
        const draft = interpolate(
          na.draft_notification,
          { ...agentSignals, ...findingShape },
          missing,
        );
        return { draft_notification: draft, missing_interpolation_vars: missing };
      })(),
    };
  };
  const notificationActions = (c.notification_actions || []).map(enrichNotification).filter(Boolean);

  // A notify obligation with no matching close.notification_actions entry would
  // leave its regulatory clock invisible. The synthesized record carries no
  // draft and is marked synthesized_from_obligation.
  const coveredObligationRefs = new Set((c.notification_actions || []).map(na => na.obligation_ref));
  for (const o of (g.jurisdiction_obligations || [])) {
    if (!o || typeof o !== 'object') continue; // skip a null/malformed obligation rather than crash close() during synthesis
    if (!String(o.obligation || '').startsWith('notify')) continue;
    // A non-number window_hours would synthesize a "…/… undefinedh" ref that
    // can never produce a deadline; surface it and skip the synthesis.
    if (typeof o.window_hours !== 'number' || !Number.isFinite(o.window_hours)) {
      if (Array.isArray(runOpts && runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, { kind: 'malformed_obligation_window_hours', obligation: `${o.jurisdiction}/${o.regulation}` }, { dedupeKey: x => x.obligation || '' });
      }
      continue;
    }
    const ref = `${o.jurisdiction}/${o.regulation} ${o.window_hours}h`;
    if (coveredObligationRefs.has(ref)) continue;
    const synthesized = enrichNotification({
      obligation_ref: ref,
      recipient: null,
      draft_notification: null,
      synthesized_from_obligation: true,
    });
    if (synthesized) notificationActions.push(synthesized);
  }

  let exception = null;
  if (c.exception_generation) {
    const closeEvalCtx = runOpts._runErrors ? { ...agentSignals, _runErrors: runOpts._runErrors } : agentSignals;
    const triggered = evalCondition(c.exception_generation.trigger_condition, closeEvalCtx, playbook);
    if (triggered) {
      const t = c.exception_generation.exception_template;
      // Exception-template tokens are operator-fill values analyzeFindingShape
      // does not supply, so the auditor-ready language routinely renders
      // `<MISSING:…>`. missing_interpolation_vars names which.
      const exMissing = [];
      // safeFindingShape, like the other three shape consumers. The feeds_into
      // context below reports the same throw on every close(), so this site's
      // own disposition is not separately observable — it is uniform so a
      // future reader does not read the bare catch as a deliberate exemption.
      const findingShape = safeFindingShape();
      exception = {
        scope: interpolate(t.scope, { ...agentSignals, ...findingShape }, exMissing),
        duration: t.duration,
        compensating_controls: t.compensating_controls,
        risk_acceptance_owner: t.risk_acceptance_owner,
        auditor_ready_language: interpolate(t.auditor_ready_language, {
          ...agentSignals,
          ...findingShape,
          framework_id: playbook.domain.frameworks_in_scope[0] || 'unspecified',
          control_id: analyzeResult.framework_gap_mapping?.[0]?.claimed_control || 'unspecified',
          ciso_name: agentSignals.ciso_name || '<CISO NAME>',
          // Deterministic mode roots the auditor-facing date in the frozen
          // epoch, so two runs over the same evidence agree.
          acceptance_date: (deterministic ? frozenEpoch : new Date().toISOString()).slice(0, 10),
          duration_expiry: agentSignals.duration_expiry || 'until vendor patch'
        }, exMissing),
        missing_interpolation_vars: exMissing,
      };
      // Also on runtime_errors, so JSON/ci consumers see the gap without
      // walking into the exception object.
      if (exMissing.length && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors,
          { kind: 'exception_unresolved_placeholders', placeholders: exMissing.slice() },
          { dedupeKey: e => (e.placeholders || []).join(',') });
      }
    }
  }

  const primaryFormat = c.evidence_package?.bundle_format || 'csaf-2.0';
  const extraFormats = Array.isArray(agentSignals._bundle_formats)
    ? agentSignals._bundle_formats.filter(f => f !== primaryFormat)
    : [];
  // Each bundle is built once, so bundle_body and bundles_by_format[primary]
  // share identity — a second build would crystallise a fresh Date.now().
  const evidencePackage = c.evidence_package ? (() => {
    // Deterministic mode pins issuedAt so every CSAF tracking date and every
    // OpenVEX timestamp collapses to one byte-stable value.
    const issuedAt = deterministic ? frozenEpoch : new Date().toISOString();
    const builtFormats = new Map();
    const buildOnce = (format) => {
      if (!builtFormats.has(format)) {
        builtFormats.set(format, buildEvidenceBundle(format, playbook, analyzeResult, validateResult, agentSignals, sessionId, issuedAt, runOpts));
      }
      return builtFormats.get(format);
    };
    const primaryBody = buildOnce(primaryFormat);
    // Always an object keyed by the primary format, even for a single format,
    // so consumers iterate uniformly instead of shimming a null.
    const byFormat = Object.fromEntries(
      [primaryFormat, ...extraFormats].map(f => [f, buildOnce(f)])
    );
    return {
      bundle_format: primaryFormat,
      contents: c.evidence_package.contents || [],
      destination: c.evidence_package.destination || 'local_only',
      signed: c.evidence_package.signed !== false,
      bundle_body: primaryBody,
      bundles_by_format: byFormat,
    };
  })() : null;

  if (evidencePackage && evidencePackage.signed && runOpts.session_key) {
    const body = JSON.stringify(evidencePackage.bundle_body);
    evidencePackage.signature = crypto
      .createHmac('sha256', runOpts.session_key)
      .update(body)
      .digest('hex');
    evidencePackage.signature_algorithm = 'HMAC-SHA256-session-key';
  } else if (evidencePackage && evidencePackage.signed) {
    evidencePackage.signature = null;
    evidencePackage.signature_pending = 'No session_key provided. Sign with Ed25519 via `node $(exceptd path)/lib/sign.js sign-evidence <bundle.json>` post-emit (contributor checkout) or `exceptd doctor --fix` to enable signing.';
  }

  const lesson = c.learning_loop?.enabled ? {
    enabled: true,
    attack_vector: interpolate(c.learning_loop.lesson_template.attack_vector, safeFindingShape()),
    control_gap: c.learning_loop.lesson_template.control_gap,
    framework_gap: c.learning_loop.lesson_template.framework_gap,
    new_control_requirement: c.learning_loop.lesson_template.new_control_requirement,
    feeds_back_to_skills: c.learning_loop.feeds_back_to_skills || [],
    proposed_for_zeroday_lessons_id: `lesson-${playbook._meta.id}-${sessionId}`
  } : { enabled: false };

  // Re-derived from the frozen epoch: taken from wall-clock-at-validate-time,
  // two runs diverge by the interval between their validate() calls.
  const regressionSchedule = c.regression_schedule ? (() => {
    let nextRun = validateResult.regression_next_run;
    if (deterministic) {
      // Against the validate phase's triggers — close declares none of its own.
      const v = resolvedPhase(playbook, directiveId, 'validate');
      nextRun = frozenRegressionNextRun(v.regression_trigger || [], new Date(frozenEpoch));
    }
    return {
      next_run: nextRun,
      trigger: c.regression_schedule.trigger,
      notify_on_skip: c.regression_schedule.notify_on_skip !== false
    };
  })() : null;

  // The whole analyze result, so conditions can reference `analyze.*` paths.
  const feedsCtx = {
    // Lowest precedence, so a feeds_into condition written as
    // `<indicator-id> == true` resolves on the standard collector path.
    ...firedIndicatorSignals(analyzeResult && analyzeResult._detect_indicators),
    // Operator signals FIRST so the engine keys below win: a submitted
    // signals.rwep must not override the value the condition tests.
    ...agentSignals,
    rwep: analyzeResult.rwep?.adjusted,
    // Bare-token parity with the escalation context: catalog conditions write
    // these unqualified, and without the top-level keys resolvePath returns
    // null, so `null >= 4` kills the chain whatever the engine computed.
    blast_radius_score: analyzeResult.blast_radius_score,
    theater_verdict: analyzeResult.compliance_theater_check?.verdict,
    compliance_theater_check: analyzeResult.compliance_theater_check,
    jurisdiction_obligations: (g && g.jurisdiction_obligations) || (playbook.phases && playbook.phases.govern && playbook.phases.govern.jurisdiction_obligations) || [],
    // theater_score follows lib/framework-gap.js: high means more theater, so a
    // gap-present verdict scores 100 and 'clear' scores 0. 'present' is the
    // allowlisted synonym for 'theater' and must score with it.
    theater_score: (analyzeResult.compliance_theater_check?.verdict === 'theater' || analyzeResult.compliance_theater_check?.verdict === 'present') ? 100 : 0,
    // The head the sbom feeds_into quantifiers re-root at; without the
    // top-level key it resolves null and the deep-dive chains stay dead.
    matched_cve: analyzeResult.matched_cves || [],
    analyze: analyzeResult,
    validate: validateResult,
    // Same two-sourced finding.* shape and guards as the escalation context.
    finding: { ...(agentSignals.finding && typeof agentSignals.finding === 'object' && !Array.isArray(agentSignals.finding) ? agentSignals.finding : {}), ...safeFindingShape() },
    // Without the accumulator, a feeds_into condition failure never reaches
    // analyze.runtime_errors[].
    ...(runOpts._runErrors ? { _runErrors: runOpts._runErrors } : {})
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
    // Alias for notification_actions. jurisdiction_clocks_count mirrors
    // ci.summary.jurisdiction_clocks_started — those whose clock has started.
    jurisdiction_notifications: notificationActions,
    jurisdiction_clocks_count: notificationActions.filter(n => n && n.clock_started_at != null).length,
    exception: exception,
    regression_schedule: regressionSchedule,
    feeds_into: feeds,
    // The runner never chains into feeds_into itself; the agent or operator
    // decides. Stated on the result so no consumer assumes a handoff happened.
    feeds_into_auto_chained: false,
  };
}

// Severity ladder for active_exploitation, higher being worse. Every value in
// scoring.js's vocabulary must appear — an omitted one falls to `?? -1`, loses
// to the -1 start, and drops out of the reduction entirely.
const ACTIVE_EXPLOITATION_RANK = { none: 0, theoretical: 1, unknown: 2, suspected: 3, confirmed: 4 };

function worstActiveExploitation(matchedCves) {
  let worst = null;
  let worstRank = -1;
  for (const c of (matchedCves || [])) {
    const v = c && c.active_exploitation;
    if (!v) continue;
    const rank = ACTIVE_EXPLOITATION_RANK[v] ?? -1;
    if (rank > worstRank) { worst = v; worstRank = rank; }
  }
  // An empty or all-unrecognized set is 'none': a draft must not assert
  // 'unknown' exploitation it never observed.
  return worst || 'none';
}

// The value playbooks gate on as `finding.severity` in feeds_into and
// escalation_criteria; without it those conditions resolve undefined.
function severityForRwep(rwep) {
  const r = typeof rwep === 'number' ? rwep : 0;
  if (r >= 80) return 'critical';
  if (r >= 50) return 'high';
  if (r >= 20) return 'medium';
  return 'low';
}

function analyzeFindingShape(a) {
  const matched = a.matched_cves || [];
  const rwepAdjusted = a.rwep?.adjusted ?? 0;
  return {
    matched_cve_ids: matched.map(c => c.cve_id).join(', '),
    // The joined form is what notification-draft templates interpolate as
    // `${matched_cve_ids}`; this is for consumers that want to iterate.
    matched_cve_ids_array: matched.map(c => c.cve_id),
    matched_cve_count: matched.length,
    kev_listed_count: matched.filter(c => c.cisa_kev).length,
    // Worst rank, not the first truthy entry: a draft reporting 'suspected'
    // while another CVE is 'confirmed' understates the threat. VEX-fixed CVEs
    // are excluded — a draft must not source exploitation from a fixed CVE.
    active_exploitation: worstActiveExploitation(matched.filter(c => c.vex_status !== 'fixed')),
    rwep_adjusted: rwepAdjusted,
    rwep_base: a.rwep?.base ?? 0,
    severity: severityForRwep(rwepAdjusted),
    blast_radius_score: a.blast_radius_score ?? 0,
    framework_id_first: a.framework_gap_mapping?.[0]?.framework || null,
    control_id_first: a.framework_gap_mapping?.[0]?.claimed_control || null
  };
}

// A vulnerability identifier's issuing authority and canonical advisory URL. An
// id with no public per-id page, and an unrecognised prefix, both resolve to a
// null helpUri rather than a fabricated link: an nvd.nist.gov URL 404s for a
// non-CVE id. The CSAF ids[] branch (csafIdsFor) carries the same knowledge.
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;
function advisoryAuthorityFor(id) {
  if (typeof id !== 'string' || !id) return { system_name: null, helpUri: null };
  if (CVE_ID_RE.test(id)) return { system_name: 'NVD', helpUri: `https://nvd.nist.gov/vuln/detail/${id}` };
  if (id.startsWith('GHSA-')) return { system_name: 'GHSA', helpUri: `https://github.com/advisories/${id}` };
  if (id.startsWith('OSV-')) return { system_name: 'OSV', helpUri: `https://osv.dev/vulnerability/${id}` };
  if (id.startsWith('RUSTSEC-')) return { system_name: 'RUSTSEC', helpUri: `https://rustsec.org/advisories/${id}.html` };
  if (id.startsWith('SNYK-')) return { system_name: 'Snyk', helpUri: `https://security.snyk.io/vuln/${id}` };
  if (id.startsWith('MAL-')) return { system_name: 'Malicious-Package', helpUri: null };
  return { system_name: 'exceptd-unknown', helpUri: null };
}

// Route a vulnerability identifier to its registered URN namespace, or to the
// private `urn:exceptd:advisory:` one, so every OpenVEX statement carries a
// valid IRI per RFC 8141.
function vulnIdToUrn(id) {
  if (typeof id !== 'string' || id.length === 0) return `urn:exceptd:advisory:${urnSlug(id)}`;
  // Registered identifiers keep their canonical case so the @id matches the
  // OpenVEX `name` / CSAF id; the private namespace slugs text and lowercases.
  const canonical = urnSlug(id, true);
  if (/^CVE-/i.test(id)) return `urn:cve:${canonical}`;
  if (/^GHSA-/i.test(id)) return `urn:ghsa:${canonical}`;
  if (/^RUSTSEC-/i.test(id)) return `urn:rustsec:${canonical}`;
  if (/^MAL-/i.test(id)) return `urn:malicious-package:${canonical}`;
  return `urn:exceptd:advisory:${urnSlug(id)}`;
}

// Build a CSAF product_tree.branches[] from the catalog's `affected_products`
// records, falling back to a heuristic parse of `affected_components[]`.
// Unparseable components raise `csaf_branch_unparseable` and drop; each level
// sorts alphabetically for determinism. Returns { branches, productIds,
// cveProductIds }, the last binding each CVE to the leaves it contributed so
// the caller can reference them from vulnerabilities[].product_status.
function buildCsafBranches(matchedCves, runOpts) {
  const tree = new Map();
  // Without the per-CVE binding the version leaves are referenced by nothing,
  // and product_status correlates only to the synthetic product.
  const leafKey = (vendor, product, version) => JSON.stringify([vendor, product, version]);
  const cveLeaves = new Map(); // cve_id → Set<leafKey>
  const addLeaf = (vendor, product, version, cveId) => {
    if (!vendor || !product || !version) return;
    if (!tree.has(vendor)) tree.set(vendor, new Map());
    const products = tree.get(vendor);
    if (!products.has(product)) products.set(product, new Set());
    products.get(product).add(version);
    if (cveId) {
      if (!cveLeaves.has(cveId)) cveLeaves.set(cveId, new Set());
      cveLeaves.get(cveId).add(leafKey(vendor, product, version));
    }
  };

  // What sits between package and version in the catalog's dominant
  // `package OP version` shape. These are never package names.
  const RANGE_OP_RE = /^(<=|>=|==|!=|~>|<|>|=|~|\^)$/;

  // Returns { vendor, product, version } or null.
  const parseComponentString = (s) => {
    if (typeof s !== 'string' || !s.trim()) return null;
    const trimmed = s.trim();
    // `vendor/product@version`
    let m = trimmed.match(/^([^/\s@]+)\/([^/\s@]+)@(.+)$/);
    if (m) return { vendor: m[1], product: m[2], version: m[3].trim() };
    const parts = trimmed.split(/\s+/);
    // `package OP version`. The operator belongs to the version qualifier
    // ('>= 4.14'), not the product_name — naming the product after '>=' or '<'
    // corrupts the CSAF affected-product list.
    if (parts.length >= 3 && RANGE_OP_RE.test(parts[1])) {
      const product = parts[0];
      const versionTokens = parts.slice(1);
      // The shape only holds when the trailing token really is a version.
      const lastTok = versionTokens[versionTokens.length - 1];
      if (/^v?\d/.test(lastTok)) {
        return { vendor: product, product, version: versionTokens.join(' ') };
      }
    }
    // `vendor product version`, where the last token starts with a digit or `v\d`.
    if (parts.length >= 3) {
      const last = parts[parts.length - 1];
      if (/^v?\d/.test(last)) {
        return { vendor: parts[0], product: parts.slice(1, -1).join(' '), version: last };
      }
    }
    return null;
  };

  for (const c of matchedCves || []) {
    if (Array.isArray(c.affected_products) && c.affected_products.length > 0) {
      for (const ap of c.affected_products) {
        if (ap && typeof ap === 'object' && ap.vendor && ap.product && ap.version) {
          addLeaf(String(ap.vendor), String(ap.product), String(ap.version), c.cve_id);
        }
      }
      continue;
    }
    const components = Array.isArray(c.affected_components) ? c.affected_components
      : (Array.isArray(c.affected_versions) ? c.affected_versions : []);
    for (const comp of components) {
      const parsed = parseComponentString(comp);
      if (parsed) {
        addLeaf(parsed.vendor, parsed.product, parsed.version, c.cve_id);
      } else if (typeof comp === 'string' && comp.trim() && runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'csaf_branch_unparseable',
          component: String(comp),
          cve_id: c.cve_id || null,
        }, { dedupeKey: e => `${e.cve_id || ''}::${e.component}` });
      }
    }
  }

  const productIds = [];
  const leafKeyToPid = new Map();
  let pidCounter = 0;
  const vendors = Array.from(tree.keys()).sort();
  const branches = vendors.map(vendor => {
    const products = tree.get(vendor);
    const productNames = Array.from(products.keys()).sort();
    return {
      category: 'vendor',
      name: vendor,
      branches: productNames.map(product => {
        const versions = Array.from(products.get(product)).sort();
        return {
          category: 'product_name',
          name: product,
          branches: versions.map(version => {
            const pid = `CSAFPID-${pidCounter++}`;
            productIds.push({ vendor, product, version, product_id: pid });
            leafKeyToPid.set(leafKey(vendor, product, version), pid);
            return {
              category: 'product_version',
              name: version,
              product: {
                name: `${vendor}/${product}@${version}`,
                product_id: pid,
              },
            };
          }),
        };
      }),
    };
  });
  const cveProductIds = {};
  for (const [cveId, keys] of cveLeaves.entries()) {
    const pids = [];
    for (const k of keys) { const pid = leafKeyToPid.get(k); if (pid) pids.push(pid); }
    if (pids.length) cveProductIds[cveId] = pids.sort();
  }
  return { branches, productIds, cveProductIds };
}

// Slugify into a URN-safe segment (RFC 8141 NSS); empty input returns
// 'unknown', never a zero-length segment. The NSS is case-sensitive, so
// preserveCase keeps a registered identifier matching its OpenVEX / CSAF form.
function urnSlug(s, preserveCase = false) {
  if (s == null) return 'unknown';
  let str = String(s);
  if (!preserveCase) str = str.toLowerCase();
  const slug = str
    .replace(preserveCase ? /[^A-Za-z0-9_-]+/g : /[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return slug.length ? slug : 'unknown';
}

// The product binding CSAF and OpenVEX share: product_tree must declare every
// product product_status references, and an OpenVEX statement MUST carry a
// `products` array (spec §4.3).
function buildProductBinding(playbook, sessionId) {
  const playbookSlug = urnSlug(playbook._meta.id);
  const sessionSlug = urnSlug(sessionId || 'session');
  const productId = `exceptd-target-${playbookSlug}-${sessionSlug}`;
  const productPurl = `pkg:exceptd/scan/${sessionSlug}/${playbookSlug}`;
  return {
    productId,
    productPurl,
    productName: playbook.domain?.name || playbook._meta.id,
  };
}

// Path-shape predicate for a SARIF artifactLocation.uri candidate. A
// look-artifact `source` is as often a shell command or prose as a file, and
// SARIF requires an RFC 3986 URI reference — anything with internal whitespace
// is a command or a sentence, not a path.
function looksLikePath(src) {
  if (typeof src !== 'string') return false;
  const trimmed = src.trim();
  if (!trimmed) return false;
  if (/\s/.test(trimmed)) return false;
  if (/^file:/i.test(trimmed)) return true;
  if (/^[A-Za-z]:[/\\]/.test(trimmed)) return true;       // Windows drive
  if (/^[/~]/.test(trimmed)) return true;                  // POSIX abs / home
  if (/^\.\.?(?:[/\\]|$)/.test(trimmed)) return true;      // relative dot
  if (/^[A-Za-z0-9_.+-]+[/\\][^\s]+$/.test(trimmed)) return true;  // bare relative path
  return false;
}
// Physical SARIF locations for an indicator hit, or null — on which the caller
// must omit `locations` rather than emit an empty array. Submission-supplied
// evidence_locations give a real file; look-artifact sources are the fallback.
function sarifLocationsForIndicator(playbook, indicator) {
  const ev = indicator && Array.isArray(indicator.evidence_locations) ? indicator.evidence_locations : null;
  if (ev && ev.length) {
    const locs = [];
    for (const e of ev) {
      // artifactLocation.uri is an RFC 3986 reference, so the separator must be
      // `/`; submission-threaded locations bypass the collectors' normalization.
      if (typeof e === "string" && e.trim()) {
        locs.push({ physicalLocation: { artifactLocation: { uri: e.trim().replace(/\\/g, "/") } } });
      } else if (e && typeof e === "object" && typeof e.uri === "string" && e.uri.trim()) {
        const pl = { artifactLocation: { uri: e.uri.trim().replace(/\\/g, "/") } };
        if (Number.isInteger(e.startLine) && e.startLine > 0) {
          pl.region = { startLine: e.startLine, ...(Number.isInteger(e.endLine) && e.endLine >= e.startLine ? { endLine: e.endLine } : {}) };
        }
        locs.push({ physicalLocation: pl });
      }
    }
    if (locs.length) return locs;
  }
  const arts = (playbook.phases?.look?.artifacts) || [];
  const candidates = arts
    .map(a => a && (a.source || a.air_gap_alternative))
    .filter(Boolean)
    .map(src => String(src).split(/\s+(?:AND|OR)\s+/i)[0].trim())
    .filter(src => src && !/^https?:/i.test(src))
    .filter(looksLikePath);
  if (!candidates.length) return null;
  return [{ physicalLocation: { artifactLocation: { uri: candidates[0] } } }];
}

// Locations for a finding-class SARIF result, never empty: GitHub Code Scanning
// silently DROPS a result with no `locations[]`, and most playbooks have no
// physical location to give. A rule-naming `logicalLocations` entry is
// SARIF-conformant (§3.33) and honest about there being no file to point at.
function sarifResultLocations(playbook, indicator, fqRuleId) {
  const phys = sarifLocationsForIndicator(playbook, indicator);
  if (phys && phys.length) return phys;
  return [{ logicalLocations: [{ name: fqRuleId, fullyQualifiedName: fqRuleId, kind: 'rule' }] }];
}

// The engine version CSAF tracking.generator names, resolved once per process.
// Bundle emission must not crash on an install where package.json is unreadable.
let _CACHED_PKG_VERSION = null;
function getEngineVersion() {
  if (_CACHED_PKG_VERSION != null) return _CACHED_PKG_VERSION;
  try {
    const pkg = require(path.join(__dirname, '..', 'package.json'));
    _CACHED_PKG_VERSION = (pkg && typeof pkg.version === 'string') ? pkg.version : 'unknown';
  } catch {
    _CACHED_PKG_VERSION = 'unknown';
  }
  return _CACHED_PKG_VERSION;
}

// The deterministic-bundle epoch: runOpts.bundleEpoch, then
// playbook._meta.last_threat_review (stable across re-runs of one catalog
// version), then 1970 so a malformed playbook cannot crash the path.
function resolveFrozenEpoch(runOpts, playbook) {
  const raw = runOpts && runOpts.bundleEpoch
    ? runOpts.bundleEpoch
    : (playbook && playbook._meta && playbook._meta.last_threat_review)
      || '1970-01-01T00:00:00Z';
  try { return new Date(raw).toISOString(); }
  catch { return '1970-01-01T00:00:00Z'; }
}

// computeRegressionNextRun against an injected base date, so two
// deterministic-mode runs produce byte-identical schedules.
function frozenRegressionNextRun(triggers, frozenNow) {
  let soonest = null;
  for (const t of (triggers || [])) {
    const parsed = parseInterval(t.interval, frozenNow);
    if (!parsed || !parsed.date) continue;
    if (!soonest || parsed.date < soonest) soonest = parsed.date;
  }
  return soonest ? soonest.toISOString() : null;
}

// --operator and --publisher-namespace land on operator-facing CSAF surfaces.
// bin/exceptd.js validates the CLI inputs, but a library consumer bypasses it
// and must not be able to smuggle a U+202E RTL OVERRIDE or a zero-width joiner
// into a bundle. Null on rejection, which callers treat as operator-unclaimed.
function sanitizeOperatorText(s) {
  if (typeof s !== 'string') return null;
  // NFC first: a Cf codepoint can arrive as a base plus combining mark that
  // only recomposes into the format category under normalisation.
  let normalised;
  try { normalised = s.normalize('NFC'); }
  catch { return null; }
  // The named threat families go through the shared vendored tables, so that
  // vocabulary has one source of truth; \p{C} is the strictly broader backstop.
  const familyStripped = codepointClass.applyCharStripPolicies(normalised, {
    bidiPolicy: 'strip',
    controlPolicy: 'strip',
    zeroWidthPolicy: 'strip',
    nullBytePolicy: 'strip',
  });
  const stripped = familyStripped.replace(/\p{C}/gu, '');
  const trimmed = stripped.trim();
  if (trimmed.length === 0) return null;
  // 256 CODEPOINTS, counted with Array.from: a `.length` cap measures UTF-16
  // code units, so astral-plane text would slip a longer string past it.
  const cps = Array.from(trimmed);
  if (cps.length <= 256) return cps.join('');
  return cps.slice(0, 256).join('');
}

/**
 * Build one evidence bundle in the requested format ('csaf-2.0', 'sarif',
 * 'openvex', 'summary', 'markdown', 'json' and their versioned spellings). An
 * unrecognised format returns a stub carrying supported_formats. `sessionId`
 * becomes part of the CSAF tracking.id, the OpenVEX @id and the attestation
 * name, so all three correlate. `issuedAt` pins the timestamp across a
 * multi-format emit, without which each call crystallises its own Date.now().
 * `runOpts` is read for operator, publisherNamespace, csafStatus, tlp and the
 * _runErrors accumulator.
 */
function buildEvidenceBundle(format, playbook, analyze, validate, agentSignals, sessionId, issuedAt, runOpts) {
  runOpts = runOpts || {};
  const playbookSlug = urnSlug(playbook._meta.id);
  const { productId, productPurl, productName } = buildProductBinding(playbook, sessionId);
  const now = typeof issuedAt === 'string' && issuedAt ? issuedAt : new Date().toISOString();

  // CSAF-2.0. vulnerabilities[] covers matched catalogue CVEs AND fired
  // indicators (as pseudo-CVEs), so a playbook with no catalogue CVEs still
  // emits a non-empty bundle. Every entry references the product through
  // product_status, which NVD / ENISA / Red Hat dashboards validate.
  if (format === 'csaf-2.0') {
    const indicatorHits = (analyze._detect_indicators || []).filter(i => i.verdict === 'hit');
    const fullProductNames = [{
      product_id: productId,
      name: productName,
      product_identification_helper: { purl: productPurl }
    }];
    // A `fixed` product_status reflects the operator's VEX disposition, never
    // the catalog's live_patch_available flag: that flag says the vendor
    // publishes a live-patch, not that this operator deployed it, and treating
    // it as fixed makes the document lie to downstream dashboards.
    // Live-patch-only stays known_affected, with the route offered as a
    // `vendor_fix` remediation.
    //
    // CSAF §3.2.1.2 restricts `cve` to `^CVE-[0-9]{4}-[0-9]{4,}$`, and the
    // catalog also keys MAL-/GHSA-/OSV- identifiers off cve_id, so those route
    // to `ids[]`. §3.2.1.5 requires a vectorString whenever a cvss_v3 block is
    // emitted, so the block is dropped when there is neither score nor vector.
    const csafCvssSeverity = (score) => {
      if (typeof score !== 'number') return null;
      if (score >= 9.0) return 'CRITICAL';
      if (score >= 7.0) return 'HIGH';
      if (score >= 4.0) return 'MEDIUM';
      if (score > 0.0)  return 'LOW';
      return 'NONE';
    };
    const csafCvssVersionFromVector = (vec) => {
      if (typeof vec !== 'string') return '3.1';
      const m = vec.match(/^CVSS:(\d+\.\d+)\//);
      if (!m) return '3.1';
      // The declared version, verbatim — gating emission to 3.0 / 3.1 per the
      // CSAF 2.0 schema is the CALLER's job.
      return m[1];
    };
    const csafIdsFor = (id) => {
      // Null for a missing id, so the caller drops the entry: String(id) puts
      // literal "null" text into vulnerabilities[], which validators reject.
      if (typeof id !== 'string' || !id) return null;
      if (id.startsWith('GHSA-'))    return { system_name: 'GHSA', text: id };
      if (id.startsWith('MAL-'))     return { system_name: 'Malicious-Package', text: id };
      if (id.startsWith('OSV-'))     return { system_name: 'OSV', text: id };
      if (id.startsWith('SNYK-'))    return { system_name: 'Snyk', text: id };
      // RUSTSEC is its own tracking authority; routing it to 'OSV' breaks the
      // (system_name, text) pair downstream ingesters resolve by.
      if (id.startsWith('RUSTSEC-')) return { system_name: 'RUSTSEC', text: id };
      // An unrecognised authority says so, rather than being misattributed.
      return { system_name: 'exceptd-unknown', text: id };
    };
    const CSAF_CVE_RE = /^CVE-\d{4}-\d{4,}$/;

    // Built up front so the CSAFPID leaves bind into product_status below.
    const csafProductTree = buildCsafBranches(analyze.matched_cves || [], runOpts);

    const cveVulns = analyze.matched_cves.map(c => {
      const isFixed = c.vex_status === 'fixed';
      const remediations = [{
        category: 'vendor_fix',
        details: validate.selected_remediation?.description
          || (c.live_patch_available ? 'Vendor publishes a live-patch — see CVE catalog `live_patch_tools` for the operator-side step.' : 'See selected remediation path.'),
        product_ids: [productId],
      }];
      const idIsCve = typeof c.cve_id === 'string' && CSAF_CVE_RE.test(c.cve_id);
      let idEntry = null;
      if (!idIsCve) {
        idEntry = csafIdsFor(c.cve_id);
        if (idEntry == null) {
          if (Array.isArray(runOpts._runErrors)) {
            pushRunError(runOpts._runErrors, {
              kind: 'bundle_cve_id_missing',
              reason: 'A matched_cves[] entry has no string cve_id (null / undefined / non-string). The CSAF vulnerability entry was omitted to avoid emitting literal "null" / "undefined" text under vulnerabilities[].ids[].',
              remediation: 'Inspect the CVE catalog feed that produced this match; the upstream record is missing its identifier and should be refreshed or excluded.'
            }, { dedupeKey: () => 'singleton' });
          }
          return null;
        }
      }
      // A real vector AND a numeric score: an emitted `base_score: 0` reads as
      // an authoritative "informational" score where there is simply no data.
      const hasCvss = typeof c.cvss_score === 'number' && typeof c.cvss_vector === 'string' && c.cvss_vector.length > 0;
      // cvss_v3 accepts only 3.0 / 3.1, and validators reject a block keyed off
      // a 2.0 / 4.0 or malformed vector. A strict-parse failure raises
      // csaf_cvss_invalid and omits the block alone — the entry survives.
      let strictParse = null;
      if (hasCvss) {
        strictParse = scoring.parseCvss31Vector(c.cvss_vector);
      }
      const vectorVersion = hasCvss ? (strictParse && strictParse.version) : null;
      const cvssV3Eligible = !!(hasCvss && strictParse && strictParse.ok);
      if (hasCvss && !cvssV3Eligible && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'csaf_cvss_invalid',
          cve_id: c.cve_id,
          reason: (strictParse && strictParse.reason) || 'cvss_vector failed strict CVSS 3.1 parse',
        }, { dedupeKey: e => e.cve_id || 'unknown' });
      }
      const scores = cvssV3Eligible ? [{
        products: [productId],
        cvss_v3: {
          version: vectorVersion,
          baseScore: c.cvss_score,
          vectorString: c.cvss_vector,
          baseSeverity: csafCvssSeverity(c.cvss_score),
        }
      }] : [];
      const base = {
        // CSAF Profile 4 mandatory test 6.1.27.5: every /vulnerabilities[]
        // item carries `notes`.
        notes: [{
          category: 'description',
          text: `${c.cve_id}: RWEP ${c.rwep}${c.active_exploitation ? `, active_exploitation=${c.active_exploitation}` : ''}${c.cisa_kev ? ', CISA KEV' : ''}.`,
        }],
        scores,
        threats: c.active_exploitation === 'confirmed' ? [{ category: 'exploit_status', details: `Active exploitation confirmed${c.cisa_kev ? ' (CISA KEV)' : ''}.` }] : [],
        remediations,
        // The CSAFPID leaves are VULNERABLE ranges, so they belong only under
        // known_affected. `fixed` keeps the synthetic product alone — affected
        // ranges there would read as fixed releases.
        product_status: isFixed
          ? { fixed: [productId] }
          : { known_affected: [productId, ...(csafProductTree.cveProductIds[c.cve_id] || [])] }
      };
      if (idIsCve) {
        return { cve: c.cve_id, ...base };
      }
      return { ids: [idEntry], ...base };
    }).filter(v => v != null);
    const indicatorVulns = indicatorHits.map(i => ({
      // The 'exceptd-indicator' pseudo-authority is namespaced so NVD / Red Hat
      // / ENISA dashboards render a non-CVE finding without misattributing it
      // to a real registry.
      ids: [{ system_name: 'exceptd-indicator', text: `${playbook._meta.id}:${i.id}` }],
      notes: [{ category: 'description', text: `Indicator ${i.id} fired (${i.confidence}${i.deterministic ? ' / deterministic' : ''}) in playbook ${playbook._meta.id}.` }],
      remediations: [{ category: 'mitigation', details: validate.selected_remediation?.description || `Consult playbook brief: exceptd brief ${playbook._meta.id}.`, product_ids: [productId] }],
      product_status: { known_affected: [productId] }
    }));
    // Framework gaps belong in document.notes[], not vulnerabilities[]: the
    // system_name slot is for recognised tracking authorities, and a made-up
    // one renders a false-positive advisory per gap downstream.
    const gapNotes = (analyze.framework_gap_mapping || []).map((g, idx) => {
      const lines = [
        `Framework: ${g.framework}`,
        g.claimed_control ? `Claimed control: ${g.claimed_control}` : null,
        g.actual_gap ? `Gap: ${g.actual_gap}` : null,
        g.required_control ? `Required: ${g.required_control}` : null,
      ].filter(Boolean);
      return {
        category: 'details',
        title: `Framework gap ${idx + 1}: ${g.framework}${g.claimed_control ? ' / ' + g.claimed_control : ''}`,
        text: lines.join('\n'),
      };
    });
    // CSAF §3.1.7.4: publisher.namespace is the trust anchor of the entity
    // publishing the advisory — the OPERATOR running the scan, not the tool
    // vendor, who is not answerable for its accuracy. Resolved as
    // --publisher-namespace, then a URL-shaped --operator, then a marked fallback.
    const operatorClean = sanitizeOperatorText(runOpts.operator);
    const explicitNs = sanitizeOperatorText(runOpts.publisherNamespace);
    let publisherNamespace;
    let publisherNamespaceSource;
    if (explicitNs && /^https?:\/\//i.test(explicitNs)) {
      publisherNamespace = explicitNs;
      publisherNamespaceSource = 'runOpts.publisherNamespace';
    } else if (operatorClean && /^https?:\/\//i.test(operatorClean)) {
      publisherNamespace = operatorClean;
      publisherNamespaceSource = 'runOpts.operator';
    } else {
      publisherNamespace = 'urn:exceptd:operator:unknown';
      publisherNamespaceSource = 'fallback';
    }
    const namespaceFallbackNote = (publisherNamespaceSource === 'fallback') ? [{
      category: 'general',
      title: 'Publisher namespace not supplied',
      text: 'No --publisher-namespace and no URL-shaped --operator were supplied to this run. CSAF §3.1.7.4 requires the namespace to be the publisher\'s trust anchor — i.e. the OPERATOR running the scan, not the tooling vendor. Re-emit with `--publisher-namespace https://your-org.example` (or a URL-shaped `--operator`) to attribute responsibility for advisory accuracy correctly.'
    }] : [];
    // Also on runtime_errors[], so a CI gate can branch on the unclaimed
    // publisher without parsing notes[] prose.
    if (publisherNamespaceSource === 'fallback' && Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, {
        kind: 'bundle_publisher_unclaimed',
        reason: 'CSAF document.publisher.namespace fell back to urn:exceptd:operator:unknown because no --publisher-namespace and no URL-shaped --operator were supplied. Operator attribution is unclaimed on this advisory.',
        remediation: 'Re-run with --publisher-namespace <https-url> (or a URL-shaped --operator).'
      }, { dedupeKey: () => 'singleton' });
    }

    // contact_details is the operator-of-record, omitted entirely when no
    // operator was supplied rather than carrying a misleading null.
    const publisherBlock = {
      category: 'vendor',
      name: 'exceptd',
      namespace: publisherNamespace,
    };
    if (operatorClean) publisherBlock.contact_details = operatorClean;

    // CSAF §3.1.11.3.5.1 makes `final` immutable — validators refuse a re-emit
    // against the same tracking.id — and a detection run with no operator
    // review loop is revisable, so the default is `interim`. --csaf-status
    // promotes it; anything unrecognised falls back rather than being emitted.
    const allowedCsafStatuses = new Set(['draft', 'interim', 'final']);
    const csafStatus = allowedCsafStatuses.has(runOpts.csafStatus)
      ? runOpts.csafStatus
      : 'interim';

    // CSAF §3.1.4 distribution.tlp is optional, and the whole block is omitted
    // when --tlp declares no level.
    const allowedTlp = new Set(['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']);
    // CSAF 2.0 §3.2.1.5.2 pins tlp.label to the TLP 1.0 enum, so the TLP 2.0
    // labels the CLI accepts map onto it and the operator's exact label
    // survives in the free-form `text`.
    const CSAF_TLP_LABEL = { CLEAR: 'WHITE', GREEN: 'GREEN', AMBER: 'AMBER', 'AMBER+STRICT': 'AMBER', RED: 'RED' };
    const csafDistribution = (runOpts.tlp && allowedTlp.has(runOpts.tlp))
      ? { tlp: { label: CSAF_TLP_LABEL[runOpts.tlp] }, text: `TLP:${runOpts.tlp}` }
      : null;

    // A zero-vulnerability advisory is informational (the profile that does not
    // require /vulnerabilities), not a security advisory with an empty array —
    // which is semantically wrong and warns under strict profile validators.
    const csafCategory = (cveVulns.length + indicatorVulns.length) > 0
      ? 'csaf_security_advisory'
      : 'csaf_informational_advisory';
    return {
      document: {
        category: csafCategory,
        csaf_version: '2.0',
        publisher: publisherBlock,
        title: `exceptd finding: ${playbook.domain.name} (${analyze.matched_cves.length} CVE(s), ${indicatorHits.length} indicator hit(s), ${(analyze.framework_gap_mapping || []).length} framework gap(s))`,
        notes: [...namespaceFallbackNote, ...gapNotes],
        // Mandatory test 6.1.27.2 requires /document/references with at least
        // one `external` item; a security_advisory carries its references
        // inside the vulnerabilities instead.
        ...(csafCategory === 'csaf_informational_advisory' ? {
          references: [{ category: 'external', summary: `exceptd playbook: ${playbook._meta.id}`, url: `https://exceptd.com/playbooks/${playbook._meta.id}` }],
        } : {}),
        ...(csafDistribution ? { distribution: csafDistribution } : {}),
        tracking: {
          // Keyed on session_id, not a timestamp: two runs in the same
          // millisecond would collide, and the id must match the OpenVEX @id
          // and the attestation file name on disk.
          id: `exceptd-${playbook._meta.id}-${sessionId}`,
          status: csafStatus,
          version: playbook._meta.version,
          // CSAF §3.1.11.3.2 places the emitting engine here.
          generator: {
            engine: { name: 'exceptd', version: getEngineVersion() },
            date: now,
          },
          initial_release_date: now,
          current_release_date: now,
          // CSAF 6.1.30 requires one versioning scheme throughout and 6.1.16
          // requires tracking.version to equal the last revision_history
          // number. tracking.version is the playbook semver, so this entry
          // carries the same semver — an integer "1" would break both.
          revision_history: [{ number: playbook._meta.version, date: now, summary: 'Initial finding emission' }]
        }
      },
      // The informational profile forbids /vulnerabilities (test 6.1.27.3),
      // and a /product_tree there is misleading — §4.3 has the reader assume
      // every named product is affected. Both are security-advisory only.
      ...(csafCategory === 'csaf_security_advisory' ? {
        product_tree: (function () {
          // NVD / ENISA / Red Hat dashboards render the affected-product list
          // off branches[], not full_product_names[] (CSAF §3.1.5.1).
          const branches = csafProductTree.branches;
          const tree = { full_product_names: fullProductNames };
          if (branches.length > 0) tree.branches = branches;
          return tree;
        })(),
        vulnerabilities: (function () {
          // Deterministic mode sorts by primary identifier; otherwise
          // insertion order stands.
          const all = [...cveVulns, ...indicatorVulns];
          if (runOpts && runOpts.bundleDeterministic === true) {
            const keyOf = (v) => (typeof v.cve === 'string' && v.cve)
              || (Array.isArray(v.ids) && v.ids[0] && typeof v.ids[0].text === 'string' ? v.ids[0].text : '');
            return all.slice().sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
          }
          return all;
        })(),
      } : {}),
      exceptd_extension: {
        classification: analyze._detect_classification,
        rwep: analyze.rwep,
        blast_radius_score: analyze.blast_radius_score,
        compliance_theater: analyze.compliance_theater_check,
        framework_gap_mapping: analyze.framework_gap_mapping,
        evidence_requirements: validate.evidence_requirements,
        residual_risk_statement: validate.residual_risk_statement,
        indicators_fired: indicatorHits.map(i => ({ id: i.id, confidence: i.confidence, deterministic: i.deterministic })),
        publisher_namespace_source: publisherNamespaceSource,
      }
    };
  }

  if (format === 'sarif' || format === 'sarif-2.1.0') {
    // Null property-bag keys render as empty rows in SARIF viewers.
    const stripNulls = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v != null));
    // Rule ids are global within a sarif-log run and GitHub Code Scanning
    // de-dupes by ruleId, so a generic id (`framework-gap-0`, a shared CVE id)
    // would let one playbook's rule silently overwrite another's on merge.
    const rulePrefix = `${playbookSlug}/`;
    // A null indicator takes the coarse playbook-source location fallback.
    const cveResults = analyze.matched_cves.map(c => {
      const result = {
        ruleId: `${rulePrefix}${c.cve_id}`,
        level: c.rwep >= 90 ? 'error' : c.rwep >= 70 ? 'warning' : 'note',
        message: { text: `${c.cve_id}: RWEP ${c.rwep}, blast_radius ${analyze.blast_radius_score == null ? 'not assessed' : analyze.blast_radius_score}. ${validate.selected_remediation?.description || ''}` },
        properties: stripNulls({
          kind: 'cve_match',
          rwep: c.rwep,
          cisa_kev: c.cisa_kev,
          cisa_kev_due_date: c.cisa_kev_due_date ?? null,
          active_exploitation: c.active_exploitation ?? null,
          ai_discovered: c.ai_discovered ?? null,
          blast_radius_score: analyze.blast_radius_score,
        }),
      };
      // Always a location — physical when known, else the rule-scoped logical
      // fallback — or Code Scanning drops the highest-severity result class.
      result.locations = sarifResultLocations(playbook, null, result.ruleId);
      return result;
    });
    const indicatorHits = (analyze._detect_indicators || []).filter(i => i.verdict === 'hit');
    const indicatorResults = indicatorHits.map(i => {
      const locs = sarifResultLocations(playbook, i, `${rulePrefix}${i.id}`);
      const result = {
        ruleId: `${rulePrefix}${i.id}`,
        level: i.deterministic ? 'error' : (i.confidence === 'high' ? 'warning' : 'note'),
        message: { text: `Indicator ${i.id} fired (${i.confidence}${i.deterministic ? ' / deterministic' : ''}). Playbook: ${playbook._meta.id}.` },
        properties: stripNulls({
          kind: 'indicator_hit',
          confidence: i.confidence,
          deterministic: i.deterministic,
          atlas_ref: i.atlas_ref,
          attack_ref: i.attack_ref,
        }),
      };
      result.locations = locs; // always present (physical or logical fallback)
      return result;
    });
    const gapResults = (analyze.framework_gap_mapping || []).map((g, idx) => ({
      ruleId: `${rulePrefix}framework-gap-${idx}`,
      // Framework gaps are control-design observations, not vulnerabilities.
      // SARIF §3.27.9 requires a present `level` to be 'none' whenever kind is
      // not 'fail' — pairing 'informational' with 'note' is a schema violation
      // strict validators and Code Scanning reject.
      kind: 'informational',
      level: 'none',
      message: { text: `${g.framework}: ${g.claimed_control} — ${g.actual_gap}${g.required_control ? '. Required: ' + g.required_control : ''}` },
      properties: stripNulls({ kind: 'framework_gap', framework: g.framework, control: g.claimed_control }),
    }));
    const cveRules = analyze.matched_cves.map(c => {
      const authority = advisoryAuthorityFor(c.cve_id);
      const isCve = CVE_ID_RE.test(typeof c.cve_id === 'string' ? c.cve_id : '');
      const rule = {
        id: `${rulePrefix}${c.cve_id}`,
        // A non-CVE id is qualified by its authority so a viewer does not read
        // a MAL- id as an NVD CVE.
        shortDescription: { text: isCve ? c.cve_id : `${c.cve_id} (${authority.system_name || 'non-CVE advisory'})` },
        fullDescription: { text: `RWEP ${c.rwep} · KEV=${c.cisa_kev} · active_exploitation=${c.active_exploitation}` },
        defaultConfiguration: { level: c.rwep >= 90 ? 'error' : c.rwep >= 70 ? 'warning' : 'note' },
      };
      // helpUri is optional; omitting it beats emitting a link that 404s.
      if (authority.helpUri) rule.helpUri = authority.helpUri;
      return rule;
    });
    const indicatorRules = indicatorHits.map(i => ({
      id: `${rulePrefix}${i.id}`, shortDescription: { text: i.id },
      fullDescription: { text: `Indicator from playbook ${playbook._meta.id}. Type: ${i.type}. Confidence: ${i.confidence}.` },
      defaultConfiguration: { level: i.deterministic ? 'error' : (i.confidence === 'high' ? 'warning' : 'note') },
    }));
    const gapRules = (analyze.framework_gap_mapping || []).map((g, idx) => ({
      id: `${rulePrefix}framework-gap-${idx}`,
      shortDescription: { text: `${g.framework}: ${g.claimed_control || `gap-${idx}`}` },
      fullDescription: { text: g.actual_gap || `Framework gap in ${g.framework}` },
      defaultConfiguration: { level: 'note' },
      help: g.required_control ? { text: `Required control: ${g.required_control}` } : undefined,
    }));
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: { driver: {
          name: 'exceptd', version: playbook._meta.version, informationUri: 'https://exceptd.com',
          rules: [...cveRules, ...indicatorRules, ...gapRules],
        } },
        results: [...cveResults, ...indicatorResults, ...gapResults],
        invocations: [{ executionSuccessful: (analyze._detect_classification !== 'inconclusive'), properties: stripNulls({
          playbook: playbook._meta.id, classification: analyze._detect_classification || 'unknown',
          rwep_adjusted: analyze.rwep?.adjusted || 0,
          remediation: validate.selected_remediation?.id || null,
        }) }],
      }]
    };
  }

  // OpenVEX 0.2.0. Every statement carries a `products` array (spec MUST) and a
  // status from the verdict: a hit is `affected` with an action_statement, a
  // miss `not_affected` with a justification, anything else
  // `under_investigation`. Framework gaps never enter this path.
  if (format === 'openvex' || format === 'openvex-0.2.0') {
    const issued = now;
    const productEntry = {
      '@id': productPurl,
      subcomponents: [{ '@id': productPurl }],
    };
    // validate() selects the priority-1 path as its last rung, so a null
    // selected_remediation means the phase declares no remediation paths at all
    // and remediation_options_considered is empty too — there is no id to name.
    const remediationId = validate.selected_remediation?.id || null;
    const remediationDescription = validate.selected_remediation?.description || null;
    const actionStatementFor = (fallback) => {
      if (remediationId && remediationDescription) {
        return `Apply remediation from validate phase: ${remediationId}. ${remediationDescription}`;
      }
      if (remediationId) return `Apply remediation from validate phase: ${remediationId}`;
      if (remediationDescription) return `Apply remediation from validate phase: ${remediationDescription}`;
      return fallback;
    };
    // As in the CSAF emitter, only an operator-declared vex_status:'fixed'
    // yields `fixed`: supply-chain consumers treat it as authoritative, so the
    // catalog's live_patch_available flag must not claim an unattested fix.
    const cveStatements = analyze.matched_cves.map(c => {
      const stmt = {
        vulnerability: { '@id': vulnIdToUrn(c.cve_id), name: c.cve_id },
        products: [productEntry],
        timestamp: issued,
        impact_statement: `RWEP ${c.rwep}. ${analyze.blast_radius_score == null ? 'Blast radius not assessed.' : `Blast radius ${analyze.blast_radius_score}/5.`}`,
      };
      if (c.vex_status === 'fixed') {
        stmt.status = 'fixed';
        // A trail back to the operator's submission, hashed deterministically
        // over (cve_id, signals) so a re-emit yields the same one.
        const trailSrc = canonicalStringify({
          cve_id: c.cve_id,
          vex_status: 'fixed',
          signals: agentSignals && typeof agentSignals === 'object' ? agentSignals : {},
        });
        const shortHash = crypto.createHash('sha256').update(trailSrc).digest('hex').slice(0, 16);
        stmt.impact_statement = `${stmt.impact_statement} Operator verified fixed via evidence_hash=${shortHash}.`;
      } else {
        stmt.status = 'affected';
        stmt.action_statement = actionStatementFor(c.live_patch_available
          ? 'Vendor publishes a live-patch — see catalog `live_patch_tools` and apply, then re-attest.'
          : 'Apply remediation from validate phase.');
      }
      return stmt;
    });
    const indicatorStatements = (analyze._detect_indicators || [])
      .filter(i => i.verdict === 'hit' || i.verdict === 'miss' || i.verdict === 'inconclusive')
      .map(i => {
        const stmt = {
          vulnerability: {
            '@id': `urn:exceptd:indicator:${playbookSlug}:${urnSlug(i.id)}`,
            name: i.id,
          },
          products: [productEntry],
          timestamp: issued,
          impact_statement: `Indicator ${i.id} (${i.verdict}; ${i.confidence}${i.deterministic ? '/deterministic' : ''}) in playbook ${playbook._meta.id}.`,
        };
        if (i.verdict === 'hit') {
          // `deterministic` describes regex specificity, not evidence
          // confidence, so a fired indicator is `affected` either way.
          stmt.status = 'affected';
          stmt.action_statement = actionStatementFor(`Run \`exceptd brief ${playbook._meta.id}\` for context.`);
        } else if (i.verdict === 'miss') {
          stmt.status = 'not_affected';
          stmt.justification = 'vulnerable_code_not_present';
        } else {
          stmt.status = 'under_investigation';
        }
        return stmt;
      });
    // `author` is the entity attesting to the disposition — the operator, not
    // the tool vendor. Same fallback ladder as the CSAF publisher.namespace.
    const vexOperatorClean = sanitizeOperatorText(runOpts.operator);
    const vexExplicitNs = sanitizeOperatorText(runOpts.publisherNamespace);
    let vexAuthor;
    if (vexExplicitNs) {
      vexAuthor = vexExplicitNs;
    } else if (vexOperatorClean) {
      vexAuthor = vexOperatorClean;
    } else {
      vexAuthor = 'urn:exceptd:operator:unknown';
      // Same shape and singleton dedupe as the CSAF path, so a multi-format
      // emit produces one canonical bundle_publisher_unclaimed entry.
      pushRunError(runOpts._runErrors, {
        kind: 'bundle_publisher_unclaimed',
        reason: 'OpenVEX author fell back to urn:exceptd:operator:unknown because no --publisher-namespace and no URL-shaped --operator were supplied. Disposition attribution is unclaimed on this VEX document.',
        remediation: 'Re-run with --publisher-namespace <https-url> (or a URL-shaped --operator).'
      }, { dedupeKey: () => 'singleton' });
    }
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      // Baked from session_id, not Date.now(), so the document URN aligns with
      // the CSAF tracking.id and the on-disk attestation file name.
      '@id': `https://exceptd.com/vex/${playbookSlug}/${urnSlug(sessionId || 'session')}`,
      author: vexAuthor,
      timestamp: issued,
      version: 1,
      statements: (function () {
        // Deterministic mode sorts by vulnerability['@id']; otherwise
        // insertion order stands.
        const all = [...cveStatements, ...indicatorStatements];
        if (runOpts && runOpts.bundleDeterministic === true) {
          const keyOf = (s) => (s && s.vulnerability && typeof s.vulnerability['@id'] === 'string')
            ? s.vulnerability['@id'] : '';
          return all.slice().sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
        }
        return all;
      })(),
    };
  }

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

  // A superset of `summary` carrying the full finding record, and the declared
  // bundle_format of several shipped playbooks — not the fallback below.
  if (format === 'json') {
    return {
      format: 'json',
      playbook: playbook._meta.id,
      playbook_version: playbook._meta.version,
      session_id: sessionId,
      generated: now,
      verdict: analyze.compliance_theater_check?.verdict || 'pending',
      matched_cves: analyze.matched_cves,
      rwep_adjusted: analyze.rwep?.adjusted || 0,
      rwep_threshold_escalate: analyze.rwep?.threshold?.escalate || null,
      blast_radius_score: analyze.blast_radius_score || 0,
      selected_remediation: validate.selected_remediation || null,
      residual_risk_statement: validate.residual_risk_statement || null,
    };
  }

  // The supported formats and nothing else: emitting analyze and validate
  // internals here leaks finding details on a typo'd format flag.
  return {
    format,
    note: 'Unknown format',
    supported_formats: ['csaf-2.0', 'sarif', 'sarif-2.1.0', 'openvex', 'openvex-0.2.0', 'summary', 'markdown', 'json'],
  };
}

// Translate the flat submission shape into the engine's nested one; an
// already-nested submission passes through unchanged. Flat is:
//   { observations: { <artifact-id>: { captured, value, indicator?, result? }
//                                     | "<precondition-value>" },
//     verdict: { theater, classification, blast_radius } }
function normalizeSubmission(submission, playbook) {
  if (!submission || typeof submission !== "object") return submission || {};

  // signal_overrides must be a plain object: spreading a string splatters it
  // into { '0': 'f', '1': 'o', … } and confuses detect()'s indicator lookup.
  if (submission.signal_overrides !== undefined && submission.signal_overrides !== null
      && (typeof submission.signal_overrides !== 'object' || Array.isArray(submission.signal_overrides))) {
    // Clone before touching _runErrors: the caller's submission may be frozen,
    // or shared across parallel runs.
    const carry = Array.isArray(submission._runErrors) ? submission._runErrors.slice() : [];
    pushRunError(carry, {
      kind: 'signal_overrides_invalid',
      supplied_type: Array.isArray(submission.signal_overrides) ? 'array' : typeof submission.signal_overrides,
      reason: 'signal_overrides must be a plain object mapping indicator-id → verdict.'
    }, { dedupeKey: e => String(e.supplied_type) });
    submission = { ...submission, signal_overrides: {}, _runErrors: carry };
  }

  // `observations` or `verdict` decides the shape even when nested keys are
  // present: the CLI injects `signals._bundle_formats` before calling this,
  // and reading that as "already nested" leaves the flat keys untranslated.
  const hasFlat = submission.observations || submission.verdict;

  if (!hasFlat) {
    if (!submission._original_shape) submission._original_shape = 'nested (v0.10.x)';
    return submission;
  }

  const out = {
    artifacts: { ...(submission.artifacts || {}) },
    signal_overrides: { ...(submission.signal_overrides || {}) },
    signals: { ...(submission.signals || {}) },
    precondition_checks: { ...(submission.precondition_checks || {}) },
    // Carried through so detect() can thread them onto firing indicators for
    // SARIF results[].locations.
    ...(submission.evidence_locations && typeof submission.evidence_locations === 'object'
      ? { evidence_locations: submission.evidence_locations } : {}),
    _original_shape: 'flat (v0.11.0)',
    // run() harvests the accumulator from agentSubmission._runErrors, which
    // the fresh `out` literal would otherwise drop.
    ...(Array.isArray(submission._runErrors) && submission._runErrors.length
      ? { _runErrors: submission._runErrors.slice() }
      : {}),
  };
  const knownPreconditions = new Set((playbook?._meta?.preconditions || []).map(p => p.id));
  const knownArtifacts = new Set((playbook?.phases?.look?.artifacts || []).map(a => a.id));

  const canonicalizeOutcome = (v) => {
    if (v === true || v === 'hit' || v === 'detected' || v === 'positive') return 'hit';
    if (v === false || v === 'miss' || v === 'no_hit' || v === 'no-hit' || v === 'clean' || v === 'clear' || v === 'not_hit' || v === 'ok' || v === 'pass' || v === 'negative') return 'miss';
    if (v === 'inconclusive' || v === 'unknown' || v === 'unverified' || v === null) return 'inconclusive';
    return v; // leave unrecognized values for detect() to decide
  };

  // Which observation produced each signal_override, so detect can emit
  // `from_observation`. Two observations on one indicator is last-write-wins,
  // and the discard is recorded as a collision for analyze to publish.
  out._signal_origins = out._signal_origins || {};
  out._signal_origins_collisions = out._signal_origins_collisions || [];
  for (const [key, val] of Object.entries(submission.observations || {})) {
    if (knownPreconditions.has(key)) {
      out.precondition_checks[key] = val === "ok" || val === true || val === "true";
      continue;
    }
    if (typeof val === "object" && val !== null) {
      const aid = knownArtifacts.has(key) ? key : (val.artifact || key);
      // Every evidence-bearing key survives, not just `value`: a collector shape
      // like { path, matched, reason } would collapse to { value: undefined,
      // captured }, so two observations capturing DIFFERENT secrets hash
      // byte-identical. artifact/indicator/result are control keys, not evidence.
      const { artifact: _a, indicator: _i, result: _r, captured: _c, value: _v, ...evidence } = val;
      const normalizedArtifact = { captured: val.captured !== false };
      if (val.value !== undefined) normalizedArtifact.value = val.value;
      for (const [ek, ev] of Object.entries(evidence)) {
        if (ek === "__proto__" || ek === "constructor" || ek === "prototype") continue;
        normalizedArtifact[ek] = ev;
      }
      out.artifacts[aid] = normalizedArtifact;
      if (val.indicator && val.result !== undefined) {
        const newVerdict = canonicalizeOutcome(val.result);
        if (out.signal_overrides[val.indicator] !== undefined && out._signal_origins[val.indicator] !== undefined) {
          out._signal_origins_collisions.push({
            indicator_id: val.indicator,
            source_observation_key: out._signal_origins[val.indicator],
            verdict: out.signal_overrides[val.indicator],
            discarded: true,
            replaced_by: key
          });
        }
        out.signal_overrides[val.indicator] = newVerdict;
        out._signal_origins[val.indicator] = key;
      }
    }
  }

  const v = submission.verdict || {};
  if (v.theater) out.signals.theater_verdict = v.theater === "actual_security" ? "clear" : v.theater;
  if (v.classification) out.signals.detection_classification = v.classification;
  if (v.blast_radius !== undefined) out.signals.blast_radius_score = v.blast_radius;

  // Own-key iteration, never Object.assign: JSON.parse keeps a submitted
  // `__proto__` as an own data property, but Object.assign writes it through
  // [[Set]] and triggers the prototype-rebinding setter on the bag.
  if (submission.precondition_checks) {
    for (const k of Object.keys(submission.precondition_checks)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      out.precondition_checks[k] = submission.precondition_checks[k];
    }
  }

  return out;
}

// Answer the preconditions the runner can answer itself — host platform, cwd
// readability, command-on-PATH — leaving only the ones that require intent
// ("operator authorized this scan") for the AI to declare.
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
    // An intent check ("operator_authorized == true") is left undefined for
    // the operator to declare; preflight handles the missing value per on_fail.
  }
  return out;
}

// The seven phases in one call.
function run(playbookId, directiveId, agentSubmission = {}, runOpts = {}) {
  const xrefErr = getXrefLoadError();
  if (xrefErr) {
    return {
      ok: false,
      blocked_by: 'catalog_corrupt',
      error: xrefErr,
      reason: 'cve-catalog.json or an index could not be parsed. Run `npm run build-indexes` to regenerate, or restore the file from git.'
    };
  }

  let playbook;
  try {
    playbook = loadPlaybook(playbookId);
  } catch (e) {
    return {
      ok: false,
      blocked_by: 'playbook_not_found',
      error: (e && e.message) ? String(e.message) : String(e),
      reason: `Failed to load playbook '${playbookId}'. Check that data/playbooks/${playbookId}.json exists.`
    };
  }

  // Before any phase runs: an unknown id otherwise throws uncaught inside
  // findDirective() and surfaces as a stack trace.
  const validDirectives = (playbook.directives || []).map(d => d.id);
  if (!validDirectives.includes(directiveId)) {
    return {
      ok: false,
      blocked_by: 'directive_not_found',
      reason: `Directive '${directiveId}' not found in playbook '${playbookId}'.`,
      valid_directives: validDirectives,
    };
  }

  agentSubmission = normalizeSubmission(agentSubmission, playbook);
  // Captured before auto-detect so the provenance report distinguishes what
  // the operator declared from what the engine resolved.
  const originalSubmissionPCs = { ...(agentSubmission.precondition_checks || {}) };
  agentSubmission = autoDetectPreconditions(agentSubmission, playbook);

  // precondition_checks merge submission → runOpts, runOpts winning as the
  // most recent caller intent; the submission was captured earlier, during
  // evidence collection. precondition_check_source names which side won.
  const fullSubmissionPCs = agentSubmission.precondition_checks || {};
  const runOptsPCs = runOpts.precondition_checks || {};
  const mergedPCs = { ...fullSubmissionPCs, ...runOptsPCs };
  const pcSource = {};
  for (const k of Object.keys(mergedPCs)) {
    const inOrigSub = Object.prototype.hasOwnProperty.call(originalSubmissionPCs, k);
    const inRun = Object.prototype.hasOwnProperty.call(runOptsPCs, k);
    // In neither side means autoDetectPreconditions supplied it ('auto'); in
    // both means a programmatic override of a submitted value ('merged').
    if (!inOrigSub && !inRun) pcSource[k] = 'auto';
    else pcSource[k] = (inOrigSub && inRun) ? 'merged' : (inRun ? 'runOpts' : 'submission');
  }
  const pre = preflight(playbook, { ...runOpts, precondition_checks: mergedPCs });
  if (!pre.ok) {
    // A blocked result carries the same envelope fields as a successful one, so
    // a consumer iterating results[] can name the playbook that failed.
    const summaryLine = capSummary(`${playbookId}: blocked at preflight (${pre.blocked_by || 'unknown'}) — ${pre.reason || ''}`);
    return {
      ok: false,
      playbook_id: playbookId,
      directive_id: directiveId,
      verdict: 'blocked',
      summary_line: summaryLine,
      phase: 'preflight',
      blocked_by: pre.blocked_by,
      reason: pre.reason,
      remediation: pre.remediation,
      issues: pre.issues,
      precondition_check_source: pcSource,
      evidence_completeness: 'not-evaluated'
    };
  }

  // The diagnostic variant, because bare acquireLock returns null on a race
  // lost in the TOCTOU window since preflight's check, and the run would then
  // proceed UNLOCKED. Released in the finally block below.
  const lockResult = acquireLockDiagnostic(playbookId);
  // Only on a confirmed live foreign holder with a real pid. A malformed
  // lockfile reports held_by_live_pid too, with holder_pid null, and blocking on
  // that lets one file left by a crash deny every future run forever.
  if (!lockResult.ok && lockResult.reason === 'held_by_live_pid'
      && Number.isInteger(lockResult.holder_pid) && lockResult.holder_pid > 0) {
    return {
      ok: false,
      playbook_id: playbookId,
      directive_id: directiveId,
      verdict: 'blocked',
      summary_line: `${playbookId}: blocked — a concurrent run holds the mutex (pid ${lockResult.holder_pid})`.slice(0, 240),
      phase: 'preflight',
      blocked_by: 'mutex',
      reason: `A concurrent run of "${playbookId}" holds the run lock (live pid ${lockResult.holder_pid}). Retry after it completes.`,
      remediation: 'Wait for the in-flight run to finish, then retry.',
      evidence_completeness: 'not-evaluated'
    };
  }
  const lockPath = lockResult.ok ? lockResult.path : null;
  _activeRuns.add(playbookId);
  // The playbook is parsed once and threaded through every phase as
  // runOpts._playbookCache. session_id is minted once, so the CSAF tracking.id,
  // OpenVEX @id, product PURLs and attestation filename carry one correlatable
  // identifier. Under bundleDeterministic it derives from the submission, so two
  // runs over identical evidence agree; --session-id still wins.
  let sessionId;
  if (runOpts.session_id) {
    sessionId = runOpts.session_id;
  } else if (runOpts.bundleDeterministic) {
    let submissionDigest;
    try {
      submissionDigest = crypto.createHash('sha256')
        .update(canonicalStringify(extractSubmissionForHash(agentSubmission)))
        .digest('hex');
    } catch (e) {
      // canonicalStringify throws EVIDENCE_TOO_DEEP on pathological nesting,
      // and the try/finally below has not opened yet — a leaked lockfile would
      // block every later run of this playbook for this PID's lifetime.
      _activeRuns.delete(playbookId);
      releaseLock(lockPath);
      throw e;
    }
    sessionId = crypto.createHash('sha256')
      .update(`${playbookId}\0${submissionDigest}\0${getEngineVersion()}`)
      .digest('hex')
      .slice(0, 16);
  } else {
    sessionId = crypto.randomBytes(8).toString('hex');
  }
  const cachedRunOpts = { ...runOpts, _playbookCache: playbook, session_id: sessionId };
  // The run-level accumulator behind analyze.runtime_errors[].
  const runErrors = [];
  cachedRunOpts._runErrors = runErrors;
  // Splice in what normalizeSubmission pushed, then strip the field off the
  // submission: the evidence_hash canonicalizes the submission, and a
  // non-deterministic _runErrors would change the digest.
  if (Array.isArray(agentSubmission._runErrors) && agentSubmission._runErrors.length) {
    runErrors.push(...agentSubmission._runErrors);
  }
  if (agentSubmission && Object.prototype.hasOwnProperty.call(agentSubmission, '_runErrors')) {
    delete agentSubmission._runErrors;
  }
  // Phases to skip, from the skip_phase preconditions preflight surfaced.
  const skipPhases = new Set();
  for (const issue of (pre.issues || [])) {
    if (issue.kind === 'precondition_skip' && issue.skip_phase) {
      skipPhases.add(issue.skip_phase);
    }
  }
  try {
    const phases = {
      govern:   govern(playbookId, directiveId, cachedRunOpts),
      direct:   direct(playbookId, directiveId, cachedRunOpts),
      look:     look(playbookId, directiveId, cachedRunOpts),
    };
    if (skipPhases.has('detect')) {
      const skipIssue = (pre.issues || []).find(i => i.kind === 'precondition_skip' && i.skip_phase === 'detect');
      phases.detect = {
        phase: 'detect',
        playbook_id: playbookId,
        directive_id: directiveId,
        skipped: true,
        reason: skipIssue ? skipIssue.id : 'precondition_skip',
        classification: 'skipped',
        indicators: [],
        false_positive_checks_required: [],
        indicators_evaluated: [],
        indicators_evaluated_count: 0,
        observations_received: [],
        signals_received: []
      };
      // analyze still runs, on an empty submission so it cannot resolve
      // indicator hits against a detect result that never happened.
      phases.analyze  = analyze(playbookId, directiveId, phases.detect, {}, cachedRunOpts);
      phases.analyze.classification = 'skipped';
    } else {
      phases.detect   = detect(playbookId, directiveId, agentSubmission, cachedRunOpts);
      phases.analyze  = analyze(playbookId, directiveId, phases.detect, agentSubmission.signals || {}, cachedRunOpts);
    }
    phases.validate = validate(playbookId, directiveId, phases.analyze, agentSubmission.signals || {}, cachedRunOpts);
    phases.close    = close(playbookId, directiveId, phases.analyze, phases.validate, agentSubmission.signals || {}, cachedRunOpts);

    // analyze() snapshotted the accumulator when it returned; validate and
    // close push after that, so late entries merge back in.
    if (runErrors.length && phases.analyze) {
      // A `_truncated` sentinel aggregates through in-place `dropped`
      // increments, so the same object sits in both arrays; skipping it keeps
      // one authoritative count instead of stamping a duplicate.
      const existing = new Set(
        (phases.analyze.runtime_errors || [])
          .filter(e => !(e && e.kind === '_truncated'))
          .map(e => JSON.stringify(e))
      );
      const additions = runErrors.filter(e => !(e && e.kind === '_truncated') && !existing.has(JSON.stringify(e)));
      if (additions.length) {
        phases.analyze.runtime_errors = (phases.analyze.runtime_errors || []).concat(additions);
      }
    }

    // evidence_hash covers the canonicalized submission itself: keyed on only
    // { playbook, directive, cves, rwep, classification }, two operators with
    // different evidence collide whenever their classifications match.
    // Timestamps are excluded so one submission always hashes the same.
    const submissionDigest = crypto.createHash('sha256')
      .update(canonicalStringify(extractSubmissionForHash(agentSubmission)))
      .digest('hex');
    const evidenceHash = crypto.createHash('sha256')
      .update(JSON.stringify({
        playbookId, directiveId,
        cves: phases.analyze.matched_cves.map(c => c.cve_id),
        rwep: phases.analyze.rwep.adjusted,
        classification: phases.detect.classification,
        submission_digest: submissionDigest,
      }))
      .digest('hex');

    // Hoisted to the result root so a `ci` consumer answers "did this detect
    // anything?" without walking into phases. detect.classification is the
    // canonical verdict — validate() carries no `verdict` field.
    const verdict = (phases.detect && phases.detect.classification) || 'inconclusive';
    const rwepScore = phases.analyze && phases.analyze.rwep && typeof phases.analyze.rwep.adjusted === 'number'
      ? phases.analyze.rwep.adjusted : null;
    // The first matched CVE id, else the fired indicator that drove the
    // verdict — never the classification, which duplicates `verdict`.
    let topFinding = null;
    if (phases.analyze && Array.isArray(phases.analyze.matched_cves) && phases.analyze.matched_cves.length) {
      topFinding = phases.analyze.matched_cves[0].cve_id;
    } else if (phases.detect && Array.isArray(phases.detect.indicators)
        && phases.detect.classification
        && phases.detect.classification !== 'not-detected'
        && phases.detect.classification !== 'not_detected'
        && phases.detect.classification !== 'inconclusive'
        && phases.detect.classification !== 'pending') {
      // Only on a real detection verdict, so a stray hit on an inconclusive run
      // cannot advertise a finding. The indicator that drove the RWEP score
      // wins, then the dominant fired indicator, then the first hit.
      const breakdown = (phases.analyze.rwep && Array.isArray(phases.analyze.rwep.breakdown))
        ? phases.analyze.rwep.breakdown : [];
      const driver = breakdown
        .filter((b) => b.fired && typeof b.weight_applied === 'number' && b.weight_applied > 0)
        .sort((a, b) => b.weight_applied - a.weight_applied)[0];
      const hits = phases.detect.indicators.filter((i) => i.verdict === 'hit');
      const dominant = hits.find((i) => i.deterministic === true || i.confidence === 'high') || hits[0];
      if (driver && driver.signal_id) topFinding = driver.signal_id;
      else if (dominant && dominant.id) topFinding = dominant.id;
    }
    // Evaluated against known separates "ran fully and found nothing" from
    // "could not evaluate" — a not_detected verdict over zero indicators
    // otherwise reads exactly like one where every indicator missed.
    const indicatorsKnown = (playbook.phases && playbook.phases.detect && playbook.phases.detect.indicators)
      ? playbook.phases.detect.indicators.length : null;
    const indicatorsEvaluated = phases.detect && typeof phases.detect.indicators_evaluated_count === 'number'
      ? phases.detect.indicators_evaluated_count : null;
    let evidenceCompleteness;
    if (indicatorsKnown == null) evidenceCompleteness = 'unknown';
    else if (indicatorsEvaluated == null) evidenceCompleteness = 'not-evaluated';
    else if (indicatorsEvaluated === 0) evidenceCompleteness = 'missing';
    else if (indicatorsEvaluated < indicatorsKnown) evidenceCompleteness = 'partial';
    else evidenceCompleteness = 'complete';
    const summaryLine = (rwepScore != null && rwepScore > 0)
      ? `${playbookId}: ${verdict} (rwep=${rwepScore}${topFinding ? `, ${topFinding}` : ''}, evidence=${evidenceCompleteness})`
      : `${playbookId}: ${verdict} (evidence=${evidenceCompleteness}${topFinding ? `, ${topFinding}` : ''})`;
    return {
      ok: true,
      playbook_id: playbookId,
      directive_id: directiveId,
      session_id: sessionId,
      // The flat answer; the phases tree below carries the full dumps.
      verdict,
      rwep_score: rwepScore,
      top_finding: topFinding,
      summary_line: summaryLine,
      evidence_completeness: evidenceCompleteness,
      indicators_evaluated: indicatorsEvaluated,
      indicators_known: indicatorsKnown,
      evidence_hash: evidenceHash,
      submission_digest: submissionDigest,
      preflight_issues: pre.issues,
      // What the collector could not scan. Advisory only — never affects
      // verdict, rwep or evidence_completeness.
      ...(Array.isArray(agentSubmission.collector_errors) && agentSubmission.collector_errors.length
        ? { collector_warnings: agentSubmission.collector_errors }
        : {}),
      // { '<pc-id>': 'submission' | 'runOpts' | 'merged' | 'auto', … }
      precondition_check_source: pcSource,
      phases
    };
  } finally {
    _activeRuns.delete(playbookId);
    releaseLock(lockPath);
  }
}

// Deterministic JSON with recursively sorted keys: {a:1, b:2} and {b:2, a:1}
// must hash alike or reattest's "same submission → same hash" breaks. Array
// order is preserved — submission order is meaningful for evidence. Throws
// EVIDENCE_TOO_DEEP past CANONICAL_MAX_DEPTH.
const CANONICAL_MAX_DEPTH = 200;
function canonicalStringify(v, _depth = 0) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  // Deeply-nested evidence would overflow the stack with an opaque internal
  // error; 200 is far beyond any legitimate submission.
  if (_depth > CANONICAL_MAX_DEPTH) {
    const e = new Error(`evidence nesting exceeds the maximum depth of ${CANONICAL_MAX_DEPTH} — flatten the submission`);
    e.code = 'EVIDENCE_TOO_DEEP';
    throw e;
  }
  if (Array.isArray(v)) return '[' + v.map(x => canonicalStringify(x, _depth + 1)).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(v[k], _depth + 1)).join(',') + '}';
}

// Re-key an artifacts map by the stable indicator id, recovered by inverting
// _signal_origins, so evidence_hash reflects the evidence VALUE and its binding
// rather than the operator's free-text observation label. bin/exceptd.js re-keys
// the attest COMPARISON the same way. Collision-safe: a stable id already used
// as a distinct key keeps the original, dropping nothing.
function _rekeyArtifactsByStableId(artifacts, signalOrigins) {
  if (!signalOrigins || typeof signalOrigins !== 'object') return artifacts;
  const obsKeyToIndicator = {};
  for (const [indicatorId, obsKey] of Object.entries(signalOrigins)) {
    if (typeof obsKey === 'string') obsKeyToIndicator[obsKey] = indicatorId;
  }
  const originalKeys = new Set(Object.keys(artifacts));
  const out = {};
  for (const [k, v] of Object.entries(artifacts)) {
    const mapped = obsKeyToIndicator[k];
    const stable = (mapped && mapped !== k && !originalKeys.has(mapped)
      && !Object.prototype.hasOwnProperty.call(out, mapped)) ? mapped : k;
    out[stable] = v;
  }
  return out;
}

// The operator-meaningful fields of a normalized submission, for hashing.
// captured_at, _signal_origins, _signal_origins_collisions and _original_shape
// are excluded as timestamps, which break "same submission → same hash", or as
// runner-internal provenance the operator never submitted.
function extractSubmissionForHash(sub) {
  if (!sub || typeof sub !== 'object') return {};
  const pick = {};
  if (sub.artifacts && typeof sub.artifacts === 'object') {
    const stripped = {};
    for (const [k, v] of Object.entries(sub.artifacts)) {
      if (v && typeof v === 'object') {
        const { captured_at, _captured_at, ...rest } = v;
        stripped[k] = rest;
      } else {
        stripped[k] = v;
      }
    }
    pick.artifacts = _rekeyArtifactsByStableId(stripped, sub._signal_origins);
  }
  if (sub.signal_overrides && typeof sub.signal_overrides === 'object') {
    pick.signal_overrides = sub.signal_overrides;
  }
  if (sub.signals && typeof sub.signals === 'object') {
    // vex_filter and vex_fixed arrive as Sets; sorted arrays serialize.
    const signals = {};
    for (const [k, v] of Object.entries(sub.signals)) {
      // An underscore-prefixed signal is a render directive, not evidence:
      // hashing `_bundle_formats` makes two runs differing only in --format
      // produce different digests. vex_filter and vex_fixed stay IN — they drop
      // CVEs and change the finding.
      if (k.startsWith('_')) continue;
      if (v instanceof Set) signals[k] = Array.from(v).sort();
      else signals[k] = v;
    }
    // An empty bag is omitted, not recorded as `signals: {}`: a submission whose
    // only signal was a render directive reduces to {} here while the baseline
    // has no `signals` key, reintroducing the --format drift filtered above.
    if (Object.keys(signals).length > 0) pick.signals = signals;
  }
  if (sub.precondition_checks && typeof sub.precondition_checks === 'object') {
    pick.precondition_checks = sub.precondition_checks;
  }
  if (sub.observations && typeof sub.observations === 'object') {
    pick.observations = sub.observations;
  }
  if (sub.verdict && typeof sub.verdict === 'object') {
    pick.verdict = sub.verdict;
  }
  return pick;
}

// The identity fields a `contains`/`includes` test targets when the array holds
// objects. Scoping membership to these keeps a non-identity field that happens
// to equal the member (a clock_starts of 'detect_confirmed', a free-form tag
// reading 'EU') from satisfying the predicate.
const OBJECT_MEMBERSHIP_FIELDS = ['jurisdiction'];

function evalCondition(expr, ctx, playbook) {
  if (!expr) return false;
  expr = expr.trim();
  expr = stripOuterParens(expr);
  if (expr === 'always') return true;
  if (expr === 'true') return true;
  if (expr === 'false') return false;

  // OR binds looser than AND, so it splits first; splitAtTopLevel is
  // depth-aware, so `A OR (B AND C)` keeps B and C as one group.
  const orParts = splitAtTopLevel(expr, 'OR');
  if (orParts.length > 1) return orParts.some(s => evalCondition(s, ctx, playbook));

  const andParts = splitAtTopLevel(expr, 'AND');
  if (andParts.length > 1) return andParts.every(s => evalCondition(s, ctx, playbook));

  // Catalog conditions write `any <path> <op> <value>`. An array head applies
  // the predicate existentially or universally across its elements; a scalar
  // head means the quantifier was prose and the comparison is the real test.
  const quant = expr.match(/^(any|all)\s+(.+)$/);
  if (quant) {
    const [, kind, inner] = quant;
    // The clause is re-evaluated WHOLE against `{ …ctx, [head]: el }`, so every
    // operator the leaf parser understands works under a quantifier. A
    // `.`-qualified head routes the bare `any <path>` form to the branch below.
    const headMatch = inner.match(/^([A-Za-z_][\w-]*)(?:\.[A-Za-z_][\w-]*)+(?:[\s.[]|$)/);
    if (headMatch) {
      const head = headMatch[1];
      const arr = resolvePath(ctx, head);
      if (Array.isArray(arr)) {
        const test = el => evalCondition(inner, { ...ctx, [head]: el }, playbook);
        return kind === 'all' ? arr.length > 0 && arr.every(test) : arr.some(test);
      }
    }
    // `any <path>` with no operator quantifies over the collection itself. The
    // match is a pure dotted-path token, so a malformed inner clause falls
    // through to the diagnostic instead of reading as an existence test.
    if (/^[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*$/.test(inner)) {
      const v = resolvePath(ctx, inner);
      if (Array.isArray(v)) {
        return kind === 'all' ? v.length > 0 && v.every(Boolean) : v.length > 0;
      }
      return !!v;
    }
    // The quantifier was prose: evaluate the bare inner comparison.
    return evalCondition(inner, ctx, playbook);
  }

  // A clause whose LHS path is absent from ctx parses fine and returns a silent
  // false, disabling what it gates without firing condition_unparsed. Only a
  // literally-absent path pushes: a present-but-empty array, or any present
  // non-collection, is a legitimate false.
  const pushPathUnresolved = () => {
    const target = (ctx && Array.isArray(ctx._runErrors)) ? ctx._runErrors
      : (playbook && Array.isArray(playbook._runErrors)) ? playbook._runErrors
      : null;
    if (target) {
      pushRunError(target, { kind: 'condition_path_unresolved', condition: String(expr).slice(0, 200) },
        { dedupeKey: x => x.condition || '' });
    }
  };

  // "rwep >= 90". Path tokens admit hyphens because signal and indicator ids
  // are canonically hyphenated across the catalog, and a `\w`-only token
  // matches none of them — every such condition falls silently to `false`.
  let m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s*(>=|<=|==|=|<|>|!=)\s*(['"]?)([^'"]+)\3$/);
  if (m) {
    const [, lhs, op, quote, rhsRaw] = m;
    const lv = resolvePath(ctx, lhs);
    // Diagnostics only; the boolean is unchanged. `== null`, not strict
    // undefined: resolvePath returns null for a missing intermediate parent and
    // undefined for a missing leaf. A bare single-segment flag is legitimately
    // absent and does not push.
    if (lhs.includes('.') && lv == null) pushPathUnresolved();
    let rv = rhsRaw;
    if (quote) {
      // A quoted literal stays as written.
    } else if (rv === 'true') rv = true;
    else if (rv === 'false') rv = false;
    else if (!isNaN(parseFloat(rv)) && /^-?\d+(\.\d+)?$/.test(rv.trim())) rv = parseFloat(rv);
    else if (/^[a-z_][\w.-]*$/i.test(rv.trim())) {
      // An unquoted identifier is a context path, falling back to the raw
      // string when it does not resolve (an unquoted literal like `theater`).
      const resolved = resolvePath(ctx, rv.trim());
      if (resolved !== undefined && resolved !== null) rv = resolved;
    }
    // Severity is an ordinal ladder, not a lexical one: with raw string `>=`,
    // `severity >= 'high'` EXCLUDES 'critical', because 'critical' < 'high'.
    const SEV = { low: 0, medium: 1, high: 2, critical: 3 };
    const lr = SEV[String(lv).toLowerCase()], rr = SEV[String(rv).toLowerCase()];
    let a = (lr !== undefined && rr !== undefined) ? lr : lv;
    let b = (lr !== undefined && rr !== undefined) ? rr : rv;
    const isOrdering = op === '>=' || op === '<=' || op === '>' || op === '<';
    if (isOrdering && (lr === undefined || rr === undefined)) {
      // The catalog writes ordering comparisons against unit-suffixed duration
      // literals (`reboot_window > 24h`), which the RHS coercion above leaves as
      // strings: `48 > '24h'` becomes `48 > NaN`, and `'6h' > '24h'` compares as
      // `'6' > '2'`. Both sides normalize to hours instead.
      const la = parseDurationHours(a), ba = parseDurationHours(b);
      if ((la !== null || ba !== null) && la !== null && ba !== null) {
        a = la; b = ba;
      } else if (
        // Two non-numeric, non-severity, non-duration strings under an ordering
        // operator degrade to a lexicographic or NaN comparison. The clause
        // parsed, so only condition_type_mismatch makes that observable.
        typeof a !== 'number' && typeof b !== 'number' &&
        !(typeof a === 'string' && /^-?\d+(?:\.\d+)?$/.test(a.trim())) &&
        !(typeof b === 'string' && /^-?\d+(?:\.\d+)?$/.test(b.trim()))
      ) {
        const target = (ctx && Array.isArray(ctx._runErrors)) ? ctx._runErrors
          : (playbook && Array.isArray(playbook._runErrors)) ? playbook._runErrors
          : null;
        if (target) {
          pushRunError(target, { kind: 'condition_type_mismatch', condition: String(expr).slice(0, 200) },
            { dedupeKey: x => x.condition || '' });
        }
      }
    }
    switch (op) {
      case '==': case '=': return lv == rv;
      case '!=': return lv != rv;
      case '>=': return a >= b;
      case '<=': return a <= b;
      case '>':  return a > b;
      case '<':  return a < b;
    }
  }

  // "scope.targets includes named_remote". `contains` is a synonym the catalog
  // also writes, and the member may be bare or quoted. Against objects,
  // membership is scoped to OBJECT_MEMBERSHIP_FIELDS: an unscoped
  // `Object.values(el).includes(member)` over-matches.
  m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s+(?:includes|contains)\s+(?:'([^']+)'|"([^"]+)"|([\w-]+))$/);
  if (m) {
    const member = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
    const arr = resolvePath(ctx, m[1]);
    if (!Array.isArray(arr)) {
      if (arr == null) pushPathUnresolved();
      return false;
    }
    return arr.some((el) =>
      el === member ||
      (el && typeof el === 'object' &&
        OBJECT_MEMBERSHIP_FIELDS.some((f) => el[f] === member))
    );
  }

  // "matched_cve.attack_class IN ['kernel-lpe', 'rce']" — a scalar LHS must be
  // in the list, an array LHS must intersect it. Both the member split and the
  // closing bracket are quote-aware: `split(',')` tears `'EU, US'` into members
  // that match nothing, and a `[^\]]*` capture truncates `'a]b'`. Either failure
  // evaluates false with no diagnostic, since the regex still matched.
  m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s+IN\s+\[/);
  if (m) {
    const body = sliceInBracketBody(expr.slice(m[0].length));
    if (body !== null) {
      const members = splitInMembers(body);
      const lv = resolvePath(ctx, m[1]);
      if (Array.isArray(lv)) return lv.some((x) => members.includes(String(x)));
      // An absent LHS path is a dead clause, as in the membership branch; a
      // present scalar simply not in the list is a legitimate false.
      if (lv == null) { pushPathUnresolved(); return false; }
      return members.includes(String(lv));
    }
    // No closing bracket at quote-depth 0 — fall through to condition_unparsed.
  }

  // "matched_cve.vector matches /regex/". The catalog authors the slash and the
  // quote form, and a one-delimiter parser silently disables the other.
  m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s+matches\s+(?:\/(.+)\/|'([^']+)'|"([^"]+)")$/);
  if (m) {
    const pattern = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
    const val = resolvePath(ctx, m[1]);
    if (typeof val !== 'string') return false;
    // A regex with a syntax bug must not crash the engine mid-analyze: the
    // clause returns false and the failure reaches analyze.runtime_errors[].
    try {
      return new RegExp(pattern, 'i').test(val); // allow:dynamic-regex — pattern comes from an Ed25519-signed catalog playbook condition (/…/ or '…'), so it cannot be attacker-controlled without breaking the signature; the try/catch covers construction-time syntax errors only (it does NOT defend against catastrophic backtracking — do not reuse this shape for operator-supplied patterns)
    } catch (e) {
      const errorRec = { _regex_eval_error: { source: m[1], expr: pattern, message: e && e.message ? String(e.message) : String(e) } };
      // The `kind` tag is what lets pushRunError cap and dedupe: one bad regex
      // otherwise fires once per evaluated element.
      const taggedErr = { kind: 'regex_eval_error', ..._regexErrorPayload(errorRec) };
      const target = (ctx && Array.isArray(ctx._runErrors)) ? ctx._runErrors
        : (playbook && Array.isArray(playbook._runErrors)) ? playbook._runErrors
        : null;
      if (target) {
        pushRunError(target, taggedErr, {
          dedupeKey: x => `${x.source || ''}::${x.expr || ''}`,
        });
      }
      return false;
    }
  }

  // An unparseable condition is a DEAD condition: false for every input,
  // silently disabling what it gates. The runtime_error is how an authoring
  // typo or an unimplemented operator gets caught at all.
  if (process.env.EXCEPTD_DEBUG) console.warn(`[runner] unknown condition: ${expr}`);
  {
    const target = (ctx && Array.isArray(ctx._runErrors)) ? ctx._runErrors
      : (playbook && Array.isArray(playbook._runErrors)) ? playbook._runErrors
      : null;
    if (target) {
      pushRunError(target, { kind: 'condition_unparsed', condition: String(expr).slice(0, 200) },
        { dedupeKey: x => x.condition || '' });
    }
  }
  return false;
}

function resolvePath(obj, dot) {
  return dot.split('.').reduce((acc, k) => acc == null ? null : acc[k], obj);
}

// Normalize a duration operand to hours: a unit-suffixed literal by its unit, a
// bare number as its own magnitude. Null for anything else, so the caller can
// require BOTH sides to normalize before comparing.
const DURATION_UNIT_HOURS = {
  h: 1, hr: 1, hrs: 1,
  m: 1 / 60, min: 1 / 60,
  d: 24, day: 24, days: 24,
  w: 168, wk: 168,
};
function parseDurationHours(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (/^-?\d+(?:\.\d+)?$/.test(s)) return parseFloat(s);
  const m = s.match(/^(\d+(?:\.\d+)?)\s*(h|hr|hrs|d|day|days|wk|w|m|min)$/i);
  if (!m) return null;
  const mult = DURATION_UNIT_HOURS[m[2].toLowerCase()];
  return mult === undefined ? null : parseFloat(m[1]) * mult;
}

// Split `expr` at each ` <sep> ` sitting at parenthesis depth 0, so
// `A OR (B AND C)` splits into [`A`, `(B AND C)`] rather than at the inner AND.
function splitAtTopLevel(expr, sep) {
  const parts = [];
  const needle = ' ' + sep + ' ';
  let depth = 0, buf = '', i = 0, quote = null;
  while (i < expr.length) {
    const ch = expr[i];
    // Inside a quoted literal, parens and the needle are text, not structure:
    // `matches 'foo('` counted blindly leaves depth 1 so no later top-level
    // OR/AND ever splits, and `contains 'EU AND US'` is torn at its inner ` AND `.
    if (quote) {
      if (ch === '\\' && i + 1 < expr.length) { buf += ch + expr[i + 1]; i += 2; continue; }
      if (ch === quote) quote = null;
      buf += ch; i++; continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; buf += ch; i++; continue; }
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

// Split an `IN [...]` member list on commas outside any quoted run, stripping
// the quotes; a comma inside a quoted member (`'EU, US'`) belongs to it. Bare
// and quoted members both parse, and empty members are dropped.
function splitInMembers(listStr) {
  const out = [];
  let buf = '';
  let quote = null;
  for (let i = 0; i < listStr.length; i++) {
    const ch = listStr[i];
    if (quote) {
      if (ch === quote) quote = null;
      else buf += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === ',') { out.push(buf.trim()); buf = ''; continue; }
    buf += ch;
  }
  out.push(buf.trim());
  return out.filter((s) => s.length);
}

// The body of an `IN [...]` list, given the text after the opening bracket. The
// terminator is the first `]` at quote-depth 0; one inside a quoted member
// (`'a]b'`) belongs to the member. Null when the list is unterminated or carries
// trailing text, so the caller falls through to condition_unparsed.
function sliceInBracketBody(rest) {
  let quote = null;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === ']') {
      // Only whitespace may follow: the bracket is the final structural token
      // for this leaf parser.
      return rest.slice(i + 1).trim() === '' ? rest.slice(0, i) : null;
    }
  }
  return null; // unterminated list
}

// Peel one balanced pair of outer parens, only when the first and last
// characters match at the same depth boundary: `((A AND B))` loses a layer,
// `(A) AND (B)` keeps both. The depth scan skips quoted literals — counting a
// paren in `matches '(a|b)'` misreads which pair, if any, is the outer one.
function stripOuterParens(expr) {
  while (expr.length >= 2 && expr[0] === '(' && expr[expr.length - 1] === ')') {
    let depth = 0;
    let outerMatches = true;
    let quote = null;
    for (let i = 0; i < expr.length - 1; i++) {
      const ch = expr[i];
      if (quote) {
        if (ch === '\\') { i++; continue; }
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === "'" || ch === '"') { quote = ch; continue; }
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      if (depth === 0 && i < expr.length - 1) { outerMatches = false; break; }
    }
    if (outerMatches) expr = expr.slice(1, -1).trim();
    else break;
  }
  return expr;
}

// Parse a clock_started_at_<event> timestamp host-timezone-independently,
// returning { date, assumed_utc } with a null date on rejection. A bare
// `new Date(s)` fails twice here: an unparseable value yields an Invalid Date
// whose .toISOString() throws later, crashing the deadline math in close(); and
// a zone-less ISO value is read in the HOST timezone, shifting a statutory
// deadline by the host's UTC offset. Such a value is coerced to UTC.
function parseOperatorClock(raw) {
  if (typeof raw !== 'string') {
    const d = new Date(raw);
    return { date: Number.isNaN(d.getTime()) ? null : d, assumed_utc: false };
  }
  const trimmed = raw.trim();
  if (!trimmed) return { date: null, assumed_utc: false };
  // A full ISO datetime missing only its zone designator. A date-only value is
  // already parsed as UTC midnight by spec and is left alone.
  let assumedUtc = false;
  let candidate = trimmed;
  const zonelessDateTime = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;
  if (zonelessDateTime.test(trimmed)) {
    candidate = trimmed.replace(' ', 'T') + 'Z';
    assumedUtc = true;
  }
  const d = new Date(candidate);
  if (Number.isNaN(d.getTime())) return { date: null, assumed_utc: false };
  return { date: d, assumed_utc: assumedUtc };
}

// The start instant for a jurisdictional clock event. The legal contract is that
// the clock starts from OPERATOR AWARENESS, not from the moment the engine emits
// a `detected` classification. An explicitly submitted clock_started_at_<event>
// wins. detect_confirmed on a detected classification, and analyze_complete /
// validate_complete once phaseFlags says their phase ran, auto-stamp `now` ONLY
// under runOpts.operator_consent.explicit (--ack). Everything else is null.
function computeClockStart(eventName, agentSignals, runOpts = {}, engineClassification = null, phaseFlags = {}, frozenEpoch = null) {
  const key = `clock_started_at_${eventName}`;
  if (agentSignals && agentSignals[key]) {
    const { date, assumed_utc } = parseOperatorClock(agentSignals[key]);
    if (!date) {
      if (runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'invalid_clock_value',
          clock_event: eventName,
          key,
          supplied: String(agentSignals[key]).slice(0, 80),
          message: `${key} is not a valid ISO instant; the jurisdictional clock did not start. Submit an ISO-8601 timestamp (e.g. 2026-06-12T10:00:00Z).`,
        }, { dedupeKey: e => e.key || '' });
      }
      return null;
    }
    if (assumed_utc && runOpts && Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, {
        kind: 'clock_timezone_assumed_utc',
        clock_event: eventName,
        key,
        supplied: String(agentSignals[key]).slice(0, 80),
        message: `${key} carries no timezone designator; interpreted as UTC. Append 'Z' or an offset to make the regulatory deadline unambiguous.`,
      }, { dedupeKey: e => e.key || '' });
    }
    return date;
  }
  // Confirmed from EITHER a submitted detection_classification or the engine's
  // own verdict: indicators fired through signal_overrides carry no separate
  // classification, and their regulatory clock would stall silently.
  const detected = agentSignals?.detection_classification === 'detected'
    || engineClassification === 'detected';
  const ack = !!(runOpts && runOpts.operator_consent && runOpts.operator_consent.explicit === true);
  if (!ack) return null;
  // Deterministic mode roots every auto-started clock in the frozen epoch, so
  // two runs over the same evidence agree.
  const autoNow = () => (frozenEpoch ? new Date(frozenEpoch) : new Date());
  if (eventName === 'detect_confirmed' && detected) return autoNow();
  if (eventName === 'analyze_complete' && phaseFlags && phaseFlags.analyze_complete === true) return autoNow();
  if (eventName === 'validate_complete' && phaseFlags && phaseFlags.validate_complete === true) return autoNow();
  return null;
}

// The agentSignals lookup key for a precondition expression: the leading path
// token, hyphens included, since a hyphenated id is the catalog norm.
function expressionKey(expr) {
  const m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)/);
  return m ? m[1] : expr;
}

// Substitute ${var} placeholders against ctx. An unresolved key renders as
// `<MISSING:key>`, never the literal `${key}` — a notification draft otherwise
// reaches a regulator with a raw template in it. missingTracker, when an array,
// collects the keys for missing_interpolation_vars[].
function interpolate(tpl, ctx, missingTracker) {
  if (!tpl || typeof tpl !== 'string') return tpl;
  return tpl.replace(/\$\{(\w+)\}/g, (_, key) => {
    const v = ctx ? ctx[key] : undefined;
    if (v !== undefined && v !== null) return String(v);
    if (missingTracker && Array.isArray(missingTracker) && !missingTracker.includes(key)) {
      missingTracker.push(key);
    }
    return `<MISSING:${key}>`;
  });
}

// Pre-run discovery: every directive across every playbook.
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
          // An operator picking a directive needs operator-facing prose.
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
  // Exported so the library-side path the CLI guard cannot reach is testable
  // without spawning a subprocess.
  sanitizeOperatorText,
  // internal helpers exposed for tests
  _resolvedPhase: resolvedPhase,
  _deepMerge: deepMerge,
  _evalCondition: evalCondition,
  _interpolate: interpolate,
  _activeRuns: _activeRuns,
  _acquireLock: acquireLock,
  _acquireLockDiagnostic: acquireLockDiagnostic,
  _releaseLock: releaseLock,
  _lockFilePath: lockFilePath,
  _vulnIdToUrn: vulnIdToUrn,
  _buildCsafBranches: buildCsafBranches,
  _advisoryAuthorityFor: advisoryAuthorityFor,
  _computeClockStart: computeClockStart,
  _worstActiveExploitation: worstActiveExploitation,
  // Re-exported from scoring so a test can enforce parity between the catalog
  // scorer and the runtime evaluator at the seam.
  _activeExploitationLadder: scoring.ACTIVE_EXPLOITATION_LADDER,
};
