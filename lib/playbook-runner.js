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
const os = require('os');
const crypto = require('crypto');
const scoring = require('./scoring');
const { assertIdComponent } = require('./id-validation');
const codepointClass = require('../vendor/blamejs/codepoint-class.js');

// cross-ref-api wraps catalog reads. If cve-catalog.json is corrupt
// JSON, cross-ref-api's loadCatalog (post-v0.12.14) catches the parse
// failure, returns an empty stub, and accumulates the error in
// getLoadErrors(). run() probes for accumulated load errors and returns
// a structured `blocked_by:'catalog_corrupt'` rather than letting analyze
// silently operate against an empty catalog. Note: the call to
// xref.byCve below force-touches the catalog so the load error surfaces
// at module load (it's lazy otherwise), which gives run() a deterministic
// signal regardless of submission shape.
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

// Probe the catalog (parse it, surface any load error) LAZILY on first need
// rather than at module load. The probe parses the ~2.6MB CVE catalog (~8.5ms);
// doing it eagerly charged that to every cheap verb (brief/ask/lint/
// discover) that never analyzes. run() calls this before the analyze path, so
// a corrupt catalog still surfaces as blocked_by:'catalog_corrupt' before
// analyze — just not on verbs that don't touch the catalog. Memoized: probes
// at most once per process.
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

// In-process mutex tracker. Survives only the current Node process.
// Persistent cross-process coordination is out of scope — that's for the GRC
// platform integration, not the runner.
const _activeRuns = new Set();

// Bounded push into a runtime_errors array with per-kind caps, optional
// per-kind dedupe, and a total cap. A long-running detect/analyze loop that
// rejects a malformed catalog entry on every iteration would otherwise let
// runtime_errors grow unbounded and balloon the bundle output. When the cap
// fires the helper records a `_truncated` sentinel so downstream consumers
// see the drop without needing to compare cardinalities.
//
//   opts.cap        per-kind cap (default 100)
//   opts.totalCap   total array cap (default 1000)
//   opts.dedupeKey  optional fn(entry) returning a string key. When supplied,
//                   a push with the same (kind, dedupeKey) tuple is skipped.
//
// Returns true if the entry was pushed, false otherwise (capped or deduped).
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

// Unwrap a legacy `{ _regex_eval_error: { source, expr, message } }` record
// into the flat fields pushRunError dedupes on. Used by evalCondition()'s
// regex-failure path so per-(source, expr) duplicates collapse to one entry
// plus a `_truncated` sentinel when the cap fires.
function _regexErrorPayload(rec) {
  if (rec && typeof rec === 'object' && rec._regex_eval_error) {
    const { source, expr, message } = rec._regex_eval_error;
    return { source, expr, message, _regex_eval_error: rec._regex_eval_error };
  }
  return { _regex_eval_error: rec };
}

// --- catalog access ---

function listPlaybooks() {
  if (!fs.existsSync(PLAYBOOK_DIR)) return [];
  return fs.readdirSync(PLAYBOOK_DIR)
    .filter(f => f.endsWith('.json') && !f.startsWith('_'))
    .map(f => f.replace(/\.json$/, ''));
}

function loadPlaybook(playbookId) {
  // Traversal defense co-located with the path.join — every caller gets it,
  // not just the CLI dispatcher's pre-validation wrapper.
  assertIdComponent(playbookId, 'playbook');
  const p = path.join(PLAYBOOK_DIR, `${playbookId}.json`);
  if (!fs.existsSync(p)) throw new Error(`Playbook not found: ${playbookId} (expected ${p})`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// Per-run playbook cache. Each phase function reads runOpts._playbookCache
// before falling back to loadPlaybook(). run() sets _playbookCache once at
// entry so seven phases share one disk read + JSON parse instead of seven.

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
    // Skip prototype-polluting keys. phase_overrides come from the Ed25519-
    // signed catalog today, but deepMerge is an exported utility (_deepMerge)
    // and must never rebind a prototype if reused with parsed/operator input —
    // same guard as the precondition_checks merge below. `out[k]=` on
    // k='__proto__' would invoke the prototype-rebinding setter.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = (k in out) ? deepMerge(out[k], v) : v;
  }
  return out;
}

// --- pre-flight: currency + preconditions + mutex ---

/**
 * Pre-flight gate. Three concerns:
 *
 *   1. Currency. threat_currency_score < 50 hard-blocks unless
 *      runOpts.forceStale=true. < 70 emits a warning issue.
 *   2. Preconditions. _meta.preconditions[] entries with on_fail in
 *      {halt, warn, skip_phase} are evaluated against
 *      runOpts.precondition_checks[id]. Missing values → precondition_unverified
 *      issue (plus halt if on_fail=halt). False values → precondition_warn or
 *      precondition_skip per on_fail.
 *   3. Mutex. _meta.mutex[] intersect with the in-process active runs set
 *      AND with the filesystem lockfile dir blocks the run.
 *
 * When runOpts.strictPreconditions === true, warn-level outcomes
 * (precondition_warn, precondition_unverified with on_fail=warn or
 * skip_phase) are ESCALATED to halts. The function returns ok:false
 * with blocked_by='precondition' and an issues array containing
 * precondition_halt entries. Callers wanting "CI gate: any unverified
 * precondition is a failure" pass strictPreconditions=true.
 *
 * When a precondition with on_fail='skip_phase' fails, the issue carries
 * skip_phase: 'detect' (default) so run() can route to a skipped-phase
 * placeholder rather than executing detect against a missing
 * prerequisite.
 */
function preflight(playbook, runOpts = {}) {
  const issues = [];
  const meta = playbook._meta;
  const strict = runOpts.strictPreconditions === true;

  // 1. Currency gate
  const score = meta.threat_currency_score;
  // A non-numeric score (absent / null / NaN from a malformed _meta) must HARD
  // BLOCK, not slip through: `undefined < 50` is false, which would silently
  // bypass the staleness gate on exactly the playbooks whose currency metadata
  // is broken. Treat "no usable score" as the most-stale state.
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

  // 2. Preconditions
  for (const pc of meta.preconditions || []) {
    const submitted = runOpts.precondition_checks?.[pc.id];
    if (submitted === undefined) {
      const submission_hint = `Submit precondition_checks in your evidence JSON, e.g. { "precondition_checks": { "${pc.id}": true } }. Pass via --evidence <file.json> or pipe to stdin with --evidence -. The runner lifts precondition_checks into runOpts before the gate evaluates.`;
      if (strict) {
        // strictPreconditions promotes unverified to halt regardless of
        // declared on_fail.
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
          // Explicit-false halts carry a specific remediation so the renderer
          // prefers it over the generic platform-gate hint — an intent/ownership
          // gate (e.g. operator-owns-ci-fleet) is not a platform mismatch.
          remediation: `Precondition ${pc.id} was submitted as false: ${pc.description} Attest it as true and re-run — submit precondition_checks {"${pc.id}": true} in your evidence JSON, or pass the owning collector's attestation flag at collect time (for example: collect cicd-pipeline-compromise --attest-ownership).`,
          issues
        };
      }
      if (strict) {
        // Warn-level + skip_phase outcomes escalate to halt under strict.
        issues.push({ kind: 'precondition_halt', id: pc.id, message: pc.description, escalated_from: pc.on_fail === 'skip_phase' ? 'precondition_skip' : 'precondition_warn' });
        return {
          ok: false,
          blocked_by: 'precondition',
          reason: `Precondition ${pc.id} (${pc.check}) failed; strict-preconditions enabled.`,
          issues
        };
      }
      if (pc.on_fail === 'skip_phase') {
        // Emit a skip_phase field so run() can route to a skipped-phase
        // placeholder. Default target phase is 'detect' (the most common
        // skip target — preconditions typically gate host-side detection).
        // Playbooks may override via pc.skip_phase.
        issues.push({ kind: 'precondition_skip', id: pc.id, message: pc.description, skip_phase: pc.skip_phase || 'detect' });
      } else {
        issues.push({ kind: 'precondition_warn', id: pc.id, message: pc.description });
      }
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

// lockDir lives at a stable per-user path so two CLI invocations from
// different working directories still share lock state for cross-process
// mutex enforcement. A process.cwd()-relative dir would let invocations
// from /tmp and from /home/user/project simultaneously each see an empty
// locks dir and both run unchallenged.
//
// Resolution order (most-specific first):
//   1. EXCEPTD_LOCK_DIR        explicit container/CI override
//   2. EXCEPTD_HOME || ~/.exceptd  + /locks/<platform>   per-user default
//   3. os.tmpdir()/exceptd-locks-<platform>              last-resort fallback
//      when the per-user home is non-writable (read-only home, restricted
//      sandbox/CI runner).
//
// The per-user home (mirroring the orchestrator's watch.lock + attestation
// roots) is both the safer location — a per-user dir is not the
// world-writable shared OS tempdir a preplant/symlink attack targets — and
// the better fit for lockDir's stated goal: ~/.exceptd is per-user-stable
// across working directories, whereas the shared tmpdir is the weaker
// choice. The path keys on os.platform() so Windows/macOS/Linux locks live
// under separate directories (avoids cross-platform stale-PID confusion when
// a host is shared across OSes via networked FS).
function resolveLockDir() {
  if (process.env.EXCEPTD_LOCK_DIR) return process.env.EXCEPTD_LOCK_DIR;
  const home = process.env.EXCEPTD_HOME || (os.homedir() && path.join(os.homedir(), '.exceptd'));
  if (home) {
    const dir = path.join(home, 'locks', process.platform);
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      // Probe writability with a marker; remove on success. A home that
      // mkdirs but can't be written (read-only mount, restrictive ACL) must
      // fall through to the tmpdir fallback rather than silently no-op every
      // lock write.
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
  // Owner-only (0700): the mutex lock files inside use O_EXCL ('wx'), but
  // tightening the parent directory keeps another local user from listing or
  // tampering with this user's lock set.
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { /* exists / EACCES — non-fatal */ }
  return dir;
}

function lockFilePath(playbookId) {
  try { return path.join(lockDir(), `${playbookId}.lock`); }
  catch { return null; }
}

// Same-PID stale-lockfile reclaim threshold. A same-process orphan (e.g.
// an earlier run() that crashed without unlinking, or a try/catch that
// swallowed the release) older than this is presumed dead and reclaimed.
// 30s mirrors lib/refresh-external.js and lib/prefetch.js; long enough
// that no legitimate playbook hold reaches it (govern/look/run phases
// complete well inside one second per playbook), short enough that a
// wedged process recovers within one CI step rather than the rest of its
// lifetime.
const STALE_LOCK_MS = 30_000;

// Create the mutex lock file with an exclusive, owner-only descriptor
// (O_CREAT | O_EXCL | 0o600 via openSync 'wx'). The lock-file NAME is
// deliberately predictable — it IS the cross-process mutex, so every contender
// must agree on it; security comes from the exclusive create (a preplanted file
// or symlink makes the open throw EEXIST/EPERM, never a silent follow), the
// 0o700 lock directory, and the 0o600 mode — written through openSync so the
// secure-create primitive is explicit rather than a bare writeFileSync. Throws
// EEXIST when the lock is already held, which every caller already handles.
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
    // Stale-PID reclaim. Without it, a process that crashed mid-run
    // leaves its lockfile behind and every subsequent invocation runs
    // UNLOCKED. Mirror withCatalogLock's pattern: parse the recorded pid,
    // probe with `process.kill(pid, 0)`. ESRCH means the holder is dead —
    // unlink and retry once. EPERM (alive, different user) or any other
    // condition: leave the lock alone and return null with a diagnostic so
    // the caller knows acquisition failed because the lock is genuinely
    // held (not because the FS is broken or the playbook id is malformed).
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
        // Same-PID stale-lockfile reclaim. If the recorded pid is ours,
        // the only way to escape an orphaned same-process lockfile is by
        // mtime. Do NOT blindly reclaim same-PID — legitimate reentrancy
        // (e.g. nested run() within one process) must still return null
        // so the caller knows the lock is held. A fresh same-PID lockfile
        // is reentrancy; one older than STALE_LOCK_MS is an orphan from
        // a crashed prior hold (or a try/catch that swallowed the release)
        // and must be reclaimed — otherwise the process can never acquire
        // this lock again for the rest of its lifetime.
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
    // Lock genuinely held (or filesystem error). Returning null keeps
    // back-compat with existing call sites that test `if (!lockPath)`.
    // Callers that want a clearer diagnostic should call
    // `acquireLockDiagnostic` instead.
    return null;
  }
}

// Callers needing to distinguish "couldn't acquire because the lock is
// genuinely held by a live process" from "couldn't acquire because of an
// unexpected error" can use this thin diagnostic wrapper.
// Returns either { ok: true, path } or { ok: false, reason, lock_path?, holder_pid? }.
// The bare `acquireLock` keeps its historical null-on-failure contract.
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
      // Same-PID stale-lockfile reclaim (diagnostic variant). Same
      // semantics as in acquireLock: a same-process lockfile older than
      // STALE_LOCK_MS is an orphan and must be reclaimed; a fresher one
      // is legitimate reentrancy and stays held.
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

// --- phase 1: govern ---

/**
 * Load GRC context for the agent. Returns jurisdiction obligations (with
 * window_hours + clock_starts so close() can compute deadlines later), theater
 * fingerprints, framework gap summary, and skills to preload.
 */
function govern(playbookId, directiveId, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const g = resolvedPhase(playbook, directiveId, 'govern');
  // Sort jurisdiction obligations by window_hours ascending so the
  // tightest deadline (e.g. DORA's 4h, NIS2's 24h, GDPR's 72h) surfaces
  // first. Operators reading the govern output for ack-time briefing need
  // the most urgent clock at the top of the list.
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
    // v0.11.12 (#124): --ack belongs semantically in govern (it acknowledges
    // the jurisdiction_obligations surfaced here). Carry it forward so
    // phases.govern.operator_consent reflects the consent state. Null when
    // --ack was not passed.
    operator_consent: runOpts.operator_consent || null
  };
}

// --- phase 2: direct ---

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

// --- phase 3: look (engine emits, agent executes) ---

function look(playbookId, directiveId, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
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
      _original_source: a.source,
      // In air-gap mode an artifact with NO air_gap_alternative silently keeps
      // its original (possibly network-bound) source — defeating air-gap with no
      // signal. Flag it so the agent treats the source as not-offline-verified
      // and the gap is observable instead of a silent network fallback.
      ...(airGap && !a.air_gap_alternative ? { air_gap_alternative_missing: true } : {}),
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
function detect(playbookId, directiveId, agentSubmission = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const det = resolvedPhase(playbook, directiveId, 'detect');
  const artifacts = agentSubmission.artifacts || {};
  const overrides = agentSubmission.signal_overrides || {};

  // v0.11.4 (#71): canonicalize the indicator result vocabulary. Operators
  // submit shapes like "no_hit" / "clean" / "ok" / false from years of
  // CI/security tooling convention; the engine internally uses
  // hit | miss | inconclusive. Without canonicalization every flat-shape
  // observation with result:"no_hit" silently fell through to inconclusive
  // and broke per-indicator detection. Canonicalization happens here so
  // both detect() and normalizeSubmission consumers see the same outcomes.
  const canonicalize = (v) => {
    if (v === true || v === 'hit' || v === 'detected' || v === 'positive') return 'hit';
    if (v === false || v === 'miss' || v === 'no_hit' || v === 'no-hit' || v === 'clean' || v === 'clear' || v === 'not_hit' || v === 'ok' || v === 'pass' || v === 'negative') return 'miss';
    if (v === 'inconclusive' || v === 'unknown' || v === 'unverified' || v === null) return 'inconclusive';
    return null; // truly unknown — fall through
  };

  // Per-indicator FP-check attestation map. Operators submit
  //   signal_overrides: { '<indicator-id>__fp_checks': { '<fp-check-name>': true } }
  // to declare which named false_positive_checks_required[] entries on the
  // indicator have been satisfied. An unverified FP check downgrades the
  // verdict from 'hit' to 'inconclusive' and surfaces fp_checks_unsatisfied
  // on the per-indicator result. See AGENTS.md Hard Rule #6 (compliance
  // theater) and AGENTS.md §"detect (AI)" — a `hit` without its FP checks
  // is not yet a `detected` classification.
  // Optional per-indicator evidence locations the submission supplies
  // (`evidence_locations: { "<indicator-id>": ["path", {uri,startLine}] }`).
  // Threaded onto each firing indicator so the SARIF renderer can populate
  // results[].locations — without this, secret/file findings ship
  // location-less and GitHub code-scanning drops them.
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
      // Gate 'hit' verdict on per-indicator false_positive_checks_required
      // satisfaction. The FP-check attestation arrives as a sibling key
      // '<id>__fp_checks' in signal_overrides; default behavior (no
      // attestation) treats every required FP check as UNSATISFIED.
      if (verdict === 'hit' && Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length) {
        // A hostile or buggy attestation may be a Proxy whose property
        // accessors throw. The filter below reads `att[fpName]` for each
        // required check; an exception inside the read would crash detect()
        // and abort the entire run. Wrap the FP-check evaluation in a
        // try/catch: on throw, treat ALL required checks as unsatisfied
        // (safest default — never silently honor an attestation we couldn't
        // read) and surface a runtime_error so the operator sees why.
        try {
          const attestation = overrides[`${ind.id}__fp_checks`];
          // Arrays satisfy `typeof === 'object'` but are NOT a valid
          // attestation map. A submission like
          //   signal_overrides: { sig__fp_checks: [true, true] }
          // would otherwise have its truthy entries matched via the index
          // fallback (att['0'] === true), silently bypassing every FP-check
          // requirement. Reject arrays explicitly so they fall through to
          // the empty-attestation branch (every required check
          // unsatisfied).
          const safeAtt = Array.isArray(attestation) ? null : attestation;
          const att = (safeAtt && typeof safeAtt === 'object') ? safeAtt : {};
          const unsatisfied = ind.false_positive_checks_required.filter(fpName => {
            // Match either by exact name string OR by indexed key '0', '1', ...
            // because false_positive_checks_required entries are free-text
            // strings, not ids. Operators may attest either by the literal
            // string or by index. Default: unsatisfied.
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
          // Treat every required check as unsatisfied — we couldn't trust the
          // attestation map. Surface the throw so operators can chase the
          // root cause (Proxy with a throwing getter, frozen object that
          // tripped invariants, etc.).
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
      // An override WAS supplied for this indicator but its value didn't
      // canonicalize to hit/miss/inconclusive (e.g. "maybe", "present", a
      // number). Pre-fix this was silently dropped — the operator believed
      // they'd asserted a result but the signal vanished, yielding a false
      // not_detected. Surface it as a runtime_error (mirrors the
      // classification_override_invalid signal) so the drop is visible.
      if (rawOverride !== undefined && runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'signal_override_unrecognized',
          indicator_id: ind.id,
          supplied_value: (typeof rawOverride === 'object') ? JSON.stringify(rawOverride).slice(0, 80) : String(rawOverride).slice(0, 80),
          message: `signal_overrides["${ind.id}"] value was not recognized (expected hit/miss/inconclusive or a boolean); the signal was ignored.`,
        }, { dedupeKey: e => e.indicator_id || '' });
      }
      // Without a usable override, treat any captured artifact as evidence
      // the indicator could be evaluated. Mark inconclusive if any artifact
      // was captured (engine doesn't pattern-match raw artifact content; the
      // host AI is responsible for that). With NO captured artifacts, this is
      // a clean empty submission — emit 'miss' so the run can reach
      // classification:'not_detected' rather than getting stuck inconclusive.
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
  const rawOverride = (agentSubmission.signals && agentSubmission.signals.detection_classification);
  const validOverrides = new Set(['detected', 'inconclusive', 'not_detected', 'clean']);
  // Any override that's a non-empty string but NOT in the allowlist (e.g.
  // 'present', 'unknown', '', '  detected  ', 'Detected') surfaces as a
  // runtime_error rather than silently falling through to engine-computed
  // classification. Operators submitting case variants / whitespace-padded
  // strings deserve a clear diagnostic, not a quiet downgrade. Treat the
  // override as absent for classification purposes once recorded.
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

  // Refuse ALL classification overrides (`detected`, `clean`,
  // `not_detected`) when any indicator was FP-downgraded. A submission
  // that maps to `'not_detected'` (either literally or via `'clean'`,
  // which maps to `'not_detected'` at this site) MUST NOT hide a
  // `verdict: 'hit'` indicator whose `false_positive_checks_required[]`
  // were unattested — that's a strictly worse false-negative outcome than
  // allowing 'detected' through. Substitute 'inconclusive' and emit a
  // runtime_error.
  // Record indicator IDs and an unsatisfied-checks count ONLY — never the
  // literal FP-check check-name strings (those are an attestation-bypass
  // hint for a hostile agent reading the runtime_errors).
  const anyFpDowngrade = indicatorResults.some(r => Array.isArray(r.fp_checks_unsatisfied) && r.fp_checks_unsatisfied.length > 0);

  let classification;
  // Track whether the override was actually honored, so we don't report a
  // refused override as "applied" (L6).
  let overrideEffective = !!override;
  if (override) {
    classification = override === 'clean' ? 'not_detected' : override;
    if (anyFpDowngrade) {
      const substituted = 'inconclusive';
      const attempted = override; // record what the operator submitted, not the mapped form
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
      // A not_detected/clean override must not silently bury a DETERMINISTIC
      // hit. A deterministic indicator firing is high-signal evidence; hiding
      // it as not_detected is a strictly worse false-negative than leaving the
      // run inconclusive. (Probabilistic hits remain overridable — that's the
      // legitimate "I confirmed these are benign" workflow.) Substitute
      // inconclusive and surface why.
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
    // v0.11.3 #71: surface what detect actually consumed. Operators reading
    // the detect output now see whether their flat-shape observations + the
    // signal_overrides + the classification override all reached the runner.
    observations_received: Object.keys(agentSubmission.artifacts || {}),
    signals_received: Object.keys(agentSubmission.signal_overrides || {}),
    // v0.11.4 (#73): downstream consumers iterating `indicators_evaluated`
    // expect an array, not a count. Restore as array; provide
    // `indicators_evaluated_count` for callers wanting the integer.
    indicators_evaluated: indicatorResults.map(i => ({
      signal_id: i.id,
      outcome: i.verdict,
      confidence: i.confidence,
      // v0.11.5 #85: surface which observation produced this indicator's
      // outcome (when the agent submitted it via flat-shape observation +
      // indicator + result fields). Null when no observation drove the
      // indicator (engine-computed default).
      from_observation: agentSubmission._signal_origins?.[i.id] || null,
    })),
    indicators_evaluated_count: indicatorResults.length,
    // Only report the override as applied when it was actually honored — a
    // refused override (FP-downgrade or deterministic-hit masking) left
    // `classification` as inconclusive, so reporting the attempted value here
    // would contradict the verdict.
    classification_override_applied: (override && overrideEffective) ? (override === 'clean' ? 'not_detected' : override) : null,
    submission_shape_seen: agentSubmission._original_shape || (agentSubmission.artifacts ? 'nested (v0.10.x)' : 'empty'),
    // Pass through any flat-shape observation collisions detected at
    // normalize time so analyze() can publish them under
    // analyze.signal_origins_with_collisions.
    _signal_origins_collisions: Array.isArray(agentSubmission._signal_origins_collisions) ? agentSubmission._signal_origins_collisions.slice() : []
  };
}

// --- phase 5: analyze ---

/**
 * RWEP composition + blast-radius scoring + theater check + framework gap
 * mapping + escalation evaluation. Inputs are the detect result + any
 * agent-submitted signal_values (e.g. blast_radius classification).
 */
function analyze(playbookId, directiveId, detectResult, agentSignals = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const an = resolvedPhase(playbook, directiveId, 'analyze');
  const directive = findDirective(playbook, directiveId);
  // F6/F20/F24: when analyze() is called directly (not via run()), no
  // runtime-error accumulator exists in runOpts. Ensure there's always a
  // local array so blast_radius / theater / xref errors surface in the
  // returned analyze.runtime_errors.
  if (!Array.isArray(runOpts._runErrors)) {
    runOpts = { ...runOpts, _runErrors: [] };
  }

  // Resolve catalogued CVEs from the domain.cve_refs list. This list is the
  // playbook's CVE scan-coverage enumeration — every CVE this playbook can
  // detect. By itself it is NOT a statement that the operator is affected by
  // any of these CVEs; affected-ness requires evidence correlation in detect.
  //
  // Two distinct sets are computed below:
  //
  //   catalogBaselineCves — every CVE the playbook scans for, with full
  //       per-CVE catalog context (RWEP / KEV / CVSS / AI-discovery /
  //       active-exploitation / patch state). Always populated when the
  //       playbook has domain.cve_refs. Each entry carries correlated_via=null
  //       and a `note` flagging it as catalog-only.
  //
  //   matchedCves       — CVEs the operator's submitted evidence actually
  //       correlates to. Correlation paths:
  //         (a) An indicator fired (verdict === 'hit') whose attack_ref or
  //             atlas_ref intersects the CVE's attack_refs / atlas_refs in
  //             the catalog.
  //         (b) An agentSignal explicitly references the CVE id with a
  //             truthy value (`agentSignals[cveId] === true`) or with a
  //             string value 'hit' / 'detected' / 'affected'.
  //       Each entry carries correlated_via=<reason string> so downstream
  //       consumers (CSAF / SARIF / OpenVEX / human renderer) can show the
  //       provenance, and so an empty matchedCves means "no evidence
  //       correlated to operator's submission" rather than "playbook has
  //       no CVEs of interest."
  //
  // VEX filter (agentSignals.vex_filter): a set of CVE IDs the operator has
  // formally declared not_affected via CycloneDX/OpenVEX. VEX-dropped CVEs
  // are removed from BOTH arrays (they're not affected — neither correlated
  // nor part of effective scan coverage for this run).
  const cveRefs = playbook.domain.cve_refs || [];
  const vexFilter = agentSignals.vex_filter instanceof Set ? agentSignals.vex_filter
    : (Array.isArray(agentSignals.vex_filter) ? new Set(agentSignals.vex_filter) : null);
  // Distinguish OpenVEX/CycloneDX "drop entirely" dispositions
  // (not_affected / false_positive) from "keep but annotate" dispositions
  // (fixed / resolved). vexFilterFromDoc returns the union; the "fixed" set
  // is computed below from agentSignals.vex_fixed when the operator passes
  // it (CLI populates it from the VEX doc alongside vex_filter).
  const vexFixed = agentSignals.vex_fixed instanceof Set ? agentSignals.vex_fixed
    : (Array.isArray(agentSignals.vex_fixed) ? new Set(agentSignals.vex_fixed) : null);
  // Wrap xref.byCve() so a corrupt catalog (or transient missing-index
  // anomaly) surfaces as a runtime_error rather than crashing analyze().
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
  // VEX-fixed CVEs remain in matched/catalog arrays but get annotated
  // with vex_status:'fixed' downstream so consumers see them as resolved.
  // Source from catalogBaselineCves (post-vexFilter survivors), NOT allCves: a
  // CVE the operator marked BOTH not_affected (dropped by vexFilter) AND fixed
  // is contradictory, and listing it as fixed while it's absent from
  // matched/baseline would have it appear in fixed_cves but nowhere else.
  const vexFixedIds = vexFixed
    ? catalogBaselineCves.filter(c => vexFixed.has(c.cve_id)).map(c => c.cve_id)
    : [];

  // Build correlation map: cve_id -> array of "indicator_hit:<id>" / "signal:<id>" reasons.
  const correlationsByCve = new Map();
  const addCorrelation = (cveId, reason) => {
    if (!correlationsByCve.has(cveId)) correlationsByCve.set(cveId, []);
    const arr = correlationsByCve.get(cveId);
    if (!arr.includes(reason)) arr.push(reason);
  };
  // (a) indicator-hit → CVE via shared attack_ref / atlas_ref.
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
  // (b) agentSignals explicitly referencing a CVE id.
  for (const c of catalogBaselineCves) {
    const sig = agentSignals[c.cve_id];
    if (sig === true || sig === 'hit' || sig === 'detected' || sig === 'affected') {
      addCorrelation(c.cve_id, `signal:${c.cve_id}`);
    }
  }

  // Indicator-level cve_ref correlation. Indicators may declare a
  // cve_ref (string OR string[]) naming CVEs whose presence the indicator
  // pattern-matches. When such an indicator fires AND the named CVE exists
  // in the catalog, the CVE joins matched_cves with correlated_via=
  // 'indicator_cve_ref:<indicator-id>'. The catalog lookup also brings in
  // CVEs the playbook didn't enumerate in domain.cve_refs — they're appended
  // to the working catalog set so the downstream matchedCves filter picks
  // them up. Dedupe is automatic via correlationsByCve (Map keyed on cve_id).
  const extraCatalogCves = [];
  const seenCatalogIds = new Set(catalogBaselineCves.map(c => c.cve_id));
  for (const fired of firedIndicators) {
    const indicator = (playbookDetect.indicators || []).find(i => i.id === fired.id);
    if (!indicator) continue;
    const raw = indicator.cve_ref;
    const refs = Array.isArray(raw) ? raw : (typeof raw === 'string' && raw ? [raw] : []);
    for (const cveId of refs) {
      // VEX-drop these the same as catalog CVEs.
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

  // Per-CVE shape — identical between matched_cves and catalog_baseline_cves
  // so consumers can iterate either without branching. matched_cves entries
  // carry a non-null correlated_via array; catalog_baseline_cves entries
  // carry correlated_via:null and a `note` clarifying the field's intent.
  const cveShape = (c, correlatedVia) => {
    // Annotate VEX-fixed CVEs with vex_status. matched_cves still
    // includes them so audit trails and SBOM reports surface "we know this
    // is in scope but vendor declared it fixed."
    const vexStatus = (vexFixed && vexFixed.has(c.cve_id)) ? 'fixed' : null;
    return {
      cve_id: c.cve_id,
      // attack_class is the coarse chainable taxonomy (kernel-lpe /
      // mcp-supply-chain / ai-c2 / prompt-injection / container-escape / …)
      // the sbom -> deep-dive feeds_into rules quantify over
      // (`any matched_cve.attack_class == 'kernel-lpe'`). It comes from the
      // catalog entry's explicit attack_class only — no fuzzy inference from
      // the free-form `type`, so an unclassified CVE stays null and the chain
      // correctly does not fire (no false escalation) rather than misrouting.
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

  // RWEP composition: start from the per-CVE rwep_score of evidence-correlated
  // matches (NOT catalog baseline) so RWEP base reflects what the operator's
  // evidence actually surfaced. The "max" reduction across matched CVEs is
  // intentional — RWEP is a "worst-case real-world exploit priority", not
  // an arithmetic average. The most-exploitable CVE in the set drives the
  // base; secondary CVEs add via rwep_inputs adjustments below rather than
  // through base summing (which would double-count overlapping risk).
  // vex_status='fixed' CVEs do NOT drive the base — vendor declared them
  // resolved. They still appear in matched_cves for audit traceability but
  // don't elevate RWEP.
  const rwepEligible = matchedCves.filter(c => !(vexFixed && vexFixed.has(c.cve_id)));
  const baseRwep = rwepEligible.length ? Math.max(...rwepEligible.map(c => c.rwep_score)) : 0;

  // rwep_factor semantics: each rwep_input.weight is conditional on the
  // matched CVE having a corresponding attribute. Multiply weight by a
  // factor in [0, 1] derived from the first matched CVE's catalog
  // attribute so a weight only fires when its CVE-attribute supports it
  // (e.g. active_exploitation +25 only when the matched CVE is under
  // active exploitation). blast_radius is sourced from the analyze-phase
  // blast_radius_score / 5 (rubric ceiling). Negative weights
  // (patch_available, live_patch_available) keep their sign so a patched
  // CVE deducts the full magnitude when the catalog confirms a
  // patch is available.
  //
  // Aliasing: playbooks ship rwep_factor values `public_poc` and
  // `ai_weaponization` for what F5 calls `poc_available` and `ai_factor`.
  // Both spellings resolve here.
  const _factorScale = (factorName, cve, blastScore) => {
    if (!cve) return 0;
    switch (factorName) {
      case 'cisa_kev':
        return cve.cisa_kev === true ? 1 : 0;
      case 'active_exploitation': {
        const v = cve.active_exploitation || (cve.entry && cve.entry.active_exploitation);
        // Route through the shared scoring resolver instead of an inline
        // `ladder[v] ?? 0` lookup so a stray-cased value ('Confirmed') scales
        // identically to the catalog scorer AND an out-of-vocabulary value
        // ('in-the-wild') surfaces the RWEP_AE_UNRECOGNISED warning rather than
        // silently zeroing the active-exploitation weight. activeExploitationMultiplier
        // (not the bare resolveActiveExploitation().multiplier) is used precisely so
        // the no-match path is OBSERVABLE — the "out-of-vocab token must surface,
        // not silently default" class. For every canonical catalog value the
        // returned multiplier is identical to the prior inline lookup.
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
        // blast_radius weights scale by the 0-5 rubric score so a max-blast
        // finding gets full weight and a low-blast finding gets a fraction.
        if (typeof blastScore !== 'number' || blastScore < 0) return 0;
        return Math.min(1, blastScore / 5);
      }
      default:
        // Unknown factor: fire as binary (legacy behavior) so playbooks with
        // novel rwep_factor strings don't silently zero out.
        return 1;
    }
  };

  // blast_radius_score validation. No supplied value → null +
  // signal='default'. Supplied value out of [0,5] → null +
  // signal='rejected' + runtime_error. Supplied value in range → use it +
  // signal='supplied'. The runner never defaults to a rubric entry — that
  // would be the opposite of safe-default when the rubric's lowest entry
  // is the LOWEST-blast row.
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
  // Use the first evidence-correlated CVE as the canonical attribute
  // source for factor scaling. If matchedCves is empty there's no per-CVE
  // evidence to gate on. v0.12.15: the prior fallback was
  // `factorCve = null` → every factor returned 0 → catalog-shape playbooks
  // (secrets, library-author, crypto-codebase, framework, cred-stores,
  // containers, runtime, crypto, ai-api) that detect WITHOUT a per-CVE
  // evidence correlation emitted `weight_applied: 0` for every fired
  // indicator, producing `adjusted: 0` for every detection. The e2e suite
  // caught this — 9/20 scenarios failed `json_path_min.adjusted >= N`.
  //
  // Domain-level fallback: when no evidence-correlated CVE is available,
  // use the highest-rwep_score entry from `workingCatalogCves` (which is
  // built from `playbook.domain.cve_refs[]` — the playbook's canonical
  // "what we're about"). This preserves factor-scaling semantics while
  // recognizing that a catalog-shape playbook's threat class is already
  // declared by its domain refs. The factor-scale annotation surfaces
  // `factor_cve_source: 'evidence' | 'domain' | 'none'` so operators see
  // which fallback was used.
  let factorCveSource = 'none';
  // Prefer an RWEP-eligible (non-VEX-fixed) matched CVE to drive factor
  // scaling — a vendor-patched CVE must not inflate adjusted RWEP via its
  // exploitation / KEV / PoC multipliers. Do NOT fall back to matchedCves[0]:
  // when EVERY evidence-correlated CVE is VEX-fixed (rwepEligible empty but
  // matchedCves non-empty) the finding is remediated, so factor scaling must be
  // suppressed entirely — base is already 0 and the fired factors must not
  // raise the adjusted score (a vendor-fixed CVE's KEV/exploitation/PoC would
  // otherwise lift it above 0). The domain-CVE and class-weight fallbacks below
  // are skipped in that case too, so every fired factor scales by 0 via
  // _factorScale(factor, null, …).
  const allMatchedVexFixed = matchedCves.length > 0 && rwepEligible.length === 0;
  let factorCve = rwepEligible[0] || null;
  if (factorCve) {
    factorCveSource = 'evidence';
  } else if (!allMatchedVexFixed && workingCatalogCves.length > 0) {
    // Highest rwep_score from domain refs.
    factorCve = workingCatalogCves.reduce((worst, c) =>
      (typeof c.rwep_score === 'number' && (!worst || c.rwep_score > worst.rwep_score)) ? c : worst,
    null);
    if (factorCve) factorCveSource = 'domain';
  }
  // v0.12.15: five shipped playbooks (secrets, library-author,
  // crypto-codebase, framework, cred-stores, containers, runtime, crypto,
  // ai-api) ship with empty `domain.cve_refs` because their attack class is
  // class-of-vulnerability rather than CVE-specific. For those playbooks
  // neither evidence-correlation NOR the domain-CVE fallback yields a
  // factorCve, so every fired indicator's `weight_applied` was forced to
  // zero by `_factorScale` returning 0. Fall back to the pre-v0.12.14
  // semantics for this case only: apply the declared weight as-is
  // (factor_scale=1, legacy semantics). The factor_cve_source annotation
  // surfaces 'class' so operators see which mode the run used.
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
    // v0.12.15: class-of-vulnerability playbooks (no factorCve from
    // evidence OR domain) apply weights as-is via the legacy semantics.
    // For CVE-anchored playbooks, scale by the matched CVE's attributes.
    // Class fallback covers blast_radius too — when the agent submitted a
    // blast score, _factorScale honors it; otherwise the class-fallback
    // applies full weight (matching pre-v0.12.14 behavior, where every
    // fired indicator contributed its full declared weight).
    let scale, factorCveSourceForBreakdown;
    if (_classScaleFallback) {
      if (input.rwep_factor === 'blast_radius' && typeof blastRadiusScore === 'number') {
        // Operator-supplied blast score is still honored even in class mode.
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

  // compliance_theater_check — engine surfaces the test; agent runs it; we
  // accept the verdict in agentSignals.theater_verdict. When agent didn't
  // submit a verdict but the detect phase reached a clear classification,
  // derive one rather than leaving the field stuck in 'pending_agent_run':
  //   detect.classification = not_detected → theater_verdict = clear
  //   detect.classification = detected     → theater_verdict = pending_agent_run
  //                                          (agent still must run reality_test)
  //   detect.classification = inconclusive → theater_verdict = pending_agent_run
  // Aliases 'clean' / 'no_theater' map to 'clear' for ergonomics.
  //
  // Validate agentSignals.theater_verdict against an allowlist so
  // downstream consumers (CSAF/SARIF/OpenVEX) never emit bundles with
  // garbage verdicts like "TODO" or free-text strings. Allowlist: clear,
  // present, theater, pending_agent_run, unknown.
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

  // framework_gap_mapping — engine emits the mapping verbatim; analyze does
  // not compute new gaps here, just attaches the playbook-declared ones.
  const frameworkGaps = an.framework_gap_mapping || [];

  // escalation criteria are evaluated AFTER the analyze result is assembled
  // (below the result literal) so conditions can reference `analyze.*` and
  // `finding.*` paths — the same roots close()'s feeds_into context
  // resolves. The flat keys (rwep, blast_radius_score, theater_verdict,
  // agent signals) remain available unchanged.
  const escalations = [];
  const runtimeErrors = []; // E3: collect regex-eval errors during analyze
  const evalCtxRoot = { _runErrors: runOpts._runErrors || runtimeErrors };

  const result = {
    phase: 'analyze',
    playbook_id: playbookId,
    directive_id: directiveId,
    // Hard Rule #1 (AGENTS.md): every CVE reference must carry CVSS + KEV +
    // PoC + AI-discovery + active-exploitation + patch/live-patch availability.
    // Pull every required field from the catalog entry; null is only emitted
    // when the catalog itself lacks the value, never when we just forgot to
    // forward it. EPSS is included because validate-cves --live populates it.
    //
    // matched_cves — evidence-correlated only. Each entry has a non-null
    // correlated_via[] array naming the indicator hits or agent signals that
    // tied the operator's submission to this CVE. Empty array means the
    // playbook's scan coverage saw no matching evidence in this run.
    matched_cves: matchedCveEntries,
    // catalog_baseline_cves — every CVE the playbook scans for, with the
    // same per-CVE shape but correlated_via=null and a note explaining the
    // field is scan-coverage metadata, NOT an operator-affected list. Use
    // this when surfacing "what CVEs does this playbook check for?" Use
    // matched_cves when surfacing "what CVEs is the operator actually
    // affected by based on submitted evidence?"
    catalog_baseline_cves: catalogBaselineEntries,
    // rwep base is reduced via Math.max across matched CVEs. Surface the
    // reduction strategy as a discoverable field so operators reading the
    // bundle understand the semantics without grepping source.
    rwep: { base: baseRwep, adjusted: adjustedRwep, breakdown: rwepBreakdown, threshold: directive ? resolvedPhase(playbook, directiveId, 'direct').rwep_threshold : null, _rwep_base_strategy: 'max' },
    blast_radius_score: blastRadiusScore,
    // Visible annotation of where blast_radius_score came from:
    //   'supplied'  — operator/agent provided a value in [0, 5].
    //   'default'   — no value supplied; runner returned null (no rubric guess).
    //   'rejected'  — value supplied but out of range; treated as default + runtime_error.
    blast_radius_signal: blastRadiusSignal,
    blast_radius_basis: blastRubric.find(r => r.blast_radius_score === blastRadiusScore) || null,
    compliance_theater_check: {
      claim: an.compliance_theater_check?.claim,
      audit_evidence: an.compliance_theater_check?.audit_evidence,
      reality_test: an.compliance_theater_check?.reality_test,
      verdict: theaterVerdict,
      // Render verdict_text for both 'theater' AND 'present' verdicts
      // ('present' is a synonym used by some playbooks for "theater is here").
      verdict_text: (theaterVerdict === 'theater' || theaterVerdict === 'present')
        ? an.compliance_theater_check?.theater_verdict_if_gap
        : null
    },
    framework_gap_mapping: frameworkGaps,
    escalations,
    // v0.11.5 (#82): expose detect's per-indicator results + classification
    // here so close()'s bundle builders can iterate indicators that fired
    // and emit them as SARIF results / OpenVEX statements / CSAF notes.
    // Prefixed with underscore to signal "for internal/render use".
    _detect_indicators: detectResult.indicators || [],
    _detect_classification: detectResult.classification,
    // Non-underscore alias so catalog feeds_into / escalation conditions that
    // reference the natural `analyze.classification` path resolve (the
    // underscore-prefixed key was render-internal only, so those conditions
    // resolved undefined and were silently dead — e.g. citation-hygiene →
    // sbom, crypto-codebase → secrets). The underscore key stays for the
    // SARIF/CSAF render consumers. On the detect-skip path run() re-sets
    // analyze.classification to 'skipped', which is the same value
    // detectResult.classification already carries there, so this is benign.
    classification: detectResult.classification,
    vex: vexFilter ? {
      filter_applied: true,
      dropped_cve_count: vexDropped.length,
      dropped_cves: vexDropped,
      // Vendor-fixed CVEs are a KEEP disposition — they stay in matched_cves
      // annotated vex_status:'fixed' and never enter vexDropped. Surface them
      // so the two dispositions are distinguishable and the note can be
      // accurate (the drop note must not list a keep-disposition as a reason).
      fixed_cves: vexFixedIds,
      fixed_cve_count: vexFixedIds.length,
      note: vexDropped.length
        ? `${vexDropped.length} CVE(s) dropped from analyze because the operator-supplied VEX statement marks them not_affected / false_positive. Vendor-fixed CVEs are NOT dropped — they remain in matched_cves with vex_status:'fixed'. The dropped CVEs remain in cve-catalog.json; the disposition lives in the VEX file.`
        : "VEX filter supplied; zero matches dropped (no CVEs in domain.cve_refs matched the VEX not-affected / false_positive set)."
    } : null,
    // Regex-eval failures surfaced here so operators can see WHICH
    // condition expression crashed without the runner dying. Only present
    // when at least one evalCondition() call hit a regex exception during
    // this analyze pass; runOpts._runErrors is the same accumulator
    // populated by run() across all phases, so callers reading this field
    // see every regex problem in the run.
    runtime_errors: (runOpts._runErrors && runOpts._runErrors.length) ? runOpts._runErrors.slice() : (runtimeErrors.length ? runtimeErrors.slice() : []),
    // Collisions when two flat-shape observations targeted the same
    // indicator id. Empty when there were no collisions or no flat-shape
    // observations submitted.
    signal_origins_with_collisions: Array.isArray(agentSignals?._signal_origins_collisions) ? agentSignals._signal_origins_collisions.slice() : (Array.isArray(detectResult?._signal_origins_collisions) ? detectResult._signal_origins_collisions.slice() : [])
  };

  // analyzeFindingShape is a pure transform but defensive-wrap it (same as
  // close()) so a malformed analyze result can't abort escalation handling.
  let findingShape;
  try { findingShape = analyzeFindingShape(result); }
  catch (e) {
    if (Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, { kind: 'analyze_shape', message: (e && e.message) ? String(e.message) : String(e) }, { dedupeKey: x => x.message || '' });
    }
    findingShape = {};
  }
  for (const ec of an.escalation_criteria || []) {
    if (evalCondition(ec.condition, { ...agentSignals, ...evalCtxRoot, rwep: adjustedRwep, blast_radius_score: blastRadiusScore, theater_verdict: theaterVerdict, compliance_theater_check: result.compliance_theater_check, jurisdiction_obligations: (playbook.phases && playbook.phases.govern && playbook.phases.govern.jurisdiction_obligations) || [], analyze: result, matched_cve: result.matched_cves || [],
        // finding.* is two-sourced: the engine computes the CVE/severity-derived
        // keys (severity, rwep_adjusted, matched_cve_*, blast_radius_score,
        // active_exploitation, framework/control_id_first) via analyzeFindingShape,
        // while the DESCRIPTIVE keys the catalog conditions gate on
        // (finding.includes_*, finding.cve_class, finding.tool_surface, …) are
        // host-AI-asserted — the agent knows whether the finding includes a
        // cloud-role-assumption path. Merge agent-supplied finding sub-fields
        // UNDER the engine shape so the descriptive keys survive while engine-owned
        // keys still WIN on collision (a poisoning signals.finding.severity can't
        // override the engine-computed severity). The !Array.isArray guard rejects
        // an array (typeof [] === 'object') that would inject numeric-index noise;
        // null is already excluded by the leading &&.
        finding: { ...(agentSignals.finding && typeof agentSignals.finding === 'object' && !Array.isArray(agentSignals.finding) ? agentSignals.finding : {}), ...findingShape } }, playbook)) {
      escalations.push({ condition: ec.condition, action: ec.action, target_playbook: ec.target_playbook || null });
    }
  }
  // Escalation evaluation may have appended regex-eval diagnostics; refresh
  // the snapshot so analyze.runtime_errors reflects them.
  result.runtime_errors = (runOpts._runErrors && runOpts._runErrors.length) ? runOpts._runErrors.slice() : (runtimeErrors.length ? runtimeErrors.slice() : []);
  return result;
}

/**
 * Extract VEX disposition sets from a CycloneDX/OpenVEX document.
 *
 * OpenVEX `fixed` and `not_affected` must NOT collapse into a single
 * "drop" set — they have different semantics:
 *
 *   - not_affected / false_positive → drop from matched_cves entirely.
 *     The vendor has formally declared the product not vulnerable; the CVE
 *     is not in scope.
 *   - fixed / resolved → KEEP in matched_cves but annotate vex_status:'fixed'.
 *     The product was vulnerable; the vendor shipped a patch. Operators
 *     still need audit trails, SBOM coverage, and confirmation that the
 *     fix landed in their build.
 *
 * Returns a `Set<string>` for the legacy "drop" set (the function's
 * historical contract), with `.fixed` attached as an own property for
 * callers that want the split. The CLI passes both as
 * agentSignals.vex_filter + agentSignals.vex_fixed to analyze().
 */
function vexFilterFromDoc(doc) {
  const out = new Set();
  const fixed = new Set();
  if (!doc || typeof doc !== 'object') {
    out.fixed = fixed;
    return out;
  }

  // CycloneDX shape — analysis.state values per CycloneDX VEX spec:
  //   not_affected / false_positive → drop
  //   resolved                       → fixed-annotation
  for (const v of (doc.vulnerabilities || [])) {
    const state = v.analysis && v.analysis.state;
    if (state === 'not_affected' || state === 'false_positive') {
      if (v.id) out.add(v.id);
    } else if (state === 'resolved') {
      if (v.id) fixed.add(v.id);
    }
  }
  // OpenVEX shape
  for (const s of (doc.statements || [])) {
    const id = s.vulnerability && (s.vulnerability['@id'] || s.vulnerability.name || s.vulnerability);
    if (typeof id !== 'string') continue;
    if (s.status === 'not_affected') out.add(id);
    else if (s.status === 'fixed') fixed.add(id);
  }
  out.fixed = fixed;
  return out;
}

// Cap a summary line at `max` chars on a word boundary, appending an ellipsis
// so a truncated line is visibly marked rather than cut mid-token. A raw
// .slice() left blocked-preflight summaries ending mid-word ("...and conne")
// with no signal that anything was dropped (the full text remains in the JSON
// envelope's reason/remediation fields).
function capSummary(s, max = 240) {
  if (typeof s !== 'string' || s.length <= max) return s;
  const slice = s.slice(0, max - 1);
  const lastSpace = slice.lastIndexOf(' ');
  const base = lastSpace > max - 40 ? slice.slice(0, lastSpace) : slice;
  return base.replace(/[\s—.,;:-]+$/, '') + '…';
}

// --- phase 6: validate ---

function validate(playbookId, directiveId, analyzeResult, agentSignals = {}, runOpts = {}) {
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  // Surface evalCondition regex errors raised here into the same
  // run-wide accumulator that analyze() reads.
  const evalCtx = runOpts._runErrors ? { ...agentSignals, _runErrors: runOpts._runErrors } : agentSignals;
  const v = resolvedPhase(playbook, directiveId, 'validate');

  // Pick the highest-priority remediation_path whose preconditions are all
  // either satisfied by agentSignals or marked unverified=allow.
  const paths = (v.remediation_paths || []).slice().sort((a, b) => a.priority - b.priority);
  // Indicators that actually fired this run — used to prefer a remediation
  // that addresses the finding (via its for_signals linkage) over the bare
  // priority-1 default when no path's preconditions are verified.
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
  // Precedence (paths is priority-sorted, so `find` returns the highest-priority
  // match). Relevance to a fired indicator outranks a satisfied-but-unrelated
  // path: recommending a ready-to-apply remediation that does NOT address the
  // finding (just because its preconditions happen to hold) was the original
  // defect — for_signals must beat it.
  //   1. addresses a fired indicator AND preconditions satisfied (relevant + ready)
  //   2. addresses a fired indicator (relevant; operator must meet its preconditions)
  //   3. preconditions satisfied (no fired-signal-linked path — actionable fallback)
  //   4. priority-1 (nothing else — at least propose the top path)
  const selected =
    paths.find(p => addressesFired(p) && satisfiedIds.has(p.id))
    || paths.find(addressesFired)
    || paths.find(p => satisfiedIds.has(p.id))
    || paths[0]
    || null;

  // selected_remediation selection logic:
  //   1. Iterate remediation_paths sorted by priority ASC (lower number =
  //      higher priority per schema convention).
  //   2. Pick the FIRST path whose every precondition (evaluated against
  //      agentSignals + playbook context) is satisfied.
  //   3. Fallback: when nothing satisfies, surface the highest-priority
  //      path anyway so the agent has SOMETHING to propose to the operator —
  //      better than emitting null and forcing the agent to guess.
  // Above this block: paths.sort + the loop populating `considered` +
  // `selected`. `remediation_options_considered[]` carries the full per-path
  // precondition trace so operators can see why a higher-priority path was
  // skipped.

  // Regression schedule. Returns a structured object with next_run +
  // event_triggers + unparseable. Backwards compatibility: keep
  // regression_next_run as the ISO string (or null) so existing CSAF /
  // attestation consumers don't break; expose the structured form
  // separately.
  const triggers = v.regression_trigger || [];
  const regressionResult = computeRegressionNextRun(triggers);

  // Reason annotation for null next_run — operators see WHY a schedule
  // didn't emit a calendar date (no day intervals declared, every trigger
  // is event-driven, or every trigger was unparseable).
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

/**
 * Extended interval parser. Supports:
 *   <N>d   — N days
 *   <N>wk  — N weeks
 *   <N>mo  — N calendar months (Date.setMonth semantics)
 *   <N>yr  — N calendar years
 *   on_event — event-triggered, no date computed; surfaces in
 *              regression_event_triggers[] for the consumer.
 * Without all five forms, a playbook declaring "regression on every
 * release" or
 * "monthly review" lost its schedule entry.
 */
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
      // Shipped playbooks key the trigger string as `condition`; `trigger` /
      // `event` are accepted for external/fixture submissions. Reading only
      // the latter two left regression_event_triggers[].trigger always null.
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
  const playbook = runOpts._playbookCache || loadPlaybook(playbookId);
  const c = resolvedPhase(playbook, directiveId, 'close');
  const g = resolvedPhase(playbook, directiveId, 'govern');
  // F2/F9: run() generates session_id once and threads it via runOpts.session_id.
  // Pre-fix, close() generated its own session_id independently of run()'s,
  // so CSAF tracking.id, OpenVEX @id, the attestation file name on disk, and
  // the run()-returned session_id were all different hex strings — operators
  // couldn't correlate the attestation file with the bundle URN inside it.
  // crypto.randomBytes() fallback only fires for direct close() calls that
  // bypass run() (e.g. unit tests).
  const sessionId = runOpts.session_id || crypto.randomBytes(8).toString('hex');

  // v0.12.27: when opt-in deterministic bundle mode is set, resolve the
  // single frozen epoch used by every timestamp surface below. Cached for
  // the whole close() call so notification_actions, regression_schedule,
  // and the bundle emitter all agree on the same Date.
  const deterministic = runOpts.bundleDeterministic === true;
  const frozenEpoch = deterministic ? resolveFrozenEpoch(runOpts, playbook) : null;

  // notification_actions — compute ISO deadlines from clock_starts events.
  // v0.11.12 (#123): enrich each entry with the matched obligation's
  // jurisdiction/regulation/window_hours/evidence_required fields. The
  // playbook's notification_actions entry only carries `obligation_ref` +
  // `draft_notification` + `recipient`; without enrichment, operators reading
  // `jurisdiction_notifications[i].jurisdiction` got `undefined`. The
  // upstream `govern.jurisdiction_obligations` has the real data — carry it
  // forward. `notification_deadline` is published as an alias for `deadline`
  // (matches the field name compliance teams expect on a notification record).
  // Which engine phases completed in this run. analyze_complete /
  // validate_complete jurisdictional clocks auto-start (under --ack) only when
  // their named phase actually ran — by the time close() executes, a
  // populated analyzeResult / validateResult proves the phase completed in the
  // same synchronous pass.
  const phaseFlags = {
    analyze_complete: !!(analyzeResult && typeof analyzeResult === 'object'),
    validate_complete: !!(validateResult && typeof validateResult === 'object'),
  };
  const enrichNotification = (na) => {
    const obligation = (g.jurisdiction_obligations || []).find(o =>
      o && typeof o === 'object' &&
      `${o.jurisdiction}/${o.regulation} ${o.window_hours}h` === na.obligation_ref
    );
    // A non-empty obligation_ref that resolves to nothing leaves the
    // jurisdiction / regulation / deadline fields null below — surface it as a
    // runtime_error so the unmatched ref is observable, not a silent null record.
    if (!obligation && na && typeof na.obligation_ref === 'string' && na.obligation_ref &&
        Array.isArray(runOpts && runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, { kind: 'unresolved_obligation_ref', obligation_ref: na.obligation_ref }, { dedupeKey: x => x.obligation_ref || '' });
    }
    // Thread runOpts + the engine-computed classification through so
    // computeClockStart can check operator_consent.explicit before
    // auto-stamping detect_confirmed, and so an engine-confirmed detection
    // starts the clock even without a separately-submitted classification.
    const engineClassification = analyzeResult?._detect_classification || null;
    const clockStart = obligation
      ? computeClockStart(obligation.clock_starts, agentSignals, runOpts, engineClassification, phaseFlags, frozenEpoch)
      : null;
    // A valid clock is a real Date whose getTime() is finite. computeClockStart
    // already returns null on an unparseable operator timestamp, but guard the
    // arithmetic below independently so no caller (or future code path) can
    // ever reach new Date(NaN).toISOString() and crash the close phase.
    const clockValid = clockStart instanceof Date && !Number.isNaN(clockStart.getTime());
    // Surface clock_pending_ack when an auto-startable event was confirmed but
    // the operator did NOT pass --ack, so the notification record is visibly
    // waiting on acknowledgement rather than silently stalled.
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
    // window_hours must be a finite number before it enters the deadline
    // arithmetic — a malformed obligation with an undefined/null/non-number
    // window_hours would otherwise compute `getTime() + NaN` and crash the
    // close phase at `new Date(NaN).toISOString()`. Runtime validation of the
    // playbook is not enforced, so guard here independently of the schema.
    const windowValid = obligation && typeof obligation.window_hours === 'number' && Number.isFinite(obligation.window_hours);
    const deadline = obligation && clockValid && windowValid
      ? new Date(clockStart.getTime() + obligation.window_hours * 3600 * 1000).toISOString()
      : 'pending_clock_start_event';
    // A notification_action whose obligation_ref was specified but resolves to
    // no obligation is an internally-inconsistent playbook (the schema requires
    // obligation_ref to name a real govern obligation). The unmatched ref is
    // already surfaced as a runtime_error above; drop the record rather than
    // emit a null-jurisdiction/regulation entry that pollutes the deadline list.
    if (!obligation && na && typeof na.obligation_ref === 'string' && na.obligation_ref) {
      return null;
    }
    return {
      ...na,
      // Carry obligation metadata forward so each notification entry is
      // operationally usable on its own (calendar deadlines, regulator
      // routing, evidence checklist).
      jurisdiction: obligation?.jurisdiction || null,
      regulation: obligation?.regulation || null,
      obligation_type: obligation?.obligation || null,
      window_hours: obligation?.window_hours ?? null,
      clock_start_event: obligation?.clock_starts || null,
      // Use the validity gate, not optional-chaining: optional-chaining only
      // short-circuits null/undefined, so a (hypothetical) Invalid Date would
      // still reach .toISOString() and throw. clockValid guarantees a finite
      // instant before we serialize.
      clock_started_at: clockValid ? clockStart.toISOString() : null,
      ...(clockPendingAck ? { clock_pending_ack: true } : {}),
      deadline,
      // Alias matching compliance-team vocabulary.
      notification_deadline: deadline,
      // Evidence the regulator expects attached (from the obligation, not
      // just the operator-facing recipient bundle on the notification entry).
      evidence_required: obligation?.evidence_required || na.evidence_attached || [],
      // Track missing interpolation variables so operators see exactly
      // which template vars failed to resolve. Empty array when all
      // placeholders rendered cleanly.
      ...(function () {
        const missing = [];
        // analyzeFindingShape is a pure transform but defensive-wrap it
        // so a malformed analyze result (missing matched_cves, etc.)
        // can't bring down the whole close phase. Failures surface in
        // runtime_errors via runOpts._runErrors when available.
        let findingShape;
        try { findingShape = analyzeFindingShape(analyzeResult); }
        catch (e) {
          if (Array.isArray(runOpts._runErrors)) {
            pushRunError(runOpts._runErrors, { kind: 'analyze_shape', message: (e && e.message) ? String(e.message) : String(e) }, { dedupeKey: e => e.message || '' });
          }
          findingShape = {};
        }
        const draft = interpolate(
          na.draft_notification,
          { ...agentSignals, ...findingShape },
          missing,
        );
        return { draft_notification: draft, missing_interpolation_vars: missing };
      })(),
    };
  };
  // enrichNotification returns null for an unresolved specified obligation_ref
  // (already surfaced as a runtime_error); filter those out so the notification
  // list never carries a null-jurisdiction record.
  const notificationActions = (c.notification_actions || []).map(enrichNotification).filter(Boolean);

  // A govern obligation that declares a notification duty but has no
  // matching close.notification_actions entry would otherwise never surface
  // in the phase-7 record set — its regulatory clock stays invisible to
  // operators reading jurisdiction_notifications. Synthesize a record for
  // each uncovered notify-type obligation so the deadline is computed and
  // visible. The synthesized entry carries no draft template (the playbook
  // declared none) and is marked synthesized_from_obligation so operators
  // can tell it apart from a playbook-authored action.
  const coveredObligationRefs = new Set((c.notification_actions || []).map(na => na.obligation_ref));
  for (const o of (g.jurisdiction_obligations || [])) {
    if (!o || typeof o !== 'object') continue; // skip a null/malformed obligation rather than crash close() during synthesis
    if (!String(o.obligation || '').startsWith('notify')) continue;
    // A notify obligation with a non-number window_hours is malformed: it would
    // synthesize a "…/… undefinedh" ref and could not produce a real deadline.
    // Surface it as a runtime_error and skip synthesis rather than emit a bogus
    // record (the deadline guard in enrichNotification also prevents the crash).
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

  // exception_generation — evaluate trigger.
  let exception = null;
  if (c.exception_generation) {
    const closeEvalCtx = runOpts._runErrors ? { ...agentSignals, _runErrors: runOpts._runErrors } : agentSignals;
    const triggered = evalCondition(c.exception_generation.trigger_condition, closeEvalCtx, playbook);
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
          // v0.12.27: deterministic mode roots acceptance_date in the
          // frozen epoch so two runs against the same evidence emit the
          // same auditor-facing date.
          acceptance_date: (deterministic ? frozenEpoch : new Date().toISOString()).slice(0, 10),
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
  // Build every bundle once and reuse, so bundle_body and
  // bundles_by_format[primary] share object identity (and timestamps).
  // Without memoisation, buildEvidenceBundle gets invoked twice for the
  // primary format and each invocation crystallises a fresh Date.now() —
  // operators diffing bundle_body against bundles_by_format.<primary> see
  // spurious millisecond drift on tracking.initial_release_date /
  // timestamp / current_release_date.
  const evidencePackage = c.evidence_package ? (() => {
    // v0.12.27: deterministic mode pins issuedAt to the frozen epoch so
    // CSAF tracking.{initial_release_date,current_release_date,
    // generator.date,revision_history[0].date} and OpenVEX timestamp +
    // statements[].timestamp all collapse to a single, byte-stable value.
    const issuedAt = deterministic ? frozenEpoch : new Date().toISOString();
    const builtFormats = new Map();
    const buildOnce = (format) => {
      if (!builtFormats.has(format)) {
        builtFormats.set(format, buildEvidenceBundle(format, playbook, analyzeResult, validateResult, agentSignals, sessionId, issuedAt, runOpts));
      }
      return builtFormats.get(format);
    };
    const primaryBody = buildOnce(primaryFormat);
    // bundles_by_format must always be an object keyed by the
    // primary format, even when no extra formats were requested. Pre-fix it
    // was null in the single-format case, forcing downstream tooling into a
    // `bundles_by_format ?? { [primaryFormat]: bundle_body }` shim in every
    // consumer. Now the field is canonically present so iteration is
    // uniform across single- and multi-format emissions.
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
  //
  // v0.12.27: deterministic mode re-derives next_run from the frozen epoch
  // rather than wall-clock-now-at-validate-time. Without this, two runs
  // against the same evidence diverge on next_run by the interval between
  // the two `validate()` invocations. Frozen base + the same interval set
  // = byte-identical schedule.
  const regressionSchedule = c.regression_schedule ? (() => {
    let nextRun = validateResult.regression_next_run;
    if (deterministic) {
      // Re-derive against the validate phase's trigger set (not the
      // close phase's regression_schedule subtree — close has no triggers
      // of its own, just the canonical interval declared upstream).
      const v = resolvedPhase(playbook, directiveId, 'validate');
      nextRun = frozenRegressionNextRun(v.regression_trigger || [], new Date(frozenEpoch));
    }
    return {
      next_run: nextRun,
      trigger: c.regression_schedule.trigger,
      notify_on_skip: c.regression_schedule.notify_on_skip !== false
    };
  })() : null;

  // feeds_into chaining — full analyze result is exposed so conditions can
  // reference `analyze.compliance_theater_check.verdict` etc.
  const feedsCtx = {
    // Operator-submitted signals come FIRST so the engine-computed reserved
    // keys below always win — otherwise a submitted signals.rwep / finding /
    // analyze would override the engine value the feeds_into condition tests
    // and could suppress a legitimate downstream chain.
    ...agentSignals,
    rwep: analyzeResult.rwep?.adjusted,
    // Bare-token parity with the escalation context (analyze()): catalog
    // feeds_into conditions reference the unqualified tokens `blast_radius_score`
    // and `theater_verdict` (e.g. framework.json's feeds_into into sbom). Without
    // these top-level keys resolvePath returns null and `null >= 4` is false
    // regardless of the engine-computed blast radius, so the chain is dead. They
    // are spread AFTER ...agentSignals so the engine value wins over any
    // operator-submitted signals.blast_radius_score / signals.theater_verdict.
    blast_radius_score: analyzeResult.blast_radius_score,
    theater_verdict: analyzeResult.compliance_theater_check?.verdict,
    // Bare top-level `compliance_theater_check` so catalog conditions that
    // reference `compliance_theater_check.verdict` unqualified (framework.json's
    // feeds_into into sbom) resolve — without it resolvePath returns null and the
    // clause is dead regardless of the engine verdict. The `analyze.*` alias
    // below stays for conditions that use the qualified path.
    compliance_theater_check: analyzeResult.compliance_theater_check,
    // Govern-phase jurisdiction obligations so feeds_into conditions like
    // `… AND jurisdiction_obligations contains 'EU'` (framework → sbom) resolve.
    jurisdiction_obligations: (g && g.jurisdiction_obligations) || (playbook.phases && playbook.phases.govern && playbook.phases.govern.jurisdiction_obligations) || [],
    // theater_score follows lib/framework-gap.js's convention: HIGH = more
    // theater detected (worse). A 'theater' verdict (a gap exists) is the
    // concerning case, so it scores 100; a clear verdict scores 0. (Earlier
    // this was inverted, so a feeds_into condition like `theater_score >= 50`
    // would have failed to fire exactly when a gap was found.)
    // 'present' is an allowlisted theater-equivalent verdict (the same
    // gap-present set verdict_text uses at line 1426 and the allowlist comment
    // names at line 1352-1353), so it must score 100 (gap detected = worse), not
    // 0. Scoring only the 'theater' spelling left a 'present' verdict scored as
    // clear — inverted for any future feeds_into condition gating on theater_score.
    theater_score: (analyzeResult.compliance_theater_check?.verdict === 'theater' || analyzeResult.compliance_theater_check?.verdict === 'present') ? 100 : 0,
    // Top-level matched_cve array so the shipped sbom feeds_into quantifiers
    // (`any matched_cve.attack_class == 'kernel-lpe'`, … IN ['ai-c2', …]) re-root
    // at each matched CVE. Without it the quantifier head resolves null and the
    // sbom -> kernel/mcp/ai-api deep-dive chains stay dead even when a matched
    // CVE carries the attack_class. The `analyze.matched_cves` alias stays for
    // conditions that use the qualified path.
    matched_cve: analyzeResult.matched_cves || [],
    analyze: analyzeResult,
    validate: validateResult,
    // finding.* is two-sourced: the engine computes the CVE/severity-derived keys
    // via analyzeFindingShape; the DESCRIPTIVE keys the catalog feeds_into
    // conditions gate on (finding.includes_*, cve_class, tool_surface,
    // mcp_server_location, pipeline_credentials_in_scope, …) are host-AI-asserted.
    // Merge the agent-supplied finding sub-fields UNDER the engine shape so the
    // descriptive keys survive while engine-owned keys WIN on collision. Same
    // shape + guards as the escalation ctx above.
    finding: { ...(agentSignals.finding && typeof agentSignals.finding === 'object' && !Array.isArray(agentSignals.finding) ? agentSignals.finding : {}), ...analyzeFindingShape(analyzeResult) },
    // Surface evalCondition regex failures from the feeds_into chain into
    // the same accumulator. Without this the regex failure happens but
    // analyze.runtime_errors[] never sees it.
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
    // v0.11.10 (#104): operators expected the field name
    // `jurisdiction_notifications`. Surface it as an alias for the full
    // notification_actions list, plus a `jurisdiction_clocks_count` that
    // mirrors `ci.summary.jurisdiction_clocks_started` — the count of
    // notifications whose clock has actually started (clock_started_at != null).
    jurisdiction_notifications: notificationActions,
    jurisdiction_clocks_count: notificationActions.filter(n => n && n.clock_started_at != null).length,
    exception: exception,
    regression_schedule: regressionSchedule,
    feeds_into: feeds,
    // feeds_into surfaces downstream playbook IDs whose preconditions
    // were satisfied by this run. The runner does NOT automatically chain
    // into them — the agent / operator decides whether to invoke them.
    // Surface that contract on the result so consumers don't assume an
    // automated handoff happened.
    feeds_into_auto_chained: false,
  };
}

// Severity ladder for active_exploitation. The worst-of reduction lets
// analyzeFindingShape report the most-exploited CVE in the matched set, not
// the first-encountered one. Higher index = worse.
// `theoretical` (PoC exists, no in-the-wild use) must rank between `none` and
// `unknown`; omitting it made `?? -1` lose to the -1 start, so an all-theoretical
// matched set wrongly reduced to 'unknown' and a theoretical+none set dropped
// the theoretical entry entirely. This vocabulary is first-class in scoring.js.
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
  // Empty / all-unrecognized matched set → 'none' (a draft must not assert
  // 'unknown' exploitation it never observed).
  return worst || 'none';
}

// Severity ladder derived from rwep_adjusted. Playbooks reference
// `finding.severity` in feeds_into and escalation_criteria conditions;
// emit it so those conditions resolve against a real value rather than
// undefined. Thresholds:
//   rwep >= 80 → critical
//   rwep >= 50 → high
//   rwep >= 20 → medium
//   rwep <  20 → low
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
    // Sibling array form for consumers that want to iterate IDs without
    // re-splitting the joined string. The joined form stays for backwards
    // compatibility with notification-draft templates that interpolate
    // `${matched_cve_ids}` verbatim.
    matched_cve_ids_array: matched.map(c => c.cve_id),
    matched_cve_count: matched.length,
    kev_listed_count: matched.filter(c => c.cisa_kev).length,
    // Reduce active_exploitation to the worst rank across all matched
    // CVEs. A .find() lookup would return the first truthy entry — e.g.
    // 'suspected' on CVE #1 when CVE #2 is 'confirmed' — under-stating
    // the threat in notification drafts.
    // Exclude VEX-fixed (vendor-patched) CVEs: a notification draft must not
    // assert active exploitation sourced from an already-remediated CVE.
    active_exploitation: worstActiveExploitation(matched.filter(c => c.vex_status !== 'fixed')),
    rwep_adjusted: rwepAdjusted,
    rwep_base: a.rwep?.base ?? 0,
    // Severity surface for playbook conditions.
    severity: severityForRwep(rwepAdjusted),
    blast_radius_score: a.blast_radius_score ?? 0,
    framework_id_first: a.framework_gap_mapping?.[0]?.framework || null,
    control_id_first: a.framework_gap_mapping?.[0]?.claimed_control || null
  };
}

// Map a vulnerability identifier to its issuing authority + the canonical
// human-readable advisory URL for that authority. CVE ids resolve to NVD;
// GHSA/OSV/RUSTSEC/SNYK each have their own advisory database. A MAL- malicious
// -package id has no public per-id advisory page, so helpUri is null (the id is
// still labelled with its system_name). An unrecognised prefix resolves to a
// null helpUri rather than a fabricated link.
//
// Used by the SARIF rule emitter (helpUri) so non-CVE matched ids no longer
// get a hardcoded nvd.nist.gov/vuln/detail/<id> URL — that URL 404s for every
// MAL-/GHSA-/OSV-/RUSTSEC- id and mislabels it as an NVD CVE. The same
// prefix→authority knowledge lives in the CSAF ids[] branch (csafIdsFor); both
// derive from this table so the two exports cannot drift.
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;
function advisoryAuthorityFor(id) {
  if (typeof id !== 'string' || !id) return { system_name: null, helpUri: null };
  if (CVE_ID_RE.test(id)) return { system_name: 'NVD', helpUri: `https://nvd.nist.gov/vuln/detail/${id}` };
  if (id.startsWith('GHSA-')) return { system_name: 'GHSA', helpUri: `https://github.com/advisories/${id}` };
  if (id.startsWith('OSV-')) return { system_name: 'OSV', helpUri: `https://osv.dev/vulnerability/${id}` };
  if (id.startsWith('RUSTSEC-')) return { system_name: 'RUSTSEC', helpUri: `https://rustsec.org/advisories/${id}.html` };
  if (id.startsWith('SNYK-')) return { system_name: 'Snyk', helpUri: `https://security.snyk.io/vuln/${id}` };
  // Malicious-package ids have no canonical per-id advisory page; label the
  // authority but emit no link rather than a fabricated NVD URL.
  if (id.startsWith('MAL-')) return { system_name: 'Malicious-Package', helpUri: null };
  return { system_name: 'exceptd-unknown', helpUri: null };
}

// Route a vulnerability identifier to its registry-specific URN namespace.
// CVE-/GHSA-/RUSTSEC-/MAL-* identifiers each have a registered URN namespace;
// unrecognised prefixes route to the `urn:exceptd:advisory:` private
// namespace so OpenVEX statements still carry a valid IRI per RFC 8141.
function vulnIdToUrn(id) {
  if (typeof id !== 'string' || id.length === 0) return `urn:exceptd:advisory:${urnSlug(id)}`;
  // Registered identifiers keep their canonical case in the NSS so the @id
  // matches the OpenVEX `name` / CSAF id exactly. The private advisory
  // namespace slugs arbitrary text, so it stays lowercase.
  const canonical = urnSlug(id, true);
  if (/^CVE-/i.test(id)) return `urn:cve:${canonical}`;
  if (/^GHSA-/i.test(id)) return `urn:ghsa:${canonical}`;
  if (/^RUSTSEC-/i.test(id)) return `urn:rustsec:${canonical}`;
  if (/^MAL-/i.test(id)) return `urn:malicious-package:${canonical}`;
  return `urn:exceptd:advisory:${urnSlug(id)}`;
}

// Build a CSAF product_tree.branches[] tree (vendor → product_name →
// product_version). Sources of vendor/product/version, in priority order:
//   (1) catalog entry `affected_products: [{ vendor, product, version }]`
//   (2) heuristic parse of `affected_components[]` strings — accepts
//       `vendor/product@version` and `vendor product version` shapes.
// Unparseable component strings emit a `csaf_branch_unparseable` runtime
// error and are dropped from the tree. Sort alphabetical at each level so
// the output is deterministic across runs.
//
// Returns `{ branches, productIds }`. productIds is a stable enumeration
// CSAFPID-0..N keyed by (vendor, product, version) insertion order so other
// emit paths can reference the leaf products by id later.
function buildCsafBranches(matchedCves, runOpts) {
  // Build a (vendor → product → Set<version>) map.
  const tree = new Map();
  const addLeaf = (vendor, product, version) => {
    if (!vendor || !product || !version) return;
    if (!tree.has(vendor)) tree.set(vendor, new Map());
    const products = tree.get(vendor);
    if (!products.has(product)) products.set(product, new Set());
    products.get(product).add(version);
  };

  // Comparison / range operators that appear between a package name and a
  // version in the catalog's dominant `package OP version` affected_versions
  // shape (e.g. "linux-kernel >= 4.14", "runc <= 1.1.11", "litellm < 1.83.7").
  // These are operators, never package names.
  const RANGE_OP_RE = /^(<=|>=|==|!=|~>|<|>|=|~|\^)$/;

  // Heuristic parser. Returns { vendor, product, version } or null.
  const parseComponentString = (s) => {
    if (typeof s !== 'string' || !s.trim()) return null;
    const trimmed = s.trim();
    // `vendor/product@version`
    let m = trimmed.match(/^([^/\s@]+)\/([^/\s@]+)@(.+)$/);
    if (m) return { vendor: m[1], product: m[2], version: m[3].trim() };
    const parts = trimmed.split(/\s+/);
    // `package OP version` — the catalog's dominant shape. The token before
    // the version is a comparison/range operator, so the PACKAGE is the
    // product name and the operator belongs to the version qualifier, not the
    // product_name. Pre-fix this split named the product after the operator
    // ('>=', '<', '=='), corrupting the CSAF affected-product list. Carry the
    // operator into the version string ('>= 4.14') so the range qualifier
    // survives while the product_name stays the real package. Multiple leading
    // operator tokens (a compound range emitted as one string) collapse into
    // the version qualifier too.
    if (parts.length >= 3 && RANGE_OP_RE.test(parts[1])) {
      const product = parts[0];
      const versionTokens = parts.slice(1);
      // Only accept the shape when the trailing token is an actual version
      // (starts with a digit or v\d) — otherwise it isn't a `package OP version`.
      const lastTok = versionTokens[versionTokens.length - 1];
      if (/^v?\d/.test(lastTok)) {
        return { vendor: product, product, version: versionTokens.join(' ') };
      }
    }
    // `vendor product version` — exactly three whitespace-separated tokens
    // where the last token starts with a digit or `v\d`.
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
          addLeaf(String(ap.vendor), String(ap.product), String(ap.version));
        }
      }
      continue;
    }
    const components = Array.isArray(c.affected_components) ? c.affected_components
      : (Array.isArray(c.affected_versions) ? c.affected_versions : []);
    for (const comp of components) {
      const parsed = parseComponentString(comp);
      if (parsed) {
        addLeaf(parsed.vendor, parsed.product, parsed.version);
      } else if (typeof comp === 'string' && comp.trim() && runOpts && Array.isArray(runOpts._runErrors)) {
        pushRunError(runOpts._runErrors, {
          kind: 'csaf_branch_unparseable',
          component: String(comp),
          cve_id: c.cve_id || null,
        }, { dedupeKey: e => `${e.cve_id || ''}::${e.component}` });
      }
    }
  }

  // Sort + emit.
  const productIds = [];
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
  return { branches, productIds };
}

// Slugify a string into a URN-safe segment (RFC 8141 NSS). Empty input →
// 'unknown' so we never emit zero-length segments. preserveCase keeps the
// canonical case of registered identifiers (e.g. CVE-2026-43284) — the NSS is
// case-sensitive per RFC 8141, and the OpenVEX `name`/CSAF id fields carry the
// canonical case, so the URN @id must match rather than fold to lowercase.
function urnSlug(s, preserveCase = false) {
  if (s == null) return 'unknown';
  let str = String(s);
  if (!preserveCase) str = str.toLowerCase();
  const slug = str
    .replace(preserveCase ? /[^A-Za-z0-9_-]+/g : /[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return slug.length ? slug : 'unknown';
}

// Build the canonical product binding shared by CSAF + OpenVEX. CSAF's
// product_tree must declare every product referenced from
// vulnerabilities[].product_status; OpenVEX statements MUST carry a
// `products` array per spec §4.3.
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

// Best-effort SARIF location list for an indicator hit. Indicator records
// don't carry a direct artifact reference; we fall back to the playbook's
// look-phase artifact source paths (the inspected files/processes). GitHub
// Code Scanning hides results without `artifactLocation.uri`, so we
// surface at least one candidate when any is known. Returns null when no
// candidate exists — caller MUST omit `locations` rather than emit empty.
//
// Source segments are heterogeneous — many playbook artifacts
// describe a shell-command capture (`uname -r`) or human prose, not a real
// file or URI. SARIF `artifactLocation.uri` is defined as a URI reference
// (RFC 3986); shell-command text + prose breaks downstream consumers
// (GitHub Code Scanning rejects with "invalid URI" or renders garbled).
// We accept only path-shaped candidates: absolute POSIX paths, `~`-home
// paths, relative paths, drive-prefixed Windows paths, or file-URI
// strings. Everything else (commands, English) is dropped, and locations
// is omitted entirely when no candidate survives.
// Path-shape predicate: accept anything that begins with a POSIX absolute
// path (`/...`), home (`~/...` or `~`), relative dot (`./...`, `../...`,
// or a bare `.`), drive-prefixed Windows path (`C:\...`, `C:/...`), or a
// `file:` URI. Also accept simple relative names that contain a slash
// (e.g. `etc/os-release`, `subdir/file.json`) — these are common in
// playbook artifact source fields. Reject anything with internal
// whitespace (commands like `uname -r`, prose like `kpatch list || ls
// /sys/kernel/livepatch`) or that looks like a sentence.
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
function sarifLocationsForIndicator(playbook, indicator) {
  // Prefer per-indicator evidence locations the submission supplied (threaded
  // onto the firing indicator by detect()). Each entry is a path string or
  // { uri, startLine?, endLine? }. This is what gives SARIF results a real
  // file location instead of the coarse playbook-source fallback below.
  const ev = indicator && Array.isArray(indicator.evidence_locations) ? indicator.evidence_locations : null;
  if (ev && ev.length) {
    const locs = [];
    for (const e of ev) {
      // SARIF artifactLocation.uri is a URI reference (RFC 3986) — the path
      // separator must be `/`. Operator/agent-supplied evidence on Windows
      // arrives with backslashes; normalize them so the emitted SARIF is
      // valid (the collectors already normalize via buildEvidenceLocations,
      // but submission-threaded locations bypass that path).
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

// Resolve the package version once per process so CSAF tracking.generator
// can name the engine that emitted the advisory. Best-effort read — bundle
// emission must not crash if package.json is missing (e.g. exotic install).
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

// v0.12.27: deterministic-bundle epoch resolution. Priority:
//   1. runOpts.bundleEpoch (operator-supplied --bundle-epoch <ISO>)
//   2. playbook._meta.last_threat_review (the freshness anchor that already
//      gates every shipped playbook — stable across re-runs of the same
//      catalog version)
//   3. '1970-01-01T00:00:00Z' fallback (effectively impossible in practice
//      because every shipped playbook carries last_threat_review, but
//      guarantees the deterministic path never crashes on a malformed
//      playbook).
// Returns a full ISO-8601 timestamp (date-only inputs are normalised).
function resolveFrozenEpoch(runOpts, playbook) {
  const raw = runOpts && runOpts.bundleEpoch
    ? runOpts.bundleEpoch
    : (playbook && playbook._meta && playbook._meta.last_threat_review)
      || '1970-01-01T00:00:00Z';
  try { return new Date(raw).toISOString(); }
  catch { return '1970-01-01T00:00:00Z'; }
}

// Recompute regression_schedule.next_run against a frozen `now` so two
// deterministic-mode runs of the same playbook produce byte-identical
// schedules. Mirrors computeRegressionNextRun but with an injected base
// date. Returns the soonest ISO timestamp or null when no interval-based
// trigger fired.
function frozenRegressionNextRun(triggers, frozenNow) {
  let soonest = null;
  for (const t of (triggers || [])) {
    const parsed = parseInterval(t.interval, frozenNow);
    if (!parsed || !parsed.date) continue;
    if (!soonest || parsed.date < soonest) soonest = parsed.date;
  }
  return soonest ? soonest.toISOString() : null;
}

// Operator-supplied identity strings (--operator) and publisher namespace
// URLs (--publisher-namespace) flow into operator-facing CSAF surfaces.
// Strip ASCII control characters as defence in depth — bin/exceptd.js
// already validates the CLI inputs, but the runner is also called from
// library consumers that may bypass the CLI surface.
//
// Strip Unicode bidi / format / control / surrogate / private-use /
// unassigned categories (\p{C} under the `u` regex flag) so direct
// library callers of buildEvidenceBundle cannot smuggle a U+202E "RTL
// OVERRIDE" or zero-width joiner past the sanitiser the way the CLI
// already refuses. NFC-normalise first so a decomposed sequence can't
// combine past the codepoint check; cap the result at 256 codepoints
// (NOT UTF-16 code units) so a string of astral-plane codepoints can't
// smuggle a longer-than-256-display string past the cap by exploiting
// JavaScript's surrogate-pair string length. Returns null on rejection
// (empty after strip, or NFC normalise threw); callers (the
// publisher-namespace + contact_details + tracking.generator sites)
// treat null as "operator-unclaimed" and route through the existing
// fallback (publisher.namespace = urn:exceptd:operator:unknown +
// bundle_publisher_unclaimed runtime warning).
function sanitizeOperatorText(s) {
  if (typeof s !== 'string') return null;
  // NFC first: a Cf codepoint may be expressed as a base + combining mark
  // that recomposes into the format category under NFC. Normalise so the
  // strip catches it.
  let normalised;
  try { normalised = s.normalize('NFC'); }
  catch { return null; }
  // Two-pass strip. First remove the named threat families (bidi-override /
  // C0-control / zero-width / null) via the shared vendored codepoint tables,
  // so the family vocabulary has a single source of truth. Then strip any
  // remaining General Category C codepoint: \p{C} (Cc/Cf/Cs/Co/Cn) is the
  // backstop — it is strictly broader than the family union (also catches
  // U+007F, U+0080-009F, private-use, unassigned), so the family pass is a
  // documented-intent superset removal and the result is identical to the
  // single \p{C} strip.
  const familyStripped = codepointClass.applyCharStripPolicies(normalised, {
    bidiPolicy: 'strip',
    controlPolicy: 'strip',
    zeroWidthPolicy: 'strip',
    nullBytePolicy: 'strip',
  });
  const stripped = familyStripped.replace(/\p{C}/gu, '');
  const trimmed = stripped.trim();
  if (trimmed.length === 0) return null;
  // Cap at 256 codepoints (Array.from counts codepoints, not UTF-16 code
  // units, so a 256-codepoint astral-plane string isn't silently extended
  // past the cap by surrogate-pair encoding).
  const cps = Array.from(trimmed);
  if (cps.length <= 256) return cps.join('');
  return cps.slice(0, 256).join('');
}

/**
 * Build a single evidence bundle in the requested machine-readable format.
 *
 * Positional contract — the seven phase functions cache the closure over
 * `playbook`, `analyze`, and `validate` so consumers don't reach into the
 * runner's intermediate state. Library callers that bypass close() (e.g.
 * external dashboards re-rendering a stored attestation) MUST honor the
 * same parameter order, names, and types.
 *
 * @param {string}   format        Output dialect. One of: 'csaf-2.0',
 *                                 'sarif' / 'sarif-2.1.0', 'openvex' /
 *                                 'openvex-0.2.0', 'summary', 'markdown'.
 *                                 Unknown values return a stub with
 *                                 supported_formats so callers can branch.
 * @param {object}   playbook      Playbook record loaded via loadPlaybook().
 *                                 Provides _meta.id / version, domain.name,
 *                                 phases.look.artifacts (for SARIF
 *                                 locations), and feeds_into / mutex.
 * @param {object}   analyze      Output of analyze(). Carries matched_cves,
 *                                 _detect_indicators, framework_gap_mapping,
 *                                 rwep, blast_radius_score,
 *                                 _detect_classification.
 * @param {object}   validate     Output of validate(). Carries
 *                                 selected_remediation, remediation_paths,
 *                                 evidence_requirements,
 *                                 residual_risk_statement.
 * @param {object}   agentSignals Agent-submitted signals (signal_overrides
 *                                 merged + cleaned). Drives the OpenVEX
 *                                 vex_status:'fixed' attestation trail and
 *                                 the CSAF cvss_v3 score-block gate.
 * @param {string}   sessionId    Run session id (threaded from run()).
 *                                 Becomes part of CSAF tracking.id,
 *                                 OpenVEX @id, and the on-disk attestation
 *                                 file name so all three correlate.
 * @param {string=}  issuedAt     Optional ISO 8601 timestamp. Pinning this
 *                                 across multi-format emits keeps CSAF /
 *                                 OpenVEX / SARIF agreed on milliseconds;
 *                                 each call would otherwise crystallise a
 *                                 fresh Date.now().
 * @param {object=}  runOpts      Operator / library knobs. Recognised
 *                                 fields: operator, publisherNamespace,
 *                                 csafStatus, tlp, _runErrors accumulator.
 * @returns {object}              The requested format's document body.
 */
function buildEvidenceBundle(format, playbook, analyze, validate, agentSignals, sessionId, issuedAt, runOpts) {
  runOpts = runOpts || {};
  const playbookSlug = urnSlug(playbook._meta.id);
  const { productId, productPurl, productName } = buildProductBinding(playbook, sessionId);
  // Pin one `now` value per bundle build (and accept an
  // upstream-provided issuedAt) so multi-format emit produces identical
  // tracking timestamps across CSAF / OpenVEX / SARIF when close() is
  // building several formats from the same run. Without the parameter,
  // each invocation crystallises a fresh `Date.now()` and bundle_body
  // versus bundles_by_format[primary] diverge on milliseconds.
  const now = typeof issuedAt === 'string' && issuedAt ? issuedAt : new Date().toISOString();

  // CSAF-2.0 shape. v0.11.5 (#82): include vulnerabilities for both matched
  // catalogue CVEs AND fired indicators (treated as advisory pseudo-CVEs
  // under `exceptd:` namespace), so playbooks without catalogue CVEs still
  // emit a non-empty bundle.
  //
  // v0.12.12 (B5): emit a product_tree so csaf_security_advisory documents
  // pass NVD/ENISA/Red Hat dashboard validation. Every vulnerability
  // entry references the product via product_status so the binding is
  // real, not cosmetic.
  if (format === 'csaf-2.0') {
    const indicatorHits = (analyze._detect_indicators || []).filter(i => i.verdict === 'hit');
    const fullProductNames = [{
      product_id: productId,
      name: productName,
      product_identification_helper: { purl: productPurl }
    }];
    // `fixed` product_status MUST reflect operator-supplied VEX
    // disposition (vex_status === 'fixed' — see analyze()), not the
    // catalog's global `live_patch_available` flag. The catalog flag
    // means "vendor publishes a live-patch in the world", not "operator
    // deployed it on this host". Declaring every live-patchable CVE as
    // fixed regardless of operator evidence would produce CSAF documents
    // that lie to downstream NVD / Red Hat dashboards. When
    // live_patch_available is the only signal, status stays
    // known_affected and the live-patch route is surfaced as a
    // `vendor_fix` remediation.
    // CSAF §3.2.1.2 restricts the `cve` field to the CVE-id
    // regex `^CVE-[0-9]{4}-[0-9]{4,}$`. The catalog also keys non-CVE
    // identifiers off `cve_id` (MAL-2026-3083, GHSA-…, OSV-…); strict
    // validators (BSI CSAF validator, ENISA dashboard) refuse documents that
    // place non-CVE values in `cve`. Branch by prefix and route non-CVE ids
    // to the `ids[]` array with a real `system_name`.
    //
    // CSAF §3.2.1.5 requires `cvss_v3.vectorString` when a
    // cvss_v3 score block is emitted. Drop the entire score block when the
    // catalog has no CVSS data (score AND vector both unset); otherwise
    // include version + baseScore + vectorString + baseSeverity from the
    // catalog entry.
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
      // Returns the declared version verbatim. The CALLER is responsible for
      // gating cvss_v3 emission to 3.0 / 3.1 per CSAF 2.0 schema. 2.0 and
      // 4.0 vectors are tagged here for diagnostic clarity but never reach
      // the cvss_v3 block downstream.
      return m[1];
    };
    const csafIdsFor = (id) => {
      // null / undefined / non-string id MUST NOT emit literal "null" /
      // "undefined" text into the vulnerabilities[] entry. String(id)
      // would coerce both to those literals; strict validators then
      // reject the document and operators see a phantom "null" CVE in
      // dashboards. Return null so the caller skips the entry entirely
      // and surfaces a runtime_error for the missing id.
      if (typeof id !== 'string' || !id) return null;
      if (id.startsWith('GHSA-'))    return { system_name: 'GHSA', text: id };
      if (id.startsWith('MAL-'))     return { system_name: 'Malicious-Package', text: id };
      if (id.startsWith('OSV-'))     return { system_name: 'OSV', text: id };
      if (id.startsWith('SNYK-'))    return { system_name: 'Snyk', text: id };
      // RUSTSEC advisories carry their own tracking authority
      // (https://rustsec.org); mis-routing them to system_name 'OSV'
      // loses the upstream provenance link and confuses downstream
      // ingesters that resolve by (system_name, text) pair.
      if (id.startsWith('RUSTSEC-')) return { system_name: 'RUSTSEC', text: id };
      // Genuinely-unknown prefix surfaces as `exceptd-unknown` so
      // downstream ingesters see that the authority wasn't recognised
      // rather than misattributing every unknown id to OSV.
      return { system_name: 'exceptd-unknown', text: id };
    };
    const CSAF_CVE_RE = /^CVE-\d{4}-\d{4,}$/;

    const cveVulns = analyze.matched_cves.map(c => {
      const isFixed = c.vex_status === 'fixed';
      const remediations = [{
        category: 'vendor_fix',
        details: validate.selected_remediation?.description
          || (c.live_patch_available ? 'Vendor publishes a live-patch — see CVE catalog `live_patch_tools` for the operator-side step.' : 'See selected remediation path.'),
        product_ids: [productId],
      }];
      // Catalog entries with a missing / non-string cve_id would
      // otherwise produce literal `text: "null"` / `text: "undefined"`
      // entries under ids[]. Skip the vulnerability entry entirely and
      // surface a runtime_error so the catalog gap is visible to
      // operators / CI gates.
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
      // only emit cvss_v3 score block when we have a real
      // vector string AND a numeric score. Pre-fix every vuln carried
      // `cvss_v3: { base_score: 0 }` even when the catalog had no CVSS
      // signal — strict validators reject the truncated block, and
      // `base_score: 0` was a downstream-misleading default that suggested
      // an authoritative "informational" score where there was simply no
      // data.
      //
      // CSAF 2.0 `cvss_v3` ONLY accepts version 3.0 / 3.1. Catalog
      // vectors prefixed CVSS:2.0/ or CVSS:4.0/ would otherwise emit a
      // cvss_v3 block with version: '2.0' / '4.0', which strict
      // validators (BSI CSAF Validator) reject outright. Drop the block
      // for non-3.x vectors and surface a runtime_error so operators can
      // see why their CVSS data didn't make it through.
      const hasCvss = typeof c.cvss_score === 'number' && typeof c.cvss_vector === 'string' && c.cvss_vector.length > 0;
      // Strict CVSS 3.1 parse (lib/scoring.parseCvss31Vector). The pre-fix
      // permissive regex accepted any CVSS:X.Y/... prefix and would emit a
      // cvss_v3 block keyed off a malformed vector — strict validators
      // (BSI CSAF Validator, ENISA dashboard) then reject the whole
      // document. Strict parse failures surface as a `csaf_cvss_invalid`
      // runtime_error, the cvss_v3 block is omitted, and the rest of the
      // vulnerability entry (product_status, remediations, etc.) survives.
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
        // CSAF Profile 4 (security_advisory) mandatory test 6.1.27.5 requires
        // every /vulnerabilities[] item to carry `notes`. Without this the
        // CVE-keyed entries failed strict validation (the indicator pseudo-CVE
        // entries already carried notes; real-CVE entries did not).
        notes: [{
          category: 'description',
          text: `${c.cve_id}: RWEP ${c.rwep}${c.active_exploitation ? `, active_exploitation=${c.active_exploitation}` : ''}${c.cisa_kev ? ', CISA KEV' : ''}.`,
        }],
        scores,
        threats: c.active_exploitation === 'confirmed' ? [{ category: 'exploit_status', details: `Active exploitation confirmed${c.cisa_kev ? ' (CISA KEV)' : ''}.` }] : [],
        remediations,
        product_status: isFixed ? { fixed: [productId] } : { known_affected: [productId] }
      };
      // route by id shape.
      if (idIsCve) {
        return { cve: c.cve_id, ...base };
      }
      return { ids: [idEntry], ...base };
    }).filter(v => v != null);
    const indicatorVulns = indicatorHits.map(i => ({
      // CSAF `system_name` values land in operator-facing validators; the
      // "exceptd-indicator" pseudo-authority is namespaced enough that NVD /
      // Red Hat / ENISA dashboards render it as a non-CVE finding without
      // misattributing to a real registry (CVE, GHSA, OSV).
      ids: [{ system_name: 'exceptd-indicator', text: `${playbook._meta.id}:${i.id}` }],
      notes: [{ category: 'description', text: `Indicator ${i.id} fired (${i.confidence}${i.deterministic ? ' / deterministic' : ''}) in playbook ${playbook._meta.id}.` }],
      remediations: [{ category: 'mitigation', details: validate.selected_remediation?.description || `Consult playbook brief: exceptd brief ${playbook._meta.id}.`, product_ids: [productId] }],
      product_status: { known_affected: [productId] }
    }));
    // Framework-gap entries land in `document.notes[]` with
    // `category: details` rather than `vulnerabilities[]` with
    // `ids: [{ system_name: 'exceptd-framework-gap' }]`. The `system_name`
    // slot is reserved for recognised vulnerability tracking authorities
    // (CVE, GHSA, etc.); exceptd-framework-gap is not one, and every
    // downstream CSAF consumer (NVD ingester, Red Hat dashboard, ENISA
    // validator) would flag the run for unknown ids and render
    // false-positive advisories at the framework_gap_mapping length.
    // Notes are the right home for advisory context that is not itself
    // a pseudo-CVE.
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
    // CSAF §3.1.7.4 publisher.namespace MUST be the trust
    // anchor of the entity publishing the advisory — the OPERATOR running the
    // scan, not the tool vendor. Pre-fix every CSAF emitted by the runner
    // claimed https://exceptd.com as namespace, falsely attributing
    // responsibility for advisory accuracy to the tooling provider. Resolve
    // in priority order: explicit --publisher-namespace > --operator if it
    // looks URL-shaped > fallback `urn:exceptd:operator:unknown` with a note
    // documenting the gap.
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
    // ALSO surface the unclaimed-publisher condition through
    // the structured runtime_errors[] accumulator so machine-readable
    // consumers (CI gates, dashboards) can branch on it without parsing
    // notes[] prose. The orchestrator's post-close pass folds late-pushed
    // _runErrors into phases.analyze.runtime_errors before the run-level
    // return, so the warning surfaces alongside other run-time anomalies.
    // De-dupe: only push once per bundle-build pass (multi-format emit
    // builds CSAF once via memoization, so this fires at most once per run).
    if (publisherNamespaceSource === 'fallback' && Array.isArray(runOpts._runErrors)) {
      pushRunError(runOpts._runErrors, {
        kind: 'bundle_publisher_unclaimed',
        reason: 'CSAF document.publisher.namespace fell back to urn:exceptd:operator:unknown because no --publisher-namespace and no URL-shaped --operator were supplied. Operator attribution is unclaimed on this advisory.',
        remediation: 'Re-run with --publisher-namespace <https-url> (or a URL-shaped --operator).'
      }, { dedupeKey: () => 'singleton' });
    }

    // thread the validated --operator name into
    // tracking.generator (engine identity) AND publisher.contact_details
    // (operator-of-record). engine.version is read from the package once per
    // process. contact_details is omitted when no operator was supplied so
    // the field doesn't carry a misleading null.
    const publisherBlock = {
      category: 'vendor',
      name: 'exceptd',
      namespace: publisherNamespace,
    };
    if (operatorClean) publisherBlock.contact_details = operatorClean;

    // CSAF §3.1.11.3.5.1 defines `final` as an immutable
    // advisory; subsequent re-emits against the same tracking.id are
    // refused by strict validators (BSI CSAF Validator). Runtime detection
    // runs with no operator review loop are inherently revisable, so the
    // default is `interim`. Operators who have reviewed and are ready to
    // promote pass `--csaf-status final` (threaded via runOpts.csafStatus);
    // any other value falls back to `interim` rather than emitting an
    // unrecognized status word.
    const allowedCsafStatuses = new Set(['draft', 'interim', 'final']);
    const csafStatus = allowedCsafStatuses.has(runOpts.csafStatus)
      ? runOpts.csafStatus
      : 'interim';

    // CSAF §3.1.4 `distribution.tlp`. Optional. When the operator supplies
    // `--tlp <label>` (threaded as runOpts.tlp), emit
    // distribution.tlp.label + distribution.text. CSAF allows omission of
    // the whole distribution block when no level is declared; the
    // pre-fix runner had no surface for this at all.
    const allowedTlp = new Set(['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']);
    // CSAF 2.0 §3.2.1.5.2 pins tlp.label to the TLP 1.0 enum
    // (WHITE/GREEN/AMBER/RED). Map the modern TLP 2.0 labels the CLI accepts
    // onto that enum so the emitted document stays schema-valid for strict
    // CSAF 2.0 consumers, while preserving the operator's exact label in the
    // free-form `text` field. (CLEAR≡WHITE; AMBER+STRICT carries AMBER's
    // disclosure scope plus a stricter handling note.)
    const CSAF_TLP_LABEL = { CLEAR: 'WHITE', GREEN: 'GREEN', AMBER: 'AMBER', 'AMBER+STRICT': 'AMBER', RED: 'RED' };
    const csafDistribution = (runOpts.tlp && allowedTlp.has(runOpts.tlp))
      ? { tlp: { label: CSAF_TLP_LABEL[runOpts.tlp] }, text: `TLP:${runOpts.tlp}` }
      : null;

    // CSAF 2.0: an advisory with zero vulnerabilities is a csaf_informational_advisory
    // (Profile 5, which does not require /vulnerabilities) rather than a
    // csaf_security_advisory (Profile 4, where an empty vulnerabilities array is
    // semantically wrong and warns under strict profile validators). A clean run
    // becomes an informational attestation; any firing CVE/indicator keeps the
    // security-advisory category.
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
        // Profile 3 (csaf_informational_advisory) mandatory test 6.1.27.2
        // requires /document/references with at least one `external` item. A
        // security_advisory carries its references inside the vulnerabilities,
        // so add this only for the informational (clean-run) profile.
        ...(csafCategory === 'csaf_informational_advisory' ? {
          references: [{ category: 'external', summary: `exceptd playbook: ${playbook._meta.id}`, url: `https://exceptd.com/playbooks/${playbook._meta.id}` }],
        } : {}),
        ...(csafDistribution ? { distribution: csafDistribution } : {}),
        tracking: {
          // F2/F9: CSAF tracking.id binds to the run's session_id (threaded
          // from run() via close()) so attestation file names, OpenVEX
          // @id, and CSAF tracking.id all share the same correlation
          // identifier. Pre-fix the timestamp was used, so two runs in
          // the same millisecond collided and one run's documents
          // referenced ids that didn't match anything else on disk.
          id: `exceptd-${playbook._meta.id}-${sessionId}`,
          status: csafStatus,
          version: playbook._meta.version,
          // name the engine that emitted the advisory.
          // CSAF §3.1.11.3.2 places this under tracking.generator.engine.
          generator: {
            engine: { name: 'exceptd', version: getEngineVersion() },
            date: now,
          },
          initial_release_date: now,
          current_release_date: now,
          // CSAF 6.1.30 requires homogeneous versioning (all version_t use the
          // same scheme) and 6.1.16 requires tracking.version === the last
          // revision_history number. tracking.version is the playbook semver,
          // so the single revision entry must carry that same semver (not the
          // integer "1", which mixed schemes AND mismatched the version).
          revision_history: [{ number: playbook._meta.version, date: now, summary: 'Initial finding emission' }]
        }
      },
      // CSAF Profile 3 (informational_advisory) forbids /vulnerabilities
      // (mandatory test 6.1.27.3) and an informational advisory carrying a
      // /product_tree is misleading (§4.3 — a reader must assume every named
      // product is affected). Emit both ONLY for the security_advisory profile;
      // a clean run's informational advisory carries neither.
      ...(csafCategory === 'csaf_security_advisory' ? {
        product_tree: (function () {
          // Synthesize a 3-level branches tree (vendor → product → version)
          // from catalog data. CSAF §3.1.5.1 makes branches[] strongly
          // recommended because NVD / ENISA / Red Hat dashboards render the
          // affected-product list off the branches tree, not full_product_names[].
          const { branches } = buildCsafBranches(analyze.matched_cves || [], runOpts);
          const tree = { full_product_names: fullProductNames };
          if (branches.length > 0) tree.branches = branches;
          return tree;
        })(),
        vulnerabilities: (function () {
          // v0.12.27: deterministic mode sorts vulnerabilities[] by their
          // primary identifier ascending; default mode preserves insertion order.
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

  // SARIF 2.1.0 — GitHub Code Scanning / VS Code SARIF Viewer / Azure DevOps
  // / most static-analysis tooling.
  //
  // v0.12.12 (B6): thread artifact source paths through to
  // result.locations[].physicalLocation.artifactLocation.uri. GitHub Code
  // Scanning hides results without populated locations, so the heuristic
  // ensures clean playbook runs still surface findings in the alerts UI.
  // v0.12.12 (B7): omit null property-bag keys so SARIF viewers don't
  // render empty fields.
  if (format === 'sarif' || format === 'sarif-2.1.0') {
    const stripNulls = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v != null));
    // SARIF rule ids are global within a single sarif-log run.
    // Pre-fix, generic ruleIds like `framework-gap-0` (and shared CVE ids
    // across playbooks) collided when results from multiple playbook runs
    // were merged into one SARIF document — GitHub Code Scanning de-dupes
    // by ruleId, so the second playbook's rule definition silently
    // overwrote the first. Prefix every ruleId with the playbook slug so
    // every rule definition is unambiguously attributable to one playbook,
    // and cross-playbook merges retain all results.
    const rulePrefix = `${playbookSlug}/`;
    // CVE-match results get the coarse playbook-source location fallback
    // (passing a null indicator skips the per-indicator evidence-locations
    // branch). Without any `locations`, GitHub Code Scanning silently DROPS
    // these results — the highest-severity result class would never surface.
    const cveFallbackLocs = sarifLocationsForIndicator(playbook, null);
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
      if (cveFallbackLocs) result.locations = cveFallbackLocs;
      return result;
    });
    const indicatorHits = (analyze._detect_indicators || []).filter(i => i.verdict === 'hit');
    const indicatorResults = indicatorHits.map(i => {
      const locs = sarifLocationsForIndicator(playbook, i);
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
      if (locs) result.locations = locs;
      return result;
    });
    const gapResults = (analyze.framework_gap_mapping || []).map((g, idx) => ({
      ruleId: `${rulePrefix}framework-gap-${idx}`,
      // Framework gaps are control-design observations, not vulnerabilities —
      // SARIF §3.27.9 `kind: informational` routes them appropriately. That
      // same clause requires: when kind !== 'fail', a present `level` SHALL be
      // 'none'. Pairing 'informational' with 'note' is a schema violation that
      // strict validators / GitHub code-scanning reject — use 'none'.
      kind: 'informational',
      level: 'none',
      message: { text: `${g.framework}: ${g.claimed_control} — ${g.actual_gap}${g.required_control ? '. Required: ' + g.required_control : ''}` },
      properties: stripNulls({ kind: 'framework_gap', framework: g.framework, control: g.claimed_control }),
    }));
    const cveRules = analyze.matched_cves.map(c => {
      // Resolve the issuing authority by id shape rather than hardcoding NVD.
      // A non-CVE matched id (MAL-/GHSA-/OSV-/RUSTSEC-/SNYK-) must NOT carry an
      // nvd.nist.gov URL — that link 404s and presents the id as an NVD CVE.
      const authority = advisoryAuthorityFor(c.cve_id);
      const isCve = CVE_ID_RE.test(typeof c.cve_id === 'string' ? c.cve_id : '');
      const rule = {
        id: `${rulePrefix}${c.cve_id}`,
        // For a non-CVE id, qualify the short description with its authority so
        // a SARIF viewer doesn't read e.g. a MAL- id as an NVD CVE.
        shortDescription: { text: isCve ? c.cve_id : `${c.cve_id} (${authority.system_name || 'non-CVE advisory'})` },
        fullDescription: { text: `RWEP ${c.rwep} · KEV=${c.cisa_kev} · active_exploitation=${c.active_exploitation}` },
        defaultConfiguration: { level: c.rwep >= 90 ? 'error' : c.rwep >= 70 ? 'warning' : 'note' },
      };
      // helpUri is optional in SARIF 2.1.0; omit it entirely when the authority
      // has no canonical per-id advisory page rather than emit a broken link.
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
          // Apply the stripNulls contract here too — the `remediation`
          // field is null for any run that didn't surface a
          // selected_remediation, and SARIF viewers render null property
          // values as visible empty rows. Same helper as the result
          // property bags above.
          playbook: playbook._meta.id, classification: analyze._detect_classification || 'unknown',
          rwep_adjusted: analyze.rwep?.adjusted || 0,
          remediation: validate.selected_remediation?.id || null,
        }) }],
      }]
    };
  }

  // OpenVEX 0.2.0 — supply-chain VEX statements.
  //
  // v0.12.12 (B1-B4): correctness sweep against the OpenVEX 0.2.0 spec.
  //  - B1: every statement now carries a `products` array (spec MUST).
  //  - B2: `status` derives from the verdict + confidence rather than being
  //        hard-coded to `under_investigation`. Hits emit `affected` with
  //        an action_statement; misses emit `not_affected` with a
  //        justification; inconclusive findings keep `under_investigation`.
  //  - B3: framework gaps are control-design observations, not
  //        vulnerabilities — they are removed from the VEX emit path. They
  //        remain in CSAF (informational notes) and SARIF (kind:
  //        informational rules).
  //  - B4: vulnerability `@id` values switch to the registered URN namespace
  //        `urn:exceptd:indicator:<playbook>:<indicator-id>` (RFC 8141) so
  //        they pass IRI validation in downstream VEX consumers.
  if (format === 'openvex' || format === 'openvex-0.2.0') {
    // Reuse the bundle-wide `now` so OpenVEX `timestamp` aligns with
    // CSAF `document.tracking.initial_release_date` when both formats are
    // emitted in the same close() pass. A per-format Date.now() would
    // cause the two bundles in bundles_by_format to disagree on
    // milliseconds.
    const issued = now;
    const productEntry = {
      '@id': productPurl,
      subcomponents: [{ '@id': productPurl }],
    };
    const remediationId = validate.selected_remediation?.id || (validate.remediation_paths?.[0]?.id) || null;
    const remediationDescription = validate.selected_remediation?.description || null;
    const actionStatementFor = (fallback) => {
      if (remediationId && remediationDescription) {
        return `Apply remediation from validate phase: ${remediationId}. ${remediationDescription}`;
      }
      if (remediationId) return `Apply remediation from validate phase: ${remediationId}`;
      if (remediationDescription) return `Apply remediation from validate phase: ${remediationDescription}`;
      return fallback;
    };
    // Same `vex_status === 'fixed'` correctness rule as the CSAF
    // emitter. The catalog `live_patch_available` flag is a global
    // "vendor publishes a live-patch" signal, not an operator-host
    // disposition. Treating it as `status: fixed` would make OpenVEX
    // statements claim resolution the operator hadn't attested to. VEX
    // consumers downstream of CISA / SBOM / supply-chain pipelines treat
    // `fixed` as authoritative — emitting it without operator attestation
    // is a downstream-misleading bug. The OpenVEX statement says
    // `affected` (with action_statement pointing to the remediation,
    // which may itself be the vendor live-patch route) unless the
    // operator declared `vex_status: fixed` on the matched CVE.
    const cveStatements = analyze.matched_cves.map(c => {
      const stmt = {
        vulnerability: { '@id': vulnIdToUrn(c.cve_id), name: c.cve_id },
        products: [productEntry],
        timestamp: issued,
        impact_statement: `RWEP ${c.rwep}. ${analyze.blast_radius_score == null ? 'Blast radius not assessed.' : `Blast radius ${analyze.blast_radius_score}/5.`}`,
      };
      if (c.vex_status === 'fixed') {
        stmt.status = 'fixed';
        // OpenVEX 0.2.0 §4.1: `fixed` is an operator-attested resolution,
        // not a global vendor flag. Augment the impact_statement with an
        // evidence trail so downstream supply-chain consumers can chase
        // the attestation back to the operator's submitted evidence.
        // Short-hash is deterministic for the same (cve_id, signals)
        // input — re-emitting the bundle for the same submission yields
        // the same trail.
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
          // Deterministic and high-confidence hits both map to `affected`.
          // The `deterministic` flag describes regex specificity, not
          // operator-evidence confidence — neither warrants
          // under_investigation when the indicator actually fired.
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
    // Cycle 9 C1: OpenVEX `author` identifies the entity attesting to the
    // disposition — for an operator-run scan that is the operator, not the
    // tool vendor. Mirror the CSAF publisher.namespace fallback ladder so a
    // downstream supply-chain consumer keying on `author` resolves to the
    // operator URN. Pre-fix every OpenVEX document falsely attributed
    // dispositions to the tooling provider. Falls back to
    // urn:exceptd:operator:unknown + bundle_publisher_unclaimed runtime
    // warning if neither runOpts.operator nor runOpts.publisherNamespace
    // is supplied.
    const vexOperatorClean = sanitizeOperatorText(runOpts.operator);
    const vexExplicitNs = sanitizeOperatorText(runOpts.publisherNamespace);
    let vexAuthor;
    if (vexExplicitNs) {
      vexAuthor = vexExplicitNs;
    } else if (vexOperatorClean) {
      vexAuthor = vexOperatorClean;
    } else {
      vexAuthor = 'urn:exceptd:operator:unknown';
      // Same shape + singleton dedupe as the CSAF path so a multi-format emit
      // produces one canonical bundle_publisher_unclaimed entry that machine
      // consumers can read consistently (reason/remediation, not message).
      pushRunError(runOpts._runErrors, {
        kind: 'bundle_publisher_unclaimed',
        reason: 'OpenVEX author fell back to urn:exceptd:operator:unknown because no --publisher-namespace and no URL-shaped --operator were supplied. Disposition attribution is unclaimed on this VEX document.',
        remediation: 'Re-run with --publisher-namespace <https-url> (or a URL-shaped --operator).'
      }, { dedupeKey: () => 'singleton' });
    }
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      // F2/F9: OpenVEX @id baked from session_id (not Date.now()) so the
      // document URN aligns with CSAF tracking.id and on-disk
      // attestation file name. Falls back to a urnSlug if sessionId
      // somehow arrived empty.
      '@id': `https://exceptd.com/vex/${playbookSlug}/${urnSlug(sessionId || 'session')}`,
      author: vexAuthor,
      timestamp: issued,
      version: 1,
      statements: (function () {
        // v0.12.27: deterministic mode sorts statements[] by
        // vulnerability['@id'] ascending. Insertion order otherwise.
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

  // Native structured-JSON bundle — a superset of `summary` carrying the full
  // finding record. This is the declared bundle_format for the secrets /
  // cred-stores / runtime / citation-hygiene playbooks; without an explicit
  // branch their default bundle fell through to the Unknown-format placeholder
  // below. Reuses the pinned `now` so multi-format builds stay
  // timestamp-consistent, and exposes the same finding fields the supported
  // csaf / markdown branches already surface — `json` is an intentional,
  // operator-selectable format, not the fallback leak path.
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

  // The fallback must NOT leak raw analyze + validate internals (matched
  // CVEs, framework gaps, residual-risk statements) under an arbitrary
  // "format" name — operators piping output to logging or third-party
  // tooling could leak finding details just by typo'ing the format flag.
  // Return the shape advertisement only.
  return {
    format,
    note: 'Unknown format',
    supported_formats: ['csaf-2.0', 'sarif', 'sarif-2.1.0', 'openvex', 'openvex-0.2.0', 'summary', 'markdown', 'json'],
  };
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

  // signal_overrides must be a plain object. Without this guard, a
  // non-object value (string "foo", array [...]) is spread into
  // out.signal_overrides via `{ ...(submission.signal_overrides || {}) }`
  // — spreading a string splatters it into { '0': 'f', '1': 'o', '2': 'o' },
  // which confuses detect()'s indicator-id lookup. Strip and log instead.
  if (submission.signal_overrides !== undefined && submission.signal_overrides !== null
      && (typeof submission.signal_overrides !== 'object' || Array.isArray(submission.signal_overrides))) {
    // Clone before mutating _runErrors so a frozen / shared input
    // submission isn't modified in place. Pre-fix a caller passing a
    // frozen submission (Object.freeze for safety, or a shared reference
    // across parallel runs) threw uncaught on the _runErrors push.
    const carry = Array.isArray(submission._runErrors) ? submission._runErrors.slice() : [];
    pushRunError(carry, {
      kind: 'signal_overrides_invalid',
      supplied_type: Array.isArray(submission.signal_overrides) ? 'array' : typeof submission.signal_overrides,
      reason: 'signal_overrides must be a plain object mapping indicator-id → verdict.'
    }, { dedupeKey: e => String(e.supplied_type) });
    submission = { ...submission, signal_overrides: {}, _runErrors: carry };
  }

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
    // Carry per-indicator evidence locations through flat normalization so
    // detect() can thread them onto firing indicators for SARIF results[].locations.
    ...(submission.evidence_locations && typeof submission.evidence_locations === 'object'
      ? { evidence_locations: submission.evidence_locations } : {}),
    _original_shape: 'flat (v0.11.0)',
    // normalizeSubmission pushes structured errors (e.g.
    // signal_overrides_invalid) onto submission._runErrors above. For flat
    // submissions the fresh `out` literal built here loses that accumulator
    // unless we forward it; run()'s harvest at the entry to detect/analyze
    // reads agentSubmission._runErrors, so without the carry, flat
    // submissions with invalid signal_overrides drop the errors before
    // they can reach analyze.runtime_errors.
    ...(Array.isArray(submission._runErrors) && submission._runErrors.length
      ? { _runErrors: submission._runErrors.slice() }
      : {}),
  };
  const knownPreconditions = new Set((playbook?._meta?.preconditions || []).map(p => p.id));
  const knownArtifacts = new Set((playbook?.phases?.look?.artifacts || []).map(a => a.id));

  // v0.11.4 (#71): canonicalize indicator outcome strings here too so the
  // signal_overrides object handed to detect() carries the runner's expected
  // hit|miss|inconclusive vocabulary regardless of what the operator typed.
  const canonicalizeOutcome = (v) => {
    if (v === true || v === 'hit' || v === 'detected' || v === 'positive') return 'hit';
    if (v === false || v === 'miss' || v === 'no_hit' || v === 'no-hit' || v === 'clean' || v === 'clear' || v === 'not_hit' || v === 'ok' || v === 'pass' || v === 'negative') return 'miss';
    if (v === 'inconclusive' || v === 'unknown' || v === 'unverified' || v === null) return 'inconclusive';
    return v; // leave unrecognized values for detect() to decide
  };

  // v0.11.5 (#85): track which observation produced each signal_override so
  // detect can emit `from_observation` on each indicator result. Diagnostic
  // value for operators chasing "which observation drove this verdict".
  //
  // When two observations target the same indicator id, last-write-wins
  // silently. Track discards in _signal_origins_collisions so analyze can
  // surface analyze.signal_origins_with_collisions for batch evidence runs.
  out._signal_origins = out._signal_origins || {};
  out._signal_origins_collisions = out._signal_origins_collisions || [];
  for (const [key, val] of Object.entries(submission.observations || {})) {
    if (knownPreconditions.has(key)) {
      out.precondition_checks[key] = val === "ok" || val === true || val === "true";
      continue;
    }
    if (typeof val === "object" && val !== null) {
      const aid = knownArtifacts.has(key) ? key : (val.artifact || key);
      // Preserve every evidence-bearing key the observation carried, not just
      // `value`. An observation whose secret/path lives under a non-`value`
      // key (e.g. { path, matched, reason } — a natural collector shape) was
      // previously collapsed to { value: undefined, captured } here, silently
      // discarding the actual evidence. Two observations capturing DIFFERENT
      // secrets under path/matched then hashed and diffed byte-identical, so
      // `attest diff` reported a false "unchanged" and masked real drift.
      // The reserved control keys (artifact/indicator/result) drive
      // signal_overrides below and are intentionally not echoed as evidence.
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
          // Collision: a prior observation already set this indicator.
          // Record the prior (which is now discarded) into the collision
          // log, then overwrite with the new one (last-write-wins).
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

  // Carry over precondition_checks if the operator supplied them at the top
  // level even in the flat shape.
  //
  // v0.12.35 (cycle 15 security F2): the prior `Object.assign(out.precondition_checks,
  // submission.precondition_checks)` form re-invoked the `__proto__` setter when
  // the operator submitted JSON containing a `__proto__` key. JSON.parse keeps
  // `__proto__` as an own data property (CreateDataProperty), but Object.assign
  // reads it via `[[Get]]` and writes via `[[Set]]`, which DOES trigger the
  // prototype-rebinding setter. The polluted prototype is confined to
  // `out.precondition_checks` (not global Object.prototype), but any future code
  // path that calls `.hasOwnProperty()` directly on the bag would observe the
  // pollution. Switch to own-key iteration so the prototype stays unmodified.
  if (submission.precondition_checks) {
    for (const k of Object.keys(submission.precondition_checks)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      out.precondition_checks[k] = submission.precondition_checks[k];
    }
  }

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
  // Catalog corruption blocks runs cleanly. Probed lazily here (before the
  // analyze path) rather than at module load, so cheap verbs don't pay the
  // catalog-parse cost.
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
    // loadPlaybook failure → structured error (not crash).
    return {
      ok: false,
      blocked_by: 'playbook_not_found',
      error: (e && e.message) ? String(e.message) : String(e),
      reason: `Failed to load playbook '${playbookId}'. Check that data/playbooks/${playbookId}.json exists.`
    };
  }

  // Validate directiveId before any phase runs. An unknown id would
  // otherwise throw inside analyze() / findDirective() uncaught, surfacing
  // as a 500-style stack trace; instead return a clean structured error
  // with the valid directive list.
  const validDirectives = (playbook.directives || []).map(d => d.id);
  if (!validDirectives.includes(directiveId)) {
    return {
      ok: false,
      blocked_by: 'directive_not_found',
      reason: `Directive '${directiveId}' not found in playbook '${playbookId}'.`,
      valid_directives: validDirectives,
    };
  }

  // v0.11.0: accept flat submission shape (observations + verdict). Normalize
  // to the engine's internal nested shape before preflight/detect. Smart
  // precondition auto-detect (redesign #9) fires here when the cwd is readable
  // / the host platform matches — the runner can answer those itself rather
  // than blocking on AI declaration.
  agentSubmission = normalizeSubmission(agentSubmission, playbook);
  // Capture pre-autoDetect submission preconditions so we report
  // user-declared provenance, not engine-auto-resolved values.
  const originalSubmissionPCs = { ...(agentSubmission.precondition_checks || {}) };
  agentSubmission = autoDetectPreconditions(agentSubmission, playbook);

  // precondition_checks merge order is submission → runOpts (runOpts
  // wins on collision). This is intentional: runOpts represents the most
  // recent caller intent (CLI flags / programmatic injection from a host
  // process), whereas submission was captured earlier during evidence
  // collection. The order is documented here AND surfaced as
  // preflight.precondition_check_source on the result so callers can see
  // whether the value came from the submission, runOpts, or both
  // (merged with runOpts winning). Provenance reports the ORIGINAL submission
  // contents — autoDetectPreconditions adds engine-derived values that
  // wouldn't be meaningful as "submission" provenance.
  const fullSubmissionPCs = agentSubmission.precondition_checks || {};
  const runOptsPCs = runOpts.precondition_checks || {};
  const mergedPCs = { ...fullSubmissionPCs, ...runOptsPCs };
  const pcSource = {};
  for (const k of Object.keys(mergedPCs)) {
    const inOrigSub = Object.prototype.hasOwnProperty.call(originalSubmissionPCs, k);
    const inRun = Object.prototype.hasOwnProperty.call(runOptsPCs, k);
    // A key present in neither the original submission nor runOpts was filled
    // in by autoDetectPreconditions (engine-derived host/platform facts) —
    // report it as 'auto', not 'submission'. Otherwise: submission ∩ runOpts =
    // a genuine programmatic override of a submitted value ('merged');
    // runOpts-only = 'runOpts'; submission-only = 'submission'.
    if (!inOrigSub && !inRun) pcSource[k] = 'auto';
    else pcSource[k] = (inOrigSub && inRun) ? 'merged' : (inRun ? 'runOpts' : 'submission');
  }
  const pre = preflight(playbook, { ...runOpts, precondition_checks: mergedPCs });
  if (!pre.ok) {
    // Blocked results MUST carry playbook_id + directive_id at the
    // result root, the same as successful results. Without this,
    // consumers iterating results[] can't identify which playbook
    // produced a preflight failure without joining against
    // playbooks_run[] by array index. `verdict:"blocked"` +
    // `summary_line` keep the flat result-envelope shape consistent
    // across both branches.
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

  // Cross-process mutex lock for this run. Use the diagnostic variant so a
  // CONFIRMED live foreign holder BLOCKS the run. The bare acquireLock returned
  // null on a lost race (the TOCTOU window between preflight's check and the
  // acquire) and the run then proceeded UNLOCKED, defeating the mutex. Block
  // only on `held_by_live_pid` — same-PID reentrancy and FS quirks still
  // proceed best-effort (lockPath null), so no legitimate nested/edge case
  // regresses. Released in the finally block.
  const lockResult = acquireLockDiagnostic(playbookId);
  // Block ONLY on a confirmed live foreign holder with a real numeric pid.
  // acquireLockDiagnostic also returns reason:'held_by_live_pid' with
  // holder_pid:null for a MALFORMED/truncated lockfile (it can't parse a pid to
  // probe). Blocking on that would let one corrupted lockfile left by a crash
  // deny every future run forever. A null-pid (malformed) lock instead falls
  // through to proceed best-effort (lockPath null) — matching how the preflight
  // mutex check treats unparsable lockfiles as stale.
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
  // Parse the playbook once at run() entry and thread the parsed object
  // through each phase via runOpts._playbookCache. Each phase otherwise
  // calls loadPlaybook() independently; for a single run that's seven
  // reads + parses of the same file. Caching saves the redundant I/O +
  // JSON parses.
  //
  // session_id is generated ONCE here and threaded into close() via
  // cachedRunOpts.session_id so CSAF tracking.id / OpenVEX @id / product
  // PURLs / on-disk attestation filenames all share one identifier.
  // Without the single-source-of-truth, close() would mint its own id
  // and operators correlating attestation files to embedded bundle URNs
  // would see mismatches.
  //
  // v0.12.27: when runOpts.bundleDeterministic is set AND the operator did
  // not pass --session-id, derive the session_id from the submission shape
  // so two runs against identical evidence produce the same id (and
  // therefore the same CSAF tracking.id / OpenVEX @id / attestation file
  // name). Mirrors the evidence_hash path further down but is computed
  // here so close() can thread it through. Operator-supplied --session-id
  // still wins on collision.
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
      // canonicalStringify deliberately throws (EVIDENCE_TOO_DEEP) on
      // pathological nesting. The mutex lockfile and the _activeRuns entry
      // are already held here, but the protecting try/finally below has
      // not opened yet — release both before rethrowing, or the leaked
      // lockfile blocks every subsequent run of this playbook for as long
      // as this PID lives.
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
  // Run-time error accumulator for evalCondition regex failures and other
  // non-fatal anomalies surfaced into analyze.runtime_errors[].
  const runErrors = [];
  cachedRunOpts._runErrors = runErrors;
  // normalizeSubmission may push structured errors (e.g.
  // signal_overrides_invalid) onto submission._runErrors. Splice them
  // into the run-level accumulator so analyze.runtime_errors[] surfaces
  // them, and strip the field off the submission so it doesn't pollute
  // the evidence_hash digest (the hash canonicalizes the submission and
  // a non-deterministic _runErrors would change it).
  if (Array.isArray(agentSubmission._runErrors) && agentSubmission._runErrors.length) {
    runErrors.push(...agentSubmission._runErrors);
  }
  if (agentSubmission && Object.prototype.hasOwnProperty.call(agentSubmission, '_runErrors')) {
    delete agentSubmission._runErrors;
  }
  // Phases the runner should SKIP execution for, based on skip_phase
  // preconditions surfaced in preflight.issues.
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
      // analyze() must still run, but with an empty submission so it doesn't
      // resolve indicator hits against a non-existent detect result.
      phases.analyze  = analyze(playbookId, directiveId, phases.detect, {}, cachedRunOpts);
      // Annotate analyze with the skip vocabulary so consumers can branch.
      phases.analyze.classification = 'skipped';
    } else {
      phases.detect   = detect(playbookId, directiveId, agentSubmission, cachedRunOpts);
      phases.analyze  = analyze(playbookId, directiveId, phases.detect, agentSubmission.signals || {}, cachedRunOpts);
    }
    phases.validate = validate(playbookId, directiveId, phases.analyze, agentSubmission.signals || {}, cachedRunOpts);
    phases.close    = close(playbookId, directiveId, phases.analyze, phases.validate, agentSubmission.signals || {}, cachedRunOpts);

    // analyze() already sliced runOpts._runErrors into
    // phases.analyze.runtime_errors at return time. Validate + close may
    // have pushed additional regex errors AFTER analyze returned; surface
    // those onto phases.analyze.runtime_errors so the field reflects every
    // regex failure in the run. De-dupe by JSON shape so the analyze-time
    // snapshot doesn't double-count.
    if (runErrors.length && phases.analyze) {
      // `_truncated` sentinels are pushed by pushRunError when a per-kind
      // or total cap fires. They aggregate via in-place `dropped` increments,
      // so the same sentinel object is BOTH in the analyze snapshot AND in
      // the late-push `runErrors` ref. Skip them on the dedupe-merge pass
      // to keep the snapshot's authoritative dropped-count, rather than
      // double-stamping a second sentinel with the same `dropped` value.
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

    // evidence_hash binds the operator's submission to the verdict. The
    // hash must include the canonicalized submission (observations,
    // signal_overrides, signals) — keying it on only { playbook, directive,
    // cves, rwep, classification } would let two operators with completely
    // different evidence collide on the same hash whenever their
    // classifications match. Use SHA-256 over the recursively sorted
    // submission. `captured_at` and other timestamp-like fields are
    // INTENTIONALLY excluded so that re-running with the same submission
    // produces the same hash — `reattest` relies on this to detect drift
    // (different submission → different hash → drift exists).
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

    // Hoist the operator-facing summary to the result root so a `ci`
    // consumer does not have to walk into phases.detect.classification
    // + phases.analyze.rwep.adjusted separately to answer the most
    // common ops question ("did this playbook detect anything?").
    //
    // Verdict source: phases.detect.classification is the canonical
    // signal — one of detected / not_detected / inconclusive / pending
    // / skipped. validate() does NOT carry a `verdict` field, so
    // sourcing the hoist from phases.validate.verdict would degrade
    // every non-blocked result to the fallback "inconclusive".
    const verdict = (phases.detect && phases.detect.classification) || 'inconclusive';
    const rwepScore = phases.analyze && phases.analyze.rwep && typeof phases.analyze.rwep.adjusted === 'number'
      ? phases.analyze.rwep.adjusted : null;
    // Top finding = first matched CVE-id when present; otherwise the dominant
    // FIRED indicator's id (the signal that actually drove the verdict), not
    // the verdict string itself. Echoing the classification made top_finding
    // carry no information beyond `verdict` and duplicated it in summary_line
    // (e.g. "detected (rwep=10, detected, ...)"). The full set lives in phases.
    let topFinding = null;
    if (phases.analyze && Array.isArray(phases.analyze.matched_cves) && phases.analyze.matched_cves.length) {
      topFinding = phases.analyze.matched_cves[0].cve_id;
    } else if (phases.detect && Array.isArray(phases.detect.indicators)
        && phases.detect.classification
        && phases.detect.classification !== 'not-detected'
        && phases.detect.classification !== 'not_detected'
        && phases.detect.classification !== 'inconclusive'
        && phases.detect.classification !== 'pending') {
      // Only on a real detection verdict: surface the FIRED indicator that
      // best explains the result. Gating on the verdict keeps a stray hit on
      // an inconclusive/not-detected run from advertising a finding. Prefer the
      // indicator that actually drove the RWEP score — the greatest
      // weight_applied among fired, weight-bearing rwep_inputs — so the
      // headline names the finding that produced the number shown beside it.
      // Fall back to the dominant fired indicator (deterministic/high
      // confidence), then the first hit, when no weighted signal fired.
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
    // Evidence completeness: indicators-evaluated vs indicators-known
    // distinguishes "ran fully and found nothing" from "couldn't
    // actually evaluate". Without this, the two states look identical
    // at the result-root level — a not_detected verdict with zero
    // indicators-evaluated reads the same as one with every indicator
    // evaluated and miss.
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
      // Flat top-level fields (B2 + B6 + B9). Operators no longer need
      // to spelunk through phases.* to get the answer to the most
      // common question. The phases tree is still present below for
      // anyone who needs the full CSAF / analyze / detect dumps.
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
      // Non-fatal collector notices (e.g. a file skipped for exceeding the
      // scan size limit) surfaced from the submission so a `collect | run`
      // consumer can see what the collector could not scan. Advisory only:
      // never affects verdict, rwep, or evidence_completeness.
      ...(Array.isArray(agentSubmission.collector_errors) && agentSubmission.collector_errors.length
        ? { collector_warnings: agentSubmission.collector_errors }
        : {}),
      // Source provenance for precondition_checks. Shape:
      //   { '<pc-id>': 'submission' | 'runOpts' | 'merged', ... }
      precondition_check_source: pcSource,
      phases
    };
  } finally {
    _activeRuns.delete(playbookId);
    releaseLock(lockPath);
  }
}

// --- helpers ---

/**
 * Deterministic JSON stringification with recursively sorted keys.
 * Without sorted keys two semantically identical submissions ({a:1, b:2}
 * vs {b:2, a:1}) would hash to different digests, breaking reattest's
 * "same submission → same hash" contract. Arrays preserve order
 * (submission order is meaningful for evidence). null + primitives pass
 * through directly. Avoids JSON.stringify's replacer indirection because
 * a top-level array would otherwise miss the canonicalization recursion.
 */
const CANONICAL_MAX_DEPTH = 200;
function canonicalStringify(v, _depth = 0) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  // Bounded recursion: adversarial (or accidental) deeply-nested evidence
  // would otherwise overflow the stack with an opaque "internal error". This
  // runs on every run() (evidence_hash + session_id derivation), so the guard
  // turns a crash into an actionable rejection. 200 levels is far beyond any
  // legitimate submission.
  if (_depth > CANONICAL_MAX_DEPTH) {
    const e = new Error(`evidence nesting exceeds the maximum depth of ${CANONICAL_MAX_DEPTH} — flatten the submission`);
    e.code = 'EVIDENCE_TOO_DEEP';
    throw e;
  }
  if (Array.isArray(v)) return '[' + v.map(x => canonicalStringify(x, _depth + 1)).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(v[k], _depth + 1)).join(',') + '}';
}

/**
 * Pick the operator-meaningful fields out of the normalized submission
 * for hashing. captured_at, _signal_origins, _signal_origins_collisions,
 * and _original_shape are intentionally excluded — they're either
 * timestamps (would break "same submission → same hash") or runner-internal
 * provenance metadata that isn't part of what the operator submitted.
 */
function extractSubmissionForHash(sub) {
  if (!sub || typeof sub !== 'object') return {};
  const pick = {};
  // Strip captured_at from artifact entries so timestamp drift doesn't
  // perturb the digest. The semantic content (value + captured-ness +
  // optional indicator binding) is what matters for "did the operator
  // submit the same evidence?".
  if (sub.artifacts && typeof sub.artifacts === 'object') {
    pick.artifacts = {};
    for (const [k, v] of Object.entries(sub.artifacts)) {
      if (v && typeof v === 'object') {
        const { captured_at, _captured_at, ...rest } = v;
        pick.artifacts[k] = rest;
      } else {
        pick.artifacts[k] = v;
      }
    }
  }
  if (sub.signal_overrides && typeof sub.signal_overrides === 'object') {
    pick.signal_overrides = sub.signal_overrides;
  }
  if (sub.signals && typeof sub.signals === 'object') {
    // vex_filter and vex_fixed may be Sets — convert to sorted arrays so
    // canonicalStringify can serialize them.
    const signals = {};
    for (const [k, v] of Object.entries(sub.signals)) {
      if (v instanceof Set) signals[k] = Array.from(v).sort();
      else signals[k] = v;
    }
    pick.signals = signals;
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

// Identity fields a `contains`/`includes` membership test targets when the
// array holds objects (e.g. jurisdiction_obligations records). Membership is
// field-scoped to these so a non-identity field (clock_starts, obligation,
// regulation, a free-form tag) that happens to equal the member cannot satisfy
// the predicate. `jurisdiction` is the only field the catalog's object-array
// `contains` conditions target today; the allowlist is the seam to extend if a
// future condition deliberately matches a different identity field.
const OBJECT_MEMBERSHIP_FIELDS = ['jurisdiction'];

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

  // Quantifier prefix: catalog conditions write `any <path> <op> <value>`
  // (e.g. framework.json's feeds_into `any compliance_theater_check.verdict ==
  // 'theater' …`). An unhandled `any `/`all ` prefix is unparseable and falls
  // through to `false`, silently disabling the clause it gates. Strip the
  // quantifier and re-evaluate the inner comparison: when the LHS path resolves
  // to a scalar (the framework theater_verdict case) the quantifier is prose
  // emphasis and the scalar comparison is the intended test; when the LHS first
  // segment resolves to an array, apply the predicate existentially (`any`) /
  // universally (`all`) across its elements. The inner clause is only the leaf
  // comparison (the surrounding AND/OR has already been split off above).
  const quant = expr.match(/^(any|all)\s+(.+)$/);
  if (quant) {
    const [, kind, inner] = quant;
    // `any head.rest <op|keyword> …` → re-root the predicate at each element of
    // `head` and apply it existentially (`any`) / universally (`all`). The head
    // is the FIRST dotted-path token of the inner clause; what follows it (`==`,
    // `IN [...]`, `contains`, `matches /…/`, `>=`, …) is operator-agnostic — the
    // inner clause is re-evaluated whole against `{ …ctx, [head]: el }`, so every
    // operator the leaf parser already understands works under a quantifier.
    // Earlier this branch only re-rooted clauses whose operator was in the
    // comparison set (`>=|<=|==|=|<|>|!=`); `IN`/`contains`/`matches` were
    // omitted, so e.g. sbom.json's `any matched_cve.attack_class IN
    // ['ai-c2','prompt-injection']` (the sbom→ai-api feeds_into trigger) fell
    // through to a whole-ctx eval where `matched_cve.attack_class` resolved to
    // undefined on the array and the clause was permanently false, while the
    // sibling `== 'kernel-lpe'` quantifiers fired. Requiring a `.`-qualified head
    // keeps the bare-token form (`any <path>`) routed to the non-emptiness branch
    // below.
    const headMatch = inner.match(/^([A-Za-z_][\w-]*)(?:\.[A-Za-z_][\w-]*)+(?:[\s.[]|$)/);
    if (headMatch) {
      const head = headMatch[1];
      const arr = resolvePath(ctx, head);
      if (Array.isArray(arr)) {
        const test = el => evalCondition(inner, { ...ctx, [head]: el }, playbook);
        return kind === 'all' ? arr.length > 0 && arr.every(test) : arr.some(test);
      }
    }
    // Bare-quantifier non-emptiness form: `any <path>` / `all <path>` with no
    // comparison operator is a quantifier OVER the resolved collection itself —
    // the author's intent is "at least one X exists" (`any`) / "every X is
    // truthy" (`all`), i.e. a non-emptiness / existence test. sbom.json's
    // `any actively_exploited_match …` EU CRA Art.14 (24h) notify_legal
    // escalation is the canonical case. Without this, the inner bare token has
    // no operator, so no comparison branch parses it and it falls through to
    // condition_unparsed → false, silently disabling the escalation even when
    // the array holds entries. Match ONLY a pure dotted-path token (no operator,
    // keyword, bracket, or space); anything with a comparison/keyword still
    // routes to the prose fall-through below so a genuinely malformed inner
    // clause stays observable.
    if (/^[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*$/.test(inner)) {
      const v = resolvePath(ctx, inner);
      if (Array.isArray(v)) {
        return kind === 'all' ? v.length > 0 && v.every(Boolean) : v.length > 0;
      }
      // Non-array scalar: existence/truthiness (null/undefined/0/'' → false).
      return !!v;
    }
    // Scalar (or unresolved-array) LHS: the quantifier is prose; evaluate the
    // bare inner comparison. If it still doesn't parse it falls through to the
    // condition_unparsed diagnostic below, so a genuinely malformed clause stays
    // observable rather than silently passing.
    return evalCondition(inner, ctx, playbook);
  }

  // Membership clauses (`contains`/`includes`/`IN [...]`) parse fine but resolve
  // their LHS path to a collection. When that path does NOT exist in ctx (the
  // resolved value is null/undefined — an authoring typo in the LHS token, or a
  // wrong-shape ctx that never populated the collection), the branch returns a
  // silent `false` that disables whatever escalation / feeds_into the clause
  // gates with no signal. The clause PARSED, so condition_unparsed (a
  // parse-failure diagnostic) never fires. Surface a distinct, low-severity
  // condition_path_unresolved so an LHS-path typo is observable — deduped on the
  // condition string like condition_unparsed. A present-but-empty array (or any
  // present value that simply isn't a collection) is a LEGITIMATE false, not an
  // unresolved path, so it does NOT push: only a literally-absent path does.
  const pushPathUnresolved = () => {
    const target = (ctx && Array.isArray(ctx._runErrors)) ? ctx._runErrors
      : (playbook && Array.isArray(playbook._runErrors)) ? playbook._runErrors
      : null;
    if (target) {
      pushRunError(target, { kind: 'condition_path_unresolved', condition: String(expr).slice(0, 200) },
        { dedupeKey: x => x.condition || '' });
    }
  };

  // "rwep >= 90". The LHS/RHS path tokens admit hyphens because signal and
  // indicator IDs are canonically hyphenated across the catalog (e.g.
  // `no-security-md`, `kver-in-affected-range`); a `\w`-only token silently
  // failed to match every hyphenated condition and fell through to `false`.
  let m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s*(>=|<=|==|=|<|>|!=)\s*(['"]?)([^'"]+)\3$/);
  if (m) {
    const [, lhs, op, quote, rhsRaw] = m;
    const lv = resolvePath(ctx, lhs);
    // A DOTTED (multi-segment) LHS that resolves absent is a suspicious dead
    // condition (authoring typo / wrong-shape ctx) — the same silent-false class
    // the contains/includes/IN branches already surface. Surface it as
    // condition_path_unresolved (observability only; the boolean result is
    // unchanged). Use `== null` (not strict undefined): resolvePath returns
    // `null` for a missing INTERMEDIATE parent and `undefined` for a missing
    // LEAF, so a strict-undefined gate would miss `analyze.classification` when
    // `analyze` itself is absent. Bare single-segment flags
    // (agent_has_filesystem_read, operator-submitted signals) are legitimately
    // absent and do NOT push. A present-but-null flag is a legitimate false:
    // single-segment, so the dot guard already excludes it. pushPathUnresolved
    // dedupes on the condition string and is per-kind capped, so it can't spam.
    if (lhs.includes('.') && lv == null) pushPathUnresolved();
    let rv = rhsRaw;
    if (quote) {
      // Explicit quoted string literal — keep as-is.
    } else if (rv === 'true') rv = true;
    else if (rv === 'false') rv = false;
    else if (!isNaN(parseFloat(rv)) && /^-?\d+(\.\d+)?$/.test(rv.trim())) rv = parseFloat(rv);
    else if (/^[a-z_][\w.-]*$/i.test(rv.trim())) {
      // Unquoted identifier — treat as a context path. Falls through to the
      // raw string if resolution returns undefined (matches the prior behavior
      // for literals like `theater` that aren't quoted).
      const resolved = resolvePath(ctx, rv.trim());
      if (resolved !== undefined && resolved !== null) rv = resolved;
    }
    // Severity is an ordinal word ladder (low < medium < high < critical), not
    // a lexically-ordered string. When both sides are severity words, compare
    // by rank so `severity >= 'high'` includes 'critical' (raw string `>=`
    // would exclude it: 'critical' < 'high' lexicographically).
    const SEV = { low: 0, medium: 1, high: 2, critical: 3 };
    const lr = SEV[String(lv).toLowerCase()], rr = SEV[String(rv).toLowerCase()];
    let a = (lr !== undefined && rr !== undefined) ? lr : lv;
    let b = (lr !== undefined && rr !== undefined) ? rr : rv;
    const isOrdering = op === '>=' || op === '<=' || op === '>' || op === '<';
    if (isOrdering && (lr === undefined || rr === undefined)) {
      // Duration literals carry a unit suffix (`24h`, `7d`, `30min`) — the
      // catalog writes ordering comparisons against them (kernel.json's
      // `reboot_window > 24h` raise_severity escalation). The RHS-coercion
      // above only converts a BARE numeric (`/^-?\d+(\.\d+)?$/`), so a unit-
      // suffixed literal stays a string. A numeric LHS then compares against a
      // string RHS (`48 > '24h'` → `48 > NaN` → false: a 48h window silently
      // fails to escalate) and a string LHS compares lexicographically
      // (`'6h' > '24h'` → `'6' > '2'` → true: a 6h window WRONGLY escalates).
      // Normalize both sides to canonical hours when a duration unit appears on
      // either side: a unit-suffixed literal converts by its unit family; a
      // bare number is taken in the same family as the duration it is compared
      // against (hours-equivalent magnitude). The comparison is then numeric.
      const la = parseDurationHours(a), ba = parseDurationHours(b);
      if ((la !== null || ba !== null) && la !== null && ba !== null) {
        a = la; b = ba;
      } else if (
        // Two non-numeric, non-severity, non-duration strings under an ordering
        // operator is a silently-degraded comparison (lexicographic / NaN) — the
        // clause PARSED so condition_unparsed never fires. Surface a distinct
        // condition_type_mismatch so the degraded comparison is observable
        // (the boolean result is unchanged; this is diagnostics only).
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

  // "scope.targets includes named_remote" — `contains` is accepted as a
  // synonym for `includes` (the catalog uses both); hyphenated paths + members
  // are admitted for the same reason as the comparison branch above.
  // The member may be a bare token OR a quoted string (the catalog's
  // `jurisdiction_obligations contains 'EU'` / `contains 'EU/EU CRA Art.14 24h'`
  // forms). When the array holds objects (jurisdiction_obligations are records
  // like `{ jurisdiction:'EU', regulation:'NIS2 Art.21', … }`), membership is
  // field-TARGETED: it matches an identity field of the obligation, not ANY
  // field value. An unscoped `Object.values(el).includes(member)` over-matched
  // — `contains 'EU'` would be satisfied by a non-jurisdiction field that
  // happened to equal 'EU' (e.g. a tag), and `contains 'detect_confirmed'`
  // would match the unrelated `clock_starts` field that holds that exact value
  // in the shipped obligations. Scoping to OBJECT_MEMBERSHIP_FIELDS keeps the
  // intended "the obligation is for jurisdiction X" semantic and prevents a
  // future field collision (or an operator-/agent-supplied obligations array)
  // from forcing a notify_legal escalation via a non-jurisdiction field.
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

  // "matched_cve.attack_class IN ['kernel-lpe', 'rce']" — membership against a
  // bracketed literal list; members may be quoted or bare. A scalar LHS must be
  // in the list; an array LHS must intersect it. Unhandled before, so every
  // `IN [...]` escalation/feeds_into atom fell through to a silent false.
  // The member list is split quote-aware: a naive `split(',')` is unaware of
  // quotes, so a quoted member that itself contains a comma (`'EU, US'`) would
  // be broken into two members (`EU` and `US`), neither of which equals the
  // author's intended whole member — the clause then evaluated false with no
  // diagnostic (the regex still matched the bracket, so condition_unparsed never
  // fired). splitInMembers walks the list tracking single/double quote state and
  // only splits on commas at quote-depth 0, then strips the surrounding quotes.
  // The CLOSING `]` is located quote-aware too: a `[^\]]*` capture stops at the
  // FIRST `]`, so a quoted member containing a literal `]` (`'a]b'`) truncated
  // the list early and left trailing text the `$` anchor couldn't match — the
  // whole clause then fell through to condition_unparsed for every input. The
  // matching bracket is now found at quote-depth 0 (an unquoted `]` is still the
  // terminator; a `]` inside a quoted member is part of that member). Trailing
  // text after the closing bracket, or an unterminated bracket, still fails to
  // match and surfaces as condition_unparsed.
  m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s+IN\s+\[/);
  if (m) {
    const body = sliceInBracketBody(expr.slice(m[0].length));
    if (body !== null) {
      const members = splitInMembers(body);
      const lv = resolvePath(ctx, m[1]);
      if (Array.isArray(lv)) return lv.some((x) => members.includes(String(x)));
      // lv == null means the LHS path doesn't exist in ctx (typo / wrong-shape) —
      // surface it as condition_path_unresolved so the dead clause is observable,
      // mirroring the contains/includes branch. A present scalar that's simply not
      // in the member list is a legitimate false and pushes nothing.
      if (lv == null) { pushPathUnresolved(); return false; }
      return members.includes(String(lv));
    }
    // body === null → no quote-depth-0 closing `]` ends the string; fall through
    // to the condition_unparsed diagnostic so the malformed clause stays visible.
  }

  // "matched_cve.vector matches /regex/" — both delimiters are accepted: the
  // slash form `matches /re/` and the quote form `matches 're'` / `matches "re"`.
  // The catalog authors both (mcp.json's feeds_into uses the quoted form), and a
  // delimiter-specific parser silently disabled whichever form it didn't match —
  // the same class as the hyphenated-token gap above.
  m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)\s+matches\s+(?:\/(.+)\/|'([^']+)'|"([^"]+)")$/);
  if (m) {
    const pattern = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
    const val = resolvePath(ctx, m[1]);
    if (typeof val !== 'string') return false;
    // An operator-supplied or playbook-supplied regex with a syntax bug
    // (or pathological backtracking) must NOT crash the engine mid-analyze.
    // Catch construction + test exceptions, return false, and push a
    // structured _regex_eval_error into ctx._runErrors (when present) so
    // analyze() can surface analyze.runtime_errors[] without losing the
    // diagnostic.
    try {
      return new RegExp(pattern, 'i').test(val); // allow:dynamic-regex — pattern comes from an Ed25519-signed catalog playbook condition (/…/ or '…'), so it cannot be attacker-controlled without breaking the signature; the try/catch covers construction-time syntax errors only (it does NOT defend against catastrophic backtracking — do not reuse this shape for operator-supplied patterns)
    } catch (e) {
      const errorRec = { _regex_eval_error: { source: m[1], expr: pattern, message: e && e.message ? String(e.message) : String(e) } };
      // Two sites where ctx may carry an accumulator: runOpts._runErrors
      // (threaded from run()) or ctx._runErrors directly. Prefer the runOpts
      // form; fall back to ctx.
      // Tag with a `kind` so pushRunError can apply per-kind cap + dedupe
      // (same source+expr regex error firing N times per playbook would
      // otherwise spam runtime_errors). The original `_regex_eval_error`
      // payload is preserved for backward compatibility.
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

  // A condition the mini-language can't parse is a DEAD condition — it returns
  // false for every input, silently disabling whatever escalation / feeds_into
  // chain / precondition it gates. Surface it as a runtime_error so a dead
  // condition is observable instead of an invisible `false` (this is how an
  // authoring typo or an unimplemented operator gets caught at runtime).
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

/**
 * Normalize a duration operand to canonical hours for a numeric comparison.
 * Accepts a unit-suffixed literal (`24h`, `7d`, `2wk`, `30min`) and converts by
 * its unit family, OR a bare number / numeric string (returned as its own
 * magnitude — the catalog writes `reboot_window > 24h` where the LHS resolves to
 * a bare hour count). Returns null for anything that is not a recognized
 * duration or plain number, so the caller can detect that BOTH sides normalized
 * before comparing numerically (and surface a type-mismatch otherwise).
 */
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
  // Bare numeric string (no unit) — take its magnitude as-is.
  if (/^-?\d+(?:\.\d+)?$/.test(s)) return parseFloat(s);
  const m = s.match(/^(\d+(?:\.\d+)?)\s*(h|hr|hrs|d|day|days|wk|w|m|min)$/i);
  if (!m) return null;
  const mult = DURATION_UNIT_HOURS[m[2].toLowerCase()];
  return mult === undefined ? null : parseFloat(m[1]) * mult;
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
  let depth = 0, buf = '', i = 0, quote = null;
  while (i < expr.length) {
    const ch = expr[i];
    // Inside a quoted string literal, parens and the ` AND `/` OR ` needle are
    // LITERAL text, not boolean structure. A regex member like `matches 'foo('`
    // carries an unbalanced `(` that — counted blindly — would leave depth=1 so
    // a real top-level OR/AND would never split at depth 0 (silently disabling
    // the disjunct/conjunct), and a member like `contains 'EU AND US'` would be
    // torn at the inner ` AND ` as if it were an operator. Track quote state and
    // skip both while inside a quote. An unescaped matching quote closes the
    // literal; `\'`/`\"` stay in. Mirrors splitInMembers' quote-aware walk.
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

/**
 * Quote-aware splitter for the body of an `IN [...]` member list. Splits on
 * commas that are OUTSIDE any quoted run, then strips the surrounding quotes and
 * trims each member. A naive `.split(',')` is quote-unaware, so a quoted member
 * that contains a comma (`'EU, US'`) would be torn into two members; this walks
 * the string tracking single/double quote state so a comma inside a quoted run
 * is treated as a literal part of that member. Bare (unquoted) members are
 * supported too — the catalog authors both forms (`'ai-c2', 'prompt-injection'`
 * and bare `kernel-lpe`). Empty members (e.g. a trailing comma) are dropped.
 */
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

/**
 * Locate the closing `]` of an `IN [...]` list quote-aware and return the body
 * between the (already-consumed) `[` and that `]`. `rest` is the text after the
 * opening bracket. The terminator is the first `]` encountered at quote-depth 0;
 * a `]` inside a single/double-quoted member (`'a]b'`) is part of the member, not
 * the terminator. A `[^\]]*` regex capture instead stops at the FIRST `]`, so a
 * quoted `]` truncated the list and left trailing text the `$` anchor rejected —
 * the clause then fell through to condition_unparsed for every input.
 *
 * Returns the body string on success, or `null` when the list is malformed:
 * unterminated (no quote-depth-0 `]`) or carrying non-whitespace text after the
 * closing bracket. `null` lets the caller fall through to the condition_unparsed
 * diagnostic so a malformed clause stays observable rather than passing silently.
 */
function sliceInBracketBody(rest) {
  let quote = null;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === ']') {
      // The bracket must be the final structural token: only whitespace may
      // follow. Anything else (e.g. `IN ['a'] AND …` reaching here, or stray
      // trailing text) is malformed for this leaf parser.
      return rest.slice(i + 1).trim() === '' ? rest.slice(0, i) : null;
    }
  }
  return null; // no quote-depth-0 closing bracket → unterminated list
}

/**
 * Strip a balanced pair of outer parens, if and only if the very first and last
 * characters are matching parens at the same depth boundary. `(A) AND (B)` keeps
 * its parens; `((A AND B))` peels one layer. The depth scan is quote-aware: a
 * paren inside a quoted string literal (e.g. a regex member `matches '(a|b)'` or
 * an unbalanced `matches 'foo('`) is literal text, not grouping structure, so it
 * must not move the depth counter — otherwise a quoted `)` could make the outer
 * pair look unbalanced (skipping a legitimate strip) or an unbalanced quoted `(`
 * could make a non-wrapping pair look outer-spanning (stripping wrongly).
 */
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

// Parse an operator-supplied clock_started_at_<event> timestamp into a valid
// Date, host-timezone-independently. Two failure modes a raw `new Date(s)`
// silently produces are guarded here:
//
//   1. Unparseable value ('not-a-date', '2026-13-99'). new Date() returns an
//      Invalid Date — a truthy object whose getTime() is NaN. Calling
//      .toISOString() on it later throws RangeError, which crashes the
//      deadline math in close() and propagates uncaught out of run(),
//      destroying the entire phase-7 notification/CSAF/deadline output. We
//      return { date: null } so the caller routes to the pending-clock branch
//      instead of crashing.
//
//   2. Zone-less ISO ('2026-06-12T10:00:00' or '2026-06-12 10:00:00'). new
//      Date() interprets a designator-less datetime in the HOST timezone, so
//      the published statutory deadline shifts by the host's UTC offset — a
//      4h DORA window computed on a UTC-7 host lands 7h late. We normalize the
//      space separator to 'T' and append 'Z' so a zone-less value is read as
//      UTC deterministically on every host, and flag assumed_utc so the caller
//      can surface that the zone was assumed.
//
// Returns { date, assumed_utc } where date is a valid Date or null, and
// assumed_utc is true only when a zone-less value was coerced to UTC.
function parseOperatorClock(raw) {
  if (typeof raw !== 'string') {
    const d = new Date(raw);
    return { date: Number.isNaN(d.getTime()) ? null : d, assumed_utc: false };
  }
  const trimmed = raw.trim();
  if (!trimmed) return { date: null, assumed_utc: false };
  // A full ISO datetime whose only missing piece is the zone designator:
  // YYYY-MM-DD, a 'T' or single space separator, HH:MM(:SS(.ms)?)?, and NO
  // trailing 'Z' / [+-]HH:MM offset. Date-only values (YYYY-MM-DD) are already
  // parsed as UTC midnight by spec, so they are left untouched.
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

/**
 * Compute the start instant for a jurisdictional clock event. The agent
 * submits clock_started_at_<event> ISO strings as it progresses through
 * incident-response milestones.
 *
 * Per AGENTS.md Phase 7, the legal contract is that the clock starts
 * from OPERATOR AWARENESS — not from the moment the engine emits a
 * `detected` classification. Auto-stamping Date.now() on detect_confirmed
 * whenever the engine classifies as detected would be incorrect: the
 * operator may not have seen the result yet. Semantics:
 *
 *   - If the agent explicitly submits clock_started_at_<event>: use it,
 *     after validating it parses and normalizing a zone-less value to UTC.
 *     An unparseable value returns null (clock stays pending) and surfaces
 *     a runtime error naming the offending key, instead of crashing close().
 *   - Otherwise, for 'detect_confirmed' with classification='detected', and
 *     for 'analyze_complete' / 'validate_complete' once their phase has run:
 *     stamp `now` ONLY if runOpts.operator_consent?.explicit === true
 *     (i.e. the operator passed --ack). The analyze/validate phases provably
 *     complete inside the same synchronous run before close() computes these
 *     clocks, so under --ack there is no operator-awareness gap. Without
 *     --ack, return null and the caller (close()) surfaces clock_pending_ack:
 *     true on the notification_actions entry so the operator sees that the
 *     clock is waiting on acknowledgement.
 *   - 'manual' and any other event without an explicit timestamp: return null.
 *
 * `phaseFlags` carries which engine phases completed in this run
 * ({ analyze_complete, validate_complete }) so the auto-stamp for those two
 * events only fires when the named phase actually ran.
 */
function computeClockStart(eventName, agentSignals, runOpts = {}, engineClassification = null, phaseFlags = {}, frozenEpoch = null) {
  // The agent submits clock_started_at_<event> ISO strings as it progresses.
  const key = `clock_started_at_${eventName}`;
  if (agentSignals && agentSignals[key]) {
    const { date, assumed_utc } = parseOperatorClock(agentSignals[key]);
    if (!date) {
      // A present-but-unparseable timestamp must not crash the close phase via
      // a downstream new Date(NaN).toISOString(). Null routes to the pending
      // branch; the runtime error tells the operator which field was bad.
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
  // Auto-stamp gate. Detection is "confirmed" when EITHER the agent submitted
  // detection_classification:'detected' OR the engine itself classified the
  // detect phase as 'detected'. Pre-fix only the agent-submitted signal was
  // honored, so an engine-confirmed detection (indicators fired from
  // signal_overrides without a separate classification submission) never
  // started the regulatory clock — notification deadlines silently stalled.
  const detected = agentSignals?.detection_classification === 'detected'
    || engineClassification === 'detected';
  const ack = !!(runOpts && runOpts.operator_consent && runOpts.operator_consent.explicit === true);
  if (!ack) return null;
  // detect_confirmed auto-starts on a confirmed detection. analyze_complete /
  // validate_complete auto-start once their engine phase has run in this same
  // pass — the event literally names a phase that completed synchronously
  // before close(), so --ack closes the awareness gap exactly as it does for
  // detect_confirmed.
  // Deterministic bundle mode roots every auto-started clock in the single
  // frozen epoch so two runs over the same evidence emit identical
  // clock_started_at and deadline values; otherwise the clock starts at
  // wall-clock now. Operator-supplied clock timestamps (handled above) are
  // never overridden — they are the explicit input.
  const autoNow = () => (frozenEpoch ? new Date(frozenEpoch) : new Date());
  if (eventName === 'detect_confirmed' && detected) return autoNow();
  if (eventName === 'analyze_complete' && phaseFlags && phaseFlags.analyze_complete === true) return autoNow();
  if (eventName === 'validate_complete' && phaseFlags && phaseFlags.validate_complete === true) return autoNow();
  return null;
}

function expressionKey(expr) {
  // For agentSignals precondition lookups — strip operators/values to leave key.
  // Admits hyphens so a hyphenated precondition id (the catalog norm) resolves
  // to the full key instead of being truncated at the first hyphen.
  const m = expr.match(/^([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*)/);
  return m ? m[1] : expr;
}

/**
 * Substitute ${var} placeholders against ctx. F14: pre-fix, missing keys
 * silently re-emitted the literal `${var}` placeholder, so notification
 * drafts could ship to regulators with `${cisa_kev_due_date}` rendered as
 * the raw template — a visible failure that operators wouldn't catch
 * before sending. Now: render as `<MISSING:${var}>` so the failure mode
 * is loud, AND if a tracker array is passed as the third argument,
 * collect the missing keys for caller surfacing as
 * missing_interpolation_vars[].
 */
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
  // Exported so library-side direct callers (the fallback path the CLI
  // guard cannot reach) can be exercised without spawning a CLI
  // subprocess.
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
  // Re-exported from scoring so parity between the catalog scorer and the
  // runtime evaluator is checkable (and enforced by a test) at the seam.
  _activeExploitationLadder: scoring.ACTIVE_EXPLOITATION_LADDER,
};
