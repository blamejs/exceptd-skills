'use strict';

/**
 * Scheduled task coordinator for skill currency maintenance.
 *
 * Schedules: weekly currency check, monthly CVE validation reminder, annual
 * full audit reminder. Emits events via event-bus.js when currency thresholds
 * are breached.
 *
 * This is a simple interval-based scheduler. For production use, swap for a
 * proper cron daemon or cloud scheduler without changing the task definitions.
 *
 * Bootstrap-fire policy. Long-cadence tasks (monthly, annual) are also
 * evaluated on `start()` so a freshly-restarted watcher does not silently
 * skip a due interval. Whether a task fires on bootstrap is gated by a
 * persisted "last fired" timestamp store at
 * `~/.exceptd/scheduler-last-fired.json` — the task fires only when the
 * elapsed time since the persisted timestamp exceeds the interval. The
 * weekly currency check always fires on bootstrap (legacy behavior).
 *
 * Implementation note — INT32 overflow guard. `setInterval` / `setTimeout`
 * delay values are coerced to a signed 32-bit integer; any value above
 * 2^31 - 1 ms (~24.8 days) is silently clamped to 1 ms by Node, which
 * causes the handler to fire ~1000×/sec. The MONTHLY_CVE_VALIDATION and
 * ANNUAL_AUDIT intervals both exceed that limit. `scheduleEvery` wraps the
 * underlying timer with a short tick interval (capped at SAFE_MAX_MS) and
 * compares wall-clock elapsed time against the requested interval, so any
 * delay — including multi-year intervals — fires exactly when due.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const { bus, EVENT_TYPES } = require('./event-bus');
const { currencyCheck } = require('./pipeline');

const SAFE_MAX_MS = 2_147_483_647;            // INT32 max — Node's setTimeout/setInterval ceiling.
const TICK_MS = Math.min(SAFE_MAX_MS, 24 * 60 * 60 * 1000);  // 24h tick by default.

const INTERVALS = {
  WEEKLY_CURRENCY: 7 * 24 * 60 * 60 * 1000,
  MONTHLY_CVE_VALIDATION: 30 * 24 * 60 * 60 * 1000,
  ANNUAL_AUDIT: 365 * 24 * 60 * 60 * 1000
};

const CURRENCY_THRESHOLDS = {
  critical: 50,
  warning: 70
};

const LAST_FIRED_KEYS = {
  WEEKLY_CURRENCY: 'weekly_currency_check',
  MONTHLY_CVE_VALIDATION: 'monthly_cve_validation',
  ANNUAL_AUDIT: 'annual_full_audit'
};

let unschedulers = [];
let running = false;

// --- persistent last-fired store ---

/**
 * Resolve the path of the last-fired persistence file. Defaults to
 * `~/.exceptd/scheduler-last-fired.json`. Honors EXCEPTD_HOME for the test
 * suite so unit tests stay isolated from the maintainer's real home dir.
 */
function _lastFiredStorePath() {
  const root = process.env.EXCEPTD_HOME || path.join(os.homedir(), '.exceptd');
  return path.join(root, 'scheduler-last-fired.json');
}

function _loadLastFired() {
  const p = _lastFiredStorePath();
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return {};
  }
}

function _saveLastFired(store) {
  const p = _lastFiredStorePath();
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(store, null, 2));
  } catch (err) {
    // Persistence is best-effort. A failed write only means the next start
    // can't tell whether the task fired; it does not break the running
    // scheduler.
    console.error('[scheduler] could not persist last-fired:', err.message);
  }
}

function _markFired(key, when) {
  const store = _loadLastFired();
  store[key] = when || new Date().toISOString();
  _saveLastFired(store);
}

function _shouldBootstrapFire(key, intervalMs) {
  const store = _loadLastFired();
  const stamp = store[key];
  if (!stamp) return true;
  const last = Date.parse(stamp);
  if (!Number.isFinite(last)) return true;
  return (Date.now() - last) >= intervalMs;
}

// --- scheduling primitive ---

/**
 * Schedule `handler` to fire every `intervalMs`, safely for intervals that
 * exceed Node's INT32 setTimeout ceiling. Returns an unschedule function.
 *
 * @param {number} intervalMs   Desired interval in milliseconds (any positive value).
 * @param {Function} handler    Function to invoke on each interval.
 * @returns {Function}          Call to stop further firings.
 */
function scheduleEvery(intervalMs, handler) {
  // T P1-4: lower-bound guard. v0.12.12 added the INT32 overflow clamp
  // (upper bound) but never asserted intervalMs > 0. `scheduleEvery(0, fn)`
  // would set a 0ms interval that fires ~10k times per second; negatives
  // (-100) coerce the same way and NaN drives setInterval into a 1ms tick.
  // All three exhaust the event loop. Refuse the call rather than silently
  // floor — the scheduler is a long-lived primitive and a footgun here
  // poisons every periodic task in the watcher.
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new RangeError(`scheduleEvery: intervalMs must be a positive finite number, got ${intervalMs}`);
  }
  const startedAt = Date.now();
  let lastFired = startedAt;
  const tick = () => {
    const now = Date.now();
    if (now - lastFired >= intervalMs) {
      lastFired = now;
      try { handler(); } catch (e) { console.error('[scheduler]', e); }
    }
  };
  const id = setInterval(tick, Math.min(intervalMs, TICK_MS));
  // Deliberately NOT calling id.unref(): the `watch` orchestrator verb
  // is long-running and relies on the scheduler timers to keep the event
  // loop alive (the event bus has no I/O of its own). Callers that don't
  // want the timer to hold the loop open should call the returned
  // unschedule function in their teardown path.
  return () => clearInterval(id);
}

// --- public API ---

/**
 * Start the scheduler. Runs the weekly task immediately, then schedules all
 * three on their intervals. Monthly and annual tasks are also "bootstrap
 * fired" on start when the persisted last-fired timestamp is older than the
 * interval (or absent), so a restarted watcher does not silently skip a due
 * window. Bootstrap-fire happens inside the same try/catch the periodic
 * wrapper uses so a single thrown task cannot crash the watcher.
 */
function start() {
  if (running) return;
  running = true;

  const safeRun = (label, fn) => {
    try { fn(); }
    catch (e) { console.error('[scheduler] ' + label + ' failed:', e); }
  };

  // Weekly always fires on bootstrap (legacy behavior).
  safeRun('weekly currency bootstrap', () => {
    runWeeklyCurrencyCheck();
    _markFired(LAST_FIRED_KEYS.WEEKLY_CURRENCY);
  });

  // Monthly + annual bootstrap-fire only when the persisted timestamp is
  // older than the interval. This closes the "freshly-restarted watcher
  // never fires the long-cadence task" gap.
  if (_shouldBootstrapFire(LAST_FIRED_KEYS.MONTHLY_CVE_VALIDATION, INTERVALS.MONTHLY_CVE_VALIDATION)) {
    safeRun('monthly CVE bootstrap', () => {
      runMonthlyCveValidation();
      _markFired(LAST_FIRED_KEYS.MONTHLY_CVE_VALIDATION);
    });
  }
  if (_shouldBootstrapFire(LAST_FIRED_KEYS.ANNUAL_AUDIT, INTERVALS.ANNUAL_AUDIT)) {
    safeRun('annual audit bootstrap', () => {
      runAnnualAudit();
      _markFired(LAST_FIRED_KEYS.ANNUAL_AUDIT);
    });
  }

  unschedulers.push(scheduleEvery(INTERVALS.WEEKLY_CURRENCY, () => {
    runWeeklyCurrencyCheck();
    _markFired(LAST_FIRED_KEYS.WEEKLY_CURRENCY);
  }));
  unschedulers.push(scheduleEvery(INTERVALS.MONTHLY_CVE_VALIDATION, () => {
    runMonthlyCveValidation();
    _markFired(LAST_FIRED_KEYS.MONTHLY_CVE_VALIDATION);
  }));
  unschedulers.push(scheduleEvery(INTERVALS.ANNUAL_AUDIT, () => {
    runAnnualAudit();
    _markFired(LAST_FIRED_KEYS.ANNUAL_AUDIT);
  }));

  console.log('[scheduler] Started. Weekly currency check, monthly CVE validation, annual audit scheduled.');
}

/**
 * Stop the scheduler and clear all timers.
 */
function stop() {
  for (const off of unschedulers) {
    try { off(); } catch { /* ignore */ }
  }
  unschedulers = [];
  running = false;
  console.log('[scheduler] Stopped.');
}

/**
 * Run just the currency check immediately (for CLI use).
 * @returns {object} Currency report
 */
function runCurrencyNow() {
  return runWeeklyCurrencyCheck();
}

// --- task implementations ---

function runWeeklyCurrencyCheck() {
  const timestamp = new Date().toISOString();
  console.log(`[scheduler] Running weekly currency check — ${timestamp}`);

  const { currency_report, action_required, critical_count } = currencyCheck();

  // Emit ONE aggregated SKILL_CURRENCY_LOW_AGGREGATE event per run instead
  // of N per-skill events. Per-run aggregate prevents downstream consumers
  // (`watch`, dashboards, alerting webhooks) from receiving an event storm
  // when N skills are simultaneously stale — common after a long pause
  // between runs or on first bootstrap. The aggregate payload carries
  // critical_count + the full array of stale skills so consumers can still
  // drill in. The legacy per-skill SKILL_CURRENCY_LOW signature is preserved
  // for callers (and tests) that consume bus.skillCurrencyLow() directly.
  const critical = currency_report.filter(s => s.currency_score < CURRENCY_THRESHOLDS.critical);
  if (critical.length > 0) {
    bus.emit(EVENT_TYPES.SKILL_CURRENCY_LOW_AGGREGATE, {
      critical_count: critical.length,
      skills: critical.map(s => ({
        skill_name: s.skill,
        currency_score: s.currency_score,
        days_since_review: s.days_since_review
      })),
      timestamp
    });
  }

  const result = {
    task: 'weekly_currency_check',
    timestamp,
    skills_checked: currency_report.length,
    action_required,
    critical_count,
    critical_skills: critical.map(s => s.skill),
    warning_skills: currency_report.filter(s =>
      s.currency_score >= CURRENCY_THRESHOLDS.critical && s.currency_score < CURRENCY_THRESHOLDS.warning
    ).map(s => s.skill)
  };

  if (action_required) {
    console.log(`[scheduler] Currency action required — ${critical_count} critical skills`);
    console.log('[scheduler] Critical skills:', result.critical_skills.join(', ') || 'none');
  }

  return result;
}

function runMonthlyCveValidation() {
  const timestamp = new Date().toISOString();
  console.log(`[scheduler] Monthly CVE validation reminder — ${timestamp}`);
  console.log('[scheduler] Action: Verify all data/cve-catalog.json entries against NVD and CISA KEV.');
  console.log('[scheduler] Action: Update last_verified dates in data/exploit-availability.json.');
  console.log('[scheduler] Run: node orchestrator/index.js validate-cves');

  return {
    task: 'monthly_cve_validation',
    timestamp,
    action: 'Run node orchestrator/index.js validate-cves to check all CVE entries'
  };
}

function runAnnualAudit() {
  const timestamp = new Date().toISOString();
  console.log(`[scheduler] Annual full skill audit — ${timestamp}`);
  console.log('[scheduler] All skills require full threat review against current landscape.');
  console.log('[scheduler] See skill-update-loop for the full annual audit procedure.');

  bus.emit(EVENT_TYPES.SKILL_CURRENCY_LOW, {
    skill_name: 'ALL',
    currency_score: 0,
    days_since_review: 365,
    note: 'Annual audit — all skills require review'
  });

  return {
    task: 'annual_full_audit',
    timestamp,
    action: 'Invoke skill-update-loop for all skills — annual currency review required'
  };
}

module.exports = {
  start,
  stop,
  runCurrencyNow,
  scheduleEvery,
  SAFE_MAX_MS,
  TICK_MS,
  INTERVALS,
  LAST_FIRED_KEYS,
  // Internal hooks exposed for tests; not part of the operator surface.
  _lastFiredStorePath,
  _shouldBootstrapFire,
  _markFired,
  _loadLastFired,
};
