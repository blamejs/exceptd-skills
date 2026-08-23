'use strict';

/**
 * Interval-based coordinator for skill currency maintenance: weekly currency
 * check, monthly CVE validation reminder, annual full audit. Breached currency
 * thresholds are emitted on event-bus.js.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const { bus, EVENT_TYPES } = require('./event-bus');
const { currencyCheck } = require('./pipeline');

const SAFE_MAX_MS = 2_147_483_647;            // INT32 max — Node's setTimeout/setInterval ceiling.
const TICK_MS = Math.min(SAFE_MAX_MS, 24 * 60 * 60 * 1000);

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

/** EXCEPTD_HOME overrides the root so tests stay off the real home dir. */
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
    // Best-effort: a failed write only costs the next start its last-fired knowledge.
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

/**
 * Schedule `handler` every `intervalMs` ms, returning an unschedule function.
 * Throws RangeError unless intervalMs is a positive finite number.
 *
 * setInterval coerces its delay to signed 32-bit — above 2^31-1 ms it clamps to
 * 1 ms and fires ~1000x/sec, which the monthly and annual intervals would hit.
 * So the timer ticks at TICK_MS or less and compares wall-clock elapsed.
 */
function scheduleEvery(intervalMs, handler) {
  // Zero, negative and NaN drive a ~1 ms tick, so refuse rather than floor.
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
  // No id.unref(): `watch` is long-running and relies on these timers to hold the
  // event loop open — the event bus has no I/O of its own.
  return () => clearInterval(id);
}

/**
 * Start the scheduler: the weekly task runs immediately, then all three run on
 * their intervals. Monthly and annual also bootstrap-fire when the persisted
 * last-fired timestamp is absent or older than the interval.
 */
function start() {
  if (running) return;
  running = true;

  const safeRun = (label, fn) => {
    try { fn(); }
    catch (e) { console.error('[scheduler] ' + label + ' failed:', e); }
  };

  // Weekly always fires on bootstrap — ungated, unlike the two below.
  safeRun('weekly currency bootstrap', () => {
    runWeeklyCurrencyCheck();
    _markFired(LAST_FIRED_KEYS.WEEKLY_CURRENCY);
  });

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

function stop() {
  for (const off of unschedulers) {
    try { off(); } catch { /* ignore */ }
  }
  unschedulers = [];
  running = false;
  console.log('[scheduler] Stopped.');
}

function runCurrencyNow() {
  return runWeeklyCurrencyCheck();
}

function runWeeklyCurrencyCheck() {
  const timestamp = new Date().toISOString();
  console.log(`[scheduler] Running weekly currency check — ${timestamp}`);

  const { currency_report, action_required, critical_count } = currencyCheck();

  // ONE aggregate event per run, not N per-skill: per-skill events storm every
  // consumer. The payload carries the full stale list so a consumer can drill in.
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
  console.log('[scheduler] Run: exceptd validate-cves');

  return {
    task: 'monthly_cve_validation',
    timestamp,
    action: 'Run `exceptd validate-cves` to check all CVE entries'
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
