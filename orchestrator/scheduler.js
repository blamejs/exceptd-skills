'use strict';

/**
 * Scheduled task coordinator for skill currency maintenance.
 *
 * Schedules: weekly currency check, monthly CVE validation, annual full audit.
 * Emits events via event-bus.js when currency thresholds are breached.
 *
 * This is a simple interval-based scheduler. For production use, swap for a
 * proper cron daemon or cloud scheduler without changing the task definitions.
 */

const { bus, EVENT_TYPES } = require('./event-bus');
const { currencyCheck } = require('./pipeline');

const INTERVALS = {
  WEEKLY_CURRENCY: 7 * 24 * 60 * 60 * 1000,
  MONTHLY_CVE_VALIDATION: 30 * 24 * 60 * 60 * 1000,
  ANNUAL_AUDIT: 365 * 24 * 60 * 60 * 1000
};

const CURRENCY_THRESHOLDS = {
  critical: 50,
  warning: 70
};

let timers = [];
let running = false;

// --- public API ---

/**
 * Start the scheduler. Runs all tasks immediately on start, then on schedule.
 */
function start() {
  if (running) return;
  running = true;

  runWeeklyCurrencyCheck();
  timers.push(setInterval(runWeeklyCurrencyCheck, INTERVALS.WEEKLY_CURRENCY));
  timers.push(setInterval(runMonthlyCveValidation, INTERVALS.MONTHLY_CVE_VALIDATION));
  timers.push(setInterval(runAnnualAudit, INTERVALS.ANNUAL_AUDIT));

  console.log('[scheduler] Started. Weekly currency check, monthly CVE validation, annual audit scheduled.');
}

/**
 * Stop the scheduler and clear all timers.
 */
function stop() {
  for (const t of timers) clearInterval(t);
  timers = [];
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

  for (const skill of currency_report) {
    if (skill.currency_score < CURRENCY_THRESHOLDS.critical) {
      bus.skillCurrencyLow({
        skill_name: skill.skill,
        currency_score: skill.currency_score,
        days_since_review: skill.days_since_review
      });
    }
  }

  const result = {
    task: 'weekly_currency_check',
    timestamp,
    skills_checked: currency_report.length,
    action_required,
    critical_count,
    critical_skills: currency_report.filter(s => s.currency_score < CURRENCY_THRESHOLDS.critical).map(s => s.skill),
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

module.exports = { start, stop, runCurrencyNow };
