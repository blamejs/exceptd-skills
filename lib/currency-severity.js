"use strict";

/**
 * lib/currency-severity.js
 *
 * Pure function used by the `exceptd doctor` verb to turn a currency report
 * into a health verdict.
 *
 * The scoring model in orchestrator/pipeline.js grades every skill on four
 * labels — current (score >= 90), acceptable (70-89), stale (50-69),
 * critical_stale (< 50) — and raises `action_required` only below 70. The
 * pre-extraction predicate in the doctor ignored that ladder and failed on
 * `currency_label !== "current"`, which folded the acceptable tier in with
 * genuine staleness.
 *
 * That made the health check a scheduled failure rather than a signal: a
 * skill's score drops from 90 to 80 the day it crosses 90 days since
 * `last_threat_review`, so any skill will turn `doctor` red on a fixed
 * cadence with no code change and nothing actually wrong.
 *
 * The tiers now map to severity the way the model defines them:
 *
 *   current                     → healthy, no entry in either bucket
 *   acceptable (drifting)       → severity:"warn", ok:true, exit 0
 *   stale / critical_stale      → ok:false (error), exit 1
 *
 * `stale_skills` keeps its original meaning — every skill that is not
 * `current` — so an existing consumer reading it still sees the full picture.
 * `drifting_skills` and `action_required_skills` split that list along the
 * boundary the exit code now respects.
 */

/**
 * @param {object[]} report        currency_report rows from currencyCheck()
 * @param {boolean}  actionRequired the report-level action_required flag
 * @returns {{ok: boolean, severity: string|null, stale: object[], drifting: object[], actionable: object[], critical: object[]}}
 */
function classifyCurrency(report, actionRequired) {
  const rows = Array.isArray(report) ? report.filter(r => r && typeof r === "object") : [];

  const stale = rows.filter(s => s.action_required || s.currency_label !== "current");
  const drifting = rows.filter(s => !s.action_required && s.currency_label !== "current");
  const actionable = rows.filter(s => s.action_required);
  const critical = rows.filter(s => s.currency_score !== undefined && s.currency_score < 50);

  // The report-level flag is honored even when no row carries action_required,
  // so an upstream that raises the flag some other way still fails closed.
  const ok = actionable.length === 0 && !actionRequired;

  return {
    ok,
    severity: ok && drifting.length > 0 ? "warn" : null,
    stale,
    drifting,
    actionable,
    critical,
  };
}

module.exports = { classifyCurrency };
