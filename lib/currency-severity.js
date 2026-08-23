"use strict";

/**
 * Pure function the `exceptd doctor` verb uses to turn a currency report into a
 * health verdict, on the ladder orchestrator/pipeline.js scores against:
 *
 *   current (>= 90)               → healthy, in neither bucket
 *   acceptable (70-89, drifting)  → severity:"warn", ok:true, exit 0
 *   stale / critical_stale (< 70) → ok:false, exit 1
 *
 * Failing on `currency_label !== "current"` instead folds the acceptable tier in
 * with real staleness and turns doctor red on a fixed cadence with nothing wrong.
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

  // The report-level flag is honored even when no row sets it, so this fails closed.
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
