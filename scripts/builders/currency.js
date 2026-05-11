"use strict";
/**
 * scripts/builders/currency.js
 *
 * Builds `data/_indexes/currency.json` — pre-computed currency scores for
 * every skill against a deterministic reference date (manifest's
 * `threat_review_date`). Saves the watchlist/scheduler from re-running
 * `orchestrator currency` to produce the same answer.
 *
 * The reference date is deterministic so the file hash stays stable until
 * skills or the reference change — which is what `validate-indexes`
 * requires. The orchestrator's interactive `currency` command remains the
 * source-of-truth for live decay; this index is the snapshot view.
 *
 * Decay formula matches pipeline.js _currencyScore() exactly:
 *   >180 days → -30, >90 → -20, >60 → -10, >30 → -5
 *   -5 per forward_watch entry
 */

const fs = require("fs");
const path = require("path");

function currencyScore(daysSinceReview, forwardWatchCount) {
  let score = 100;
  if (daysSinceReview > 180) score -= 30;
  else if (daysSinceReview > 90) score -= 20;
  else if (daysSinceReview > 60) score -= 10;
  else if (daysSinceReview > 30) score -= 5;
  score -= forwardWatchCount * 5;
  return Math.max(0, score);
}

function currencyLabel(score) {
  if (score >= 90) return "current";
  if (score >= 70) return "acceptable";
  if (score >= 50) return "stale";
  return "critical_stale";
}

function parseFrontmatterForwardWatchCount(body) {
  const m = body.match(/^---\n([\s\S]*?)\n---/);
  if (!m) return 0;
  const fm = m[1];
  // Counts top-level "forward_watch:" list items. Lines starting with "  - "
  // immediately after a "forward_watch:" line until the next non-indented key.
  const lines = fm.split(/\r?\n/);
  let inFw = false;
  let count = 0;
  for (const line of lines) {
    if (/^forward_watch:\s*$/.test(line)) {
      inFw = true;
      continue;
    }
    if (inFw) {
      if (/^\s*-\s+/.test(line)) {
        count++;
      } else if (/^[a-zA-Z_]/.test(line)) {
        // New top-level key — end of forward_watch block.
        break;
      }
    }
  }
  return count;
}

function buildCurrency({ root, manifest, skills }) {
  const ref = manifest.threat_review_date || "2026-05-01";
  const refDate = new Date(ref + "T00:00:00Z");

  const rows = [];
  for (const s of skills) {
    const body = fs.readFileSync(path.join(root, s.path), "utf8");
    const fwCount = parseFrontmatterForwardWatchCount(body);
    const reviewDate = new Date((s.last_threat_review || "2020-01-01") + "T00:00:00Z");
    const days = Math.floor((refDate - reviewDate) / 86400000);
    const score = currencyScore(days, fwCount);
    rows.push({
      skill: s.name,
      last_threat_review: s.last_threat_review || null,
      days_since_review: days,
      currency_score: score,
      currency_label: currencyLabel(score),
      forward_watch_count: fwCount,
      action_required: score < 70,
    });
  }
  rows.sort((a, b) => a.currency_score - b.currency_score || a.skill.localeCompare(b.skill));

  const summary = {
    current: rows.filter((r) => r.currency_label === "current").length,
    acceptable: rows.filter((r) => r.currency_label === "acceptable").length,
    stale: rows.filter((r) => r.currency_label === "stale").length,
    critical_stale: rows.filter((r) => r.currency_label === "critical_stale").length,
    action_required: rows.filter((r) => r.action_required).length,
  };

  return {
    _meta: {
      schema_version: "1.0.0",
      reference_date: ref,
      note: "Pre-computed skill currency snapshot. Reference date is manifest.threat_review_date (deterministic). Re-runs of build-indexes against the same inputs produce byte-identical output. The orchestrator `currency` command produces a real-time view against today's date.",
      decay_formula: "100 base; -30/-20/-10/-5 at 180/90/60/30-day thresholds; -5 per forward_watch entry. Label thresholds: ≥90 current, ≥70 acceptable, ≥50 stale, <50 critical_stale.",
    },
    summary,
    skills: rows,
  };
}

module.exports = { buildCurrency };
