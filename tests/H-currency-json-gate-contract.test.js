"use strict";
/**
 * Contract test for the ATLAS-currency workflow's stale-skill gate.
 *
 * .github/workflows/atlas-currency.yml decides whether to open a
 * "Skills past review window" issue by reading the `action_required`
 * field from `node orchestrator/index.js currency --json`. That gate is
 * only correct if `action_required` is a value-derived boolean — true iff
 * at least one skill scores below the critical currency threshold — rather
 * than a flag bound to some human-readable prose string the workflow used
 * to grep for.
 *
 * This locks that contract: the JSON output must carry a boolean
 * `action_required`, a non-empty `currency_report` with a numeric
 * `currency_score` per skill, and `action_required` must equal the
 * value-derived "any skill below the action threshold" predicate. If a
 * future change renames the field or decouples it from the scores, the
 * workflow gate silently breaks and this test catches it first.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const ORCH = path.join(ROOT, "orchestrator", "index.js");

// Two distinct thresholds drive the JSON gate fields (orchestrator/pipeline.js):
//   - action_required: true iff ANY skill's currency_score < 70 (the warn
//     tier — "past review window", which is what the workflow issues on)
//   - critical_count: the COUNT of skills with currency_score < 50
const ACTION_THRESHOLD = 70;
const CRITICAL_THRESHOLD = 50;

// Run the exact command the workflow runs and extract the JSON object.
// runCurrencyNow() may print a non-JSON scheduler line to stdout before
// the JSON document, so take the last line that parses as an object —
// the same robustness the workflow's gate applies.
function currencyJson() {
  const r = spawnSync(process.execPath, [ORCH, "currency", "--json"], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30000,
  });
  assert.equal(r.status, 0, `currency --json exited ${r.status}: ${r.stderr}`);
  const jsonLine = r.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("{"))
    .pop();
  assert.ok(jsonLine, `no JSON object line in currency --json stdout: ${r.stdout}`);
  return JSON.parse(jsonLine);
}

test("currency --json exposes a value-derived action_required boolean", () => {
  const j = currencyJson();

  assert.equal(j.ok, true);
  assert.equal(
    typeof j.action_required,
    "boolean",
    "action_required must be a boolean the workflow gate can read directly"
  );
  assert.equal(typeof j.critical_count, "number");

  assert.ok(Array.isArray(j.currency_report), "currency_report must be an array");
  assert.ok(j.currency_report.length > 0, "currency_report must not be empty");
  for (const s of j.currency_report) {
    assert.equal(
      typeof s.currency_score,
      "number",
      `every report entry must carry a numeric currency_score (${s.skill})`
    );
  }
});

test("action_required equals the value-derived below-threshold predicate", () => {
  const j = currencyJson();

  // Recompute both gate decisions straight from the per-skill scores. This
  // is what the workflow's gate must reduce to — independent of any prose.
  const belowAction = j.currency_report.filter(
    (s) => s.currency_score < ACTION_THRESHOLD
  );
  const belowCritical = j.currency_report.filter(
    (s) => s.currency_score < CRITICAL_THRESHOLD
  );

  assert.equal(
    j.action_required,
    belowAction.length > 0,
    `action_required (${j.action_required}) must match the value-derived ` +
      `"any skill below ${ACTION_THRESHOLD}%" predicate; ` +
      `${belowAction.length} skill(s) below the action threshold`
  );
  assert.equal(
    j.critical_count,
    belowCritical.length,
    `critical_count must equal the count of skills below ${CRITICAL_THRESHOLD}%`
  );
  // Per-entry action_required mirrors the same warn-tier predicate.
  for (const s of j.currency_report) {
    assert.equal(
      s.action_required,
      s.currency_score < ACTION_THRESHOLD,
      `per-skill action_required must derive from the score (${s.skill})`
    );
  }
});
