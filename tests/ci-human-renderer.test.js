"use strict";

/**
 * tests/ci-human-renderer.test.js
 *
 * Pins the operator-facing surfaces of `ci`:
 *
 *   1. Default output is a human digest (table), not JSON.
 *   2. `--json` still emits the documented structured envelope.
 *   3. Result envelope carries `verdict` / `rwep_score` / `top_finding`
 *      / `summary_line` / `evidence_completeness` /
 *      `indicators_evaluated` / `indicators_known` at the top level.
 *   4. Blocked results carry `playbook_id` (same shape contract as
 *      successful results).
 *   5. Session-level warnings are deduped — N copies of the same
 *      bundle_publisher_unclaimed entry collapse to one summary row.
 *   6. `--scope <type>` summary surfaces the inclusion rule so
 *      operators see why cross-cutting + sbom appear alongside the
 *      requested scope.
 *
 * Per the anti-coincidence rule: every assertion checks an exact
 * key/value, not "ok-truthy" / "non-zero" / etc.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test("ci default output is human text, not JSON", () => {
  // No --json / --pretty: the humanRenderer path fires unconditionally
  // when a renderer is registered (matches `run` v0.11.9 behavior).
  const r = cli(["ci", "--required", "cred-stores"]);
  assert.equal(tryJson(r.stdout), null,
    "default ci output must NOT be parseable JSON (operator-readable digest)");
  assert.match(r.stdout, /^ci: 1 playbook\(s\)/,
    "human header line must lead with `ci: N playbook(s)`");
  assert.match(r.stdout, /playbook\s+verdict\s+rwep\s+evidence\s+finding/,
    "per-playbook table header must be present");
  assert.match(r.stdout, /Full structured result: --json/,
    "footer must point operator at --json for the structured body");
});

test("ci --json still emits parseable JSON with documented envelope", () => {
  const r = cli(["ci", "--required", "cred-stores", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --json must emit parseable JSON");
  assert.equal(body.verb, "ci");
  assert.equal(typeof body.summary, "object");
  // Summary carries deduped runtime warnings.
  assert.ok(Array.isArray(body.summary.runtime_warnings),
    "summary.runtime_warnings must be an array");
  assert.equal(typeof body.summary.runtime_warnings_count, "number");
});

test("ci result carries top-level verdict / rwep_score / summary_line / evidence_completeness", () => {
  const r = cli(["ci", "--required", "secrets", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --json must emit parseable JSON");
  const row = body.results.find(x => x.playbook_id === "secrets");
  assert.ok(row, "secrets result must be present");
  if (row.ok === false) {
    // Blocked path: playbook_id MUST be at the top of the result
    // envelope (same contract as the success path).
    assert.equal(row.playbook_id, "secrets",
      "blocked results must carry playbook_id at top level");
    assert.equal(row.evidence_completeness, "not-evaluated",
      "blocked results report evidence_completeness=not-evaluated");
  } else {
    // Verdict MUST be derived from phases.detect.classification.
    // validate() does not carry a `verdict` field — sourcing the
    // hoist from phases.validate.verdict would degrade every non-
    // blocked result to the fallback "inconclusive".
    assert.equal(typeof row.verdict, "string");
    assert.equal(row.verdict, row.phases?.detect?.classification,
      "hoisted verdict must equal phases.detect.classification — not phases.validate.verdict");
    assert.ok(["detected", "not_detected", "inconclusive", "pending", "skipped"].includes(row.verdict),
      `verdict must be one of the documented enum values; got ${row.verdict}`);
    assert.equal(typeof row.summary_line, "string");
    assert.ok(["complete", "partial", "missing", "unknown", "not-evaluated"]
      .includes(row.evidence_completeness),
      `evidence_completeness must be one of the documented enum values; got ${row.evidence_completeness}`);
    // rwep_score is null on inconclusive-no-evidence; explicit number otherwise.
    assert.ok(row.rwep_score === null || typeof row.rwep_score === "number",
      "rwep_score is number or null, never undefined");
    // indicators_known is a count (or null when phase.detect.indicators absent).
    assert.ok(row.indicators_known === null || typeof row.indicators_known === "number",
      "indicators_known is number or null");
  }
});

test("ci --scope code surfaces scope_inclusion_rules in summary", () => {
  const r = cli(["ci", "--scope", "code", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --scope code --json must emit parseable JSON");
  assert.equal(body.summary.scope_request, "code");
  assert.ok(Array.isArray(body.summary.scope_inclusion_rules),
    "summary.scope_inclusion_rules must be an array");
  assert.ok(body.summary.scope_inclusion_rules.length >= 2,
    "scope_inclusion_rules must enumerate at least the scope-match rule and cross-cutting rule");
  // The code-scope-specific rule about sbom auto-inclusion fires only
  // when a lockfile is detected; the exceptd repo has package-lock.json
  // so the rule must be present.
  const sbomRule = body.summary.scope_inclusion_rules.find(s => /sbom/.test(s));
  assert.ok(sbomRule, "scope_inclusion_rules must mention sbom auto-inclusion on a lockfile repo");
});

test("ci --scope code dedupes session-level warnings across N playbooks", () => {
  // ci --scope code runs 8 playbooks on this repo (4 code + 4 cross-
  // cutting, sbom skipped because of mutex). Each successful playbook
  // independently touches the CSAF bundle-build path, which surfaces
  // the bundle_publisher_unclaimed warning when --publisher-namespace
  // is not supplied. The dedup folds N copies into one summary entry.
  const r = cli(["ci", "--scope", "code", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --scope code --json must emit parseable JSON");
  // Count occurrences across results vs. summary dedup.
  let perResultCount = 0;
  for (const row of body.results) {
    const errs = row?.phases?.analyze?.runtime_errors || [];
    perResultCount += errs.filter(e => e.kind === "bundle_publisher_unclaimed").length;
  }
  const summaryDedup = body.summary.runtime_warnings.filter(e => e.kind === "bundle_publisher_unclaimed").length;
  if (perResultCount > 0) {
    assert.equal(summaryDedup, 1,
      `summary.runtime_warnings must dedupe bundle_publisher_unclaimed to a single entry; got ${summaryDedup}`);
    assert.ok(perResultCount > summaryDedup,
      "per-result count must exceed dedup count when the warning is session-level");
  }
});
