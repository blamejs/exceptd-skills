"use strict";
/**
 * tests/workflows-security.test.js
 *
 * Cross-workflow security invariants. The CI-workflow ↔ branch-protection
 * sync lives in tests/ci-workflow.test.js; this file enforces the rules
 * that apply uniformly to EVERY workflow YAML in .github/workflows/:
 *
 *   1. No `${{ steps.*.outputs.* }}` interpolation inside an
 *      `actions/github-script` `script:` template literal — the value is
 *      attacker-controlled in any workflow whose inputs / step outputs
 *      derive from external data. Route via `env:` and read from
 *      `process.env.<NAME>` instead (CWE-1395 / Scorecard
 *      DangerousWorkflowID).
 *
 *   2. No `${{ inputs.* }}` interpolation directly inside a bash `run:`
 *      block — workflow_dispatch inputs are operator-typed and can
 *      contain shell metacharacters. Route via `env:` and reference
 *      as `"$INPUT_NAME"` with proper quoting (CWE-78).
 *
 *   3. Every third-party action reference is SHA-pinned (40-char hex
 *      after `@`). Floating tags are rejected. gitleaks (curl from
 *      GitHub releases API) is the documented deliberate float and
 *      lives outside the `uses:` surface this rule covers.
 *
 *   4. Every workflow declares explicit `permissions:` somewhere —
 *      either at workflow level or on every job. Inherited
 *      write-all is forbidden (Scorecard TokenPermissionsID).
 *
 * These rules existed in spirit before — the v0.12.16 audit surfaced
 * F3 (atlas-currency github-script template literal) and F4 (refresh.yml
 * bash run: interpolation) as concrete regressions. This file is the
 * machine-enforced version of the audit so the same class can't
 * recur.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const WORKFLOWS_DIR = path.join(ROOT, ".github", "workflows");

function listWorkflows() {
  return fs
    .readdirSync(WORKFLOWS_DIR)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .map((f) => path.join(WORKFLOWS_DIR, f));
}

/**
 * Split the YAML into steps. Each step starts with `      - name:` (6-space
 * indent under a job, then list-item dash). We extract a flat array of
 * `{name, body}` so the per-step assertions below can reason about a step
 * in isolation — `env:` set on a step does NOT bleed across step boundaries.
 *
 * This is a lightweight scanner; it intentionally avoids a full YAML parse
 * because the test must not introduce a dev-dependency on `js-yaml`.
 */
function splitSteps(yaml) {
  const lines = yaml.split(/\r?\n/);
  const steps = [];
  let cur = null;
  for (const line of lines) {
    // Step boundary: 6-space indent + `- ` (also matches `- name:` and
    // `- uses:` since some steps start with uses).
    if (/^ {6}- /.test(line)) {
      if (cur) steps.push(cur);
      cur = { name: null, body: line + "\n" };
      const nm = line.match(/^ {6}-\s*name:\s*(.+?)\s*$/);
      if (nm) cur.name = nm[1].replace(/^["']|["']$/g, "");
      continue;
    }
    if (cur) {
      // A step ends when indentation drops below 8 spaces (back to job-level keys).
      if (/^ {0,7}\S/.test(line) && !/^ {6}- /.test(line) && line.trim() !== "") {
        steps.push(cur);
        cur = null;
        continue;
      }
      cur.body += line + "\n";
      if (cur.name == null) {
        const nm = line.match(/^ {8}name:\s*(.+?)\s*$/);
        if (nm) cur.name = nm[1].replace(/^["']|["']$/g, "");
      }
    }
  }
  if (cur) steps.push(cur);
  return steps;
}

test("every workflow file parses with at least one job", () => {
  const files = listWorkflows();
  assert.ok(files.length >= 5, `expected >=5 workflow files, got ${files.length}`);
  for (const f of files) {
    const yaml = fs.readFileSync(f, "utf8");
    assert.match(yaml, /^jobs:\s*$/m, `${path.basename(f)} must declare jobs:`);
  }
});

test("no ${{ steps.*.outputs.* }} inside github-script template literal", () => {
  for (const f of listWorkflows()) {
    const yaml = fs.readFileSync(f, "utf8");
    const steps = splitSteps(yaml);
    for (const step of steps) {
      // Only check steps that invoke actions/github-script.
      if (!/uses:\s*actions\/github-script@/.test(step.body)) continue;
      // Extract the script: | block.
      const scriptMatch = step.body.match(/^\s*script:\s*\|[^\n]*\n([\s\S]*?)(?=^\s{8,12}\S|^\s{0,6}\S|\Z)/m);
      if (!scriptMatch) continue;
      const script = scriptMatch[1];
      assert.doesNotMatch(
        script,
        /\$\{\{\s*steps\.[^}]+\.outputs\./,
        `${path.basename(f)} step "${step.name}" interpolates ` +
          `\${{ steps.*.outputs.* }} inside a github-script template literal. ` +
          `Route via env: and read from process.env (CWE-1395).`
      );
      assert.doesNotMatch(
        script,
        /\$\{\{\s*inputs\./,
        `${path.basename(f)} step "${step.name}" interpolates ` +
          `\${{ inputs.* }} inside a github-script template literal. ` +
          `Route via env: and read from process.env (CWE-1395).`
      );
      assert.doesNotMatch(
        script,
        /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|head_commit|review|workflow_run)\./,
        `${path.basename(f)} step "${step.name}" interpolates user-controlled ` +
          `\${{ github.event.* }} inside a github-script template literal. ` +
          `Route via env: and read from process.env (CWE-1395).`
      );
    }
  }
});

test("no ${{ inputs.* }} or untrusted github.event.* inside bash run: blocks (must be routed via env:)", () => {
  for (const f of listWorkflows()) {
    const yaml = fs.readFileSync(f, "utf8");
    const steps = splitSteps(yaml);
    for (const step of steps) {
      // Skip github-script steps — that surface is covered by the prior test.
      if (/uses:\s*actions\/github-script@/.test(step.body)) continue;
      // Only consider steps that have a `run:` line.
      if (!/^\s*run:\s/.test(step.body) && !/^\s*run:\s*\|/.test(step.body)) continue;

      // Extract the run: block content. Accept both single-line and
      // block-scalar forms.
      const runMatch = step.body.match(/^\s*run:\s*\|[^\n]*\n([\s\S]*?)(?=^\s{8,12}\S|^\s{0,6}\S|\Z)/m);
      let runBody;
      if (runMatch) {
        runBody = runMatch[1];
      } else {
        const single = step.body.match(/^\s*run:\s*(.+)$/m);
        runBody = single ? single[1] : "";
      }
      if (!runBody) continue;

      assert.doesNotMatch(
        runBody,
        /\$\{\{\s*inputs\./,
        `${path.basename(f)} step "${step.name}" interpolates ` +
          `\${{ inputs.* }} directly inside a bash run: block. ` +
          `Route via env: and reference as "$VAR_NAME" with proper quoting (CWE-78).`
      );
      assert.doesNotMatch(
        runBody,
        /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|head_commit|review|workflow_run)\./,
        `${path.basename(f)} step "${step.name}" interpolates user-controlled ` +
          `\${{ github.event.* }} directly inside a bash run: block. ` +
          `Route via env: and reference as "$VAR_NAME" (CWE-78).`
      );
    }
  }
});

test("every third-party action reference is SHA-pinned (40-char hex)", () => {
  for (const f of listWorkflows()) {
    const yaml = fs.readFileSync(f, "utf8");
    const usesLines = yaml
      .split(/\r?\n/)
      .filter((l) => /^\s*uses:\s*/.test(l))
      .map((l) => l.trim());
    for (const line of usesLines) {
      assert.match(
        line,
        /uses:\s*[a-z0-9._-]+\/[a-z0-9._/-]+@[0-9a-f]{40}\s*(?:#.*)?$/i,
        `${path.basename(f)}: action reference must be SHA-pinned: ${line}`
      );
    }
  }
});

test("every workflow declares permissions: somewhere (workflow or job level)", () => {
  for (const f of listWorkflows()) {
    const yaml = fs.readFileSync(f, "utf8");
    assert.match(
      yaml,
      /^permissions:\s*(?:\n|$)|^\s{4}permissions:\s*(?:\n|$)/m,
      `${path.basename(f)} must declare \`permissions:\` at workflow or job level (Scorecard TokenPermissionsID)`
    );
    assert.doesNotMatch(
      yaml,
      /^permissions:\s*write-all/m,
      `${path.basename(f)} must not declare write-all permissions`
    );
  }
});

test("actions/checkout SHA comment is consistent across workflows", () => {
  const checkoutLines = [];
  for (const f of listWorkflows()) {
    const yaml = fs.readFileSync(f, "utf8");
    for (const line of yaml.split(/\r?\n/)) {
      if (/uses:\s*actions\/checkout@/.test(line)) {
        const m = line.match(/uses:\s*actions\/checkout@([0-9a-f]{40})\s*#\s*(v\S+)/i);
        if (m) checkoutLines.push({ file: path.basename(f), sha: m[1], tag: m[2] });
      }
    }
  }
  // Group by SHA. Each SHA must have exactly one tag comment across all uses.
  const byShaToTags = new Map();
  for (const c of checkoutLines) {
    if (!byShaToTags.has(c.sha)) byShaToTags.set(c.sha, new Set());
    byShaToTags.get(c.sha).add(c.tag);
  }
  for (const [sha, tags] of byShaToTags) {
    assert.equal(
      tags.size,
      1,
      `actions/checkout@${sha} is annotated with conflicting version comments ` +
        `across workflows: ${Array.from(tags).join(", ")}. Pick one canonical ` +
        `version comment and apply it everywhere.`
    );
  }
});

test("atlas-currency.yml routes the currency report via env: (not template literal)", () => {
  const f = path.join(WORKFLOWS_DIR, "atlas-currency.yml");
  const yaml = fs.readFileSync(f, "utf8");
  // Must reference REPORT_TEXT env var.
  assert.match(
    yaml,
    /REPORT_TEXT:\s*\$\{\{\s*steps\.currency\.outputs\.report\s*\}\}/,
    "atlas-currency.yml must route steps.currency.outputs.report via env.REPORT_TEXT"
  );
  assert.match(
    yaml,
    /process\.env\.REPORT_TEXT/,
    "atlas-currency.yml github-script must read the report from process.env.REPORT_TEXT"
  );
});

test("refresh.yml validates inputs.source against [a-z,]+ allowlist before passing to shell", () => {
  const f = path.join(WORKFLOWS_DIR, "refresh.yml");
  const yaml = fs.readFileSync(f, "utf8");
  // Must use SOURCE_INPUT env var (not direct ${{ inputs.source }} in run:).
  assert.match(
    yaml,
    /SOURCE_INPUT:\s*\$\{\{\s*inputs\.source\s*\}\}/,
    "refresh.yml must route inputs.source via env.SOURCE_INPUT"
  );
  // Must enforce the [a-z,]+ shape allowlist.
  assert.match(
    yaml,
    /grep\s+-Eq\s+'\^\[a-z,\]\+\$'/,
    "refresh.yml must validate SOURCE_INPUT against ^[a-z,]+$ before using it"
  );
});
