"use strict";
/**
 * CI workflow ↔ branch-protection sync test.
 *
 * docs/REPO-SETTINGS.md §3 hardcodes the list of required status checks
 * for branch protection on `main`. Those context names must match the
 * `name:` field of every job in .github/workflows/ci.yml and
 * scorecard.yml. If a maintainer renames a job and forgets to update
 * REPO-SETTINGS.md, branch protection silently degrades — the renamed
 * check stops being required, so a PR can merge without it ever running.
 *
 * This test parses both files and asserts:
 *   - Every required check listed in REPO-SETTINGS.md exists as a job
 *     name in one of the workflow files.
 *   - Every CI job we expect to gate releases is listed as required.
 *   - Workflow-level permissions are least-privilege (read-only).
 *   - Project-controlled actions are pinned by SHA, not floating tags
 *     (third-party actions only — first-party actions/* are also pinned
 *     in practice, but we verify the ones that touch secrets / write
 *     anywhere).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const CI_WORKFLOW = path.join(ROOT, ".github", "workflows", "ci.yml");
const SCORECARD_WORKFLOW = path.join(ROOT, ".github", "workflows", "scorecard.yml");
const REPO_SETTINGS = path.join(ROOT, "docs", "REPO-SETTINGS.md");

function parseJobNames(yamlPath) {
  const yaml = fs.readFileSync(yamlPath, "utf8");
  const lines = yaml.split(/\r?\n/);
  const jobs = [];
  let inJobs = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    if (/^[a-zA-Z_]/.test(line) && !/^jobs:/.test(line)) break;

    const jobMatch = line.match(/^ {2}([a-z0-9-]+):\s*$/);
    if (jobMatch) {
      for (let j = i + 1; j < lines.length; j++) {
        const next = lines[j];
        if (/^ {2}[a-z0-9-]+:\s*$/.test(next)) break;
        if (/^[a-zA-Z_]/.test(next)) break;
        const nameMatch = next.match(/^ {4}name:\s*(.+?)\s*$/);
        if (nameMatch) {
          jobs.push(nameMatch[1].replace(/^["']|["']$/g, ""));
          break;
        }
      }
    }
  }
  return jobs;
}

function parseRequiredChecks() {
  const md = fs.readFileSync(REPO_SETTINGS, "utf8");
  // Extract context names from the JSON block under §3.
  const checks = [];
  for (const m of md.matchAll(/"context":\s*"([^"]+)"/g)) {
    checks.push(m[1]);
  }
  return checks;
}

function expandMatrixJobs(jobNames) {
  // CI defines a matrix job named `Tests (${{ matrix.os }})` which
  // GitHub expands at run time into one status check per OS. The
  // REPO-SETTINGS.md required-checks list names each expansion
  // explicitly. Translate the abstract name to its concrete expansions.
  const expanded = [];
  for (const name of jobNames) {
    if (name.includes("${{ matrix.os }}")) {
      for (const os of ["ubuntu-latest", "windows-latest", "macos-latest"]) {
        expanded.push(name.replace("${{ matrix.os }}", os));
      }
    } else {
      expanded.push(name);
    }
  }
  return expanded;
}

test("REPO-SETTINGS.md lists the required-checks JSON block", () => {
  const checks = parseRequiredChecks();
  assert.ok(
    checks.length >= 8,
    `expected at least 8 required checks in REPO-SETTINGS.md §3, found ${checks.length}`
  );
});

test("every REPO-SETTINGS.md required check exists in a workflow", () => {
  const ciJobs = expandMatrixJobs(parseJobNames(CI_WORKFLOW));
  const scorecardJobs = parseJobNames(SCORECARD_WORKFLOW);
  const allWorkflowJobs = new Set([...ciJobs, ...scorecardJobs]);
  const requiredChecks = parseRequiredChecks();

  for (const check of requiredChecks) {
    assert.ok(
      allWorkflowJobs.has(check),
      `required check "${check}" listed in docs/REPO-SETTINGS.md is not a job ` +
        `in ci.yml or scorecard.yml. Either add the job or remove the requirement.`
    );
  }
});

test("critical CI jobs are listed as required in REPO-SETTINGS.md", () => {
  // Inverse direction: if a CI job is one of the load-bearing gates
  // (signature verification, secret scan, snapshot gate), it MUST be a
  // required check. A maintainer adding a new gate must also list it.
  const ciJobs = expandMatrixJobs(parseJobNames(CI_WORKFLOW));
  const requiredChecks = new Set(parseRequiredChecks());

  const mustBeRequired = [
    "Verify skill signatures (Ed25519)",
    "Data integrity (catalog + manifest snapshot)",
    "Lint skill files",
    "Secret scan (gitleaks)",
    "Lint summary",
  ];

  for (const job of mustBeRequired) {
    assert.ok(
      ciJobs.includes(job),
      `expected CI job "${job}" to exist in ci.yml`
    );
    assert.ok(
      requiredChecks.has(job),
      `CI job "${job}" must be a required status check in docs/REPO-SETTINGS.md §3`
    );
  }
});

test("ci.yml declares workflow-level least-privilege permissions", () => {
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  // Match a top-level `permissions:` block (zero indent) followed by
  // `contents: read`. Reject `write-all` or any unscoped writes.
  assert.match(
    yaml,
    /^permissions:\s*\n\s+contents:\s*read\s*$/m,
    "ci.yml must declare workflow-level `permissions: contents: read`"
  );
  assert.doesNotMatch(
    yaml,
    /^permissions:\s*write-all/m,
    "ci.yml must not declare workflow-level write-all permissions"
  );
});

test("ci.yml declares concurrency cancel-in-progress", () => {
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  assert.match(
    yaml,
    /^concurrency:\s*\n\s+group:\s*ci-\$\{\{\s*github\.ref\s*\}\}/m,
    "ci.yml must scope concurrency by ref"
  );
  assert.match(
    yaml,
    /cancel-in-progress:\s*true/,
    "ci.yml must cancel in-progress runs on the same ref"
  );
});

test("ci.yml pins every third-party action by SHA", () => {
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  // Find every `uses:` line.
  const usesLines = yaml
    .split(/\r?\n/)
    .filter((l) => /^\s*uses:\s*/.test(l))
    .map((l) => l.trim());

  assert.ok(usesLines.length > 0, "ci.yml has at least one `uses:` line");

  for (const line of usesLines) {
    // Accept either:
    //   uses: <owner>/<repo>@<40-char SHA>  # <tag>
    //   uses: <owner>/<repo>/<path>@<40-char SHA>  # <tag>
    assert.match(
      line,
      /uses:\s*[a-z0-9._-]+\/[a-z0-9._/-]+@[0-9a-f]{40}\s*(?:#.*)?$/i,
      `action reference must be SHA-pinned: ${line}`
    );
  }
});

test("scorecard.yml workflow exists and runs on push to main + weekly cron", () => {
  const yaml = fs.readFileSync(SCORECARD_WORKFLOW, "utf8");
  assert.match(yaml, /name:\s*OpenSSF Scorecard/);
  assert.match(yaml, /branches:\s*\[main\]/);
  assert.match(yaml, /cron:\s*"27 5 \* \* 1"/);
});

test("ci.yml runs only on main + tag + PR + manual dispatch", () => {
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  // Trigger surface should match the blamejs convention: scoped to main,
  // not a wide-open `branches: ['**']` (which would burn CI minutes on
  // every dev branch push). The `tags: ["v*"]` line covers release tags.
  assert.match(yaml, /branches:\s*\[main\]/);
  assert.match(yaml, /tags:\s*\["v\*"\]/);
  assert.match(yaml, /workflow_dispatch:/);
  assert.doesNotMatch(
    yaml,
    /branches:\s*\[\s*['"]\*\*['"]\s*\]/,
    "ci.yml must not trigger on every branch — scope to main + PR to main"
  );
});

test("Tests matrix covers ubuntu, windows, macos", () => {
  const yaml = fs.readFileSync(CI_WORKFLOW, "utf8");
  assert.match(yaml, /ubuntu-latest/);
  assert.match(yaml, /windows-latest/);
  assert.match(yaml, /macos-latest/);
});
