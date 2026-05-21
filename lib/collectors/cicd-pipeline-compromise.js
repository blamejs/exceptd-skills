"use strict";

/**
 * lib/collectors/cicd-pipeline-compromise.js
 *
 * Companion collector for the `cicd-pipeline-compromise` playbook.
 * Consumer-side CI/CD posture: walks .github/workflows/*.yml,
 * .gitlab-ci.yml, .circleci/config.yml, and the project's
 * infra/terraform/policies dirs for OIDC trust JSON. Flips
 * deterministic indicators that detect the published-Action and
 * fork-PR attack classes documented in the playbook.
 *
 * Skipped indicators (require GitHub API or HSM/KMS access, left
 * unflipped so the runner returns inconclusive):
 *
 *   self-hosted-runner-non-ephemeral    needs GitHub API (runners list)
 *   runner-scoped-signing-key           needs HSM/KMS inspection
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const COLLECTOR_ID = "cicd-pipeline-compromise";

function readSafe(p, max = 512 * 1024) {
  try {
    const s = fs.statSync(p);
    if (s.size > max) return null;
    return fs.readFileSync(p, "utf8");
  } catch { return null; }
}

function walkWorkflows(root) {
  const out = [];
  const wfDir = path.join(root, ".github", "workflows");
  if (fs.existsSync(wfDir)) {
    let entries;
    try { entries = fs.readdirSync(wfDir, { withFileTypes: true }); }
    catch { entries = []; }
    for (const e of entries) {
      if (!e.isFile()) continue;
      if (!/\.(ya?ml)$/i.test(e.name)) continue;
      const full = path.join(wfDir, e.name);
      const content = readSafe(full);
      if (content != null) out.push({ full, rel: path.relative(root, full).replace(/\\/g, "/"), content });
    }
  }
  // Also recognise the most common single-file CI YAMLs at repo root.
  for (const top of [".gitlab-ci.yml", ".circleci/config.yml"]) {
    const full = path.join(root, top);
    if (fs.existsSync(full)) {
      const content = readSafe(full);
      if (content != null) out.push({ full, rel: top, content });
    }
  }
  return out;
}

// `on:` trigger detection. Workflows declare triggers via either
// a YAML list (`on: [push, pull_request_target]`), a single
// scalar (`on: push`), or a YAML mapping (`on:\n  push:\n  pull_request_target:`).
// Heuristic accepts all three.
function workflowHasTrigger(content, name) {
  // scalar form: `on: <name>`
  if (new RegExp(`^\\s*on:\\s*['"]?${name}['"]?\\s*(?:#.*)?$`, "m").test(content)) return true;
  // list form: `on: [..., <name>, ...]`
  const listMatch = content.match(/^\s*on:\s*\[([^\]]*)\]/m);
  if (listMatch && new RegExp(`(?:^|,)\\s*['"]?${name}['"]?\\s*(?:,|$)`).test(listMatch[1])) return true;
  // mapping form: `on:\n  <name>:` (key with optional sub-mapping)
  const mapMatch = content.match(/^\s*on:\s*\n((?:[ \t]+[^\n]+\n?)+)/m);
  if (mapMatch && new RegExp(`^[ \\t]+${name}:`, "m").test(mapMatch[1])) return true;
  return false;
}

function scanWorkflow(content, rel) {
  const hits = {
    "workflow-injection-sink": [],
    "pull-request-target-with-pr-checkout": [],
    "actions-floating-tag-pin": [],
    "secret-exposed-to-fork-pr": [],
  };

  const hasPRTarget = workflowHasTrigger(content, "pull_request_target");
  const hasIssueComment = workflowHasTrigger(content, "issue_comment");

  // pull-request-target-with-pr-checkout: PRT trigger + actions/
  // checkout referencing the PR's head sha or head_ref.
  if (hasPRTarget) {
    const checkoutPresent = /uses:\s*['"]?actions\/checkout@/.test(content);
    const refPRHead =
      /ref:\s*['"]?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/m.test(content) ||
      /ref:\s*['"]?\$\{\{\s*github\.head_ref\s*\}\}/m.test(content);
    if (checkoutPresent && refPRHead) {
      hits["pull-request-target-with-pr-checkout"].push({ file: rel, snippet: "pull_request_target trigger + checkout of PR head" });
    }
  }

  // workflow-injection-sink: ${{ github.event.<title|body|...> }}
  // interpolated directly inside a `run:` block. Conservative form:
  // file-wide presence of one of the dangerous expressions AND the
  // expression appears outside an `env:` mapping context that would
  // have made it safe.
  if (hasPRTarget || hasIssueComment || workflowHasTrigger(content, "pull_request")) {
    const dangerousExprs = [
      /\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.ref)\s*\}\}/,
      /\$\{\{\s*github\.event\.issue\.(?:title|body)\s*\}\}/,
      /\$\{\{\s*github\.event\.comment\.body\s*\}\}/,
      /\$\{\{\s*github\.event\.head_commit\.message\s*\}\}/,
      /\$\{\{\s*github\.event\.review\.body\s*\}\}/,
    ];
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Quick filter: dangerous expression on this line?
      const matchedExpr = dangerousExprs.find(re => re.test(line));
      if (!matchedExpr) continue;
      // If the dangerous expr is inside an `env:` mapping (key: value
      // shape on a YAML env block), the shell sees it as a variable
      // and it's not an injection sink. Walk back up to 3 lines to
      // find the nearest preceding YAML key indicator.
      const ctx = lines.slice(Math.max(0, i - 3), i + 1).join("\n");
      const isEnvBinding = /^\s+[A-Z_][A-Z0-9_]*:\s*['"]?\$\{\{\s*github\.event/m.test(ctx);
      // Detect `run:` proximity. The expression must land inside a
      // run-block; otherwise it's an `env:` binding or `with:` arg.
      const inRun = /^\s+run:/m.test(ctx) || /^\s+\|/m.test(ctx) || lines[i].trim().startsWith("- run:");
      if (inRun && !isEnvBinding) {
        hits["workflow-injection-sink"].push({ file: rel, line: i + 1, snippet: line.trim().slice(0, 160) });
        break;
      }
    }
  }

  // actions-floating-tag-pin: `uses: <owner>/<repo>@<ref>` where ref
  // isn't a 40-char hex SHA AND owner isn't `actions` (first-party
  // GitHub repos excluded by the playbook predicate). Excludes local
  // composite actions (`uses: ./`).
  const lines2 = content.split(/\r?\n/);
  for (let i = 0; i < lines2.length; i++) {
    const m = lines2[i].match(/^\s*-?\s*uses:\s*['"]?([^'"\s#]+)['"]?/);
    if (!m) continue;
    const refStr = m[1];
    if (refStr.startsWith("./") || refStr.startsWith("docker://")) continue;
    const atIdx = refStr.lastIndexOf("@");
    if (atIdx === -1) continue;
    const slash = refStr.indexOf("/");
    if (slash === -1) continue;
    const owner = refStr.slice(0, slash);
    if (owner === "actions") continue; // first-party
    const rev = refStr.slice(atIdx + 1);
    if (!/^[0-9a-f]{40}$/i.test(rev)) {
      hits["actions-floating-tag-pin"].push({ file: rel, line: i + 1, snippet: lines2[i].trim() });
    }
  }

  // secret-exposed-to-fork-pr: pull_request_target trigger + the
  // workflow references `secrets.X` for any X other than GITHUB_TOKEN.
  // Pull-request-from-forks (without target) requires runtime info
  // to detect fork status — left to operator evidence.
  if (hasPRTarget) {
    const secretsRefs = content.match(/\$\{\{\s*secrets\.([A-Z_][A-Z0-9_]*)\s*\}\}/g) || [];
    const nonDefault = secretsRefs.filter(r => !/secrets\.GITHUB_TOKEN/.test(r));
    if (nonDefault.length > 0) {
      hits["secret-exposed-to-fork-pr"].push({ file: rel, snippet: `pull_request_target + ${nonDefault.length} secrets.* reference(s)` });
    }
  }

  return hits;
}

function scanOidcPolicies(root) {
  // Walk infra/ + terraform/ + policies/ (depth 4) for *.json that
  // names token.actions.githubusercontent.com AND has a wildcarded
  // sub-claim. The playbook lists `repo:<org>/*:*`, `repo:*:*`, and
  // bare `*` as wildcard shapes.
  const rootDirs = ["infra", "terraform", "policies", ".aws", ".github"].map(d => path.join(root, d));
  const finds = [];
  function walk(dir, depth) {
    if (depth > 4 || finds.length > 5) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full, depth + 1); continue; }
      if (!e.isFile() || !/\.json$/i.test(e.name)) continue;
      const text = readSafe(full);
      if (!text) continue;
      if (!/token\.actions\.githubusercontent\.com/.test(text)) continue;
      // sub-claim wildcards. Cover the three shapes the playbook lists.
      const subWildcard =
        /"token\.actions\.githubusercontent\.com:sub"\s*:\s*"\*"/.test(text) ||
        /"token\.actions\.githubusercontent\.com:sub"\s*:\s*"repo:\*[^"]*"/.test(text) ||
        /"token\.actions\.githubusercontent\.com:sub"\s*:\s*"repo:[^"]*\/\*:[^"]*"/.test(text);
      if (subWildcard) finds.push({ file: path.relative(root, full).replace(/\\/g, "/"), snippet: "OIDC sub-claim wildcarded across repos or branches" });
    }
  }
  for (const rd of rootDirs) if (fs.existsSync(rd)) walk(rd, 0);
  return finds;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  // cwd-is-repo precondition: .git directory present. Outside a
  // repo we have no workflows / no OIDC trust JSON to walk.
  const cwdIsRepo = fs.existsSync(path.join(root, ".git"));
  if (!cwdIsRepo) {
    return {
      precondition_checks: { "cwd-is-repo": false },
      artifacts: {
        "workflow-yaml-inventory": { value: "skipped — cwd is not a git repository", captured: false, reason: "no .git directory at cwd" },
      },
      signal_overrides: {},
      collector_meta: {
        collector_id: COLLECTOR_ID,
        collector_version: "2026-05-21",
        platform: process.platform,
        captured_at: new Date().toISOString(),
        cwd: root,
        duration_ms: Date.now() - startTime,
      },
      collector_errors: errors,
    };
  }

  const workflows = walkWorkflows(root);
  const aggregateHits = {
    "workflow-injection-sink": [],
    "pull-request-target-with-pr-checkout": [],
    "actions-floating-tag-pin": [],
    "secret-exposed-to-fork-pr": [],
  };
  for (const w of workflows) {
    const h = scanWorkflow(w.content, w.rel);
    for (const [k, v] of Object.entries(h)) aggregateHits[k].push(...v);
  }

  const oidcWildcards = scanOidcPolicies(root);

  const signal_overrides = {
    "workflow-injection-sink": aggregateHits["workflow-injection-sink"].length > 0 ? "hit" : "miss",
    "pull-request-target-with-pr-checkout": aggregateHits["pull-request-target-with-pr-checkout"].length > 0 ? "hit" : "miss",
    "actions-floating-tag-pin": aggregateHits["actions-floating-tag-pin"].length > 0 ? "hit" : "miss",
    "secret-exposed-to-fork-pr": aggregateHits["secret-exposed-to-fork-pr"].length > 0 ? "hit" : "miss",
    "wildcarded-oidc-sub-claim": oidcWildcards.length > 0 ? "hit" : "miss",
  };

  const artifacts = {
    "workflow-yaml-inventory": {
      value: workflows.length ? workflows.map(w => w.rel).join(", ") : "no workflow files found at cwd",
      captured: true,
    },
    "oidc-trust-policy-inventory": {
      value: oidcWildcards.length
        ? `${oidcWildcards.length} wildcarded sub-claim(s): ${oidcWildcards.map(f => f.file).join(", ")}`
        : "no wildcarded OIDC sub-claim found in infra / terraform / policies",
      captured: true,
    },
    "actions-sha-pinning": {
      value: `${aggregateHits["actions-floating-tag-pin"].length} non-SHA third-party uses: reference(s) across ${workflows.length} workflow(s)`,
      captured: true,
    },
    "fork-pr-workflow-exposure": {
      value: `${aggregateHits["pull-request-target-with-pr-checkout"].length} workflow(s) check out PR head under pull_request_target`,
      captured: true,
    },
    "runner-secrets-inventory": {
      value: `${aggregateHits["secret-exposed-to-fork-pr"].length} workflow(s) reference non-default secrets under pull_request_target`,
      captured: true,
    },
    "self-hosted-runner-registrations": {
      value: "not captured by this collector — requires GitHub API (runners list)",
      captured: false,
      reason: "GH runners API access needed; deferred to operator evidence",
    },
    "signing-key-locations": {
      value: "not captured by this collector — requires HSM/KMS or runtime inspection",
      captured: false,
      reason: "HSM/KMS access needed; deferred to operator evidence",
    },
  };

  return {
    precondition_checks: { "cwd-is-repo": true },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-21",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
      workflows_scanned: workflows.length,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
