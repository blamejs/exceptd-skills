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
const { codeExcludeSet, isLinkedWorktreeDir, buildEvidenceLocations } = require("./scan-excludes");

// Shared code-scope name exclusions (dependency caches, build output, VCS +
// agent scratch). Threaded into the OIDC-policy descent so a trust JSON in a
// build-output dir (e.g. `dist/`) is not scanned — consistent with the other
// tree-walking collectors.
const OIDC_WALK_EXCLUDES = codeExcludeSet();

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

// `on:` trigger detection. Workflows declare triggers via four
// canonical YAML shapes:
//   - scalar:     `on: push`
//   - inline list: `on: [push, pull_request_target]`
//   - block list:  `on:\n  - push\n  - pull_request_target`
//   - mapping:     `on:\n  push:\n  pull_request_target:`
// Heuristic accepts all four.
function workflowHasTrigger(content, name) {
  if (new RegExp(`^\\s*on:\\s*['"]?${name}['"]?\\s*(?:#.*)?$`, "m").test(content)) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal (pull_request_target / issue_comment / pull_request), never operator/file input
  const listMatch = content.match(/^\s*on:\s*\[([^\]]*)\]/m);
  if (listMatch && new RegExp(`(?:^|,)\\s*['"]?${name}['"]?\\s*(?:,|$)`).test(listMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
  // block list AND mapping forms both follow `on:\n` with indented
  // continuation lines. Capture the block and inspect for either
  // `- <name>` (list) or `<name>:` (mapping) within it.
  const blockMatch = content.match(/^\s*on:\s*\n((?:[ \t]+[^\n]+\n?)+)/m);
  if (blockMatch) {
    if (new RegExp(`^[ \\t]+-\\s+['"]?${name}['"]?\\s*(?:#.*)?\\s*$`, "m").test(blockMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
    if (new RegExp(`^[ \\t]+${name}:`, "m").test(blockMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
  }
  return false;
}

// Find `actions/checkout` step blocks and return true when any one
// of them carries a `ref:` line referencing the PR head. Each step
// block is delimited by the next sibling `- ` at the same
// indentation (or de-indented line, meaning we've left steps[]).
// Binding the ref match to the checkout step prevents false hits
// when another unrelated step references the PR head while the
// actual checkout is safely fetching the base ref.
function checkoutBindsPrHead(content) {
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(\s*-\s+)uses:\s*['"]?actions\/checkout@/);
    if (!m) continue;
    const baseIndent = m[1].length;
    let blockEnd = lines.length;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j];
      if (line.trim() === "") continue;
      const indentM = line.match(/^(\s*)\S/);
      if (!indentM) continue;
      const indent = indentM[1].length;
      // Next sibling step starts with `-` at the same indent, or
      // any line de-indented past the step base ends the block.
      if (indent < baseIndent) { blockEnd = j; break; }
      if (indent === baseIndent && line.trim().startsWith("- ")) { blockEnd = j; break; }
    }
    const block = lines.slice(i, blockEnd).join("\n");
    if (/ref:\s*['"]?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/m.test(block) ||
        /ref:\s*['"]?\$\{\{\s*github\.head_ref\s*\}\}/m.test(block)) {
      return true;
    }
  }
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

  // pull-request-target-with-pr-checkout: PRT trigger AND the
  // PR-head ref reference is bound to an actions/checkout step
  // (not to an unrelated step that happens to read head_ref).
  if (hasPRTarget && checkoutBindsPrHead(content)) {
    hits["pull-request-target-with-pr-checkout"].push({ file: rel, snippet: "pull_request_target trigger + checkout of PR head" });
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
    // A real `uses:` line is never multiple KB. Skip overlong lines so a
    // crafted whitespace run can't drive regex backtracking.
    if (lines2[i].length > 4096) continue;
    // `^[ \t]*(?:-[ \t]*)?` anchors the indentation once, then an optional
    // `- ` list marker — no overlapping `\s*` runs that backtrack.
    const m = lines2[i].match(/^[ \t]*(?:-[ \t]*)?uses:\s*['"]?([^'"\s#]+)['"]?/);
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
    // Compare the captured secret NAME exactly to GITHUB_TOKEN. An unanchored
    // /secrets\.GITHUB_TOKEN/ substring test also matched custom secrets such
    // as GITHUB_TOKEN_PROD, silently treating them as the built-in token and
    // dropping a real fork-PR secret exposure (false negative).
    const nonDefault = [];
    for (const m of content.matchAll(/\$\{\{\s*secrets\.([A-Z_][A-Z0-9_]*)\s*\}\}/g)) {
      if (m[1] !== "GITHUB_TOKEN") nonDefault.push(m[0]);
    }
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
      if (OIDC_WALK_EXCLUDES.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        // Skip linked git worktrees (gitdir-pointer `.git` file), e.g.
        // agent-created repo copies under `.claude/worktrees/<id>/`
        // nested below a scanned policy/infra dir — rescanning them
        // double-counts the same OIDC trust documents.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
        continue;
      }
      if (!e.isFile() || !/\.json$/i.test(e.name)) continue;
      const text = readSafe(full);
      if (!text) continue;
      // Boundary-anchored so a label lookalike (`…githubusercontent.com.evil`,
      // `eviltoken.actions.…`) embedded in the JSON can't trip the pre-filter;
      // the issuer still matches in AWS oidc-provider ARN, claim-key, and bare
      // value forms.
      if (!/(?<![\w.-])token\.actions\.githubusercontent\.com(?![\w.-])/.test(text)) continue;
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
      precondition_checks: { "cwd-is-repo": false, "ci-config-readable": false, "operator-owns-ci-fleet": false },
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

  // Per-indicator file locations for every indicator flipped to "hit", so a
  // SARIF result points at the workflow YAML (or OIDC trust JSON) that
  // triggered it. Line-scanned indicators (workflow-injection-sink,
  // actions-floating-tag-pin) carry a real line; the trigger-shape and
  // OIDC-wildcard indicators record the file only and surface as file-level.
  const evidence_locations = {};
  const evidenceSources = { ...aggregateHits, "wildcarded-oidc-sub-claim": oidcWildcards };
  for (const [id, list] of Object.entries(evidenceSources)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(list);
      if (locs.length) evidence_locations[id] = locs;
    }
  }

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
    // Attest preconditions.
    //   ci-config-readable — the collector just walked workflow YAML
    //     + OIDC trust JSON; filesystem reads succeeded. Auto-true.
    //   operator-owns-ci-fleet — REQUIRES explicit operator opt-in via
    //     `--attest-ownership` (or args.attestOwnership === true). The
    //     playbook gates this `on_fail: halt`; running collect against
    //     any cwd (e.g. `--cwd /other/repo`) does NOT implicitly attest
    //     ownership of that fleet's CI authorization scope. Operators
    //     who own the CI fleet they're auditing pass the flag; running
    //     collect | run without the flag halts at the runner's
    //     preflight gate (as the playbook intends).
    precondition_checks: {
      "cwd-is-repo": true,
      "ci-config-readable": true,
      "operator-owns-ci-fleet": args.attestOwnership === true || args["attest-ownership"] === true,
    },
    artifacts,
    signal_overrides,
    ...(Object.keys(evidence_locations).length ? { evidence_locations } : {}),
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
