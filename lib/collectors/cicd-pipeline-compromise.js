"use strict";

/**
 * Companion collector for the `cicd-pipeline-compromise` playbook: walks CI
 * workflow YAML and the infra / terraform / policies dirs for OIDC trust JSON.
 * `self-hosted-runner-non-ephemeral` and `runner-scoped-signing-key` are left
 * unflipped (GitHub runners API / HSM inspection), so they report inconclusive.
 * Interface: lib/collectors/README.md.
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, isLinkedWorktreeDir, buildEvidenceLocations } = require("./scan-excludes");

// Shared code-scope exclusions, so a trust JSON under `dist/` is not scanned.
const OIDC_WALK_EXCLUDES = codeExcludeSet();

const COLLECTOR_ID = "cicd-pipeline-compromise";

function readSafe(p, max = 512 * 1024) {
  let fd;
  try {
    fd = fs.openSync(p, "r");
    const s = fs.fstatSync(fd);
    if (s.size > max) return null;
    // readFileSync(fd) loops read() to EOF; a single readSync can return short on
    // a network or FUSE fd. Reading the open fd keeps fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
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

// Trigger detection across the four canonical `on:` shapes: scalar
// (`on: push`), inline list, block list, and mapping.
function workflowHasTrigger(content, name) {
  if (new RegExp(`^\\s*on:\\s*['"]?${name}['"]?\\s*(?:#.*)?$`, "m").test(content)) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal (pull_request_target / issue_comment / pull_request), never operator/file input
  const listMatch = content.match(/^\s*on:\s*\[([^\]]*)\]/m);
  if (listMatch && new RegExp(`(?:^|,)\\s*['"]?${name}['"]?\\s*(?:,|$)`).test(listMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
  // Block-list and mapping forms both follow `on:\n` with indented continuations.
  const blockMatch = content.match(/^\s*on:\s*\n((?:[ \t]+[^\n]+\n?)+)/m);
  if (blockMatch) {
    if (new RegExp(`^[ \\t]+-\\s+['"]?${name}['"]?\\s*(?:#.*)?\\s*$`, "m").test(blockMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
    if (new RegExp(`^[ \\t]+${name}:`, "m").test(blockMatch[1])) return true; // allow:dynamic-regex — `name` is a hardcoded trigger literal, never operator/file input
  }
  return false;
}

// True when an `actions/checkout` step block carries a `ref:` naming the PR head.
// Binding the ref to the checkout step keeps an unrelated step's reference to the
// PR head from reading as a hit while the checkout fetches the base ref.
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
      // The block ends at a sibling `-` on the same indent, or any de-indent.
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

  if (hasPRTarget && checkoutBindsPrHead(content)) {
    hits["pull-request-target-with-pr-checkout"].push({ file: rel, snippet: "pull_request_target trigger + checkout of PR head" });
  }

  // workflow-injection-sink: an attacker-controlled `${{ github.event.* }}`
  // interpolated inside a `run:` block, outside a safe `env:` mapping.
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
      const matchedExpr = dangerousExprs.find(re => re.test(line));
      if (!matchedExpr) continue;
      // Inside an `env:` mapping the shell sees a variable, not a sink.
      const ctx = lines.slice(Math.max(0, i - 3), i + 1).join("\n");
      const isEnvBinding = /^\s+[A-Z_][A-Z0-9_]*:\s*['"]?\$\{\{\s*github\.event/m.test(ctx);
      // The expression counts only inside a run-block.
      const inRun = /^\s+run:/m.test(ctx) || /^\s+\|/m.test(ctx) || lines[i].trim().startsWith("- run:");
      if (inRun && !isEnvBinding) {
        hits["workflow-injection-sink"].push({ file: rel, line: i + 1, snippet: line.trim().slice(0, 160) });
        break;
      }
    }
  }

  // actions-floating-tag-pin: `uses: <owner>/<repo>@<ref>` where ref is not a
  // 40-char hex SHA; owner `actions` and local composite actions are excluded.
  const lines2 = content.split(/\r?\n/);
  for (let i = 0; i < lines2.length; i++) {
    // A real `uses:` line is never multiple KB; skipping overlong ones keeps a
    // crafted whitespace run from driving regex backtracking.
    if (lines2[i].length > 4096) continue;
    // Indentation is anchored once, then an optional `- ` — no overlapping `\s*`.
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

  // secret-exposed-to-fork-pr: a pull_request_target trigger plus a `secrets.X`
  // reference for any X other than GITHUB_TOKEN. A plain pull_request from a fork
  // needs runtime fork status, so it stays operator evidence.
  if (hasPRTarget) {
    // The captured secret NAME is compared exactly: an unanchored
    // /secrets\.GITHUB_TOKEN/ also matches a custom GITHUB_TOKEN_PROD.
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
  // Walks the infra dirs to depth 4 for *.json naming
  // token.actions.githubusercontent.com with a wildcarded sub-claim.
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
        // A linked worktree holds the same trust documents; rescanning double-counts.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
        continue;
      }
      if (!e.isFile() || !/\.json$/i.test(e.name)) continue;
      const text = readSafe(full);
      if (!text) continue;
      // Each pattern is bound to the leading `"` of the JSON key, so a lookalike
      // issuer like `"eviltoken.actions…"` cannot match.
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

  // Outside a repo there are no workflows and no OIDC trust JSON to walk.
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

  // File locations for every indicator flipped to "hit", so a SARIF result points
  // at the YAML or trust JSON behind it; without a line it surfaces as file-level.
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
    // operator-owns-ci-fleet requires explicit opt-in through `--attest-ownership`:
    // pointing collect at any cwd does NOT attest ownership of that fleet's CI
    // authorization scope, and the playbook gates the precondition `on_fail: halt`.
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
