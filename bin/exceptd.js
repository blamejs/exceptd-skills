#!/usr/bin/env node
"use strict";
/**
 * bin/exceptd.js
 *
 * Single executable entry point for the published `@blamejs/exceptd-skills`
 * package. Routes subcommands to the right internal script so consumers
 * who installed via npm / npx don't need to know the on-disk layout.
 *
 * Subcommands (use `exceptd help` for the full list):
 *
 *   path                  Print absolute path to the installed package
 *                         (so AI assistants can be pointed at AGENTS.md
 *                         + skills/ + data/_indexes/).
 *   prefetch [args]       Warm a local cache of upstream artifacts.
 *   refresh  [args]       Cache-aware external-data refresh.
 *   build-indexes [args]  Rebuild data/_indexes/ derived files.
 *   scan                  Scan environment for findings.
 *   dispatch              Scan then route findings to skills.
 *   skill <name>          Show context for a specific skill.
 *   currency              Skill currency report.
 *   report [format]       Compliance / executive / technical report.
 *   validate-cves [args]  Cross-check CVE catalog against NVD/KEV/EPSS.
 *   validate-rfcs [args]  Cross-check RFC catalog against Datatracker.
 *   watchlist [args]      Forward-watch aggregator.
 *   verify                Verify every skill's Ed25519 signature.
 *
 * Seven-phase playbook contract (govern → direct → look → detect →
 * analyze → validate → close):
 *
 *   plan                  List playbooks + directives for session planning.
 *   govern <playbook>     Phase 1: load GRC context.
 *   direct <playbook>     Phase 2: scope the investigation.
 *   look <playbook>       Phase 3: emit artifact-collection spec for agent.
 *   run <playbook>        Phases 4-7 (detect/analyze/validate/close) from
 *                         agent submission JSON.
 *   ingest                Alias for `run` matching AGENTS.md terminology.
 *   reattest <session>    Re-run a prior session and diff evidence_hash.
 *
 *   help, --help, -h      This help.
 *   version, --version,
 *     -v                  Print the package version.
 *
 * All subcommand args after the subcommand name are forwarded verbatim
 * to the underlying script.
 *
 * The dispatcher resolves the internal package root at runtime, so
 * `npx @blamejs/exceptd-skills <cmd>` (which downloads + runs from a temp
 * dir) and a normal local `node bin/exceptd.js <cmd>` invocation behave
 * identically.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

// Package root = the directory containing this bin script's parent
// (e.g. <somewhere>/node_modules/@blamejs/exceptd-skills).
const PKG_ROOT = path.resolve(__dirname, "..");

// Subcommand → resolved script path. Lazy-resolved per call so a missing
// optional component (e.g. orchestrator/) just fails that one command
// instead of crashing dispatcher init.
const COMMANDS = {
  path:            null,                                                       // built-in
  version:         null,                                                       // built-in
  help:            null,                                                       // built-in
  "--version":     null,
  "-v":            null,
  "--help":        null,
  "-h":            null,
  prefetch:        () => path.join(PKG_ROOT, "lib", "prefetch.js"),
  refresh:         () => path.join(PKG_ROOT, "lib", "refresh-external.js"),
  "build-indexes": () => path.join(PKG_ROOT, "scripts", "build-indexes.js"),
  verify:          () => path.join(PKG_ROOT, "lib", "verify.js"),
  scan:            () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  dispatch:        () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  skill:           () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  currency:        () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  report:          () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  "validate-cves": () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  "validate-rfcs": () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  watchlist:       () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  "framework-gap": () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  "framework-gap-analysis": () => path.join(PKG_ROOT, "orchestrator", "index.js"),
  // Seven-phase playbook verbs — handled in-process via lib/playbook-runner.js.
  plan:     null,
  govern:   null,
  direct:   null,
  look:     null,
  run:      null,
  ingest:   null,
  reattest: null,
};

const ORCHESTRATOR_PASSTHROUGH = new Set([
  "scan", "dispatch", "skill", "currency", "report",
  "validate-cves", "validate-rfcs", "watchlist",
  "framework-gap", "framework-gap-analysis",
]);

// Seven-phase playbook verbs handled in-process (no subprocess dispatch).
const PLAYBOOK_VERBS = new Set([
  "plan", "govern", "direct", "look", "run", "ingest", "reattest", "list-attestations",
]);

function readPkgVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
}

function printHelp() {
  console.log(`exceptd — @blamejs/exceptd-skills v${readPkgVersion()}

Usage: exceptd <command> [args]
       npx @blamejs/exceptd-skills <command> [args]

Discovery:
  path                       Print absolute path to the installed package.
                             Point your AI assistant here:
                               $(exceptd path)/AGENTS.md
                               $(exceptd path)/data/_indexes/summary-cards.json

External data:
  prefetch [args]            Warm local cache of upstream artifacts
                             (KEV / NVD / EPSS / IETF / GitHub releases).
                             Try: exceptd prefetch --no-network --quiet
  refresh [args]             Refresh against cache + apply upserts.
                             Try: exceptd refresh --from-cache --swarm

Build / verify:
  build-indexes [args]       Regenerate data/_indexes/*.json.
                             Try: exceptd build-indexes --changed
  verify                     Verify every skill's Ed25519 signature.

Analyst:
  scan                       Scan environment for findings.
  dispatch                   Scan then route findings to skills.
  skill <name>               Show context for a specific skill.
  currency                   Skill currency report.
  report [format]            Compliance / executive / technical report.
  validate-cves [args]       Cross-check CVE catalog vs NVD/KEV/EPSS.
                             Add --from-cache to read from prefetch cache.
  validate-rfcs [args]       Cross-check RFC catalog vs IETF Datatracker.
  watchlist [args]           Forward-watch aggregator across skills.

Playbook runner — seven-phase contract
(govern → direct → look → detect → analyze → validate → close):
  plan [--playbook id]...    List playbooks + directives, grouped by scope.
                             [--scope system|code|service|cross-cutting|all]
                             [--flat] [--mode m] [--session-id id] [--pretty]
  govern <playbook>          Phase 1: GRC context (jurisdictions, theater,
                             framework gaps, skill_preload).
                             [--directive id] [--mode m] [--air-gap]
  direct <playbook>          Phase 2: scope (threat_context, rwep_threshold,
                             skill_chain, token_budget).
                             [--directive id]
  look <playbook>            Phase 3: artifact-collection spec the host AI
                             should execute.
                             [--directive id] [--air-gap]
  run [playbook]             Phases 4-7: detect → analyze → validate → close.
                             Three invocation modes:
                               run <playbook>           single playbook (explicit)
                               run --scope <type>       run all playbooks of that scope
                               run --all                run every playbook
                               run                      auto-detect from cwd:
                                                          .git/         → code
                                                          /proc + os-release → system
                             [--directive id] [--evidence file|-]
                             [--session-id id] [--session-key hex]
                             [--force-stale] [--air-gap]
  ingest                     Alias for 'run' matching AGENTS.md terminology.
                             [--domain id] [--directive id] [--evidence f|-]
  reattest <session-id>      Re-run prior attestation, diff evidence_hash,
                             report unchanged | drifted | resolved.

Output flags (playbook verbs): default JSON one-line; --pretty for indented.

Common:
  help                       This help.
  version                    Package version.

Examples:
  npx @blamejs/exceptd-skills path
  npx @blamejs/exceptd-skills prefetch
  npx @blamejs/exceptd-skills validate-cves --from-cache --no-fail
  npx @blamejs/exceptd-skills skill kernel-lpe-triage

Full documentation: ${PKG_ROOT}/README.md
Project rules:      ${PKG_ROOT}/AGENTS.md
`);
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    printHelp();
    process.exit(0);
  }
  const cmd = argv[0];
  const rest = argv.slice(1);

  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    process.exit(0);
  }
  if (cmd === "version" || cmd === "--version" || cmd === "-v") {
    process.stdout.write(readPkgVersion() + "\n");
    process.exit(0);
  }
  if (cmd === "path") {
    process.stdout.write(PKG_ROOT + "\n");
    process.exit(0);
  }

  // Seven-phase playbook verbs run in-process — they emit JSON to stdout
  // rather than dispatch to a script.
  if (PLAYBOOK_VERBS.has(cmd)) {
    dispatchPlaybook(cmd, rest);
    return;
  }

  const resolver = COMMANDS[cmd];
  if (typeof resolver !== "function") {
    process.stderr.write(`exceptd: unknown command "${cmd}". Run \`exceptd help\` for the list.\n`);
    process.exit(2);
  }

  const script = resolver();
  if (!fs.existsSync(script)) {
    process.stderr.write(`exceptd: command "${cmd}" not available — expected ${path.relative(PKG_ROOT, script)} in the installed package.\n`);
    process.exit(2);
  }

  // Orchestrator subcommands need the subcommand name preserved as argv[0]
  // for orchestrator/index.js's switch statement.
  const finalArgs = ORCHESTRATOR_PASSTHROUGH.has(cmd) ? [script, cmd, ...rest] : [script, ...rest];
  const res = spawnSync(process.execPath, finalArgs, { stdio: "inherit", cwd: PKG_ROOT });
  if (res.error) {
    process.stderr.write(`exceptd: failed to run ${cmd}: ${res.error.message}\n`);
    process.exit(2);
  }
  process.exit(typeof res.status === "number" ? res.status : 1);
}

// ---------------------------------------------------------------------------
// Seven-phase playbook dispatch (in-process)
// ---------------------------------------------------------------------------

/**
 * Tiny POSIX-ish argv parser. Recognised forms:
 *   --flag                       → boolean true
 *   --key value                  → string
 *   --key=value                  → string
 *   --repeatable v1 --repeatable v2 → array (when listed in `multi`)
 * Bare positional args land in `_`. Unknown flags fall through as booleans /
 * strings using the same rules so the harness stays forgiving for future
 * additions without forcing a schema bump here.
 */
function parseArgs(argv, opts) {
  const knownBool = new Set(opts.bool || []);
  const knownMulti = new Set(opts.multi || []);
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const key = (eq === -1 ? a.slice(2) : a.slice(2, eq));
      if (eq !== -1) {
        const val = a.slice(eq + 1);
        if (knownMulti.has(key)) { (out[key] = out[key] || []).push(val); }
        else out[key] = val;
        continue;
      }
      if (knownBool.has(key)) { out[key] = true; continue; }
      // Look ahead for a value; if next token is another flag, treat as bool.
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        out[key] = true;
      } else {
        if (knownMulti.has(key)) { (out[key] = out[key] || []).push(next); }
        else out[key] = next;
        i++;
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

function emit(obj, pretty) {
  const s = pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
  process.stdout.write(s + "\n");
}

function emitError(msg, extra, pretty) {
  const body = Object.assign({ ok: false, error: msg }, extra || {});
  const s = pretty ? JSON.stringify(body, null, 2) : JSON.stringify(body);
  process.stderr.write(s + "\n");
  process.exit(1);
}

function readEvidence(evidenceFlag) {
  if (!evidenceFlag) return {};
  if (evidenceFlag === "-") {
    const buf = fs.readFileSync(0, "utf8"); // stdin
    if (!buf.trim()) return {};
    return JSON.parse(buf);
  }
  return JSON.parse(fs.readFileSync(evidenceFlag, "utf8"));
}

function loadRunner() {
  return require(path.join(PKG_ROOT, "lib", "playbook-runner.js"));
}

function firstDirectiveId(runner, playbookId) {
  const pb = runner.loadPlaybook(playbookId);
  if (!pb.directives || !pb.directives.length) {
    throw new Error(`Playbook ${playbookId} has no directives.`);
  }
  return pb.directives[0].id;
}

function dispatchPlaybook(cmd, argv) {
  // Per-verb --help / -h before any positional-arg validation so users always
  // get usage text instead of an error about missing arguments.
  if (argv.includes("--help") || argv.includes("-h")) {
    printPlaybookVerbHelp(cmd);
    process.exit(0);
  }

  const args = parseArgs(argv, {
    bool:  ["pretty", "air-gap", "force-stale", "all", "flat", "directives", "ci", "latest", "diff-from-latest"],
    multi: ["playbook"],
  });
  const pretty = !!args.pretty;
  const runOpts = {
    airGap: !!args["air-gap"],
    forceStale: !!args["force-stale"],
  };
  if (args["session-id"]) runOpts.session_id = args["session-id"];
  if (args["session-key"]) runOpts.session_key = args["session-key"];
  if (args.mode) runOpts.mode = args.mode;

  let runner;
  try {
    runner = loadRunner();
  } catch (e) {
    emitError(`Failed to load lib/playbook-runner.js: ${e.message}`, null, pretty);
    return;
  }

  try {
    switch (cmd) {
      case "plan":     return cmdPlan(runner, args, runOpts, pretty);
      case "govern":   return cmdGovern(runner, args, runOpts, pretty);
      case "direct":   return cmdDirect(runner, args, pretty);
      case "look":     return cmdLook(runner, args, runOpts, pretty);
      case "run":      return cmdRun(runner, args, runOpts, pretty);
      case "ingest":   return cmdIngest(runner, args, runOpts, pretty);
      case "reattest": return cmdReattest(runner, args, runOpts, pretty);
      case "list-attestations": return cmdListAttestations(runner, args, runOpts, pretty);
    }
  } catch (e) {
    emitError(e.message, { verb: cmd }, pretty);
  }
}

function printPlaybookVerbHelp(verb) {
  const cmds = {
    plan: `plan — list playbooks + directives, grouped by scope.

Flags:
  --playbook <id> ...     Filter to one or more playbook IDs.
  --scope <type>          Filter by scope: system | code | service | cross-cutting | all
  --flat                  Disable grouped-by-scope output; emit flat list.
  --directives            Include directive id + title + applies_to per playbook.
  --session-id <id>       Reuse a specific session ID for the planning output.
  --mode <m>              Investigation mode forwarded into govern.
  --pretty                Indented JSON output.`,
    govern: `govern <playbook> — phase 1, load GRC context for a playbook.

Args / flags:
  <playbook>              Playbook ID. Required positional.
  --directive <id>        Specific directive (default: first one).
  --mode <m>              Investigation mode forwarded into govern policy.
  --air-gap               Honor _meta.air_gap_mode + air_gap_alternative paths.
  --pretty                Indented JSON output.

Output: jurisdiction_obligations, theater_fingerprints, framework_context, skill_preload.`,
    direct: `direct <playbook> — phase 2, threat context + skill chain + token budget.

Args / flags:
  <playbook>              Required positional.
  --directive <id>        Specific directive (default: first one).
  --pretty                Indented JSON output.`,
    look: `look <playbook> — phase 3, artifact-collection spec the host AI executes.

Args / flags:
  <playbook>              Required positional.
  --directive <id>        Specific directive (default: first one).
  --air-gap               Honor air_gap_alternative paths.
  --pretty                Indented JSON output.

Output includes a 'preconditions' array — the host AI MUST verify each
precondition with its own probes and declare results back in the submission as:
  { "precondition_checks": { "<id>": true | false } }
The runner refuses the run if a precondition with on_fail=halt is unverified.`,
    run: `run [playbook] — phases 4-7 (detect → analyze → validate → close).

Invocation modes:
  run <playbook>          Single playbook (explicit).
  run --scope <type>      Run all playbooks of that scope.
  run --all               Run every playbook.
  run                     Auto-detect from cwd:
                            .git/                  → code playbooks
                            /proc + os-release     → system playbooks
                          Always includes cross-cutting playbooks.

Flags:
  --directive <id>        Specific directive (default: first one per playbook).
  --evidence <file|->     Path to submission JSON or '-' for stdin.
                          Single-playbook shape:
                            { artifacts, signal_overrides, signals, precondition_checks }
                          Multi-playbook shape:
                            { "<playbook_id>": { artifacts, ... }, ... }
  --vex <file>            Load a CycloneDX or OpenVEX document. CVEs marked
                          not_affected | resolved | false_positive (CycloneDX)
                          or not_affected | fixed (OpenVEX) drop out of
                          analyze.matched_cves. The disposition is preserved
                          under analyze.vex.dropped_cves.
  --diff-from-latest      Compare evidence_hash against the most recent prior
                          attestation for the same playbook in
                          .exceptd/attestations/. Emits status: unchanged | drifted.
  --ci                    Machine-readable verdict for CI gates. Exits non-zero
                          (code 2) when phases.detect.classification === 'detected'
                          OR phases.analyze.rwep.adjusted >= rwep_threshold.escalate.
                          Logs PASS/FAIL reason to stderr.
  --session-id <id>       Reuse a specific session ID.
  --session-key <hex>     HMAC sign the evidence_package with this key.
  --force-stale           Override the threat_currency_score < 50 hard-block.
  --air-gap               Honor air_gap_alternative paths.
  --pretty                Indented JSON output.

Attestation is persisted to .exceptd/attestations/<session_id>/ on every
successful run (single: attestation.json; multi: <playbook_id>.json).`,
    ingest: `ingest — alias for 'run' matching AGENTS.md terminology.

Flags:
  --domain <id>           Playbook ID (overrides submission.playbook_id).
  --directive <id>        Directive ID (overrides submission.directive_id).
  --evidence <file|->     Submission JSON. May include playbook_id/directive_id.
  --pretty                Indented JSON output.`,
    reattest: `reattest [<session-id> | --latest] — replay a prior session and diff the evidence_hash.

Args / flags:
  <session-id>            Looks under .exceptd/attestations/<id>/attestation.json.
  --latest                Find the most-recent attestation automatically.
  --playbook <id>         Restrict --latest to a specific playbook.
  --since <ISO>           Restrict --latest to attestations after this ISO 8601 timestamp.
  --pretty                Indented JSON output.

Reports: unchanged | drifted | resolved from evidence_hash + classification deltas.`,
    "list-attestations": `list-attestations [--playbook <id>] — enumerate prior attestations.

Args / flags:
  --playbook <id>         Filter to one playbook.
  --pretty                Indented JSON output.

Lists every attestation under .exceptd/attestations/<session_id>/, sorted
newest-first, with truncated evidence_hash + capture timestamp + file path.`,
  };
  process.stdout.write((cmds[verb] || `${verb} — no per-verb help available; see \`exceptd help\` for the full list.`) + "\n");
}

function cmdPlan(runner, args, runOpts, pretty) {
  let playbookIds = args.playbook
    ? (Array.isArray(args.playbook) ? args.playbook : [args.playbook])
    : null;
  // --scope filters playbook list by _meta.scope.
  if (!playbookIds && args.scope) {
    playbookIds = filterPlaybooksByScope(runner, args.scope);
  }
  const plan = runner.plan({
    playbookIds: playbookIds || undefined,
    mode: runOpts.mode,
    session_id: runOpts.session_id,
  });
  // Default UX: group by scope unless --flat or a filter was applied.
  if (!args.flat && !playbookIds) {
    plan.grouped_by_scope = groupPlaybooksByScope(plan.playbooks);
    plan.scope_summary = Object.fromEntries(
      Object.entries(plan.grouped_by_scope).map(([s, list]) => [s, list.length])
    );
  }
  // --directives expands each playbook entry with its directive id + title +
  // applies_to so operators / AIs can pick a specific directive without
  // grepping playbook source.
  if (args.directives) {
    for (const pb of plan.playbooks) {
      const full = runner.loadPlaybook(pb.id);
      pb.directives = full.directives.map(d => ({ id: d.id, title: d.title, applies_to: d.applies_to }));
    }
  }
  emit(plan, pretty);
}

function filterPlaybooksByScope(runner, scope) {
  const ids = runner.listPlaybooks();
  return ids.filter(id => {
    try {
      const pb = runner.loadPlaybook(id);
      return scope === "all" || pb._meta.scope === scope;
    } catch { return false; }
  });
}

function groupPlaybooksByScope(playbooks) {
  const groups = {};
  for (const pb of playbooks) {
    const scope = pb.scope || pb._meta?.scope || "unscoped";
    (groups[scope] = groups[scope] || []).push(pb.id);
  }
  return groups;
}

/**
 * Auto-detect which scopes apply to the cwd. Returns an array of scope strings.
 * - `code`     when the cwd looks like a git repo
 * - `system`   when /proc + /etc/os-release exist (Linux host)
 * - `service`  always included as advisory — service investigations don't
 *              depend on cwd; the operator/AI decides whether to run them
 *
 * Returns at minimum `['cross-cutting']` so framework correlation can always
 * run after other findings land.
 */
function detectScopes() {
  const detected = [];
  if (fs.existsSync(path.join(process.cwd(), ".git"))) detected.push("code");
  if (fs.existsSync("/proc") && fs.existsSync("/etc/os-release")) detected.push("system");
  // service playbooks need explicit invocation — they have side effects
  // (probing remote endpoints) so we don't auto-include them.
  return detected.length ? detected : ["cross-cutting"];
}

function cmdGovern(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) return emitError("govern: missing <playbookId> positional argument.", null, pretty);
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return emitError(`govern: playbook ${playbookId} has no directives.`, null, pretty);
  emit(runner.govern(playbookId, directiveId, runOpts), pretty);
}

function cmdDirect(runner, args, pretty) {
  const playbookId = args._[0];
  if (!playbookId) return emitError("direct: missing <playbookId> positional argument.", null, pretty);
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return emitError(`direct: playbook ${playbookId} has no directives.`, null, pretty);
  emit(runner.direct(playbookId, directiveId), pretty);
}

function cmdLook(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) return emitError("look: missing <playbookId> positional argument.", null, pretty);
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return emitError(`look: playbook ${playbookId} has no directives.`, null, pretty);
  emit(runner.look(playbookId, directiveId, runOpts), pretty);
}

function cmdRun(runner, args, runOpts, pretty) {
  const positional = args._[0];

  // Multi-playbook dispatch path. Triggered by --all, --scope <type>, or by
  // a bare `exceptd run` (no positional, no flags) which auto-detects scopes
  // from the cwd.
  if (!positional && (args.all || args.scope)) {
    let ids;
    if (args.all) {
      ids = runner.listPlaybooks();
    } else {
      ids = filterPlaybooksByScope(runner, args.scope);
    }
    return cmdRunMulti(runner, ids, args, runOpts, pretty, { trigger: args.all ? "--all" : `--scope ${args.scope}` });
  }
  if (!positional && !args.all && !args.scope) {
    const scopes = detectScopes();
    const ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s));
    const unique = [...new Set(ids)];
    if (unique.length === 0) {
      return emitError("run: no playbook resolved. Pass <playbookId>, --scope <type>, or --all.", null, pretty);
    }
    return cmdRunMulti(runner, unique, args, runOpts, pretty, { trigger: "auto-detect", detected_scopes: scopes });
  }

  // Single-playbook path (existing behavior).
  const playbookId = positional;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return emitError(`run: playbook ${playbookId} has no directives.`, null, pretty);

  let submission = {};
  if (args.evidence) {
    try {
      submission = readEvidence(args.evidence);
    } catch (e) {
      return emitError(`run: failed to read evidence: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }

  // Lift precondition_checks out of the submission into runOpts so the agent
  // can declare host-platform / tool-availability facts in one JSON blob.
  if (submission.precondition_checks) {
    runOpts.precondition_checks = submission.precondition_checks;
  }

  // --vex <file>: load a CycloneDX/OpenVEX document and pass the not_affected
  // CVE ID set through to analyze() so matched_cves drops them.
  if (args.vex) {
    try {
      const vexDoc = JSON.parse(fs.readFileSync(args.vex, "utf8"));
      const vexSet = runner.vexFilterFromDoc(vexDoc);
      submission.signals = submission.signals || {};
      submission.signals.vex_filter = [...vexSet];
    } catch (e) {
      return emitError(`run: failed to load --vex ${args.vex}: ${e.message}`, null, pretty);
    }
  }

  const result = runner.run(playbookId, directiveId, submission, runOpts);

  // Persist attestation for reattest cycles when the run succeeded.
  if (result && result.ok && result.session_id) {
    try {
      const dir = path.join(process.cwd(), ".exceptd", "attestations", result.session_id);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, "attestation.json"),
        JSON.stringify({
          session_id: result.session_id,
          playbook_id: result.playbook_id,
          directive_id: result.directive_id,
          evidence_hash: result.evidence_hash,
          submission,
          run_opts: { airGap: runOpts.airGap, forceStale: runOpts.forceStale, mode: runOpts.mode },
          captured_at: new Date().toISOString(),
        }, null, 2)
      );
    } catch { /* non-fatal — attestation persistence is best-effort */ }
  }

  if (result && result.ok === false) {
    process.stderr.write((pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + "\n");
    process.exit(1);
  }

  // --diff-from-latest: compare evidence_hash against the most recent prior
  // attestation for this playbook. Drift mode for cron baselines.
  // We've already persisted the CURRENT attestation above, so the find must
  // skip our session_id to get the actual prior one.
  if (args["diff-from-latest"] && result && result.evidence_hash) {
    const prior = findLatestAttestation({ playbookId, excludeSessionId: result.session_id });
    if (prior) {
      const priorHash = prior.parsed.evidence_hash;
      result.diff_from_latest = {
        prior_session_id: prior.parsed.session_id,
        prior_captured_at: prior.parsed.captured_at,
        prior_evidence_hash: priorHash,
        new_evidence_hash: result.evidence_hash,
        status: priorHash === result.evidence_hash ? "unchanged" : "drifted",
      };
    } else {
      result.diff_from_latest = { status: "no_prior_attestation_for_playbook", playbook_id: playbookId };
    }
  }

  // --ci: machine-readable verdict for CI gates.
  //
  // The detect phase classification is the host-specific signal — "is THIS
  // environment exploitable for the catalogued CVEs". rwep.base is the
  // worst-known catalog score for the domain, which is roughly constant
  // regardless of the local environment; we don't fail CI on that alone or
  // every CI run against a domain with KEV-listed catalog entries would
  // perma-fail.
  //
  // Verdict:
  //   detected                → FAIL (exit 2)
  //   inconclusive + rwep ≥ escalate
  //                           → FAIL (the agent's evidence raised RWEP)
  //   not_detected            → PASS (exit 0)
  //   inconclusive + rwep < escalate
  //                           → PASS with WARN to stderr (visibility gap)
  if (args.ci && result && result.phases) {
    const classification = result.phases.detect && result.phases.detect.classification;
    const rwep = result.phases.analyze && result.phases.analyze.rwep;
    const threshold = rwep && rwep.threshold && rwep.threshold.escalate;
    const adjusted = rwep && typeof rwep.adjusted === "number" ? rwep.adjusted : 0;
    const escalate = typeof threshold === "number" && adjusted >= threshold;

    emit(result, pretty);

    if (classification === "detected") {
      process.stderr.write(`[exceptd run --ci] FAIL: classification=detected rwep=${adjusted} threshold=${threshold}\n`);
      process.exit(2);
    }
    if (classification === "inconclusive" && escalate) {
      process.stderr.write(`[exceptd run --ci] FAIL: classification=inconclusive AND rwep=${adjusted} >= threshold=${threshold}\n`);
      process.exit(2);
    }
    if (classification === "inconclusive") {
      process.stderr.write(`[exceptd run --ci] PASS+WARN: classification=inconclusive rwep=${adjusted} < threshold=${threshold} (visibility gap)\n`);
    } else {
      process.stderr.write(`[exceptd run --ci] PASS: classification=${classification} rwep=${adjusted}\n`);
    }
    return;
  }

  emit(result, pretty);
}

/**
 * Multi-playbook run. Iterates `ids` (already filtered by scope or auto-detect),
 * runs each through runner.run with a shared session_id, persists each
 * attestation under .exceptd/attestations/<session_id>/<playbook_id>.json, and
 * emits a single aggregate bundle. Refuses if no evidence is provided (the
 * host AI MUST submit observations per playbook — the engine can't synthesize them).
 *
 * Evidence shape for multi-run: { <playbook_id>: { artifacts, signal_overrides, signals, precondition_checks } }
 * Falls back to running every playbook with empty evidence (engine returns
 * inconclusive findings + visibility gaps) when no --evidence is given.
 */
function cmdRunMulti(runner, ids, args, runOpts, pretty, meta) {
  const sessionId = runOpts.session_id || require("crypto").randomBytes(8).toString("hex");
  runOpts.session_id = sessionId;

  let bundle = {};
  if (args.evidence) {
    try { bundle = readEvidence(args.evidence); } catch (e) {
      return emitError(`run: failed to read evidence bundle: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }

  const results = [];
  for (const id of ids) {
    const pb = runner.loadPlaybook(id);
    const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
    if (!directiveId) {
      results.push({ playbook_id: id, ok: false, error: "no directives" });
      continue;
    }
    const submission = bundle[id] || {};
    const perRunOpts = { ...runOpts };
    if (submission.precondition_checks) perRunOpts.precondition_checks = submission.precondition_checks;

    const result = runner.run(id, directiveId, submission, perRunOpts);

    // Persist per-playbook attestation under the shared session.
    if (result && result.ok) {
      try {
        const dir = path.join(process.cwd(), ".exceptd", "attestations", sessionId);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(
          path.join(dir, `${id}.json`),
          JSON.stringify({
            session_id: sessionId,
            playbook_id: id,
            directive_id: directiveId,
            evidence_hash: result.evidence_hash,
            submission,
            run_opts: { airGap: perRunOpts.airGap, forceStale: perRunOpts.forceStale, mode: perRunOpts.mode },
            captured_at: new Date().toISOString(),
          }, null, 2)
        );
      } catch { /* non-fatal */ }
    }
    results.push(result);
  }

  emit({
    ok: results.every(r => r.ok !== false),
    session_id: sessionId,
    trigger: meta.trigger,
    detected_scopes: meta.detected_scopes || null,
    playbooks_run: ids,
    summary: {
      total: results.length,
      succeeded: results.filter(r => r.ok !== false).length,
      blocked: results.filter(r => r.ok === false).length,
      detected: results.filter(r => r.phases?.detect?.classification === "detected").length,
      inconclusive: results.filter(r => r.phases?.detect?.classification === "inconclusive").length,
    },
    results,
  }, pretty);
}

function cmdIngest(runner, args, runOpts, pretty) {
  // `ingest` matches the AGENTS.md ingest contract. The submission JSON may
  // carry playbook_id + directive_id; --domain/--directive flags override.
  let submission = {};
  if (args.evidence) {
    try {
      submission = readEvidence(args.evidence);
    } catch (e) {
      return emitError(`ingest: failed to read evidence: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }
  const playbookId = args.domain || submission.playbook_id || submission.domain;
  if (!playbookId) return emitError("ingest: no playbook resolved — pass --domain <id> or include playbook_id in evidence JSON.", null, pretty);
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive
    || submission.directive_id
    || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return emitError(`ingest: playbook ${playbookId} has no directives.`, null, pretty);

  // Strip the routing keys so the runner only sees the contract shape it expects.
  const cleanedSubmission = {
    artifacts: submission.artifacts || {},
    signal_overrides: submission.signal_overrides || {},
    signals: submission.signals || {},
  };

  if (submission.precondition_checks) {
    runOpts.precondition_checks = submission.precondition_checks;
  }

  const result = runner.run(playbookId, directiveId, cleanedSubmission, runOpts);

  if (result && result.ok && result.session_id) {
    try {
      const dir = path.join(process.cwd(), ".exceptd", "attestations", result.session_id);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, "attestation.json"),
        JSON.stringify({
          session_id: result.session_id,
          playbook_id: result.playbook_id,
          directive_id: result.directive_id,
          evidence_hash: result.evidence_hash,
          submission: cleanedSubmission,
          run_opts: { airGap: runOpts.airGap, forceStale: runOpts.forceStale, mode: runOpts.mode },
          captured_at: new Date().toISOString(),
        }, null, 2)
      );
    } catch { /* non-fatal */ }
  }

  if (result && result.ok === false) {
    process.stderr.write((pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + "\n");
    process.exit(1);
  }
  emit(result, pretty);
}

/**
 * Find the latest attestation file under .exceptd/attestations/.
 * Filters: optional playbook ID and optional "since" ISO timestamp.
 * Returns { sessionId, playbookId, file, parsed } or null.
 */
function findLatestAttestation(opts = {}) {
  const root = path.join(process.cwd(), ".exceptd", "attestations");
  if (!fs.existsSync(root)) return null;
  const sessions = fs.readdirSync(root, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);
  const candidates = [];
  for (const sid of sessions) {
    const sdir = path.join(root, sid);
    for (const f of fs.readdirSync(sdir).filter(x => x.endsWith(".json"))) {
      try {
        const p = path.join(sdir, f);
        const j = JSON.parse(fs.readFileSync(p, "utf8"));
        if (opts.playbookId && j.playbook_id !== opts.playbookId) continue;
        if (opts.since && (j.captured_at || "") < opts.since) continue;
        if (opts.excludeSessionId && sid === opts.excludeSessionId) continue;
        candidates.push({ sessionId: sid, playbookId: j.playbook_id, file: p, parsed: j });
      } catch { /* skip malformed */ }
    }
  }
  candidates.sort((a, b) => (b.parsed.captured_at || "").localeCompare(a.parsed.captured_at || ""));
  return candidates[0] || null;
}

function cmdReattest(runner, args, runOpts, pretty) {
  // --latest [--playbook <id>] [--since <ISO>] — find prior attestation
  // without requiring the operator to know the session-id.
  let sessionId = args._[0];
  let attFile = null;
  if (!sessionId && args.latest) {
    const found = findLatestAttestation({
      playbookId: args.playbook ? (Array.isArray(args.playbook) ? args.playbook[0] : args.playbook) : null,
      since: args.since || null,
    });
    if (!found) return emitError("reattest: --latest found no matching attestations.", { filter: { playbook: args.playbook || null, since: args.since || null } }, pretty);
    sessionId = found.sessionId;
    attFile = found.file;
  }
  if (!sessionId) return emitError("reattest: missing <session-id>. Pass a session-id or --latest [--playbook <id>] [--since <ISO>].", null, pretty);
  const dir = path.join(process.cwd(), ".exceptd", "attestations", sessionId);
  if (!attFile) attFile = path.join(dir, "attestation.json");
  if (!fs.existsSync(attFile)) {
    return emitError(`reattest: no attestation found at ${path.relative(process.cwd(), attFile)}`, { session_id: sessionId }, pretty);
  }
  let prior;
  try {
    prior = JSON.parse(fs.readFileSync(attFile, "utf8"));
  } catch (e) {
    return emitError(`reattest: failed to parse prior attestation: ${e.message}`, { session_id: sessionId }, pretty);
  }

  // Re-run with an empty submission against the same playbook/directive.
  // Preserve only precondition_checks from the prior submission so the runner
  // doesn't halt on host-environment guards (the reattest is about evidence
  // drift, not re-verifying that the host is still Linux etc.).
  const emptySubmission = { artifacts: {}, signal_overrides: {}, signals: {} };
  const replayOpts = Object.assign({}, runOpts, {
    airGap: !!(prior.run_opts && prior.run_opts.airGap) || runOpts.airGap,
    forceStale: true, // bypass currency block on reattest — drift comparison is the point
  });
  if (prior.submission && prior.submission.precondition_checks) {
    replayOpts.precondition_checks = prior.submission.precondition_checks;
  } else {
    // Fallback: synthesise pass-through preconditions from the playbook so the
    // replay isn't blocked when the operator didn't originally pass them.
    try {
      const pb = runner.loadPlaybook(prior.playbook_id);
      const synth = {};
      for (const pc of (pb._meta && pb._meta.preconditions) || []) synth[pc.id] = true;
      replayOpts.precondition_checks = synth;
    } catch { /* ignore */ }
  }
  const replay = runner.run(prior.playbook_id, prior.directive_id, emptySubmission, replayOpts);

  if (!replay || replay.ok === false) {
    return emitError(`reattest: replay failed: ${replay && replay.reason || "unknown"}`, { replay }, pretty);
  }

  const priorHash = prior.evidence_hash;
  const newHash = replay.evidence_hash;
  let status;
  if (priorHash === newHash) {
    status = "unchanged";
  } else {
    // If the original was a detected finding and the replay no longer detects,
    // call it "resolved"; otherwise "drifted".
    const priorClassification = (prior.submission && prior.submission.signals
      && prior.submission.signals.detection_classification) || null;
    const newClassification = replay.phases && replay.phases.detect && replay.phases.detect.classification;
    if (priorClassification === "detected" && newClassification !== "detected") {
      status = "resolved";
    } else {
      status = "drifted";
    }
  }

  emit({
    ok: true,
    verb: "reattest",
    session_id: sessionId,
    playbook_id: prior.playbook_id,
    directive_id: prior.directive_id,
    status,
    prior_evidence_hash: priorHash,
    replay_evidence_hash: newHash,
    prior_captured_at: prior.captured_at,
    replayed_at: new Date().toISOString(),
    replay_classification: replay.phases && replay.phases.detect && replay.phases.detect.classification,
    replay_rwep_adjusted: replay.phases && replay.phases.analyze && replay.phases.analyze.rwep && replay.phases.analyze.rwep.adjusted,
  }, pretty);
}

function cmdListAttestations(runner, args, runOpts, pretty) {
  const root = path.join(process.cwd(), ".exceptd", "attestations");
  if (!fs.existsSync(root)) {
    return emit({ ok: true, attestations: [], note: `No attestations directory at ${path.relative(process.cwd(), root)}` }, pretty);
  }
  const sessions = fs.readdirSync(root, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);

  const entries = [];
  for (const sid of sessions) {
    const sdir = path.join(root, sid);
    const files = fs.readdirSync(sdir).filter(f => f.endsWith(".json"));
    for (const f of files) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(sdir, f), "utf8"));
        // Apply --playbook filter if supplied.
        if (args.playbook && j.playbook_id !== args.playbook) continue;
        entries.push({
          session_id: sid,
          playbook_id: j.playbook_id,
          directive_id: j.directive_id,
          evidence_hash: j.evidence_hash ? j.evidence_hash.slice(0, 16) + "..." : null,
          captured_at: j.captured_at || null,
          file: path.relative(process.cwd(), path.join(sdir, f)),
        });
      } catch { /* skip malformed */ }
    }
  }
  entries.sort((a, b) => (b.captured_at || "").localeCompare(a.captured_at || ""));
  emit({
    ok: true,
    attestations: entries,
    count: entries.length,
    filter: { playbook: args.playbook || null },
  }, pretty);
}

if (require.main === module) main();

module.exports = { COMMANDS, PKG_ROOT, PLAYBOOK_VERBS };
