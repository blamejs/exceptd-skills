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
  watch:           () => path.join(PKG_ROOT, "orchestrator", "index.js"),
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
  "validate-cves", "validate-rfcs", "watchlist", "watch",
  "framework-gap", "framework-gap-analysis",
]);

// Seven-phase playbook verbs handled in-process (no subprocess dispatch).
// v0.11.0 introduces: brief (collapses plan/govern/direct/look), discover (scan + dispatch),
// doctor (currency + verify + validate-cves + validate-rfcs), ci (CI gate),
// ai-run (streaming JSONL), ask (plain-English routing).
const PLAYBOOK_VERBS = new Set([
  // v0.11.0 canonical surface:
  "brief", "run", "ai-run", "attest", "discover", "doctor", "ci", "ask",
  "verify-attestation", "run-all", "lint",
  // v0.10.x legacy verbs — kept as aliases with deprecation banner, removed in v0.12+:
  "plan", "govern", "direct", "look", "ingest", "reattest", "list-attestations",
]);

// Map legacy verb names to their v0.11.0 replacement so the dispatcher can
// emit a single deprecation banner per session.
const LEGACY_VERB_REPLACEMENTS = {
  plan: "brief --all",
  govern: "brief <pb> --phase govern",
  direct: "brief <pb> --phase direct",
  look: "brief <pb> --phase look",
  ingest: "run",
  reattest: "attest diff",
  "list-attestations": "attest list",
  scan: "discover --scan-only",
  dispatch: "discover",
  currency: "doctor --currency",
  verify: "doctor --signatures",
  "validate-cves": "doctor --cves",
  "validate-rfcs": "doctor --rfcs",
  watchlist: "watch",
  prefetch: "refresh --no-network",
  "build-indexes": "refresh --indexes-only",
};

function readPkgVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
}

function printWelcome() {
  // v0.11.0 redesign #4 — first-run experience. `exceptd` with no args used to
  // print full help (a wall of text). Now it shows two ways in and where to
  // go from there.
  console.log(`exceptd — @blamejs/exceptd-skills v${readPkgVersion()}

Welcome. Two ways to start:

  exceptd discover           # scan this directory + recommend playbooks
  exceptd ask "<question>"   # plain-English routing to a playbook

If you know what you want:

  exceptd brief <playbook>   # what does this playbook check?
  exceptd run <playbook>     # run it
  exceptd ci --scope code    # CI gate against every code-scoped playbook

Common starting playbooks
  code repos:    secrets, sbom, library-author, crypto-codebase
  Linux hosts:   kernel, hardening, runtime, cred-stores
  AI / service:  ai-api, mcp, crypto

Full reference: exceptd help
Per-verb help:  exceptd <verb> --help
`);
}

function printHelp() {
  console.log(`exceptd — @blamejs/exceptd-skills v${readPkgVersion()}

Usage: exceptd <command> [args]
       npx @blamejs/exceptd-skills <command> [args]

v0.11.0 canonical surface
─────────────────────────

  brief [playbook]           Unified info doc — jurisdictions + threat context
                             + preconditions + artifacts + indicators. Replaces
                             plan + govern + direct + look.
                             --all                  every playbook
                             --scope <type>         system | code | service | cross-cutting
                             --directives           expand directive metadata
                             --phase <name>         emit only one phase (legacy compat)

  run [playbook]             Phases 4-7. Auto-detects cwd context when no
                             playbook positional.
                             --scope <type> | --all | run-all (alias)
                             --evidence <file|->    flat or nested submission
                             --evidence-dir <dir>   per-playbook submission files
                             --vex <file>           CycloneDX / OpenVEX filter
                             --format <fmt> ...     csaf-2.0 | sarif | openvex | markdown | summary
                             --diff-from-latest     drift vs prior attestation
                             --ci                   exit-code gate (use \`exceptd ci\` instead)
                             --operator <name>      bind attestation to identity
                             --ack                  explicit jurisdiction-consent
                             --session-id <id>      reuse session id (collision refused)
                             --force-overwrite      override session collision refusal
                             --session-key <hex>    HMAC sign evidence_package
                             --force-stale          override threat_currency_score<50 gate
                             --air-gap              honor air_gap_alternative paths

  ai-run <playbook>          JSONL streaming variant of run. AI emits events
                             back on stdin; runner streams phase events on stdout.
                             --no-stream            single-shot mode

  attest <subverb> <sid>     Auditor-facing operations:
                             attest show          full attestation
                             attest list          inventory all sessions
                             attest export        redacted bundle (--format csaf)
                             attest verify        Ed25519 signature check
                             attest diff          drift vs prior or --against <other-sid>

  discover                   Scan cwd → recommend playbooks. Replaces scan + dispatch.

  doctor                     Health check: signatures + currency + cve catalog
                             + rfc catalog + attestation-signing status.
                             --signatures | --currency | --cves | --rfcs

  ci                         One-shot CI gate. Exits 2 on detected or rwep≥escalate.
                             --all | --scope <type> | (auto-detect)
                             --max-rwep <n>         cap below playbook default
                             --block-on-jurisdiction-clock
                             --evidence-dir <dir>

  ask "<question>"           Plain-English routing to playbook(s).

  lint <pb> <evidence>       Pre-flight check submission shape vs playbook
                             (preconditions / artifacts / indicators) without
                             executing phases 4-7.

  verify-attestation <sid>   Alias for \`attest verify\`.
  run-all                    Alias for \`run --all\`.

  skill <name>               Show context for a specific skill.
  framework-gap <fw> <ref>   Programmatic gap analysis (one framework, one CVE/scenario).
  path                       Absolute path to the installed package.
  version                    Package version.

  refresh [args]             Refresh upstream catalogs + indexes. Replaces
                             prefetch + refresh + build-indexes.

v0.10.x compatibility (will be removed in v0.12)
────────────────────────────────────────────────

These verbs still work but emit a one-time deprecation banner. The
[DEPRECATED] prefix is included so \`exceptd help | grep '^  [a-z]'\`
doesn't surface them in the active-verbs list. Migrate to v0.11:

  [DEPRECATED] plan              → brief --all
  [DEPRECATED] govern <pb>       → brief <pb> --phase govern
  [DEPRECATED] direct <pb>       → brief <pb> --phase direct
  [DEPRECATED] look <pb>         → brief <pb> --phase look
  [DEPRECATED] ingest            → run
  [DEPRECATED] reattest <sid>    → attest diff <sid>
  [DEPRECATED] list-attestations → attest list
  [DEPRECATED] scan              → discover --scan-only
  [DEPRECATED] dispatch          → discover
  [DEPRECATED] currency          → doctor --currency
  [DEPRECATED] verify            → doctor --signatures
  [DEPRECATED] validate-cves     → doctor --cves
  [DEPRECATED] validate-rfcs     → doctor --rfcs
  [DEPRECATED] watchlist         → watch
  [DEPRECATED] prefetch          → refresh --no-network
  [DEPRECATED] build-indexes     → refresh --indexes-only

Output: default human-readable (v0.11.0). --json for machine output.
        --pretty for indented JSON.

Examples:
  exceptd discover                                  # what's in this dir?
  exceptd brief secrets --pretty                    # what does secrets check?
  exceptd run secrets --evidence ev.json --ci       # run + CI gate
  exceptd attest list --playbook secrets            # prior attestations
  exceptd attest verify <session-id>                # tamper check
  exceptd ci --scope code --max-rwep 70             # gate every code playbook
  exceptd ask "I think someone replaced npm packages"   # natural-language route

Full documentation: ${PKG_ROOT}/README.md
Project rules:      ${PKG_ROOT}/AGENTS.md
`);
}

function main() {
  const argv = process.argv.slice(2);

  // --json-stdout-only: silence ALL stderr emissions (deprecation banners,
  // unsigned-attestation warnings, hook output). Operators piping the JSON
  // result through `jq` or scripting around exit codes want clean stdout
  // exclusively. Handled here at top of main so the deprecation banner +
  // unsigned warning are suppressed before they fire.
  if (argv.includes("--json-stdout-only")) {
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, encoding, cb) => {
      // Let actual error frames through (uncaught exceptions need to surface
      // for debugging); suppress framework stderr.
      if (typeof chunk === "string" && chunk.startsWith("Error")) return origStderrWrite(chunk, encoding, cb);
      if (typeof cb === "function") cb();
      return true;
    };
  }

  if (argv.length === 0) {
    printWelcome();
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
    // One-time deprecation banner per process when a legacy verb is invoked.
    if (LEGACY_VERB_REPLACEMENTS[cmd] && !process.env.EXCEPTD_DEPRECATION_SHOWN) {
      // Mention the installed version explicitly so an operator on v0.10.x
      // who reads "Prefer brief..." doesn't go looking for a verb that
      // doesn't exist in their install. v0.11.0+ has the replacement; v0.10.x
      // users see this with the explicit "upgrade to v0.11.0 first" note.
      const ver = readPkgVersion();
      const haveBrief = ver !== "unknown" && ver.match(/^(\d+)\.(\d+)/) && (parseInt(RegExp.$1, 10) > 0 || parseInt(RegExp.$2, 10) >= 11);
      process.stderr.write(
        `[exceptd] DEPRECATION: \`${cmd}\` is a v0.10.x verb. ` +
        (haveBrief
          ? `Prefer \`${LEGACY_VERB_REPLACEMENTS[cmd]}\` (available in this install, v${ver}). `
          : `Upgrade to v0.11.0+ then use \`${LEGACY_VERB_REPLACEMENTS[cmd]}\` (currently installed: v${ver}). `) +
        `Legacy verbs remain functional through this release; they will be removed in v0.12. ` +
        `Suppress: export EXCEPTD_DEPRECATION_SHOWN=1.\n`
      );
      process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    }
    dispatchPlaybook(cmd, rest);
    return;
  }

  // v0.11.2 bug #65: `refresh --no-network` / `refresh --indexes-only` were
  // documented as the v0.11.0 replacements for `prefetch` / `build-indexes`
  // but the underlying refresh script doesn't know those flags. Translate
  // here so the deprecation pointer actually works.
  let effectiveCmd = cmd;
  let effectiveRest = rest;
  if (cmd === "refresh" && rest.includes("--no-network")) {
    effectiveCmd = "prefetch";
    effectiveRest = rest.filter(a => a !== "--no-network");
  } else if (cmd === "refresh" && rest.includes("--indexes-only")) {
    effectiveCmd = "build-indexes";
    effectiveRest = rest.filter(a => a !== "--indexes-only");
  }

  const resolver = COMMANDS[effectiveCmd];
  if (typeof resolver !== "function") {
    // Emit a structured JSON error matching the seven-phase verbs so operators
    // piping through `jq` get one consistent shape across the CLI surface.
    // Plain-text "unknown command" still reaches stderr for human readers.
    const err = { ok: false, error: `unknown command "${cmd}"`, hint: "Run `exceptd help` for the list of verbs.", verb: cmd };
    process.stderr.write(JSON.stringify(err) + "\n");
    process.exit(2);
  }

  const script = resolver();
  if (!fs.existsSync(script)) {
    process.stderr.write(`exceptd: command "${cmd}" not available — expected ${path.relative(PKG_ROOT, script)} in the installed package.\n`);
    process.exit(2);
  }

  // Orchestrator subcommands need the subcommand name preserved as argv[0]
  // for orchestrator/index.js's switch statement.
  const finalArgs = ORCHESTRATOR_PASSTHROUGH.has(effectiveCmd) ? [script, effectiveCmd, ...effectiveRest] : [script, ...effectiveRest];
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

function emit(obj, pretty, humanRenderer) {
  // v0.11.9 (#99): default to HUMAN-readable unconditionally when a renderer
  // is provided. Pre-0.11.9 the default depended on process.stdout.isTTY,
  // which is false under most automation harnesses (Claude Code's Bash tool,
  // GitHub Actions, CI runners, subprocess pipes). Operators saw JSON
  // everywhere "default human" was advertised. Now:
  //   --json or --json-stdout-only   → compact JSON
  //   --pretty                       → indented JSON
  //   default (no flag, renderer present) → HUMAN
  //   default (no flag, no renderer)      → indented JSON when TTY else compact
  // This closes the longest-standing UX gap across 8 releases.
  const wantJson = !!global.__exceptdWantJson || !!process.env.EXCEPTD_RAW_JSON;
  if (humanRenderer && !wantJson && !pretty) {
    process.stdout.write(humanRenderer(obj) + "\n");
    return;
  }
  const interactive = process.stdout.isTTY && !process.env.EXCEPTD_RAW_JSON;
  const indent = pretty || (interactive && !pretty);
  const s = indent ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
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
    bool:  ["pretty", "air-gap", "force-stale", "all", "flat", "directives",
            "ci", "latest", "diff-from-latest", "explain", "signal-list", "ack",
            "force-overwrite", "no-stream", "block-on-jurisdiction-clock",
            "json-stdout-only", "fix", "human", "json", "strict-preconditions"],
    multi: ["playbook", "format"],
  });
  // v0.11.2 bug #60: flip defaults to human-readable. JSON via explicit --json
  // (or --pretty implies indented JSON). The v0.11.0 CHANGELOG claimed this
  // was already done; the code in fact emitted JSON unconditionally. Now:
  //   --json or --pretty  → JSON (one-line or indented respectively)
  //   --json-stdout-only  → JSON, suppress stderr
  //   default             → human-readable text
  // Verbs that have their own human renderer (discover/doctor/refresh/lint
  // /ask/attest list) continue to use it; verbs that don't yet (brief/run/
  // ai-run/ci/attest show/export/diff/verify) fall back to indented JSON
  // labeled as such — better than no signal.
  args._jsonMode = !!(args.json || args.pretty || args["json-stdout-only"]);
  // Hoist into module-level state so emit() can read it without plumbing.
  global.__exceptdWantJson = args._jsonMode;
  const pretty = !!args.pretty;
  const runOpts = {
    airGap: !!args["air-gap"],
    forceStale: !!args["force-stale"],
  };
  if (args["session-id"]) runOpts.session_id = args["session-id"];
  if (args["attestation-root"]) runOpts.attestationRoot = args["attestation-root"];
  if (args["session-key"]) {
    // Bug #33: validate that --session-key is hex. Previously any string was
    // silently accepted; HMAC signing then either failed silently or produced
    // an unverifiable signature.
    if (!/^[0-9a-fA-F]+$/.test(args["session-key"])) {
      return emitError("run: --session-key must be hex characters only (0-9, a-f). Generate with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"", { provided_length: args["session-key"].length }, pretty);
    }
    if (args["session-key"].length < 16) {
      return emitError("run: --session-key is too short (need at least 16 hex chars / 64 bits of entropy).", { provided_length: args["session-key"].length }, pretty);
    }
    runOpts.session_key = args["session-key"];
  }
  if (args.mode) {
    // Bug #32: validate --mode against the accepted set. Previously
    // `--mode garbage` was silently accepted.
    const VALID_MODES = ["self_service", "authorized_pentest", "ir_response", "ctf", "research", "compliance_audit"];
    if (!VALID_MODES.includes(args.mode)) {
      return emitError(`run: --mode "${args.mode}" not in accepted set ${JSON.stringify(VALID_MODES)}.`, { provided: args.mode }, pretty);
    }
    runOpts.mode = args.mode;
  }
  // Multi-operator teams need attestations bound to a specific human or
  // service identity. --operator <name> persists into the attestation file
  // for audit-trail accountability. Free-form string; no validation.
  if (args.operator) runOpts.operator = args.operator;
  // --ack: operator acknowledges the jurisdiction obligations surfaced by
  // govern. Captured in attestation; downstream tooling can check whether
  // consent was explicit vs. implicit. AGENTS.md says the AI should surface
  // and wait for ack — this is how the ack gets recorded.
  if (args.ack) runOpts.operator_consent = { acked_at: new Date().toISOString(), explicit: true };

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
      case "attest": return cmdAttest(runner, args, runOpts, pretty);
      case "brief": return cmdBrief(runner, args, runOpts, pretty);
      case "run-all": return cmdRunAll(runner, args, runOpts, pretty);
      case "verify-attestation": return cmdVerifyAttestation(runner, args, runOpts, pretty);
      case "lint": return cmdLint(runner, args, runOpts, pretty);
      case "discover": return cmdDiscover(runner, args, runOpts, pretty);
      case "doctor": return cmdDoctor(runner, args, runOpts, pretty);
      case "ai-run": return cmdAiRun(runner, args, runOpts, pretty);
      case "ask":    return cmdAsk(runner, args, runOpts, pretty);
      case "ci":     return cmdCi(runner, args, runOpts, pretty);
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
  --evidence-dir <dir>    Read <playbook-id>.json files from a directory and
                          merge into the multi-run bundle. Cron-friendly.
  --vex <file>            Load a CycloneDX or OpenVEX document. CVEs marked
                          not_affected | resolved | false_positive (CycloneDX)
                          or not_affected | fixed (OpenVEX) drop out of
                          analyze.matched_cves. The disposition is preserved
                          under analyze.vex.dropped_cves.
  --format <fmt> ...      Emit the close.evidence_package bundle in additional
                          formats. Repeatable. Supported: csaf-2.0 | sarif |
                          openvex | markdown. CSAF is always primary; extras
                          populate close.evidence_package.bundles_by_format.
  --explain               Dry-run: emit preconditions, required artifacts,
                          recognized signal keys, and a submission skeleton.
                          Does not run detect/analyze/validate/close.
  --signal-list           Emit only the signal_overrides keys the detect phase
                          recognizes (lighter than --explain).
  --operator <name>       Bind the attestation to a specific human/service
                          identity. Persisted under attestation.operator.
  --ack                   Mark explicit operator consent to the jurisdiction
                          obligations surfaced by govern. Persisted under
                          attestation.operator_consent.
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
    attest: `attest <subverb> <session-id> — auditor-facing attestation operations.

Subverbs:
  attest show <sid>       Emit the full (unredacted) attestation.
  attest export <sid>     Emit redacted JSON suitable for audit submission.
                          Strips raw artifact values; preserves evidence_hash,
                          signature, classification, RWEP, remediation choice.
                          --format csaf wraps the export in a CSAF envelope.
  attest verify <sid>     Verify .sig sidecar against keys/public.pem.
                          Reports tamper status per attestation file.

All subverbs honor --pretty for indented JSON output.`,
    discover: `discover — context-aware playbook recommender (v0.11.0).

Replaces: scan + dispatch + recommend.

Sniffs the cwd (.git/, package.json, pyproject.toml, requirements.txt,
Cargo.toml, go.mod, Dockerfile, docker-compose.yml, *.tf, k8s/, .env) and
on Linux reads /etc/os-release to detect host distro. Emits a list of
recommended exceptd playbooks tailored to what was found.

Flags:
  --scan-only             Also include legacy \`scan\` output under legacy_scan.
  --json                  Emit JSON (default is human-readable text).
  --pretty                Indented JSON output (implies --json).

Output: context + recommended_playbooks[] + next_steps[].`,
    doctor: `doctor — one-shot health check (v0.11.0).

Replaces: currency + verify + validate-cves + validate-rfcs + signing-status.

Subchecks:
  --signatures            Ed25519 signature verification across all skills.
  --currency              Skill currency report (last_threat_review).
  --cves                  CVE catalog validation (offline view).
  --rfcs                  RFC catalog validation (offline view).
  (no flag)               All four, plus signing-status (private key presence).

Flags:
  --json                  Emit JSON (default is human-readable text).
  --pretty                Indented JSON output (implies --json).

Output: checks{} per subcheck + summary{all_green, issues_count}.`,
    "ai-run": `ai-run <playbook> — streaming JSONL contract for AI-driven runs (v0.11.0).

Emits one JSON event per line as the seven phases progress, and reads
evidence events back on stdin. Single pipe instead of brief → look → run.

Flags:
  <playbook>              Required positional.
  --directive <id>        Specific directive (default: first one).
  --no-stream             Single-shot mode: emit all phases as one JSON doc
                          without reading stdin (uses runner.run directly).
  --pretty                Indented JSON output (single-shot only).

Stdin event grammar (one JSON object per line):
  {"event":"evidence","payload":{"observations":{},"verdict":{}}}

Emits phases: govern → direct → look → await_evidence → detect → analyze
→ validate → close, then {"event":"done","ok":true,"session_id":"..."}.
Errors emit {"event":"error","reason":"..."} and exit non-zero.`,
    ask: `ask "<plain-English question>" — keyword routing to playbooks (v0.11.0).

Tokenises the question (words > 3 chars), scores every playbook by overlap
against domain.name + domain.attack_class + the first sentence of
phases.direct.threat_context, returns the top 5 matches with a confidence
score.

Args / flags:
  "<question>"            Plain-English question. Wrap in quotes.
  --pretty                Indented JSON output.

Output: { verb, question, routed_to:[ids], confidence, next_step,
full_match_list }. Empty match list when no token overlap — surfaces a
hint pointing at \`exceptd brief --all\` / \`exceptd discover\`.`,
    ci: `ci [--all|--scope <type>] — one-shot CI gate (v0.11.0).

Top-level CI verb. Equivalent to \`run --all --ci\` but with a clean
exit-code contract designed for one-line .github/workflows entries.

Flags:
  --all                   Run every playbook.
  --scope <type>          Filter: system | code | service | cross-cutting.
  (no flag)               Auto-detect scopes from cwd (same logic as run).
  --evidence <file>       Submission bundle (multi-playbook shape).
  --evidence-dir <dir>    Read <playbook-id>.json files from a directory.
  --max-rwep <int>        Override RWEP escalate threshold (default: per-playbook).
  --block-on-jurisdiction-clock
                          Fail when any close.notification_actions started a
                          regulatory clock (GDPR 72h, HIPAA breach, etc.).
  --pretty                Indented JSON output.

Exit codes: 0 PASS, 2 FAIL (detected | rwep ≥ cap | clock started w/ block flag).
Output: verb, session_id, playbooks_run, summary{total, detected,
max_rwep_observed, jurisdiction_clocks_started, verdict}, results[].`,
  };
  process.stdout.write((cmds[verb] || `${verb} — no per-verb help available; see \`exceptd help\` for the full list.`) + "\n");
}

/**
 * `brief` — collapses plan + govern + direct + look into one informational
 * document. Phases 1-3 of the seven-phase contract are entirely informational
 * (no state mutation), so the AI reads ONE document instead of three CLI
 * round-trips.
 *
 * Modes:
 *   brief <playbook>          → one playbook, all three info phases unified
 *   brief --all               → every playbook (replaces `plan`)
 *   brief <playbook> --phase <name>
 *                             → emit only the named phase (compat with
 *                               legacy `govern`/`direct`/`look` callers)
 */
/**
 * `lint <playbook> <evidence-file>` — pre-flight check the submission shape
 * against the playbook's expected indicators / preconditions / artifacts
 * WITHOUT executing detect/analyze/validate/close. Lets the AI iterate on
 * its evidence JSON before going through phases 4-7. Returns a categorized
 * list: ok / missing_required / unknown_keys / type_mismatch / suggestions.
 */
function cmdLint(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  const evidencePath = args._[1] || args.evidence;
  if (!playbookId || !evidencePath) {
    return emitError("lint: usage: exceptd lint <playbook> <evidence-file|->", null, pretty);
  }
  let pb;
  try { pb = runner.loadPlaybook(playbookId); }
  catch (e) { return emitError(`lint: ${e.message}`, { playbook: playbookId }, pretty); }

  let submission;
  try { submission = readEvidence(evidencePath); }
  catch (e) { return emitError(`lint: failed to read evidence: ${e.message}`, { evidence: evidencePath }, pretty); }

  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  const lookPhase = pb.phases?.look || {};
  const detectPhase = pb.phases?.detect || {};

  const requiredArtifacts = (lookPhase.artifacts || []).filter(a => a.required).map(a => a.id);
  const knownArtifacts = new Set((lookPhase.artifacts || []).map(a => a.id));
  const knownIndicators = new Set((detectPhase.indicators || []).map(i => i.id));
  const knownPreconditions = new Set((pb._meta?.preconditions || []).map(p => p.id));

  // v0.11.5 #83: shared shape contract with runner. Pre-0.11.5 lint
  // walked the raw submission and only matched observations whose key was
  // a known artifact id. The runner's normalizeSubmission follows
  // `val.artifact` indirection — so observations with arbitrary keys
  // (obs-1, obs-2) and an `artifact:` field route correctly. Lint must
  // do the same normalization before validating, or lint and run disagree
  // on what's a valid submission.
  const normalized = runner.normalizeSubmission(submission, pb);
  const flat = submission.observations || null;

  // After normalize, validation walks the canonical nested shape.
  const missingRequired = requiredArtifacts.filter(id => {
    const a = normalized.artifacts && normalized.artifacts[id];
    return !a || !a.captured;
  });

  const unknownArtifactKeys = Object.keys(normalized.artifacts || {})
    .filter(k => !knownArtifacts.has(k));
  const unknownSignalKeys = Object.keys(normalized.signal_overrides || {})
    .filter(k => !knownIndicators.has(k));
  const unknownObservationKeys = flat
    ? Object.keys(flat).filter(k => {
        // Skip observations with explicit `artifact:` indirection — those
        // are valid by-design even when the key doesn't match a known artifact.
        const v = flat[k];
        if (v && typeof v === "object" && v.artifact) return false;
        return !knownArtifacts.has(k) && !knownIndicators.has(k) && !knownPreconditions.has(k);
      })
    : [];

  const unsuppliedPreconditions = [...knownPreconditions].filter(
    p => !(((submission.precondition_checks || {}).hasOwnProperty(p)) || ((normalized.precondition_checks || {}).hasOwnProperty(p)))
  );

  const issues = [];
  // v0.11.6 (#94): missing_required_artifact downgraded from error to warn.
  // The runner doesn't refuse a submission missing required artifacts — it
  // runs with the indicators that have data and marks the rest inconclusive.
  // Lint was stricter than runner; users got errors on submissions the runner
  // accepted. Now: lint warns about missing artifacts but doesn't fail.
  for (const id of missingRequired) {
    issues.push({ severity: "warn", kind: "missing_required_artifact", artifact_id: id, hint: `Add to submission.artifacts.${id} = { value, captured: true } (or under observations in the flat shape). The run will still execute without this; the corresponding indicators will return 'inconclusive'.` });
  }
  for (const k of unknownArtifactKeys) {
    issues.push({ severity: "warn", kind: "unknown_artifact_key", key: k, hint: `Not in playbook ${playbookId} look.artifacts[]. Recognized: ${[...knownArtifacts].slice(0, 10).join(", ")}…` });
  }
  for (const k of unknownSignalKeys) {
    issues.push({ severity: "warn", kind: "unknown_signal_override_key", key: k, hint: `Not in playbook ${playbookId} detect.indicators[]. Run \`exceptd run ${playbookId} --signal-list\` to enumerate.` });
  }
  for (const p of unsuppliedPreconditions) {
    issues.push({ severity: "info", kind: "precondition_unverified", precondition_id: p, hint: `Add submission.precondition_checks.${p} = true|false (or under observations in the flat shape).` });
  }
  for (const k of unknownObservationKeys) {
    issues.push({ severity: "warn", kind: "unknown_observation_key", key: k });
  }

  // #71 (v0.11.3) + #83 (v0.11.5): when a submission is flat-shape but the
  // post-normalize signal_overrides is empty AND no verdict.classification
  // is supplied, detect() will return inconclusive. Surface this before run.
  if (flat) {
    const verdictClass = submission.verdict?.classification;
    const verdictWillDrive = verdictClass === "clean" || verdictClass === "not_detected" || verdictClass === "detected" || verdictClass === "inconclusive";
    const normalizedHasOverrides = Object.keys(normalized.signal_overrides || {}).length > 0;
    if (!verdictWillDrive && !normalizedHasOverrides) {
      const observationsCount = Object.keys(flat).length;
      issues.push({
        severity: "info",
        kind: "detect_will_be_inconclusive",
        hint: `Flat submission with ${observationsCount} observation(s) but no indicator+result fields and no verdict.classification. detect() will return 'inconclusive'. Each observation needs { "indicator": "<id>", "result": "hit"|"miss"|"inconclusive" } to drive an indicator outcome. Run \`exceptd run ${playbookId} --signal-list\` for the indicator IDs.`,
      });
    }
  }

  const ok = issues.every(i => i.severity !== "error");
  emit({
    verb: "lint",
    ok,
    playbook_id: playbookId,
    directive_id: directiveId,
    submission_shape: flat ? "flat (v0.11.0)" : "nested (v0.10.x)",
    summary: {
      errors: issues.filter(i => i.severity === "error").length,
      warnings: issues.filter(i => i.severity === "warn").length,
      info: issues.filter(i => i.severity === "info").length,
    },
    issues,
  }, pretty, (obj) => {
    // v0.11.6 (#95) human renderer for lint.
    const lines = [`lint: ${obj.playbook_id} (${obj.directive_id}) — shape: ${obj.submission_shape}`];
    lines.push(`  ${obj.ok ? "[ok]" : "[!! fail]"}  errors=${obj.summary.errors}  warnings=${obj.summary.warnings}  info=${obj.summary.info}`);
    if (obj.issues.length > 0) {
      for (const i of obj.issues.slice(0, 30)) {
        const tag = i.severity === "error" ? "[!! ERROR]" : (i.severity === "warn" ? "[!! WARN ]" : "[i  INFO ]");
        lines.push(`  ${tag} ${i.kind}${i.artifact_id ? ": " + i.artifact_id : ""}${i.observation_key ? ": " + i.observation_key : ""}${i.key ? ": " + i.key : ""}${i.precondition_id ? ": " + i.precondition_id : ""}`);
        if (i.hint) lines.push(`             ${i.hint}`);
      }
      if (obj.issues.length > 30) lines.push(`  … and ${obj.issues.length - 30} more (use --json for full list)`);
    }
    return lines.join("\n");
  });
  if (!ok) process.exitCode = 1;
}

function cmdBrief(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  const onlyPhase = args.phase || null;

  if (!playbookId || args.all) {
    // Multi-playbook brief (replaces `plan`). Reuses cmdPlan output shape.
    return cmdPlan(runner, args, runOpts, pretty);
  }

  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);

  const govern = runner.govern(playbookId, directiveId, runOpts);
  const direct = runner.direct(playbookId, directiveId);
  const look = runner.look(playbookId, directiveId, runOpts);

  // If --phase was passed, emit only that phase to ease legacy migration.
  if (onlyPhase === "govern") return emit(govern, pretty);
  if (onlyPhase === "direct") return emit(direct, pretty);
  if (onlyPhase === "look") return emit(look, pretty);

  emit({
    verb: "brief",
    playbook_id: playbookId,
    directive_id: directiveId,
    scope: pb._meta?.scope || null,
    threat_currency_score: pb._meta?.threat_currency_score,

    // From govern phase:
    jurisdiction_obligations: govern.jurisdiction_obligations,
    theater_fingerprints: govern.theater_fingerprints,
    framework_context: govern.framework_context,
    skill_preload: govern.skill_preload,

    // From direct phase:
    threat_context: direct.threat_context,
    rwep_threshold: direct.rwep_threshold,
    framework_lag_declaration: direct.framework_lag_declaration,
    skill_chain: direct.skill_chain,
    token_budget: direct.token_budget,

    // From look phase:
    preconditions: look.preconditions,
    precondition_submission_shape: look.precondition_submission_shape,
    artifacts: look.artifacts,
    collection_scope: look.collection_scope,
    environment_assumptions: look.environment_assumptions,
    fallback_if_unavailable: look.fallback_if_unavailable,

    // Forward references — what the AI will see during run:
    detect_indicators_preview: (pb.phases?.detect?.indicators || []).map(i => ({
      id: i.id, type: i.type, confidence: i.confidence, deterministic: !!i.deterministic
    })),
  }, pretty, (obj) => {
    // v0.11.8 (#99) — human renderer for `brief`. Used on TTY when --json /
    // --pretty are NOT set. Structured digest covering the three info phases.
    const lines = [];
    lines.push(`brief: ${obj.playbook_id} (${obj.directive_id})`);
    lines.push(`  scope: ${obj.scope || "n/a"}   threat_currency_score: ${obj.threat_currency_score}`);
    if (obj.jurisdiction_obligations?.length) {
      lines.push(`\nJurisdiction obligations (${obj.jurisdiction_obligations.length}):`);
      for (const j of obj.jurisdiction_obligations.slice(0, 6)) {
        lines.push(`  ${j.jurisdiction} ${j.regulation} → ${j.window_hours}h on ${j.clock_starts}`);
      }
      if (obj.jurisdiction_obligations.length > 6) lines.push(`  … ${obj.jurisdiction_obligations.length - 6} more`);
    }
    if (obj.threat_context) {
      const first = obj.threat_context.split(/(?<=[.!?])\s+/)[0] || "";
      lines.push(`\nThreat context: ${first.slice(0, 200)}${first.length > 200 ? "…" : ""}`);
    }
    if (obj.rwep_threshold) {
      lines.push(`\nRWEP threshold: escalate ${obj.rwep_threshold.escalate} · monitor ${obj.rwep_threshold.monitor} · close ${obj.rwep_threshold.close}`);
    }
    const required = (obj.artifacts || []).filter(a => a.required);
    const optional = (obj.artifacts || []).filter(a => !a.required);
    lines.push(`\nRequired artifacts (${required.length}): ${required.map(a => a.id).join(", ") || "(none)"}`);
    if (optional.length) lines.push(`Optional artifacts (${optional.length}): ${optional.map(a => a.id).slice(0, 8).join(", ")}${optional.length > 8 ? ", …" : ""}`);
    const indicators = obj.detect_indicators_preview || [];
    lines.push(`\nIndicators (${indicators.length}): ${indicators.map(i => i.id).slice(0, 8).join(", ")}${indicators.length > 8 ? ", …" : ""}`);
    if (obj.preconditions?.length) {
      lines.push(`\nPreconditions (${obj.preconditions.length}):`);
      for (const p of obj.preconditions) {
        lines.push(`  ${p.id} (${p.on_fail}): ${p.description?.slice(0, 80) || p.check}`);
      }
    }
    lines.push(`\nRun: exceptd run ${obj.playbook_id} --evidence <file|-> --json`);
    lines.push(`Full structured doc: --json or --pretty`);
    return lines.join("\n");
  });
}

/** `run-all` alias for `run --all`. */
function cmdRunAll(runner, args, runOpts, pretty) {
  args.all = true;
  return cmdRun(runner, args, runOpts, pretty);
}

/** `verify-attestation <sid>` alias for `attest verify <sid>`. */
function cmdVerifyAttestation(runner, args, runOpts, pretty) {
  args._ = ["verify", ...(args._ || [])];
  return cmdAttest(runner, args, runOpts, pretty);
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
  // --directives expands each playbook entry with directive id + title +
  // applies_to + description. v0.10.3-aware fallback: pull description from
  // (a) explicit d.description, (b) directive override threat_context,
  // (c) playbook-level direct.threat_context first sentence, (d) playbook
  // domain.name. Operators need operator-facing prose, not just an ID + enum.
  if (args.directives) {
    for (const pb of plan.playbooks) {
      const full = runner.loadPlaybook(pb.id);
      const baseDirect = full.phases?.direct || {};
      pb.directives = full.directives.map(d => {
        const overrideDirect = d.phase_overrides?.direct || {};
        const threatContext = overrideDirect.threat_context || baseDirect.threat_context || null;
        const firstSentence = threatContext ? (threatContext.split(/(?<=[.!?])\s+/)[0] || "").slice(0, 240) : null;
        return {
          id: d.id,
          title: d.title,
          description: d.description || firstSentence || full.domain?.name || null,
          applies_to: d.applies_to,
          threat_context_preview: firstSentence,
        };
      });
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

  // --explain: dry-run that emits the preconditions + artifacts + indicators
  // + signal keys the agent would need to supply, WITHOUT running detect/
  // analyze/validate/close. Lets operators preview before assembling evidence.
  if (args.explain) {
    const lookPhase = runner.look(playbookId, directiveId, runOpts);
    const detectPhase = runner.loadPlaybook(playbookId).phases?.detect || {};
    const detectResolved = runner._resolvedPhase ? runner._resolvedPhase(pb, directiveId, "detect") : detectPhase;
    emit({
      verb: "run",
      mode: "explain",
      playbook_id: playbookId,
      directive_id: directiveId,
      scope: pb._meta?.scope || null,
      preconditions: lookPhase.preconditions,
      precondition_submission_shape: lookPhase.precondition_submission_shape,
      artifacts_required: lookPhase.artifacts.filter(a => a.required).map(a => ({ id: a.id, type: a.type, source: a.source })),
      artifacts_optional: lookPhase.artifacts.filter(a => !a.required).map(a => ({ id: a.id, type: a.type, source: a.source, fallback: lookPhase.fallback_if_unavailable.find(f => f.artifact_id === a.id) })),
      signal_keys: (detectResolved.indicators || []).map(i => ({ id: i.id, type: i.type, deterministic: !!i.deterministic, confidence: i.confidence })),
      detect_classification_override: { hint: "submit signals.detection_classification = 'detected' | 'inconclusive' | 'not_detected' | 'clean' to override engine-computed classification.", valid_values: ["detected", "inconclusive", "not_detected", "clean"] },
      submission_skeleton: {
        artifacts: Object.fromEntries(lookPhase.artifacts.map(a => [a.id, { value: "<your captured output>", captured: true }])),
        signal_overrides: Object.fromEntries((detectResolved.indicators || []).map(i => [i.id, "hit | miss | inconclusive"])),
        signals: { detection_classification: "<one of: detected|inconclusive|not_detected|clean>", theater_verdict: "<clear | theater | pending_agent_run>" },
        precondition_checks: Object.fromEntries(lookPhase.preconditions.map(p => [p.id, true])),
      }
    }, pretty);
    return;
  }

  // --signal-list: enumerate every signal_overrides key the detect phase
  // recognizes. Lighter than --explain.
  if (args["signal-list"]) {
    const detectResolved = runner._resolvedPhase
      ? runner._resolvedPhase(pb, directiveId, "detect")
      : pb.phases?.detect;
    emit({
      verb: "run",
      mode: "signal-list",
      playbook_id: playbookId,
      directive_id: directiveId,
      signal_overrides_keys: (detectResolved?.indicators || []).map(i => i.id),
      signal_value_grammar: "hit | miss | inconclusive",
      detection_classification_override_keys: ["detected", "inconclusive", "not_detected", "clean"],
    }, pretty);
    return;
  }

  let submission = {};
  // v0.11.1: auto-detect piped stdin (process.stdin.isTTY === false means
  // something is piping into us). If no --evidence flag and stdin is a pipe,
  // assume `--evidence -`. Operators forgetting the flag previously got a
  // confusing precondition halt; now the common case "just works."
  if (!args.evidence && process.stdin.isTTY === false) {
    args.evidence = "-";
  }
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

  // --format <fmt>: override the playbook's declared evidence_package.bundle_format.
  // Supports csaf-2.0 | sarif | openvex | markdown. Multiple --format flags
  // produce multiple bundles in the close response under bundles_by_format.
  if (args.format) {
    // Normalize shortcut names to the runner's canonical bundle keys before
    // passing through. "csaf" → "csaf-2.0"; "sarif" / "openvex" / "markdown"
    // / "summary" stay verbatim. Anything else is rejected after the run
    // result is in hand (so the run still completes).
    const formats = (Array.isArray(args.format) ? args.format : [args.format])
      .map(f => f === "csaf" ? "csaf-2.0" : f);
    submission.signals = submission.signals || {};
    submission.signals._bundle_formats = formats;
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

  // v0.11.9 (#113/#114): surface --operator and --ack in the run result so
  // operators see the attribution + consent state without inspecting the
  // attestation file. Pre-0.11.9 these were persisted to disk only.
  // v0.11.10 (#119): add result.ack alias for consumers reading the
  // ack state by that name (`result.ack` is shorter + matches the CLI flag).
  if (result && runOpts.operator) result.operator = runOpts.operator;
  if (result && runOpts.operator_consent) {
    result.operator_consent = runOpts.operator_consent;
    result.ack = !!runOpts.operator_consent.explicit;
  } else if (result) {
    result.ack = false;
  }

  // Persist attestation for reattest cycles when the run succeeded.
  if (result && result.ok && result.session_id) {
    const persistResult = persistAttestation({
      sessionId: result.session_id,
      playbookId: result.playbook_id,
      directiveId: result.directive_id,
      evidenceHash: result.evidence_hash,
      operator: runOpts.operator,
      operatorConsent: runOpts.operator_consent,
      submission,
      runOpts,
      forceOverwrite: !!args["force-overwrite"],
      filename: "attestation.json",
    });
    if (!persistResult.ok) {
      // Session-id collision without --force-overwrite. Refuse, surface the
      // existing path so the operator can decide, and emit JSON to stderr
      // matching the unified error shape. Exit non-zero — a silent overwrite
      // is a tamper-evidence violation.
      const err = {
        ok: false,
        error: persistResult.error,
        existing_attestation: persistResult.existingPath,
        hint: "Pass --force-overwrite to replace, or supply a fresh --session-id (omit the flag for an auto-generated hex).",
        verb: "run",
      };
      process.stderr.write(JSON.stringify(err) + "\n");
      process.exit(3);
    }
    if (persistResult.prior_session_id) {
      // Force-overwrite happened — surface the prior_session_id in the
      // returned result so the operator/AI can see what the new attestation
      // replaced and link back via the prior_session_id field persisted on
      // disk.
      result.prior_session_id = persistResult.prior_session_id;
      result.overwrote_at = persistResult.overwrote_at;
    }
  }

  if (result && result.ok === false) {
    process.stderr.write((pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + "\n");
    process.exit(1);
  }

  // v0.11.6 (#96): --strict-preconditions escalates warn-level preflight
  // issues to exit 1. Default (without the flag) preserves the existing
  // behavior where warn-level issues stay informational. CI gates wanting
  // "fail on any unverified precondition" pass this flag.
  if (args["strict-preconditions"] && result && Array.isArray(result.preflight_issues)) {
    const warnIssues = result.preflight_issues.filter(i =>
      i.kind === "precondition_unverified" || i.kind === "precondition_warn"
    );
    if (warnIssues.length > 0) {
      process.stderr.write(`[exceptd run] --strict-preconditions: ${warnIssues.length} unverified/warn precondition(s) — exit 1.\n`);
      emit(result, pretty);
      // v0.11.11: exitCode + return so emit()'s stdout flushes (process.exit
      // can truncate buffered async stdout writes when piped).
      process.exitCode = 1;
      return;
    }
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

  // v0.11.2 bug #59 / feature #70: --format actually transforms the top-level
  // output. Previously it only populated close.evidence_package.bundles_by_format
  // and the operator still saw the full JSON. Now:
  //   --format summary  → single-line JSON digest (5 fields)
  //   --format markdown → operator-readable markdown digest of the run
  //   --format csaf-2.0/sarif/openvex → the corresponding bundle from close
  //   (default — no --format) → full JSON result as before
  if (args.format) {
    const requested = Array.isArray(args.format) ? args.format[0] : args.format;
    const VALID = ["summary", "markdown", "csaf-2.0", "csaf", "sarif", "openvex", "json"];
    if (!VALID.includes(requested)) {
      return emitError(`run: --format "${requested}" not in accepted set ${JSON.stringify(VALID)}.`, null, pretty);
    }
    if (requested === "summary") {
      const cls = result.phases?.detect?.classification;
      const rwep = result.phases?.analyze?.rwep?.adjusted ?? 0;
      const blast = result.phases?.analyze?.blast_radius_score ?? 0;
      const cves = result.phases?.analyze?.matched_cves?.length ?? 0;
      const next = result.phases?.close?.feeds_into?.join(",") || "";
      const clocks = (result.phases?.close?.notification_actions || []).filter(n => n.clock_started_at).length;
      emit({
        ok: result.ok, playbook: result.playbook_id, session_id: result.session_id,
        classification: cls, rwep, blast_radius: blast, matched_cves: cves,
        feeds_into: next, jurisdiction_clocks: clocks, evidence_hash: result.evidence_hash,
      }, pretty);
      return;
    }
    if (requested === "markdown") {
      const lines = [];
      lines.push(`# exceptd run: ${result.playbook_id}`);
      lines.push(`session-id: ${result.session_id}`);
      lines.push(`evidence-hash: ${result.evidence_hash}`);
      lines.push("");
      const cls = result.phases?.detect?.classification || "n/a";
      const rwep = result.phases?.analyze?.rwep?.adjusted ?? 0;
      const top = result.phases?.analyze?.rwep?.threshold?.escalate ?? "n/a";
      lines.push(`**Classification:** ${cls}  **RWEP:** ${rwep} / ${top}  **Blast radius:** ${result.phases?.analyze?.blast_radius_score ?? "n/a"}/5`);
      lines.push("");
      const cves = result.phases?.analyze?.matched_cves || [];
      if (cves.length) {
        lines.push(`## Matched CVEs (${cves.length})`);
        for (const c of cves) lines.push(`- **${c.cve_id}** · RWEP ${c.rwep} · KEV=${c.cisa_kev} · ${c.active_exploitation}`);
        lines.push("");
      }
      const rem = result.phases?.validate?.selected_remediation;
      if (rem) {
        lines.push(`## Recommended remediation`);
        lines.push(`**${rem.id}** (priority ${rem.priority}) — ${rem.description}`);
        lines.push("");
      }
      const notif = result.phases?.close?.notification_actions || [];
      if (notif.length) {
        lines.push(`## Notification clocks`);
        for (const n of notif) lines.push(`- ${n.obligation_ref} → deadline ${n.deadline}`);
        lines.push("");
      }
      const feeds = result.phases?.close?.feeds_into || [];
      if (feeds.length) lines.push(`**Next playbooks suggested:** ${feeds.join(", ")}`);
      process.stdout.write(lines.join("\n") + "\n");
      return;
    }
    // CSAF/SARIF/OpenVEX bundles live under close.evidence_package — the
    // runner writes them under canonical keys ("csaf-2.0", "sarif",
    // "openvex"). Normalize the user-supplied shortcuts.
    const formatNorm = requested === "csaf" ? "csaf-2.0" : requested;
    const bbf = result.phases?.close?.evidence_package?.bundles_by_format || {};
    const body = bbf[formatNorm] || result.phases?.close?.evidence_package?.bundle_body;
    if (body) {
      emit(body, pretty);
      return;
    }
    // Fallback: full result
  }

  emit(result, pretty, (obj) => {
    // v0.11.8 (#99) — human renderer for `run`. Used on TTY when --json /
    // --pretty are NOT set. One-screen digest of the run; full JSON via --json.
    const lines = [];
    lines.push(`run: ${obj.playbook_id} (${obj.directive_id})`);
    lines.push(`  session-id: ${obj.session_id}`);
    lines.push(`  evidence-hash: ${obj.evidence_hash}`);
    const cls = obj.phases?.detect?.classification || "n/a";
    const rwep = obj.phases?.analyze?.rwep;
    const adj = rwep?.adjusted ?? 0;
    const base = rwep?.base ?? 0;
    const top = rwep?.threshold?.escalate ?? "n/a";
    const verdictIcon = cls === "detected" ? "[!! DETECTED]" : cls === "inconclusive" ? "[i  INCONCLUSIVE]" : "[ok]";
    lines.push(`\n${verdictIcon}  classification=${cls}  RWEP ${adj}/${top}${adj !== base ? ` (Δ${adj - base} from operator evidence)` : " (catalog baseline)"}  blast_radius=${obj.phases?.analyze?.blast_radius_score ?? "n/a"}/5`);
    const cves = obj.phases?.analyze?.matched_cves || [];
    if (cves.length) {
      lines.push(`\nMatched CVEs (${cves.length}):`);
      for (const c of cves.slice(0, 6)) lines.push(`  ${c.cve_id}  RWEP ${c.rwep}  KEV=${c.cisa_kev}  ${c.active_exploitation || ""}`);
      if (cves.length > 6) lines.push(`  … ${cves.length - 6} more`);
    }
    const indicators = obj.phases?.detect?.indicators || [];
    const hits = indicators.filter(i => i.verdict === "hit");
    if (hits.length) {
      lines.push(`\nIndicators that fired (${hits.length}):`);
      for (const i of hits.slice(0, 8)) lines.push(`  ${i.id}  (${i.confidence}${i.deterministic ? "/deterministic" : ""})`);
    }
    const rem = obj.phases?.validate?.selected_remediation;
    if (rem) {
      lines.push(`\nRecommended remediation: ${rem.id} (priority ${rem.priority})`);
      lines.push(`  ${rem.description?.slice(0, 200) || ""}`);
    }
    const notif = (obj.phases?.close?.notification_actions || []).filter(n => n.clock_started_at);
    if (notif.length) {
      lines.push(`\nNotification clocks started (${notif.length}):`);
      for (const n of notif) lines.push(`  ${n.obligation_ref} → deadline ${n.deadline}`);
    }
    const feeds = obj.phases?.close?.feeds_into || [];
    if (feeds.length) lines.push(`\nNext playbooks suggested: ${feeds.join(", ")}`);
    const issues = obj.preflight_issues || [];
    if (issues.length) {
      lines.push(`\nPreflight warnings (${issues.length}):`);
      for (const i of issues) lines.push(`  [${i.on_fail}] ${i.id}: ${i.check || ""}`);
    }
    lines.push(`\nFull structured result: --json (or --pretty for indented).`);
    return lines.join("\n");
  });
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
  // --evidence-dir <dir>: each <playbook-id>.json under the directory is read
  // as that playbook's submission. Lets operators wire up one cron job that
  // collects per-playbook evidence into a directory, then runs the whole
  // contract in one pass.
  if (args["evidence-dir"]) {
    const dir = args["evidence-dir"];
    if (!fs.existsSync(dir)) {
      return emitError(`run: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
      const pbId = f.replace(/\.json$/, "");
      try {
        bundle[pbId] = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      } catch (e) {
        return emitError(`run: failed to parse --evidence-dir entry ${f}: ${e.message}`, null, pretty);
      }
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
      const persisted = persistAttestation({
        sessionId,
        playbookId: id,
        directiveId,
        evidenceHash: result.evidence_hash,
        operator: perRunOpts.operator,
        operatorConsent: perRunOpts.operator_consent,
        submission,
        runOpts: perRunOpts,
        forceOverwrite: !!args["force-overwrite"],
        filename: `${id}.json`,
      });
      if (!persisted.ok) {
        // Multi-run collision: don't abort the whole bundle; surface in the
        // per-playbook result so the operator can see exactly which
        // playbook's attestation refused to overwrite.
        result.attestation_persist = { ok: false, error: persisted.error };
      } else if (persisted.prior_session_id) {
        result.attestation_persist = { ok: true, prior_session_id: persisted.prior_session_id, overwrote_at: persisted.overwrote_at };
      }
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
  // v0.11.9 (#100): cmdRunMulti exits non-zero when any individual run
  // returned ok:false. Pre-0.11.9 the aggregate result had {ok:false} in
  // the body but exit code stayed 0 — CI gates couldn't distinguish "ran
  // clean" from "blocked." Now matches cmdRun's single-playbook contract.
  const anyBlocked = results.some(r => r.ok === false);
  if (anyBlocked) process.exit(1);
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
      const dir = path.join(resolveAttestationRoot(runOpts), result.session_id);
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
 * Resolve the attestation root for a given run. Resolution order (most-specific
 * first):
 *   1. --attestation-root <path>    explicit caller override
 *   2. EXCEPTD_HOME env var         operator-level configuration
 *   3. ~/.exceptd/attestations/<repo-or-host-tag>/   default (v0.11.0+)
 *   4. .exceptd/attestations/       legacy cwd-relative fallback when ~/.exceptd
 *                                    can't be created (read-only home / sandbox)
 *
 * Repo tag is derived from `git config --get remote.origin.url` + branch when
 * available, else a hostname tag. This means `attest list` works regardless of
 * which directory you happened to run from. Operators can override via env.
 */
function resolveAttestationRoot(runOpts) {
  if (runOpts && runOpts.attestationRoot) return runOpts.attestationRoot;
  if (process.env.EXCEPTD_HOME) return path.join(process.env.EXCEPTD_HOME, "attestations");
  const home = require("os").homedir();
  if (!home) return path.join(process.cwd(), ".exceptd", "attestations");
  const root = path.join(home, ".exceptd", "attestations", deriveRunTag());
  try {
    fs.mkdirSync(root, { recursive: true });
    return root;
  } catch {
    return path.join(process.cwd(), ".exceptd", "attestations");
  }
}

/**
 * Derive a stable tag for attestations: `<repo-name>@<branch>` when in a git
 * repo, else `host:<hostname>`. Used as the per-context directory under
 * ~/.exceptd/attestations/ so multi-repo operators don't conflate sessions.
 */
function deriveRunTag() {
  const { spawnSync } = require("child_process");
  try {
    const remote = spawnSync("git", ["config", "--get", "remote.origin.url"], { encoding: "utf8" });
    if (remote.status === 0 && remote.stdout.trim()) {
      const url = remote.stdout.trim();
      const repoName = (url.match(/[\/:]([^/]+?)(?:\.git)?$/) || [, "unknown"])[1];
      const branch = spawnSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { encoding: "utf8" });
      const branchName = branch.status === 0 ? branch.stdout.trim() : "head";
      return `${repoName}@${branchName}`.replace(/[^A-Za-z0-9._@-]/g, "_");
    }
  } catch {}
  return `host:${require("os").hostname()}`.replace(/[^A-Za-z0-9._@:-]/g, "_");
}

/**
 * Persist an attestation file. Refuses to overwrite an existing file unless
 * `forceOverwrite` is true. When force-overwriting, the new attestation
 * records `prior_session_id` (== current session_id; the prior content is
 * what's being replaced) plus a `prior_evidence_hash` link extracted from
 * the file on disk before clobbering — so the audit-trail chain survives.
 *
 * Returns { ok: true, prior_session_id?, overwrote_at?, persist_path } on
 * success; or { ok: false, error, existingPath } when the operator hit a
 * collision without --force-overwrite.
 */
function persistAttestation(args) {
  const { sessionId, playbookId, directiveId, evidenceHash, operator,
          operatorConsent, submission, runOpts, forceOverwrite, filename } = args;
  const root = resolveAttestationRoot(runOpts);
  const dir = path.join(root, sessionId);
  const filePath = path.join(dir, filename);

  let prior = null;
  if (fs.existsSync(filePath)) {
    try { prior = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch {}
    if (!forceOverwrite) {
      return {
        ok: false,
        error: `Attestation already exists at ${path.relative(process.cwd(), filePath)}. Session-id collision (${sessionId}) — refusing to overwrite to preserve audit trail.`,
        existingPath: path.relative(process.cwd(), filePath),
      };
    }
  }

  try {
    fs.mkdirSync(dir, { recursive: true });
    const attestation = {
      session_id: sessionId,
      playbook_id: playbookId,
      directive_id: directiveId,
      evidence_hash: evidenceHash,
      operator: operator || null,
      operator_consent: operatorConsent || null,
      submission,
      run_opts: { airGap: runOpts.airGap, forceStale: runOpts.forceStale, mode: runOpts.mode },
      captured_at: new Date().toISOString(),
      // When overwriting (with --force-overwrite), link to the prior content
      // by evidence_hash + capture timestamp. session_id is the same (that's
      // why we collided), so it's the hash + timestamp that distinguish.
      prior_evidence_hash: prior ? (prior.evidence_hash || null) : null,
      prior_captured_at: prior ? (prior.captured_at || null) : null,
    };
    fs.writeFileSync(filePath, JSON.stringify(attestation, null, 2));
    maybeSignAttestation(filePath);
    return {
      ok: true,
      prior_session_id: prior ? sessionId : null,
      overwrote_at: prior ? prior.captured_at : null,
    };
  } catch (e) {
    return { ok: false, error: `Failed to write attestation: ${e.message}`, existingPath: null };
  }
}

/**
 * Ed25519-sign an attestation file when .keys/private.pem is available
 * (matches lib/sign.js convention for skill signing). Writes a sidecar
 * `<file>.sig` alongside the attestation. Defense against post-hoc tampering
 * by anyone who can write to .exceptd/.
 *
 * Without a private key, writes a marker file documenting the signed=false
 * state so downstream tooling can distinguish "operator declined signing"
 * from "the .sig file was deleted by an attacker."
 */
function maybeSignAttestation(filePath) {
  const crypto = require("crypto");
  const sigPath = filePath + ".sig";
  const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
  const content = fs.readFileSync(filePath, "utf8");
  // One-time-per-process unsigned warning so cron jobs don't spam stderr.
  // Operators who set `.keys/private.pem` get tamper-evident attestations;
  // operators without the keypair get a single nudge per session telling them
  // exactly how to enable signing.
  if (!fs.existsSync(privKeyPath) && !process.env.EXCEPTD_UNSIGNED_WARNED) {
    process.stderr.write(
      "[attest] attestation will be written UNSIGNED (no private key at .keys/private.pem). " +
      "Operators reading the attestation later can verify the SHA-256 hash but not authenticity. " +
      "Enable Ed25519 signing: `node lib/sign.js generate-keypair`. " +
      "Suppress this notice: export EXCEPTD_UNSIGNED_WARNED=1.\n"
    );
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
  }
  try {
    if (fs.existsSync(privKeyPath)) {
      const privateKey = fs.readFileSync(privKeyPath, "utf8");
      const sig = crypto.sign(null, Buffer.from(content, "utf8"), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      });
      fs.writeFileSync(sigPath, JSON.stringify({
        algorithm: "Ed25519",
        signature_base64: sig.toString("base64"),
        signed_at: new Date().toISOString(),
        signs_path: path.basename(filePath),
        signs_sha256: crypto.createHash("sha256").update(content).digest("base64"),
      }, null, 2));
    } else {
      fs.writeFileSync(sigPath, JSON.stringify({
        algorithm: "unsigned",
        signed: false,
        signed_at: null,
        signs_path: path.basename(filePath),
        signs_sha256: crypto.createHash("sha256").update(content).digest("base64"),
        note: "No private key at .keys/private.pem — attestation is hash-stable but unsigned. Run `node lib/sign.js generate-keypair` to enable signing.",
      }, null, 2));
    }
  } catch { /* non-fatal — signing failure shouldn't block the run */ }
}

/**
 * Resolve a session-id to its on-disk directory. Searches both the v0.11.0
 * default root and the legacy cwd-relative root; returns whichever exists.
 * Returns null if neither has the session.
 */
function findSessionDir(sessionId, runOpts) {
  const candidates = [
    path.join(resolveAttestationRoot(runOpts), sessionId),
    path.join(process.cwd(), ".exceptd", "attestations", sessionId),
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

/**
 * Find the latest attestation file under .exceptd/attestations/.
 * Filters: optional playbook ID and optional "since" ISO timestamp.
 * Returns { sessionId, playbookId, file, parsed } or null.
 */
function findLatestAttestation(opts = {}) {
  // Search both the v0.11.0 default root (~/.exceptd/) and the legacy cwd-
  // relative root so operators with prior attestations don't lose their
  // history when the default moved.
  const roots = [resolveAttestationRoot(opts), path.join(process.cwd(), ".exceptd", "attestations")];
  const seen = new Set();
  const candidates = [];
  for (const root of roots) {
    if (seen.has(root) || !fs.existsSync(root)) continue;
    seen.add(root);
    walkAttestationDir(root, opts, candidates);
  }
  candidates.sort((a, b) => (b.parsed.captured_at || "").localeCompare(a.parsed.captured_at || ""));
  return candidates[0] || null;
}

function walkAttestationDir(root, opts, candidates) {
  if (!fs.existsSync(root)) return;
  const sessions = fs.readdirSync(root, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);
  for (const sid of sessions) {
    const sdir = path.join(root, sid);
    for (const f of fs.readdirSync(sdir).filter(x => x.endsWith(".json") && !x.endsWith(".sig"))) {
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
  const dir = findSessionDir(sessionId, runOpts) || path.join(resolveAttestationRoot(runOpts), sessionId);
  if (!attFile) attFile = path.join(dir, "attestation.json");
  if (!fs.existsSync(attFile)) {
    return emitError(`reattest: no attestation found at ${attFile}`, { session_id: sessionId }, pretty);
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

/**
 * `exceptd attest <subverb> <session-id>` — auditor-facing operations on
 * persisted attestations. Subverbs:
 *   export <session-id>   Emit redacted JSON suitable for audit submission.
 *                         Strips raw artifact values; preserves only
 *                         evidence_hash + signatures + classification + RWEP.
 *                         Falls back to a CSAF-shaped envelope when --format csaf.
 *   verify <session-id>   Verify the .sig sidecar against keys/public.pem.
 *                         Reports signed_by + tamper status.
 *   show <session-id>     Emit the full (unredacted) attestation. Convenience
 *                         alias for `cat .exceptd/attestations/<sid>/attestation.json`.
 */
function cmdAttest(runner, args, runOpts, pretty) {
  const subverb = args._[0];
  const sessionId = args._[1];
  if (!subverb) {
    return emitError("attest: missing subverb. Usage: attest list | show <sid> | export <sid> | verify <sid> | diff <sid>", null, pretty);
  }
  // `list` doesn't require a session-id positional.
  if (subverb === "list") {
    return cmdListAttestations(runner, args, runOpts, pretty);
  }
  if (!sessionId) {
    return emitError(`attest ${subverb}: missing <session-id> positional argument.`, null, pretty);
  }
  const dir = findSessionDir(sessionId, runOpts);
  if (!dir) {
    return emitError(`attest ${subverb}: no session dir for ${sessionId}. Searched: ${resolveAttestationRoot(runOpts)} + .exceptd/attestations/`, { session_id: sessionId }, pretty);
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
  const attestations = files.map(f => {
    try { return JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); }
    catch { return null; }
  }).filter(Boolean);

  if (subverb === "show") {
    emit({ session_id: sessionId, attestations }, pretty);
    return;
  }

  if (subverb === "diff") {
    // `attest diff <session-id> [--against <other-session-id>]` — drift
    // comparison. Without --against, replays current state against prior
    // session (= reattest). With --against, compares two sessions A vs B
    // by evidence_hash + artifact-level field diff.
    if (args.against) {
      const otherDir = findSessionDir(args.against, runOpts);
      if (!otherDir) {
        return emitError(`attest diff --against ${args.against}: no session dir found.`, null, pretty);
      }
      const otherFiles = fs.readdirSync(otherDir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
      if (otherFiles.length === 0) {
        return emitError(`attest diff --against ${args.against}: no attestations under that session id.`, null, pretty);
      }
      const other = JSON.parse(fs.readFileSync(path.join(otherDir, otherFiles[0]), "utf8"));
      const self = attestations[0];
      emit({
        verb: "attest diff",
        a_session: sessionId,
        b_session: args.against,
        a_captured: self.captured_at,
        b_captured: other.captured_at,
        a_evidence_hash: self.evidence_hash,
        b_evidence_hash: other.evidence_hash,
        status: self.evidence_hash === other.evidence_hash ? "unchanged" : "drifted",
        // v0.11.8 (#102): normalize submissions before diffing so flat-shape
        // (observations + verdict) submissions emit meaningful artifact_diff
        // counts. Pre-0.11.8 (self.submission||{}).artifacts was undefined
        // for flat submissions; the diff returned all zeros even when
        // artifacts were present in observations.
        artifact_diff: diffArtifacts(
          normalizedArtifacts(self.submission, runner),
          normalizedArtifacts(other.submission, runner)
        ),
        signal_override_diff: diffSignalOverrides(
          normalizedSignalOverrides(self.submission, runner),
          normalizedSignalOverrides(other.submission, runner)
        ),
      }, pretty);
      return;
    }
    // Fall through to reattest-style replay below by setting subverb to a
    // sentinel and re-dispatching via cmdReattest.
    args._ = [sessionId];
    return cmdReattest(runner, args, {}, pretty);
  }

  if (subverb === "list") {
    return cmdListAttestations(runner, args, {}, pretty);
  }

  if (subverb === "verify") {
    const crypto = require("crypto");
    const pubKeyPath = path.join(PKG_ROOT, "keys", "public.pem");
    const pubKey = fs.existsSync(pubKeyPath) ? fs.readFileSync(pubKeyPath, "utf8") : null;
    const results = files.map(f => {
      const sigPath = path.join(dir, f + ".sig");
      if (!fs.existsSync(sigPath)) return { file: f, signed: false, verified: false, reason: "no .sig sidecar" };
      const sigDoc = JSON.parse(fs.readFileSync(sigPath, "utf8"));
      if (sigDoc.algorithm === "unsigned") return { file: f, signed: false, verified: false, reason: "attestation explicitly unsigned (no private key when written)" };
      if (!pubKey) return { file: f, signed: true, verified: false, reason: "no public key at keys/public.pem to verify against" };
      const content = fs.readFileSync(path.join(dir, f), "utf8");
      try {
        const ok = crypto.verify(null, Buffer.from(content, "utf8"), {
          key: pubKey, dsaEncoding: "ieee-p1363",
        }, Buffer.from(sigDoc.signature_base64, "base64"));
        return { file: f, signed: true, verified: !!ok, reason: ok ? "Ed25519 signature valid" : "Ed25519 signature INVALID — possible post-hoc tampering" };
      } catch (e) {
        return { file: f, signed: true, verified: false, reason: `verify error: ${e.message}` };
      }
    });
    emit({ verb: "attest verify", session_id: sessionId, results }, pretty);
    return;
  }

  if (subverb === "export") {
    // Redaction: strip raw `value` fields from submitted artifacts; preserve
    // captured-state flag, evidence_hash, classification, RWEP, confidence,
    // remediation choice, residual risk acceptance, signature. Auditors get
    // what they need (the verdict + proof of process) without leaking raw
    // captured data (which may contain PII / secret shapes).
    //
    // v0.11.3: --format is registered as multi in parseArgs, so args.format
    // is an array when present. Unwrap for direct comparison.
    let formatRaw = args.format || "json";
    if (Array.isArray(formatRaw)) formatRaw = formatRaw[0];
    const format = formatRaw === "csaf-2.0" ? "csaf" : formatRaw;
    // v0.11.6 (#98): validate against accepted set. Pre-0.11.6 unknown
    // formats fell through to the default redacted JSON output, silently
    // accepting any value the operator passed.
    const VALID_EXPORT_FORMATS = ["json", "csaf", "csaf-2.0"];
    if (!VALID_EXPORT_FORMATS.includes(formatRaw)) {
      return emitError(`attest export: --format "${formatRaw}" not in accepted set ${JSON.stringify(VALID_EXPORT_FORMATS)}.`, null, pretty);
    }
    const redacted = attestations.map(a => ({
      session_id: a.session_id,
      playbook_id: a.playbook_id,
      directive_id: a.directive_id,
      evidence_hash: a.evidence_hash,
      operator: a.operator,
      operator_consent: a.operator_consent,
      captured_at: a.captured_at,
      run_opts: a.run_opts,
      artifacts_redacted: Object.fromEntries(Object.entries((a.submission && a.submission.artifacts) || {})
        .map(([k, v]) => [k, { captured: !!v.captured, reason: v.reason || null, redacted_value: "[redacted]" }])),
      signal_overrides: (a.submission && a.submission.signal_overrides) || {},
      signals_redacted: Object.fromEntries(Object.entries((a.submission && a.submission.signals) || {})
        .filter(([k]) => !/_filter$|_key$|token|secret|password/i.test(k))),
      precondition_checks: (a.submission && a.submission.precondition_checks) || {},
    }));

    if (format === "csaf") {
      // Lightweight CSAF envelope for audit submission — caller can post this
      // directly to a CSAF-aware GRC platform.
      emit({
        document: {
          category: "csaf_security_advisory",
          csaf_version: "2.0",
          publisher: { category: "vendor", name: "exceptd", namespace: "https://exceptd.com" },
          title: `Auditor export — session ${sessionId}`,
          tracking: { id: `exceptd-export-${sessionId}`, status: "final", version: "1", initial_release_date: new Date().toISOString() },
        },
        exceptd_export: { session_id: sessionId, attestations: redacted, exported_at: new Date().toISOString(), redaction_policy: "v0.10.3-default" },
      }, pretty);
    } else {
      emit({
        verb: "attest export",
        session_id: sessionId,
        exported_at: new Date().toISOString(),
        redaction_policy: "v0.10.3-default — artifact values stripped; signal_overrides + precondition_checks + evidence_hash + signature preserved.",
        attestations: redacted,
      }, pretty);
    }
    return;
  }

  return emitError(`attest: unknown subverb "${subverb}". Try export | verify | show.`, null, pretty);
}

/**
 * v0.11.8 (#102): extract normalized artifacts/signal_overrides from a stored
 * attestation submission. Flat-shape submissions store `observations` only;
 * nested submissions store `artifacts` + `signal_overrides`. Returning the
 * canonical nested view of both shapes lets `attest diff` produce meaningful
 * counts regardless of which shape the operator submitted.
 */
function normalizedArtifacts(submission, runner) {
  if (!submission || typeof submission !== "object") return {};
  if (submission.artifacts) return submission.artifacts;
  if (submission.observations) {
    try {
      const norm = runner.normalizeSubmission({ observations: submission.observations }, { _meta: {}, phases: { look: { artifacts: [] } } });
      return norm.artifacts || {};
    } catch { return {}; }
  }
  return {};
}
function normalizedSignalOverrides(submission, runner) {
  if (!submission || typeof submission !== "object") return {};
  if (submission.signal_overrides) return submission.signal_overrides;
  if (submission.observations) {
    try {
      const norm = runner.normalizeSubmission({ observations: submission.observations }, { _meta: {}, phases: { look: { artifacts: [] } } });
      return norm.signal_overrides || {};
    } catch { return {}; }
  }
  return {};
}

/**
 * Per-artifact diff between two submissions. Returns { added, removed, changed }
 * keyed by artifact id. Used by `attest diff` (bug #34 fix) so operators get
 * field-level context instead of a binary evidence_hash signal.
 */
function diffArtifacts(a, b) {
  a = a || {}; b = b || {};
  const allIds = new Set([...Object.keys(a), ...Object.keys(b)]);
  // v0.11.10 (#102): total_compared disambiguates the empty-both case.
  // unchanged_count: 0 + added: 0 + removed: 0 + changed: 0 is ambiguous
  // ("0 unchanged of how many?"); total_compared answers it.
  const out = { total_compared: allIds.size, added: [], removed: [], changed: [], unchanged_count: 0 };
  for (const id of allIds) {
    const av = a[id], bv = b[id];
    if (!av && bv) {
      out.added.push({ id, captured: !!bv.captured, value_preview: previewValue(bv.value) });
    } else if (av && !bv) {
      out.removed.push({ id, captured: !!av.captured, value_preview: previewValue(av.value) });
    } else if (av && bv && JSON.stringify(av) !== JSON.stringify(bv)) {
      out.changed.push({
        id,
        a_captured: !!av.captured, b_captured: !!bv.captured,
        a_value_preview: previewValue(av.value), b_value_preview: previewValue(bv.value),
      });
    } else if (av && bv) {
      // v0.11.8 (#102): both sides have the entry AND they're identical →
      // unchanged. Pre-0.11.8 the unchanged path was unreachable because the
      // !av && bv guards short-circuited when both existed.
      out.unchanged_count++;
    }
  }
  return out;
}

function diffSignalOverrides(a, b) {
  a = a || {}; b = b || {};
  const allIds = new Set([...Object.keys(a), ...Object.keys(b)]);
  const out = { total_compared: allIds.size, changed: [], unchanged_count: 0 };
  for (const id of allIds) {
    if (a[id] !== b[id]) out.changed.push({ id, a: a[id] || null, b: b[id] || null });
    else out.unchanged_count++;
  }
  return out;
}

function previewValue(v) {
  if (v === null || v === undefined) return null;
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 80 ? s.slice(0, 80) + "…" : s;
}

// ---------------------------------------------------------------------------
// v0.11.0: cmdDiscover — context-aware playbook recommender.
// Collapses scan + dispatch + recommend into one verb. Sniffs the cwd, reads
// /etc/os-release on Linux, and outputs a list of recommended playbooks.
// ---------------------------------------------------------------------------
function cmdDiscover(runner, args, runOpts, pretty) {
  const cwd = process.cwd();
  const wantJson = !!args.json || !!args.pretty;
  const indent = !!args.pretty;

  // File-presence sniffer. Each probe is independently fault-tolerant so a
  // permission error on one path can't poison the whole detection.
  const detected = [];
  function probe(rel, label) {
    try {
      if (fs.existsSync(path.join(cwd, rel))) detected.push(label || rel);
    } catch { /* swallow */ }
  }
  probe(".git", ".git/");
  probe("package.json");
  probe("package-lock.json");
  probe("yarn.lock");
  probe("pnpm-lock.yaml");
  probe("pyproject.toml");
  probe("requirements.txt");
  probe("Pipfile");
  probe("Cargo.toml");
  probe("go.mod");
  probe("Dockerfile");
  probe("docker-compose.yml");
  probe("docker-compose.yaml");
  probe("kustomization.yaml");
  probe("k8s", "k8s/");
  probe(".env");
  probe(".envrc");

  // Terraform / IaC — glob the top level for *.tf.
  try {
    const tfFiles = fs.readdirSync(cwd).filter(f => f.endsWith(".tf"));
    if (tfFiles.length) detected.push(`*.tf (${tfFiles.length})`);
  } catch { /* swallow */ }

  // Git remote (best-effort, never fatal).
  let gitRemote = null;
  if (detected.includes(".git/")) {
    try {
      const headPath = path.join(cwd, ".git", "config");
      if (fs.existsSync(headPath)) {
        const cfg = fs.readFileSync(headPath, "utf8");
        const m = cfg.match(/\[remote "origin"\][\s\S]*?url\s*=\s*(\S+)/);
        if (m) gitRemote = m[1];
      }
    } catch { /* swallow */ }
  }

  // Host platform / distro.
  const hostPlatform = process.platform;
  let hostDistro = null;
  if (hostPlatform === "linux") {
    try {
      const res = spawnSync("cat", ["/etc/os-release"], { encoding: "utf8" });
      if (res.status === 0 && res.stdout) {
        const idMatch = res.stdout.match(/^ID=(.+)$/m);
        const verMatch = res.stdout.match(/^VERSION_ID=(.+)$/m);
        const prettyMatch = res.stdout.match(/^PRETTY_NAME=(.+)$/m);
        hostDistro = {
          id: idMatch ? idMatch[1].replace(/^"|"$/g, "") : null,
          version_id: verMatch ? verMatch[1].replace(/^"|"$/g, "") : null,
          pretty_name: prettyMatch ? prettyMatch[1].replace(/^"|"$/g, "") : null,
        };
      }
    } catch { /* swallow */ }
  }

  // Build recommendation set. Dedup by playbook id so multi-trigger rules
  // don't double-list.
  const isRepo = detected.includes(".git/");
  const hasNode = detected.includes("package.json") || detected.includes("package-lock.json")
    || detected.includes("yarn.lock") || detected.includes("pnpm-lock.yaml");
  const hasPython = detected.includes("pyproject.toml") || detected.includes("requirements.txt")
    || detected.includes("Pipfile");
  const hasRust = detected.includes("Cargo.toml");
  const hasGo = detected.includes("go.mod");
  const hasLockfile = hasNode || hasPython || hasRust || hasGo;
  const hasContainers = detected.includes("Dockerfile") || detected.includes("docker-compose.yml")
    || detected.includes("docker-compose.yaml");
  const isLinux = hostPlatform === "linux";

  const recs = [];
  const seen = new Set();
  function recommend(id, reason) {
    if (seen.has(id)) return;
    seen.add(id);
    recs.push({ id, reason });
  }

  if (isRepo && hasLockfile) {
    const langs = [hasNode && "node", hasPython && "python", hasRust && "rust", hasGo && "go"]
      .filter(Boolean).join("/");
    recommend("secrets", `git repo + ${langs} lockfile → check for committed credentials`);
    recommend("sbom", `git repo + ${langs} lockfile → SBOM + supply-chain integrity`);
    recommend("library-author", `git repo + ${langs} lockfile → publisher-side audit`);
    recommend("crypto-codebase", `git repo + ${langs} lockfile → cryptographic primitive review`);
  }
  if (hasContainers) {
    recommend("containers", "Dockerfile / docker-compose present → container security review");
  }
  if (isLinux) {
    recommend("kernel", "Linux host detected → kernel LPE / privilege escalation triage");
    recommend("hardening", "Linux host detected → system hardening review");
    recommend("runtime", "Linux host detected → runtime behavior review");
    recommend("cred-stores", "Linux host detected → credential store review");
  }
  // Always include cross-cutting framework correlation.
  recommend("framework", "cross-cutting: framework correlation always applicable");

  const nextSteps = [
    "exceptd brief <playbook>       # learn what a playbook checks",
    "exceptd run <playbook>          # run it",
    "exceptd run --scope code        # run all code-scoped playbooks (auto-detected)",
    "exceptd ci --scope code         # CI-gate against all code-scoped playbooks",
  ];

  const out = {
    verb: "discover",
    context: {
      cwd,
      git_remote: gitRemote,
      detected_files: detected,
      host_platform: hostPlatform,
      host_distro: hostDistro,
    },
    recommended_playbooks: recs,
    next_steps: nextSteps,
  };

  // --scan-only: also run legacy `scan` and embed under legacy_scan. Use
  // spawnSync against orchestrator/index.js — the orchestrator was designed
  // to be invoked as a subprocess, and isolating it via spawn prevents one
  // bad scanner from killing the whole discover verb.
  if (args["scan-only"]) {
    const orchPath = path.join(PKG_ROOT, "orchestrator", "index.js");
    try {
      const res = spawnSync(process.execPath, [orchPath, "scan", "--json"], {
        encoding: "utf8",
        cwd,
        timeout: 30000,
      });
      if (res.status === 0 && res.stdout) {
        try { out.legacy_scan = JSON.parse(res.stdout); }
        catch { out.legacy_scan = { ok: false, raw: res.stdout.slice(0, 2000), parse_error: true }; }
      } else {
        out.legacy_scan = {
          ok: false,
          exit_code: res.status,
          stderr: (res.stderr || "").slice(0, 2000),
        };
      }
    } catch (e) {
      out.legacy_scan = { ok: false, error: e.message };
    }
  }

  if (wantJson) {
    emit(out, indent);
    return;
  }

  // Default: human-readable text. (v0.11.0 redesign #5 — flipped defaults.)
  const lines = [];
  lines.push("exceptd discover");
  lines.push(`  cwd:            ${cwd}`);
  if (gitRemote) lines.push(`  git remote:     ${gitRemote}`);
  lines.push(`  platform:       ${hostPlatform}${hostDistro && hostDistro.pretty_name ? "  (" + hostDistro.pretty_name + ")" : ""}`);
  lines.push(`  detected:       ${detected.length ? detected.join(", ") : "(nothing recognized)"}`);
  lines.push("");
  lines.push(`Recommended playbooks (${recs.length}):`);
  for (const r of recs) {
    lines.push(`  - ${r.id.padEnd(20)} ${r.reason}`);
  }
  lines.push("");
  lines.push("Next steps:");
  for (const s of nextSteps) lines.push(`  ${s}`);
  if (out.legacy_scan) {
    lines.push("");
    lines.push(`legacy scan: ${out.legacy_scan.ok === false ? "FAILED" : "ok"}`);
  }
  process.stdout.write(lines.join("\n") + "\n");
}

// ---------------------------------------------------------------------------
// v0.11.0: cmdDoctor — one-shot health check.
// Collapses verify + currency + validate-cves + validate-rfcs + signing-status.
// Each subcheck is independently fault-tolerant: a single failure surfaces
// in the JSON but never crashes the verb.
// ---------------------------------------------------------------------------
function cmdDoctor(runner, args, runOpts, pretty) {
  const wantJson = !!args.json || !!args.pretty;
  const indent = !!args.pretty;

  // Selective subchecks. If any of the four flags is passed, run only those.
  // If none are passed, run all four plus signing-status.
  const onlySigs = !!args.signatures;
  const onlyCurrency = !!args.currency;
  const onlyCves = !!args.cves;
  const onlyRfcs = !!args.rfcs;
  const anySelected = onlySigs || onlyCurrency || onlyCves || onlyRfcs;
  const runSigs = !anySelected || onlySigs;
  const runCurrency = !anySelected || onlyCurrency;
  const runCves = !anySelected || onlyCves;
  const runRfcs = !anySelected || onlyRfcs;
  const runSigning = !anySelected;

  const checks = {};
  const issues = [];

  if (runSigs) {
    try {
      const verifyPath = path.join(PKG_ROOT, "lib", "verify.js");
      const res = spawnSync(process.execPath, [verifyPath], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 30000,
      });
      const text = (res.stdout || "") + (res.stderr || "");
      const okMatch = text.match(/(\d+)\/(\d+)\s+skills?\s+passed/i);
      const fpMatch = text.match(/SHA256:\s*([A-Za-z0-9+/=]+)/);
      const ok = res.status === 0;
      checks.signatures = {
        ok,
        skills_passed: okMatch ? Number(okMatch[1]) : null,
        skills_total: okMatch ? Number(okMatch[2]) : null,
        fingerprint_sha256: fpMatch ? fpMatch[1] : null,
        ...(ok ? {} : { exit_code: res.status, raw: text.slice(0, 500) }),
      };
      if (!ok) issues.push("signatures");
    } catch (e) {
      checks.signatures = { ok: false, error: e.message };
      issues.push("signatures");
    }
  }

  if (runCurrency) {
    try {
      const orchPath = path.join(PKG_ROOT, "orchestrator", "index.js");
      const res = spawnSync(process.execPath, [orchPath, "currency", "--json"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 30000,
      });
      let parsed = null;
      if (res.stdout) {
        const m = res.stdout.match(/\{[\s\S]*\}\s*$/);
        if (m) {
          try { parsed = JSON.parse(m[0]); } catch { /* fall through */ }
        }
      }
      if (parsed && Array.isArray(parsed.currency_report)) {
        const stale = parsed.currency_report.filter(s => s.action_required || s.currency_label !== "current");
        const critical = parsed.currency_report.filter(s => s.currency_score !== undefined && s.currency_score < 50);
        const ok = stale.length === 0 && !parsed.action_required;
        checks.currency = {
          ok,
          total_skills: parsed.currency_report.length,
          stale_skills: stale.map(s => s.skill),
          critical_stale: critical.map(s => s.skill),
          critical_count: parsed.critical_count || 0,
        };
        if (!ok) issues.push("currency");
      } else {
        checks.currency = {
          ok: res.status === 0,
          exit_code: res.status,
          raw: (res.stdout || res.stderr || "").slice(0, 500),
          parse_error: true,
        };
        if (res.status !== 0) issues.push("currency");
      }
    } catch (e) {
      checks.currency = { ok: false, error: e.message };
      issues.push("currency");
    }
  }

  if (runCves) {
    try {
      const orchPath = path.join(PKG_ROOT, "orchestrator", "index.js");
      // validate-cves doesn't emit JSON; parse text for row count + drift.
      const res = spawnSync(process.execPath, [orchPath, "validate-cves", "--offline"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 30000,
      });
      const text = (res.stdout || "") + (res.stderr || "");
      const totalMatch = text.match(/(\d+)\s+CVEs?\s+in\s+catalog/i);
      const driftMatch = text.match(/drift[:\s]+(\d+)/i);
      const ok = res.status === 0;
      checks.cves = {
        ok,
        total: totalMatch ? Number(totalMatch[1]) : null,
        drift: driftMatch ? Number(driftMatch[1]) : 0,
        ...(ok ? {} : { exit_code: res.status, raw: text.slice(0, 500) }),
      };
      if (!ok) issues.push("cves");
    } catch (e) {
      checks.cves = { ok: false, error: e.message };
      issues.push("cves");
    }
  }

  if (runRfcs) {
    try {
      const orchPath = path.join(PKG_ROOT, "orchestrator", "index.js");
      const res = spawnSync(process.execPath, [orchPath, "validate-rfcs", "--offline"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 30000,
      });
      const text = (res.stdout || "") + (res.stderr || "");
      const rfcRows = (text.match(/^RFC-\d+/gm) || []).length;
      const driftMatch = text.match(/drift[:\s]+(\d+)/i);
      const ok = res.status === 0;
      checks.rfcs = {
        ok,
        total: rfcRows,
        drift: driftMatch ? Number(driftMatch[1]) : 0,
        ...(ok ? {} : { exit_code: res.status, raw: text.slice(0, 500) }),
      };
      if (!ok) issues.push("rfcs");
    } catch (e) {
      checks.rfcs = { ok: false, error: e.message };
      issues.push("rfcs");
    }
  }

  if (runSigning) {
    try {
      const keyPath = path.join(process.cwd(), ".keys", "private.pem");
      const fallback = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath) || fs.existsSync(fallback);
      // Bug #61 (v0.11.2): signing-status missing key is a real WARNING. The
      // attestation pipeline writes unsigned files when this is absent, which
      // operators reading the attestation later cannot verify for authenticity.
      // The summary line must reflect this — pre-0.11.2 said "all checks green"
      // directly above [!!] private key MISSING. Now: it's a warning that
      // populates summary.warnings_count.
      checks.signing = {
        ok: present, // not green if the key is missing — operators need the nudge
        severity: present ? "info" : "warn",
        private_key_present: present,
        can_sign_attestations: present,
        ...(present ? {} : { hint: "run `node lib/sign.js generate-keypair` (or `exceptd doctor --fix`) to enable attestation signing" }),
      };
    } catch (e) {
      checks.signing = { ok: false, error: e.message };
    }
  }

  // Walk every check and split: errors (severity error/missing/fail) vs warnings
  // (severity warn). all_green is true ONLY when zero errors AND zero warnings.
  const warnList = [];
  const errorList = [];
  for (const [k, v] of Object.entries(checks)) {
    if (v.ok === false) errorList.push(k);
    else if (v.severity === "warn") warnList.push(k);
  }
  const allGreen = errorList.length === 0 && warnList.length === 0;
  const out = {
    verb: "doctor",
    checks,
    summary: {
      all_green: allGreen,
      issues_count: errorList.length,
      warnings_count: warnList.length,
      failed_checks: errorList,
      warning_checks: warnList,
    },
  };

  // v0.11.6 (#97): --fix runs BEFORE the JSON early-return so `exceptd doctor
  // --fix --json` actually fixes (was a no-op pre-0.11.6). Re-runs the
  // signing check after fix so the returned JSON reflects the post-fix state.
  if (args.fix && checks.signing && !checks.signing.private_key_present) {
    process.stderr.write("[doctor --fix] generating Ed25519 keypair via `node lib/sign.js generate-keypair`...\n");
    const r = require("child_process").spawnSync(process.execPath, [path.join(PKG_ROOT, "lib", "sign.js"), "generate-keypair"], {
      stdio: ["ignore", "pipe", "pipe"], cwd: PKG_ROOT,
    });
    if (r.status === 0) {
      // Re-verify the private key is now present so the JSON output reflects
      // the fix.
      const keyPath = path.join(process.cwd(), ".keys", "private.pem");
      const fallback = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath) || fs.existsSync(fallback);
      checks.signing = { ok: present, severity: present ? "info" : "warn", private_key_present: present, can_sign_attestations: present };
      out.checks = checks;
      out.summary.fix_applied = "ed25519_keypair_generated";
      process.stderr.write("[doctor --fix] keypair generated — re-checking signing status.\n");
    } else {
      out.summary.fix_attempted = "ed25519_keypair_generation_failed";
      out.summary.fix_exit_code = r.status;
      process.stderr.write(`[doctor --fix] generation failed (exit=${r.status}); run \`node lib/sign.js generate-keypair\` manually.\n`);
    }
  }

  if (wantJson) {
    emit(out, indent);
    if (!allGreen) process.exitCode = 1;
    return;
  }

  // Default: human checklist. v0.11.0 redesign #5.
  const lines = [];
  lines.push("exceptd doctor");
  function mark(c, render) {
    if (!c) return;
    // Three states: ok / warn / error. Bug #61 (v0.11.2) — warn must not be
    // shown as ok and must count toward the summary so the bottom line
    // matches the visible icons above.
    const icon = c.ok && c.severity !== "warn" ? "[ok]" : (c.severity === "warn" ? "[!! warn]" : "[!! fail]");
    lines.push(`  ${icon} ${render(c)}`);
  }
  mark(checks.signatures, c =>
    c.ok
      ? `skill signatures verified (${c.skills_passed ?? "?"}/${c.skills_total ?? "?"})`
      : `skill signatures FAILED (exit=${c.exit_code ?? "?"})`
  );
  mark(checks.currency, c =>
    c.ok
      ? `skill currency: all green (${c.total_skills ?? "?"} skills)`
      : `skill currency: ${c.stale_skills?.length || "?"} stale, ${c.critical_count ?? 0} critical`
  );
  mark(checks.cves, c =>
    c.ok
      ? `CVE catalog: ${c.total ?? "?"} entries, drift ${c.drift ?? 0}`
      : `CVE catalog FAILED (exit=${c.exit_code ?? "?"})`
  );
  mark(checks.rfcs, c =>
    c.ok
      ? `RFC catalog: ${c.total ?? "?"} entries, drift ${c.drift ?? 0}`
      : `RFC catalog FAILED (exit=${c.exit_code ?? "?"})`
  );
  if (checks.signing) {
    if (checks.signing.private_key_present) {
      lines.push(`  [ok] attestation signing: private key present (.keys/private.pem)`);
    } else {
      lines.push(`  [!!] attestation signing: private key MISSING (.keys/private.pem) — run \`node lib/sign.js generate-keypair\` to enable`);
    }
  }
  lines.push("");
  if (allGreen) {
    lines.push(`summary: all checks green`);
  } else if (errorList.length === 0) {
    lines.push(`summary: ${warnList.length} warning(s) — ${warnList.join(", ")}`);
  } else {
    lines.push(`summary: ${errorList.length} fail / ${warnList.length} warn — fail: ${errorList.join(", ")}; warn: ${warnList.join(", ") || "none"}`);
  }
  process.stdout.write(lines.join("\n") + "\n");
  // v0.11.6 (#97): --fix already ran above the JSON early-return. Echo the
  // applied/attempted state here for human readers.
  if (out.summary.fix_applied) {
    process.stdout.write(`\n[doctor --fix] ${out.summary.fix_applied} — re-run \`exceptd doctor\` to confirm.\n`);
  } else if (out.summary.fix_attempted) {
    process.stdout.write(`\n[doctor --fix] ${out.summary.fix_attempted} (exit=${out.summary.fix_exit_code}); run \`node lib/sign.js generate-keypair\` manually.\n`);
    process.exitCode = 1;
    return;
  }
  if (errorList.length > 0) process.exitCode = 1;
  // Warnings alone do NOT force exit 1 — CI gates use exit 0 to mean "ran
  // successfully" even with informational warnings. Operators reading the
  // visible "[!! warn]" line still see the issue.
}

function cmdListAttestations(runner, args, runOpts, pretty) {
  // Enumerate sessions across both v0.11.0 default root and legacy cwd-
  // relative root, so operators with prior attestations still see them.
  const roots = [resolveAttestationRoot(runOpts), path.join(process.cwd(), ".exceptd", "attestations")];
  const entries = [];
  const seenRoots = new Set();
  for (const root of roots) {
    if (seenRoots.has(root) || !fs.existsSync(root)) continue;
    seenRoots.add(root);
    const sessions = fs.readdirSync(root, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);
    for (const sid of sessions) {
      const sdir = path.join(root, sid);
      const files = fs.readdirSync(sdir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
      for (const f of files) {
        try {
          const j = JSON.parse(fs.readFileSync(path.join(sdir, f), "utf8"));
          if (args.playbook && j.playbook_id !== args.playbook) continue;
          if (args.since && (j.captured_at || "") < args.since) continue;
          entries.push({
            session_id: sid,
            playbook_id: j.playbook_id,
            directive_id: j.directive_id,
            evidence_hash: j.evidence_hash ? j.evidence_hash.slice(0, 16) + "..." : null,
            captured_at: j.captured_at || null,
            attestation_root: root,
            file: path.join(sdir, f),
          });
        } catch { /* skip malformed */ }
      }
    }
  }
  entries.sort((a, b) => (b.captured_at || "").localeCompare(a.captured_at || ""));
  emit({
    ok: true,
    attestations: entries,
    count: entries.length,
    filter: { playbook: args.playbook || null, since: args.since || null },
    roots_searched: [...seenRoots],
  }, pretty, (obj) => {
    // v0.11.6 (#95) human renderer for attest list: one row per session.
    const lines = [`attest list — ${obj.count} attestation(s)`];
    if (obj.count === 0) {
      lines.push(`  (no attestations under ${obj.roots_searched.join(' or ')})`);
      return lines.join("\n");
    }
    lines.push(`  ${"session-id".padEnd(20)}  ${"playbook".padEnd(16)}  ${"captured-at".padEnd(20)}  evidence-hash`);
    lines.push(`  ${"-".repeat(20)}  ${"-".repeat(16)}  ${"-".repeat(20)}  ${"-".repeat(20)}`);
    for (const e of obj.attestations.slice(0, 50)) {
      lines.push(`  ${(e.session_id || "?").padEnd(20)}  ${(e.playbook_id || "?").padEnd(16)}  ${(e.captured_at || "").slice(0, 19).padEnd(20)}  ${e.evidence_hash || ""}`);
    }
    if (obj.count > 50) lines.push(`  … and ${obj.count - 50} more (use --json for full list)`);
    return lines.join("\n");
  });
}

// ---------------------------------------------------------------------------
// v0.11.0 verbs: ai-run, ask, ci
// ---------------------------------------------------------------------------

/**
 * `ai-run <playbook>` — streaming JSONL contract for AI-driven runs.
 *
 * Emits one JSON object per line over stdout as the seven phases progress;
 * reads {"event":"evidence","payload":{observations,verdict}} from stdin
 * once it's announced the await_evidence phase. Designed so a host AI can
 * pipe one bidirectional channel instead of doing brief → look → run as
 * three CLI round-trips with an intermediate evidence file.
 *
 * --no-stream falls back to a single JSON document combining every phase
 * for callers that don't want event-driven I/O (smoke tests, batch jobs).
 */
function cmdAiRun(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) {
    return emitError("ai-run: missing <playbook> positional argument.", null, pretty);
  }
  let pb;
  try { pb = runner.loadPlaybook(playbookId); }
  catch (e) { return emitError(`ai-run: ${e.message}`, { playbook: playbookId }, pretty); }
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) {
    return emitError(`ai-run: playbook ${playbookId} has no directives.`, null, pretty);
  }

  // Compute the informational phases up front — both stream and no-stream
  // modes share them.
  let governPhase, directPhase, lookPhase;
  try {
    governPhase = runner.govern(playbookId, directiveId, runOpts);
    directPhase = runner.direct(playbookId, directiveId);
    lookPhase = runner.look(playbookId, directiveId, runOpts);
  } catch (e) {
    process.stdout.write(JSON.stringify({ event: "error", reason: e.message, phase: "info" }) + "\n");
    process.exit(1);
  }

  const governEvent = {
    phase: "govern",
    playbook_id: playbookId,
    directive_id: directiveId,
    jurisdiction_obligations: governPhase.jurisdiction_obligations || [],
    theater_fingerprints: governPhase.theater_fingerprints || [],
    framework_context: governPhase.framework_context || null,
    skill_preload: governPhase.skill_preload || [],
  };
  const directEvent = {
    phase: "direct",
    threat_context: directPhase.threat_context || null,
    rwep_threshold: directPhase.rwep_threshold || null,
    framework_lag_declaration: directPhase.framework_lag_declaration || null,
    skill_chain: directPhase.skill_chain || [],
    token_budget: directPhase.token_budget || null,
  };
  const lookEvent = {
    phase: "look",
    artifacts_required: (lookPhase.artifacts || []).filter(a => a.required),
    artifacts_optional: (lookPhase.artifacts || []).filter(a => !a.required),
    preconditions: lookPhase.preconditions || [],
    precondition_submission_shape: lookPhase.precondition_submission_shape || null,
    collection_scope: lookPhase.collection_scope || null,
  };
  const submissionShape = {
    observations: {},
    verdict: {},
    note: "Send back as {\"event\":\"evidence\",\"payload\":{\"observations\":{...},\"verdict\":{...}}}.",
  };

  // ----- single-shot path -----
  if (args["no-stream"]) {
    // Read any pre-supplied evidence from stdin OR from --evidence flag.
    let payload = { observations: {}, verdict: {} };
    if (args.evidence) {
      try { payload = readEvidence(args.evidence); }
      catch (e) { return emitError(`ai-run: failed to read --evidence: ${e.message}`, null, pretty); }
    } else if (!process.stdin.isTTY) {
      // Drain stdin for any evidence event.
      try {
        const buf = fs.readFileSync(0, "utf8");
        if (buf.trim()) {
          // Accept either a bare submission object or a single evidence event.
          for (const line of buf.split(/\r?\n/)) {
            const t = line.trim();
            if (!t) continue;
            try {
              const parsed = JSON.parse(t);
              if (parsed && parsed.event === "evidence" && parsed.payload) {
                payload = parsed.payload;
                break;
              }
              // Bare submission fallback.
              if (parsed && (parsed.observations || parsed.artifacts || parsed.signal_overrides)) {
                payload = parsed.observations
                  ? parsed
                  : { observations: { ...(parsed.artifacts || {}), ...(parsed.signal_overrides || {}) }, verdict: parsed.signals || {} };
                break;
              }
            } catch { /* skip non-JSON lines */ }
          }
        }
      } catch { /* stdin empty / unreadable — fall through with empty payload */ }
    }
    const submission = buildSubmissionFromPayload(payload);
    let result;
    try {
      result = runner.run(playbookId, directiveId, submission, runOpts);
    } catch (e) {
      return emitError(`ai-run: runner threw: ${e.message}`, { playbook: playbookId }, pretty);
    }
    if (!result || result.ok === false) {
      process.stderr.write((pretty ? JSON.stringify(result || {}, null, 2) : JSON.stringify(result || {})) + "\n");
      process.exit(1);
    }
    // v0.11.8 (#101): unify ai-run --no-stream shape with `run`. Pre-0.11.8
    // ai-run flattened phases to top-level (`govern`, `direct`, `look`, ...),
    // while `run` nested them under `phases.*`. Operators writing JSONPath
    // queries had to know which verb produced the payload. Now both share
    // `{ok, playbook_id, directive_id, session_id, evidence_hash, phases: {...}}`.
    emit({
      ok: result.ok !== false,
      verb: "ai-run",
      mode: "no-stream",
      playbook_id: playbookId,
      directive_id: directiveId,
      session_id: result.session_id,
      evidence_hash: result.evidence_hash,
      phases: {
        govern: governEvent,
        direct: directEvent,
        look: lookEvent,
        detect: result.phases?.detect || null,
        analyze: result.phases?.analyze || null,
        validate: result.phases?.validate || null,
        close: result.phases?.close || null,
      },
    }, pretty);
    return;
  }

  // ----- streaming path -----
  // Emit info phases immediately, then wait for an evidence event on stdin.
  const writeLine = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");
  writeLine(governEvent);
  writeLine(directEvent);
  writeLine(lookEvent);
  writeLine({ phase: "await_evidence", submission_shape: submissionShape });

  let handled = false;
  let buf = "";

  const handleLine = (line) => {
    if (handled) return;
    let parsed;
    try { parsed = JSON.parse(line); }
    catch (e) {
      writeLine({ event: "error", reason: `invalid JSON on stdin: ${e.message}`, line_preview: line.slice(0, 120) });
      process.exit(1);
    }
    if (!parsed || parsed.event !== "evidence" || !parsed.payload) {
      // Ignore non-evidence chatter so the host AI can interleave its own
      // status events; only an "evidence" event triggers phases 4-7.
      return;
    }
    handled = true;
    const submission = buildSubmissionFromPayload(parsed.payload);
    let result;
    try {
      result = runner.run(playbookId, directiveId, submission, runOpts);
    } catch (e) {
      writeLine({ event: "error", reason: `runner threw: ${e.message}` });
      process.exit(1);
    }
    if (!result || result.ok === false) {
      writeLine({ event: "error", reason: result?.reason || "runner returned ok:false", result });
      process.exit(1);
    }
    writeLine({ phase: "detect", ...result.phases?.detect });
    writeLine({ phase: "analyze", ...result.phases?.analyze });
    writeLine({ phase: "validate", ...result.phases?.validate });
    writeLine({ phase: "close", ...result.phases?.close });
    writeLine({ event: "done", ok: true, session_id: result.session_id, evidence_hash: result.evidence_hash });
    process.exit(0);
  };

  // Handle empty/closed stdin: emit a hint then exit cleanly so AI agents
  // calling ai-run without piping anything see a useful message rather than
  // a hung process.
  if (process.stdin.isTTY) {
    writeLine({ event: "error", reason: "ai-run streaming mode requires evidence on stdin; pipe {\"event\":\"evidence\",\"payload\":{...}} or use --no-stream." });
    process.exit(1);
  }

  process.stdin.on("data", (chunk) => {
    buf += chunk.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) handleLine(line);
    }
  });
  process.stdin.on("end", () => {
    // Final flush — handle a trailing line without a newline.
    const tail = buf.trim();
    if (tail) handleLine(tail);
    if (!handled) {
      // Bug #66 (v0.11.2): stdin closed without an evidence event. Before
      // declaring an error, try to interpret the raw stdin as a bare
      // submission object (the common shell-pipe case where `echo
      // '{...}' | exceptd ai-run secrets` pipes the submission body, not a
      // wrapped event). If it parses as such, run with it and complete the
      // phases. Otherwise emit the helpful error.
      const raw = (process.stdin._consumed || "") || buf;
      const allText = process.stdin._allText;
      if (allText && allText.trim()) {
        try {
          const parsed = JSON.parse(allText.trim());
          if (parsed && (parsed.observations || parsed.artifacts || parsed.signal_overrides || parsed.precondition_checks)) {
            handleLine(JSON.stringify({ event: "evidence", payload: parsed }));
            return;
          }
        } catch { /* fall through to error */ }
      }
      writeLine({ event: "error", reason: "stdin closed without an evidence event. Pipe `{\"event\":\"evidence\",\"payload\":{...}}` for streaming mode, or pass --no-stream + --evidence <file> for single-shot." });
      process.exit(1);
    }
  });

  // Capture stdin for the post-close fallback.
  process.stdin._allText = "";
  process.stdin.on("data", chunk => { process.stdin._allText += chunk.toString(); });
}

/**
 * Coerce a stdin payload into the runner submission shape. Accepts both the
 * v0.11.0 ai-run shape (observations + verdict) and the nested v0.10.x shape
 * (artifacts + signal_overrides + signals) for forward/back compat.
 */
function buildSubmissionFromPayload(payload) {
  if (!payload || typeof payload !== "object") return { artifacts: {}, signal_overrides: {}, signals: {} };
  // Nested v0.10.x shape passthrough.
  if (payload.artifacts || payload.signal_overrides || payload.signals) {
    return {
      artifacts: payload.artifacts || {},
      signal_overrides: payload.signal_overrides || {},
      signals: payload.signals || {},
      precondition_checks: payload.precondition_checks || undefined,
    };
  }
  // v0.11.0 flat shape: observations becomes the artifacts+signal_overrides
  // union (the runner normalises both via normalizeSubmission), verdict
  // becomes signals.
  return {
    artifacts: payload.observations || {},
    signal_overrides: payload.observations || {},
    signals: payload.verdict || {},
    precondition_checks: payload.precondition_checks || undefined,
  };
}

/**
 * `ask "<question>"` — plain-English routing. Scores every playbook by token
 * overlap against domain.name + domain.attack_class + first sentence of
 * phases.direct.threat_context. Returns the top 5 matches with a confidence
 * score (matched tokens / total tokens).
 */
/**
 * `ask "<question>"` — plain-English routing to playbook(s).
 *
 * v0.11.2 rewrite (#58 / #67): the v0.11.0 implementation only indexed
 * domain.name + attack_class + first sentence of threat_context, with a
 * length>3 token filter that dropped short but-meaningful words like "PQC"
 * or "MCP". The richer index now includes:
 *   - playbook id
 *   - domain.name + domain.attack_class
 *   - domain.attack_refs (T-numbers) + atlas_refs (AML-numbers)
 *   - domain.cwe_refs + frameworks_in_scope
 *   - phases.govern.theater_fingerprints[].claim
 *   - phases.direct.threat_context (full, not first sentence)
 *   - phases.direct.framework_lag_declaration
 *   - skill_chain skill names
 *   - phases.look.collection_scope.asset_scope
 *
 * Token filter dropped to length >= 2 (was > 3) so "PQC" / "MCP" / "CI"
 * tokens match. Synonym map handles common operator phrasings ("API
 * keys" → secrets, "supply chain" → sbom / library-author, etc).
 *
 * Threshold: top match must have score >= 1 (was > 0; same). When no
 * playbook scores >= 1, fall back to substring match on playbook ID
 * itself ("secrets" → secrets playbook).
 */
function cmdAsk(runner, args, runOpts, pretty) {
  const question = (args._ || []).join(" ").trim();
  if (!question) {
    return emitError("ask: usage: exceptd ask \"<plain-English question>\"", null, pretty);
  }
  const ids = runner.listPlaybooks();
  const q = question.toLowerCase();

  // Synonym expansion — common operator phrasings → playbook-relevant tokens.
  // Keeps cmdAsk dependency-free; rich enough to cover the 80% of natural
  // queries listed in the operator report.
  const SYNONYMS = {
    "credential": ["secret", "key", "token", "password", "cred"],
    "credentials": ["secret", "key", "token", "password", "cred"],
    "api key": ["secret", "credential"],
    "api keys": ["secret", "credential"],
    "supply chain": ["sbom", "dependency", "vendor", "package", "library", "publish"],
    "supply-chain": ["sbom", "dependency", "vendor", "package", "library", "publish"],
    "npm package": ["sbom", "dependency", "library", "publish"],
    "npm packages": ["sbom", "dependency", "library", "publish"],
    "pqc": ["post-quantum", "quantum", "crypto", "ml-kem", "ml-dsa", "kyber", "dilithium"],
    "quantum": ["pqc", "post-quantum"],
    "audit": ["scan", "review", "check", "validate", "verify"],
    "mcp": ["model context protocol", "tool", "ai-tool"],
    "ai": ["llm", "model", "anthropic", "openai", "claude"],
    "compliance": ["framework", "audit", "soc", "iso", "nist", "gdpr", "dora", "nis2", "regulator"],
    "kernel": ["lpe", "linux", "privilege", "escalation", "cve", "uname"],
    "container": ["docker", "kubernetes", "k8s", "compose", "image"],
    "secret": ["credential", "key", "token", "env", "leak"],
    "secrets": ["credential", "key", "token", "env", "leak", "repo"],
    "config": ["configuration", "settings"],
  };

  // Tokenize question (length >= 2, lowercase) + expand via synonyms.
  const baseTokens = q.split(/\W+/).filter(t => t.length >= 2);
  const expanded = new Set(baseTokens);
  // multi-word synonym keys
  for (const [phrase, syns] of Object.entries(SYNONYMS)) {
    if (q.includes(phrase)) for (const s of syns) expanded.add(s);
  }
  // single-word synonym keys
  for (const t of baseTokens) {
    if (SYNONYMS[t]) for (const s of SYNONYMS[t]) expanded.add(s);
  }
  const tokens = [...expanded];

  const scored = [];
  for (const id of ids) {
    let pb;
    try { pb = runner.loadPlaybook(id); } catch { continue; }
    const haystack = [
      pb._meta?.id || id,
      pb.domain?.name || "",
      pb.domain?.attack_class || "",
      ...(pb.domain?.attack_refs || []),
      ...(pb.domain?.atlas_refs || []),
      ...(pb.domain?.cwe_refs || []),
      ...(pb.domain?.frameworks_in_scope || []),
      ...((pb.phases?.govern?.theater_fingerprints || []).map(t => t.claim || "")),
      ...((pb.phases?.govern?.theater_fingerprints || []).map(t => t.pattern_id || "")),
      pb.phases?.direct?.threat_context || "",
      pb.phases?.direct?.framework_lag_declaration || "",
      ...((pb.phases?.direct?.skill_chain || []).map(s => s.skill || "")),
      pb.phases?.look?.collection_scope?.asset_scope || "",
      pb.phases?.look?.collection_scope?.time_window || "",
    ].join(" ").toLowerCase();
    let score = 0;
    for (const t of tokens) if (haystack.includes(t)) score++;
    // ID match counts double — "secrets" should map to the secrets playbook.
    if (tokens.some(t => (pb._meta?.id || id) === t)) score += 3;
    scored.push({ id: pb._meta?.id || id, score });
  }
  scored.sort((a, b) => b.score - a.score);
  const top = scored.filter(s => s.score > 0).slice(0, 5);

  // v0.11.2: default human-readable; --json for machine.
  if (top.length === 0) {
    const result = {
      verb: "ask",
      question,
      routed_to: [],
      hint: "No playbook matched. Try `exceptd brief --all` to see what's available, or `exceptd discover` to detect what's in your cwd.",
    };
    if (args.json) return emit(result, pretty);
    process.stdout.write(`ask: ${question}\n  no playbook matched.\n  try: exceptd discover  (auto-detect what's in your cwd)\n`);
    return;
  }

  const result = {
    verb: "ask",
    question,
    routed_to: top.map(t => t.id),
    confidence: Math.min(1, top[0].score / Math.max(2, tokens.length)),
    next_step: `exceptd run ${top[0].id}    # or: exceptd brief ${top[0].id} to learn first`,
    full_match_list: top,
  };
  if (args.json) return emit(result, pretty);
  process.stdout.write(`ask: ${question}\n  top match: ${top[0].id} (score ${top[0].score})\n  next: ${result.next_step}\n  alternates: ${top.slice(1).map(t => t.id).join(", ") || "(none)"}\n`);
}

/**
 * `ci [--all|--scope <type>]` — top-level CI gate. Effectively
 * `run --all --ci` packaged as a verb so .github/workflows lines are short.
 *
 * Exit codes:
 *   0   PASS  — no detected findings, no rwep ≥ cap, no clock started (when
 *               --block-on-jurisdiction-clock is set).
 *   2   FAIL  — any of the above tripped.
 */
function cmdCi(runner, args, runOpts, pretty) {
  const scope = args.scope;
  const maxRwep = args["max-rwep"] !== undefined ? Number(args["max-rwep"]) : null;
  const blockOnClock = !!args["block-on-jurisdiction-clock"];

  // v0.11.9 (#115): --required <playbook,playbook,...> takes precedence over
  // --scope and --all. Operators specifying an explicit set get exactly that
  // set, no more, no less. Pre-0.11.9 the flag was silently ignored.
  let ids;
  if (args.required) {
    const requestedRaw = Array.isArray(args.required) ? args.required.join(",") : args.required;
    const requested = requestedRaw.split(",").map(s => s.trim()).filter(Boolean);
    const all = runner.listPlaybooks();
    const unknown = requested.filter(r => !all.includes(r));
    if (unknown.length > 0) {
      return emitError(`ci --required: unknown playbook ID(s) ${JSON.stringify(unknown)}. Known: ${all.join(", ")}.`, null, pretty);
    }
    ids = requested;
  } else if (args.all) {
    ids = runner.listPlaybooks();
  } else if (scope) {
    ids = filterPlaybooksByScope(runner, scope);
    // Always include cross-cutting playbooks regardless of scope choice.
    const cross = filterPlaybooksByScope(runner, "cross-cutting");
    ids = [...new Set([...ids, ...cross])];
    // For code-scope on a repo: also include sbom (system-scope but
    // repo-relevant) so ci output matches discover.
    if (scope === "code" && fs.existsSync(path.join(process.cwd(), ".git"))) {
      const hasLockfile = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "Cargo.lock", "go.sum"]
        .some(f => fs.existsSync(path.join(process.cwd(), f)));
      if (hasLockfile && runner.listPlaybooks().includes("sbom") && !ids.includes("sbom")) {
        ids.push("sbom");
      }
    }
  } else {
    const scopes = detectScopes();
    ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s));
    ids = [...new Set(ids)];
  }
  if (!ids || ids.length === 0) {
    return emitError("ci: no playbooks matched. Pass --all, --scope <type>, or run from a repo/Linux-host context.", null, pretty);
  }

  const sessionId = runOpts.session_id || require("crypto").randomBytes(8).toString("hex");

  // Evidence: --evidence <file> or --evidence-dir <dir>. Both produce a
  // bundle keyed by playbook id; ids without a key get an empty submission.
  let bundle = {};
  if (args.evidence) {
    try { bundle = readEvidence(args.evidence); }
    catch (e) { return emitError(`ci: failed to read --evidence: ${e.message}`, null, pretty); }
  }
  if (args["evidence-dir"]) {
    const dir = args["evidence-dir"];
    if (!fs.existsSync(dir)) {
      return emitError(`ci: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
      try {
        bundle[f.replace(/\.json$/, "")] = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      } catch (e) {
        return emitError(`ci: failed to parse evidence-dir entry ${f}: ${e.message}`, null, pretty);
      }
    }
  }

  const results = [];
  let fail = false;
  let failReasons = [];

  for (const id of ids) {
    let pb;
    try { pb = runner.loadPlaybook(id); }
    catch (e) { results.push({ playbook_id: id, ok: false, error: e.message }); fail = true; continue; }
    const directiveId = (pb.directives[0] && pb.directives[0].id);
    if (!directiveId) {
      results.push({ playbook_id: id, ok: false, error: "no directives" });
      fail = true;
      continue;
    }
    const submission = bundle[id] || {};
    const perOpts = { ...runOpts, session_id: sessionId };
    if (submission.precondition_checks) perOpts.precondition_checks = submission.precondition_checks;
    let result;
    try { result = runner.run(id, directiveId, submission, perOpts); }
    catch (e) { result = { ok: false, error: e.message, playbook_id: id }; }
    results.push(result);
    if (!result || result.ok === false) {
      fail = true;
      failReasons.push(`${id}: blocked (${result?.reason || result?.error || "unknown"})`);
      continue;
    }
    const cls = result.phases?.detect?.classification;
    const rwepBase = result.phases?.analyze?.rwep?.base ?? 0;
    const rwepAdj = result.phases?.analyze?.rwep?.adjusted ?? 0;
    const cap = maxRwep !== null
      ? maxRwep
      : (result.phases?.analyze?.rwep?.threshold?.escalate ?? 90);
    const clockStarted = (result.phases?.close?.notification_actions || [])
      .some(n => n && n.clock_started_at != null);

    if (cls === "detected") {
      fail = true;
      failReasons.push(`${id}: classification=detected`);
    }
    // v0.11.8 (#103): only count RWEP against the cap when the operator's
    // signals actually moved the score, OR classification reached "detected".
    // Pre-0.11.8 a fresh `ci --scope code` run with NO operator evidence
    // failed because catalog-baseline RWEP (e.g. 90 for KEV-listed kernel
    // CVEs) exceeded the default cap (80). That penalized inconclusive runs
    // for catalogue facts the operator hadn't yet weighed in on. Now: only
    // RWEP DELTA (adjusted - base) counts against the cap on inconclusive
    // classifications. Detected runs still fail on absolute RWEP.
    if (cls === "detected" && rwepAdj >= cap) {
      // Already failed above; this branch documents the rationale.
    } else if (cls === "inconclusive" && rwepAdj - rwepBase >= cap) {
      fail = true;
      failReasons.push(`${id}: rwep_delta=${rwepAdj - rwepBase} >= cap=${cap} (classification=inconclusive; operator evidence raised the score)`);
    }
    if (blockOnClock && clockStarted) {
      fail = true;
      failReasons.push(`${id}: jurisdiction clock started`);
    }
  }

  const rwepValues = results.map(r => r.phases?.analyze?.rwep?.adjusted ?? 0);
  const maxRwepObserved = rwepValues.length ? Math.max(...rwepValues) : 0;

  const summary = {
    total: results.length,
    detected: results.filter(r => r.phases?.detect?.classification === "detected").length,
    inconclusive: results.filter(r => r.phases?.detect?.classification === "inconclusive").length,
    not_detected: results.filter(r => ["not_detected", "clean"].includes(r.phases?.detect?.classification)).length,
    blocked: results.filter(r => r && r.ok === false).length,
    max_rwep_observed: maxRwepObserved,
    jurisdiction_clocks_started: results
      .flatMap(r => r.phases?.close?.notification_actions || [])
      .filter(n => n && n.clock_started_at != null).length,
    verdict: fail ? "FAIL" : "PASS",
    fail_reasons: failReasons,
  };

  // v0.11.4 (#72): ci --format <fmt> previously emitted the full bundle
  // regardless of flag. Now honors the same shortcuts as `run --format`:
  //   summary  → one-line JSON of session + verdict + counts
  //   markdown → operator-readable digest
  //   csaf     → CSAF 2.0 envelope wrapping every result
  //   sarif    → SARIF 2.1.0 with results from every playbook
  //   openvex  → OpenVEX statements derived from every playbook's matched_cves
  let formatRaw = args.format;
  if (Array.isArray(formatRaw)) formatRaw = formatRaw[0];
  const fmt = formatRaw === "csaf-2.0" ? "csaf" : formatRaw;
  if (fmt === "summary") {
    emit({ verb: "ci", session_id: sessionId, playbooks_run: ids, summary }, pretty);
  } else if (fmt === "markdown") {
    const lines = [`# exceptd ci summary`, `session-id: ${sessionId}`, `verdict: **${summary.verdict}**`, ``];
    lines.push(`**Playbooks run:** ${summary.total} (${summary.detected} detected, ${summary.inconclusive} inconclusive, ${summary.not_detected} clean, ${summary.blocked} blocked)`);
    lines.push(`**Max RWEP observed:** ${summary.max_rwep_observed}`);
    lines.push(`**Jurisdiction clocks started:** ${summary.jurisdiction_clocks_started}`);
    if (summary.fail_reasons.length) {
      lines.push(``, `## Fail reasons`);
      for (const r of summary.fail_reasons) lines.push(`- ${r}`);
    }
    process.stdout.write(lines.join("\n") + "\n");
  } else if (fmt === "csaf" || fmt === "sarif" || fmt === "openvex") {
    // Aggregate the per-run bundles_by_format if present.
    const bundles = results.map(r => r.phases?.close?.evidence_package?.bundles_by_format?.[fmt === "csaf" ? "csaf-2.0" : fmt]).filter(Boolean);
    emit({ verb: "ci", session_id: sessionId, format: fmt, bundles_count: bundles.length, bundles }, pretty);
  } else if (fmt && fmt !== "json") {
    // v0.11.4 (#76): garbage format rejected with structured error, not silent empty stdout.
    process.stderr.write(JSON.stringify({ ok: false, error: `ci: --format "${fmt}" not in accepted set ["summary","markdown","csaf-2.0","sarif","openvex","json"].`, verb: "ci" }) + "\n");
    process.exit(2);
  } else {
    emit({ verb: "ci", session_id: sessionId, playbooks_run: ids, summary, results }, pretty);
  }
  if (fail) {
    process.stderr.write(`[exceptd ci] FAIL: ${failReasons.join("; ")}\n`);
    // v0.11.11: use exitCode + return instead of process.exit() so the
    // structured stdout JSON has a chance to flush when stdout is piped.
    // process.exit() can truncate buffered async stdout writes.
    process.exitCode = 2;
    return;
  }
  // v0.11.10 (#100): ci exits non-zero when NO evidence was supplied AND
  // every playbook returned inconclusive. Pre-0.11.10 this exited 0,
  // conflating "ran clean" with "never ran." Operators forgot --evidence /
  // --evidence-dir and assumed a green CI = real coverage. Now: surface
  // the gap loudly.
  const suppliedEvidence = args.evidence || args["evidence-dir"];
  const allInconclusive = summary.inconclusive === summary.total && summary.total > 0;
  if (!suppliedEvidence && allInconclusive) {
    process.stderr.write(`[exceptd ci] WARN: no --evidence supplied and all ${summary.total} playbook(s) returned inconclusive. CI exit 3 = "ran but never had real data." Pass --evidence <file> or --evidence-dir <dir> for a real gate.\n`);
    process.exitCode = 3;
  }
}

if (require.main === module) main();

module.exports = { COMMANDS, PKG_ROOT, PLAYBOOK_VERBS };
