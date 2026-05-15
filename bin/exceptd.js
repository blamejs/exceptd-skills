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

// Centralised exit-code constants + id validators + flag-typo suggester.
// Replacing the prior bare-numbers + inline-regex pattern with named
// constants so a new verb cannot regress the exit-code contract by typo,
// and so the help-text dump (`doctor --exit-codes`) and the runtime
// behavior share the same source of truth.
const { EXIT_CODES, listExitCodes } = require(path.join(PKG_ROOT, "lib", "exit-codes.js"));
const { validateIdComponent } = require(path.join(PKG_ROOT, "lib", "id-validation.js"));
const { suggestFlag, flagsFor } = require(path.join(PKG_ROOT, "lib", "flag-suggest.js"));

/**
 * Factor the EXPECTED_FINGERPRINT pin check used by
 * the attestation pipeline. Centralizes the policy (compute live SHA-256
 * fingerprint of the loaded public.pem, compare to keys/EXPECTED_FINGERPRINT,
 * honor KEYS_ROTATED=1 bypass, tolerate missing pin file) so every site
 * that loads keys/public.pem applies the same check.
 *
 * Returns null when the check passes (or when no pin file exists), or a
 * human-readable error string when the pin diverges and the rotation env
 * is not set. lib/verify.js exposes a parallel checkExpectedFingerprint()
 * that operates on a precomputed fingerprint shape; this wrapper accepts
 * the raw PEM directly so callers don't have to compute the fingerprint
 * themselves.
 */
function assertExpectedFingerprint(pubKeyPem) {
  if (!pubKeyPem) return null;
  const cryptoMod = require("crypto");
  const pinPath = path.join(PKG_ROOT, "keys", "EXPECTED_FINGERPRINT");
  if (!fs.existsSync(pinPath)) return null;
  let liveFp;
  try {
    const ko = cryptoMod.createPublicKey(pubKeyPem);
    const der = ko.export({ type: "spki", format: "der" });
    liveFp = "SHA256:" + cryptoMod.createHash("sha256").update(der).digest("base64");
  } catch (e) {
    return `EXPECTED_FINGERPRINT check: failed to derive live fingerprint: ${e.message}`;
  }
  // Route through the shared lib/verify loader so a BOM-prefixed pin file
  // (Notepad with files.encoding=utf8bom) is tolerated identically across
  // every verify site. The helper strips leading U+FEFF + ignores comment
  // lines.
  const { loadExpectedFingerprintFirstLine } = require(path.join(PKG_ROOT, "lib", "verify.js"));
  const firstLine = loadExpectedFingerprintFirstLine(pinPath) || "";
  if (firstLine === liveFp) return null;
  if (process.env.KEYS_ROTATED === "1") {
    process.emitWarning(
      `EXPECTED_FINGERPRINT mismatch accepted via KEYS_ROTATED=1: live=${liveFp} pin=${firstLine}. ` +
      `Update keys/EXPECTED_FINGERPRINT to lock the new pin.`,
      { code: 'EXCEPTD_KEYS_ROTATED_OVERRIDE' }
    );
    return null;
  }
  return (
    `EXPECTED_FINGERPRINT mismatch: live=${liveFp} pin=${firstLine}. ` +
    `If this is an intentional rotation, re-run with KEYS_ROTATED=1 and ` +
    `update keys/EXPECTED_FINGERPRINT.`
  );
}

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
  "refresh-network": () => path.join(PKG_ROOT, "lib", "refresh-network.js"),
  "refresh-curate":  () => path.join(PKG_ROOT, "lib", "cve-curation.js"),
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
  // v0.10.x legacy verbs — kept as aliases with deprecation banner, scheduled for removal in v0.13:
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

v0.12.0 canonical surface
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
                             --upstream-check       (v0.11.14) opt-in registry freshness
                                                    check before detect; warns if local
                                                    catalog is behind latest published
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
                             --registry-check       (v0.11.14) opt-in: query npm registry
                                                    for latest published version + days behind

  ci                         One-shot CI gate. Exit codes: 0 PASS, 1 framework error,
                             2 detected/escalate, 3 ran-but-no-evidence,
                             4 blocked (ok:false), 5 jurisdiction clock started.
                             (Codes 6/7/8/9 surface on attest verify / run /
                             ai-run / ingest, not ci.)
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
                             --network              (v0.11.14) fetch latest signed
                                                    catalog snapshot from npm registry,
                                                    verify against local keys/public.pem,
                                                    swap data/ in place (no CLI/lib reload)
                             --advisory <id>        (v0.12.0) seed a catalog entry from a
                                                    CVE-* or GHSA-* ID via GitHub Advisory
                                                    Database. Writes draft with
                                                    _auto_imported:true. Use --apply to
                                                    write to disk.
                             --curate <CVE-ID>      (v0.12.0) emit editorial questions +
                                                    ranked candidates (ATLAS/ATT&CK/CWE/
                                                    framework gaps) for a draft entry.
                             --prefetch             populate offline cache
                             --from-cache           consume offline cache
                             --indexes-only         rebuild indexes only
                             Sources: kev|epss|nvd|rfc|pins|ghsa (v0.12.0).
                                                    ghsa drafts pass validator as warnings.

v0.10.x compatibility (will be removed in v0.13)
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

Unknown verbs exit 2 with a structured ok:false body on stderr.

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
    // v0.11.14 (#130): `path copy` was silently consuming the `copy` arg and
    // printing the path. Operators on Windows / Linux saw no clipboard write.
    // Now: implement clipboard copy on the three host platforms (clip on
    // Windows, pbcopy on macOS, xclip|wl-copy|xsel on Linux). If no usable
    // tool is found, fall through to print + stderr-warn (so STDOUT still
    // gives the path for shell consumers like `cd "$(exceptd path)"`).
    const wantCopy = rest.includes("copy") || rest.includes("--copy");
    if (wantCopy) {
      const { spawnSync } = require("child_process");
      const platform = process.platform;
      const candidates = platform === "win32" ? [["clip"]]
        : platform === "darwin" ? [["pbcopy"]]
        : [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-bi"]];
      let copied = false;
      let tried = [];
      for (const [bin, ...argv] of candidates) {
        tried.push(bin);
        const res = spawnSync(bin, argv, { input: PKG_ROOT, encoding: "utf8" });
        if (res.status === 0 && !res.error) { copied = true; break; }
      }
      if (copied) {
        process.stderr.write(`[exceptd path] copied to clipboard: ${PKG_ROOT}\n`);
        process.stdout.write(PKG_ROOT + "\n");
        process.exit(0);
      }
      process.stderr.write(`[exceptd path] copy: no clipboard tool available (tried: ${tried.join(", ")}). Path printed to stdout instead.\n`);
      process.stdout.write(PKG_ROOT + "\n");
      process.exit(0);
    }
    process.stdout.write(PKG_ROOT + "\n");
    process.exit(0);
  }

  // v0.12.8: emit the deprecation banner BEFORE branching on PLAYBOOK_VERBS
  // so that legacy aliases routed through STANDALONE_VERBS or the orchestrator
  // (scan, dispatch, currency, verify, validate-cves, validate-rfcs,
  // watchlist, prefetch, build-indexes) also surface the rename.
  // Previously the banner only fired for PLAYBOOK_VERBS-resident aliases
  // (plan, govern, direct, look, ingest, reattest, list-attestations).
  if (LEGACY_VERB_REPLACEMENTS[cmd] && !process.env.EXCEPTD_DEPRECATION_SHOWN) {
    const ver = readPkgVersion();
    const haveBrief = ver !== "unknown" && ver.match(/^(\d+)\.(\d+)/) && (parseInt(RegExp.$1, 10) > 0 || parseInt(RegExp.$2, 10) >= 11);
    process.stderr.write(
      `[exceptd] DEPRECATION: \`${cmd}\` is a v0.10.x verb. ` +
      (haveBrief
        ? `Prefer \`${LEGACY_VERB_REPLACEMENTS[cmd]}\` (available in this install, v${ver}). `
        : `Upgrade to v0.11.0+ then use \`${LEGACY_VERB_REPLACEMENTS[cmd]}\` (currently installed: v${ver}). `) +
      `Legacy verbs remain functional through this release; they will be removed in v0.13. ` +
      `Suppress: export EXCEPTD_DEPRECATION_SHOWN=1.\n`
    );
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
  }

  // Seven-phase playbook verbs run in-process — they emit JSON to stdout
  // rather than dispatch to a script.
  if (PLAYBOOK_VERBS.has(cmd)) {
    dispatchPlaybook(cmd, rest);
    return;
  }

  // v0.11.2 bug #65: `refresh --no-network` / `refresh --indexes-only` were
  // documented as the v0.11.0 replacements for `prefetch` / `build-indexes`
  // but the underlying refresh script doesn't know those flags. Translate
  // here so the deprecation pointer actually works.
  let effectiveCmd = cmd;
  let effectiveRest = rest;
  if (cmd === "refresh" && (rest.includes("--no-network") || rest.includes("--prefetch"))) {
    // v0.11.14 (#129): --prefetch is the operator-facing name for the
    // cache-population path. --no-network retained as alias for back-compat.
    //
    // v0.12.16: BUT — `refresh --no-network` previously stripped BOTH flags
    // before invoking prefetch.js, leaving prefetch in network-fetching
    // (default) mode. The operator's "do not touch the network" intent was
    // lost in dispatch. Ubuntu CI passed because cached data was warm;
    // Windows + macOS CI runners with cold caches hit 30s test timeout
    // attempting 47 real fetches. Preserve `--no-network` when the operator
    // explicitly supplied it; strip only `--prefetch` (the alias).
    effectiveCmd = "prefetch";
    const wantedNoNetwork = rest.includes("--no-network");
    effectiveRest = rest.filter(a => a !== "--prefetch");
    if (wantedNoNetwork && !effectiveRest.includes("--no-network")) {
      // Already preserved; no-op. But explicit so a future filter regression
      // is visible.
    }
  } else if (cmd === "refresh" && rest.includes("--indexes-only")) {
    effectiveCmd = "build-indexes";
    effectiveRest = rest.filter(a => a !== "--indexes-only");
  } else if (cmd === "refresh" && rest.includes("--network")) {
    // v0.11.14: --network fetches a fresh signed catalog snapshot from the
    // maintainer's npm-published tarball, verifies signatures against the
    // public key already shipped in the operator's install, and swaps
    // data/ in place. Same trust boundary as `npm update -g`; fresher
    // data slice without requiring a full package upgrade.
    effectiveCmd = "refresh-network";
    effectiveRest = rest.filter(a => a !== "--network");
  } else if (cmd === "refresh" && rest.includes("--curate")) {
    // v0.12.0: --curate <CVE-ID> emits editorial questions + ranked
    // candidates (atlas/attack/cwe/framework) for a draft catalog entry.
    // Operator or AI assistant fills the null editorial fields.
    effectiveCmd = "refresh-curate";
    effectiveRest = rest;
  }

  const resolver = COMMANDS[effectiveCmd];
  if (typeof resolver !== "function") {
    // Emit a structured JSON error matching the seven-phase verbs so operators
    // piping through `jq` get one consistent shape across the CLI surface.
    // emitError() sets exitCode + returns rather than calling process.exit()
    // so the stderr JSON drains before teardown; promote the exit code to 2
    // afterwards (unknown-command remains a distinct exit class).
    emitError(`unknown command "${cmd}"`, { hint: "Run `exceptd help` for the list of verbs.", verb: cmd });
    process.exitCode = 2;
    return;
  }

  const script = resolver();
  if (!fs.existsSync(script)) {
    // emitError + exitCode rather than stderr + exit() so the JSON drains.
    emitError(
      `command "${cmd}" not available — expected ${path.relative(PKG_ROOT, script)} in the installed package.`,
      { verb: cmd }
    );
    process.exitCode = 2;
    return;
  }

  // Orchestrator subcommands need the subcommand name preserved as argv[0]
  // for orchestrator/index.js's switch statement.
  const finalArgs = ORCHESTRATOR_PASSTHROUGH.has(effectiveCmd) ? [script, effectiveCmd, ...effectiveRest] : [script, ...effectiveRest];
  const res = spawnSync(process.execPath, finalArgs, { stdio: "inherit", cwd: PKG_ROOT });
  if (res.error) {
    // emitError + exitCode rather than stderr + exit() so the JSON drains.
    emitError(`failed to run ${cmd}: ${res.error.message}`, { verb: cmd });
    process.exitCode = 2;
    return;
  }
  // Propagate the child's exit status via exitCode so any buffered output
  // from the child (rare with stdio:"inherit", possible on Windows) gets
  // a chance to drain before the parent tears down.
  process.exitCode = typeof res.status === "number" ? res.status : 1;
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
  //
  // v0.11.13 (#127): emit() now ALSO sets process.exitCode = 1 when the body
  // carries `ok: false` at top level (unless a caller already set a different
  // non-zero exitCode). Pre-0.11.13 verbs that emitted ok:false to stdout
  // without explicitly setting the exit code returned 0, defeating `set -e`
  // and CI gates. The previous fix was per-verb; this is a universal catch
  // so new verbs / new ok:false paths can't regress the contract.
  if (obj && obj.ok === false && !process.exitCode) {
    process.exitCode = 1;
  }
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
  // v0.12.14: the v0.11.13 emit() fix used exitCode + return
  // to defend stdout-buffered writes from truncation under piped consumers.
  // emitError() (stderr) kept process.exit(1), which has the same truncation
  // class — CLAUDE.md's "fix the class, not the instance." Now: write to
  // stderr, set exitCode = 1, return. Every caller already uses
  // `return emitError(...)` so the return-value propagation is clean.
  const body = Object.assign({ ok: false, error: msg }, extra || {});
  const s = pretty ? JSON.stringify(body, null, 2) : JSON.stringify(body);
  process.stderr.write(s + "\n");
  process.exitCode = 1;
}

/**
 * Shared BOM-tolerant JSON file reader. Windows tools commonly emit
 * UTF-8-BOM (EF BB BF) or UTF-16 LE/BE (FF FE / FE FF). The default
 * `fs.readFileSync(path, "utf8")` chokes on the leading 0xFEFF (UTF-8-BOM
 * becomes a literal BOM codepoint that `JSON.parse` refuses) and decodes
 * UTF-16 as garbage. Route every operator-supplied JSON file through here.
 *
 *   1. read as Buffer
 *   2. detect BOM (UTF-16 LE / BE / UTF-8 BOM)
 *   3. decode appropriately, strip leading BOM if present
 *   4. JSON.parse
 *
 * On parse failure, throw a clean message that preserves the operator-facing
 * path but does NOT leak the raw V8 parser stack — operators see "failed to
 * parse JSON at <path>: <reason>", not a 12-line trace.
 */
function readJsonFile(filePath) {
  let buf;
  try { buf = fs.readFileSync(filePath); }
  catch (e) { throw new Error(`failed to read ${filePath}: ${e.message}`); }
  let text;
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    text = buf.slice(2).toString("utf16le");
  } else if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    // UTF-16 BE: Node has no native decoder. Swap byte pairs to LE, then decode.
    //
    // refuse odd-length payloads up front rather than carry
    // the trailing byte through a partial swap. A UTF-16BE payload by
    // definition has an even byte count after the BOM; odd-length input is
    // either truncated or not UTF-16BE at all.
    //
    // use Buffer.alloc (zero-initialised) instead of
    // Buffer.allocUnsafe so an unexpected loop bound never lets uninitialised
    // heap bytes leak into the decoded string and downstream JSON.parse
    // error message.
    const payloadLength = buf.length - 2;
    if (payloadLength % 2 !== 0) {
      throw new Error(`failed to read ${filePath}: UTF-16BE payload must have an even byte count after BOM; got ${payloadLength} bytes — file may be truncated.`);
    }
    const swapped = Buffer.alloc(payloadLength);
    for (let i = 2; i < buf.length - 1; i += 2) {
      swapped[i - 2] = buf[i + 1];
      swapped[i - 1] = buf[i];
    }
    text = swapped.toString("utf16le");
  } else if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    text = buf.slice(3).toString("utf8");
  } else {
    text = buf.toString("utf8");
  }
  // Belt-and-braces: strip any residual leading U+FEFF the decode may have left.
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  try { return JSON.parse(text); }
  catch (e) {
    throw new Error(`failed to parse JSON at ${filePath}: ${e.message}`);
  }
}

function readEvidence(evidenceFlag) {
  if (!evidenceFlag) return {};
  if (evidenceFlag === "-") {
    const buf = fs.readFileSync(0, "utf8"); // stdin
    if (!buf.trim()) return {};
    return JSON.parse(buf);
  }
  // v0.12.12: read enforces a max size to defend against an operator
  // accidentally passing a multi-gigabyte file (binary, log, or
  // adversarial JSON bomb). 32 MB is well beyond any legitimate
  // submission and still drains in a single read on modern hardware.
  const MAX_EVIDENCE_BYTES = 32 * 1024 * 1024;
  let stat;
  try { stat = fs.statSync(evidenceFlag); }
  catch (e) { throw new Error(`evidence path not readable: ${e.message}`); }
  if (stat.size > MAX_EVIDENCE_BYTES) {
    throw new Error(`evidence file too large: ${stat.size} bytes > ${MAX_EVIDENCE_BYTES} byte limit. Reduce the submission or split into multiple playbook runs.`);
  }
  // Route through readJsonFile() for UTF-8-BOM / UTF-16 tolerance.
  // Windows-tool-emitted JSON commonly carries these markers; the raw "utf8"
  // decode in readFileSync chokes on the leading 0xFEFF.
  return readJsonFile(evidenceFlag);
}

function loadRunner() {
  return require(path.join(PKG_ROOT, "lib", "playbook-runner.js"));
}

/**
 * Detect whether stdin actually has data without blocking.
 *
 * `!process.stdin.isTTY` (the previous heuristic) fires when isTTY is
 * `false`, `undefined`, OR `null`. Test harnesses with custom stdin
 * duplexers (Mocha/Jest, some Docker stdin-passthrough wrappers) leave
 * isTTY === undefined but never write any bytes — falling into
 * `fs.readFileSync(0, "utf8")` then BLOCKS waiting for an EOF that
 * never arrives.
 *
 * Strategy:
 *
 *   1. If isTTY is truthy → operator is at a terminal, never read stdin.
 *   2. POSIX: trust isFIFO / isSocket / isCharacterDevice. Regular file
 *      requires size > 0 (empty file redirection should not be treated
 *      as piped input).
 *   3. Windows: `isTTY === false` strict (filters out wrapped test
 *      duplexers which leave isTTY === undefined). DO NOT gate on size
 *      because Windows pipes report as regular files with size 0 even
 *      when bytes are queued — gating would silently skip every
 *      `echo {...} | exceptd run` invocation.
 *   4. If a wrapped test harness on Windows does want stdin auto-read
 *      to skip, the harness must set `process.stdin.isTTY = undefined`
 *      explicitly (Mocha/Jest do this by default).
 *
 * Returns `true` if the caller may safely fs.readFileSync(0) without
 * risking an indefinite block on a wrapped empty stream.
 */
function hasReadableStdin() {
  if (process.stdin.isTTY) return false;
  let st;
  try { st = fs.fstatSync(0); }
  catch {
    // fstat failed — on Windows require `isTTY === false` STRICTLY (not
    // falsy). A non-strict check returns true when isTTY is undefined (e.g.
    // Mocha/Jest test harnesses with a wrapped duplexer on Windows), which
    // causes fs.readFileSync(0) to block indefinitely waiting on an EOF
    // that never arrives. MSYS-bash piping on win32 sets isTTY === false,
    // so the strict check still admits genuine piped input.
    if (process.platform === "win32") return process.stdin.isTTY === false;
    return false;
  }
  // POSIX pipes / FIFOs / sockets / character devices report size 0
  // even when bytes are queued (or about to be). Trust them — a real
  // `echo '{...}' | exceptd run` pipeline lands here, and readFileSync(0)
  // will read to EOF cleanly. If the write end is open and no bytes
  // arrive, the read blocks — that's the operator's contract, not the
  // CLI's to second-guess. Wrapped test harnesses that never write
  // should pass `--evidence -` explicitly.
  if (typeof st.isFIFO === "function" && st.isFIFO()) return true;
  if (typeof st.isSocket === "function" && st.isSocket()) return true;
  if (typeof st.isCharacterDevice === "function" && st.isCharacterDevice()) return true;
  // Regular file (e.g. `exceptd run <evidence.json` shell redirect).
  // size 0 here means a legitimately empty file.
  if (typeof st.size === "number" && st.size > 0) return true;
  // Windows fallback: pipes don't surface as FIFOs via fstat on win32
  // (they appear as regular files with size 0 even when bytes queued).
  // Trust isTTY === false strictly — that filters out wrapped test
  // duplexers (which leave isTTY === undefined) while keeping cmd.exe /
  // PowerShell / MSYS pipes working (isTTY === false when piped). Do NOT
  // gate on size > 0 here: a Windows pipe with bytes queued reports as
  // a regular file with size 0, and gating would silently skip every
  // `echo {...} | exceptd run|ingest|ai-run` invocation.
  if (process.platform === "win32" && process.stdin.isTTY === false) return true;
  return false;
}

/**
 * ISO-8601 shape regex applied BEFORE Date.parse for --since flags. Without
 * the regex check, bare integers like "99" coerce through Date.parse to
 * 1999-12-01T00:00:00Z (two-digit-year heuristic), silently filtering the
 * wrong years. Requires an explicit calendar-date shape (YYYY-MM-DD with
 * optional time component) before handing to Date.parse.
 *
 * Returns null on success; returns the human-facing error message string
 * on failure so the caller can wrap it with its own verb prefix.
 */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;
function validateIsoSince(raw) {
  if (typeof raw !== "string" || !ISO_DATE_RE.test(raw) || isNaN(Date.parse(raw))) {
    return `--since must be a parseable ISO-8601 calendar timestamp (e.g. 2026-05-01 or 2026-05-01T00:00:00Z). Got: ${JSON.stringify(String(raw)).slice(0, 80)}`;
  }
  return null;
}

/**
 * Detect whether a parsed JSON document is plausibly CycloneDX VEX or
 * OpenVEX. The runner's vexFilterFromDoc returns Set(0) tolerantly for
 * anything else, which means an operator who passes SARIF / SBOM / CSAF /
 * advisory JSON by mistake gets zero filter + zero feedback. We pre-validate
 * at the CLI layer so the operator finds out at flag parse time.
 *
 * Returns { ok, detected, top_level_keys[] }. `detected` is one of:
 *   "cyclonedx-vex" | "openvex" | "not-vex"
 */
function detectVexShape(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { ok: false, detected: "not-an-object", top_level_keys: [] };
  }
  const keys = Object.keys(doc);
  // CycloneDX VEX: bomFormat==="CycloneDX" + vulnerabilities[] is the
  // canonical shape; CycloneDX 1.4+ also allows a standalone vulnerabilities
  // document where entries carry analysis.state. Accept either when the
  // entries look vex-shaped (have id/bom_ref/analysis).
  if (Array.isArray(doc.vulnerabilities)) {
    const isBom = doc.bomFormat === "CycloneDX";
    const specStr = typeof doc.specVersion === "string" ? doc.specVersion : "";
    const hasCyclonedxMarker = isBom || specStr.startsWith("1.");
    // Empty vulnerabilities arrays cannot vouch for CycloneDX shape on their
    // own — `{"bomFormat":"NOT-CycloneDX","vulnerabilities":[]}` would
    // otherwise pass because `length === 0` trivially satisfies
    // `entriesLookVex`. Require a real CycloneDX marker (bomFormat or
    // specVersion) when the array is empty; non-empty arrays still pass when
    // any entry has vex-shaped fields (id / bom-ref / analysis).
    if (doc.vulnerabilities.length === 0) {
      if (hasCyclonedxMarker) {
        return { ok: true, detected: "cyclonedx-vex", top_level_keys: keys };
      }
      return { ok: false, detected: "empty-vulnerabilities-without-cyclonedx-marker", top_level_keys: keys };
    }
    const entriesLookVex = doc.vulnerabilities.some(v => v && typeof v === "object" && (v.id || v["bom-ref"] || v.bom_ref || v.analysis));
    if (isBom || entriesLookVex) {
      return { ok: true, detected: "cyclonedx-vex", top_level_keys: keys };
    }
  }
  // OpenVEX: @context starts with https://openvex.dev AND statements[]
  const ctx = doc["@context"];
  const ctxStr = Array.isArray(ctx) ? ctx[0] : ctx;
  if (typeof ctxStr === "string" && ctxStr.startsWith("https://openvex.dev") && Array.isArray(doc.statements)) {
    return { ok: true, detected: "openvex", top_level_keys: keys };
  }
  // Common false-positive shapes — give the operator a hint.
  if (Array.isArray(doc.runs) && doc.$schema && String(doc.$schema).includes("sarif")) {
    return { ok: false, detected: "sarif-not-vex", top_level_keys: keys };
  }
  if (doc.document && doc.document.category && String(doc.document.category).startsWith("csaf_")) {
    return { ok: false, detected: "csaf-advisory-not-vex", top_level_keys: keys };
  }
  // A CycloneDX SBOM with no `vulnerabilities` key is a legitimate "0-CVE
  // VEX filter" submission — the operator is asserting nothing here is
  // exploitable. Accept it as cyclonedx-vex with an empty filter set (the
  // runner's vexFilterFromDoc returns Set(0) for the same shape). Same logic
  // for documents that carry a CycloneDX-flavored specVersion ("1.x") without
  // bomFormat — Windows tooling sometimes drops the marker on export.
  const cyclonedxMarker =
    doc.bomFormat === "CycloneDX" ||
    (typeof doc.specVersion === "string" && /^1\./.test(doc.specVersion));
  if (cyclonedxMarker && !Array.isArray(doc.vulnerabilities)) {
    return { ok: true, detected: "cyclonedx-vex-zero-cve", top_level_keys: keys };
  }
  if (Array.isArray(doc.statements) && !ctxStr) {
    return { ok: false, detected: "statements-array-but-no-openvex-context", top_level_keys: keys };
  }
  return { ok: false, detected: "unrecognized", top_level_keys: keys };
}

function firstDirectiveId(runner, playbookId) {
  // Defense-in-depth: callers that touch this helper directly (test
  // harnesses, library consumers) still get path-traversal refusal.
  const r = validateIdComponent(playbookId, "playbook");
  if (!r.ok) throw new Error(`invalid playbook id (${r.reason}): ${typeof playbookId === "string" ? playbookId.slice(0, 80) : typeof playbookId}`);
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
            "force-replay",
            "json-stdout-only", "fix", "human", "json", "strict-preconditions",
            // v0.12.9: doctor --shipped-tarball runs the verify-shipped-tarball
            // gate alongside --signatures. doctor --registry-check + --signatures
            // were already accepted; explicit registration removes the silent
            // "unknown bool flag" surface in parseArgs.
            "shipped-tarball", "registry-check", "signatures", "currency", "cves", "rfcs",
            // doctor --exit-codes dumps the canonical exit-code table.
            "exit-codes"],
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

  // Flag-typo defense: anything supplied by the operator that isn't on the
  // verb's allowlist gets a Levenshtein suggestion + immediate refusal.
  // Pre-fix, `exceptd run --evidnce ev.json` silently absorbed --evidnce as
  // a boolean flag and produced a cryptic downstream error when the runner
  // got no evidence. Now: refuse at the dispatcher with the suggested
  // correct flag so operators see the typo before any side effects run.
  //
  // Ignore parser-internal scratch keys (`_jsonMode`, leading-underscore) +
  // the bare-positional bucket (`_`). REQUIRES_VALUE catches the
  // value-bearing flags that parsed as boolean true (i.e. the operator
  // forgot the value).
  // Value-bearing flags only. Boolean flags (--ack, --latest, --force-replay,
  // --force-stale, --ci, --pretty, etc.) are intentionally absent because
  // their `true` parse is the canonical operator intent.
  const REQUIRES_VALUE = new Set([
    "evidence", "evidence-dir", "session-id", "operator", "csaf-status",
    "publisher-namespace", "mode", "scope", "playbook", "phase", "tlp",
    "against", "since", "bundle-epoch", "attestation-root", "format",
  ]);
  const verbAllowlist = flagsFor(cmd);
  const allowlistSet = new Set(verbAllowlist);
  // Internal-passthrough flags used by the parser / dispatcher that aren't
  // in the operator-facing allowlist but must not trigger the typo check.
  // The allowlist in lib/flag-suggest.js is operator-facing-only — these
  // are the legacy/internal escape hatches that still need to flow
  // through without a refusal.
  const PASSTHROUGH_FLAGS = new Set([
    "directive", "domain", "phase", "signal-list", "explain",
    "signatures", "currency", "cves", "rfcs", "shipped-tarball",
    "human", "json-stdout-only", "max-rwep", "diff-from-latest",
    "upstream-check", "latest", "force-replay", "flat", "directives",
    "fix", "session-key", "all", "scope", "playbook",
  ]);
  for (const key of Object.keys(args)) {
    if (key === "_" || key.startsWith("_")) continue;
    // Per-verb help is universal even when not in the allowlist.
    if (key === "help" || key === "h") continue;
    if (PASSTHROUGH_FLAGS.has(key)) {
      if (REQUIRES_VALUE.has(key) && args[key] === true) {
        return emitError(
          `${cmd}: --${key} requires a value.`,
          { verb: cmd, flag: key },
          pretty
        );
      }
      continue;
    }
    if (allowlistSet.has(key)) {
      if (REQUIRES_VALUE.has(key) && args[key] === true) {
        return emitError(
          `${cmd}: --${key} requires a value.`,
          { verb: cmd, flag: key },
          pretty
        );
      }
      continue;
    }
    // Refuse only when a close suggestion exists (likely typo). Unknown
    // flags with no near-match fall through to verb-level handling so a
    // future addition doesn't require an allowlist edit in this file
    // before it can ship. The PASSTHROUGH_FLAGS list above plus the
    // per-verb allowlist in lib/flag-suggest.js together cover every
    // shipped flag; anything that misses both AND has a typo suggestion
    // is the case operators benefit from refusing.
    const suggestion = suggestFlag(key, verbAllowlist);
    if (suggestion) {
      return emitError(
        `unknown flag --${key}`,
        { verb: cmd, suggested: suggestion },
        pretty
      );
    }
  }
  const runOpts = {
    // Air-gap can be requested via the explicit flag OR the
    // EXCEPTD_AIR_GAP=1 environment variable. The env-var path is for
    // operators who export it once at shell-init time so every subsequent
    // invocation inherits the disposition without remembering the flag.
    airGap: !!args["air-gap"] || process.env.EXCEPTD_AIR_GAP === "1",
    forceStale: !!args["force-stale"],
  };
  // Air-gap advisory (one-time per process). Routed to stderr so JSON
  // consumers on stdout don't see it. The exceptd CLI does not perform
  // network egress in air-gap mode, but a host AI driving exceptd may
  // still call its model API — surface the boundary so operators verify
  // their agent runtime is offline too.
  if (runOpts.airGap && !process.env.EXCEPTD_AIR_GAP_NOTICE_SHOWN) {
    process.stderr.write(
      `[exceptd] air-gap: exceptd will not perform network egress. Your AI agent may still call its model API; verify your agent runtime is also offline.\n`
    );
    process.env.EXCEPTD_AIR_GAP_NOTICE_SHOWN = "1";
  }
  if (args["session-id"]) {
    // --session-id is a filesystem path component (resolves to
    // .exceptd/attestations/<id>/attestation.json). Operator-supplied input
    // with `..` or path separators escapes the attestation root. Route
    // through the shared validateIdComponent('session') helper so the regex
    // + all-dots refusal stay aligned with persistAttestation /
    // validateSessionIdForRead.
    const sid = args["session-id"];
    const r = validateIdComponent(sid, "session");
    if (!r.ok) {
      return emitError(
        `run: --session-id ${r.reason}. Path separators and '..' are rejected.`,
        { provided: typeof sid === "string" ? sid.slice(0, 80) : typeof sid },
        pretty
      );
    }
    runOpts.session_id = sid;
  }
  if (args["attestation-root"]) {
    // v0.12.12: --attestation-root must resolve to an absolute path the
    // operator owns. Reject `..`-bearing relatives at input so a misconfigured
    // env doesn't write outside the intended root. Final resolution still
    // happens in resolveAttestationRoot — this is the input-validation layer.
    const ar = args["attestation-root"];
    if (typeof ar !== "string" || ar.length === 0) {
      return emitError("run: --attestation-root must be a non-empty string.", { provided: typeof ar }, pretty);
    }
    const arSegments = ar.split(/[\\/]/);
    if (arSegments.some(seg => seg === "..")) {
      return emitError(
        "run: --attestation-root must not contain '..' path segments. Pass an absolute path under your home directory or an explicit project-relative path without traversal.",
        { provided: ar.slice(0, 200) },
        pretty
      );
    }
    // All-dots segments (`.`, `..`, `...`, etc.) all resolve into or above
    // the intended parent directory, defeating the attestation-root
    // confinement check. Refuse any non-empty segment that is entirely dots
    // — the leading-`.` empty segment of an absolute POSIX path is allowed,
    // and a single `.` mid-path means "this dir" but is collapsed by
    // path.resolve anyway; explicit refusal is cheaper than reasoning about
    // every collapsed-equivalent shape.
    if (arSegments.some(seg => seg.length > 0 && /^\.+$/.test(seg))) {
      return emitError(
        "run: --attestation-root path segment cannot consist entirely of dots (rejected: '.', '..', '...', etc.). Pass an absolute path or a project-relative path without traversal.",
        { provided: ar.slice(0, 200) },
        pretty
      );
    }
    runOpts.attestationRoot = path.resolve(ar);
  }
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
  // for audit-trail accountability.
  //
  // Validate the input. Without this, a value flows into runOpts unchanged
  // and an operator could inject newlines / control chars / arbitrary
  // length into attestation export output (multi-line "operator:" key/value
  // pairs are a forgery surface — a forged second line could look like a
  // separate attestation field to a naive parser). Strip ASCII control
  // chars (\x00-\x1F + \x7F), cap length at 256, reject if all-whitespace.
  if (args.operator !== undefined) {
    if (typeof args.operator !== "string") {
      return emitError("run: --operator must be a string.", { provided: typeof args.operator }, pretty);
    }
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1F\x7F]/.test(args.operator)) {
      return emitError(
        "run: --operator contains ASCII control characters (newline, tab, NUL, etc.). Refusing — these would corrupt attestation export shape and enable forgery via multi-line injection.",
        { provided_length: args.operator.length },
        pretty
      );
    }
    if (args.operator.length > 256) {
      return emitError(
        `run: --operator too long: ${args.operator.length} chars (limit 256). Use a stable identifier (email, service-account name) — not a free-form description.`,
        { provided_length: args.operator.length },
        pretty
      );
    }
    if (args.operator.trim().length === 0) {
      return emitError(
        "run: --operator is empty or whitespace-only. Pass a meaningful identifier or omit the flag.",
        null,
        pretty
      );
    }
    // The ASCII-only control-char regex above misses Unicode categories
    // Cc / Cf / Co / Cn — bidi overrides (U+202E "RTL OVERRIDE"),
    // zero-width joiners (U+200B-D), invisible format chars, private-use
    // codepoints, unassigned codepoints. An operator string like
    // "alice‮evilbob" renders as "alicebobevila" in any UI that respects
    // bidi — a forgery surface where the attested name looks like Bob but the
    // bytes are Alice. Reject anything outside a positive allowlist of
    // printable ASCII + most BMP printable codepoints (skipping the format /
    // control / surrogate gaps).
    //
    // Implementation: NFC-normalise first (so a decomposed sequence can't
    // smuggle a combining mark past the codepoint check), then iterate
    // codepoints and refuse Cc/Cf/Co/Cn. We use \p{C} via the `u` regex flag,
    // which matches Cc + Cf + Cs + Co + Cn in one shot. Unicode 15.1 is the
    // baseline supported by Node 20.
    let normalized;
    try { normalized = args.operator.normalize("NFC"); }
    catch (e) {
      return emitError(
        `run: --operator failed Unicode NFC normalisation: ${e.message}`,
        { provided_length: args.operator.length },
        pretty
      );
    }
    if (normalized.length === 0) {
      return emitError(
        "run: --operator is empty after Unicode NFC normalisation. Pass a meaningful identifier or omit the flag.",
        null,
        pretty
      );
    }
    if (/\p{C}/u.test(normalized)) {
      // Find the offending codepoint to surface a useful hint without
      // round-tripping the raw bytes into the error body.
      let offending = "";
      for (const cp of normalized) {
        if (/\p{C}/u.test(cp)) {
          offending = "U+" + cp.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
          break;
        }
      }
      return emitError(
        `run: --operator contains a Unicode control / format / private-use / unassigned codepoint (${offending}). Bidi overrides (U+202E), zero-width joiners (U+200B–D), and format marks corrupt attestation rendering and enable name-forgery. Use printable identifiers only.`,
        { provided_length: args.operator.length, offending_codepoint: offending },
        pretty
      );
    }
    runOpts.operator = normalized;
  }

  // --csaf-status and --publisher-namespace shape the CSAF bundle emitted by
  // phases 5-7. Verbs that don't drive those phases (brief, plan, govern,
  // direct, look, attest, list-attestations, discover, doctor, lint, ask,
  // verify-attestation, reattest) never assemble a bundle, so silently
  // consuming these flags is a UX trap. Refuse on those verbs so the
  // operator knows the flag was discarded — same pattern as --ack. Error
  // message templates and emitError prefixes use the in-scope `cmd` verb so
  // a brief invocation says "brief:" rather than misattributing the flag
  // to run.
  const BUNDLE_FLAG_RELEVANT_VERBS = new Set([
    "run", "ci", "run-all", "ai-run", "ingest",
  ]);

  // --publisher-namespace <url> threads into the CSAF
  // bundle's document.publisher.namespace field. CSAF §3.1.7.4 requires the
  // namespace to be the publisher's trust anchor — i.e. the OPERATOR
  // running the scan, not the tooling vendor. Pre-fix this was hard-coded
  // to https://exceptd.com, misattributing responsibility for advisory
  // accuracy. Validation mirrors --operator (string, ≤256 chars, no
  // ASCII / Unicode control characters), plus a URL-shape check (`^https?:`).
  if (args["publisher-namespace"] !== undefined) {
    if (!BUNDLE_FLAG_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --publisher-namespace is irrelevant on this verb (no CSAF bundle is assembled). --publisher-namespace only applies to verbs that drive phases 5-7: ${[...BUNDLE_FLAG_RELEVANT_VERBS].sort().join(", ")}. Re-invoke without --publisher-namespace, or pass it on \`exceptd run ${cmd === "brief" ? args._[0] || "<playbook>" : "<playbook>"} --publisher-namespace <url>\` once you're past the briefing step.`,
        { verb: cmd, flag: "publisher-namespace", error_class: "irrelevant-flag", accepted_verbs: [...BUNDLE_FLAG_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    const ns = args["publisher-namespace"];
    if (typeof ns !== "string") {
      return emitError(`${cmd}: --publisher-namespace must be a string.`, { provided: typeof ns }, pretty);
    }
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1F\x7F]/.test(ns)) {
      return emitError(
        `${cmd}: --publisher-namespace contains ASCII control characters. Refusing — these would corrupt CSAF rendering and break URL parsing in downstream consumers.`,
        { provided_length: ns.length },
        pretty
      );
    }
    if (ns.length === 0 || ns.length > 256) {
      return emitError(
        `${cmd}: --publisher-namespace length ${ns.length} out of bounds (1–256).`,
        { provided_length: ns.length },
        pretty
      );
    }
    if (!/^https?:\/\//i.test(ns)) {
      return emitError(
        `${cmd}: --publisher-namespace must be a URL starting with http:// or https:// (e.g. https://your-org.example). CSAF §3.1.7.4 requires the namespace to be the publisher's trust anchor.`,
        { provided: ns.slice(0, 80) },
        pretty
      );
    }
    runOpts.publisherNamespace = ns;
  }

  // --csaf-status promotes the CSAF tracking.status from the
  // runtime default (`interim`) to `final` for operators who have reviewed
  // the advisory and accept the immutable-advisory contract of CSAF
  // §3.1.11.3.5.1. Accepts the three CSAF spec values; anything else is
  // rejected at input so an operator typo (`finel`) doesn't silently fall
  // back to interim and produce surprise.
  if (args["csaf-status"] !== undefined) {
    if (!BUNDLE_FLAG_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --csaf-status is irrelevant on this verb (no CSAF bundle is assembled). --csaf-status only applies to verbs that drive phases 5-7: ${[...BUNDLE_FLAG_RELEVANT_VERBS].sort().join(", ")}. Re-invoke without --csaf-status, or pass it on \`exceptd run ${cmd === "brief" ? args._[0] || "<playbook>" : "<playbook>"} --csaf-status <status>\` once you're past the briefing step.`,
        { verb: cmd, flag: "csaf-status", error_class: "irrelevant-flag", accepted_verbs: [...BUNDLE_FLAG_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    const cs = args["csaf-status"];
    const allowed = ["draft", "interim", "final"];
    if (typeof cs !== "string" || !allowed.includes(cs)) {
      return emitError(
        `${cmd}: --csaf-status must be one of ${JSON.stringify(allowed)}. Got: ${JSON.stringify(String(cs)).slice(0, 40)}`,
        { provided: cs },
        pretty
      );
    }
    runOpts.csafStatus = cs;
  }

  // --ack: operator acknowledges the jurisdiction obligations surfaced by
  // govern. Captured in attestation; downstream tooling can check whether
  // consent was explicit vs. implicit. AGENTS.md says the AI should surface
  // and wait for ack — this is how the ack gets recorded.
  //
  // --ack only makes sense on verbs that drive phases 5-7 (run / ingest /
  // ai-run / ci / run-all / reattest). Info-only verbs (brief, plan,
  // govern, direct, look, attest, list-attestations, discover, doctor,
  // lint, ask, verify-attestation) never consume an attestation clock —
  // accepting --ack silently is a UX trap where operators believe they have
  // recorded consent. Refuse on those verbs so the operator knows the flag
  // is irrelevant.
  const ACK_RELEVANT_VERBS = new Set([
    "run", "ingest", "ai-run", "ci", "run-all", "reattest",
  ]);
  if (args.ack) {
    if (!ACK_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --ack is irrelevant on this verb (no jurisdiction clock at stake). --ack only applies to verbs that drive phases 5-7: ${[...ACK_RELEVANT_VERBS].sort().join(", ")}. Re-invoke without --ack, or use \`exceptd run ${cmd === "brief" ? args._[0] || "<playbook>" : "<playbook>"} --ack\` once you're past the briefing step.`,
        { verb: cmd, accepted_verbs: [...ACK_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    runOpts.operator_consent = { acked_at: new Date().toISOString(), explicit: true };
  }

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
    // v0.11.14 (#131): when the operator typed a skill name (kernel-lpe-triage)
    // and got "Playbook not found," surface the playbooks that load that skill.
    // 13 playbooks vs 38 skills with many-to-many: operators routinely confuse
    // the two because the website (and AGENTS.md) describe both as runnable.
    const m = e && e.message && e.message.match(/^Playbook not found: ([^\s(]+)/);
    if (m) {
      const wanted = m[1];
      const hint = buildSkillToPlaybookHint(runner, wanted);
      if (hint) {
        return emitError(`Playbook not found: "${wanted}". ${hint}`, { verb: cmd, wanted, type: "playbook_not_found" }, pretty);
      }
    }
    // Wrap bare e.message so operators see the verb that triggered the
    // failure + the next action they can take. Re-running with --pretty
    // expands the cause for log-scraping; the GitHub-issues pointer lets
    // operators report reproducible-but-unhandled exceptions.
    emitError(
      `${cmd}: internal error (${e && e.message ? e.message : String(e)}). Re-run with --pretty for context; file at https://github.com/blamejs/exceptd-skills/issues if reproducible.`,
      { verb: cmd },
      pretty
    );
  }
}

function buildSkillToPlaybookHint(runner, wanted) {
  try {
    const ids = runner.listPlaybooks ? runner.listPlaybooks() : [];
    const matches = [];
    for (const id of ids) {
      let pb;
      try { pb = runner.loadPlaybook(id); } catch { continue; }
      const skills = new Set();
      const collect = (val) => {
        if (Array.isArray(val)) val.forEach(collect);
        else if (val && typeof val === "object") Object.values(val).forEach(collect);
        else if (typeof val === "string") skills.add(val);
      };
      collect(pb.phases?.govern?.skill_preload);
      for (const d of (pb.directives || [])) {
        collect(d.phase_overrides?.govern?.skill_preload);
      }
      if (skills.has(wanted)) matches.push(id);
    }
    if (matches.length > 0) {
      return `That is a SKILL (read-only knowledge unit), not a PLAYBOOK (executable). Skill "${wanted}" is loaded by playbook${matches.length === 1 ? "" : "s"}: ${matches.join(", ")}. ` +
             `To execute: \`exceptd run ${matches[0]}\`. To read the skill: \`exceptd skill ${wanted}\`. ` +
             `Tip: \`exceptd brief --all\` lists all 13 playbooks; \`exceptd watch\` lists skills.`;
    }
    // No matching skill either — provide nearest-playbook suggestions.
    // v0.12.9 (P3 #9 from production smoke): substring fallback first (cheap),
    // then edit-distance for typos that don't substring-match (`secrt`,
    // `kernl`, `cret-stores`). Without the second pass `run secrt` returned
    // the generic "13 playbooks" message even though `secrets` is one edit
    // away.
    const subMatches = ids.filter(id => id.includes(wanted) || wanted.includes(id)).slice(0, 3);
    const fuzzyMatches = subMatches.length === 0 ? nearestByEditDistance(wanted, ids, 2).slice(0, 3) : [];
    const near = subMatches.length ? subMatches : fuzzyMatches;
    if (near.length > 0) {
      return `Did you mean: ${near.join(", ")}? Run \`exceptd brief --all\` for the full list.`;
    }
    return `Run \`exceptd brief --all\` to list the 13 playbooks.`;
  } catch { return null; }
}

/**
 * Cheap Levenshtein distance, used to surface "Did you mean X?" suggestions
 * for misspelled playbook ids in the `run <typo>` error path. Returns ids
 * whose distance from `wanted` is ≤ `maxDistance`, sorted by closest first.
 * Bounded by the candidate set size (13 playbooks), so the O(n*m) cost is
 * negligible.
 */
function nearestByEditDistance(wanted, ids, maxDistance) {
  if (!wanted || !Array.isArray(ids)) return [];
  const w = String(wanted).toLowerCase();
  const scored = [];
  for (const id of ids) {
    const d = editDistance(w, id.toLowerCase());
    if (d <= maxDistance) scored.push({ id, d });
  }
  scored.sort((a, b) => a.d - b.d);
  return scored.map(s => s.id);
}

function editDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const prev = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let cur = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const next = Math.min(prev[j] + 1, cur + 1, prev[j - 1] + cost);
      prev[j - 1] = cur;
      cur = next;
    }
    prev[b.length] = cur;
  }
  return prev[b.length];
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
  --csaf-status <s>       CSAF tracking.status for the close.evidence_package
                          bundle. One of: draft | interim (default) | final.
                          'final' commits to CSAF §3.1.11.3.5.1 immutability —
                          set this only after operator review of the advisory.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          publisher trust anchor — i.e. the operator's
                          organisation, NOT the tooling vendor. Must be an
                          http://… or https://… URL, ≤256 chars.
  --diff-from-latest      Compare evidence_hash against the most recent prior
                          attestation for the same playbook in
                          .exceptd/attestations/. Emits status: unchanged | drifted.
  --ci                    Machine-readable verdict for CI gates. Exits non-zero
                          (code 2) when phases.detect.classification === 'detected'
                          OR phases.analyze.rwep.adjusted >= rwep_threshold.escalate.
                          Logs PASS/FAIL reason to stderr.
  --upstream-check        (v0.11.14) Opt-in: query npm registry for the latest
                          published @blamejs/exceptd-skills version before
                          detect. Warns to stderr (no exit-code change) when
                          the local install is behind, so an operator using a
                          stale catalog finds out before the run completes.
  --strict-preconditions  Escalate warn-level precondition failures to halt.
                          Without this flag, only on_fail=halt preconditions
                          block; warn-level surface in stderr but the run
                          proceeds. With it, any precondition_check returning
                          false fails the run and exits non-zero.
  --session-id <id>       Reuse a specific session ID. Collisions refused
                          unless --force-overwrite is also passed.
  --force-overwrite       Override the session-id collision refusal.
  --session-key <hex>     HMAC sign the evidence_package with this key.
                          Output carries an 'hmac' field the verifier can check.
  --force-stale           Override the threat_currency_score < 50 hard-block.
  --air-gap               Honor air_gap_alternative paths in look.artifacts[]
                          and skip the network-touching collection variants.
  --pretty                Indented JSON output.

Attestation is persisted to .exceptd/attestations/<session_id>/ on every
successful run (single: attestation.json; multi: <playbook_id>.json).

Exit codes (per-verb, post-run):
  0  PASS                  Run completed; classification clean, RWEP under cap.
  1  Framework error       Runner threw, unreadable evidence, etc.
  2  FAIL (detected)       classification=detected OR rwep ≥ escalate cap.
  3  Ran-but-no-evidence   All inconclusive AND no --evidence supplied.
  4  Blocked               Result returned ok:false (preflight halt).
  5  CLOCK_STARTED         --block-on-jurisdiction-clock fired.
  6  TAMPERED              Surfaced by attest verify; sidecar verification failed.
  7  SESSION_ID_COLLISION  run --session-id duplicate without --force-overwrite.
  8  LOCK_CONTENTION       persistAttestation could not acquire the per-slot
                           attestation lock after the bounded retry budget
                           (~1-2s). Distinct from 1 so callers can retry the
                           operation rather than treat it as a hard failure.
                           Surfaces as body.lock_contention=true,
                           body.exit_code=8.
  9  STORAGE_EXHAUSTED     Attestation write hit ENOSPC / EDQUOT / EROFS.

Other operator-facing flags (full list in source; surfaced here for grep):
  --vex <file>            CycloneDX / OpenVEX disposition filter.
  --evidence-dir <dir>    Per-playbook submission files.
  --attestation-root <p>  Override .exceptd/ root for this run.
  --mode <m>              Investigation mode (self_service | authorized_pentest
                          | ir_response | ctf | research | compliance_audit).`,
    ingest: `ingest — alias for 'run' matching AGENTS.md terminology.

Flags:
  --domain <id>           Playbook ID (overrides submission.playbook_id).
  --directive <id>        Directive ID (overrides submission.directive_id).
  --evidence <file|->     Submission JSON. May include playbook_id/directive_id.
  --session-id <id>       Reuse a specific session id (must satisfy
                          /^[A-Za-z0-9._-]{1,64}$/).
  --force-overwrite       Override session-id collision refusal.
  --operator <name>       Bind attestation to a specific identity.
  --ack                   Explicit operator consent for jurisdiction clock.
  --attestation-root <p>  Override .exceptd/ root for this ingest.
  --mode <m>              Investigation mode (self_service | authorized_pentest
                          | ir_response | ctf | research | compliance_audit).
  --air-gap               Honor air_gap_alternative paths.
  --force-stale           Override threat_currency_score<50 gate.
  --csaf-status <s>       CSAF tracking.status for the close.evidence_package
                          bundle. One of: draft | interim (default) | final.
                          'final' commits to CSAF §3.1.11.3.5.1 immutability —
                          set this only after operator review of the advisory.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          operator's organisation URL, NOT the tooling vendor.
                          Must be an http://… or https://… URL, ≤256 chars.
  --pretty                Indented JSON output.

Exit codes: 0 PASS, 1 framework, 4 blocked, 7 SESSION_ID_COLLISION,
8 LOCK_CONTENTION, 9 STORAGE_EXHAUSTED.`,
    reattest: `reattest [<session-id> | --latest] — replay a prior session and diff the evidence_hash.

Args / flags:
  <session-id>            Looks under .exceptd/attestations/<id>/attestation.json.
  --latest                Find the most-recent attestation automatically.
  --playbook <id>         Restrict --latest to a specific playbook.
  --since <ISO>           Restrict --latest to attestations after this ISO 8601 timestamp.
  --pretty                Indented JSON output.

Reports: unchanged | drifted | resolved from evidence_hash + classification deltas.

Exit codes:
  0  verification succeeded
  1  generic failure
  6  TAMPERED (sidecar or signature mismatch on the prior attestation)`,
    "list-attestations": `list-attestations [--playbook <id>] — enumerate prior attestations.

Args / flags:
  --playbook <id>         Filter to one playbook.
  --pretty                Indented JSON output.

Lists every attestation under .exceptd/attestations/<session_id>/, sorted
newest-first, with truncated evidence_hash + capture timestamp + file path.`,
    attest: `attest <subverb> <session-id> — auditor-facing attestation operations.

Subverbs (list | show | export | verify | diff):
  attest show <sid>       Emit the full (unredacted) attestation.
  attest list             Inventory every prior attestation under
                          ~/.exceptd/attestations/ (or EXCEPTD_HOME when set).
                          Filter with --playbook <id> or --since <ISO> (must
                          be a parseable ISO-8601 timestamp). Newest first;
                          truncated evidence_hash + capture timestamp + path
                          per entry.
  attest export <sid>     Emit redacted JSON suitable for audit submission.
                          Strips raw artifact values; preserves evidence_hash,
                          signature, classification, RWEP, remediation choice.
                          --format <csaf|csaf-2.0|json> wraps the export
                          (default: redacted JSON; csaf yields a CSAF 2.0
                          envelope).
  attest verify <sid>     Verify .sig sidecar against keys/public.pem.
                          Reports tamper status per attestation file. Replay
                          records (kind=replay) verify under replay_results;
                          a replay-record tamper raises body.replay_tamper +
                          warnings[] but does NOT exit non-zero (the audit
                          trail can be regenerated via reattest).
  attest diff <sid>       Diff <sid> against the most-recent prior attestation
                          for the same playbook, or against --against <other-sid>
                          for an explicit pair. Reports unchanged | drifted |
                          resolved per evidence_hash + classification deltas.

All subverbs honor --pretty for indented JSON output.

Exit codes (attest verify):
  0  verification succeeded
  1  generic failure
  6  TAMPERED (sidecar or signature mismatch on an attestation; replay-record
              tamper warns but exits 0)`,
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

Output: context + recommended_playbooks[] + next_steps[].

discover always exits 0 (recommendations are informational; absence of a
match is not a failure). JSON output is the canonical surface — humans see
a digest by default; pass --json for the structured shape.`,
    doctor: `doctor — one-shot health check (v0.11.0).

Replaces: currency + verify + validate-cves + validate-rfcs + signing-status.

Subchecks:
  --signatures            Ed25519 signature verification across all skills.
  --currency              Skill currency report (last_threat_review).
  --cves                  CVE catalog validation (offline view).
  --rfcs                  RFC catalog validation (offline view).
  --registry-check        (v0.11.14) Opt-in: query the npm registry for the
                          latest published version + days-since-publish.
                          Surfaces under checks.registry.{local_version,
                          published_version, same, behind, days_since_latest_publish}.
                          Off by default — keeps doctor offline-clean unless
                          asked.
  --fix                   (v0.12.5) Attempt to auto-remediate detected gaps.
                          Currently scoped to: regenerate the local Ed25519
                          private key when keys/public.pem exists but
                          .keys/private.pem is absent. Does NOT modify any
                          file outside .keys/.
  (no flag)               All four subchecks above (sans --registry-check
                          unless explicitly requested), plus signing-status
                          (private key presence under .keys/).

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
  --csaf-status <s>       CSAF tracking.status for the close.evidence_package
                          bundle. One of: draft | interim (default) | final.
                          'final' commits to CSAF §3.1.11.3.5.1 immutability —
                          set this only after operator review of the advisory.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          operator's organisation URL, NOT the tooling vendor.
                          Must be an http://… or https://… URL, ≤256 chars.
  --evidence <file|->     Single-shot mode: pre-supplied submission JSON.
  --operator <name>       Bind the attestation to a specific identity.
  --ack                   Mark explicit operator consent (jurisdiction clock).
  --force-overwrite       Override session-id collision refusal.
  --session-id <id>       Reuse a specific session id (must satisfy
                          /^[A-Za-z0-9._-]{1,64}$/).
  --pretty                Indented JSON output (single-shot only).

Exit codes:
  0  done                  Run completed; emitted {"event":"done","ok":true}.
  1  framework error       Engine threw or stdin parse failure.
  3  SESSION_ID_COLLISION  --session-id duplicate; pass --force-overwrite or fresh id.
  8  LOCK_CONTENTION       Concurrent persistAttestation lock held.
  9  STORAGE_EXHAUSTED     Disk/quota/RO filesystem on attestation write.

Stdin event grammar (one JSON object per line):
  {"event":"evidence","payload":{"observations":{},"verdict":{}}}

Stdin acceptance contract:
  In streaming mode, ai-run reads JSON-Lines from stdin until the FIRST
  parseable {"event":"evidence","payload":{...}} line. That line wins:
  subsequent evidence events on the same run are ignored (the handler
  marks itself \`handled\` and refuses re-entry). Non-evidence chatter
  (status updates, the host AI's own progress events) is silently
  ignored — the host can interleave its own JSON events without
  triggering a phase transition. Invalid JSON on any line exits 1 with
  an {"event":"error","reason":"invalid JSON on stdin: ..."} frame.

  If the host needs to send multiple evidence batches, spawn a separate
  ai-run per batch (each produces an independent session_id). Use
  --no-stream + --evidence <file> for single-shot single-batch runs.

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
hint pointing at \`exceptd brief --all\` / \`exceptd discover\`.

ask always exits 0. JSON via --json (default is a one-line digest on TTY).`,
    ci: `ci [--all|--scope <type>] — one-shot CI gate (v0.11.0).

Top-level CI verb. Equivalent to \`run --all --ci\` but with a clean
exit-code contract designed for one-line .github/workflows entries.

Flags:
  --all                   Run every playbook.
  --scope <type>          Filter: system | code | service | cross-cutting.
  --required <ids>        Comma-separated playbook ids that MUST run, even if
                          scope-detection would exclude them. Fails if a
                          required id is unknown.
  (no flag)               Auto-detect scopes from cwd (same logic as run).
  --evidence <file>       Submission bundle (multi-playbook shape).
  --evidence-dir <dir>    Read <playbook-id>.json files from a directory.
  --max-rwep <int>        Override RWEP escalate threshold (default: per-playbook).
  --block-on-jurisdiction-clock
                          Fail when any close.notification_actions started a
                          regulatory clock (GDPR 72h, HIPAA breach, etc.).
  --format <fmt>          Output shape. Supported: json (default, single-line),
                          summary (5-field digest), markdown (human digest).
                          Bundles (csaf-2.0/sarif/openvex) live on per-run
                          attestations, not the aggregate ci verdict.
  --csaf-status <s>       CSAF tracking.status threaded into per-run bundles.
                          One of: draft | interim (default) | final.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          operator's organisation URL, NOT the tooling vendor.
  --json                  Force single-line JSON (overrides any TTY heuristics).
  --pretty                Indented JSON output (implies --json).

Exit codes:
  0  PASS                  All scoped playbooks ran and verdict is clean.
  1  Framework error       Runner threw, unreadable evidence, etc.
  2  FAIL (detected)       At least one playbook returned
                           classification=detected, OR rwep ≥ escalate, OR
                           --max-rwep cap exceeded.
  3  Ran-but-no-evidence   Every result was inconclusive AND no evidence was
                           submitted (visibility gap — CI should fail loud).
  4  Blocked               Result returned ok:false (preflight halt, missing
                           preconditions with on_fail=halt, etc.).
  5  CLOCK_STARTED         --block-on-jurisdiction-clock fired: at least one
                           close.notification_actions entry started a
                           regulatory clock (NIS2 24h, GDPR 72h, DORA 4h,
                           etc.) and the operator has not acked.

(ci does not persist attestations per-run; exit codes 6/7/8/9 surface on
\`attest verify\` and on \`run\` / \`ai-run\` / \`ingest\`, not on \`ci\`.)

Output: verb, session_id, playbooks_run, summary{total, detected,
max_rwep_observed, jurisdiction_clocks_started, verdict, fail_reasons[]},
results[].`,
    brief: `brief [playbook] — unified info doc (v0.11.0).

Collapses the three info-only phases plan + govern + direct + look into a
single document. Phases 1-3 of the seven-phase contract are entirely
informational; brief reads them in one CLI invocation instead of three.

Modes:
  brief                   Auto-detect playbooks for the cwd. Returns a list.
  brief <playbook>        Single-playbook brief with jurisdiction obligations
                          + threat context + preconditions + artifacts +
                          indicators.
  brief --all             Every shipped playbook.
  brief --scope <type>    Filter: system | code | service | cross-cutting.
  brief <pb> --phase <p>  Emit only the named phase (govern | direct | look).
                          Compat for legacy callers.

Flags:
  --directives            Expand directive metadata per playbook.
  --pretty                Indented JSON output.
  --json                  Force single-line JSON.

Output (single-playbook): playbook_id, directives[], jurisdiction_obligations[],
threat_context, preconditions[], artifacts[], indicators[].`,
    lint: `lint <playbook> <evidence-file> — pre-flight check submission shape.

Validates the submission JSON against the playbook's expected indicators /
preconditions / artifacts WITHOUT executing detect/analyze/validate/close.
Lets the AI iterate on its evidence before going through phases 4-7.

Args / flags:
  <playbook>              Playbook id. Required.
  <evidence-file>         Submission JSON path. Required.
  --pretty                Indented JSON output.

Output categories: ok, missing_required, missing_required_artifact,
unknown_keys, type_mismatch, suggestions.`,
    "verify-attestation": `verify-attestation <session-id> — alias for \`attest verify\`.

See \`exceptd attest --help\` for the full attest verb. This alias matches
the historical verify-attestation entry-point name used by some downstream
consumers.

Flags: --pretty.`,
    "run-all": `run-all — alias for \`run --all\`.

Identical exit-code and output contract as \`run --all\`. Maintained for
operators who script the verb form rather than the flag.

Flags (selected — see \`exceptd run --help\` for the full list):
  --csaf-status <s>       CSAF tracking.status for per-run close.evidence_package
                          bundles. One of: draft | interim (default) | final.
                          'final' commits to CSAF §3.1.11.3.5.1 immutability —
                          set this only after operator review of the advisory.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          operator's organisation URL, NOT the tooling vendor.
                          Must be an http://… or https://… URL, ≤256 chars.`,
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
  if (refuseInvalidPlaybookId("lint", playbookId, pretty)) return;
  let pb;
  try { pb = runner.loadPlaybook(playbookId); }
  catch (e) {
    // Route the not-found / load-error case through the skill-to-playbook
    // hint helper so an operator who typed a skill id (kernel-lpe-triage)
    // gets the same actionable pointer dispatchPlaybook surfaces for cmdRun.
    const m = e && e.message && e.message.match(/^Playbook not found: ([^\s(]+)/);
    if (m) {
      const hint = buildSkillToPlaybookHint(runner, m[1]);
      if (hint) {
        return emitError(`lint: Playbook not found: "${m[1]}". ${hint}`, { playbook: playbookId, type: "playbook_not_found" }, pretty);
      }
    }
    return emitError(`lint: ${e.message}`, { playbook: playbookId }, pretty);
  }

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

  // v0.12.9 (P2 #7 from production smoke): refuse garbage values to --phase.
  // Pre-v0.12.9 `brief secrets --phase foo` silently accepted any string and
  // emitted the full brief — operators got no signal the flag was misused.
  // The legacy-compat surface is exactly the three v0.10.x verb names
  // (govern | direct | look); anything else is a typo or a misunderstanding.
  if (onlyPhase != null) {
    const ACCEPTED_PHASES = ["govern", "direct", "look"];
    if (!ACCEPTED_PHASES.includes(onlyPhase)) {
      return emitError(`brief: --phase "${onlyPhase}" not in accepted set ${JSON.stringify(ACCEPTED_PHASES)}.`, { verb: "brief", provided: onlyPhase }, pretty);
    }
  }

  if (!playbookId || args.all) {
    // Multi-playbook brief (replaces `plan`). Reuses cmdPlan output shape.
    return cmdPlan(runner, args, runOpts, pretty);
  }

  if (refuseInvalidPlaybookId("brief", playbookId, pretty)) return;
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

// v0.12.15: --scope must validate against the accepted
// set. The prior shape silently returned [] for any unknown scope, which
// in `run --scope nonsense` produced `count: 0` + exit 0 (cmd reports
// "ran 0 playbooks") and in `ci --scope nonsense` silently ran only the
// cross-cutting set (the union with `framework` produced a false-positive
// PASS). Both are operator-intent loss patterns CLAUDE.md flags as the
// "field-present, content-wrong" class.
const VALID_SCOPES = ["system", "code", "service", "cross-cutting", "all"];

function validateScopeOrThrow(scope) {
  if (typeof scope !== "string" || !VALID_SCOPES.includes(scope)) {
    throw new Error(
      `--scope must be one of ${JSON.stringify(VALID_SCOPES)}; got ${JSON.stringify(scope)}.`
    );
  }
  return scope;
}

/**
 * Wrap every operator-controlled loadPlaybook() call so a path-traversal
 * shaped id (`../../etc/passwd`, `..`, absolute path) is refused at the
 * dispatcher before the runner ever sees it. Routes through
 * validateIdComponent('playbook'), which enforces /^[a-z][a-z0-9-]{0,63}$/.
 * On failure returns the structured emitError shape; on success returns
 * null so the caller can short-circuit with a single `if (refusal) return refusal;`.
 */
function refuseInvalidPlaybookId(verb, playbookId, pretty) {
  const r = validateIdComponent(playbookId, "playbook");
  if (!r.ok) {
    emitError(
      `${verb}: invalid <playbook> id — ${r.reason}.`,
      { verb, provided: typeof playbookId === "string" ? playbookId.slice(0, 80) : typeof playbookId },
      pretty
    );
    return true;
  }
  return false;
}

/**
 * Shared "playbook has no directives" refusal. Six sites in this file
 * previously hand-rolled the same error string; consolidating means a
 * future remediation pointer (e.g. "run `exceptd brief <id>` to inspect
 * the playbook") changes in one place.
 */
function refuseNoDirectives(verb, playbookId, pretty) {
  return emitError(
    `${verb}: playbook ${playbookId} has no directives. Inspect the playbook with \`exceptd brief ${playbookId}\` or report at https://github.com/blamejs/exceptd-skills/issues.`,
    { verb, playbook: playbookId },
    pretty
  );
}

function filterPlaybooksByScope(runner, scope) {
  validateScopeOrThrow(scope);
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
  if (refuseInvalidPlaybookId("govern", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("govern", playbookId, pretty);
  emit(runner.govern(playbookId, directiveId, runOpts), pretty);
}

function cmdDirect(runner, args, pretty) {
  const playbookId = args._[0];
  if (!playbookId) return emitError("direct: missing <playbookId> positional argument.", null, pretty);
  if (refuseInvalidPlaybookId("direct", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("direct", playbookId, pretty);
  emit(runner.direct(playbookId, directiveId), pretty);
}

function cmdLook(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) return emitError("look: missing <playbookId> positional argument.", null, pretty);
  if (refuseInvalidPlaybookId("look", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("look", playbookId, pretty);
  emit(runner.look(playbookId, directiveId, runOpts), pretty);
}

function cmdRun(runner, args, runOpts, pretty) {
  const positional = args._[0];

  // Multi-playbook dispatch path. Triggered by --all, --scope <type>, or by
  // a bare `exceptd run` (no positional, no flags) which auto-detects scopes
  // from the cwd.
  // Gate on `args.scope !== undefined` rather than truthy `args.scope`.
  // `--scope ""` parses to `args.scope === ""`, which is falsy; a truthy
  // gate would silently fall through to auto-detect and run whatever
  // scopes happened to match the cwd, masking the operator's explicit
  // (if malformed) intent. An empty string reaches validateScopeOrThrow
  // which rejects with the accepted-set message.
  if (!positional && (args.all || args.scope !== undefined)) {
    let ids;
    if (args.all) {
      ids = runner.listPlaybooks();
    } else {
      try { ids = filterPlaybooksByScope(runner, args.scope); }
      catch (e) { return emitError(`run: ${e.message}`, { provided_scope: args.scope }, pretty); }
    }
    return cmdRunMulti(runner, ids, args, runOpts, pretty, { trigger: args.all ? "--all" : `--scope ${args.scope}` });
  }
  if (!positional && !args.all && args.scope === undefined) {
    const scopes = detectScopes();
    const ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s));
    const unique = [...new Set(ids)];
    if (unique.length === 0) {
      // Surface the auto-detect failure cause so operators see WHY no
      // playbook was resolved instead of just "nothing matched." Mirrors
      // detectScopes()' two probes — `.git/` for code, `/proc + os-release`
      // for system — and enumerates the accepted explicit flags so the
      // remediation is one line.
      const hasGit = fs.existsSync(path.join(process.cwd(), ".git"));
      const hasProc = fs.existsSync("/proc") && fs.existsSync("/etc/os-release");
      const probes = [];
      if (!hasGit) probes.push("no .git/ in cwd (code-scope auto-detect skipped)");
      if (!hasProc) probes.push("no /proc + /etc/os-release (system-scope auto-detect skipped — not a Linux host or under sandbox)");
      const reason = probes.length ? ` Auto-detect probes: ${probes.join("; ")}.` : "";
      return emitError(
        `run: no playbook resolved. Pass <playbookId>, --scope <type> (one of ${JSON.stringify(VALID_SCOPES)}), or --all.${reason}`,
        { verb: "run", cwd: process.cwd(), detected_scopes: scopes },
        pretty
      );
    }
    return cmdRunMulti(runner, unique, args, runOpts, pretty, { trigger: "auto-detect", detected_scopes: scopes });
  }

  // Single-playbook path (existing behavior).
  const playbookId = positional;
  if (refuseInvalidPlaybookId("run", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("run", playbookId, pretty);

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
  // v0.11.1: auto-detect piped stdin. If no --evidence flag and stdin is a
  // pipe, assume `--evidence -`. Operators forgetting the flag previously
  // got a confusing precondition halt; now the common case "just works."
  // Use the fstat-probing hasReadableStdin() helper. A raw `!isTTY` check
  // fires when isTTY is undefined (test harnesses with wrapped duplexers —
  // Mocha/Jest, Docker stdin-passthrough — leave isTTY === undefined but
  // never write any bytes), which causes readFileSync(0) to block waiting
  // on an EOF that never arrives. hasReadableStdin() does an fstat() probe
  // first, then falls back to a strict isTTY===false check only on Windows
  // (where fstat on a pipe is unreliable). MSYS-bash on win32 reports
  // isTTY === false for genuine piped input, so that path still works.
  if (!args.evidence && hasReadableStdin()) {
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
    let vexDoc;
    // Cap --vex file size at 32 MiB (binary mebibytes, i.e. 32 * 1024 * 1024
    // = 33,554,432 bytes), matching readEvidence()'s --evidence cap. Without
    // the cap, a multi-GB file (binary log, JSON bomb, or accident) blocks
    // the event loop for minutes / OOM's the process. 32 MiB is well beyond
    // any legitimate VEX submission.
    const MAX_VEX_BYTES = 32 * 1024 * 1024;
    let vstat;
    try { vstat = fs.statSync(args.vex); }
    catch (e) {
      return emitError(`run: failed to stat --vex ${args.vex}: ${e.message}`, null, pretty);
    }
    if (vstat.size > MAX_VEX_BYTES) {
      // Error message names the binary mebi convention explicitly so
      // operators don't mistake the cap for 32 * 10^6 = 32,000,000 bytes (MB).
      return emitError(
        `run: --vex file too large: ${vstat.size} bytes exceeds 32 MiB limit (${MAX_VEX_BYTES.toLocaleString("en-US")} bytes). Reduce the document or split into multiple passes.`,
        { provided_path: args.vex, size_bytes: vstat.size, limit_bytes: MAX_VEX_BYTES },
        pretty
      );
    }
    try {
      // BOM-tolerant read. Windows-tool-emitted CycloneDX commonly carries
      // UTF-8-BOM or UTF-16 LE/BE markers; the raw "utf8" decode in
      // readFileSync chokes on the leading 0xFEFF.
      vexDoc = readJsonFile(args.vex);
    } catch (e) {
      return emitError(`run: failed to load --vex ${args.vex}: ${e.message}`, null, pretty);
    }
    // Validate the VEX shape BEFORE handing to runner.vexFilterFromDoc.
    // The runner tolerantly returns Set(0) for anything that's not CycloneDX
    // or OpenVEX shape, so an operator who passes a SARIF / SBOM / CSAF
    // advisory by mistake got ZERO filter applied and ZERO feedback. Now:
    // reject with a clear error naming the detected shape.
    const shape = detectVexShape(vexDoc);
    if (!shape.ok) {
      return emitError(
        `run: --vex file doesn't look like CycloneDX or OpenVEX. Detected shape: ${shape.detected}. ` +
        `Expected CycloneDX VEX (bomFormat:"CycloneDX" + vulnerabilities[]) or OpenVEX (@context starting "https://openvex.dev" + statements[]).`,
        { provided_path: args.vex, top_level_keys: shape.top_level_keys },
        pretty
      );
    }
    try {
      const vexSet = runner.vexFilterFromDoc(vexDoc);
      submission.signals = submission.signals || {};
      submission.signals.vex_filter = [...vexSet];
      // vexFilterFromDoc attaches a `.fixed` Set as an own property on the
      // returned filter Set (CycloneDX `analysis.state: 'resolved'` + OpenVEX
      // `status: 'fixed'` populate it). Forward it through to
      // signals.vex_fixed so analyze() receives the fixed-disposition CVE
      // ids, `vex_status: 'fixed'` annotates matched_cves entries, and CSAF
      // product_status.fixed + OpenVEX status:'fixed' propagate into the
      // bundle.
      submission.signals.vex_fixed = vexSet.fixed ? [...vexSet.fixed] : [];
    } catch (e) {
      return emitError(`run: failed to apply --vex ${args.vex}: ${e.message}`, null, pretty);
    }
  }

  // v0.11.14: opt-in `--upstream-check` queries the npm registry BEFORE
  // detect to warn operators if their local catalog is behind the latest
  // published version. Opt-in so the runner stays offline by default.
  // Network bounded by an 8s timeout; degrades gracefully when offline.
  let upstreamCheck = null;
  if (args["upstream-check"]) {
    try {
      const cliPath = path.join(PKG_ROOT, "lib", "upstream-check-cli.js");
      const res = spawnSync(process.execPath, [cliPath, "--timeout", "5000"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 8000,
      });
      try { upstreamCheck = JSON.parse((res.stdout || "").trim()); } catch { /* fall through */ }
      if (upstreamCheck && upstreamCheck.behind) {
        process.stderr.write(`[exceptd run --upstream-check] STALE: local v${upstreamCheck.local_version} < published v${upstreamCheck.latest_version} (published ${upstreamCheck.latest_published_at}, ${upstreamCheck.days_since_latest_publish}d ago). Continuing with local catalog. Run \`npm update -g @blamejs/exceptd-skills\` or \`exceptd refresh --network\` to consume the latest.\n`);
      }
    } catch (e) {
      upstreamCheck = { ok: false, error: e.message, source: "offline" };
    }
  }

  const result = runner.run(playbookId, directiveId, submission, runOpts);
  if (result && upstreamCheck) result.upstream_check = upstreamCheck;

  // v0.11.9 (#113/#114): surface --operator and --ack in the run result so
  // operators see the attribution + consent state without inspecting the
  // attestation file. Pre-0.11.9 these were persisted to disk only.
  // v0.11.10 (#119): add result.ack alias for consumers reading the
  // ack state by that name (`result.ack` is shorter + matches the CLI flag).
  if (result && runOpts.operator) result.operator = runOpts.operator;

  // --ack consent only counts when a jurisdiction clock is actually at
  // stake — i.e. the run produced classification=detected (a real finding
  // that may trigger NIS2 24h / DORA 4h / GDPR 72h obligations). On a
  // not-detected or inconclusive run, persisting the consent would record
  // operator acknowledgement of a clock that never started. Surface the
  // ack state in the run body either way so operators see what happened,
  // but only persist `operator_consent` into the attestation when
  // classification === detected.
  const detectClassification = result && result.phases && result.phases.detect
    ? result.phases.detect.classification
    : null;
  const consentApplies =
    !!runOpts.operator_consent && detectClassification === "detected";
  if (result && runOpts.operator_consent) {
    result.operator_consent = runOpts.operator_consent;
    result.ack = !!runOpts.operator_consent.explicit;
    result.ack_applied = consentApplies;
    if (!consentApplies) {
      result.ack_skipped_reason = `classification=${detectClassification || "unknown"}; consent only persisted when classification=detected (jurisdiction clock at stake).`;
    }
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
      // Gate consent persistence on classification=detected.
      operatorConsent: consentApplies ? runOpts.operator_consent : null,
      submission,
      runOpts,
      forceOverwrite: !!args["force-overwrite"],
      filename: "attestation.json",
    });
    if (!persistResult.ok) {
      // Session-id collision without --force-overwrite, OR --force-overwrite
      // lost the lockfile race, OR the filesystem refused the write (full
      // disk, quota, read-only). Three distinct exit-code classes:
      //   8  LOCK_CONTENTION       — retry from the outside (transient)
      //   9  STORAGE_EXHAUSTED     — disk/quota/RO — operator-side infra fix
      //   7  SESSION_ID_COLLISION  — pass --force-overwrite or fresh id
      // Route through emitError() shape so the body goes to stderr and exit
      // codes propagate via the emit() contract.
      const err = {
        ok: false,
        error: persistResult.error,
        existing_attestation: persistResult.existingPath,
        hint: persistResult.storage_exhausted
          ? "Free disk space, lift quota, or remount the attestation root read-write; then retry."
          : "Pass --force-overwrite to replace, or supply a fresh --session-id (omit the flag for an auto-generated hex).",
        verb: "run",
      };
      if (persistResult.lock_contention) {
        err.lock_contention = true;
        err.exit_code = EXIT_CODES.LOCK_CONTENTION;
      }
      if (persistResult.storage_exhausted) {
        err.storage_exhausted = true;
        err.exit_code = EXIT_CODES.STORAGE_EXHAUSTED;
      }
      emitError(persistResult.error, err, pretty);
      if (persistResult.lock_contention) process.exitCode = EXIT_CODES.LOCK_CONTENTION;
      else if (persistResult.storage_exhausted) process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED;
      else process.exitCode = EXIT_CODES.SESSION_ID_COLLISION;
      return;
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
    // Align preflight-halt exit code between `run --ci` and `ci`: both use
    // 4 (BLOCKED) when --ci is in effect so operators can wire one set of
    // exit-code expectations regardless of which verb they call. Without
    // --ci the legacy exit 1 is preserved (ok:false bodies are framework
    // signals when no CI gating is requested).
    process.stderr.write((pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + "\n");
    process.exitCode = args.ci ? EXIT_CODES.BLOCKED : EXIT_CODES.GENERIC_FAILURE;
    return;
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
      // v0.12.12: surface the contract violation in the emitted body so
      // downstream consumers grepping the JSON see WHY the exit is non-zero.
      // result.ok stays true (the playbook executed) but the explicit flag
      // makes the strict-preconditions contract observable, not just inferable
      // from exit code + stderr line.
      result.strict_preconditions_violated = warnIssues.map(i => ({
        id: i.id, kind: i.kind, message: i.message || null, on_fail: i.on_fail || null,
      }));
      process.stderr.write(`[exceptd run] --strict-preconditions: ${warnIssues.length} unverified/warn precondition(s) — exit ${EXIT_CODES.GENERIC_FAILURE}.\n`);
      emit(result, pretty);
      // v0.11.11: exitCode + return so emit()'s stdout flushes (process.exit
      // can truncate buffered async stdout writes when piped).
      process.exitCode = EXIT_CODES.GENERIC_FAILURE;
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

  // --block-on-jurisdiction-clock (F3): the flag was registered + documented on
  // `run --help` but only honored on cmdCi. Pre-fix, `exceptd run mcp
  // --block-on-jurisdiction-clock` exited 0 even when an NIS2 24h clock had
  // started. Now: when ANY close.notification_actions entry has a started
  // clock that the operator hasn't acked, exit 5 (CLOCK_STARTED) with a
  // stderr line naming the obligations. Mirrors cmdCi semantics.
  if (args["block-on-jurisdiction-clock"] && result && result.phases) {
    const startedClocks = (result.phases?.close?.notification_actions || [])
      .filter(n => n && n.clock_started_at != null && n.clock_pending_ack !== true);
    if (startedClocks.length > 0) {
      const refs = startedClocks
        .map(n => `${n.obligation_ref || n.jurisdiction || "?"}@${n.clock_started_at}`)
        .join("; ");
      process.stderr.write(`[exceptd run --block-on-jurisdiction-clock] CLOCK_STARTED: ${startedClocks.length} jurisdiction clock(s) running and unacked: ${refs}. Exit ${EXIT_CODES.JURISDICTION_CLOCK_STARTED}.\n`);
      emit(result, pretty);
      process.exitCode = EXIT_CODES.JURISDICTION_CLOCK_STARTED;
      return;
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

    // v0.12.8: use process.exitCode + return instead of process.exit() so
    // buffered async stdout (which `emit` writes to) is allowed to drain
    // before the event loop ends. v0.11.10 (#100) is the canonical class:
    // process.exit(N) immediately after a stdout write can truncate output
    // under piped consumers (CI runners, jq, test harnesses).
    if (classification === "detected") {
      process.stderr.write(`[exceptd run --ci] FAIL: classification=detected rwep=${adjusted} threshold=${threshold}\n`);
      process.exitCode = EXIT_CODES.DETECTED_ESCALATE;
      return;
    }
    if (classification === "inconclusive" && escalate) {
      process.stderr.write(`[exceptd run --ci] FAIL: classification=inconclusive AND rwep=${adjusted} >= threshold=${threshold}\n`);
      process.exitCode = EXIT_CODES.DETECTED_ESCALATE;
      return;
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
    // F11: surface --diff-from-latest verdict in the human renderer so
    // operators see whether the run drifted from the previous attestation
    // without adding --json. One summary line follows the classification.
    // Marker text is grep-matched by tests/audit-i-l-m-fixes.test.js F11.
    // - unchanged: same evidence_hash as prior → reassuring single line.
    // - drifted: evidence differs → loud DRIFTED marker.
    // - no_prior_attestation_for_playbook: no line — don't clutter the
    //   output when there is nothing to compare against.
    if (obj.diff_from_latest) {
      const dfl = obj.diff_from_latest;
      if (dfl.status === "unchanged") {
        lines.push(`> drift vs prior: unchanged (same evidence_hash as session ${dfl.prior_session_id})`);
      } else if (dfl.status === "drifted") {
        lines.push(`> drift vs prior: DRIFTED — evidence_hash differs from session ${dfl.prior_session_id}`);
      }
      // no_prior_attestation_for_playbook intentionally produces no line.
    }
    const cves = obj.phases?.analyze?.matched_cves || [];
    const baseline = obj.phases?.analyze?.catalog_baseline_cves || [];
    if (cves.length) {
      lines.push(`\nMatched CVEs (${cves.length}):`);
      for (const c of cves.slice(0, 6)) {
        const via = Array.isArray(c.correlated_via) && c.correlated_via.length ? `  via ${c.correlated_via[0]}${c.correlated_via.length > 1 ? ` (+${c.correlated_via.length - 1})` : ""}` : "";
        lines.push(`  ${c.cve_id}  RWEP ${c.rwep}  KEV=${c.cisa_kev}  ${c.active_exploitation || ""}${via}`);
      }
      if (cves.length > 6) lines.push(`  … ${cves.length - 6} more`);
    } else if (baseline.length) {
      // No evidence correlated to any CVE — clarify rather than implying the
      // operator is affected by the catalog enumeration. Pre-fix output read
      // like a hit list; explicit zero + scan-coverage callout fixes that.
      lines.push(`\nNo CVEs correlated to your evidence. Playbook catalog (informational): ${baseline.length} CVE(s) this playbook scans for.`);
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
      // v0.12.9 (P3 #12 from production smoke): handle preconditions without
      // an `on_fail` field (precondition.check was satisfied trivially or the
      // playbook omits the field). Pre-v0.12.9 these rendered as `[undefined]
      // <id>:`. Now: omit the bracket when on_fail is absent, and fall back
      // to the description if `check` is missing too.
      for (const i of issues) {
        const tag = i.on_fail ? `[${i.on_fail}] ` : "";
        const detail = i.check || i.description || i.reason || "(no detail)";
        lines.push(`  ${tag}${i.id}: ${detail}`);
      }
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
/**
 * Collapse per-playbook notification_actions into a deduped rollup.
 * Multi-playbook runs frequently surface the same jurisdiction clock from
 * 5-10 contributing playbooks (every EU-touching playbook starts a fresh
 * NIS2 Art.23 24h clock). Operators were drafting one notification per
 * entry instead of one per (jurisdiction, regulation, obligation, window).
 * Key tuple stays additive — every contributor playbook id lands in
 * `triggered_by_playbooks[]` — and earliest clock_started_at + deadline
 * win so the strictest deadline is what an operator sees.
 */
function buildJurisdictionClockRollup(results) {
  const m = new Map();
  for (const r of results || []) {
    if (!r || !r.phases) continue;
    const actions = r.phases?.close?.notification_actions || [];
    for (const n of actions) {
      if (!n || n.clock_started_at == null) continue;
      const key = [
        n.jurisdiction || "?",
        n.regulation || "?",
        n.obligation_ref || "?",
        String(n.window_hours ?? "?"),
      ].join("::");
      const existing = m.get(key);
      if (existing) {
        if (!existing.triggered_by_playbooks.includes(r.playbook_id)) {
          existing.triggered_by_playbooks.push(r.playbook_id);
        }
        // Strictest (earliest) clock_started_at + deadline win.
        if ((n.clock_started_at || "") < (existing.clock_started_at || "")) {
          existing.clock_started_at = n.clock_started_at;
        }
        if (n.deadline && (!existing.deadline || n.deadline < existing.deadline)) {
          existing.deadline = n.deadline;
        }
      } else {
        // Emit `obligation` and retain `obligation_ref` as a kept-name alias
        // for any consumer that already parses the older shape. The dedupe
        // key still keys on n.obligation_ref since that's the field
        // notification-action stubs carry; the rollup body just exposes
        // both names.
        const obligation = n.obligation_ref || null;
        m.set(key, {
          jurisdiction: n.jurisdiction || null,
          regulation: n.regulation || null,
          obligation,
          obligation_ref: obligation,
          window_hours: n.window_hours ?? null,
          clock_started_at: n.clock_started_at,
          deadline: n.deadline || null,
          triggered_by_playbooks: [r.playbook_id],
        });
      }
    }
  }
  return [...m.values()];
}

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
    if (typeof dir !== "string" || dir.length === 0) {
      return emitError("run: --evidence-dir must be a non-empty string.", null, pretty);
    }
    if (!fs.existsSync(dir)) {
      return emitError(`run: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    const resolvedDir = path.resolve(dir);
    // v0.12.12: only `<playbook-id>.json` entries are honored. Reject
    // anything where the filename strip leaves traversal segments — npm
    // refuses to write such filenames so the realistic risk is an operator
    // symlink/junction inside the dir, but the filter is cheap.
    for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
      const pbId = f.replace(/\.json$/, "");
      // Reuse the shared playbook-id validator so the --evidence-dir entry
      // filter agrees with the runtime playbook-id allowlist. Previously
      // accepted dots / underscores / uppercase that no real playbook id
      // uses, which would silently absorb a typo'd filename as a "valid"
      // entry that loadPlaybook then refused mid-loop.
      const pbCheck = validateIdComponent(pbId, "playbook");
      if (!pbCheck.ok) {
        return emitError(
          `run: --evidence-dir entry ${JSON.stringify(f)} has invalid playbook-id segment (${pbCheck.reason}).`,
          { entry: f, expected_shape: "<playbook-id>.json (lowercase, starts with letter, no dots)" },
          pretty
        );
      }
      const entryPath = path.resolve(path.join(resolvedDir, f));
      if (!entryPath.startsWith(resolvedDir + path.sep)) {
        return emitError(`run: --evidence-dir entry ${f} resolves outside the directory; refusing.`, null, pretty);
      }
      // The path.resolve check above only catches `..` traversal in the
      // joined path; fs.readFileSync(entryPath) still follows symlinks, so
      // a `<pb-id>.json -> /etc/shadow` symlink inside the dir would happily
      // slurp the target. lstat is symlink-aware (it does NOT follow);
      // refuse anything that's not a regular file. Defense in depth on top
      // of the readdir filter — a junction (Windows) or bind-mount can
      // shape-shift in between filter and read.
      let lst;
      try { lst = fs.lstatSync(entryPath); }
      catch (e) {
        return emitError(`run: --evidence-dir entry ${f}: lstat failed: ${e.message}`, null, pretty);
      }
      if (lst.isSymbolicLink()) {
        return emitError(`run: --evidence-dir entry ${f} is a symbolic link; refusing (symlinks bypass the directory-confinement check).`, { entry: f }, pretty);
      }
      if (!lst.isFile()) {
        return emitError(`run: --evidence-dir entry ${f} is not a regular file; refusing.`, { entry: f }, pretty);
      }
      // Windows directory junctions are reparse-point dirs that
      // `lstat().isSymbolicLink()` returns FALSE for (Node treats them as
      // ordinary directories), bypassing the symlink refusal above. Use
      // realpathSync to resolve the entry and confirm it still lives under
      // the resolved evidence-dir — the realpath approach is portable
      // (catches POSIX symlinks too, defense in depth) and works regardless
      // of whether the OS exposes reparse-point bits.
      let realEntry;
      try { realEntry = fs.realpathSync(entryPath); }
      catch (e) {
        return emitError(`run: --evidence-dir entry ${f}: realpath failed: ${e.message}`, null, pretty);
      }
      if (realEntry !== entryPath && !realEntry.startsWith(resolvedDir + path.sep)) {
        return emitError(
          `run: --evidence-dir entry ${f} resolves outside the directory (junction / reparse-point / symlink target). Refusing.`,
          { entry: f, resolved_to: realEntry },
          pretty
        );
      }
      // Hardlink defense in depth: no clean cross-platform refusal exists —
      // hardlinks are indistinguishable from regular files at the inode
      // level. Surface a stderr warning when nlink > 1 so the operator is
      // aware a second name may point at the same file. Not a refusal —
      // legitimate use cases (atomic rename, package-manager dedup) produce
      // nlink > 1 without malicious intent.
      if (lst.nlink > 1) {
        process.stderr.write(`[exceptd run --evidence-dir] WARNING: ${f} has nlink=${lst.nlink}; a hardlink to this file exists elsewhere on the filesystem. Hardlinks cannot be refused cross-platform — confirm the file content is what you expect.\n`);
      }
      try {
        bundle[pbId] = JSON.parse(fs.readFileSync(entryPath, "utf8"));
      } catch (e) {
        return emitError(`run: failed to parse --evidence-dir entry ${f}: ${e.message}`, null, pretty);
      }
    }
  }

  const results = [];
  for (const id of ids) {
    // Defense-in-depth: ids come from listPlaybooks() / filterPlaybooksByScope
    // (which read trusted catalog data), but threading every id through
    // validateIdComponent('playbook') means a corrupt catalog cannot
    // path-traverse via this loop either.
    const r = validateIdComponent(id, "playbook");
    if (!r.ok) {
      results.push({ playbook_id: id, ok: false, error: `invalid playbook id (${r.reason})` });
      continue;
    }
    const pb = runner.loadPlaybook(id);
    const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
    if (!directiveId) {
      results.push({ playbook_id: id, ok: false, error: `playbook ${id} has no directives` });
      continue;
    }
    const submission = bundle[id] || {};
    const perRunOpts = { ...runOpts };
    if (submission.precondition_checks) perRunOpts.precondition_checks = submission.precondition_checks;

    const result = runner.run(id, directiveId, submission, perRunOpts);

    // Per-playbook --ack gating: consent only counts when a jurisdiction
    // clock is actually at stake on THIS playbook's verdict — i.e. its
    // detect.classification === 'detected'. Without this gate, a single
    // --ack on a run-all invocation would persist explicit consent into
    // every playbook's attestation regardless of whether that playbook's
    // run started a clock. The `ack_skipped_reason` surface mirrors cmdRun
    // so consumers see exactly which playbooks consumed the ack.
    const perDetectClassification = result && result.phases && result.phases.detect
      ? result.phases.detect.classification
      : null;
    const perConsentApplies =
      !!perRunOpts.operator_consent && perDetectClassification === "detected";
    if (result && perRunOpts.operator_consent) {
      result.operator_consent = perRunOpts.operator_consent;
      result.ack = !!perRunOpts.operator_consent.explicit;
      result.ack_applied = perConsentApplies;
      if (!perConsentApplies) {
        result.ack_skipped_reason = `classification=${perDetectClassification || "unknown"}; consent only persisted when classification=detected (jurisdiction clock at stake).`;
      }
    } else if (result) {
      result.ack = false;
    }

    // Persist per-playbook attestation under the shared session.
    if (result && result.ok) {
      const persisted = persistAttestation({
        sessionId,
        playbookId: id,
        directiveId,
        evidenceHash: result.evidence_hash,
        operator: perRunOpts.operator,
        // Gate consent persistence on this playbook's classification, not
        // on the aggregate run's --ack presence.
        operatorConsent: perConsentApplies ? perRunOpts.operator_consent : null,
        submission,
        runOpts: perRunOpts,
        forceOverwrite: !!args["force-overwrite"],
        filename: `${id}.json`,
      });
      if (!persisted.ok) {
        // Multi-run collision: don't abort the whole bundle; surface in the
        // per-playbook result so the operator can see exactly which
        // playbook's attestation refused to overwrite. Propagate
        // lock_contention / storage_exhausted / exit_code so the aggregate
        // exit-code gate below picks the right top-level code (8 / 9 /
        // 7 / 1) instead of collapsing every persist failure to 1.
        result.attestation_persist = { ok: false, error: persisted.error };
        if (persisted.lock_contention) {
          result.attestation_persist.lock_contention = true;
          result.attestation_persist.exit_code = EXIT_CODES.LOCK_CONTENTION;
        }
        if (persisted.storage_exhausted) {
          result.attestation_persist.storage_exhausted = true;
          result.attestation_persist.exit_code = EXIT_CODES.STORAGE_EXHAUSTED;
        }
      } else if (persisted.prior_session_id) {
        result.attestation_persist = { ok: true, prior_session_id: persisted.prior_session_id, overwrote_at: persisted.overwrote_at };
      }
    }
    results.push(result);
  }

  // Dedupe jurisdiction-clock notification actions across all playbook
  // results into a single rollup. Without this, a 13-playbook multi-run
  // with 8 contributors of "EU NIS2 Art.23 24h" produces 8 separate
  // entries and operators draft 8 NIS2 notifications when one suffices.
  // Per-playbook entries are preserved on individual results; this rollup
  // is additive — keyed on (jurisdiction, regulation, obligation_ref,
  // window_hours) — with a triggered_by_playbooks[] list so operators see
  // which playbooks contributed.
  const jurisdictionClockRollup = buildJurisdictionClockRollup(results);

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
    jurisdiction_clock_rollup: jurisdictionClockRollup,
    results,
  }, pretty);
  // v0.11.9 (#100): cmdRunMulti exits non-zero when any individual run
  // returned ok:false. Pre-0.11.9 the aggregate result had {ok:false} in
  // the body but exit code stayed 0 — CI gates couldn't distinguish "ran
  // clean" from "blocked." v0.12.8: use exitCode (not process.exit()) so
  // the aggregate JSON emitted above is allowed to fully drain.
  //
  // Aggregate exit-code precedence: LOCK_CONTENTION > STORAGE_EXHAUSTED >
  // BLOCKED. Lock contention is transient (retry-from-outside fixes it);
  // storage exhaustion is an infra event requiring operator action;
  // ok:false in a per-playbook result is the BLOCKED case. Surfacing the
  // most-specific code first means a CI gate can branch on the right
  // remediation without parsing the body.
  const anyLockBusy = results.some(r => r.attestation_persist && r.attestation_persist.lock_contention === true);
  const anyStorageExhausted = results.some(r => r.attestation_persist && r.attestation_persist.storage_exhausted === true);
  const anyBlocked = results.some(r => r.ok === false);
  if (anyLockBusy) { process.exitCode = EXIT_CODES.LOCK_CONTENTION; return; }
  if (anyStorageExhausted) { process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED; return; }
  if (anyBlocked) { process.exitCode = EXIT_CODES.GENERIC_FAILURE; return; }
}

function cmdIngest(runner, args, runOpts, pretty) {
  // `ingest` matches the AGENTS.md ingest contract. The submission JSON may
  // carry playbook_id + directive_id; --domain/--directive flags override.
  let submission = {};
  // Auto-detect piped stdin (parity with cmdRun) so
  // `echo '{...}' | exceptd ingest` reads the routing JSON instead of
  // failing with "no playbook resolved" because args.evidence stays
  // undefined.
  // Route stdin auto-detection through hasReadableStdin() (see cmdRun for
  // rationale). Wrapped-stdin test harnesses (Mocha/Jest, Docker
  // stdin-passthrough) would otherwise block here forever on the
  // readFileSync(0) call when isTTY === undefined.
  if (!args.evidence && hasReadableStdin()) {
    args.evidence = "-";
  }
  if (args.evidence) {
    try {
      submission = readEvidence(args.evidence);
    } catch (e) {
      return emitError(`ingest: failed to read evidence: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }
  const playbookId = args.domain || submission.playbook_id || submission.domain;
  if (!playbookId) return emitError("ingest: no playbook resolved — pass --domain <id> or include playbook_id in evidence JSON.", null, pretty);
  if (refuseInvalidPlaybookId("ingest", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive
    || submission.directive_id
    || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("ingest", playbookId, pretty);

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

  // v0.12.8: route ingest's attestation persistence through persistAttestation
  // — the same path cmdRun + cmdRunMulti use — so the session-id collision
  // refusal AND the Ed25519 sidecar signing both apply. Pre-v0.12.8 ingest
  // had its own inline writeFileSync with neither check, meaning two ingest
  // calls with the same session-id silently clobbered the audit trail and no
  // .sig sidecar was written.
  if (result && result.ok && result.session_id) {
    // Mirror cmdRun / cmdRunMulti: gate operator_consent persistence on
    // classification === 'detected'. --ack is meaningful only when a
    // jurisdiction clock is at stake; persisting consent on a
    // not-detected ingest forges audit-trail consent for a clock that
    // never started.
    const ingestClassification = result.phases && result.phases.detect ? result.phases.detect.classification : null;
    const ingestConsentApplies = ingestClassification === "detected";
    if (runOpts.operator_consent && !ingestConsentApplies) {
      result.ack = true;
      result.ack_applied = false;
      result.ack_skipped_reason = `classification=${ingestClassification || "unknown"}; consent only persisted when classification=detected (jurisdiction clock at stake).`;
    }
    const persisted = persistAttestation({
      sessionId: result.session_id,
      playbookId: result.playbook_id,
      directiveId: result.directive_id,
      evidenceHash: result.evidence_hash,
      operator: runOpts.operator,
      operatorConsent: ingestConsentApplies ? runOpts.operator_consent : null,
      submission: cleanedSubmission,
      runOpts,
      forceOverwrite: !!args["force-overwrite"],
      filename: "attestation.json",
    });
    if (!persisted.ok) {
      // Route every persist-failure shape through emitError so the
      // emit() ok:false → exitCode contract applies uniformly. Three
      // exit classes: LOCK_CONTENTION (transient), STORAGE_EXHAUSTED
      // (infra), SESSION_ID_COLLISION (operator decision).
      const ctx = { session_id: result.session_id, existing_path: persisted.existingPath };
      if (persisted.lock_contention) {
        ctx.lock_contention = true;
        ctx.exit_code = EXIT_CODES.LOCK_CONTENTION;
      }
      if (persisted.storage_exhausted) {
        ctx.storage_exhausted = true;
        ctx.exit_code = EXIT_CODES.STORAGE_EXHAUSTED;
      }
      emitError(persisted.error, ctx, pretty);
      if (persisted.lock_contention) process.exitCode = EXIT_CODES.LOCK_CONTENTION;
      else if (persisted.storage_exhausted) process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED;
      else process.exitCode = EXIT_CODES.SESSION_ID_COLLISION;
      return;
    }
    if (persisted.prior_session_id) {
      result.attestation_persist = { ok: true, prior_session_id: persisted.prior_session_id, overwrote_at: persisted.overwrote_at };
    }
  }

  if (result && result.ok === false) {
    process.stderr.write((pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + "\n");
    process.exitCode = 1;
    return;
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
  // v0.12.12: session-id is supposed to be sanitized at input. Defense in
  // depth: reject anything that path-traverses out of the attestation root.
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(sessionId || "")) {
    return {
      ok: false,
      error: `Refusing to persist attestation with unsafe session-id: ${JSON.stringify(sessionId).slice(0, 80)}. Must match /^[A-Za-z0-9._-]{1,64}$/.`,
      existingPath: null,
    };
  }
  if (!/^[A-Za-z0-9._-]{1,64}\.json$/.test(filename || "")) {
    return {
      ok: false,
      error: `Refusing to persist attestation with unsafe filename: ${JSON.stringify(filename).slice(0, 80)}.`,
      existingPath: null,
    };
  }
  const root = resolveAttestationRoot(runOpts);
  const dir = path.join(root, sessionId);
  const filePath = path.join(dir, filename);
  // Final-resolution check: dir must remain inside root after normalization.
  const normRoot = path.resolve(root) + path.sep;
  if (!(path.resolve(dir) + path.sep).startsWith(normRoot)) {
    return {
      ok: false,
      error: `Refusing to persist attestation outside root. session_id=${sessionId} root=${root}`,
      existingPath: null,
    };
  }

  try {
    fs.mkdirSync(dir, { recursive: true });
    const writeAttestation = (priorEvidenceHash, priorCapturedAt, flag) => {
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
        prior_evidence_hash: priorEvidenceHash,
        prior_captured_at: priorCapturedAt,
      };
      // Atomic-create via O_EXCL ('wx' flag) eliminates the TOCTOU window
      // between existsSync and writeFileSync. Two concurrent run-with-same-
      // session-id invocations now produce one winner + one EEXIST loser,
      // not silent last-write-wins.
      fs.writeFileSync(filePath, JSON.stringify(attestation, null, 2), { flag });
      maybeSignAttestation(filePath);
    };

    try {
      writeAttestation(null, null, "wx");
      return { ok: true, prior_session_id: null, overwrote_at: null };
    } catch (eExcl) {
      if (eExcl.code !== "EEXIST") throw eExcl;
      // Slot already taken — read prior to chain audit trail, then decide.
      let prior = null;
      try { prior = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { /* malformed prior — proceed */ }
      if (!forceOverwrite) {
        return {
          ok: false,
          error: `Attestation already exists at ${path.relative(process.cwd(), filePath)}. Session-id collision (${sessionId}) — refusing to overwrite to preserve audit trail.`,
          existingPath: path.relative(process.cwd(), filePath),
        };
      }
      // Serialize the read-prior + write-new sequence behind a lockfile so
      // concurrent --force-overwrite invocations against the same session-id
      // slot do not degrade to last-write-wins. Pattern matches
      // withCatalogLock + withIndexLock: O_EXCL 'wx' on a sibling .lock file
      // with bounded retry, PID-liveness check on contention, mtime fallback
      // for orphaned lockfiles.
      // DD P1-2: MAX_RETRIES is capped at 10. persistAttestation is sync and
      // called from sync callers, so the wait loop must busy-spin (no
      // event-loop yield available). A larger bound would peg the CPU and
      // freeze the event loop for multiple seconds under attestation
      // contention. Capping at 10 bounds the freeze at ~1-2s; beyond that
      // callers receive the LOCK_CONTENTION sentinel on the result object
      // and can retry from the outside without holding the CPU. Async
      // refactor of persistAttestation + every caller is a v0.13.0
      // candidate.
      const lockPath = filePath + ".lock";
      const MAX_RETRIES = 10;
      const STALE_LOCK_MS = 30_000;
      let acquired = false;
      for (let i = 0; i < MAX_RETRIES; i++) {
        try {
          fs.writeFileSync(lockPath, String(process.pid), { flag: "wx" });
          acquired = true;
          break;
        } catch (lockErr) {
          // Distinguish lockfile contention (EEXIST/EPERM = another holder)
          // from storage-exhaustion classes (ENOSPC = disk full,
          // EROFS = read-only fs, EDQUOT = quota exceeded). The latter are
          // infra-level failures that no amount of retry-spin will resolve;
          // surface them with a distinct exit code (STORAGE_EXHAUSTED = 9)
          // so operator runbooks can branch on "free disk" vs "retry".
          if (lockErr.code === "ENOSPC" || lockErr.code === "EROFS" || lockErr.code === "EDQUOT") {
            process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED;
            return {
              ok: false,
              error: `STORAGE_EXHAUSTED: ${lockErr.message}`,
              existingPath: path.relative(process.cwd(), filePath),
              storage_exhausted: true,
              exit_code: EXIT_CODES.STORAGE_EXHAUSTED,
            };
          }
          if (lockErr.code !== "EEXIST" && lockErr.code !== "EPERM") throw lockErr;
          let reclaimed = false;
          try {
            const raw = fs.readFileSync(lockPath, "utf8").trim();
            const pid = Number.parseInt(raw, 10);
            if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
              try { process.kill(pid, 0); }
              catch (probeErr) {
                if (probeErr && probeErr.code === "ESRCH") {
                  try { fs.unlinkSync(lockPath); reclaimed = true; } catch {}
                }
              }
            }
          } catch {}
          if (reclaimed) continue;
          try {
            const stat = fs.statSync(lockPath);
            if (Date.now() - stat.mtimeMs > STALE_LOCK_MS) {
              try { fs.unlinkSync(lockPath); } catch {}
              continue;
            }
          } catch {}
          // Synchronous spin — persistAttestation is sync; we cannot await.
          const deadline = Date.now() + 50 + Math.floor(Math.random() * 150);
          while (Date.now() < deadline) { /* spin */ }
        }
      }
      if (!acquired) {
        // Surface lock_contention as a distinct sentinel so callers can
        // distinguish a genuine lock-busy condition (retry-from-outside is
        // the right move) from a hard failure (write error, permission
        // denial). The sync spin budget is bounded above so this return
        // fires after ~1-2s of contention.
        //
        // emit() auto-maps any ok:false body to process.exitCode = 1 (only
        // when the current value is still 0). Pin process.exitCode = 8 HERE
        // before the caller hands the body to emit(); emit() preserves the
        // already-non-zero value. Exit code 8 is reserved exclusively for
        // LOCK_CONTENTION (attestation persist); see the exit-code table in
        // printGlobalHelp().
        process.exitCode = EXIT_CODES.LOCK_CONTENTION;
        return {
          ok: false,
          error: `LOCK_CONTENTION: Failed to acquire attestation lock at ${path.relative(process.cwd(), lockPath)} after ${MAX_RETRIES} attempts (~1-2s of contention). Retry the operation; if it persists, inspect the lockfile for a stale holder.`,
          existingPath: path.relative(process.cwd(), filePath),
          lock_contention: true,
          exit_code: EXIT_CODES.LOCK_CONTENTION,
        };
      }
      try {
        // Re-read prior INSIDE the lock — the value captured before lock
        // acquisition may be stale if another --force-overwrite landed
        // between our EEXIST probe and the lock grab.
        let lockedPrior = prior;
        try { lockedPrior = JSON.parse(fs.readFileSync(filePath, "utf8")); }
        catch { /* keep pre-lock prior */ }
        writeAttestation(lockedPrior ? (lockedPrior.evidence_hash || null) : null,
                         lockedPrior ? (lockedPrior.captured_at || null) : null,
                         "w");
        return {
          ok: true,
          prior_session_id: lockedPrior ? sessionId : null,
          overwrote_at: lockedPrior ? lockedPrior.captured_at : null,
        };
      } finally {
        try { fs.unlinkSync(lockPath); } catch {}
      }
    }
  } catch (e) {
    // ENOSPC / EROFS / EDQUOT are storage-exhaustion classes — surface
    // them with a distinct sentinel + exit code so callers route them
    // through a different remediation path than generic write errors.
    if (e && (e.code === "ENOSPC" || e.code === "EROFS" || e.code === "EDQUOT")) {
      process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED;
      return {
        ok: false,
        error: `STORAGE_EXHAUSTED: ${e.message}`,
        existingPath: null,
        storage_exhausted: true,
        exit_code: EXIT_CODES.STORAGE_EXHAUSTED,
      };
    }
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
/**
 * Byte-stability normalize() for the attestation pipeline.
 * Strips a leading UTF-8 BOM and collapses CRLF → LF. Mirrors the
 * normalize() implementations in lib/sign.js, lib/verify.js,
 * lib/refresh-network.js, and scripts/verify-shipped-tarball.js. Five
 * sites total; tests/normalize-contract.test.js asserts byte-identical
 * output across all of them.
 */
function normalizeAttestationBytes(input) {
  let s = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, "\n");
}

function maybeSignAttestation(filePath) {
  const crypto = require("crypto");
  const sigPath = filePath + ".sig";
  // v0.12.9 (P2 #3 from production smoke + codex P1 PR #4 review): keep the
  // sign key aligned with the VERIFY key. `attest verify` checks signatures
  // against PKG_ROOT/keys/public.pem; if we sign with cwd/.keys/private.pem
  // (e.g. the maintainer's repo-local keypair) the resulting `.sig` will
  // verify INVALID and report a false tamper signal on every freshly-written
  // attestation. PKG_ROOT-only resolution is the right answer; the original
  // smoke report's "doctor finds key, run does not" gap is fixed in `doctor`
  // (reporting only PKG_ROOT now), not by making `run` follow a cwd key the
  // verifier doesn't trust.
  const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
  // Normalize attestation bytes before sign — strip leading UTF-8 BOM +
  // collapse CRLF to LF. Mirrors lib/sign.js / lib/verify.js /
  // lib/refresh-network.js / scripts/verify-shipped-tarball.js. The
  // attestation file lives on disk under .exceptd/ and can pick up CRLF
  // through git-attribute / editor round-trips on Windows; without
  // normalization the sign/verify pair diverges on the same logical content.
  // The byte-stability contract spans five sites; tests/normalize-contract
  // .test.js enforces byte-identical output across all of them.
  const rawContent = fs.readFileSync(filePath, "utf8");
  const content = normalizeAttestationBytes(rawContent);
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
      // The sidecar's Ed25519 signature covers ONLY the attestation file
      // bytes. Fields that travel inside the .sig but are NOT in the signed
      // message are replay-rewrite trivial: an attacker who can write the
      // directory can mutate them without invalidating the signature. The
      // sidecar therefore carries only the algorithm tag, the Ed25519
      // signature payload, and an explanatory note — no `signed_at`,
      // `signs_path`, or `signs_sha256`. Operators reading freshness use
      // filesystem mtime; the attestation file's `captured_at` field is
      // what's signed.
      fs.writeFileSync(sigPath, JSON.stringify({
        algorithm: "Ed25519",
        signature_base64: sig.toString("base64"),
        note: "Ed25519 signature covers the attestation file bytes only. Use filesystem mtime for freshness; use the attestation's `captured_at` for the signed timestamp.",
      }, null, 2));
    } else {
      fs.writeFileSync(sigPath, JSON.stringify({
        algorithm: "unsigned",
        signed: false,
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
/**
 * v0.12.14: session-id validation — applied at every READ
 * site, not just writes. The write path (persistAttestation) was hardened
 * in v0.12.12, but the read paths (findSessionDir / cmdAttest / cmdReattest)
 * accepted arbitrary strings and joined them into path.join(root, id) with
 * no normalization. Reproducer that exfiltrated $HOME/.claude.json:
 *   exceptd attest show '../../..'
 *
 * Validation regex + root-confinement check matches persistAttestation.
 */
function validateSessionIdForRead(sessionId) {
  // Route through validateIdComponent('session') so the regex + all-dots
  // refusal stay aligned with the write-path validator in
  // persistAttestation. Single source of truth in lib/id-validation.js.
  const r = validateIdComponent(sessionId, "session");
  if (!r.ok) {
    throw new Error(
      `Invalid session-id: ${typeof sessionId === "string" ? JSON.stringify(sessionId).slice(0, 80) : typeof sessionId}. ${r.reason}.`
    );
  }
  return sessionId;
}

function findSessionDir(sessionId, runOpts) {
  // v0.12.14: validate the session-id at every read path.
  try { validateSessionIdForRead(sessionId); }
  catch { return null; }
  const candidates = [
    path.join(resolveAttestationRoot(runOpts), sessionId),
    path.join(process.cwd(), ".exceptd", "attestations", sessionId),
  ];
  for (const c of candidates) {
    // Final-resolution check: the resolved candidate must stay strictly
    // inside its parent root after normalization. Defense in depth on top
    // of the regex check above — catches anything that survives the
    // string-level filter.
    const parent = path.dirname(c);
    const resolved = path.resolve(c);
    if (!resolved.startsWith(path.resolve(parent) + path.sep)) continue;
    if (fs.existsSync(c)) return c;
  }
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
        // Replay records (kind: 'replay') are an audit trail of force-replay
        // overrides, not a separate attestation. They have no captured_at /
        // evidence_hash and must not surface as candidates for --latest.
        // Gate on the parsed kind so a renamed file cannot smuggle a replay
        // record into the listing.
        if (j && j.kind === "replay") continue;
        if (opts.playbookId && j.playbook_id !== opts.playbookId) continue;
        if (opts.since && (j.captured_at || "") < opts.since) continue;
        if (opts.excludeSessionId && sid === opts.excludeSessionId) continue;
        candidates.push({ sessionId: sid, playbookId: j.playbook_id, file: p, parsed: j });
      } catch { /* skip malformed */ }
    }
  }
}

/**
 * Factored Ed25519-sidecar verification used by both `attest verify` and
 * `reattest`. Returns { file, signed, verified, reason } for a given
 * attestation file path.
 *
 * Callers must check `signed && verified` before consuming the
 * attestation. cmdReattest refuses to replay on verify-fail unless
 * --force-replay is set, so a tampered attestation cannot silently feed
 * forged input into the drift verdict.
 */
function verifyAttestationSidecar(attFile) {
  const crypto = require("crypto");
  const sigPath = attFile + ".sig";
  const pubKeyPath = path.join(PKG_ROOT, "keys", "public.pem");
  const pubKey = fs.existsSync(pubKeyPath) ? fs.readFileSync(pubKeyPath, "utf8") : null;
  // Consult keys/EXPECTED_FINGERPRINT before honoring
  // the loaded public key. The v0.12.16 CHANGELOG claimed "pin consulted
  // at every public-key load site," but reattest's signature verifier
  // loaded keys/public.pem without the pin cross-check. A coordinated
  // attacker who swapped keys/public.pem on the operator's host could
  // verify-against-attacker-key without surfacing the divergence. Honors
  // KEYS_ROTATED=1 to bypass during legitimate rotation.
  if (pubKey) {
    const pinError = assertExpectedFingerprint(pubKey);
    if (pinError) {
      return { file: attFile, signed: false, verified: false, reason: pinError };
    }
  }
  if (!fs.existsSync(sigPath)) {
    return { file: attFile, signed: false, verified: false, reason: "no .sig sidecar" };
  }
  let sigDoc;
  try { sigDoc = JSON.parse(fs.readFileSync(sigPath, "utf8")); }
  catch (e) {
    // a corrupt-JSON sidecar is observationally indistinguishable
    // from sidecar tamper — an attacker who can rewrite attestation.json can
    // also truncate / mangle the .sig file. Surface as a distinct
    // tamper-class reason so callers can require --force-replay. Pre-fix,
    // cmdReattest only refused on `reason === "no .sig sidecar"`; a
    // parse-error reason fell through to the benign NOTE branch and replay
    // proceeded against forged input.
    return {
      file: attFile,
      signed: false,
      verified: false,
      reason: `sidecar parse error: ${e.message}`,
      tamper_class: "sidecar-corrupt",
    };
  }
  if (sigDoc.algorithm === "unsigned") {
    // `algorithm: "unsigned"` is only legitimate when written
    // by maybeSignAttestation() at attestation-creation time on a host
    // WITHOUT .keys/private.pem. If the verifying host HAS a private key,
    // an "unsigned" sidecar is a substitution attack: tamper attestation.json
    // (breaking Ed25519) then overwrite .sig with the unsigned stub to bypass
    // the tamper detector. Promote to tamper-class so callers can refuse.
    const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
    if (fs.existsSync(privKeyPath)) {
      return {
        file: attFile,
        signed: false,
        verified: false,
        reason: "attestation explicitly unsigned but .keys/private.pem IS present on this host — sidecar substitution suspected (legitimate unsigned attestations cannot exist alongside a private key)",
        tamper_class: "unsigned-substitution",
      };
    }
    return { file: attFile, signed: false, verified: false, reason: "attestation explicitly unsigned (no private key when written)" };
  }
  // Strict algorithm check. A branch on `=== "unsigned"` alone would let
  // null, undefined, "RSA-PSS", arrays, etc. fall through to crypto.verify
  // with default Ed25519 args — which can either succeed against
  // wrong-algorithm signature bytes accidentally (an attacker who can
  // write the sidecar replays an existing Ed25519 signature under a
  // downgrade-bait algorithm tag) or throw a generic verify error.
  // Refuse anything that isn't exactly "Ed25519" or "unsigned" with a
  // structured tamper class so callers can route the refusal through the
  // same exit-6 path as other tamper events.
  if (sigDoc.algorithm !== "Ed25519") {
    return {
      file: attFile,
      signed: false,
      verified: false,
      reason: "unsupported algorithm: " + JSON.stringify(sigDoc.algorithm),
      tamper_class: "algorithm-unsupported",
    };
  }
  if (!pubKey) {
    return { file: attFile, signed: true, verified: false, reason: "no public key at keys/public.pem to verify against" };
  }
  let content;
  try {
    const raw = fs.readFileSync(attFile, "utf8");
    // Apply the same normalize() used by the signer so the verify path is
    // byte-stable across CRLF / BOM churn (Windows checkout with
    // core.autocrlf=true, editor round-trips, git-attributes flips).
    content = normalizeAttestationBytes(raw);
  }
  catch (e) { return { file: attFile, signed: true, verified: false, reason: `attestation read error: ${e.message}` }; }
  try {
    const ok = crypto.verify(null, Buffer.from(content, "utf8"), {
      key: pubKey, dsaEncoding: "ieee-p1363",
    }, Buffer.from(sigDoc.signature_base64, "base64"));
    return {
      file: attFile,
      signed: true,
      verified: !!ok,
      reason: ok ? "Ed25519 signature valid" : "Ed25519 signature INVALID — possible post-hoc tampering",
    };
  } catch (e) {
    return { file: attFile, signed: true, verified: false, reason: `verify error: ${e.message}` };
  }
}

function cmdReattest(runner, args, runOpts, pretty) {
  const crypto = require("crypto");
  // Validate --since as ISO-8601, mirroring `attest list --since`. An
  // invalid date would otherwise pass through to walkAttestationDir, where
  // the lexical comparison either matches all or none unpredictably.
  if (args.since != null) {
    // ISO-8601 shape regex BEFORE Date.parse — bare integers like "99"
    // would otherwise parse as the year 1999 and silently filter wrong
    // eras.
    const sinceErr = validateIsoSince(args.since);
    if (sinceErr) return emitError(`reattest: ${sinceErr}`, null, pretty);
  }
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

  // Verify the .sig sidecar BEFORE consuming the prior attestation. A
  // tampered attestation.json would otherwise be silently parsed and the
  // drift verdict computed against forged input. Refuse on verify-fail
  // with exit 6 (TAMPERED) unless --force-replay is explicitly set.
  // Unsigned attestations (no private key was available at run time) emit
  // a stderr warning but proceed — that's an operator config issue, not
  // tampering. `verified === false && signed === true` is the real tamper
  // signal.
  const verify = verifyAttestationSidecar(attFile);
  // Collapse tamper-class detection. Any non-benign sidecar state
  // (signed-but-invalid, sidecar-corrupt, unsigned-substitution) refuses
  // replay unless --force-replay is set. A predicate of only
  // `verify.signed && !verify.verified` would miss corrupt-JSON sidecars
  // and substituted "unsigned" sidecars on a host WITH a private key —
  // both of which let replay proceed against forged input.
  const isSignedTamper = verify.signed && !verify.verified;
  const isClassTamper = !verify.signed && (
    verify.tamper_class === "sidecar-corrupt"
    || verify.tamper_class === "unsigned-substitution"
    // Extend tamper-class refusal to algorithm-unsupported sidecars —
    // anything other than "Ed25519" or "unsigned". Without explicit
    // refusal, a sidecar that throws inside crypto.verify (e.g.
    // signature_base64 missing on a downgrade-bait shape) emerges as
    // signed:true + verified:false through the catch block by accident.
    // The strict pre-check surfaces the class directly; refuse on it too.
    || verify.tamper_class === "algorithm-unsupported"
  );
  if ((isSignedTamper || isClassTamper) && !args["force-replay"]) {
    process.stderr.write(`[exceptd reattest] TAMPERED: attestation at ${attFile} failed Ed25519 verification (${verify.reason}). Refusing to replay against forged input. Pass --force-replay to override (the replay output records sidecar_verify so the audit trail captures the override).\n`);
    const body = {
      ok: false,
      error: `reattest: prior attestation failed signature verification — refusing to replay`,
      verb: "reattest",
      session_id: sessionId,
      attestation_file: attFile,
      sidecar_verify: verify,
      hint: "If you have inspected the attestation and the divergence is benign (e.g. you re-signed manually), pass --force-replay.",
    };
    process.stderr.write(JSON.stringify(body) + "\n");
    process.exitCode = EXIT_CODES.TAMPERED;
    return;
  }
  if ((isSignedTamper || isClassTamper) && args["force-replay"]) {
    process.stderr.write(`[exceptd reattest] WARNING: --force-replay overriding failed signature verification on ${attFile} (${verify.reason}). The replay output records sidecar_verify so the override is audit-visible.\n`);
  } else if (!verify.signed && verify.reason && verify.reason.includes("no .sig sidecar") && !args["force-replay"]) {
    // missing-sidecar is NOT benign. The previous flow accepted
    // a missing .sig file silently (only blocked on signed-but-invalid).
    // Sidecar deletion is observationally identical to sidecar tamper —
    // an attacker who can rewrite the attestation can also rm the sidecar,
    // and pre-fix that path produced a green replay with no audit warning.
    // Now: refuse unless --force-replay, and the persisted replay body
    // records sidecar_verify so the override is audit-visible. Operators
    // whose original run wrote unsigned attestations (no private key
    // available) hit the "explicitly unsigned" branch below, which is
    // distinguishable from a missing sidecar.
    process.stderr.write(`[exceptd reattest] TAMPERED-OR-MISSING: no .sig sidecar at ${attFile}.sig. Sidecar deletion is treated the same as sidecar tamper — refusing to replay against potentially-forged input. Pass --force-replay to override (the replay output records sidecar_verify so the audit trail captures the override).\n`);
    const body = {
      ok: false,
      error: `reattest: prior attestation has no .sig sidecar — refusing to replay`,
      verb: "reattest",
      session_id: sessionId,
      attestation_file: attFile,
      sidecar_verify: verify,
      hint: "If the sidecar was intentionally removed (e.g. a clean operator rotation) and you have inspected the attestation, pass --force-replay.",
    };
    process.stderr.write(JSON.stringify(body) + "\n");
    process.exitCode = EXIT_CODES.TAMPERED;
    return;
  } else if (!verify.signed && verify.reason && verify.reason.includes("no .sig sidecar") && args["force-replay"]) {
    process.stderr.write(`[exceptd reattest] WARNING: --force-replay overriding missing .sig sidecar on ${attFile}. The replay output records sidecar_verify so the override is audit-visible.\n`);
  } else if (!verify.signed && verify.reason && verify.reason.startsWith("attestation explicitly unsigned") && !args["force-replay"]) {
    // legitimately-unsigned attestations (written when the
    // attesting host had no private key) require --force-replay to consume.
    // Pre-fix, the NOTE branch accepted them silently — which let an
    // attacker swap a valid .sig with the unsigned stub on a host that
    // happens to be private-key-absent at verify time. The cost of
    // requiring --force-replay is one explicit operator step; the benefit
    // is that any unsigned-substitution event becomes audit-visible via
    // sidecar_verify + force_replay in the emitted body.
    process.stderr.write(`[exceptd reattest] EXPLICITLY-UNSIGNED: attestation at ${attFile} carries an "unsigned" sidecar (${verify.reason}). Replay against unsigned input requires --force-replay so the audit trail captures the override.\n`);
    const body = {
      ok: false,
      error: `reattest: prior attestation is explicitly unsigned — refusing to replay without --force-replay`,
      verb: "reattest",
      session_id: sessionId,
      attestation_file: attFile,
      sidecar_verify: verify,
      hint: "If the original attestation was legitimately produced without a private key, pass --force-replay. The replay body will record sidecar_verify: 'explicitly-unsigned' + force_replay: true.",
    };
    process.stderr.write(JSON.stringify(body) + "\n");
    process.exitCode = EXIT_CODES.TAMPERED;
    return;
  } else if (!verify.signed && verify.reason && verify.reason.startsWith("attestation explicitly unsigned") && args["force-replay"]) {
    process.stderr.write(`[exceptd reattest] WARNING: --force-replay overriding explicitly-unsigned attestation on ${attFile}. The replay output records sidecar_verify: 'explicitly-unsigned' so the override is audit-visible.\n`);
  } else if (!verify.signed && verify.reason !== "no .sig sidecar") {
    process.stderr.write(`[exceptd reattest] NOTE: attestation at ${attFile} has no Ed25519 signature (${verify.reason}). Proceeding — unsigned attestations are an operator config issue, not tamper evidence.\n`);
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
      // Defense-in-depth: the prior attestation's playbook_id came from
      // disk, but a malicious or corrupt prior could still smuggle an
      // invalid id. validateIdComponent refuses anything outside the
      // canonical playbook-id shape.
      const r = validateIdComponent(prior.playbook_id, "playbook");
      if (r.ok) {
        const pb = runner.loadPlaybook(prior.playbook_id);
        const synth = {};
        for (const pc of (pb._meta && pb._meta.preconditions) || []) synth[pc.id] = true;
        replayOpts.precondition_checks = synth;
      }
    } catch { /* ignore */ }
  }
  const replay = runner.run(prior.playbook_id, prior.directive_id, emptySubmission, replayOpts);

  if (!replay || replay.ok === false) {
    // When replay.reason is falsy, dump the available keys so an operator
    // can correlate the failure to a body field — pre-fix the error message
    // bottomed out at "unknown" with no breadcrumb into the runner output.
    const reason = (replay && replay.reason) || (replay && replay.error) || null;
    const keys = replay && typeof replay === "object" ? Object.keys(replay).join(",") : "(no body)";
    return emitError(
      `reattest: replay failed: ${reason || `no reason field — replay body keys: [${keys}]`}`,
      { replay, replay_body_keys: replay && typeof replay === "object" ? Object.keys(replay) : null },
      pretty
    );
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

  const replayedAt = new Date().toISOString();
  const sidecarVerifyClass = classifySidecarVerify(verify);
  const forceReplay = !!args["force-replay"];

  // Persist a `replay-<isoZ>.json` record under the session directory for
  // every cmdReattest replay verdict. Without disk persistence, a
  // force-replay override emitted to stdout becomes invisible to any
  // subsequent auditor once the operator's shell closes. Each replay
  // writes a new file alongside the original attestation.json, signed via
  // the standard maybeSignAttestation path so the audit chain remains
  // tamper-evident. The file is picked up automatically by
  // `attest verify <sid>` (which iterates every *.json under the session
  // dir).
  //
  // Filename shape: ISO-8601 uses ':' which the persistAttestation regex
  // refuses; substitute ':' with '-' and keep millisecond precision so
  // multiple replays in the same second do not collide on EEXIST. The
  // resulting filename satisfies /^[A-Za-z0-9._-]{1,64}\.json$/.
  const replayBaseName = "replay-" + replayedAt.replace(/:/g, "-");
  const replayBody = {
    kind: "replay",
    session_id: sessionId,
    playbook_id: prior.playbook_id,
    directive_id: prior.directive_id,
    status,
    prior_evidence_hash: priorHash,
    replay_evidence_hash: newHash,
    prior_captured_at: prior.captured_at,
    replayed_at: replayedAt,
    replay_classification: replay.phases && replay.phases.detect && replay.phases.detect.classification,
    replay_rwep_adjusted: replay.phases && replay.phases.analyze && replay.phases.analyze.rwep && replay.phases.analyze.rwep.adjusted,
    sidecar_verify: verify,
    sidecar_verify_class: sidecarVerifyClass,
    force_replay: forceReplay,
  };
  let replayPersisted = null;
  let replayPath = null;
  try {
    // Retry on EEXIST: two concurrent reattests sharing the same
    // millisecond timestamp would collide on the base name. Append a short
    // random suffix until O_EXCL accepts the write or the cap is exhausted.
    const dir = path.dirname(attFile);
    const MAX_SUFFIX_TRIES = 8;
    let written = false;
    let lastErr = null;
    for (let i = 0; i < MAX_SUFFIX_TRIES; i++) {
      const suffix = i === 0 ? "" : "-" + crypto.randomBytes(3).toString("hex");
      const candidate = path.join(dir, replayBaseName + suffix + ".json");
      try {
        fs.writeFileSync(candidate, JSON.stringify(replayBody, null, 2), { flag: "wx" });
        replayPath = candidate;
        written = true;
        break;
      } catch (e) {
        lastErr = e;
        if (!e || e.code !== "EEXIST") throw e;
      }
    }
    if (!written) throw lastErr || new Error("replay-record write: EEXIST after " + MAX_SUFFIX_TRIES + " attempts");
    replayPersisted = { ok: true, path: replayPath, sidecar_signed: true };
  } catch (e) {
    // Non-fatal — stdout emit is the operator's primary surface; a
    // disk-persistence failure shouldn't mask the verdict. Surface the
    // condition in the response body so an operator-side audit pipeline
    // can re-run the persist later.
    replayPersisted = { ok: false, error: String((e && e.message) || e) };
  }
  if (replayPersisted && replayPersisted.ok && replayPath) {
    // Sidecar signing is best-effort: the unsigned replay record on disk
    // is still a valid audit-trail entry. Split from the write try{} so a
    // sign-time failure doesn't mask a successful write.
    try {
      maybeSignAttestation(replayPath);
    } catch (e) {
      replayPersisted.sidecar_signed = false;
      replayPersisted.sidecar_sign_error = String((e && e.message) || e);
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
    replayed_at: replayedAt,
    replay_classification: replay.phases && replay.phases.detect && replay.phases.detect.classification,
    replay_rwep_adjusted: replay.phases && replay.phases.analyze && replay.phases.analyze.rwep && replay.phases.analyze.rwep.adjusted,
    // Persist the sidecar verify result + the force-replay flag so the
    // audit trail records whether the replay was authenticated input.
    sidecar_verify: verify,
    // emit a one-token classification label alongside the
    // full sidecar_verify object so log scrapers / dashboards can filter on
    // override events without parsing reason strings. Values:
    //   'verified'             — Ed25519 sidecar verified
    //   'tampered'             — signed-but-invalid signature (post-hoc tamper)
    //   'sidecar-corrupt'      — sidecar JSON parse failure (tamper class)
    //   'unsigned-substitution'— "unsigned" sidecar on a host with private key
    //                            (substitution attack signal)
    //   'algorithm-unsupported'— sidecar algorithm field is neither "Ed25519"
    //                            nor "unsigned" (downgrade-bait substitution)
    //   'explicitly-unsigned'  — legitimately-unsigned attestation
    //   'no-sidecar'           — sidecar file absent
    //   'no-public-key'        — infra-missing (operator-side keys/public.pem absent)
    sidecar_verify_class: sidecarVerifyClass,
    force_replay: forceReplay,
    // Surface the persisted replay-record path (or persistence failure
    // reason) so an auditor reading the CLI response can locate the
    // on-disk artifact without re-deriving the filename.
    replay_persisted: replayPersisted,
  }, pretty);
}

/**
 * map a verifyAttestationSidecar() result to a one-token
 * classification label. The label is persisted alongside the full
 * sidecar_verify object so auditors can filter override events by class
 * without regexing the human-readable reason string.
 */
function classifySidecarVerify(verify) {
  if (!verify || typeof verify !== "object") return "unknown";
  if (verify.signed && verify.verified) return "verified";
  if (verify.signed && !verify.verified) return "tampered";
  if (verify.tamper_class === "sidecar-corrupt") return "sidecar-corrupt";
  if (verify.tamper_class === "unsigned-substitution") return "unsigned-substitution";
  // `algorithm-unsupported` is its own class label so log scrapers /
  // dashboards can filter downgrade-bait events without parsing the reason.
  if (verify.tamper_class === "algorithm-unsupported") return "algorithm-unsupported";
  if (typeof verify.reason === "string" && verify.reason.startsWith("attestation explicitly unsigned")) return "explicitly-unsigned";
  if (typeof verify.reason === "string" && verify.reason.includes("no .sig sidecar")) return "no-sidecar";
  if (typeof verify.reason === "string" && verify.reason.includes("no public key")) return "no-public-key";
  return "unknown";
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
    return emitError(
      `attest ${subverb}: missing <session-id> positional argument. Inventory prior sessions with \`exceptd attest list\`; or pass \`--latest\` to operate on the most recent.`,
      { verb: `attest ${subverb}` },
      pretty
    );
  }
  // Distinguish "validation rejected" from "valid format but not found".
  // findSessionDir() returns null for BOTH (regex-rejected ids collapse to
  // the "no session dir" message), which gives operators a misleading
  // error — a string with `..` or `/` looks to them like an existing-
  // session lookup that failed, not a refusal. Call the same validator
  // up front; emit its specific message when it throws.
  try { validateSessionIdForRead(sessionId); }
  catch (e) {
    return emitError(`attest ${subverb}: ${e.message}`, { session_id_input: typeof sessionId === "string" ? sessionId.slice(0, 80) : typeof sessionId }, pretty);
  }
  const dir = findSessionDir(sessionId, runOpts);
  if (!dir) {
    return emitError(`attest ${subverb}: no session dir for ${sessionId}. Searched: ${resolveAttestationRoot(runOpts)} + .exceptd/attestations/`, { session_id: sessionId }, pretty);
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
  // Partition session-dir JSON files by parsed `kind` field. Replay records
  // (written by `cmdReattest`) live alongside attestations under the same
  // session directory but represent audit-trail entries, not separate
  // sessions. Gate on the parsed payload — not filename prefix — so a
  // renamed file cannot smuggle a replay into the attestations[] list.
  const attestations = [];
  const replays = [];
  for (const f of files) {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); }
    catch { continue; }
    if (!parsed) continue;
    if (parsed.kind === "replay") replays.push(parsed);
    else attestations.push(parsed);
  }

  if (subverb === "show") {
    emit({ session_id: sessionId, attestations, attestation_replays: replays }, pretty);
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
      // Pick the comparison target deterministically:
      //   1. Prefer attestation.json (the canonical write-path filename).
      //   2. Otherwise, walk every non-replay JSON in the dir, sort by
      //      parsed.captured_at descending, and take the newest.
      //   3. Replay records (kind === "replay") are audit-trail entries,
      //      not attestations — skip them so a replay file sorted ahead of
      //      attestation.json cannot shadow the real attestation in the
      //      diff.
      let other = null;
      const otherAttestationPath = path.join(otherDir, "attestation.json");
      if (fs.existsSync(otherAttestationPath)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(otherAttestationPath, "utf8"));
          if (parsed && parsed.kind !== "replay") other = parsed;
        } catch { /* fall through to scan */ }
      }
      if (!other) {
        const candidates = [];
        for (const f of otherFiles) {
          try {
            const parsed = JSON.parse(fs.readFileSync(path.join(otherDir, f), "utf8"));
            if (!parsed || parsed.kind === "replay") continue;
            candidates.push(parsed);
          } catch { /* skip malformed */ }
        }
        candidates.sort((a, b) => (b.captured_at || "").localeCompare(a.captured_at || ""));
        other = candidates[0] || null;
      }
      if (!other) {
        return emitError(`attest diff --against ${args.against}: no attestations under that session id.`, null, pretty);
      }
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
          normalizedArtifacts(self.submission, runner, self.playbook_id),
          normalizedArtifacts(other.submission, runner, other.playbook_id)
        ),
        signal_override_diff: diffSignalOverrides(
          normalizedSignalOverrides(self.submission, runner, self.playbook_id),
          normalizedSignalOverrides(other.submission, runner, other.playbook_id)
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
    // Same pin cross-check as verifyAttestationSidecar().
    // The v0.12.16 promise that EXPECTED_FINGERPRINT is consulted at every
    // public-key load site was not honored here — `attest verify` loaded
    // keys/public.pem raw. Refuse to verify any sidecar when the local
    // public.pem diverges from the pinned fingerprint (unless KEYS_ROTATED=1).
    const pinError = pubKey ? assertExpectedFingerprint(pubKey) : null;
    if (pinError) {
      return emitError(
        `attest verify: ${pinError}`,
        { verb: "attest verify", session_id: sessionId, pin_error: pinError },
        pretty
      );
    }
    // on the verifying host, detect "unsigned" sidecar
    // substitution by checking whether .keys/private.pem is present. A
    // legitimately-unsigned attestation cannot coexist with a private key on
    // the same host — that combination is sidecar substitution (attacker
    // tampered attestation.json and overwrote .sig with the unsigned stub).
    const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
    const hasPrivKey = fs.existsSync(privKeyPath);

    // Sidecar-verify helper shared by both the attestations[] and
    // replay-records[] partitions. Centralising the per-file verify
    // logic means a future tamper-class addition lands in one place
    // instead of two parallel branches.
    const verifySidecar = (f) => {
      const sigPath = path.join(dir, f + ".sig");
      if (!fs.existsSync(sigPath)) return { file: f, signed: false, verified: false, reason: "no .sig sidecar" };
      let sigDoc;
      try { sigDoc = JSON.parse(fs.readFileSync(sigPath, "utf8")); }
      catch (e) {
        return {
          file: f,
          signed: false,
          verified: false,
          reason: `sidecar parse error: ${e.message}`,
          tamper_class: "sidecar-corrupt",
        };
      }
      if (sigDoc.algorithm === "unsigned") {
        if (hasPrivKey) {
          return {
            file: f,
            signed: false,
            verified: false,
            reason: "attestation explicitly unsigned but .keys/private.pem IS present on this host — sidecar substitution suspected (legitimate unsigned attestations cannot exist alongside a private key)",
            tamper_class: "unsigned-substitution",
          };
        }
        return { file: f, signed: false, verified: false, reason: "attestation explicitly unsigned (no private key when written)" };
      }
      if (sigDoc.algorithm !== "Ed25519") {
        return {
          file: f,
          signed: false,
          verified: false,
          reason: "unsupported algorithm: " + JSON.stringify(sigDoc.algorithm),
          tamper_class: "algorithm-unsupported",
        };
      }
      if (!pubKey) return { file: f, signed: true, verified: false, reason: "no public key at keys/public.pem to verify against" };
      const rawContent = fs.readFileSync(path.join(dir, f), "utf8");
      const content = normalizeAttestationBytes(rawContent);
      try {
        const ok = crypto.verify(null, Buffer.from(content, "utf8"), {
          key: pubKey, dsaEncoding: "ieee-p1363",
        }, Buffer.from(sigDoc.signature_base64, "base64"));
        return { file: f, signed: true, verified: !!ok, reason: ok ? "Ed25519 signature valid" : "Ed25519 signature INVALID — possible post-hoc tampering" };
      } catch (e) {
        return { file: f, signed: true, verified: false, reason: `verify error: ${e.message}` };
      }
    };

    // Partition session-dir files by the parsed `kind` field so the verify
    // output cleanly separates attestations from replay records. Mixing
    // both into a single `results` array let a replay-record tamper event
    // promote exit 6 against the operator's expectation that the
    // attestation itself was the integrity-critical artifact. With the
    // partition: attestation tamper → exit 6 (operator must investigate);
    // replay-record tamper → audit-trail warning only (exit stays 0 so
    // CI gates don't fail on a corrupted audit log they can simply
    // regenerate via `reattest`).
    const attResults = [];
    const replayResults = [];
    for (const f of files) {
      let parsed = null;
      try { parsed = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); }
      catch { /* unparseable JSON — treat as attestation so tamper detection still surfaces */ }
      const verdict = verifySidecar(f);
      if (parsed && parsed.kind === "replay") {
        replayResults.push(Object.assign({ replayed_at: parsed.replayed_at || null }, verdict));
      } else {
        attResults.push(Object.assign({ captured_at: parsed && parsed.captured_at || null }, verdict));
      }
    }
    // Deterministic ordering so the output diffs cleanly across runs.
    attResults.sort((a, b) => (a.captured_at || "").localeCompare(b.captured_at || ""));
    replayResults.sort((a, b) => (a.replayed_at || "").localeCompare(b.replayed_at || ""));

    const tamperPredicate = (r) =>
      (r.signed && !r.verified)
      || r.tamper_class === "sidecar-corrupt"
      || r.tamper_class === "unsigned-substitution"
      || r.tamper_class === "algorithm-unsupported";
    const attTampered = attResults.some(tamperPredicate);
    const replayTampered = replayResults.some(tamperPredicate);

    const body = {
      verb: "attest verify",
      session_id: sessionId,
      results: attResults,
      replay_results: replayResults,
    };
    if (attTampered) {
      body.ok = false;
      body.error = "attest verify: one or more attestations failed Ed25519 verification — possible post-hoc tampering";
      process.exitCode = EXIT_CODES.TAMPERED;
    } else if (replayTampered) {
      // Replay-record tamper is an audit-trail signal but not an
      // attestation-integrity violation; surface a warning so operators
      // see the corruption without promoting the exit code.
      body.replay_tamper = true;
      body.warnings = ["one or more replay records failed Ed25519 verification — audit-trail corruption suspected, regenerate via reattest"];
    }
    emit(body, pretty);
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
function _playbookArtifactCatalog(runner, playbookId) {
  if (!playbookId) return null;
  try {
    const pb = runner.loadPlaybook ? runner.loadPlaybook(playbookId) : null;
    if (!pb) return null;
    const arts = (pb.phases?.look?.artifacts || []).filter(a => a && a.id);
    if (arts.length === 0) return null;
    return Object.fromEntries(arts.map(a => [a.id, { captured: false, _catalog_stub: true }]));
  } catch { return null; }
}
function _playbookSignalCatalog(runner, playbookId) {
  if (!playbookId) return null;
  try {
    const pb = runner.loadPlaybook ? runner.loadPlaybook(playbookId) : null;
    if (!pb) return null;
    const inds = (pb.phases?.look?.indicators || []).filter(i => i && i.id);
    if (inds.length === 0) return null;
    return Object.fromEntries(inds.map(i => [i.id, 'inconclusive']));
  } catch { return null; }
}
function normalizedArtifacts(submission, runner, playbookId) {
  if (!submission || typeof submission !== "object") {
    return _playbookArtifactCatalog(runner, playbookId) || {};
  }
  if (submission.artifacts && Object.keys(submission.artifacts).length > 0) return submission.artifacts;
  if (submission.observations && Object.keys(submission.observations).length > 0) {
    // v0.11.12 (#126): load real playbook so look.artifacts catalog can map
    // observations. v0.11.13 (#128): when normalize succeeds but produces an
    // empty map, fall through to direct mapping instead of returning empty.
    if (playbookId) {
      try {
        const pb = runner.loadPlaybook ? runner.loadPlaybook(playbookId) : null;
        if (pb) {
          const norm = runner.normalizeSubmission({ observations: submission.observations }, pb);
          if (norm && norm.artifacts && Object.keys(norm.artifacts).length > 0) return norm.artifacts;
        }
      } catch { /* fall through */ }
    }
    const out = {};
    for (const [k, v] of Object.entries(submission.observations)) {
      out[k] = (v && typeof v === "object") ? v : { value: v };
    }
    return out;
  }
  // v0.11.13 (#128): empty submission ({} or {observations:{}}). Identical
  // hashes still mean "no operator data was supplied, same on both sides."
  // Fall back to the playbook's look.artifacts catalog so total_compared
  // reflects "N catalog artifacts, all uniformly empty on both sides."
  return _playbookArtifactCatalog(runner, playbookId) || {};
}
function normalizedSignalOverrides(submission, runner, playbookId) {
  if (!submission || typeof submission !== "object") {
    return _playbookSignalCatalog(runner, playbookId) || {};
  }
  if (submission.signal_overrides && Object.keys(submission.signal_overrides).length > 0) return submission.signal_overrides;
  if (submission.observations && Object.keys(submission.observations).length > 0) {
    if (playbookId) {
      try {
        const pb = runner.loadPlaybook ? runner.loadPlaybook(playbookId) : null;
        if (pb) {
          const norm = runner.normalizeSubmission({ observations: submission.observations }, pb);
          if (norm && norm.signal_overrides && Object.keys(norm.signal_overrides).length > 0) return norm.signal_overrides;
        }
      } catch { /* fall through */ }
    }
    const out = {};
    for (const [k, v] of Object.entries(submission.observations)) {
      if (v && typeof v === "object" && v.result !== undefined) out[k] = v.result;
    }
    return out;
  }
  return _playbookSignalCatalog(runner, playbookId) || {};
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

  // `doctor --exit-codes` dumps the canonical exit-code table as JSON so
  // operator-facing docs cannot drift from runtime behavior. Short-circuit
  // before the regular health checks since the dump is informational.
  if (args["exit-codes"]) {
    emit({ verb: "doctor", exit_codes: listExitCodes() }, pretty);
    return;
  }

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

      // v0.12.9 (P3 #10 from production smoke): also run the shipped-tarball
      // round-trip gate (sign + pack + extract + verify) when the operator
      // opts in via --shipped-tarball. This is the v0.12.3 verify-as-shipped
      // gate that closed the v0.11.x → v0.12.4 signature regression class
      // (source-tree verify passed; shipped-tarball verify failed). It's
      // opt-in because npm pack adds ~5-10s and creates tempdir churn —
      // routine `doctor --signatures` stays fast.
      if (args["shipped-tarball"]) {
        try {
          const tarballScript = path.join(PKG_ROOT, "scripts", "verify-shipped-tarball.js");
          if (fs.existsSync(tarballScript)) {
            const tRes = spawnSync(process.execPath, [tarballScript], {
              encoding: "utf8",
              cwd: PKG_ROOT,
              timeout: 120000,
            });
            const tText = (tRes.stdout || "") + (tRes.stderr || "");
            const tOk = tRes.status === 0;
            const tMatch = tText.match(/(\d+)\/(\d+)\s+pass,\s+(\d+)\s+fail/i);
            checks.signatures.shipped_tarball = {
              ok: tOk,
              skills_passed: tMatch ? Number(tMatch[1]) : null,
              skills_total: tMatch ? Number(tMatch[2]) : null,
              skills_failed: tMatch ? Number(tMatch[3]) : null,
              ...(tOk ? {} : { exit_code: tRes.status, raw: tText.slice(-500) }),
            };
            if (!tOk) issues.push("signatures.shipped_tarball");
          } else {
            checks.signatures.shipped_tarball = {
              ok: null,
              skipped: true,
              reason: "scripts/verify-shipped-tarball.js not present (likely an installed package, not a source checkout). The tarball-verify gate runs at release time; routine integrity is covered by `--signatures`.",
            };
          }
        } catch (e) {
          checks.signatures.shipped_tarball = { ok: false, error: e.message };
          issues.push("signatures.shipped_tarball");
        }
      }
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
      // v0.12.9 codex P1 (PR #4): report only PKG_ROOT — that's the path
      // maybeSignAttestation() and `attest verify` actually use. Pre-v0.12.9
      // doctor also reported cwd-resident keys as present, which gave a
      // false-positive "signing enabled" signal when the operator's cwd
      // key was misaligned with the PKG_ROOT-resident public key used at
      // verify time.
      const keyPath = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath);
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

  // v0.11.14: opt-in `--registry-check` queries the npm registry for the
  // latest published version + publish date and computes "days behind."
  // Opt-in (not on every doctor invocation) so offline use + air-gap
  // workflows aren't disturbed. Routed through a child process to keep
  // cmdDoctor synchronous + bound the network timeout cleanly.
  if (args["registry-check"]) {
    // Refuse network egress when air-gap mode is active. Surface as a
    // skipped check (informational), not an error — the operator opted
    // into air-gap and would otherwise see a confusing network-error
    // result from the upstream-check probe.
    if (runOpts && runOpts.airGap) {
      checks.registry = {
        ok: null,
        skipped: "air-gap",
        reason: "registry probe disabled in air-gap mode",
      };
    } else {
    try {
      const cliPath = path.join(PKG_ROOT, "lib", "upstream-check-cli.js");
      const res = spawnSync(process.execPath, [cliPath, "--timeout", "5000"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 8000,
      });
      let parsed = null;
      try { parsed = JSON.parse((res.stdout || "").trim()); } catch { /* fall through */ }
      if (parsed) {
        checks.registry = {
          ok: parsed.ok && (parsed.same || parsed.ahead),
          severity: parsed.behind ? "warn" : (parsed.ok ? "info" : "warn"),
          ...parsed,
        };
      } else {
        checks.registry = {
          ok: false,
          severity: "warn",
          error: "upstream-check did not return JSON",
          exit_code: res.status,
          raw: ((res.stderr || res.stdout || "")).slice(0, 200),
        };
      }
    } catch (e) {
      checks.registry = { ok: false, severity: "warn", error: e.message };
    }
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
      // the fix. v0.12.9 codex P1: PKG_ROOT-only (sign + verify use this path).
      const keyPath = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath);
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
    // Four states: ok / warn / error / skipped. `skipped` is informational
    // (e.g. air-gap mode disabled the network probe) and renders as
    // [info] so it doesn't read like a failure to operators scanning the
    // checklist. Three pre-existing states retained.
    let icon;
    if (c.skipped) icon = "[info]";
    else if (c.ok && c.severity !== "warn") icon = "[ok]";
    else if (c.severity === "warn") icon = "[!! warn]";
    else icon = "[!! fail]";
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
  // v0.12.9 (P3 #11 from production smoke): render registry-check in text mode.
  // Pre-v0.12.9 --registry-check populated checks.registry only in the JSON
  // output; operators in text mode had to add --json to see if the flag did
  // anything. Now the line surfaces in the human checklist.
  mark(checks.registry, c => {
    if (c.skipped) return `npm registry check: skipped (${c.reason || "unknown reason"})`;
    if (!c.ok && !c.same && c.behind) {
      const days = c.days_since_latest_publish != null ? `${c.days_since_latest_publish}d` : "?";
      return `npm registry: local v${c.local_version ?? "?"} BEHIND published v${c.published_version ?? "?"} (${days})`;
    }
    if (c.same) {
      return `npm registry: local v${c.local_version ?? "?"} == published v${c.published_version ?? "?"} (current)`;
    }
    if (c.ahead) {
      return `npm registry: local v${c.local_version ?? "?"} AHEAD of published v${c.published_version ?? "?"} (unreleased / dev install)`;
    }
    return `npm registry: check returned no comparison (raw exit=${c.exit_code ?? "?"})`;
  });
  // v0.12.9 (P3 #10): surface shipped_tarball sub-check when --shipped-tarball was used.
  if (checks.signatures?.shipped_tarball) {
    const st = checks.signatures.shipped_tarball;
    if (st.skipped) {
      lines.push(`  [info] shipped tarball verify: skipped (${st.reason})`);
    } else if (st.ok) {
      lines.push(`  [ok] shipped tarball verify: ${st.skills_passed ?? "?"}/${st.skills_total ?? "?"} skills pass on extracted tarball`);
    } else {
      lines.push(`  [!!] shipped tarball verify FAILED: ${st.skills_failed ?? "?"}/${st.skills_total ?? "?"} skills fail (exit=${st.exit_code ?? "?"})`);
    }
  }
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
  // v0.12.14: --playbook is registered as `multi:` so
  // `--playbook a --playbook b` lands as an array. The prior filter used
  // strict equality (`j.playbook_id !== args.playbook`) — always false for
  // array, silently producing count: 0. Normalize to a Set up-front.
  const playbookFilter = (() => {
    if (args.playbook == null) return null;
    const list = Array.isArray(args.playbook) ? args.playbook : [args.playbook];
    return new Set(list.filter(x => typeof x === "string" && x.length > 0));
  })();
  // v0.12.14: --since must be a parseable ISO-8601 timestamp.
  // Prior behavior silently accepted any string and lexically compared to
  // captured_at, producing 0-result or full-result depending on the string.
  if (args.since != null) {
    // ISO-8601 shape regex BEFORE Date.parse — bare integers like "99"
    // would otherwise parse as the year 1999 and silently filter wrong
    // eras.
    const sinceErr = validateIsoSince(args.since);
    if (sinceErr) return emitError(`attest list: ${sinceErr}`, null, pretty);
  }
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
          // replay-<isoZ>.json records share the session dir with
          // attestation.json but are not separate sessions. Gate on the
          // parsed `kind` field rather than filename so a rename cannot
          // smuggle a replay record into the listing.
          if (j && j.kind === "replay") continue;
          // v0.12.14: normalized array-set filter (see top of fn).
          if (playbookFilter && !playbookFilter.has(j.playbook_id)) continue;
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
    filter: { playbook: playbookFilter ? [...playbookFilter] : null, since: args.since || null },
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
  if (refuseInvalidPlaybookId("ai-run", playbookId, pretty)) return;
  let pb;
  try { pb = runner.loadPlaybook(playbookId); }
  catch (e) { return emitError(`ai-run: ${e.message}`, { playbook: playbookId }, pretty); }
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) {
    return refuseNoDirectives("ai-run", playbookId, pretty);
  }

  // Compute the informational phases up front — both stream and no-stream
  // modes share them.
  let governPhase, directPhase, lookPhase;
  try {
    governPhase = runner.govern(playbookId, directiveId, runOpts);
    directPhase = runner.direct(playbookId, directiveId);
    lookPhase = runner.look(playbookId, directiveId, runOpts);
  } catch (e) {
    // process.exit(1) immediately after a stdout write can
    // truncate buffered output under piped consumers (same class as v0.11.10
    // #100). Use exitCode+return so the JSONL error frame drains. Also write
    // the framed error event so the stdout-only JSONL contract holds — host
    // AIs reading this stream must see structured frames, never bare text.
    process.stdout.write(JSON.stringify({ event: "error", reason: e.message, phase: "info", playbook_id: playbookId, directive_id: directiveId }) + "\n");
    process.exitCode = 1;
    return;
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
    } else if (hasReadableStdin()) {
      // hasReadableStdin() probes via fstat before falling into
      // readFileSync(0). Wrapped-stdin test harnesses (isTTY===undefined,
      // size===0) would otherwise hang here.
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
      return emitError(
        `ai-run: internal error (${e && e.message ? e.message : String(e)}). Re-run with --pretty for context; file at https://github.com/blamejs/exceptd-skills/issues if reproducible.`,
        { playbook: playbookId, verb: "ai-run" },
        pretty
      );
    }
    if (!result || result.ok === false) {
      // v0.12.12: same exit-after-write anti-pattern as the pre-stream
      // load path. Use exitCode + return so stderr drains.
      process.stderr.write((pretty ? JSON.stringify(result || {}, null, 2) : JSON.stringify(result || {})) + "\n");
      process.exitCode = 1;
      return;
    }
    // v0.12.14: ai-run --no-stream previously emitted a
    // session_id but never persisted the attestation, so the AI agent
    // calling ai-run couldn't chain into `attest show / verify / diff`
    // or `reattest` with the returned id. Now: same persistAttestation
    // shape as cmdRun, so AI-facing flow round-trips cleanly.
    if (result.session_id) {
      // Mirror cmdRun: gate operator_consent on classification === 'detected'.
      const aiClassification = result.phases && result.phases.detect ? result.phases.detect.classification : null;
      const aiConsentApplies = aiClassification === "detected";
      if (runOpts.operator_consent && !aiConsentApplies) {
        result.ack = true;
        result.ack_applied = false;
        result.ack_skipped_reason = `classification=${aiClassification || "unknown"}; consent only persisted when classification=detected (jurisdiction clock at stake).`;
      }
      const persistResult = persistAttestation({
        sessionId: result.session_id,
        playbookId: result.playbook_id || playbookId,
        directiveId: result.directive_id || directiveId,
        evidenceHash: result.evidence_hash,
        operator: runOpts.operator,
        operatorConsent: aiConsentApplies ? runOpts.operator_consent : null,
        submission,
        runOpts,
        forceOverwrite: !!args["force-overwrite"],
        filename: "attestation.json",
      });
      if (!persistResult.ok && !args["force-overwrite"]) {
        // Collision without --force-overwrite. AI agents typically pass
        // unique session ids each run, so this path is rare but surface
        // it cleanly via the same JSONL contract. Three exit-code classes
        // (LOCK_CONTENTION / STORAGE_EXHAUSTED / SESSION_ID_COLLISION) so
        // a host-AI driver can branch on remediation without parsing the
        // reason string.
        const eventBody = {
          event: "error", reason: persistResult.error,
          existing_attestation: persistResult.existingPath,
        };
        if (persistResult.lock_contention) {
          eventBody.lock_contention = true;
          eventBody.exit_code = EXIT_CODES.LOCK_CONTENTION;
        }
        if (persistResult.storage_exhausted) {
          eventBody.storage_exhausted = true;
          eventBody.exit_code = EXIT_CODES.STORAGE_EXHAUSTED;
        }
        process.stdout.write(JSON.stringify(eventBody) + "\n");
        if (persistResult.lock_contention) process.exitCode = EXIT_CODES.LOCK_CONTENTION;
        else if (persistResult.storage_exhausted) process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED;
        else process.exitCode = EXIT_CODES.SESSION_ID_COLLISION;
        return;
      }
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

  // v0.12.8: every writeLine() in this handler writes to stdout. Replacing
  // process.exit() with exitCode + closing stdin lets the JSONL frames
  // drain before the event loop ends. `handled` plus process.stdin.pause()
  // prevents further callbacks from re-entering the handler.
  const finish = (code) => {
    process.exitCode = code;
    try { process.stdin.pause(); } catch { /* non-fatal */ }
  };
  const handleLine = (line) => {
    if (handled) return;
    let parsed;
    try { parsed = JSON.parse(line); }
    catch (e) {
      handled = true;
      writeLine({ event: "error", reason: `invalid JSON on stdin: ${e.message}`, line_preview: line.slice(0, 120) });
      return finish(1);
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
      return finish(1);
    }
    if (!result || result.ok === false) {
      writeLine({ event: "error", reason: result?.reason || "runner returned ok:false", result });
      return finish(1);
    }
    writeLine({ phase: "detect", ...result.phases?.detect });
    writeLine({ phase: "analyze", ...result.phases?.analyze });
    writeLine({ phase: "validate", ...result.phases?.validate });
    writeLine({ phase: "close", ...result.phases?.close });
    // v0.12.14: persist the attestation in streaming mode
    // too. Without this, the session_id emitted in the `done` frame
    // can't be resolved by `attest show / verify / diff` or `reattest`.
    if (result.session_id) {
      // Mirror cmdRun: gate operator_consent on classification === 'detected'.
      const aiClassification = result.phases && result.phases.detect ? result.phases.detect.classification : null;
      const aiConsentApplies = aiClassification === "detected";
      const persistResult = persistAttestation({
        sessionId: result.session_id,
        playbookId: result.playbook_id || playbookId,
        directiveId: result.directive_id || directiveId,
        evidenceHash: result.evidence_hash,
        operator: runOpts.operator,
        operatorConsent: aiConsentApplies ? runOpts.operator_consent : null,
        submission,
        runOpts,
        forceOverwrite: !!args["force-overwrite"],
        filename: "attestation.json",
      });
      if (!persistResult.ok && !args["force-overwrite"]) {
        const eventBody = { event: "error", reason: persistResult.error,
                            existing_attestation: persistResult.existingPath };
        if (persistResult.lock_contention) {
          eventBody.lock_contention = true;
          eventBody.exit_code = EXIT_CODES.LOCK_CONTENTION;
          writeLine(eventBody);
          return finish(EXIT_CODES.LOCK_CONTENTION);
        }
        if (persistResult.storage_exhausted) {
          eventBody.storage_exhausted = true;
          eventBody.exit_code = EXIT_CODES.STORAGE_EXHAUSTED;
          writeLine(eventBody);
          return finish(EXIT_CODES.STORAGE_EXHAUSTED);
        }
        writeLine(eventBody);
        return finish(EXIT_CODES.SESSION_ID_COLLISION);
      }
    }
    writeLine({ event: "done", ok: true, session_id: result.session_id, evidence_hash: result.evidence_hash });
    return finish(0);
  };

  // Handle empty/closed stdin: emit a hint then exit cleanly so AI agents
  // calling ai-run without piping anything see a useful message rather than
  // a hung process.
  if (process.stdin.isTTY) {
    writeLine({ event: "error", reason: "ai-run streaming mode requires evidence on stdin; pipe {\"event\":\"evidence\",\"payload\":{...}} or use --no-stream." });
    process.exitCode = 1;
    return;
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
      process.exitCode = 1;
      return;
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
 *   0   PASS           — no detected findings, no rwep ≥ cap, no clock fired.
 *   2   FAIL           — detected classification OR rwep ≥ cap.
 *   3   NO_EVIDENCE    — every result inconclusive AND no --evidence supplied.
 *   4   BLOCKED        — at least one playbook returned ok:false (preflight halt).
 *   5   CLOCK_STARTED  — --block-on-jurisdiction-clock fired (F18); separated
 *                        from FAIL so operators distinguish "detected" from
 *                        "regulatory notification deadline running."
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
    try { ids = filterPlaybooksByScope(runner, scope); }
    catch (e) { return emitError(`ci: ${e.message}`, { provided_scope: scope }, pretty); }
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
  // Track jurisdiction-clock signals separately from generic FAIL so the
  // exit code can distinguish "detected/escalated" (2) from "regulatory
  // clock running, operator must notify" (5).
  let clockStartedFail = false;
  let clockStartedReasons = [];

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
      // Separate "clock started" from generic FAIL: exit 5 (CLOCK_STARTED)
      // is selected below, taking precedence over FAIL but not BLOCKED, so
      // operators can distinguish "playbook detected" from "regulatory
      // clock running."
      clockStartedFail = true;
      clockStartedReasons.push(`${id}: jurisdiction clock started`);
    }
  }

  const rwepValues = results.map(r => r.phases?.analyze?.rwep?.adjusted ?? 0);
  const maxRwepObserved = rwepValues.length ? Math.max(...rwepValues) : 0;

  // v0.12.9 (P1 #2 from production smoke): reconcile verdict with exit code.
  // Pre-v0.12.9 the no-evidence-all-inconclusive path emitted verdict="PASS"
  // but the process exited 3 ("ran but no evidence"). CI consumers reading
  // exit code only failed a PASS run; consumers reading verdict only passed
  // a no-data run. Now compute the verdict up-front to match the exit-code
  // matrix (BLOCKED > FAIL > NO_EVIDENCE > PASS) so both surfaces agree.
  const suppliedEvidenceForVerdict = args.evidence || args["evidence-dir"];
  const blockedCount = results.filter(r => r && r.ok === false).length;
  const inconclusiveCount = results.filter(r => r.phases?.detect?.classification === "inconclusive").length;
  const totalForVerdict = results.length;
  const noEvidenceAllInconclusive = !suppliedEvidenceForVerdict && totalForVerdict > 0 && inconclusiveCount === totalForVerdict;
  // Precedence: BLOCKED > CLOCK_STARTED > FAIL > NO_EVIDENCE > PASS.
  // CLOCK_STARTED outranks FAIL because the operator explicitly opted into
  // the clock gate (--block-on-jurisdiction-clock); when that gate fires,
  // they want the regulatory-deadline signal even if a detected finding
  // also surfaces. (A detected finding is still in the body for the
  // operator to act on; the exit-code dimension just answers "what's the
  // top-line reason this gate failed.")
  const computedVerdict = blockedCount > 0
    ? "BLOCKED"
    : clockStartedFail
      ? "CLOCK_STARTED"
      : fail
        ? "FAIL"
        : noEvidenceAllInconclusive
          ? "NO_EVIDENCE"
          : "PASS";

  // v0.12.9 (P2 #8 from production smoke): roll up per-playbook framework_gap
  // mappings to the ci top-level. Phase 7 of the seven-phase contract surfaces
  // framework_gap_mapping per result; pre-v0.12.9 ci never aggregated them,
  // so operators got individual-playbook results only. Now: top-level
  // framework_gap_rollup lists each {framework, claimed_control} once with
  // the set of playbooks that flagged it — single-glance "what gaps did this
  // gate uncover across the scoped playbooks."
  const gapRollupMap = new Map();
  for (const r of results) {
    const gaps = r.phases?.analyze?.framework_gap_mapping || [];
    for (const g of gaps) {
      const key = `${g.framework || "unknown"}::${g.claimed_control || "unspecified"}`;
      const existing = gapRollupMap.get(key);
      if (existing) {
        if (!existing.playbooks.includes(r.playbook_id)) existing.playbooks.push(r.playbook_id);
      } else {
        gapRollupMap.set(key, {
          framework: g.framework || null,
          claimed_control: g.claimed_control || null,
          why_insufficient: g.why_insufficient || null,
          playbooks: [r.playbook_id],
        });
      }
    }
  }
  const frameworkGapRollup = [...gapRollupMap.values()];

  const summary = {
    total: results.length,
    detected: results.filter(r => r.phases?.detect?.classification === "detected").length,
    inconclusive: inconclusiveCount,
    not_detected: results.filter(r => ["not_detected", "clean"].includes(r.phases?.detect?.classification)).length,
    blocked: blockedCount,
    max_rwep_observed: maxRwepObserved,
    jurisdiction_clocks_started: results
      .flatMap(r => r.phases?.close?.notification_actions || [])
      .filter(n => n && n.clock_started_at != null).length,
    framework_gap_rollup: frameworkGapRollup,
    framework_gap_count: frameworkGapRollup.length,
    // Dedupe jurisdiction-clock notifications across playbooks; see
    // buildJurisdictionClockRollup. Without this, multi-playbook ci runs
    // produce one notification entry per contributing playbook (often 8+)
    // when a single notification per (jurisdiction, regulation,
    // obligation, window) is the right shape.
    jurisdiction_clock_rollup: buildJurisdictionClockRollup(results),
    verdict: computedVerdict,
    fail_reasons: failReasons,
    clock_started_reasons: clockStartedReasons,
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
    // Route through emitError so the body propagates exit codes via the
    // emit() ok:false contract. ci-format-typo is operator-decision class
    // (GENERIC_FAILURE), not DETECTED_ESCALATE.
    emitError(
      `ci: --format "${fmt}" not in accepted set ["summary","markdown","csaf-2.0","sarif","openvex","json"].`,
      { verb: "ci" },
      pretty
    );
    return;
  } else {
    emit({ verb: "ci", session_id: sessionId, playbooks_run: ids, summary, results }, pretty);
  }
  // v0.11.14 (#134): exit-code matrix with BLOCKED before FAIL.
  // Pre-0.11.14 the `if (fail)` check fired first for blocked runs (because
  // the loop pushed blocked entries onto failReasons), so blocked runs got
  // exit 2 (FAIL/detected) instead of exit 4 (BLOCKED/didn't-execute).
  // Operators wiring CI gates couldn't distinguish "playbook detected a
  // problem" from "playbook never executed because preflight halted."
  //
  // Exit-code matrix (final, documented in --help):
  //   0  PASS      every playbook produced a result, none detected/escalating
  //   1  FRAMEWORK engine/parse error (set by emit() when body is ok:false)
  //   2  FAIL      detected classification OR rwep>=escalate
  //   3  NO-DATA   ran but no --evidence and all inconclusive
  //   4  BLOCKED   at least one playbook returned ok:false (preflight halt,
  //                stale threat intel, missing precondition, mutex contention)
  // Precedence: BLOCKED > FAIL > NO-DATA > PASS. A blocked playbook didn't
  // actually evaluate signals, so it can't be a true detection.
  if (summary.blocked > 0) {
    const blockedReasons = failReasons.filter(r => r.includes("blocked"));
    process.stderr.write(`[exceptd ci] BLOCKED: ${summary.blocked}/${summary.total} playbook(s) halted before detect. Exit ${EXIT_CODES.BLOCKED}. Reasons:\n  ${blockedReasons.join("\n  ")}\n`);
    process.exitCode = EXIT_CODES.BLOCKED;
    return;
  }
  // Precedence: BLOCKED > CLOCK_STARTED > FAIL. The operator opted into
  // --block-on-jurisdiction-clock; when a clock fires, that's the gate
  // result they want to see at the exit-code layer. Per-playbook detected
  // findings remain in the body for them to investigate.
  if (clockStartedFail) {
    process.stderr.write(`[exceptd ci] CLOCK_STARTED: ${clockStartedReasons.join("; ")}. Exit ${EXIT_CODES.JURISDICTION_CLOCK_STARTED}.\n`);
    process.exitCode = EXIT_CODES.JURISDICTION_CLOCK_STARTED;
    return;
  }
  if (fail) {
    process.stderr.write(`[exceptd ci] FAIL: ${failReasons.join("; ")}\n`);
    // v0.11.11: exitCode + return so emit()'s stdout flushes.
    process.exitCode = EXIT_CODES.DETECTED_ESCALATE;
    return;
  }
  const suppliedEvidence = args.evidence || args["evidence-dir"];
  const allInconclusive = summary.inconclusive === summary.total && summary.total > 0;
  if (!suppliedEvidence && allInconclusive) {
    process.stderr.write(`[exceptd ci] WARN: no --evidence supplied and all ${summary.total} playbook(s) returned inconclusive. CI exit ${EXIT_CODES.RAN_NO_EVIDENCE} = "ran but never had real data." Pass --evidence <file> or --evidence-dir <dir> for a real gate.\n`);
    process.exitCode = EXIT_CODES.RAN_NO_EVIDENCE;
  }
}

if (require.main === module) main();

module.exports = { COMMANDS, PKG_ROOT, PLAYBOOK_VERBS, persistAttestation };
