#!/usr/bin/env node
"use strict";
/** Package entry point: routes each subcommand to its script, args forwarded verbatim. */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

// Resolved at runtime so `npx` from a temp dir and a local `node bin/exceptd.js` agree.
const PKG_ROOT = path.resolve(__dirname, "..");

// `doctor --exit-codes` dumps EXIT_CODES, so help text and runtime share one source.
const { EXIT_CODES, listExitCodes, safeExit } = require(path.join(PKG_ROOT, "lib", "exit-codes.js"));
const { validateIdComponent } = require(path.join(PKG_ROOT, "lib", "id-validation.js"));
const { suggestFlag, flagsFor, VERB_FLAG_ALLOWLIST } = require(path.join(PKG_ROOT, "lib", "flag-suggest.js"));
const codepointClass = require(path.join(PKG_ROOT, "vendor", "blamejs", "codepoint-class.js"));

// Union of every flag known to ANY verb. One valid elsewhere falls through to the
// verb handler for a tailored message; only a flag unknown EVERYWHERE is refused here.
const ALL_KNOWN_FLAGS = new Set(
  Object.values(VERB_FLAG_ALLOWLIST).flat()
);

/**
 * Returns null when the pin passes or no pin file exists; an error string when
 * live public.pem diverges from keys/EXPECTED_FINGERPRINT without KEYS_ROTATED=1.
 * Takes raw PEM; lib/verify.js's checkExpectedFingerprint() takes a fingerprint.
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
  // The shared loader strips U+FEFF and comment lines, so a BOM-prefixed pin
  // file reads the same at every verify site.
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

// Subcommand → resolved script path. Lazy-resolved per call so a missing optional
// component (e.g. orchestrator/) fails that one command, not dispatcher init.
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
  // Citation resolvers, offline-first: catalog/index → cache → opt-in lookup.
  cve:             () => path.join(PKG_ROOT, "lib", "cve-cli.js"),
  rfc:             () => path.join(PKG_ROOT, "lib", "rfc-cli.js"),
  // Seven-phase playbook verbs — handled in-process via lib/playbook-runner.js.
  run:      null,
  reattest: null,
};

const ORCHESTRATOR_PASSTHROUGH = new Set([
  "scan", "dispatch", "skill", "currency", "report",
  "validate-cves", "validate-rfcs", "watchlist", "watch",
  "framework-gap", "framework-gap-analysis",
]);

// Did-you-mean for unknown verbs. Edit distance capped at 2: anything above 1
// reports 2, so callers only learn "≤1 or not".
function levenshtein1(a, b) {
  if (a === b) return 0;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return 2; // short-circuit: can't be ≤ 1
  let i = 0, j = 0, edits = 0;
  while (i < la && j < lb) {
    if (a.charCodeAt(i) !== b.charCodeAt(j)) {
      if (++edits > 1) return 2;
      // An adjacent transposition counts as one edit; pure Levenshtein scores it 2.
      if (la === lb && i + 1 < la && j + 1 < lb
          && a.charCodeAt(i) === b.charCodeAt(j + 1)
          && a.charCodeAt(i + 1) === b.charCodeAt(j)) {
        i += 2; j += 2;
        continue;
      }
      if (la > lb) i++;
      else if (la < lb) j++;
      else { i++; j++; }
    } else { i++; j++; }
  }
  edits += (la - i) + (lb - j);
  return edits <= 1 ? edits : 2;
}

function suggestVerb(cmd, known) {
  if (!cmd || typeof cmd !== 'string') return [];
  const matches = [];
  for (const v of known) {
    if (levenshtein1(cmd, v) <= 1) matches.push(v);
  }
  return matches.sort();
}

// Seven-phase playbook verbs handled in-process (no subprocess dispatch).
// `reattest` / `list-attestations` are canonical short forms, not removable aliases.
const PLAYBOOK_VERBS = new Set([
  "brief", "run", "ai-run", "attest", "discover", "doctor", "ci", "ask",
  "verify-attestation", "run-all", "lint", "collect",
  "reattest", "list-attestations", "recipes",
]);

// Removed verb → its replacement. Refused with the hint and a non-zero exit, so a
// script pinned to an old name fails loudly rather than silently routing.
const REMOVED_VERBS = {
  plan: "brief --all",
  govern: "brief <pb> --phase govern",
  direct: "brief <pb> --phase direct",
  look: "brief <pb> --phase look",
  ingest: "run",
};

/**
 * Parses `icacls <path>` for any principal beyond the current user,
 * NT AUTHORITY\SYSTEM and BUILTIN\Administrators. Returns
 * { ok, extraPrincipals, error? }; ok:true with no principals off Windows.
 */
function checkWindowsAcl(targetPath) {
  if (process.platform !== 'win32') return { ok: true, extraPrincipals: [] };
  const childProc = require('child_process');
  const user = (process.env.USERNAME || '').toLowerCase();
  // Present on every Windows ACL, so not "broader than user-only".
  const ALLOWED_PRINCIPAL_SUFFIXES = [
    `\\${user}`,
    'nt authority\\system',
    'builtin\\administrators',
    'administrators',
  ];
  let stdout;
  try {
    stdout = childProc.execFileSync('icacls', [targetPath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
  } catch (e) {
    return { ok: false, extraPrincipals: [], error: (e && e.message) || String(e) };
  }
  const extraPrincipals = [];
  // icacls prints one principal per line as `name:(perms)`, wrapped by a path
  // line and a "Successfully processed" footer.
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.toLowerCase().startsWith('successfully processed')) continue;
    const m = line.match(/^([^:()]+?):\(/);
    if (!m) continue;
    const principal = m[1].trim().toLowerCase();
    const isAllowed = ALLOWED_PRINCIPAL_SUFFIXES.some((suffix) => principal.endsWith(suffix));
    if (!isAllowed) extraPrincipals.push(m[1].trim());
  }
  return { ok: extraPrincipals.length === 0, extraPrincipals };
}

function readPkgVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
}

function printWelcome() {
  console.log(`exceptd — @blamejs/exceptd-skills v${readPkgVersion()}

Welcome. Two ways to start:

  exceptd discover           # scan this directory + recommend playbooks
  exceptd ask "<question>"   # plain-English routing to a playbook

If you know what you want:

  exceptd brief <playbook>   # what does this playbook check?
  exceptd run <playbook>     # run it
  exceptd ci --scope code    # CI gate against every code-scoped playbook

Common starting playbooks
  git repos:      secrets, sbom, library-author, crypto-codebase
  GitHub Actions: cicd-pipeline-compromise (.github/workflows/ present)
  Linux hosts:    kernel, hardening, runtime, cred-stores, crypto
  AI assistants:  mcp (MCP client config), ai-api (shell rc + AI key exports)
  containers:     containers (Dockerfile / docker-compose)

\`exceptd discover\` is the authoritative recommender — it inspects your
cwd + host and only suggests the playbooks that actually apply.

Full reference: exceptd help
Per-verb help:  exceptd <verb> --help
`);
}

function printHelp() {
  console.log(`exceptd — @blamejs/exceptd-skills v${readPkgVersion()}

Usage: exceptd <command> [args]
       npx @blamejs/exceptd-skills <command> [args]

Quick start
───────────

  New here? These three cover most workflows:

    exceptd discover            Scan this directory; list the playbooks that apply.
    exceptd brief <playbook>    What a playbook checks — threat context + indicators.
    exceptd run <playbook>      Investigate it (add --ci for a pass/fail exit gate).

  Not sure which playbook fits? Describe the problem in plain language:

    exceptd ask "someone may have tampered with our npm packages"

Canonical verbs
───────────────

  brief [playbook]           Unified info doc — jurisdictions + threat context
                             + preconditions + artifacts + indicators. Replaces
                             plan + govern + direct + look.
                             --all                  every playbook
                             --scope <type>         system | code | service | cross-cutting
                             --directives           expand directive metadata
                             --flat                 ungrouped list (omit scope grouping)
                             --phase <name>         emit only one phase (legacy compat)

  run [playbook]             Phases 4-7. Auto-detects cwd context when no
                             playbook positional.
                             --scope <type> | --all | run-all (alias)
                             --evidence <file|->    flat or nested submission
                             --evidence-dir <dir>   per-playbook submission files
                             --vex <file>           CycloneDX / OpenVEX filter
                             --format <fmt> ...     csaf-2.0 | sarif | openvex | markdown | summary | json
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
                                                  (--require-signed: unsigned → exit 1)
                             attest diff          drift vs prior or --against <other-sid>
                             attest prune         GC: delete sessions older than
                                                  --all-older-than <ISO> (--dry-run to preview)

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
                             ai-run, not ci.)
                             --all | --scope <type> | (auto-detect)
                             --max-rwep <n>         cap below playbook default
                             --block-on-jurisdiction-clock
                             --evidence-dir <dir>

  ask "<question>"           Plain-English routing to playbook(s).
  recipes [<id>]             List curated multi-skill workflows (or expand one).

  lint <pb> <evidence>       Pre-flight check submission shape vs playbook
                             (preconditions / artifacts / indicators) without
                             executing phases 4-7.

  verify-attestation <sid>   Alias for \`attest verify\`.
  run-all                    Alias for \`run --all\`.

  cve <CVE-ID>               Resolve a CVE citation: published | rejected | disputed
                             | fabricated | nonexistent (catalog → cache → one NVD
                             lookup). --air-gap/--no-network offline-only; exit 2 on
                             a citation that won't stand up.
  rfc <number>               Resolve an RFC number → title + status from the local
                             index (offline). --check "<title>" flags a mismatch.
  collect <playbook>         Run a playbook's companion collector; emits submission
                             JSON to pipe into \`run --evidence -\`. --resolve
                             (citation-hygiene) resolves uncatalogued citations.
  skill <name>               Show context for a specific skill.
  framework-gap <fw> <ref>   Programmatic gap analysis (one framework, one CVE/scenario).
  watchlist [--alerts]       Forward-watch aggregator across skills (one-shot).
  watch                      Long-running forward-watch daemon (blocks; Ctrl-C).
  report [executive]         Structured posture report.
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
                             Sources: kev|epss|nvd|rfc|pins|ghsa|osv.
                                                    ghsa drafts pass validator as warnings.
                             --check-advisories     poll primary-source advisory
                                                    feeds; report-only diffs[].

Removed verbs (refused — these now error with a pointer to the replacement)
───────────────────────────────────────────────────────────────────────────

Already gone. Invoking one prints a refusal naming its replacement. Listed
here so old scripts know where each moved:

  [REMOVED] plan              → brief --all
  [REMOVED] govern <pb>       → brief <pb> --phase govern
  [REMOVED] direct <pb>       → brief <pb> --phase direct
  [REMOVED] look <pb>         → brief <pb> --phase look
  [REMOVED] ingest            → run

Deprecated aliases (still work — prefer the canonical verb)
───────────────────────────────────────────────────────────

These still run their original implementation — they are NOT transparent
aliases, and several (scan, dispatch, currency, validate-cves, validate-rfcs)
emit the older orchestrator output shape, not the canonical verb's. Migrate to
the canonical replacement listed (whose output may differ); the [DEPRECATED]
prefix keeps them out of the active-verbs list \`exceptd help | grep '^  [a-z]'\`
surfaces.

  [DEPRECATED] scan              → discover --scan-only
  [DEPRECATED] dispatch          → discover
  [DEPRECATED] currency          → doctor --currency
  [DEPRECATED] verify            → doctor --signatures
  [DEPRECATED] validate-cves     → doctor --cves
  [DEPRECATED] validate-rfcs     → doctor --rfcs
  [DEPRECATED] prefetch          → refresh --prefetch
  [DEPRECATED] build-indexes     → refresh --indexes-only

Accepted short forms (canonical — not deprecated):

  reattest <sid>        short form of \`attest diff <sid>\`
  list-attestations     short form of \`attest list\`

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

Unknown verbs exit 10 (UNKNOWN_COMMAND) with a structured ok:false body on stderr. Exit 2 means a verb ran and detected an escalation-worthy finding (DETECTED_ESCALATE).

Full documentation: ${PKG_ROOT}/README.md
Project rules:      ${PKG_ROOT}/AGENTS.md
`);
}

function main() {
  const argv = process.argv.slice(2);

  // --json-stdout-only silences ALL stderr, at the top of main so the deprecation
  // banner and unsigned-attestation warning never fire.
  if (argv.includes("--json-stdout-only")) {
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
    // emitError reads this to route its ok:false envelope to stdout; without it a
    // failing invocation emits nothing and a `| jq` consumer sees an empty document.
    global.__exceptdJsonStdoutOnly = true;
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, encoding, cb) => {
      // Uncaught exception frames still surface; framework stderr does not.
      if (typeof chunk === "string" && chunk.startsWith("Error")) return origStderrWrite(chunk, encoding, cb);
      if (typeof cb === "function") cb();
      return true;
    };
  }

  // --quiet drops only the advisory stderr lines, keeping human-readable output,
  // errors and exit codes. Skipped under --json-stdout-only, which patched more.
  if (argv.includes("--quiet") && !argv.includes("--json-stdout-only")) {
    global.__exceptdQuiet = true;
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, encoding, cb) => {
      // Contract-violation notes ("[exceptd run] ..."), error frames and uncaught
      // exceptions still surface, so --quiet never hides why a run failed.
      if (typeof chunk === "string" && /^\[exceptd\] (note|tip):/.test(chunk)) {
        if (typeof cb === "function") cb();
        return true;
      }
      return origStderrWrite(chunk, encoding, cb);
    };
  }

  if (argv.length === 0) {
    printWelcome();
    safeExit(EXIT_CODES.SUCCESS); return;
  }
  const cmd = argv[0];
  const rest = argv.slice(1);

  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    // Routes through the same printPlaybookVerbHelp() `exceptd <verb> --help` uses.
    if (rest.length > 0 && typeof rest[0] === 'string' && rest[0].length > 0) {
      const verb = rest[0];
      // A removed verb refuses here rather than printing help for a dead verb.
      if (REMOVED_VERBS[verb]) {
        emitError(
          `'${verb}' was removed in v0.13.0. Use \`exceptd ${REMOVED_VERBS[verb]}\` instead.`,
          { verb, removed_in: "0.13.0", replacement: REMOVED_VERBS[verb] }
        );
        return;
      }
      if (printPlaybookVerbHelp(verb)) {
        safeExit(EXIT_CODES.SUCCESS); return;
      }
      process.stderr.write(`[exceptd help] no verb-specific help for "${verb}" — falling through to top-level help. Run \`exceptd help\` for the full verb list.\n`);
    }
    printHelp();
    safeExit(EXIT_CODES.SUCCESS); return;
  }
  if (cmd === "version" || cmd === "--version" || cmd === "-v") {
    process.stdout.write(readPkgVersion() + "\n");
    safeExit(EXIT_CODES.SUCCESS); return;
  }
  if (cmd === "path") {
    // With no clipboard tool, the path still goes to stdout and the warning to
    // stderr, so `cd "$(exceptd path)"` keeps working.
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
        safeExit(EXIT_CODES.SUCCESS); return;
      }
      process.stderr.write(`[exceptd path] copy: no clipboard tool available (tried: ${tried.join(", ")}). Path printed to stdout instead.\n`);
      process.stdout.write(PKG_ROOT + "\n");
      safeExit(EXIT_CODES.SUCCESS); return;
    }
    process.stdout.write(PKG_ROOT + "\n");
    safeExit(EXIT_CODES.SUCCESS); return;
  }

  if (REMOVED_VERBS[cmd]) {
    emitError(
      `'${cmd}' was removed in v0.13.0. Use \`exceptd ${REMOVED_VERBS[cmd]}\` instead.`,
      {
        verb: cmd,
        removed_in: "0.13.0",
        replacement: REMOVED_VERBS[cmd],
        deprecation_history: "Deprecated in v0.11.0 with a soft banner; slated-for-removal-in-v0.13 announced in v0.12.0; removed in v0.13.0.",
      }
    );
    return;
  }

  // Seven-phase playbook verbs run in-process, emitting JSON rather than dispatching.
  if (PLAYBOOK_VERBS.has(cmd)) {
    dispatchPlaybook(cmd, rest);
    return;
  }

  // refresh.js knows none of these flags; translate to the script that does.
  let effectiveCmd = cmd;
  let effectiveRest = rest;
  if (cmd === "refresh" && (rest.includes("--no-network") || rest.includes("--prefetch"))) {
    // Strip only `--prefetch` (the alias). `--no-network` must reach prefetch.js:
    // dropping it leaves prefetch fetching, so a cold cache hits every upstream.
    effectiveCmd = "prefetch";
    const wantedNoNetwork = rest.includes("--no-network");
    effectiveRest = rest.filter(a => a !== "--prefetch");
    if (wantedNoNetwork && !effectiveRest.includes("--no-network")) {
      // Unreachable while the filter above spares --no-network.
    }
  } else if (cmd === "refresh" && rest.includes("--indexes-only")) {
    effectiveCmd = "build-indexes";
    effectiveRest = rest.filter(a => a !== "--indexes-only");
  } else if (cmd === "refresh" && rest.includes("--network")) {
    // --network swaps data/ in place from the npm-published tarball, verified against
    // the installed public key: the `npm update -g` trust boundary, no full upgrade.
    effectiveCmd = "refresh-network";
    effectiveRest = rest.filter(a => a !== "--network");
  } else if (cmd === "refresh" && (rest.includes("--curate") || rest.includes("--curate-batch"))) {
    // Both land on cve-curation.js, whose cli() branches to lib/cve-batch.js
    // when it sees --curate-batch.
    effectiveCmd = "refresh-curate";
    effectiveRest = rest;
  }

  const resolver = COMMANDS[effectiveCmd];
  if (typeof resolver !== "function") {
    // UNKNOWN_COMMAND (10) stays distinct from DETECTED_ESCALATE (2): a caller
    // branching on exit status must tell a typo from a real finding. De-dup via
    // Set — COMMANDS and ORCHESTRATOR_PASSTHROUGH overlap deliberately.
    const known = [...new Set([
      ...Object.keys(COMMANDS),
      ...PLAYBOOK_VERBS,
      ...ORCHESTRATOR_PASSTHROUGH,
    ])].filter((v) => v && !v.startsWith('-'));
    const dym = suggestVerb(cmd, known);
    const hint = dym.length > 0
      ? `Did you mean \`${dym.join("` or `")}\`? Run \`exceptd help\` for the full verb list.`
      : "Run `exceptd help` for the list of verbs.";
    emitError(`unknown command "${cmd}"`, { hint, verb: cmd, did_you_mean: dym });
    process.exitCode = EXIT_CODES.UNKNOWN_COMMAND;
    return;
  }

  const script = resolver();
  if (!fs.existsSync(script)) {
    emitError(
      `command "${cmd}" not available — expected ${path.relative(PKG_ROOT, script)} in the installed package.`,
      { verb: cmd }
    );
    process.exitCode = EXIT_CODES.UNKNOWN_COMMAND;
    return;
  }

  // The orchestrator forwards `--help` as a positional, so these verbs would try to
  // resolve a skill named "--help". Only verbs with no help handler of their own.
  const SPAWN_HELP_USAGE = {
    skill: "exceptd skill <name>          Show the full context document for one skill. Run `exceptd skill` with no arguments to list all skill IDs.",
    "framework-gap": "exceptd framework-gap <framework> <cve-or-scenario>   One-framework gap analysis.",
    "framework-gap-analysis": "exceptd framework-gap <framework> <cve-or-scenario>   One-framework gap analysis.",
    cve: "exceptd cve <CVE-ID> [--json] [--air-gap|--no-network]   Resolve a CVE: published/rejected/disputed/fabricated/nonexistent (catalog -> cache -> NVD). Exit 2 when the citation won't stand up (rejected/fabricated/nonexistent/withdrawn).",
    rfc: "exceptd rfc <number> [--check \"<title>\"] [--json] [--air-gap]   Resolve an RFC number -> title + status (local index, offline). Exit 2 when nonexistent or --check title MISMATCH.",
    // watch MUST stay here: without it `watch --help` spawns the blocking daemon.
    watch: "exceptd watch          Long-running forward-watch daemon (blocks; Ctrl-C to stop). For a one-shot aggregator use `exceptd watchlist`.",
    watchlist: "exceptd watchlist [--alerts] [--org-scan --org <login>] [--by-skill] [--json]   One-shot forward-watch aggregator across skills.",
    report: "exceptd report [executive] [--json]   Structured posture report. Markdown by default; pass --json for machine-readable output.",
    scan: "exceptd scan [--json]          [legacy] Working-directory CVE/KEV scan (orchestrator). See `exceptd discover`.",
    dispatch: "exceptd dispatch [--json]      [legacy] Scan + route findings to skills (orchestrator). See `exceptd discover`.",
    currency: "exceptd currency [--json]      [legacy] Skill threat-currency report. See `exceptd doctor --currency`.",
    "validate-cves": "exceptd validate-cves [--offline|--air-gap] [--json]   Validate the CVE catalog against upstream (offline-first).",
    "validate-rfcs": "exceptd validate-rfcs [--offline|--air-gap] [--json]   Validate the RFC index against upstream (offline-first).",
  };
  if ((effectiveRest.includes("--help") || effectiveRest.includes("-h")) && SPAWN_HELP_USAGE[effectiveCmd]) {
    process.stdout.write(SPAWN_HELP_USAGE[effectiveCmd] + "\n  Full reference: exceptd help\n");
    return;
  }

  // Orchestrator subcommands need the name preserved as argv[0] for
  // orchestrator/index.js's switch statement.
  const finalArgs = ORCHESTRATOR_PASSTHROUGH.has(effectiveCmd) ? [script, effectiveCmd, ...effectiveRest] : [script, ...effectiveRest];
  const res = spawnSync(process.execPath, finalArgs, { stdio: "inherit", cwd: PKG_ROOT });
  if (res.error) {
    emitError(`failed to run ${cmd}: ${res.error.message}`, { verb: cmd });
    process.exitCode = EXIT_CODES.UNKNOWN_COMMAND;
    return;
  }
  // `process.exitCode`, not `process.exit()` — the child's output must drain.
  process.exitCode = typeof res.status === "number" ? res.status : 1;
}

/**
 * Tiny POSIX-ish argv parser. `--flag` is boolean true, `--key value` and
 * `--key=value` are strings, a key listed in `multi` accumulates an array, and
 * bare positionals land in `_`. Unknown flags follow the same rules.
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
  // --json / --pretty win over the TTY heuristic (isTTY is false under most CI
  // harnesses). The ok:false → exitCode contract lives here rather than per-verb,
  // so a new verb emitting ok:false cannot return 0 and defeat `set -e`.
  if (obj && obj.ok === false && !process.exitCode) {
    process.exitCode = EXIT_CODES.GENERIC_FAILURE;
  }
  // Every emitted body carries a top-level `ok` so a stdout consumer can assume the
  // envelope. Arrays are excluded: spreading one yields numeric string keys plus a
  // spurious ok:true, corrupting the SARIF results and OpenVEX statements passed
  // through verbatim.
  if (obj && typeof obj === 'object' && !Array.isArray(obj) && !('ok' in obj)) {
    obj = { ok: true, ...obj };
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
  // Sets exitCode rather than calling process.exit(), so a piped stdout drains.
  // Shape follows stderr's TTY state: a JSON envelope when piped, "error: <msg>"
  // plus helper lines when interactive. --json / --pretty force JSON either way.
  const body = Object.assign({ ok: false, error: msg }, extra || {});
  // --json-stdout-only routes this envelope to stdout, so it must be JSON. An error
  // raised before flag parsing sets __exceptdWantJson has only this flag to go on;
  // without it a human string reaches the machine channel and breaks `| jq`.
  const wantJson = !!global.__exceptdWantJson || !!process.env.EXCEPTD_RAW_JSON || !!global.__exceptdJsonStdoutOnly;
  const stderrIsTty = process.stderr.isTTY === true;
  let s;
  if (wantJson || !stderrIsTty) {
    s = pretty ? JSON.stringify(body, null, 2) : JSON.stringify(body);
  } else {
    const lines = [`error: ${msg}`];
    if (extra && typeof extra === "object") {
      const helperFields = ["hint", "suggested", "did_you_mean", "remediation", "submission_hint"];
      for (const key of helperFields) {
        if (extra[key] != null) lines.push(`  ${key}: ${extra[key]}`);
      }
    }
    s = lines.join("\n");
  }
  // stderr is suppressed under --json-stdout-only, so the envelope goes to stdout
  // or the error surfaces on neither stream. The flag has already forced JSON.
  if (global.__exceptdJsonStdoutOnly) {
    process.stdout.write(s + "\n");
  } else {
    process.stderr.write(s + "\n");
  }
  process.exitCode = EXIT_CODES.GENERIC_FAILURE;
}

/**
 * BOM-tolerant JSON reader — route every operator-supplied JSON file through here:
 * `fs.readFileSync(path, "utf8")` leaves a UTF-8 BOM in the string and decodes
 * UTF-16 as garbage. Throws "failed to parse JSON at <path>: <reason>".
 */
function readJsonFile(filePath) {
  let buf;
  try { buf = fs.readFileSync(filePath); }
  catch (e) { throw new Error(`failed to read ${filePath}: ${e.message}`); }
  let text;
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    text = buf.slice(2).toString("utf16le");
  } else if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    // UTF-16BE: Node has no native decoder, so swap byte pairs to LE first, and an
    // odd-length payload is refused up front. Buffer.alloc, not allocUnsafe: an
    // unexpected loop bound must not leak uninitialised heap into the string.
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
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  try { return JSON.parse(text); }
  catch (e) {
    throw new Error(`failed to parse JSON at ${filePath}: ${e.message}`);
  }
}

// Evidence must be a JSON object: `null`, an array or a scalar parse fine but reach
// the runner as an internal error or a silently-empty run. Rejected at the boundary.
function asEvidenceObject(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    const got = parsed === null ? "null" : Array.isArray(parsed) ? "array" : typeof parsed;
    throw new Error(`evidence must be a JSON object (e.g. {"artifacts": {...}, "signal_overrides": {...}}); got ${got}. Run \`exceptd brief <playbook>\` for the expected shape.`);
  }
  return parsed;
}

function readEvidence(evidenceFlag, opts = {}) {
  if (!evidenceFlag) return {};
  // The cap binds on BOTH branches: uncapped, piped multi-GB JSON OOMs the runner.
  const MAX_EVIDENCE_BYTES = 32 * 1024 * 1024;
  if (evidenceFlag === "-") {
    // fs.readFileSync(0) honours no maxBuffer, so the cap is enforced per chunk.
    const chunks = [];
    let total = 0;
    const buf = Buffer.alloc(1024 * 1024);
    let n;
    while ((n = fs.readSync(0, buf, 0, buf.length, null)) > 0) {
      total += n;
      if (total > MAX_EVIDENCE_BYTES) {
        throw new Error(`evidence on stdin exceeds size limit: ${total}+ bytes > ${MAX_EVIDENCE_BYTES} byte limit. Pipe a smaller submission, or split into multiple playbook runs.`);
      }
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    const text = Buffer.concat(chunks).toString("utf8");
    if (!text.trim()) {
      // Empty stdin stays a legitimate posture-only walk, so only the note changes.
      // Explicit `--evidence -` only: on the auto-promotion path nothing was asked
      // for, and writing here corrupts `run ... 2>&1 | jq` in CI.
      if (opts.explicit !== false) {
        process.stderr.write(
          `[exceptd] note: --evidence - read 0 bytes from stdin. Treating as empty evidence {}. ` +
          `If you meant to pipe a submission, run \`exceptd brief <playbook>\` to see the expected shape; ` +
          `if you wanted a posture-only walk, this message is informational and the run will proceed.\n`,
        );
      }
      return {};
    }
    return asEvidenceObject(JSON.parse(text));
  }
  let stat;
  try { stat = fs.statSync(evidenceFlag); }
  catch (e) { throw new Error(`evidence path not readable: ${e.message}`); }
  if (stat.size > MAX_EVIDENCE_BYTES) {
    throw new Error(`evidence file too large: ${stat.size} bytes > ${MAX_EVIDENCE_BYTES} byte limit. Reduce the submission or split into multiple playbook runs.`);
  }
  return asEvidenceObject(readJsonFile(evidenceFlag));
}

function loadRunner() {
  return require(path.join(PKG_ROOT, "lib", "playbook-runner.js"));
}

/**
 * True when the caller may fs.readFileSync(0) without risking an indefinite block.
 * A bare `!process.stdin.isTTY` is not enough: a wrapped stdin duplexer leaves
 * isTTY === undefined and never writes a byte, so the read waits on an EOF that
 * never comes. A harness wanting stdin auto-read skipped leaves isTTY undefined.
 */
function hasReadableStdin() {
  if (process.stdin.isTTY) return false;
  let st;
  try { st = fs.fstatSync(0); }
  catch {
    // `=== false` STRICTLY: a falsy check admits isTTY === undefined (a wrapped test
    // duplexer) and blocks forever. MSYS-bash piping on win32 sets it false.
    if (process.platform === "win32") return process.stdin.isTTY === false;
    return false;
  }
  // POSIX pipes, FIFOs, sockets and character devices report size 0 with bytes
  // queued, so they are trusted without a size check.
  if (typeof st.isFIFO === "function" && st.isFIFO()) return true;
  if (typeof st.isSocket === "function" && st.isSocket()) return true;
  if (typeof st.isCharacterDevice === "function" && st.isCharacterDevice()) return true;
  // Regular file (`exceptd run <evidence.json`); size 0 is an empty file.
  if (typeof st.size === "number" && st.size > 0) return true;
  // A win32 pipe fstats as a regular file of size 0 with bytes queued, so this
  // branch must NOT gate on size — that silently skips every `echo {} | exceptd`.
  if (process.platform === "win32" && process.stdin.isTTY === false) return true;
  return false;
}

/**
 * The shape check runs BEFORE Date.parse: bare integers like "99" coerce to
 * 1999-12-01T00:00:00Z and silently filter the wrong years. Returns null on
 * success, or the error message for the caller to prefix with its own verb.
 */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;
function validateIsoSince(raw, flagName = "--since") {
  if (typeof raw !== "string" || !ISO_DATE_RE.test(raw) || isNaN(Date.parse(raw))) {
    return `${flagName} must be a parseable ISO-8601 calendar timestamp (e.g. 2026-05-01 or 2026-05-01T00:00:00Z). Got: ${JSON.stringify(String(raw)).slice(0, 80)}`;
  }
  return null;
}

/**
 * Pre-validates a --vex document: vexFilterFromDoc returns Set(0) for anything it
 * doesn't recognise, so a SARIF or CSAF file passed by mistake would filter
 * nothing, silently. Returns { ok, detected, top_level_keys }.
 */
function detectVexShape(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { ok: false, detected: "not-an-object", top_level_keys: [] };
  }
  const keys = Object.keys(doc);
  // Canonical CycloneDX VEX is bomFormat==="CycloneDX" + vulnerabilities[]; 1.4+
  // also allows a standalone vulnerabilities document carrying analysis.state.
  if (Array.isArray(doc.vulnerabilities)) {
    const isBom = doc.bomFormat === "CycloneDX";
    const specStr = typeof doc.specVersion === "string" ? doc.specVersion : "";
    const hasCyclonedxMarker = isBom || specStr.startsWith("1.");
    // An empty array satisfies `entriesLookVex` trivially, so it needs a real
    // bomFormat / specVersion marker to pass.
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
  const ctx = doc["@context"];
  const ctxStr = Array.isArray(ctx) ? ctx[0] : ctx;
  if (typeof ctxStr === "string" && ctxStr.startsWith("https://openvex.dev/") && Array.isArray(doc.statements)) {
    return { ok: true, detected: "openvex", top_level_keys: keys };
  }
  // Common false-positive shapes — give the operator a hint.
  if (Array.isArray(doc.runs) && doc.$schema && String(doc.$schema).includes("sarif")) {
    return { ok: false, detected: "sarif-not-vex", top_level_keys: keys };
  }
  if (doc.document && doc.document.category && String(doc.document.category).startsWith("csaf_")) {
    return { ok: false, detected: "csaf-advisory-not-vex", top_level_keys: keys };
  }
  // A CycloneDX SBOM with no `vulnerabilities` key asserts nothing is exploitable,
  // so it is a zero-CVE filter. specVersion "1.x" alone counts as the marker:
  // some tooling drops bomFormat on export.
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
  // Validated here too, so a direct caller still gets the traversal refusal.
  const r = validateIdComponent(playbookId, "playbook");
  if (!r.ok) throw new Error(`invalid playbook id (${r.reason}): ${typeof playbookId === "string" ? playbookId.slice(0, 80) : typeof playbookId}`);
  const pb = runner.loadPlaybook(playbookId);
  if (!pb.directives || !pb.directives.length) {
    throw new Error(`Playbook ${playbookId} has no directives.`);
  }
  return pb.directives[0].id;
}

function dispatchPlaybook(cmd, argv) {
  // Per-verb --help before positional validation, so a bare verb gets usage text
  // rather than a missing-argument error.
  if (argv.includes("--help") || argv.includes("-h")) {
    printPlaybookVerbHelp(cmd);
    safeExit(EXIT_CODES.SUCCESS); return;
  }

  const args = parseArgs(argv, {
    bool:  ["pretty", "air-gap", "force-stale", "all", "flat", "directives",
            "ci", "latest", "diff-from-latest", "explain", "signal-list", "ack",
            "force-overwrite", "no-stream", "block-on-jurisdiction-clock",
            "force-replay",
            "json-stdout-only", "fix", "human", "json", "strict-preconditions",
            // Byte-stable bundle output; frozen timestamp from --bundle-epoch.
            "bundle-deterministic",
            "shipped-tarball", "registry-check", "signatures", "currency", "cves", "rfcs",
            "collectors",
            "exit-codes",
            // Opts in the policy-skipped playbooks the scope filter excludes.
            "include-judgement-shaped"],
    multi: ["playbook", "format"],
  });
  // Default is human-readable text, or indented JSON for verbs with no renderer yet.
  args._jsonMode = !!(args.json || args.pretty || args["json-stdout-only"]);
  // Module-level so emit() can read it without plumbing.
  global.__exceptdWantJson = args._jsonMode;
  const pretty = !!args.pretty;

  // Flag-typo defense, refused before any side effect runs: `run --evidnce ev.json`
  // otherwise parses as a boolean and fails downstream with a cryptic error.
  // REQUIRES_VALUE holds value-bearing flags only — a boolean's `true` parse is the
  // operator's intent, so listing one here would refuse correct usage.
  const REQUIRES_VALUE = new Set([
    "evidence", "evidence-dir", "session-id", "operator", "csaf-status",
    "publisher-namespace", "mode", "scope", "playbook", "phase", "tlp",
    "against", "since", "bundle-epoch", "attestation-root", "format",
    "cwd",  // exceptd collect <pb> --cwd <path>
    "limit",  // exceptd attest list --limit <n>
    "required",  // exceptd ci --required <pb,pb> — value-less form must refuse, not `true.split(",")`
  ]);
  const verbAllowlist = flagsFor(cmd);
  const allowlistSet = new Set(verbAllowlist);
  // lib/flag-suggest.js's allowlist is operator-facing only; these internal flags
  // still flow through without tripping the typo check.
  const PASSTHROUGH_FLAGS = new Set([
    "directive", "domain", "phase", "signal-list", "explain",
    "signatures", "currency", "cves", "rfcs", "shipped-tarball", "collectors",
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
    // Valid on another verb: fall through for the handler's tailored guidance.
    if (ALL_KNOWN_FLAGS.has(key)) continue;
    // Unknown everywhere: a new flag must be added to its verb's allowlist in
    // lib/flag-suggest.js (or to PASSTHROUGH_FLAGS) or it is refused here.
    const suggestion = suggestFlag(key, verbAllowlist);
    return emitError(
      `${cmd}: unknown flag --${key}`,
      {
        verb: cmd,
        unknown_flags: [{ flag: `--${key}`, did_you_mean: suggestion ? [`--${suggestion}`] : [] }],
        known_flags: verbAllowlist.filter((f) => typeof f === "string").sort().map((f) => `--${f}`),
      },
      pretty
    );
  }
  const runOpts = {
    // EXCEPTD_AIR_GAP=1 equals the flag, so a shell-init export binds every run.
    airGap: !!args["air-gap"] || process.env.EXCEPTD_AIR_GAP === "1",
    forceStale: !!args["force-stale"],
  };
  // One-time per process, on stderr so stdout JSON consumers don't see it.
  if (runOpts.airGap && !process.env.EXCEPTD_AIR_GAP_NOTICE_SHOWN) {
    process.stderr.write(
      `[exceptd] air-gap: exceptd will not perform network egress. Your AI agent may still call its model API; verify your agent runtime is also offline.\n`
    );
    process.env.EXCEPTD_AIR_GAP_NOTICE_SHOWN = "1";
  }
  if (args["session-id"] !== undefined) {
    // --session-id becomes a path component under .exceptd/attestations/<id>/, so
    // `..` or a separator escapes the root; validateIdComponent('session') keeps
    // the rule aligned with persistAttestation / validateSessionIdForRead.
    // Presence-gated: a truthy gate skips the validator for `--session-id ""`.
    const sid = args["session-id"];
    const r = validateIdComponent(sid, "session");
    if (!r.ok) {
      return emitError(
        `${cmd}: --session-id ${r.reason}. Path separators and '..' are rejected.`,
        { verb: cmd, provided: typeof sid === "string" ? sid.slice(0, 80) : typeof sid },
        pretty
      );
    }
    runOpts.session_id = sid;
  }
  if (args["attestation-root"]) {
    // Input validation only; resolveAttestationRoot does the final resolution.
    const ar = args["attestation-root"];
    if (typeof ar !== "string" || ar.length === 0) {
      return emitError(`${cmd}: --attestation-root must be a non-empty string.`, { verb: cmd, provided: typeof ar }, pretty);
    }
    const arSegments = ar.split(/[\\/]/);
    if (arSegments.some(seg => seg === "..")) {
      return emitError(
        `${cmd}: --attestation-root must not contain '..' path segments. Pass an absolute path under your home directory or an explicit project-relative path without traversal.`,
        { verb: cmd, provided: ar.slice(0, 200) },
        pretty
      );
    }
    // Every all-dots segment resolves into or above the intended parent and defeats
    // the confinement, so all are refused rather than one shape at a time.
    if (arSegments.some(seg => seg.length > 0 && /^\.+$/.test(seg))) {
      return emitError(
        `${cmd}: --attestation-root path segment cannot consist entirely of dots (rejected: '.', '..', '...', etc.). Pass an absolute path or a project-relative path without traversal.`,
        { verb: cmd, provided: ar.slice(0, 200) },
        pretty
      );
    }
    runOpts.attestationRoot = path.resolve(ar);
  }
  if (args["session-key"]) {
    // A non-hex key reaches HMAC signing and yields an unverifiable signature.
    if (!/^[0-9a-fA-F]+$/.test(args["session-key"])) {
      return emitError(`${cmd}: --session-key must be hex characters only (0-9, a-f). Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`, { verb: cmd, provided_length: args["session-key"].length }, pretty);
    }
    if (args["session-key"].length < 16) {
      return emitError(`${cmd}: --session-key is too short (need at least 16 hex chars / 64 bits of entropy).`, { verb: cmd, provided_length: args["session-key"].length }, pretty);
    }
    runOpts.session_key = args["session-key"];
  }
  if (args.mode !== undefined) {
    // Presence-gated so `--mode ""` reaches the set check instead of slipping past.
    const VALID_MODES = ["self_service", "authorized_pentest", "ir_response", "ctf", "research", "compliance_audit"];
    if (!VALID_MODES.includes(args.mode)) {
      const dym = suggestFlag(String(args.mode), VALID_MODES);
      const hint = dym ? ` Did you mean "${dym}"?` : '';
      return emitError(
        `${cmd}: --mode "${args.mode}" not in accepted set ${JSON.stringify(VALID_MODES)}.${hint}`,
        { verb: cmd, provided: args.mode, accepted: VALID_MODES, did_you_mean: dym ? [dym] : [] },
        pretty,
      );
    }
    runOpts.mode = args.mode;
  }
  // --operator persists into the attestation, so a control character is a forgery
  // surface: a newline reads as a separate attestation field to a naive parser.
  if (args.operator !== undefined) {
    if (typeof args.operator !== "string") {
      return emitError(`${cmd}: --operator must be a string.`, { verb: cmd, provided: typeof args.operator }, pretty);
    }
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1F\x7F]/.test(args.operator)) {
      return emitError(
        `${cmd}: --operator contains ASCII control characters (newline, tab, NUL, etc.). Refusing — these would corrupt attestation export shape and enable forgery via multi-line injection.`,
        { verb: cmd, provided_length: args.operator.length },
        pretty
      );
    }
    if (args.operator.length > 256) {
      return emitError(
        `${cmd}: --operator too long: ${args.operator.length} chars (limit 256). Use a stable identifier (email, service-account name) — not a free-form description.`,
        { verb: cmd, provided_length: args.operator.length },
        pretty
      );
    }
    if (args.operator.trim().length === 0) {
      return emitError(
        `${cmd}: --operator is empty or whitespace-only. Pass a meaningful identifier or omit the flag.`,
        { verb: cmd },
        pretty
      );
    }
    // The ASCII regex above misses Unicode Cc/Cf/Co/Cn — bidi, zero-width, format, private-use, unassigned.
    // allow:bidi-codepoint-literal — illustrative bidi-forgery example in the --operator reject-path doc comment
    // "alice‮evilbob" renders as "alicebobevila" wherever bidi is honoured, so
    // the attested name reads as Bob while the bytes say Alice. NFC-normalise first,
    // or a decomposed sequence smuggles a combining mark past the codepoint check.
    let normalized;
    try { normalized = args.operator.normalize("NFC"); }
    catch (e) {
      return emitError(
        `${cmd}: --operator failed Unicode NFC normalisation: ${e.message}`,
        { verb: cmd, provided_length: args.operator.length },
        pretty
      );
    }
    if (normalized.length === 0) {
      return emitError(
        `${cmd}: --operator is empty after Unicode NFC normalisation. Pass a meaningful identifier or omit the flag.`,
        { verb: cmd },
        pretty
      );
    }
    if (/\p{C}/u.test(normalized)) {
      // \p{C} is the reject gate — broader than the family regexes below, which only
      // CLASSIFY the first offending codepoint for the hint. Narrowing the gate to
      // those tables readmits U+007F, U+0080-009F, private-use and unassigned.
      let offending = "";
      let family = "control / format / private-use / unassigned codepoint";
      for (const cp of normalized) {
        if (/\p{C}/u.test(cp)) {
          offending = "U+" + cp.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
          if (codepointClass.BIDI_RE.test(cp)) family = "bidirectional-override codepoint";
          else if (codepointClass.ZERO_WIDTH_RE.test(cp)) family = "zero-width / invisible codepoint";
          else if (cp === codepointClass.NULL_BYTE) family = "null byte";
          else if (codepointClass.C0_CTRL_RE.test(cp)) family = "C0 control character";
          break;
        }
      }
      return emitError(
        `${cmd}: --operator contains a Unicode ${family} (${offending}). Bidi overrides, zero-width joiners, and format marks corrupt attestation rendering and enable name-forgery. Use printable identifiers only.`,
        { verb: cmd, provided_length: args.operator.length, offending_codepoint: offending, offending_family: family },
        pretty
      );
    }
    runOpts.operator = normalized;
  }

  // Only these verbs assemble a CSAF bundle. Elsewhere the bundle flags are refused
  // rather than consumed, so no operator believes a discarded flag applied.
  const BUNDLE_FLAG_RELEVANT_VERBS = new Set([
    "run", "ci", "run-all", "ai-run",
  ]);

  // --publisher-namespace threads into document.publisher.namespace. CSAF §3.1.7.4
  // requires the publisher's own trust anchor — the operator, not the vendor.
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

  // --csaf-status promotes tracking.status off the `interim` default; `final` carries
  // the immutable-advisory contract of CSAF §3.1.11.3.5.1, so a typo is refused
  // rather than falling back to interim.
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

  // --tlp stamps the bundle's CSAF document.distribution marking (TLP 2.0 labels).
  if (args.tlp !== undefined) {
    if (!BUNDLE_FLAG_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --tlp is irrelevant on this verb (no bundle is assembled). --tlp only applies to verbs that drive phases 5-7: ${[...BUNDLE_FLAG_RELEVANT_VERBS].sort().join(", ")}.`,
        { verb: cmd, flag: "tlp", error_class: "irrelevant-flag", accepted_verbs: [...BUNDLE_FLAG_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    const tlp = typeof args.tlp === "string" ? args.tlp.toUpperCase() : args.tlp;
    const allowedTlp = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];
    if (typeof tlp !== "string" || !allowedTlp.includes(tlp)) {
      return emitError(
        `${cmd}: --tlp must be one of ${JSON.stringify(allowedTlp)} (TLP 2.0). Got: ${JSON.stringify(String(args.tlp)).slice(0, 40)}`,
        { verb: cmd, flag: "tlp", provided: args.tlp },
        pretty
      );
    }
    runOpts.tlp = tlp;
  }

  // Deterministic emit: timestamps freeze to --bundle-epoch (else the playbook's
  // last_threat_review), an auto session_id derives from sha256(playbook +
  // evidence_hash + engine_version), and vulnerabilities[] / statements[] sort.
  if (args["bundle-deterministic"] !== undefined && args["bundle-deterministic"] !== false) {
    if (!BUNDLE_FLAG_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --bundle-deterministic is irrelevant on this verb (no bundle is assembled). --bundle-deterministic only applies to verbs that drive phases 5-7: ${[...BUNDLE_FLAG_RELEVANT_VERBS].sort().join(", ")}.`,
        { verb: cmd, flag: "bundle-deterministic", error_class: "irrelevant-flag", accepted_verbs: [...BUNDLE_FLAG_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    runOpts.bundleDeterministic = true;
  }
  if (args["bundle-epoch"] !== undefined) {
    if (!BUNDLE_FLAG_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --bundle-epoch is irrelevant on this verb (no bundle is assembled). --bundle-epoch only applies to verbs that drive phases 5-7: ${[...BUNDLE_FLAG_RELEVANT_VERBS].sort().join(", ")}.`,
        { verb: cmd, flag: "bundle-epoch", error_class: "irrelevant-flag", accepted_verbs: [...BUNDLE_FLAG_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    const epoch = args["bundle-epoch"];
    if (typeof epoch !== "string") {
      return emitError(
        `${cmd}: --bundle-epoch must be a string ISO-8601 timestamp.`,
        { verb: cmd, flag: "bundle-epoch", provided: typeof epoch },
        pretty
      );
    }
    const isoErr = validateIsoSince(epoch);
    if (isoErr) {
      return emitError(
        `${cmd}: --bundle-epoch must be a parseable ISO-8601 calendar timestamp (e.g. 2026-01-01T00:00:00Z). Got: ${JSON.stringify(epoch).slice(0, 80)}`,
        { verb: cmd, flag: "bundle-epoch", provided: epoch.slice(0, 80) },
        pretty
      );
    }
    // Always a full ISO timestamp downstream: date-only becomes T00:00:00.000Z.
    runOpts.bundleEpoch = new Date(epoch).toISOString();
  }

  // --ack records acknowledgement of the jurisdiction obligations into the
  // attestation, so tooling can tell explicit consent from implicit. Refused on
  // info-only verbs, which start no clock for consent to attach to.
  const ACK_RELEVANT_VERBS = new Set([
    "run", "ai-run", "ci", "run-all", "reattest",
  ]);
  if (args.ack) {
    if (!ACK_RELEVANT_VERBS.has(cmd)) {
      return emitError(
        `${cmd}: --ack is irrelevant on this verb (no jurisdiction clock at stake). --ack only applies to verbs that drive phases 5-7: ${[...ACK_RELEVANT_VERBS].sort().join(", ")}. Re-invoke without --ack, or use \`exceptd run ${cmd === "brief" ? args._[0] || "<playbook>" : "<playbook>"} --ack\` once you're past the briefing step.`,
        { verb: cmd, flag: "ack", error_class: "irrelevant-flag", accepted_verbs: [...ACK_RELEVANT_VERBS].sort() },
        pretty
      );
    }
    runOpts.operator_consent = { acked_at: new Date().toISOString(), explicit: true };
  }

  // PASSTHROUGH_FLAGS short-circuits the typo loop above, so a flag parked there
  // would be silently dropped on a verb that doesn't consume it. Each entry names
  // the verbs that do; anywhere else is an irrelevant-flag refusal. `--cwd` is the
  // sharp one: `run secrets --cwd /target` would pass on a directory never read.
  const SINGLE_VERB_PASSTHROUGH = {
    "max-rwep": ["ci"],
    "diff-from-latest": ["run"],
    "upstream-check": ["run"],
    "cwd": ["collect", "discover"],
  };
  for (const [flag, relevantVerbs] of Object.entries(SINGLE_VERB_PASSTHROUGH)) {
    // Gate on presence: a boolean parses as `true`, a value-bearing one as string.
    if (args[flag] === undefined || args[flag] === false) continue;
    if (relevantVerbs.includes(cmd)) continue;
    return emitError(
      `${cmd}: --${flag} is irrelevant on this verb (nothing here consumes it). --${flag} only applies to: ${relevantVerbs.slice().sort().join(", ")}. Re-invoke without --${flag}, or pass it on \`exceptd ${relevantVerbs[0]} …\`.`,
      { verb: cmd, flag, error_class: "irrelevant-flag", accepted_verbs: relevantVerbs.slice().sort() },
      pretty
    );
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
      case "run":      return cmdRun(runner, args, runOpts, pretty);
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
      case "recipes": return cmdRecipes(runner, args, runOpts, pretty);
      case "ci":     return cmdCi(runner, args, runOpts, pretty);
      case "collect": return cmdCollect(runner, args, runOpts, pretty);
    }
  } catch (e) {
    // Playbooks and skills both read as runnable, so a skill name typed as a
    // playbook gets the playbooks loading it, not a bare "Playbook not found".
    const m = e && e.message && e.message.match(/^Playbook not found: ([^\s(]+)/);
    if (m) {
      const wanted = m[1];
      const hint = buildSkillToPlaybookHint(runner, wanted);
      if (hint) {
        return emitError(`Playbook not found: "${wanted}". ${hint}`, { verb: cmd, wanted, type: "playbook_not_found" }, pretty);
      }
    }
    // A validation message is the operator's to fix, so it is emitted plainly rather
    // than as an "internal error". The NPE/TypeError guards keep a real fault whose
    // text happens to contain "invalid" on the bug path.
    const msg = e && e.message ? String(e.message) : String(e);
    if (
      /\b(must be|must match|not in accepted set|is not a valid|unrecognized)\b|\binvalid /i.test(msg) &&
      msg.length < 300 &&
      !/cannot read prop|is not a function|is not defined|undefined \(reading|maximum call stack/i.test(msg)
    ) {
      return emitError(`${cmd}: ${msg}`, { verb: cmd, type: "validation_error" }, pretty);
    }
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
             `Tip: \`exceptd brief --all\` lists all ${ids.length} playbooks; \`exceptd watch\` lists skills.`;
    }
    // No matching skill either. Substring first (cheap), then edit distance.
    const subMatches = ids.filter(id => id.includes(wanted) || wanted.includes(id)).slice(0, 3);
    const fuzzyMatches = subMatches.length === 0 ? nearestByEditDistance(wanted, ids, 2).slice(0, 3) : [];
    const near = subMatches.length ? subMatches : fuzzyMatches;
    if (near.length > 0) {
      return `Did you mean: ${near.join(", ")}? Run \`exceptd brief --all\` for the full list.`;
    }
    return `Run \`exceptd brief --all\` to list the ${ids.length} playbooks.`;
  } catch { return null; }
}

/**
 * Returns the ids within `maxDistance` edits of `wanted`, closest first.
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
    recipes: `recipes [<id>] — curated multi-skill workflows (use-case → ordered skill chain).

With no id: lists every recipe with its "when to use" guidance.
With <id>:  expands that recipe's ordered skill_chain and notes.

Flags:
  --json   Machine-readable output.`,
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
  --format <fmt> ...      Transform stdout. Supported: summary | markdown |
                          csaf-2.0 | csaf | sarif | openvex | json (json = the
                          full run result). Standardized bundles (csaf/sarif/
                          openvex) are emitted as spec-conformant documents.
                          Repeatable, but only ONE document goes to stdout — the
                          first; every requested bundle is embedded under
                          close.evidence_package.bundles_by_format (see via
                          --json). Passing several prints a note to stderr.
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
  --bundle-deterministic  Emit byte-stable CSAF / OpenVEX / close envelope.
                          Freezes tracking + timestamp fields to a single
                          epoch, derives session_id from evidence hash when
                          not supplied via --session-id, and sorts
                          vulnerabilities[] / statements[] ascending.
                          Off by default; opt-in for reproducible-build
                          pipelines + diff-friendly attestation review.
  --bundle-epoch <ISO>    Frozen epoch for --bundle-deterministic. ISO-8601
                          calendar timestamp (date or date+time). Falls back
                          to the playbook's last_threat_review when omitted.
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

Subverbs (list | show | export | verify | diff | prune):
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
  attest prune            GC stale sessions: delete attestations older than
                          --all-older-than <ISO>. --dry-run previews the set
                          without deleting.

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
  --cwd <dir>             Scan <dir> instead of the current directory.
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
                          file outside .keys/. When the key is already
                          present, --fix is a no-op (surfaces fix_status:
                          "already_present" so callers can distinguish
                          clean-state from broken-state).
  --collectors            Audit the per-playbook collector layer:
                          which playbooks have a collector module under
                          lib/collectors/, which are policy-skipped by
                          design, and which collectors haven't been wired
                          up yet. JSON emits has_collector / policy_skips /
                          without_collector arrays.
  --ai-config             Walk the operator's AI-assistant configuration
                          files (~/.claude/, ~/.cursor/, ~/.codeium/,
                          ~/.aider/, ~/.continue/) and surface sensitive
                          content (API keys, tokens, MCP server
                          definitions) plus on Windows the icacls ACL
                          state. Combine with --fix to harden ACLs.
                          Opt-in — never part of the default scan.
  --exit-codes            Dump the canonical EXIT_CODES table as JSON.
                          Useful for CI / scripting consumers that want
                          the documented exit-code contract without parsing
                          help text. Off by default.
  --shipped-tarball       Round-trip the verify-shipped-tarball gate:
                          npm pack → extract to a tempdir → run
                          lib/verify.js against the extracted tree.
                          Surfaces the signature-regression class where
                          source-tree verify passes but the published
                          tarball fails. Off by default.
  (no flag)               --signatures + --currency + --cves + --rfcs +
                          signing-status. --registry-check, --collectors,
                          --ai-config, --exit-codes, --shipped-tarball are
                          opt-in and never run as part of the default scan.

Flags:
  --json                  Emit JSON (default is human-readable text).
  --pretty                Indented JSON output (implies --json).
  --air-gap               Suppress the --registry-check network probe.

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
  --bundle-deterministic  Emit byte-stable bundles for reproducible pipelines.
  --bundle-epoch <ISO>    Frozen epoch for --bundle-deterministic.
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
  7  SESSION_ID_COLLISION  --session-id duplicate; pass --force-overwrite or fresh id.
  8  LOCK_CONTENTION       Concurrent persistAttestation lock held.
  9  STORAGE_EXHAUSTED     Disk/quota/RO filesystem on attestation write.

Stdin event grammar (one JSON object per line):
  {"event":"evidence","payload":{
    "precondition_checks": {...},  // per-precondition boolean assertions
    "observations":        {...},  // per-artifact + per-indicator captures
    "verdict":             {...}   // optional operator-supplied verdict
  }}
  observations[<key>] carries both artifact captures
  ({ captured: true, value: "..." }) AND indicator overrides
  ({ indicator: "<id>", result: "hit"|"miss" }) — the runner normalises
  both branches from a single map. The alternative nested shape
  ({ artifacts, signal_overrides, signals }) is also accepted; do not mix
  the two — if signal_overrides is present, observations/verdict are
  ignored.

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
                          Clocks are STARTED, not pending — most playbooks
                          declare clock_starts: "detect_confirmed", which
                          stays pending_clock_start_event until two things
                          align: (a) the submission's verdict.classification
                          (signals.detection_classification) is "detected",
                          AND (b) the operator passes --ack (records
                          operator_consent.explicit = true). Alternatively,
                          stamp it directly with
                          verdict.clock_started_at_detect_confirmed: "<ISO>"
                          in the submission's signals. Without one of those
                          paths the clocks stay pending and the flag is a
                          no-op.
  --format <fmt>          Output shape. Supported: json (default, single-line),
                          summary (5-field digest), markdown (human digest).
                          Bundles (csaf-2.0/sarif/openvex) live on per-run
                          attestations, not the aggregate ci verdict.
  --csaf-status <s>       CSAF tracking.status threaded into per-run bundles.
                          One of: draft | interim (default) | final.
  --publisher-namespace <url>
                          CSAF document.publisher.namespace (§3.1.7.4). The
                          operator's organisation URL, NOT the tooling vendor.
  --bundle-deterministic  Emit byte-stable bundles across per-playbook runs.
  --bundle-epoch <ISO>    Frozen epoch for --bundle-deterministic.
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
\`attest verify\` and on \`run\` / \`ai-run\`, not on \`ci\`.)

Output: verb, session_id, playbooks_run, summary{total, detected,
max_rwep_observed, jurisdiction_clocks_started, verdict, fail_reasons[]},
results[].`,
    collect: `collect <playbook> [--cwd <dir>] [--attest-ownership] [--resolve] [--air-gap] [--json]

Scan the working directory (or --cwd <dir>) and emit an evidence submission
for <playbook>, ready to pipe into \`run\`:

  exceptd collect <playbook> | exceptd run <playbook> --evidence -

Flags:
  --cwd <dir>             Scan <dir> instead of the current directory.
  --attest-ownership      Attest that you own (or hold written authorisation
                          for) the asset being scanned, satisfying an ownership
                          precondition (e.g. cicd-pipeline-compromise's
                          operator-owns-ci-fleet gate) so run does not block.
  --resolve               (citation-hygiene) resolve uncatalogued CVE/RFC
                          citations found during the scan.
  --air-gap               Do not touch the network during collection.
  --json                  Raw JSON (default when piped; collect output is the
                          submission, not a human digest).`,
    brief: `brief [playbook] — unified info doc (v0.11.0).

Collapses the info-only phases govern + direct + look into a single document,
and replaces the removed plan / govern / direct / look verbs. Phases 1-3 of
the seven-phase contract are entirely informational; brief reads them in one
CLI invocation instead of three.

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
  --flat                  Ungrouped playbook list (omit grouped_by_scope +
                          scope_summary). Use with --all / --scope.
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
                          Must be an http://… or https://… URL, ≤256 chars.
  --bundle-deterministic  Emit byte-stable bundles across the multi-run set.
  --bundle-epoch <ISO>    Frozen epoch for --bundle-deterministic.`,
  };
  // Returns whether a verb block existed, so `help <verb>` knows to fall through.
  if (cmds[verb]) {
    process.stdout.write(cmds[verb] + "\n");
    return true;
  }
  process.stdout.write(`${verb} — no per-verb help available; see \`exceptd help\` for the full list.\n`);
  return false;
}

/** Runs a playbook's collector, emitting submission JSON for `run --evidence -`. */
async function cmdCollect(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) {
    return emitError(
      "collect: usage: exceptd collect <playbook>",
      {
        hint: "Run `exceptd doctor --collectors` to see which playbooks have collectors, or `exceptd discover` to see which apply to this cwd.",
      },
      pretty,
    );
  }
  if (refuseInvalidPlaybookId("collect", playbookId, pretty)) return;

  const collectorPath = path.join(PKG_ROOT, "lib", "collectors", `${playbookId}.js`);
  if (!fs.existsSync(collectorPath)) {
    const collectorsDir = path.join(PKG_ROOT, "lib", "collectors");
    let available = [];
    try {
      available = fs.readdirSync(collectorsDir)
        .filter(f => f.endsWith(".js"))
        .map(f => f.replace(/\.js$/, ""));
    } catch {}
    return emitError(
      `collect: no companion collector for "${playbookId}". The AI-evidence path remains: see \`exceptd lint ${playbookId} -\` for the submission shape and supply your own evidence to \`exceptd run ${playbookId} --evidence -\`.`,
      {
        verb: "collect",
        playbook_id: playbookId,
        collectors_available: available,
        type: "collector_not_found",
        exit_code: 1,
      },
      pretty
    );
  }

  let mod;
  try { mod = require(collectorPath); }
  catch (e) {
    return emitError(`collect: failed to load collector ${path.relative(PKG_ROOT, collectorPath)}: ${e.message}`, { verb: "collect", playbook_id: playbookId }, pretty);
  }
  if (typeof mod.collect !== "function") {
    return emitError(`collect: collector at ${path.relative(PKG_ROOT, collectorPath)} does not export a collect() function`, { verb: "collect", playbook_id: playbookId }, pretty);
  }

  let cwd = process.cwd();
  // `--cwd ""` is falsy: without this branch it scans process.cwd() instead.
  if (args.cwd === "") {
    return emitError(`collect: --cwd was given an empty value; pass an existing directory path`, { verb: "collect", playbook_id: playbookId }, pretty);
  }
  if (args.cwd) {
    const resolved = path.resolve(String(args.cwd));
    let stat;
    try { stat = fs.statSync(resolved); }
    catch (e) {
      return emitError(`collect: --cwd "${args.cwd}" does not exist (${e.message})`, { verb: "collect", playbook_id: playbookId, provided_cwd: args.cwd }, pretty);
    }
    if (!stat.isDirectory()) {
      return emitError(`collect: --cwd "${args.cwd}" is not a directory`, { verb: "collect", playbook_id: playbookId, provided_cwd: args.cwd }, pretty);
    }
    cwd = resolved;
  }

  let submission;
  try {
    submission = mod.collect({ cwd, env: process.env, args });
  } catch (e) {
    return emitError(
      `collect: collector for "${playbookId}" threw an unhandled exception: ${e.message}. File a bug — collectors must catch their own errors and surface them via collector_errors[].`,
      { verb: "collect", playbook_id: playbookId, stack: e.stack || null },
      pretty,
    );
  }

  // An empty signal_overrides is indistinguishable from "ran and found nothing",
  // so a failed precondition gets one stderr line.
  const failedPre = Object.entries(submission.precondition_checks || {})
    .filter(([, v]) => v === false)
    .map(([k]) => k);
  if (failedPre.length > 0) {
    // Any failed precondition, not just an empty submission: a collector failing a
    // consent gate still emits artifacts that `run` blocks at preflight.
    const emptySignals = !submission.signal_overrides || Object.keys(submission.signal_overrides).length === 0;
    const tail = emptySignals
      ? "empty submission emitted (collector skipped on this host)"
      : "submission emitted, but `run` will block at preflight until this precondition is satisfied";
    process.stderr.write(`[collect ${playbookId}] precondition not satisfied: ${failedPre.join(", ")} — ${tail}\n`);
  }

  // air_gap_mode rides on the collect envelope so a downstream `run --evidence -`
  // sees the same disposition. A playbook's own _meta.air_gap_mode counts: `run`
  // honors it without --air-gap, so collect must mirror it or the two disagree.
  let pbMetaAirGap = false;
  try { pbMetaAirGap = !!(runner.loadPlaybook(playbookId)?._meta?.air_gap_mode); }
  catch { /* a collector exists, so the load should not fail; default to false */ }
  const collectAirGap = !!(runOpts.airGap || process.env.EXCEPTD_AIR_GAP === "1" || pbMetaAirGap);

  // --resolve flips the signals parked by citations the offline catalog could not
  // confirm. Only a collector exporting applyResolution supports it.
  if (args.resolve) {
    if (typeof mod.applyResolution !== "function") {
      return emitError(
        `collect: --resolve is not supported by the "${playbookId}" collector (no resolution step).`,
        { verb: "collect", playbook_id: playbookId },
        pretty,
      );
    }
    try {
      submission = await mod.applyResolution(submission, { airGap: collectAirGap });
    } catch (e) {
      return emitError(
        `collect: --resolve failed for "${playbookId}": ${e.message}`,
        { verb: "collect", playbook_id: playbookId },
        pretty,
      );
    }
  }

  // `...submission` first: a collector's own `air_gap_mode` must not clobber the marker.
  const collectBody = { verb: "collect", playbook_id: playbookId, ...submission, air_gap_mode: collectAirGap };
  // The human summary is TTY-only: off a TTY the output feeds
  // `| exceptd run <pb> --evidence -`, where prose fails to parse.
  const collectHuman = process.stdout.isTTY ? (obj) => {
    const lines = [];
    const meta = obj.collector_meta || {};
    lines.push(`collect: ${obj.playbook_id}  (${meta.collector_version || "?"} on ${meta.platform || "?"})`);
    if (meta.duration_ms != null) lines.push(`  duration: ${meta.duration_ms}ms`);
    const pre = obj.precondition_checks || {};
    if (Object.keys(pre).length) {
      lines.push(`\nPreconditions:`);
      for (const [k, v] of Object.entries(pre)) {
        const icon = v ? "[ok]" : "[!!]";
        lines.push(`  ${icon} ${k} = ${v}`);
      }
    }
    const artifacts = obj.artifacts || {};
    if (Object.keys(artifacts).length) {
      lines.push(`\nArtifacts:`);
      for (const [k, a] of Object.entries(artifacts)) {
        const icon = a.captured ? "[ok]" : "[skip]";
        const val = (a.value || "").length > 120 ? (a.value || "").slice(0, 117) + "..." : (a.value || "");
        lines.push(`  ${icon} ${k}: ${val}`);
        if (!a.captured && a.reason) lines.push(`         reason: ${a.reason}`);
      }
    }
    const signals = obj.signal_overrides || {};
    const hits = Object.entries(signals).filter(([, v]) => v === "hit");
    if (hits.length) {
      lines.push(`\nIndicators that fired (${hits.length}):`);
      for (const [k] of hits) lines.push(`  [hit]  ${k}`);
    }
    const errs = obj.collector_errors || [];
    if (errs.length) {
      lines.push(`\nCollector warnings (${errs.length}):`);
      for (const e of errs.slice(0, 5)) {
        lines.push(`  [${e.kind || "warning"}] ${e.artifact_id ? e.artifact_id + ": " : ""}${e.reason || "(no detail)"}`);
      }
      if (errs.length > 5) lines.push(`  … ${errs.length - 5} more`);
    }
    lines.push(`\n→ next: exceptd collect ${obj.playbook_id} | exceptd run ${obj.playbook_id} --evidence -`);
    lines.push(`Full structured result: --json (or --pretty for indented JSON).`);
    return lines.join("\n");
  } : undefined;
  emit(collectBody, pretty, collectHuman);
}

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
    // Same skill-id hint dispatchPlaybook gives cmdRun.
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

  // Lint validates the NORMALIZED submission: normalizeSubmission follows
  // `val.artifact` indirection, so skipping it makes lint and run disagree.
  const normalized = runner.normalizeSubmission(submission, pb);
  const flat = submission.observations || null;

  // Absent and present-but-uncaptured (captured:false plus a reason) stay separate:
  // conflating them tells the operator to add an artifact that is already there.
  const missingRequired = requiredArtifacts.filter(id => !(normalized.artifacts && normalized.artifacts[id]));
  const uncapturedRequired = requiredArtifacts.filter(id => {
    const a = normalized.artifacts && normalized.artifacts[id];
    return a && !a.captured;
  });

  const unknownArtifactKeys = Object.keys(normalized.artifacts || {})
    .filter(k => !knownArtifacts.has(k));
  const unknownSignalKeys = Object.keys(normalized.signal_overrides || {})
    .filter(k => !knownIndicators.has(k));
  const unknownObservationKeys = flat
    ? Object.keys(flat).filter(k => {
        // An explicit `artifact:` indirection is valid whatever the key is.
        const v = flat[k];
        if (v && typeof v === "object" && v.artifact) return false;
        return !knownArtifacts.has(k) && !knownIndicators.has(k) && !knownPreconditions.has(k);
      })
    : [];

  const unsuppliedPreconditions = [...knownPreconditions].filter(
    p => !(((submission.precondition_checks || {}).hasOwnProperty(p)) || ((normalized.precondition_checks || {}).hasOwnProperty(p)))
  );

  // Both shapes are checked: every collector emits the nested `precondition_checks`,
  // so checking only flat `observations` hides precondition-id drift on collect→lint.
  const unknownPreconditionKeys = [...new Set([
    ...Object.keys(submission.precondition_checks || {}),
    ...Object.keys(normalized.precondition_checks || {}),
  ])].filter(k => !knownPreconditions.has(k));

  const issues = [];
  // warn, not error: the runner accepts a submission missing required artifacts and
  // marks those indicators inconclusive, so failing here outstrips the real run.
  for (const id of missingRequired) {
    issues.push({ severity: "warn", kind: "missing_required_artifact", artifact_id: id, hint: `Add to submission.artifacts.${id} = { value, captured: true } (or under observations in the flat shape). The run will still execute without this; the corresponding indicators will return 'inconclusive'.` });
  }
  for (const id of uncapturedRequired) {
    const a = normalized.artifacts[id];
    const reason = a && typeof a.reason === "string" ? a.reason : null;
    issues.push({ severity: "warn", kind: "uncaptured_required_artifact", artifact_id: id, captured: false, ...(reason ? { reason } : {}), hint: `Artifact "${id}" is present but captured:false${reason ? ` (${reason})` : ""} — it is NOT missing; nothing to add. Its indicators will return 'inconclusive'. Common when a collector intentionally skips a platform-specific probe (e.g. POSIX mode bits on Windows).` });
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
  for (const k of unknownPreconditionKeys) {
    const recognized = [...knownPreconditions];
    issues.push({
      severity: "warn",
      kind: "unknown_precondition_key",
      precondition_id: k,
      hint: `Not in playbook ${playbookId} _meta.preconditions[].${recognized.length ? ` Recognized: ${recognized.slice(0, 10).join(", ")}.` : " This playbook declares no preconditions."} A collector emitting a foreign precondition id (e.g. the crypto collector attesting \`linux-platform\`, which belongs to kernel/runtime/hardening) means the attestation will not satisfy any real gate.`,
    });
  }
  for (const k of unknownObservationKeys) {
    issues.push({ severity: "warn", kind: "unknown_observation_key", key: k });
  }

  // Empty post-normalize signal_overrides with no verdict.classification means
  // detect() returns inconclusive; say so before the run.
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
  } else {
    // Nested shape, same trapdoor: detect() drives hit/miss off signal_overrides
    // or a verdict override, never off artifact presence.
    const verdictClass = submission.verdict?.classification;
    const verdictWillDrive = verdictClass === "clean" || verdictClass === "not_detected" || verdictClass === "detected" || verdictClass === "inconclusive";
    const normalizedHasOverrides = Object.keys(normalized.signal_overrides || {}).length > 0;
    const submissionHasArtifacts = Object.keys(submission.artifacts || {}).length > 0;
    if (submissionHasArtifacts && !verdictWillDrive && !normalizedHasOverrides) {
      const someIndicatorIds = [...knownIndicators].slice(0, 3).join('", "');
      issues.push({
        severity: "info",
        kind: "no_signal_overrides_supplied",
        hint: `Nested submission has artifacts but no signal_overrides — every indicator will return 'inconclusive' (verdict will be 'inconclusive', not 'detected' / 'not_detected'). To drive a concrete verdict, populate \`signal_overrides\` with the indicators you investigated: { "${someIndicatorIds}": "hit"|"miss" }. ${knownIndicators.size} indicator(s) known — see \`exceptd brief ${playbookId}\` for the full list. Alternatively, supply \`verdict.classification = "clean"|"not_detected"|"detected"\` to bypass indicator evaluation.`,
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
  if (!ok) process.exitCode = EXIT_CODES.GENERIC_FAILURE;
}

function cmdBrief(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  // Only an OMITTED flag is null: `--phase ""` keeps its empty string so the
  // accepted-set check refuses it rather than reading "no filter".
  const onlyPhase = args.phase === undefined ? null : args.phase;

  if (onlyPhase != null) {
    const ACCEPTED_PHASES = ["govern", "direct", "look"];
    if (!ACCEPTED_PHASES.includes(onlyPhase)) {
      const dym = suggestFlag(String(onlyPhase), ACCEPTED_PHASES);
      const hint = dym ? ` Did you mean "${dym}"?` : '';
      return emitError(
        `brief: --phase "${onlyPhase}" not in accepted set ${JSON.stringify(ACCEPTED_PHASES)}.${hint}`,
        { verb: "brief", provided: onlyPhase, accepted: ACCEPTED_PHASES, did_you_mean: dym ? [dym] : [] },
        pretty,
      );
    }
  }

  if (!playbookId || args.all) {
    return cmdPlan(runner, args, runOpts, pretty);
  }

  if (refuseInvalidPlaybookId("brief", playbookId, pretty)) return;
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);

  const govern = runner.govern(playbookId, directiveId, runOpts);
  const direct = runner.direct(playbookId, directiveId);
  const look = runner.look(playbookId, directiveId, runOpts);

  if (onlyPhase === "govern") return emit(govern, pretty);
  if (onlyPhase === "direct") return emit(direct, pretty);
  if (onlyPhase === "look") return emit(look, pretty);

  emit({
    verb: "brief",
    playbook_id: playbookId,
    directive_id: directiveId,
    scope: pb._meta?.scope || null,
    threat_currency_score: pb._meta?.threat_currency_score,

    jurisdiction_obligations: govern.jurisdiction_obligations,
    theater_fingerprints: govern.theater_fingerprints,
    framework_context: govern.framework_context,
    skill_preload: govern.skill_preload,

    threat_context: direct.threat_context,
    rwep_threshold: direct.rwep_threshold,
    framework_lag_declaration: direct.framework_lag_declaration,
    skill_chain: direct.skill_chain,
    token_budget: direct.token_budget,

    preconditions: look.preconditions,
    precondition_submission_shape: look.precondition_submission_shape,
    artifacts: look.artifacts,
    collection_scope: look.collection_scope,
    environment_assumptions: look.environment_assumptions,
    fallback_if_unavailable: look.fallback_if_unavailable,

    detect_indicators_preview: (pb.phases?.detect?.indicators || []).map(i => ({
      id: i.id, type: i.type, confidence: i.confidence, deterministic: !!i.deterministic
    })),
  }, pretty, (obj) => {
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
    if (optional.length) lines.push(`Optional artifacts (${optional.length}): ${optional.map(a => a.id).slice(0, 8).join(", ")}${optional.length > 8 ? `, … +${optional.length - 8}` : ""}`);
    const indicators = obj.detect_indicators_preview || [];
    lines.push(`\nIndicators (${indicators.length}): ${indicators.map(i => i.id).slice(0, 8).join(", ")}${indicators.length > 8 ? `, … +${indicators.length - 8}` : ""}`);
    if (obj.preconditions?.length) {
      lines.push(`\nPreconditions (${obj.preconditions.length}):`);
      for (const p of obj.preconditions) {
        const pdesc = p.description || p.check || "";
        lines.push(`  ${p.id} (${p.on_fail}): ${pdesc.length > 80 ? pdesc.slice(0, 80) + "…" : pdesc}`);
      }
    }
    lines.push(`\nCollect evidence: exceptd collect ${obj.playbook_id} | exceptd run ${obj.playbook_id} --evidence -`);
    lines.push(`Run with your own evidence: exceptd run ${obj.playbook_id} --evidence <file|-> --json`);
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
  // An empty --playbook falls through the truthy gate below as null and plans
  // across ALL playbooks.
  if (args.playbook === "" || (Array.isArray(args.playbook) && args.playbook.some(p => p === ""))) {
    return emitError("plan: --playbook was given an empty value; pass a playbook id, or omit --playbook to plan across all.", { verb: "plan", flag: "playbook" }, pretty);
  }
  let playbookIds = args.playbook
    ? (Array.isArray(args.playbook) ? args.playbook : [args.playbook])
    : null;
  if (!playbookIds && args.scope) {
    playbookIds = filterPlaybooksByScope(runner, args.scope);
  }
  const plan = runner.plan({
    playbookIds: playbookIds || undefined,
    mode: runOpts.mode,
    session_id: runOpts.session_id,
  });
  // Grouped by scope unless --flat or a filter was applied.
  if (!args.flat && !playbookIds) {
    plan.grouped_by_scope = groupPlaybooksByScope(plan.playbooks);
    plan.scope_summary = Object.fromEntries(
      Object.entries(plan.grouped_by_scope).map(([s, list]) => [s, list.length])
    );
  }
  // --directives expands each entry. The description falls back d.description →
  // directive threat_context override → first threat_context sentence →
  // domain.name, so an entry always carries prose, not just an id and an enum.
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
  emit(plan, pretty, (obj) => {
    const lines = [];
    const summary = obj.scope_summary || {};
    const totalScope = Object.values(summary).reduce((a, b) => a + b, 0);
    const total = obj.playbooks?.length || 0;
    lines.push(`brief: ${total} playbook(s)  session-id: ${obj.session_id}`);
    if (totalScope > 0) {
      const scopeLine = Object.entries(summary).map(([s, n]) => `${s}=${n}`).join("  ");
      lines.push(`  ${scopeLine}`);
    }
    lines.push("");

    // grouped_by_scope holds ids only, so name and score come from the flat list.
    const byId = {};
    for (const pb of obj.playbooks || []) {
      if (pb && pb.id) byId[pb.id] = pb;
    }
    const renderDirectives = (pb) => {
      const dirs = pb && Array.isArray(pb.directives) ? pb.directives : null;
      if (!dirs || !dirs.length) return;
      for (const d of dirs) {
        const title = d.title || d.id || "?";
        const truncTitle = title.length > 80 ? title.slice(0, 77) + "..." : title;
        lines.push(`      → ${(d.id || "?").padEnd(48)}  ${truncTitle}`);
        if (d.threat_context_preview) {
          const ctx = d.threat_context_preview;
          const truncCtx = ctx.length > 140 ? ctx.slice(0, 137) + "..." : ctx;
          lines.push(`        ${truncCtx}`);
        }
      }
    };

    const grouped = obj.grouped_by_scope;
    if (grouped) {
      const scopeOrder = ["code", "system", "service", "cross-cutting"];
      const otherScopes = Object.keys(grouped).filter(s => !scopeOrder.includes(s));
      for (const scope of [...scopeOrder, ...otherScopes]) {
        const list = grouped[scope];
        if (!list || !list.length) continue;
        lines.push(`[${scope}]  (${list.length})`);
        for (const id of list) {
          const pb = byId[id] || {};
          const tcs = pb.threat_currency_score != null ? ` tcs=${pb.threat_currency_score}` : "";
          const dom = pb.domain?.name || "";
          const truncDom = dom.length > 80 ? dom.slice(0, 77) + "..." : dom;
          lines.push(`  ${(id || "?").padEnd(28)}${tcs.padEnd(8)}  ${truncDom}`);
          renderDirectives(pb);
        }
        lines.push("");
      }
    } else {
      for (const pb of obj.playbooks || []) {
        const tcs = pb.threat_currency_score != null ? ` tcs=${pb.threat_currency_score}` : "";
        const sc = pb.scope ? `[${pb.scope}]` : "[?]";
        const dom = pb.domain?.name || "";
        const truncDom = dom.length > 80 ? dom.slice(0, 77) + "..." : dom;
        lines.push(`  ${sc.padEnd(16)} ${(pb.id || "?").padEnd(28)}${tcs.padEnd(8)}  ${truncDom}`);
        renderDirectives(pb);
      }
      lines.push("");
    }

    lines.push(`Next:`);
    lines.push(`  exceptd brief <playbook>          # full info doc (jurisdictions + threat + indicators + artifacts)`);
    lines.push(`  exceptd discover                  # cwd-aware playbook recommendations`);
    lines.push(`  exceptd ci --scope <type>         # gate a cwd against every playbook in <type>`);
    lines.push(`\nFull structured result: --json (or --pretty for indented JSON).`);
    return lines.join("\n");
  });
}

// An unknown scope must throw, not filter to []: `run --scope nonsense` would exit 0
// having run nothing, and `ci --scope nonsense` PASS on the cross-cutting set alone.
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
 * Guards every operator-controlled loadPlaybook() call. Emits the error itself and
 * returns true when the id is bad, false when the caller may proceed.
 */
function refuseInvalidPlaybookId(verb, playbookId, pretty) {
  const r = validateIdComponent(playbookId, "playbook");
  if (!r.ok) {
    // A case-only typo (`run SECRETS`) fails the lowercase id regex before the
    // fuzzy did-you-mean path runs, so it is suggested here.
    let suggestion = null;
    if (typeof playbookId === "string") {
      const lowered = playbookId.toLowerCase();
      if (lowered !== playbookId && validateIdComponent(lowered, "playbook").ok) {
        try {
          if (fs.existsSync(path.join(PKG_ROOT, "data", "playbooks", `${lowered}.json`))) suggestion = lowered;
        } catch { /* fall back to no suggestion */ }
      }
    }
    emitError(
      `${verb}: invalid <playbook> id — ${r.reason}.${suggestion ? ` Did you mean: ${suggestion}?` : ""}`,
      {
        verb,
        provided: typeof playbookId === "string" ? playbookId.slice(0, 80) : typeof playbookId,
        ...(suggestion ? { did_you_mean: [suggestion] } : {}),
      },
      pretty
    );
    return true;
  }
  return false;
}

/** The one "playbook has no directives" refusal; several verbs call it. */
function refuseNoDirectives(verb, playbookId, pretty) {
  return emitError(
    `${verb}: playbook ${playbookId} has no directives. Inspect the playbook with \`exceptd brief ${playbookId}\` or report at https://github.com/blamejs/exceptd-skills/issues.`,
    { verb, playbook: playbookId },
    pretty
  );
}

// Playbooks whose halt-preconditions are operator-attested booleans no CI gate can
// infer; including them halts `ci --all` at preflight. `framework` stays out — it is
// analyze-only and its one precondition is on_fail:warn. So does
// `cicd-pipeline-compromise`: its ownership halt is opt-in via the collector, and
// evidence-dir consumers supply the precondition.
const POLICY_SKIPPED_PLAYBOOKS = new Set([
  "ai-discovered-cve-triage",
  "audit-log-integrity",
  "decompression-dos",
  "cloud-iam-incident",
  "idp-incident",
  "identity-sso-compromise",
  "llm-tool-use-exfil",
  "log-injection-telemetry",
  "mail-server-hardening",
  "multitenancy-isolation",
  "network-trust",
  "post-quantum-migration",
  "privacy-consent-ops",
  "ransomware",
  "self-update-integrity",
  "supply-chain-recovery",
  "vc-wallet-trust",
  "webhook-callback-abuse",
]);

function filterPlaybooksByScope(runner, scope, opts = {}) {
  validateScopeOrThrow(scope);
  const ids = runner.listPlaybooks();
  const includeJudgementShaped = opts.includeJudgementShaped === true;
  return ids.filter(id => {
    try {
      const pb = runner.loadPlaybook(id);
      if (scope !== "all" && pb._meta.scope !== scope) return false;
      // --include-judgement-shaped opts the attestation-required set back in.
      if (!includeJudgementShaped && POLICY_SKIPPED_PLAYBOOKS.has(id)) return false;
      return true;
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
 * Scopes applying to the cwd: `code` for a git repo, `system` for a Linux host,
 * else `['cross-cutting']` so framework correlation always runs. `service` is never
 * auto-detected — those playbooks probe remote endpoints and need an explicit call.
 */
function detectScopes() {
  const detected = [];
  if (fs.existsSync(path.join(process.cwd(), ".git"))) detected.push("code");
  if (fs.existsSync("/proc") && fs.existsSync("/etc/os-release")) detected.push("system");
  return detected.length ? detected : ["cross-cutting"];
}

function cmdRun(runner, args, runOpts, pretty) {
  const positional = args._[0];

  // Multi-playbook dispatch: --all, --scope <type>, or a bare `exceptd run` that
  // auto-detects from the cwd. Gated on `!== undefined`: a truthy gate lets
  // `--scope ""` fall through to auto-detect instead of validateScopeOrThrow.
  if (!positional && (args.all || args.scope !== undefined)) {
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    let ids;
    if (args.all) {
      ids = runner.listPlaybooks().filter(id =>
        includeJudgementShaped || !POLICY_SKIPPED_PLAYBOOKS.has(id)
      );
    } else {
      try { ids = filterPlaybooksByScope(runner, args.scope, { includeJudgementShaped }); }
      catch (e) { return emitError(`run: ${e.message}`, { provided_scope: args.scope }, pretty); }
    }
    return cmdRunMulti(runner, ids, args, runOpts, pretty, { trigger: args.all ? "--all" : `--scope ${args.scope}` });
  }
  if (!positional && !args.all && args.scope === undefined) {
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    const scopes = detectScopes();
    const ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s, { includeJudgementShaped }));
    const unique = [...new Set(ids)];
    if (unique.length === 0) {
      // Mirrors detectScopes()' two probes so the message names WHY nothing
      // resolved; both must stay in step with that function.
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

  const playbookId = positional;
  if (refuseInvalidPlaybookId("run", playbookId, pretty)) return;
  // Only cmdRunMulti reads --evidence-dir; accepting it on a single playbook
  // would run EMPTY evidence and report a clean "not_detected".
  if (args["evidence-dir"]) {
    return emitError(
      `run ${playbookId}: --evidence-dir applies to contract runs (exceptd run --all / --scope <type>), where it reads one <playbook-id>.json per playbook. For a single playbook, pass its evidence directly: exceptd collect ${playbookId} | exceptd run ${playbookId} --evidence -  (or --evidence ${playbookId}.json).`,
      { playbook: playbookId, provided: "--evidence-dir", use_instead: "--evidence <file|->" },
      pretty
    );
  }
  const pb = runner.loadPlaybook(playbookId);
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) return refuseNoDirectives("run", playbookId, pretty);

  // --explain is a dry run: emits what the agent must supply, no phases 4-7.
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
  // Piped stdin is promoted to `--evidence -`. The probe must be hasReadableStdin(),
  // not a bare `!isTTY`: that fires on isTTY === undefined and blocks forever on a
  // wrapped stream. `--evidence ""` is falsy and would run as no-evidence at exit 0.
  if (args.evidence === "") {
    return emitError("run: --evidence was given an empty value; pass a file path, '-' for stdin, or omit --evidence for a no-evidence run", { verb: "run" }, pretty);
  }
  const autoStdin = !args.evidence && hasReadableStdin();
  if (autoStdin) {
    args.evidence = "-";
  }
  if (args.evidence) {
    try {
      // explicit:false suppresses the empty-stdin nudge on the auto-promotion path,
      // which otherwise breaks `run ... 2>&1 | jq` on every no-evidence CI run.
      submission = readEvidence(args.evidence, { explicit: !autoStdin });
    } catch (e) {
      return emitError(`run: failed to read evidence: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }

  // precondition_checks stay OUT of runOpts: run() derives them from the submission,
  // and copying them in reports every one as provenance "merged", not "submission".

  // --format overrides the playbook's evidence_package.bundle_format; repeating it
  // produces several bundles under bundles_by_format.
  if (args.format) {
    // "csaf" is the shortcut for the runner's canonical "csaf-2.0" key. An
    // unrecognised format is rejected after the run, so the run still completes.
    const formats = (Array.isArray(args.format) ? args.format : [args.format])
      .map(f => f === "csaf" ? "csaf-2.0" : f);
    submission.signals = submission.signals || {};
    submission.signals._bundle_formats = formats;
  }

  // --vex <file>: pass the not_affected CVE ID set to analyze() so matched_cves
  // drops them.
  if (args.vex) {
    let vexDoc;
    // Matches readEvidence()'s cap; uncapped, a multi-GB file OOMs the process.
    const MAX_VEX_BYTES = 32 * 1024 * 1024;
    let vstat;
    try { vstat = fs.statSync(args.vex); }
    catch (e) {
      return emitError(`run: failed to stat --vex ${args.vex}: ${e.message}`, null, pretty);
    }
    if (vstat.size > MAX_VEX_BYTES) {
      // The message says MiB and prints the bytes, so the cap can't read as 32e6.
      return emitError(
        `run: --vex file too large: ${vstat.size} bytes exceeds 32 MiB limit (${MAX_VEX_BYTES.toLocaleString("en-US")} bytes). Reduce the document or split into multiple passes.`,
        { provided_path: args.vex, size_bytes: vstat.size, limit_bytes: MAX_VEX_BYTES },
        pretty
      );
    }
    try {
      vexDoc = readJsonFile(args.vex);
    } catch (e) {
      return emitError(`run: failed to load --vex ${args.vex}: ${e.message}`, null, pretty);
    }
    // Shape-checked BEFORE vexFilterFromDoc, which returns Set(0) for anything it
    // doesn't recognise — a mistaken SARIF or CSAF would filter nothing, silently.
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
      // vexFilterFromDoc hangs a `.fixed` Set off the returned Set; forwarding it is
      // what makes CSAF product_status.fixed and OpenVEX status:'fixed' reach it.
      submission.signals.vex_fixed = vexSet.fixed ? [...vexSet.fixed] : [];
    } catch (e) {
      return emitError(`run: failed to apply --vex ${args.vex}: ${e.message}`, null, pretty);
    }
  }

  // --upstream-check queries npm before detect to warn when the local catalog is
  // behind. Opt-in, bounded by an 8s timeout.
  let upstreamCheck = null;
  if (args["upstream-check"]) {
    // The helper has no air-gap awareness of its own, so the refusal lives here.
    // A playbook declaring _meta.air_gap_mode refuses egress without the flag too.
    if (runOpts.airGap || process.env.EXCEPTD_AIR_GAP === "1" || pb._meta?.air_gap_mode) {
      upstreamCheck = {
        ok: false,
        source: "air-gap",
        air_gap_blocked: true,
        skipped_reason: "--upstream-check would query the npm registry; refused under --air-gap.",
      };
    } else {
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
  }

  const result = runner.run(playbookId, directiveId, submission, runOpts);
  if (result && upstreamCheck) result.upstream_check = upstreamCheck;

  // Hoisted to the envelope top so a consumer sees the air-gap disposition
  // without descending into phases.govern.
  if (result) {
    result.air_gap_mode = !!(pb._meta?.air_gap_mode || runOpts.airGap);
  }

  if (result && runOpts.operator) result.operator = runOpts.operator;

  // Consent is persisted ONLY on classification=detected, when a jurisdiction clock
  // actually starts: acknowledging a clock that never started is a false audit
  // trail. The run body reports the ack state either way.
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

  if (result && result.ok && result.session_id) {
    const persistResult = persistAttestation({
      sessionId: result.session_id,
      playbookId: result.playbook_id,
      directiveId: result.directive_id,
      evidenceHash: result.evidence_hash,
      operator: runOpts.operator,
      operatorConsent: consentApplies ? runOpts.operator_consent : null,
      submission,
      runOpts,
      forceOverwrite: !!args["force-overwrite"],
      filename: "attestation.json",
    });
    if (!persistResult.ok) {
      // Three distinct exit codes, because the caller's remediation differs.
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
      // A force-overwrite happened; the id names what this attestation replaced.
      result.prior_session_id = persistResult.prior_session_id;
      result.overwrote_at = persistResult.overwrote_at;
    }
    // Echoed by the renderer, so the attest verify / diff hint names a real file.
    if (persistResult.attestation_path) {
      result.attestation_path = persistResult.attestation_path;
    }
  }

  if (result && result.ok === false) {
    // `run --ci` and `ci` agree on 4 (BLOCKED) for a preflight halt. Assigned BEFORE
    // emit(), whose ok:false fallback only fires on an unset exitCode.
    process.exitCode = args.ci ? EXIT_CODES.BLOCKED : EXIT_CODES.GENERIC_FAILURE;
    emit(result, pretty, (obj) => {
      const v = obj.verdict || "error";
      const tag = v === "blocked" ? "[blocked]" : "[error]";
      const lines = [`${tag}  ${obj.playbook_id || "run"}${obj.directive_id ? ` (${obj.directive_id})` : ""}`];
      // summary_line is already a complete sentence; reason is the fallback.
      const detail = obj.summary_line || obj.reason;
      if (detail) lines.push(`  ${detail}`);
      // The engine's remediation wins, else a hint from blocked_by — each names a live verb.
      if (obj.remediation) {
        lines.push(`  → ${obj.remediation}`);
      } else {
        const hints = {
          precondition: "→ A required precondition is unmet — the reason above names the specific gate. It may be a platform mismatch, OR an attestation/evidence the run needs (submit it in your evidence JSON's precondition_checks). For a platform mismatch, list applicable playbooks: exceptd brief --all",
          mutex: "→ Another run holds this playbook's mutex. Wait for it to finish, then retry.",
          currency: "→ Threat intel is stale. Refresh sources (exceptd refresh) or re-run with --force-stale to override.",
          catalog_corrupt: "→ The CVE catalog failed to load. Reinstall the package or run: exceptd doctor",
          playbook_not_found: "→ Unknown playbook. List available playbooks: exceptd brief --all",
          directive_not_found: `→ Unknown directive for this playbook. See its directives: exceptd brief ${obj.playbook_id || "<playbook>"}`,
        };
        if (obj.blocked_by && hints[obj.blocked_by]) lines.push(`  ${hints[obj.blocked_by]}`);
      }
      lines.push("  Full envelope: re-run with --json");
      return lines.join("\n");
    });
    return;
  }

  // --strict-preconditions escalates warn-level preflight issues to exit 1.
  if (args["strict-preconditions"] && result && Array.isArray(result.preflight_issues)) {
    // precondition_skip MUST stay in this filter: a false skip_phase precondition
    // means detect never ran, and omitting it passes the gate at verdict:skipped.
    const warnIssues = result.preflight_issues.filter(i =>
      i.kind === "precondition_unverified" || i.kind === "precondition_warn" || i.kind === "precondition_skip"
    );
    if (warnIssues.length > 0) {
      // result.ok stays true — the playbook did execute — so the body names it.
      result.strict_preconditions_violated = warnIssues.map(i => ({
        id: i.id, kind: i.kind, message: i.message || null, on_fail: i.on_fail || null,
      }));
      process.stderr.write(`[exceptd run] --strict-preconditions: ${warnIssues.length} unverified/warn precondition(s) — exit ${EXIT_CODES.GENERIC_FAILURE}.\n`);
      emit(result, pretty);
      // `process.exitCode`, not `process.exit()` — a piped write can be truncated.
      process.exitCode = EXIT_CODES.GENERIC_FAILURE;
      return;
    }
  }

  // This attestation is already persisted, so the lookup excludes its session_id.
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

  // Any started, unacked clock in close.notification_actions exits 5, naming the
  // obligations on stderr. Same semantics as cmdCi.
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

  // --ci gates on the detect classification, the host-specific signal. rwep.base is
  // the domain's worst-known catalog score and barely moves with the environment:
  // failing on it alone perma-fails every run against a KEV-holding domain.
  if (args.ci && result && result.phases) {
    const classification = result.phases.detect && result.phases.detect.classification;
    const rwep = result.phases.analyze && result.phases.analyze.rwep;
    const threshold = rwep && rwep.threshold && rwep.threshold.escalate;
    const adjusted = rwep && typeof rwep.adjusted === "number" ? rwep.adjusted : 0;
    const escalate = typeof threshold === "number" && adjusted >= threshold;

    emit(result, pretty);

    // `process.exitCode`, not `process.exit()` — emit() just wrote to stdout.
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

  // --format transforms the top-level output; omitted, the full JSON result stands.
  if (args.format) {
    const requestedAll = Array.isArray(args.format) ? args.format : [args.format];
    const requested = requestedAll[0];
    const VALID = ["summary", "markdown", "csaf-2.0", "csaf", "sarif", "openvex", "json"];
    if (!VALID.includes(requested)) {
      const dym = suggestFlag(String(requested), VALID);
      const hint = dym ? ` Did you mean "${dym}"?` : '';
      return emitError(
        `run: --format "${requested}" not in accepted set ${JSON.stringify(VALID)}.${hint}`,
        { verb: "run", provided: requested, accepted: VALID, did_you_mean: dym ? [dym] : [] },
        pretty,
      );
    }
    // --format wins over --json, and says so: a script piping for JSON that adds
    // --format markdown would otherwise get non-JSON with no signal.
    if ((args.json || global.__exceptdWantJson) && requested !== "json") {
      process.stderr.write(
        `[exceptd] note: --format "${requested}" overrides --json; stdout is the ${requested} document, not the JSON envelope.\n`
      );
    }
    // Only one document goes to stdout; the extras are named, not dropped silently.
    if (requestedAll.length > 1) {
      process.stderr.write(
        `[exceptd] note: ${requestedAll.length} --format values given; emitting "${requested}" to stdout. ` +
        `All requested bundles are embedded under phases.close.evidence_package.bundles_by_format — ` +
        `re-run with --json to see them.\n`
      );
    }
    // `json` is the full run result. Falling through to the bundle lookup finds the
    // runner's unknown-format stub under bundles_by_format.json and emits that.
    if (requested === "json") {
      emit(result, pretty);
      return;
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
    const formatNorm = requested === "csaf" ? "csaf-2.0" : requested;
    const bbf = result.phases?.close?.evidence_package?.bundles_by_format || {};
    const body = bbf[formatNorm] || result.phases?.close?.evidence_package?.bundle_body;
    if (body) {
      // Written verbatim, NOT through emit(): `ok` is not a permitted top-level
      // property in the SARIF, CSAF or OpenVEX schemas, and a strict validator
      // rejects it. `exceptd_extension` stays — a legal CSAF vendor extension.
      const { ok: _ok, ...spec } = body;
      process.stdout.write(JSON.stringify(spec, null, pretty ? 2 : 0) + "\n");
      return;
    }
  }

  emit(result, pretty, (obj) => {
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
    // "Ran every indicator and found nothing" and "could not evaluate" look
    // identical without this line. Decisive and inconclusive counts split for the
    // same reason: an all-inconclusive run is complete by count but decided nothing.
    if (obj.evidence_completeness && obj.indicators_known != null) {
      const ev = obj.evidence_completeness;
      const ke = obj.indicators_evaluated ?? 0;
      const kn = obj.indicators_known;
      const indicators = obj.phases?.detect?.indicators || [];
      const decisive = indicators.filter(i => i.verdict === "hit" || i.verdict === "miss").length;
      const inconclusive = indicators.filter(i => i.verdict === "inconclusive").length;
      const hasInconclusiveSubset = inconclusive > 0 && decisive > 0 && cls === "inconclusive";
      if (hasInconclusiveSubset) {
        lines.push(`  evidence: ${ev}  (${decisive}/${kn} decisive, ${inconclusive} inconclusive — add signal_overrides to drive a verdict)`);
      } else {
        lines.push(`  evidence: ${ev}  (${ke}/${kn} indicators evaluated)`);
      }
      if (ev === "missing" || ev === "partial") {
        lines.push(`  → next: exceptd lint ${obj.playbook_id} -    # paste {} on stdin, see exact JSON paths to populate`);
      }
    }
    // The marker text of these three lines is grep-matched by
    // tests/audit-i-l-m-fixes.test.js. The no-prior line matters as much as the
    // others: without it a fresh attestation dir prints nothing at all.
    if (obj.diff_from_latest) {
      const dfl = obj.diff_from_latest;
      if (dfl.status === "unchanged") {
        lines.push(`> drift vs prior: unchanged (same evidence_hash as session ${dfl.prior_session_id})`);
      } else if (dfl.status === "drifted") {
        lines.push(`> drift vs prior: DRIFTED — evidence_hash differs from session ${dfl.prior_session_id}`);
      } else if (dfl.status === "no_prior_attestation_for_playbook") {
        lines.push(`> drift vs prior: no prior attestation found for ${dfl.playbook_id || obj.playbook_id} — this run becomes the baseline`);
      }
    }
    // --upstream-check fired a network call; the operator who asked "am I current?"
    // gets a one-line answer without grepping the JSON envelope.
    if (obj.upstream_check) {
      const u = obj.upstream_check;
      if (u.same) {
        lines.push(`> upstream check: local v${u.local_version} == published v${u.latest_version} (current)`);
      } else if (u.behind) {
        const days = u.days_since_latest_publish != null ? `${u.days_since_latest_publish}d behind` : "behind";
        lines.push(`> upstream check: local v${u.local_version} BEHIND published v${u.latest_version} (${days}) — run \`npm install -g @blamejs/exceptd-skills@latest\``);
      } else if (u.ahead) {
        lines.push(`> upstream check: local v${u.local_version} ahead of published v${u.latest_version} (unreleased / dev install)`);
      } else if (!u.ok) {
        lines.push(`> upstream check: skipped (${u.reason || u.hint || "registry unreachable"})`);
      }
    }
    const cves = obj.phases?.analyze?.matched_cves || [];
    const baseline = obj.phases?.analyze?.catalog_baseline_cves || [];
    if (cves.length) {
      lines.push(`\nMatched CVEs (${cves.length}):`);
      for (const c of cves.slice(0, 6)) {
        const via = Array.isArray(c.correlated_via) && c.correlated_via.length ? `  via ${c.correlated_via[0]}${c.correlated_via.length > 1 ? ` (+${c.correlated_via.length - 1})` : ""}` : "";
        lines.push(`  ${c.cve_id}  RWEP ${c.rwep}  KEV=${c.cisa_kev ? "Y" : "N"}  ${c.active_exploitation || ""}${via}`);
      }
      if (cves.length > 6) lines.push(`  … ${cves.length - 6} more`);
    } else if (baseline.length) {
      // Nothing correlated: naming the zero keeps the catalog enumeration from
      // reading as a hit list the operator is affected by.
      lines.push(`\nNo CVEs correlated to your evidence. Playbook catalog (informational): ${baseline.length} CVE(s) this playbook scans for.`);
    }
    const indicators = obj.phases?.detect?.indicators || [];
    const hits = indicators.filter(i => i.verdict === "hit");
    if (hits.length) {
      lines.push(`\nIndicators that fired (${hits.length}):`);
      for (const i of hits.slice(0, 8)) {
        // Avoids printing "deterministic/deterministic".
        const detSuffix = (i.deterministic && i.confidence !== "deterministic") ? "/deterministic" : "";
        lines.push(`  ${i.id}  (${i.confidence}${detSuffix})`);
      }
      if (hits.length > 8) lines.push(`  … ${hits.length - 8} more`);
    }
    // validate() picks a remediation path even on a not_detected run, so the label
    // is conditional: "Recommended remediation" would read as action required.
    const rem = obj.phases?.validate?.selected_remediation;
    if (rem) {
      if (cls === "detected") {
        lines.push(`\nRecommended remediation: ${rem.id} (priority ${rem.priority})`);
      } else {
        lines.push(`\nRemediation path (informational — verdict=${cls}, no action required now): ${rem.id} (priority ${rem.priority})`);
      }
      const remDesc = rem.description || "";
      lines.push(`  ${remDesc.length > 200 ? remDesc.slice(0, 200) + "… (full steps: --json)" : remDesc}`);
    }
    // Both started and pending clocks show on a detected run: the pending ones are
    // what the operator needs before taking the action that starts them.
    const allNotif = obj.phases?.close?.notification_actions || [];
    const startedNotif = allNotif.filter(n => n.clock_started_at);
    const pendingNotif = allNotif.filter(n => !n.clock_started_at);
    if (startedNotif.length) {
      lines.push(`\nNotification clocks started (${startedNotif.length}):`);
      for (const n of startedNotif) lines.push(`  ${n.obligation_ref} → deadline ${n.deadline}`);
    }
    if (pendingNotif.length && cls === "detected") {
      lines.push(`\nPending jurisdiction obligations (${pendingNotif.length}) — clock starts on operator action:`);
      // Grouped by clock_start_event: one line per event class, not per regulation.
      const byEvent = {};
      for (const n of pendingNotif) {
        const ev = n.clock_start_event || "unspecified";
        if (!byEvent[ev]) byEvent[ev] = [];
        byEvent[ev].push(`${n.jurisdiction || "?"}/${n.regulation || "?"} (${n.window_hours || "?"}h)`);
      }
      for (const [ev, refs] of Object.entries(byEvent)) {
        lines.push(`  on ${ev}:  ${refs.join(", ")}`);
      }
      lines.push(`  → next: exceptd run ${obj.playbook_id} --evidence <file> --format csaf-2.0    # generate the draft advisory + notification bodies`);
    }
    const feeds = obj.phases?.close?.feeds_into || [];
    if (feeds.length) lines.push(`\nNext playbooks suggested: ${feeds.join(", ")}`);

    // The attestation path is cwd-tagged (~/.exceptd/attestations/<repo>@<branch>/),
    // so `attest verify <sid>` from another cwd fails with "no session dir".
    if (obj.attestation_path) {
      lines.push(`\nAttestation written: ${obj.attestation_path}`);
      lines.push(`  exceptd attest verify ${obj.session_id}     # tamper check`);
      lines.push(`  exceptd attest diff ${obj.session_id}       # vs. most-recent prior for this playbook`);
    }
    const issues = obj.preflight_issues || [];
    if (issues.length) {
      lines.push(`\nPreflight warnings (${issues.length}):`);
      for (const i of issues) {
        // A playbook may omit on_fail, so the bracket is conditional.
        const tag = i.on_fail ? `[${i.on_fail}] ` : "";
        // precondition_warn issues carry their text in `message`, so it stays here.
        const detail = i.check || i.description || i.reason || i.message || "(no detail)";
        lines.push(`  ${tag}${i.id}: ${detail}`);
      }
    }
    // Without this, a malformed submission completes with an [ok] verdict and the
    // reason sits only in phases.analyze.runtime_errors, invisible at the terminal.
    const runtimeErrors = obj.phases?.analyze?.runtime_errors || [];
    if (runtimeErrors.length) {
      lines.push(`\nRuntime warnings (${runtimeErrors.length}):`);
      for (const e of runtimeErrors) {
        // Some kinds carry no `reason`, only context fields.
        const rawReason = e.reason || [e.component, e.cve_id].filter(Boolean).join(" / ") || "(no detail)";
        const reason = rawReason.length > 180 ? rawReason.slice(0, 177) + "..." : rawReason;
        lines.push(`  [${e.kind || "warning"}] ${reason}`);
        if (e.remediation) lines.push(`    → ${e.remediation}`);
      }
    }
    // A collector skip (a file over the scan-size limit) otherwise reaches only
    // --json, and the render reads "evidence: complete" over an unscanned tree.
    const collectorWarnings = obj.collector_warnings || [];
    if (collectorWarnings.length) {
      lines.push(`\nCollector notices (${collectorWarnings.length}):`);
      for (const w of collectorWarnings) {
        const rawReason = w.reason || w.message || "(no detail)";
        const reason = rawReason.length > 180 ? rawReason.slice(0, 177) + "..." : rawReason;
        lines.push(`  [${w.kind || "notice"}] ${reason}`);
      }
    }
    lines.push(`\nFull structured result: --json (or --pretty for indented).`);
    return lines.join("\n");
  });
}

/**
 * Collapses per-playbook notification_actions into one entry per (jurisdiction,
 * regulation, obligation, window) — the operator owes one notification, not ten.
 * Contributors land in `triggered_by_playbooks[]`; the earliest clock_started_at
 * and deadline win, so what shows is the strictest deadline.
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
        if ((n.clock_started_at || "") < (existing.clock_started_at || "")) {
          existing.clock_started_at = n.clock_started_at;
        }
        if (n.deadline && (!existing.deadline || n.deadline < existing.deadline)) {
          existing.deadline = n.deadline;
        }
      } else {
        // `obligation` and `obligation_ref` carry the same value, since consumers
        // parse either; the dedupe key reads the stub-carried obligation_ref.
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

// The one reader for `--evidence-dir <dir>`, shared by cmdRunMulti and cmdCi: a
// second copy would let one verb's symlink / junction / O_NOFOLLOW / realpath
// defenses drift from the other's. Returns { ok: true, bundle } or { ok: false,
// error, extra } on the first refusal — the caller emits it, and owns the
// directory-exists and empty-string guards.
function readEvidenceDir(dir, verb) {
  const bundle = {};
  const resolvedDir = path.resolve(dir);
  // The base realpath resolves ONCE so the per-entry containment gate compares like
  // for like: under a symlinked ancestor (/var -> /private/var) every
  // `startsWith(resolvedDir)` test would otherwise refuse its own evidence files.
  let realResolvedDir;
  try { realResolvedDir = fs.realpathSync(resolvedDir); }
  catch { realResolvedDir = resolvedDir; }
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
    const pbId = f.replace(/\.json$/, "");
    // The runtime allowlist's validator, so a typo'd filename is refused here
    // rather than rejected by loadPlaybook mid-loop.
    const pbCheck = validateIdComponent(pbId, "playbook");
    if (!pbCheck.ok) {
      return {
        ok: false,
        error: `${verb}: --evidence-dir entry ${JSON.stringify(f)} has invalid playbook-id segment (${pbCheck.reason}).`,
        extra: { entry: f, expected_shape: "<playbook-id>.json (lowercase, starts with letter, no dots)" },
      };
    }
    const entryPath = path.resolve(path.join(resolvedDir, f));
    if (!entryPath.startsWith(resolvedDir + path.sep)) {
      return { ok: false, error: `${verb}: --evidence-dir entry ${f} resolves outside the directory; refusing.`, extra: null };
    }
    // path.resolve only catches `..` in the joined path; a `<pb-id>.json ->
    // /etc/shadow` symlink would still be followed. Open ONE O_NOFOLLOW descriptor
    // first and decide everything about it: stat-then-open leaves a TOCTOU window.
    // O_NOFOLLOW is a no-op on Windows, so the fstat type check plus the lstat and
    // realpath gates below carry the junction defense there.
    let efd;
    try {
      const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
      efd = fs.openSync(entryPath, fs.constants.O_RDONLY | O_NOFOLLOW);
    } catch (e) {
      const why = e.code === "ELOOP"
        ? "symbolic link refused (symlinks bypass the directory-confinement check)"
        : e.message;
      return { ok: false, error: `${verb}: --evidence-dir entry ${f}: open failed: ${why}`, extra: { entry: f } };
    }
    try {
      const st = fs.fstatSync(efd);
      if (!st.isFile()) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f} is not a regular file; refusing (symlink / junction / dir / fifo bypass the directory-confinement check).`, extra: { entry: f } };
      }
      // A warning, not a refusal: a hardlink is indistinguishable from a regular
      // file, and atomic rename and package dedup both produce nlink > 1.
      if (st.nlink > 1) {
        process.stderr.write(`[exceptd ${verb} --evidence-dir] WARNING: ${f} has nlink=${st.nlink}; a hardlink to this file exists elsewhere on the filesystem. Hardlinks cannot be refused cross-platform — confirm the file content is what you expect.\n`);
      }
      // Read from `efd` FIRST: the descriptor is O_NOFOLLOW and fstat-confirmed, so
      // these are the validated inode's bytes. The gates below decide whether to USE
      // them, discarding otherwise, which leaves no check-then-use window.
      const raw = fs.readFileSync(efd, "utf8");
      // O_NOFOLLOW is a no-op on Windows, so a symlink is refused explicitly here.
      let lst;
      try { lst = fs.lstatSync(entryPath); }
      catch (e) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f}: lstat failed: ${e.message}`, extra: null };
      }
      if (lst.isSymbolicLink()) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f} is a symbolic link; refusing (symlinks bypass the directory-confinement check).`, extra: { entry: f } };
      }
      // lstat().isSymbolicLink() is FALSE for a Windows directory junction, so
      // realpath is what confirms the entry lives under the resolved dir.
      let realEntry;
      try { realEntry = fs.realpathSync(entryPath); }
      catch (e) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f}: realpath failed: ${e.message}`, extra: null };
      }
      if (!realEntry.startsWith(realResolvedDir + path.sep)) {
        return {
          ok: false,
          error: `${verb}: --evidence-dir entry ${f} resolves outside the directory (junction / reparse-point / symlink target). Refusing.`,
          extra: { entry: f, resolved_to: realEntry },
        };
      }
      // The asEvidenceObject guard the single-file and stdin paths use: a `<pb>.json`
      // parsing to an array or scalar would run as empty, a false-clean not_detected.
      bundle[pbId] = asEvidenceObject(JSON.parse(raw));
    } catch (e) {
      // Parse failures and the asEvidenceObject refusal land here; the symlink and
      // junction refusals above return directly.
      return { ok: false, error: `${verb}: --evidence-dir entry ${f}: ${e.message}`, extra: { entry: f } };
    } finally {
      try { fs.closeSync(efd); } catch { /* already closed / invalid fd */ }
    }
  }
  return { ok: true, bundle };
}

function cmdRunMulti(runner, ids, args, runOpts, pretty, meta) {
  const sessionId = runOpts.session_id || require("crypto").randomBytes(8).toString("hex");
  runOpts.session_id = sessionId;

  let bundle = {};
  // An empty value (an unset shell variable in `--evidence "$EV"`) is falsy, so the
  // gates below skip, the bundle stays {}, and every playbook reads clean at exit 0.
  if (args.evidence === "") {
    return emitError("run: --evidence was given an empty value; pass a file path, '-' for stdin, or omit --evidence for a no-evidence run", { verb: "run", flag: "evidence" }, pretty);
  }
  if (args["evidence-dir"] === "") {
    return emitError("run: --evidence-dir was given an empty value; pass an existing directory, or omit --evidence-dir", { verb: "run", flag: "evidence-dir" }, pretty);
  }
  if (args.evidence) {
    try { bundle = readEvidence(args.evidence); } catch (e) {
      return emitError(`run: failed to read evidence bundle: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }
  // Each <playbook-id>.json under the directory is that playbook's submission.
  if (args["evidence-dir"]) {
    const dir = args["evidence-dir"];
    if (typeof dir !== "string") {
      return emitError("run: --evidence-dir must be a string.", null, pretty);
    }
    if (!fs.existsSync(dir)) {
      return emitError(`run: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    const er = readEvidenceDir(dir, "run");
    if (!er.ok) return emitError(er.error, er.extra, pretty);
    Object.assign(bundle, er.bundle);
  }

  const results = [];
  for (const id of ids) {
    // ids come from the catalog; validating each keeps a corrupt one from
    // path-traversing through this loop.
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

    // --ack is gated on THIS playbook's classification: one --ack on a run-all would
    // otherwise write explicit consent into attestations that started no clock.
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

    if (result && result.ok) {
      const persisted = persistAttestation({
        sessionId,
        playbookId: id,
        directiveId,
        evidenceHash: result.evidence_hash,
        operator: perRunOpts.operator,
        operatorConsent: perConsentApplies ? perRunOpts.operator_consent : null,
        submission,
        runOpts: perRunOpts,
        forceOverwrite: !!args["force-overwrite"],
        filename: `${id}.json`,
      });
      if (!persisted.ok) {
        // The bundle keeps running; the failure lands on the per-playbook result.
        // lock_contention / storage_exhausted must propagate or the aggregate gate
        // below collapses every persist failure to exit 1.
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

  // Additive: the per-playbook entries stay on the individual results.
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
  }, pretty, (obj) => {
    const s = obj.summary;
    const lines = [];
    const detectedTotal = s.detected;
    const icon = s.blocked > 0 ? "[!! BLOCKED]" : detectedTotal > 0 ? "[!! DETECTED]" : "[ok]";
    lines.push(`run ${obj.trigger || "multi"}: ${obj.playbooks_run.length} playbook(s)  session-id: ${obj.session_id}`);
    lines.push(`\n${icon}  detected=${detectedTotal}  inconclusive=${s.inconclusive}  clean=${s.total - detectedTotal - s.inconclusive - s.blocked}  blocked=${s.blocked}  total=${s.total}`);
    const rows = (obj.results || []).map(r => (r && r.ok === false)
      ? { id: r.playbook_id || "?", verdict: "blocked", rwep: "-", evidence: r.evidence_completeness || "not-evaluated", top: r.blocked_by || r.reason || r.error || "" }
      : { id: r.playbook_id || "?", verdict: r?.phases?.detect?.classification || r?.verdict || "?", rwep: (r?.rwep_score != null) ? String(r.rwep_score) : "-", evidence: r?.evidence_completeness || "unknown", top: r?.top_finding || "" });
    const wId = Math.max(8, ...rows.map(r => r.id.length));
    const wV = Math.max(8, ...rows.map(r => r.verdict.length));
    const wR = Math.max(4, ...rows.map(r => r.rwep.length));
    const wE = Math.max(8, ...rows.map(r => r.evidence.length));
    const pad = (str, w) => (str + " ".repeat(w)).slice(0, w);
    lines.push("");
    lines.push(`  ${pad("playbook", wId)}  ${pad("verdict", wV)}  ${pad("rwep", wR)}  ${pad("evidence", wE)}  finding`);
    lines.push(`  ${"-".repeat(wId)}  ${"-".repeat(wV)}  ${"-".repeat(wR)}  ${"-".repeat(wE)}  -------`);
    for (const row of rows) {
      const finding = row.top.length > 80 ? row.top.slice(0, 77) + "..." : row.top;
      lines.push(`  ${pad(row.id, wId)}  ${pad(row.verdict, wV)}  ${pad(row.rwep, wR)}  ${pad(row.evidence, wE)}  ${finding}`);
    }
    const clocks = obj.jurisdiction_clock_rollup || [];
    if (clocks.length) {
      lines.push(`\nJurisdiction clocks (${clocks.length}):`);
      for (const n of clocks.slice(0, 5)) lines.push(`  ${n.jurisdiction || "?"}/${n.regulation || "?"} → deadline ${n.deadline || "?"}`);
      if (clocks.length > 5) lines.push(`  … ${clocks.length - 5} more (--json for all)`);
    }
    lines.push(`\nFull structured results: --json or --pretty`);
    return lines.join("\n");
  });
  // Exit-code precedence, most specific first, so a CI gate branches on the right
  // remediation without parsing the body: LOCK_CONTENTION > STORAGE_EXHAUSTED >
  // SESSION_ID_COLLISION > GENERIC_FAILURE. `process.exitCode`, not
  // `process.exit()` — the aggregate JSON above still has to drain.
  const anyLockBusy = results.some(r => r.attestation_persist && r.attestation_persist.lock_contention === true);
  const anyStorageExhausted = results.some(r => r.attestation_persist && r.attestation_persist.storage_exhausted === true);
  // A persist failure that is neither lock-contention nor storage-exhaustion is a
  // session-id collision; without this a reused --session-id exits 0 having
  // persisted nothing.
  const anySessionCollision = results.some(r =>
    r.attestation_persist && r.attestation_persist.ok === false
    && !r.attestation_persist.lock_contention && !r.attestation_persist.storage_exhausted);
  const anyBlocked = results.some(r => r.ok === false);
  if (anyLockBusy) { process.exitCode = EXIT_CODES.LOCK_CONTENTION; return; }
  if (anyStorageExhausted) { process.exitCode = EXIT_CODES.STORAGE_EXHAUSTED; return; }
  if (anySessionCollision) { process.exitCode = EXIT_CODES.SESSION_ID_COLLISION; return; }
  if (anyBlocked) { process.exitCode = EXIT_CODES.GENERIC_FAILURE; return; }
}

/**
 * Attestation root, most-specific first:
 *   1. runOpts.attestationRoot (--attestation-root)
 *   2. $EXCEPTD_HOME/attestations
 *   3. ~/.exceptd/attestations/<repo-or-host-tag>/
 *   4. ./.exceptd/attestations/ when the home path can't be created
 * The repo tag is what lets `attest list` work from any directory.
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
 * `<repo-name>@<branch>` inside a git repo, else `host:<hostname>`. Names the
 * per-context directory, so a multi-repo operator's sessions stay separate.
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
 * Writes an attestation, refusing to overwrite unless `forceOverwrite`. An overwrite
 * carries `prior_evidence_hash` and `prior_captured_at` read off disk first, so the
 * audit chain survives. Returns { ok: true, prior_session_id, overwrote_at,
 * attestation_path }, or { ok: false, error, existingPath } on a refused collision.
 */
function persistAttestation(args) {
  const { sessionId, playbookId, directiveId, evidenceHash, operator,
          operatorConsent, submission, runOpts, forceOverwrite, filename } = args;
  // Re-checked here so nothing path-traverses out of the attestation root.
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
      error: `Refusing to persist attestation with unsafe filename: ${String(JSON.stringify(filename)).slice(0, 80)}.`,
      existingPath: null,
    };
  }
  const root = resolveAttestationRoot(runOpts);
  const dir = path.join(root, sessionId);
  const filePath = path.join(dir, filename);
  // dir must remain inside root after normalization.
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
        // On an overwrite the session_id is unchanged — that is why it collided —
        // so the hash and timestamp are what identify the prior.
        prior_evidence_hash: priorEvidenceHash,
        prior_captured_at: priorCapturedAt,
      };
      // Body and .sig go to fsync'd tmp files, then place with linkSync (create) or
      // rename (force-overwrite), so a crash mid-write cannot leave a truncated
      // attestation.json. linkSync carries the O_EXCL collision guarantee: EEXIST
      // when the slot is taken. Mode 0o600 — an attestation holds evidence.
      const crypto = require("crypto");
      const jsonStr = JSON.stringify(attestation, null, 2);
      const sigPath = filePath + ".sig";
      const suffix = `.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
      const jsonTmp = filePath + suffix;
      const sigTmp = sigPath + suffix;
      const writeFsync = (p, data) => {
        const fd = fs.openSync(p, "w", 0o600);
        try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); }
        finally { fs.closeSync(fd); }
      };
      // Computed over the SAME normalized bytes that land, so sig matches body.
      const sidecarBytes = computeSidecarBytes(normalizeAttestationBytes(jsonStr));
      writeFsync(jsonTmp, jsonStr);
      writeFsync(sigTmp, sidecarBytes);
      try {
        if (flag === "wx") {
          try {
            fs.linkSync(jsonTmp, filePath);
          } catch (linkErr) {
            if (linkErr.code === "EEXIST") throw linkErr; // collision — outer handler decides
            // No hard-link support (EPERM/EXDEV/ENOSYS): existsSync plus atomic
            // rename, a narrow TOCTOU window on those filesystems only.
            if (fs.existsSync(filePath)) { const e = new Error("EEXIST"); e.code = "EEXIST"; throw e; }
            fs.renameSync(jsonTmp, filePath);
          }
          try {
            fs.renameSync(sigTmp, sigPath);
          } catch (sigErr) {
            // The body landed, the sidecar did not. Left in place it holds the slot
            // forever — every retry collides with EEXIST and verification reports
            // the attestation unsigned — so the slot is released before rethrowing.
            try { fs.unlinkSync(filePath); } catch { /* best-effort slot release */ }
            throw sigErr;
          }
          try { fs.unlinkSync(jsonTmp); } catch { /* hard-link path leaves a second name */ }
        } else {
          // Force-overwrite under the persist lock; both tmps are already fsync'd.
          fs.renameSync(jsonTmp, filePath);
          fs.renameSync(sigTmp, sigPath);
        }
      } catch (placeErr) {
        // Any placement failure, EEXIST included, leaves no orphan tmp at the slot.
        try { fs.unlinkSync(jsonTmp); } catch { /* may already be linked/renamed */ }
        try { fs.unlinkSync(sigTmp); } catch { /* may already be renamed */ }
        throw placeErr;
      }
      try {
        const { restrictWindowsAcl } = require(path.join(PKG_ROOT, "lib", "sign.js"));
        restrictWindowsAcl(filePath);
        restrictWindowsAcl(sigPath);
      } catch { /* sign.js not loadable in some test paths — best-effort */ }
    };

    try {
      writeAttestation(null, null, "wx");
      return { ok: true, prior_session_id: null, overwrote_at: null, attestation_path: filePath };
    } catch (eExcl) {
      if (eExcl.code !== "EEXIST") throw eExcl;
      // Slot taken — read the prior to chain the audit trail, then decide.
      let prior = null;
      try { prior = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { /* malformed prior — proceed */ }
      if (!forceOverwrite) {
        return {
          ok: false,
          error: `Attestation already exists at ${path.relative(process.cwd(), filePath)}. Session-id collision (${sessionId}) — refusing to overwrite to preserve audit trail.`,
          existingPath: path.relative(process.cwd(), filePath),
        };
      }
      // A lockfile serializes read-prior + write-new, so concurrent --force-overwrite
      // runs on one slot don't degrade to last-write-wins. Same shape as
      // withCatalogLock / withIndexLock: O_EXCL 'wx' on a sibling .lock, bounded
      // retry, PID-liveness probe, mtime fallback. MAX_RETRIES stays small — the
      // wait busy-spins, so ten bounds the freeze at ~1-2s before LOCK_CONTENTION.
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
          // ENOSPC / EROFS / EDQUOT are infra failures no retry-spin resolves, so
          // they exit 9: the runbook branches on "free disk" vs "retry".
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
          // Synchronous spin: persistAttestation cannot await.
          const deadline = Date.now() + 50 + Math.floor(Math.random() * 150);
          while (Date.now() < deadline) { /* spin */ }
        }
      }
      if (!acquired) {
        // The lock_contention sentinel separates lock-busy from a hard write failure.
        // exitCode is pinned to 8 HERE, before emit(): emit() maps an ok:false body
        // to 1 only while exitCode is still 0, and preserves a non-zero value.
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
        // Re-read INSIDE the lock: another --force-overwrite may have landed since
        // the EEXIST probe.
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
          attestation_path: filePath,
        };
      } finally {
        try { fs.unlinkSync(lockPath); } catch {}
      }
    }
  } catch (e) {
    // Storage exhaustion gets its own sentinel and exit code, routing to a
    // different remediation than a generic write error.
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
 * Strips a leading UTF-8 BOM and collapses CRLF → LF. Four other copies exist
 * (lib/sign.js, lib/verify.js, lib/refresh-network.js, scripts/verify-shipped-
 * tarball.js); tests/normalize-contract.test.js asserts all five agree byte-wise.
 */
function normalizeAttestationBytes(input) {
  let s = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return s.replace(/\r\n/g, "\n");
}

// Returns the `.sig` sidecar bytes for already-normalized attestation content.
// Writes no file: the persist path renames the returned string into place, so the
// body never lands without its sidecar ready.
function computeSidecarBytes(contentNormalized) {
  const crypto = require("crypto");
  // PKG_ROOT only: `attest verify` checks PKG_ROOT/keys/public.pem, so signing
  // with a cwd-local key would verify INVALID.
  const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
  // Once per process, so a cron job doesn't spam stderr.
  if (!fs.existsSync(privKeyPath) && !process.env.EXCEPTD_UNSIGNED_WARNED) {
    const pkgRootSegments = PKG_ROOT.split(/[\\/]/);
    const isConsumerInstall =
      pkgRootSegments.includes("node_modules") ||
      path.basename(path.dirname(PKG_ROOT)) === "@blamejs";
    if (isConsumerInstall) {
      process.stderr.write("[attest] writing unsigned attestation (consumer install — signing is contributor-only).\n");
    } else {
      process.stderr.write(
        "[attest] attestation will be written UNSIGNED (no private key at .keys/private.pem). " +
        "Operators reading the attestation later can verify the SHA-256 hash but not authenticity. " +
        "Enable Ed25519 signing: `exceptd doctor --fix` (or for contributor checkouts: `node $(exceptd path)/lib/sign.js generate-keypair`). " +
        "Suppress this notice: export EXCEPTD_UNSIGNED_WARNED=1.\n"
      );
    }
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
  }
  try {
    if (fs.existsSync(privKeyPath)) {
      const privateKey = fs.readFileSync(privKeyPath, "utf8");
      const sig = crypto.sign(null, Buffer.from(contentNormalized, "utf8"), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      });
      // The signature covers ONLY the attestation file bytes; no rewritable
      // metadata travels in the sidecar.
      return JSON.stringify({
        algorithm: "Ed25519",
        signature_base64: sig.toString("base64"),
        note: "Ed25519 signature covers the attestation file bytes only. Use filesystem mtime for freshness; use the attestation's `captured_at` for the signed timestamp.",
      }, null, 2);
    }
    return JSON.stringify({
      algorithm: "unsigned",
      signed: false,
      note: "No private key at .keys/private.pem — attestation is hash-stable but unsigned. Run `exceptd doctor --fix` to enable signing.",
    }, null, 2);
  } catch {
    // A signing failure must not block the run, and every body needs a sidecar,
    // so the fallback is an unsigned marker.
    return JSON.stringify({
      algorithm: "unsigned",
      signed: false,
      note: "Signing failed at write time; attestation is hash-stable but unsigned.",
    }, null, 2);
  }
}

// Signs an already-written file in place. Replay records only: they write a
// uniquely-named file, needing none of the persist path's collision handling.
function maybeSignAttestation(filePath) {
  const content = normalizeAttestationBytes(fs.readFileSync(filePath, "utf8"));
  const sidecar = computeSidecarBytes(content);
  fs.writeFileSync(filePath + ".sig", sidecar, { mode: 0o600 });
  try { require(path.join(PKG_ROOT, "lib", "sign.js")).restrictWindowsAcl(filePath + ".sig"); } catch { /* best-effort */ }
}

/**
 * Every READ site validates the session-id, not just the write path: unvalidated,
 * `attest show '../../..'` reaches path.join(root, id) and reads outside the
 * attestation root. Throws on a bad id.
 */
function validateSessionIdForRead(sessionId) {
  // lib/id-validation.js is the single source of truth, shared with the write path.
  const r = validateIdComponent(sessionId, "session");
  if (!r.ok) {
    throw new Error(
      `Invalid session-id: ${typeof sessionId === "string" ? JSON.stringify(sessionId).slice(0, 80) : typeof sessionId}. ${r.reason}.`
    );
  }
  return sessionId;
}

function findSessionDir(sessionId, runOpts) {
  try { validateSessionIdForRead(sessionId); }
  catch { return null; }
  const candidates = [
    path.join(resolveAttestationRoot(runOpts), sessionId),
    path.join(process.cwd(), ".exceptd", "attestations", sessionId),
  ];
  for (const c of candidates) {
    // The resolved candidate must stay strictly inside its parent root.
    const parent = path.dirname(c);
    const resolved = path.resolve(c);
    if (!resolved.startsWith(path.resolve(parent) + path.sep)) continue;
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * Newest attestation matching opts.playbookId / opts.since, as
 * { sessionId, playbookId, file, parsed }, or null.
 */
function findLatestAttestation(opts = {}) {
  // Both the home root and the cwd-relative one, so older history is still found.
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
        // A replay record has no captured_at or evidence_hash, so it is never a
        // --latest candidate. Gated on the parsed kind: a rename cannot smuggle
        // one into the listing.
        if (j && j.kind === "replay") continue;
        // `!= null`, not truthiness: an empty-string id would widen the match.
        if (opts.playbookId != null && j.playbook_id !== opts.playbookId) continue;
        if (opts.since && (j.captured_at || "") < opts.since) continue;
        if (opts.excludeSessionId && sid === opts.excludeSessionId) continue;
        candidates.push({ sessionId: sid, playbookId: j.playbook_id, file: p, parsed: j });
      } catch { /* skip malformed */ }
    }
  }
}

/**
 * Ed25519 sidecar verification for `attest verify` and `reattest`. Returns
 * { file, signed, verified, reason }; a caller MUST check `signed && verified`
 * before consuming the attestation, or forged input feeds the verdict.
 */
function verifyAttestationSidecar(attFile) {
  const crypto = require("crypto");
  const sigPath = attFile + ".sig";
  const pubKeyPath = path.join(PKG_ROOT, "keys", "public.pem");
  const pubKey = fs.existsSync(pubKeyPath) ? fs.readFileSync(pubKeyPath, "utf8") : null;
  // Every public-key load site consults keys/EXPECTED_FINGERPRINT: without it, an
  // attacker who swaps keys/public.pem gets verify-against-attacker-key silently.
  if (pubKey) {
    const pinError = assertExpectedFingerprint(pubKey);
    if (pinError) {
      // A pin mismatch means this key is NOT the published one, so verifying against
      // it proves nothing. The tamper_class makes reattest treat it as tamper.
      return { file: attFile, signed: false, verified: false, tamper_class: "fingerprint-mismatch", reason: pinError };
    }
  }
  if (!fs.existsSync(sigPath)) {
    // Benign ONLY when none was ever expected — a keyless host with no signed peer.
    // Where a sig SHOULD exist, its absence is deletion to evade detection, and the
    // tamper_class makes `attest diff` and `reattest` refuse it too.
    const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
    let expected = fs.existsSync(privKeyPath);
    if (!expected) {
      try {
        const dir = path.dirname(attFile);
        for (const sf of fs.readdirSync(dir)) {
          if (!sf.endsWith(".sig")) continue;
          try {
            const sd = JSON.parse(fs.readFileSync(path.join(dir, sf), "utf8"));
            if (sd && sd.algorithm === "Ed25519") { expected = true; break; }
          } catch { /* skip unparseable sidecar */ }
        }
      } catch { /* dir unreadable — fall through to benign */ }
    }
    if (expected) {
      return { file: attFile, signed: false, verified: false, reason: "no .sig sidecar, but one was expected (signing key present or a signed peer attestation exists) — sidecar deletion suspected", tamper_class: "sidecar-missing" };
    }
    return { file: attFile, signed: false, verified: false, reason: "no .sig sidecar" };
  }
  let sigDoc;
  try { sigDoc = JSON.parse(fs.readFileSync(sigPath, "utf8")); }
  catch (e) {
    // A corrupt-JSON sidecar is indistinguishable from tamper: whoever can rewrite
    // the attestation can mangle the .sig. Its own tamper_class keeps a caller
    // matching on reason strings from letting it through the benign branch.
    return {
      file: attFile,
      signed: false,
      verified: false,
      reason: `sidecar parse error: ${e.message}`,
      tamper_class: "sidecar-corrupt",
    };
  }
  if (sigDoc.algorithm === "unsigned") {
    // An unsigned sidecar is legitimate only on a host WITHOUT .keys/private.pem.
    // Where a private key exists it is substitution: tamper the body, then overwrite
    // .sig with the unsigned stub to bypass the detector.
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
  // Anything not exactly "Ed25519" or "unsigned" is refused. A branch on
  // `=== "unsigned"` alone lets null, "RSA-PSS" or an array reach crypto.verify
  // under default Ed25519 args — a downgrade-bait replay of a real signature.
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
    // The signer's normalize(), so verification is stable across CRLF/BOM churn.
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

/**
 * The A-side attestation for `attest diff`, as { parsed, file } or null — its REAL
 * on-disk file, since a multi-playbook session writes per-playbook `<id>.json` and
 * no attestation.json, and the sidecar check needs the exact path. Prefers
 * attestation.json, else newest by captured_at, as the B-side resolves.
 * `attestations[i]` pairs with `files[i]`; the caller pushes them in lockstep.
 */
function resolveSelfAttestation(dir, attestations, files) {
  if (!Array.isArray(attestations) || attestations.length === 0) return null;
  const canonicalPath = path.join(dir, "attestation.json");
  const canonicalIdx = files.indexOf(canonicalPath);
  if (canonicalIdx !== -1) {
    return { parsed: attestations[canonicalIdx], file: files[canonicalIdx] };
  }
  let best = { parsed: attestations[0], file: files[0] };
  for (let i = 1; i < attestations.length; i++) {
    const cur = attestations[i].captured_at || "";
    const bestCap = best.parsed.captured_at || "";
    if (cur.localeCompare(bestCap) > 0) best = { parsed: attestations[i], file: files[i] };
  }
  return best;
}

/**
 * `attest prune --all-older-than <ISO>`: deletes whole session directories whose
 * `captured_at` predates the cutoff, confined to direct children of the resolved
 * roots. Nothing else removes them, so the store grows monotonically without it.
 */
function cmdPruneAttestations(runner, args, runOpts, pretty) {
  const cutoffRaw = args["all-older-than"];
  if (!cutoffRaw) {
    return emitError(
      "attest prune: --all-older-than <ISO-8601 date> is required (e.g. attest prune --all-older-than 2026-01-01). Add --dry-run to preview.",
      { verb: "attest prune" },
      pretty,
    );
  }
  const isoErr = validateIsoSince(cutoffRaw, "--all-older-than");
  if (isoErr) return emitError(`attest prune: ${isoErr}`, { verb: "attest prune" }, pretty);
  const cutoffMs = Date.parse(cutoffRaw);
  const dryRun = !!args["dry-run"];

  // Canonicalize before dedup: a Set over raw strings collapses only byte-identical
  // paths, so two roots naming the SAME directory each scan it, inflating
  // scanned/kept/pruned_count and double-listing the preview.
  const canonicalRoot = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
  const roots = [];
  const seenRoots = new Set();
  for (const r of [resolveAttestationRoot(runOpts), path.join(process.cwd(), ".exceptd", "attestations")]) {
    const c = canonicalRoot(r);
    if (seenRoots.has(c)) continue;
    seenRoots.add(c);
    roots.push(c);
  }
  const pruned = [];
  let kept = 0;
  let scanned = 0;
  for (const root of roots) {
    let sessions;
    try { sessions = fs.readdirSync(root, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name); }
    catch { continue; }
    for (const sid of sessions) {
      const sdir = path.join(root, sid);
      scanned++;
      // A session with no parseable date is left alone — never delete undated.
      let captured = null;
      let replayFallback = null;
      try {
        for (const f of fs.readdirSync(sdir)) {
          if (!f.endsWith(".json") || f.endsWith(".sig")) continue;
          let j; try { j = JSON.parse(fs.readFileSync(path.join(sdir, f), "utf8")); } catch { continue; }
          if (!j) continue;
          if (j.kind === "replay") {
            // A session holding only replay records is otherwise undateable and
            // never ages out, so the newest replay timestamp stands in.
            if (typeof j.replayed_at === "string" && (!replayFallback || j.replayed_at > replayFallback)) replayFallback = j.replayed_at;
            continue;
          }
          if (typeof j.captured_at === "string" && (!captured || j.captured_at > captured)) captured = j.captured_at;
        }
      } catch { continue; }
      const dateStr = captured || replayFallback;
      const ts = dateStr ? Date.parse(dateStr) : NaN;
      if (!Number.isFinite(ts)) { kept++; continue; }
      if (ts < cutoffMs) {
        // sdir must resolve to a direct child of root, so a crafted session name
        // cannot escape. Evaluated in BOTH modes, or a session the real run refuses
        // shows as [would-delete] in the preview. realDir feeds the rmSync below, so
        // gate and delete act on one canonical path with no TOCTOU between them.
        let realDir = null;
        try {
          const realRoot = fs.realpathSync(root);
          const candidate = fs.realpathSync(sdir);
          if (path.dirname(candidate) === realRoot) realDir = candidate;
        } catch { /* unresolvable -> not deletable */ }
        if (realDir === null) { kept++; continue; }
        if (!dryRun) {
          // pruned_count is a post-condition: a session counts only once deleted.
          try { fs.rmSync(realDir, { recursive: true, force: true }); }
          catch { kept++; continue; /* skip undeletable */ }
        }
        pruned.push({ session_id: sid, captured_at: captured, replayed_at: captured ? undefined : replayFallback, dir: sdir });
      } else {
        kept++;
      }
    }
  }

  emit({
    ok: true,
    verb: "attest prune",
    dry_run: dryRun,
    cutoff: cutoffRaw,
    scanned,
    pruned_count: pruned.length,
    kept,
    pruned: pruned.map(p => ({ session_id: p.session_id, captured_at: p.captured_at, replayed_at: p.replayed_at })),
    roots_searched: roots,
  }, pretty, (obj) => {
    const lines = [];
    lines.push(`attest prune${obj.dry_run ? " (DRY-RUN)" : ""}: cutoff ${obj.cutoff}`);
    lines.push(`  scanned ${obj.scanned} session(s)  |  ${obj.dry_run ? "would prune" : "pruned"} ${obj.pruned_count}  |  kept ${obj.kept}`);
    for (const p of obj.pruned.slice(0, 20)) lines.push(`  ${obj.dry_run ? "[would-delete]" : "[deleted]"} ${p.session_id}  (${((p.captured_at || p.replayed_at) || "").slice(0, 19)})`);
    if (obj.pruned_count > 20) lines.push(`  … ${obj.pruned_count - 20} more`);
    if (obj.dry_run && obj.pruned_count > 0) lines.push(`  → re-run without --dry-run to delete.`);
    return lines.join("\n");
  });
}

function cmdReattest(runner, args, runOpts, pretty) {
  const crypto = require("crypto");
  // An invalid --since reaches walkAttestationDir's lexical compare, matching
  // all or none unpredictably.
  if (args.since != null) {
    const sinceErr = validateIsoSince(args.since);
    if (sinceErr) return emitError(`reattest: ${sinceErr}`, null, pretty);
  }
  // --playbook is registered `multi:`, so a single value arrives as a one-element
  // array; an empty value unwraps to "" and widens --latest to every playbook.
  let playbookFilter = null;
  if (args.playbook != null) {
    playbookFilter = Array.isArray(args.playbook) ? args.playbook[0] : args.playbook;
    if (typeof playbookFilter !== "string" || playbookFilter === "") {
      return emitError("reattest: --playbook was given an empty value. Pass a playbook id (e.g. --playbook kernel) or omit --playbook to match across all playbooks.", { verb: "reattest", flag: "playbook" }, pretty);
    }
  }
  let sessionId = args._[0];
  let attFile = null;
  if (!sessionId && args.latest) {
    const found = findLatestAttestation({
      playbookId: playbookFilter,
      since: args.since || null,
    });
    if (!found) return emitError("reattest: --latest found no matching attestations.", { filter: { playbook: args.playbook || null, since: args.since || null } }, pretty);
    sessionId = found.sessionId;
    attFile = found.file;
  }
  if (!sessionId) return emitError("reattest: missing <session-id>. Pass a session-id or --latest [--playbook <id>] [--since <ISO>].", null, pretty);
  // Validated BEFORE the join below: when findSessionDir returns null the `||`
  // fallback joins this id onto the attestation root, so a `../`-bearing one reads
  // a forged attestation and writes a signed replay record outside it.
  try { validateSessionIdForRead(sessionId); }
  catch (e) { return emitError(`reattest: ${e.message}`, { session_id_input: typeof sessionId === "string" ? sessionId.slice(0, 80) : typeof sessionId }, pretty); }
  const dir = findSessionDir(sessionId, runOpts) || path.join(resolveAttestationRoot(runOpts), sessionId);
  if (!attFile) attFile = path.join(dir, "attestation.json");
  if (!fs.existsSync(attFile)) {
    return emitError(`reattest: no attestation found at ${attFile}`, { session_id: sessionId }, pretty);
  }

  // The sidecar is verified BEFORE the prior attestation is consumed, or the drift
  // verdict computes against forged input. Exit 6 (TAMPERED) unless --force-replay.
  // Unsigned warns and proceeds — a config state; `signed && !verified` is tamper.
  const verify = verifyAttestationSidecar(attFile);
  if (isTamperedSidecarVerify(verify) && !args["force-replay"]) {
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
  if (isTamperedSidecarVerify(verify) && args["force-replay"]) {
    process.stderr.write(`[exceptd reattest] WARNING: --force-replay overriding failed signature verification on ${attFile} (${verify.reason}). The replay output records sidecar_verify so the override is audit-visible.\n`);
  } else if (!verify.signed && verify.reason && verify.reason.includes("no .sig sidecar") && !args["force-replay"]) {
    // A missing sidecar is NOT benign: deletion is observationally identical to
    // tamper, and whoever can rewrite the attestation can rm the .sig. An
    // originally-unsigned one takes the distinguishable branch below.
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
    // A legitimately-unsigned attestation still needs --force-replay: accepting one
    // silently lets an attacker swap a valid .sig for the unsigned stub on any host
    // lacking a private key at verify time. The override is recorded in the body.
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

  // Replays the ORIGINAL persisted submission, never an empty stub: an empty replay
  // yields a different evidence_hash for every session, so every unchanged one reads
  // "drifted". Replaying the prior reproduces its hash, and a mismatch then means
  // the hash, the canonicalization or the verdict moved.
  const replaySubmission = (prior.submission && typeof prior.submission === "object")
    ? prior.submission
    : { artifacts: {}, signal_overrides: {}, signals: {} };
  const replayOpts = Object.assign({}, runOpts, {
    airGap: !!(prior.run_opts && prior.run_opts.airGap) || runOpts.airGap,
    forceStale: true, // bypass currency block on reattest — drift comparison is the point
  });
  if (prior.submission && prior.submission.precondition_checks) {
    replayOpts.precondition_checks = prior.submission.precondition_checks;
  } else {
    // Preconditions synthesised from the playbook, so a replay isn't blocked when
    // the operator never supplied them.
    try {
      // The playbook_id came off disk, where a corrupt prior could smuggle one.
      const r = validateIdComponent(prior.playbook_id, "playbook");
      if (r.ok) {
        const pb = runner.loadPlaybook(prior.playbook_id);
        const synth = {};
        for (const pc of (pb._meta && pb._meta.preconditions) || []) synth[pc.id] = true;
        replayOpts.precondition_checks = synth;
      }
    } catch { /* ignore */ }
  }
  const replay = runner.run(prior.playbook_id, prior.directive_id, replaySubmission, replayOpts);

  if (!replay || replay.ok === false) {
    // A falsy replay.reason dumps the body's keys, so the message still names
    // something the operator can look at.
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
    // A prior "detected" that no longer detects is "resolved", not "drifted".
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

  // Every replay verdict lands on disk beside attestation.json, where `attest verify`
  // picks it up: an override printed only to stdout is invisible to an auditor.
  // ISO-8601 ':' is refused by the filename regex, so it becomes '-'; millisecond
  // precision keeps two replays in the same second from colliding on EEXIST.
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
    // Two concurrent reattests can share a millisecond, so a random suffix is
    // appended until O_EXCL accepts.
    const dir = path.dirname(attFile);
    const MAX_SUFFIX_TRIES = 8;
    let written = false;
    let lastErr = null;
    for (let i = 0; i < MAX_SUFFIX_TRIES; i++) {
      const suffix = i === 0 ? "" : "-" + crypto.randomBytes(3).toString("hex");
      const candidate = path.join(dir, replayBaseName + suffix + ".json");
      try {
        // 0o600 plus the Windows ACL: a replay record carries the same evidence.
        fs.writeFileSync(candidate, JSON.stringify(replayBody, null, 2), { flag: "wx", mode: 0o600 });
        try {
          const { restrictWindowsAcl } = require(path.join(PKG_ROOT, "lib", "sign.js"));
          restrictWindowsAcl(candidate);
        } catch { /* best-effort */ }
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
    // Non-fatal: the stdout verdict is the primary surface, and the failure rides
    // in the body so an audit pipeline can re-run the persist.
    replayPersisted = { ok: false, error: String((e && e.message) || e) };
  }
  if (replayPersisted && replayPersisted.ok && replayPath) {
    // Signing is best-effort — an unsigned replay record is still a valid audit
    // entry. Split from the write try{} so a sign failure cannot mask the write.
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
    // Records whether the replay ran against authenticated input.
    sidecar_verify: verify,
    // One-token label beside the full object, so a log scraper can filter override
    // events without parsing reason strings. See classifySidecarVerify.
    sidecar_verify_class: sidecarVerifyClass,
    force_replay: forceReplay,
    // The on-disk path, so an auditor need not re-derive the filename.
    replay_persisted: replayPersisted,
  }, pretty, (obj) => {
    const lines = [];
    lines.push(`attest diff: ${obj.session_id} (${obj.playbook_id})`);
    const icon = obj.status === "unchanged" ? "[ok]" : "[i  DRIFTED]";
    lines.push(`\n${icon}  status=${obj.status}`);
    lines.push(`  prior:  ${obj.prior_evidence_hash}  (${obj.prior_captured_at || '(no detail)'})`);
    lines.push(`  replay: ${obj.replay_evidence_hash}  (${obj.replayed_at || '(no detail)'})`);
    if (obj.replay_classification) {
      lines.push(`  replay classification: ${obj.replay_classification}  RWEP=${obj.replay_rwep_adjusted ?? 0}`);
    }
    if (obj.sidecar_verify_class) {
      lines.push(`  sidecar verify: ${obj.sidecar_verify_class}`);
    }
    if (obj.replay_persisted && obj.replay_persisted.ok && obj.replay_persisted.path) {
      lines.push(`  replay record: ${obj.replay_persisted.path}`);
    }
    if (obj.status === "drifted") {
      lines.push(`\n  → next: exceptd attest show ${obj.session_id}            # inspect the prior submission`);
      lines.push(`         exceptd run ${obj.playbook_id} --evidence <new>      # capture a fresh attestation against the new state`);
    }
    return lines.join("\n");
  });
}

/**
 * The one tamper predicate over a verifyAttestationSidecar() result: any non-benign
 * sidecar state refuses replay unless --force-replay. A bare `signed && !verified`
 * misses every class listed below. The list lives HERE, so a new tamper class in
 * the verifier has exactly one refusal site to extend.
 */
function isTamperedSidecarVerify(verify) {
  if (!verify || typeof verify !== "object") return false;
  const isSignedTamper = verify.signed && !verify.verified;
  const isClassTamper = !verify.signed && (
    verify.tamper_class === "sidecar-corrupt"
    || verify.tamper_class === "unsigned-substitution"
    // A downgrade-bait sidecar throwing inside crypto.verify would otherwise
    // surface as signed:true + verified:false through the catch.
    || verify.tamper_class === "algorithm-unsupported"
    // A public.pem failing the pin is the key-swap the pin exists for.
    || verify.tamper_class === "fingerprint-mismatch"
    // Absent-but-expected is deletion-to-evade, so stripping a .sig cannot
    // dodge the diff gate.
    || verify.tamper_class === "sidecar-missing"
  );
  return Boolean(isSignedTamper || isClassTamper);
}

/**
 * One-token label for a verifyAttestationSidecar() result, persisted beside the full
 * object so an auditor can filter by class without regexing the reason string.
 */
function classifySidecarVerify(verify) {
  if (!verify || typeof verify !== "object") return "unknown";
  if (verify.signed && verify.verified) return "verified";
  if (verify.signed && !verify.verified) return "tampered";
  if (verify.tamper_class === "sidecar-corrupt") return "sidecar-corrupt";
  if (verify.tamper_class === "unsigned-substitution") return "unsigned-substitution";
  if (verify.tamper_class === "algorithm-unsupported") return "algorithm-unsupported";
  if (verify.tamper_class === "fingerprint-mismatch") return "fingerprint-mismatch";
  if (typeof verify.reason === "string" && verify.reason.startsWith("attestation explicitly unsigned")) return "explicitly-unsigned";
  if (typeof verify.reason === "string" && verify.reason.includes("no .sig sidecar")) return "no-sidecar";
  if (typeof verify.reason === "string" && verify.reason.includes("no public key")) return "no-public-key";
  return "unknown";
}

// The one `attest diff` renderer, shared by the --against and most-recent-prior
// branches. Reads only fields off the emitted object, so both render identically.
function renderAttestDiff(obj) {
  const lines = [];
  lines.push(`attest diff: ${obj.a_session}${obj.a_playbook ? ` (${obj.a_playbook})` : ""}`);
  lines.push(`  vs ${obj.b_session}${obj.b_captured ? ` (captured ${obj.b_captured})` : ""}`);
  const icon = obj.status === "unchanged" ? "[ok]" : "[!]";
  lines.push(`  ${icon}  status=${obj.status}  evidence_hash=${(obj.a_evidence_hash || "").slice(0, 12)}...`);
  const ad = obj.artifact_diff || {};
  const sd = obj.signal_override_diff || {};
  lines.push(`  artifact diff:  ${ad.added?.length ?? 0} added, ${ad.removed?.length ?? 0} removed, ${ad.changed?.length ?? 0} changed, ${ad.unchanged_count ?? 0} unchanged (of ${ad.total_compared ?? 0})`);
  lines.push(`  signal diff:    ${sd.changed?.length ?? 0} changed, ${sd.unchanged_count ?? 0} unchanged (of ${sd.total_compared ?? 0})`);
  if (obj.sidecar_verify) {
    // classifySidecarVerify, never an inline reason-string match: an unsigned-
    // substitution reason also contains "explicitly unsigned" and reads as benign.
    lines.push(`  sidecar verify: ${classifySidecarVerify(obj.sidecar_verify)}`);
  }
  return lines.join("\n");
}
function cmdAttest(runner, args, runOpts, pretty) {
  const subverb = args._[0];
  const sessionId = args._[1];
  if (!subverb) {
    return emitError("attest: missing subverb. Usage: attest list | show <sid> | export <sid> | verify <sid> [--require-signed] | diff <sid> | prune --all-older-than <ISO> [--dry-run]", null, pretty);
  }
  // Checked BEFORE the session-id branch, so `attest verfy sid` gets the
  // did-you-mean, not a misleading "no session dir".
  const ATTEST_SUBVERBS = ["list", "show", "export", "verify", "diff", "prune"];
  if (!ATTEST_SUBVERBS.includes(subverb)) {
    const dym = suggestVerb(subverb, ATTEST_SUBVERBS);
    const hint = dym.length > 0
      ? `Did you mean: ${dym.join(" | ")}? Accepted: ${ATTEST_SUBVERBS.join(" | ")}.`
      : `Accepted: ${ATTEST_SUBVERBS.join(" | ")}.`;
    return emitError(
      `attest: unknown subverb "${subverb}". ${hint}`,
      { verb: "attest", subverb_input: subverb, did_you_mean: dym, accepted_subverbs: ATTEST_SUBVERBS },
      pretty
    );
  }
  // `list` and `prune` take no session-id positional.
  if (subverb === "list") {
    return cmdListAttestations(runner, args, runOpts, pretty);
  }
  if (subverb === "prune") {
    return cmdPruneAttestations(runner, args, runOpts, pretty);
  }
  if (!sessionId) {
    return emitError(
      `attest ${subverb}: missing <session-id> positional argument. Inventory prior sessions with \`exceptd attest list\`; or pass \`--latest\` to operate on the most recent.`,
      { verb: `attest ${subverb}` },
      pretty
    );
  }
  // findSessionDir() returns null for a rejected id AND a valid one that isn't
  // there, so validating up front separates "refused" from "not found".
  try { validateSessionIdForRead(sessionId); }
  catch (e) {
    return emitError(`attest ${subverb}: ${e.message}`, { session_id_input: typeof sessionId === "string" ? sessionId.slice(0, 80) : typeof sessionId }, pretty);
  }
  const dir = findSessionDir(sessionId, runOpts);
  if (!dir) {
    return emitError(`attest ${subverb}: no session dir for ${sessionId}. Searched: ${resolveAttestationRoot(runOpts)} + .exceptd/attestations/`, { session_id: sessionId }, pretty);
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
  // Replay records share the session directory. Partitioned on the parsed `kind`,
  // not the filename, so a rename cannot smuggle one into attestations[].
  const attestations = [];
  const attestationFiles = [];
  const replays = [];
  for (const f of files) {
    let parsed;
    const fp = path.join(dir, f);
    try { parsed = JSON.parse(fs.readFileSync(fp, "utf8")); }
    catch { continue; }
    if (!parsed) continue;
    if (parsed.kind === "replay") replays.push(parsed);
    // The path is tracked beside the parsed body so the A-side verify reaches the
    // ACTUAL signed file: a run-all session writes per-playbook `<id>.json` and no
    // attestation.json, where a hardcoded path passes a forged A-side at exit 0.
    else { attestations.push(parsed); attestationFiles.push(fp); }
  }

  if (subverb === "show") {
    emit({ verb: "attest show", session_id: sessionId, attestations, attestation_replays: replays }, pretty);
    return;
  }

  if (subverb === "diff") {
    // Without --against, diffs against the most-recent prior session; with it,
    // compares two named sessions by evidence_hash plus a field diff. An empty
    // `--against "$VAR"` is falsy and would skip that branch, comparing against a
    // DIFFERENT baseline than the operator named.
    if (args.against === "") {
      return emitError(
        'attest diff: --against was given an empty value; pass a session-id, or omit --against to diff against the most-recent prior.',
        { verb: "attest diff", flag: "against" },
        pretty
      );
    }
    if (args.against) {
      // Same gate as the primary sid: a traversal value gets "invalid session-id".
      try { validateSessionIdForRead(args.against); }
      catch (e) {
        return emitError(`attest diff --against: ${e.message}`, { against_input: typeof args.against === "string" ? args.against.slice(0, 80) : typeof args.against }, pretty);
      }
      const otherDir = findSessionDir(args.against, runOpts);
      if (!otherDir) {
        return emitError(`attest diff --against ${args.against}: no session dir found.`, null, pretty);
      }
      const otherFiles = fs.readdirSync(otherDir).filter(f => f.endsWith(".json") && !f.endsWith(".sig"));
      // Comparison target: attestation.json when present, else the newest non-replay
      // JSON by captured_at, so no replay record can shadow the real attestation.
      let other = null;
      let otherPath = null;
      const otherAttestationPath = path.join(otherDir, "attestation.json");
      if (fs.existsSync(otherAttestationPath)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(otherAttestationPath, "utf8"));
          if (parsed && parsed.kind !== "replay") { other = parsed; otherPath = otherAttestationPath; }
        } catch { /* fall through to scan */ }
      }
      if (!other) {
        const candidates = [];
        for (const f of otherFiles) {
          try {
            const fp = path.join(otherDir, f);
            const parsed = JSON.parse(fs.readFileSync(fp, "utf8"));
            if (!parsed || parsed.kind === "replay") continue;
            candidates.push({ parsed, file: fp });
          } catch { /* skip malformed */ }
        }
        candidates.sort((a, b) => (b.parsed.captured_at || "").localeCompare(a.parsed.captured_at || ""));
        if (candidates[0]) { other = candidates[0].parsed; otherPath = candidates[0].file; }
      }
      if (!other) {
        return emitError(`attest diff --against ${args.against}: no attestations under that session id.`, null, pretty);
      }
      const selfResolved = resolveSelfAttestation(dir, attestations, attestationFiles);
      const self = selfResolved && selfResolved.parsed;
      if (!self) {
        return emitError(
          `attest diff ${sessionId}: no attestation found in session dir (only replay records). The session may be replay-only; verify with \`exceptd attest show ${sessionId}\`.`,
          { verb: "attest diff", session_id: sessionId, attestation_count: 0, replay_count: replays.length },
          pretty
        );
      }
      // BOTH sidecars are verified: the B-side drives the drift verdict as much as
      // the A-side, so a forged comparison attestation is refused too rather than
      // diffed under an A-only green line. Exit TAMPERED unless --force-replay.
      const aSidecarVerify = verifyAttestationSidecar(selfResolved.file);
      const bSidecarVerify = otherPath
        ? verifyAttestationSidecar(otherPath)
        : { file: null, signed: false, verified: false, reason: "no B-side attestation file resolved" };
      const aTampered = isTamperedSidecarVerify(aSidecarVerify);
      const bTampered = isTamperedSidecarVerify(bSidecarVerify);
      if ((aTampered || bTampered) && !args["force-replay"]) {
        const sides = [aTampered && "A-side", bTampered && "--against (B-side)"].filter(Boolean).join(" + ");
        process.stderr.write(`[exceptd attest diff] TAMPERED: ${sides} attestation failed Ed25519 verification. Refusing to diff against forged input. Pass --force-replay to override (the output records a_sidecar_verify + b_sidecar_verify).\n`);
        emit({
          ok: false,
          error: `attest diff: ${sides} attestation failed signature verification — refusing to diff`,
          verb: "attest diff",
          a_session: sessionId,
          b_session: args.against,
          a_sidecar_verify: aSidecarVerify,
          b_sidecar_verify: bSidecarVerify,
          hint: "If a sidecar was intentionally removed/rotated and you have inspected the attestation, pass --force-replay.",
        }, pretty);
        process.exitCode = EXIT_CODES.TAMPERED;
        return;
      }
      emit({
        verb: "attest diff",
        a_session: sessionId,
        a_playbook: self.playbook_id,
        b_session: args.against,
        a_captured: self.captured_at,
        b_captured: other.captured_at,
        a_evidence_hash: self.evidence_hash,
        b_evidence_hash: other.evidence_hash,
        status: self.evidence_hash === other.evidence_hash ? "unchanged" : "drifted",
        sidecar_verify: aSidecarVerify,
        a_sidecar_verify: aSidecarVerify,
        b_sidecar_verify: bSidecarVerify,
        // Submissions are normalized before diffing, or a flat-shape submission's
        // artifacts read as undefined and the diff returns all zeros. The catalog
        // stub stands in ONLY when BOTH sides are empty: against a populated peer it
        // manufactures phantom drift for every catalog id that peer omitted.
        ...(() => {
          const bothEmpty = !submissionHasData(self.submission) && !submissionHasData(other.submission);
          return {
            artifact_diff: diffArtifacts(
              normalizedArtifacts(self.submission, runner, self.playbook_id, bothEmpty),
              normalizedArtifacts(other.submission, runner, other.playbook_id, bothEmpty)
            ),
            signal_override_diff: diffSignalOverrides(
              normalizedSignalOverrides(self.submission, runner, self.playbook_id, bothEmpty),
              normalizedSignalOverrides(other.submission, runner, other.playbook_id, bothEmpty)
            ),
          };
        })(),
      }, pretty, renderAttestDiff);
      return;
    }
    // No --against: diff the most-recent prior attestation for the SAME playbook.
    // A comparison only — nothing is replayed.
    const selfResolved = resolveSelfAttestation(dir, attestations, attestationFiles);
    const self = selfResolved && selfResolved.parsed;
    if (!self) {
      return emitError(
        `attest diff ${sessionId}: no attestation found in session dir.`,
        { verb: "attest diff", session_id: sessionId, attestation_count: 0 },
        pretty,
      );
    }
    const prior = findLatestAttestation({
      playbookId: self.playbook_id,
      excludeSessionId: sessionId,
    });
    if (!prior) {
      emit({
        verb: "attest diff",
        a_session: sessionId,
        a_captured: self.captured_at,
        a_evidence_hash: self.evidence_hash,
        status: "no-prior",
        message: `no prior attestation found for playbook "${self.playbook_id}" other than session "${sessionId}" — this run becomes the baseline.`,
      }, pretty);
      return;
    }
    const other = prior.parsed;
    const status = self.evidence_hash === other.evidence_hash ? "unchanged" : "drifted";
    // Same dual-side tamper refusal as the --against branch: verifying only the
    // A-side lets a forged auto-selected prior produce a drift verdict at exit 0.
    // Each side verifies its own resolved path, so a run-all attestation is checked
    // against its real `<id>.json.sig`.
    const aSidecarVerify = verifyAttestationSidecar(selfResolved.file);
    const bSidecarVerify = prior.file
      ? verifyAttestationSidecar(prior.file)
      : { file: null, signed: false, verified: false, reason: "no prior attestation file resolved" };
    const aTampered = isTamperedSidecarVerify(aSidecarVerify);
    const bTampered = isTamperedSidecarVerify(bSidecarVerify);
    if ((aTampered || bTampered) && !args["force-replay"]) {
      const sides = [aTampered && "A-side", bTampered && "prior (B-side)"].filter(Boolean).join(" + ");
      process.stderr.write(`[exceptd attest diff] TAMPERED: ${sides} attestation failed Ed25519 verification. Refusing to diff against forged input. Pass --force-replay to override (the output records a_sidecar_verify + b_sidecar_verify).\n`);
      emit({
        ok: false,
        error: `attest diff: ${sides} attestation failed signature verification — refusing to diff`,
        verb: "attest diff",
        a_session: sessionId,
        b_session: prior.sessionId,
        a_sidecar_verify: aSidecarVerify,
        b_sidecar_verify: bSidecarVerify,
        hint: "If a sidecar was intentionally removed/rotated and you have inspected the attestation, pass --force-replay.",
      }, pretty);
      process.exitCode = EXIT_CODES.TAMPERED;
      return;
    }
    emit({
      verb: "attest diff",
      a_session: sessionId,
      a_playbook: self.playbook_id,
      b_session: prior.sessionId,
      a_captured: self.captured_at,
      b_captured: other.captured_at,
      a_evidence_hash: self.evidence_hash,
      b_evidence_hash: other.evidence_hash,
      status,
      // `sidecar_verify` is the A-side under its other name; the a_/b_ pair matches
      // the --against branch's shape.
      sidecar_verify: aSidecarVerify,
      a_sidecar_verify: aSidecarVerify,
      b_sidecar_verify: bSidecarVerify,
      // Peer-symmetric as above: real-vs-empty diffs against {}, not the catalog.
      ...(() => {
        const bothEmpty = !submissionHasData(self.submission) && !submissionHasData(other.submission);
        return {
          artifact_diff: diffArtifacts(
            normalizedArtifacts(self.submission, runner, self.playbook_id, bothEmpty),
            normalizedArtifacts(other.submission, runner, other.playbook_id, bothEmpty),
          ),
          signal_override_diff: diffSignalOverrides(
            normalizedSignalOverrides(self.submission, runner, self.playbook_id, bothEmpty),
            normalizedSignalOverrides(other.submission, runner, other.playbook_id, bothEmpty),
          ),
        };
      })(),
    }, pretty, renderAttestDiff);
    return;
  }

  if (subverb === "verify") {
    const crypto = require("crypto");
    const pubKeyPath = path.join(PKG_ROOT, "keys", "public.pem");
    const pubKey = fs.existsSync(pubKeyPath) ? fs.readFileSync(pubKeyPath, "utf8") : null;
    // The pin cross-check verifyAttestationSidecar() applies: a public.pem
    // diverging from the pin refuses every sidecar here too.
    const pinError = pubKey ? assertExpectedFingerprint(pubKey) : null;
    if (pinError) {
      return emitError(
        `attest verify: ${pinError}`,
        { verb: "attest verify", session_id: sessionId, pin_error: pinError },
        pretty
      );
    }
    // An unsigned attestation cannot coexist with a private key on the same host,
    // so that pairing is sidecar substitution.
    const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
    const hasPrivKey = fs.existsSync(privKeyPath);
    // A signed peer in the session means a sig was expected, so a sibling without
    // one is a deletion. With hasPrivKey this makes `attest verify` treat it as
    // tamper, as reattest does; the keyless all-unsigned case stays benign.
    let anyPeerEd25519Signed = false;
    try {
      for (const sf of fs.readdirSync(dir)) {
        if (!sf.endsWith(".sig")) continue;
        try {
          const sd = JSON.parse(fs.readFileSync(path.join(dir, sf), "utf8"));
          if (sd && sd.algorithm === "Ed25519") { anyPeerEd25519Signed = true; break; }
        } catch { /* skip unparseable sidecar */ }
      }
    } catch { /* dir unreadable — fall through */ }

    // Shared by the attestations[] and replay-records[] partitions, so a new tamper
    // class lands in one place rather than two parallel branches.
    const verifySidecar = (f) => {
      const sigPath = path.join(dir, f + ".sig");
      if (!fs.existsSync(sigPath)) {
        // Benign ONLY when none was ever expected — keyless host, no signed peer.
        // Where a sig SHOULD exist, its absence is deletion to evade detection.
        if (hasPrivKey || anyPeerEd25519Signed) {
          return { file: f, signed: false, verified: false, reason: "no .sig sidecar, but one was expected (signing key present or a signed peer attestation exists) — sidecar deletion suspected", tamper_class: "sidecar-missing" };
        }
        return { file: f, signed: false, verified: false, reason: "no .sig sidecar" };
      }
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

    // Partitioned on the parsed `kind` because the two carry different exit codes:
    // attestation tamper → exit 6, replay-record tamper → a warning at exit 0, since
    // a corrupted audit log is regenerable via `reattest` and must not fail CI.
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
      || r.tamper_class === "algorithm-unsupported"
      || r.tamper_class === "sidecar-missing";
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
      body.replay_tamper = true;
      body.warnings = ["one or more replay records failed Ed25519 verification — audit-trail corruption suspected, regenerate via reattest"];
    }
    // --require-signed makes "not Ed25519-verified" a failure (exit 1 via the
    // ok:false contract, distinct from tamper's 6). Without it, an attacker who
    // tampers the body AND deletes the .sig exits 0.
    if (!attTampered && args["require-signed"] && (attResults.length === 0 || !attResults.every(r => r.verified))) {
      body.ok = false;
      body.require_signed = true;
      // The length check is load-bearing: `[].every()` is vacuously true, so a
      // session with no attestation would otherwise pass strict mode.
      body.error = attResults.length === 0
        ? "attest verify --require-signed: no signed attestation present for this session — refusing under strict mode"
        : "attest verify --require-signed: one or more attestations are not Ed25519-verified (unsigned or missing .sig sidecar) — refusing under strict mode";
    }
    emit(body, pretty, (obj) => {
      const lines = [];
      lines.push(`attest verify: ${obj.session_id}`);
      const att = obj.results || [];
      const rep = obj.replay_results || [];
      if (att.length === 0 && rep.length === 0) {
        lines.push(`  [!! NO_DATA] no attestation files found for session.`);
        lines.push(`\n  → next: exceptd attest list                  # browse persisted sessions`);
        return lines.join("\n");
      }
      // An explicitly-unsigned attestation is not tamper — the default on a CI
      // runner with no .keys/private.pem — so the gate is tamper_class.
      const noTamper = att.every(r => !r.tamper_class) && rep.every(r => !r.tamper_class);
      const allVerified = att.every(r => r.verified) && rep.every(r => r.verified);
      const icon = obj.ok === false ? (obj.require_signed ? "[!! UNSIGNED-REJECTED]" : "[!! TAMPERED]") : (obj.replay_tamper ? "[i  REPLAY_TAMPER]" : (allVerified ? "[ok]" : "[i  UNSIGNED]"));
      lines.push(`\n${icon}  ${att.filter(r => r.verified).length}/${att.length} attestation(s) verified, ${rep.filter(r => r.verified).length}/${rep.length} replay record(s) verified`);
      // Precedence: verified, then tamper_class, then unsigned (written without a
      // key — not a failure), then a verify error (no public key, read error).
      const statusFor = (r) => {
        if (r.verified) return "[ok]";
        if (r.tamper_class) return `[!! ${r.tamper_class.toUpperCase()}]`;
        if (r.signed === false) return "[i  UNSIGNED]";
        return "[i  VERIFY-ERROR]";
      };
      for (const r of att) {
        lines.push(`  ${statusFor(r)}  ${r.file}  — ${r.reason || "(no reason)"}`);
      }
      for (const r of rep) {
        lines.push(`  ${statusFor(r)}  ${r.file}  (replay)  — ${r.reason || "(no reason)"}`);
      }
      if (obj.ok === false) {
        lines.push(`\n  → next: exceptd attest show ${obj.session_id} --pretty   # inspect the disputed file directly`);
        lines.push(`         exceptd attest list --playbook <id>                # find a non-tampered prior session for the same playbook`);
      } else if (obj.replay_tamper) {
        lines.push(`\n  → next: exceptd attest diff ${obj.session_id} --force-replay   # regenerate the replay record`);
      } else if (allVerified || noTamper) {
        lines.push(`\n  → next: exceptd attest diff ${obj.session_id}            # compare against prior session for this playbook`);
        lines.push(`         exceptd attest show ${obj.session_id} --pretty     # inspect the persisted attestation`);
      }
      return lines.join("\n");
    });
    return;
  }

  if (subverb === "export") {
    // Redaction: raw artifact `value` fields go, the verdict and proof of process
    // stay, so an auditor gets what they need without captured data that may hold
    // PII or secrets. --format is registered `multi:`, so it arrives as an array.
    let formatRaw = args.format || "json";
    if (Array.isArray(formatRaw)) formatRaw = formatRaw[0];
    const format = formatRaw === "csaf-2.0" ? "csaf" : formatRaw;
    const VALID_EXPORT_FORMATS = ["json", "csaf", "csaf-2.0"];
    if (!VALID_EXPORT_FORMATS.includes(formatRaw)) {
      const dym = suggestFlag(String(formatRaw), VALID_EXPORT_FORMATS);
      const hint = dym ? ` Did you mean "${dym}"?` : '';
      return emitError(
        `attest export: --format "${formatRaw}" not in accepted set ${JSON.stringify(VALID_EXPORT_FORMATS)}.${hint}`,
        { verb: "attest export", provided: formatRaw, accepted: VALID_EXPORT_FORMATS, did_you_mean: dym ? [dym] : [] },
        pretty,
      );
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
      // Only an exact hit/miss/inconclusive survives: the contract stores an
      // unrecognized value verbatim and `<id>__fp_checks` holds arbitrary operator
      // maps, so anything else in a "redacted" bundle becomes "[redacted]". The
      // keyname denylist matches signals_redacted; tests/cli-coverage.js asserts it.
      signal_overrides: Object.fromEntries(Object.entries((a.submission && a.submission.signal_overrides) || {})
        .filter(([k]) => !/_filter$|_key$|token|secret|password/i.test(k))
        .map(([k, v]) => [k, (v === "hit" || v === "miss" || v === "inconclusive") ? v : "[redacted]"])),
      // VALUES are redacted, not just sensitive keys dropped: a submitted signal
      // value can hold a captured credential string.
      signals_redacted: Object.fromEntries(Object.entries((a.submission && a.submission.signals) || {})
        .filter(([k]) => !/_filter$|_key$|token|secret|password/i.test(k))
        .map(([k]) => [k, "[redacted]"])),
      precondition_checks: (a.submission && a.submission.precondition_checks) || {},
    }));

    if (format === "csaf") {
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
        redaction_policy: "v0.10.3-default — artifact values stripped; signal_overrides reduced to hit/miss/inconclusive verdicts (free-form values redacted); precondition_checks + evidence_hash + signature preserved.",
        attestations: redacted,
      }, pretty);
    }
    return;
  }

  // Unreachable while the membership check stays ahead of the dispatch.
  return emitError(`attest: unknown subverb "${subverb}".`, { verb: "attest", subverb_input: subverb }, pretty);
}

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
    const inds = (pb.phases?.detect?.indicators || []).filter(i => i && i.id);
    if (inds.length === 0) return null;
    return Object.fromEntries(inds.map(i => [i.id, 'inconclusive']));
  } catch { return null; }
}
// True when a submission carried artifacts, signal_overrides or observations. Diff
// symmetry hinges on it: the catalog stub may stand in for an empty side only when
// BOTH sides are empty, else every catalog id the peer omitted reads as drift.
function submissionHasData(submission) {
  if (!submission || typeof submission !== "object") return false;
  const nonEmpty = (o) => o && typeof o === "object" && Object.keys(o).length > 0;
  return nonEmpty(submission.artifacts)
    || nonEmpty(submission.signal_overrides)
    || nonEmpty(submission.observations);
}
// attest diff compares artifacts by map key, and normalizeSubmission keys flat-shape
// artifacts by the operator-chosen OBSERVATION key, not the stable indicator id — so
// identical evidence under different observation keys diffs as all-added/all-removed.
// Re-keys from _signal_origins, keeping the original where there is no binding.
// Diff-only: neither normalizeSubmission's map nor the evidence_hash changes.
function rekeyArtifactsByStableId(artifacts, signalOrigins) {
  if (!artifacts || !signalOrigins || typeof signalOrigins !== "object") return artifacts || {};
  const obsKeyToIndicator = {};
  for (const [indicatorId, obsKey] of Object.entries(signalOrigins)) {
    if (typeof obsKey === "string") obsKeyToIndicator[obsKey] = indicatorId;
  }
  const originalKeys = new Set(Object.keys(artifacts));
  const out = {};
  for (const [k, v] of Object.entries(artifacts)) {
    const mapped = obsKeyToIndicator[k];
    // Re-key ONLY where it cannot drop an artifact: the indicator id must not be a
    // distinct original key nor claimed by an earlier re-key. Either collision keeps
    // the original key, so nothing is overwritten.
    const stable = (mapped && mapped !== k && !originalKeys.has(mapped)
      && !Object.prototype.hasOwnProperty.call(out, mapped)) ? mapped : k;
    out[stable] = v;
  }
  return out;
}
function normalizedArtifacts(submission, runner, playbookId, applyEmptyFallback = true) {
  if (!submission || typeof submission !== "object") {
    return applyEmptyFallback ? (_playbookArtifactCatalog(runner, playbookId) || {}) : {};
  }
  if (submission.artifacts && Object.keys(submission.artifacts).length > 0) return submission.artifacts;
  if (submission.observations && Object.keys(submission.observations).length > 0) {
    // The real playbook is loaded so look.artifacts can map the observations; a
    // normalize yielding an empty map falls through to the direct mapping below.
    if (playbookId) {
      try {
        const pb = runner.loadPlaybook ? runner.loadPlaybook(playbookId) : null;
        if (pb) {
          const norm = runner.normalizeSubmission({ observations: submission.observations }, pb);
          if (norm && norm.artifacts && Object.keys(norm.artifacts).length > 0) {
            return rekeyArtifactsByStableId(norm.artifacts, norm._signal_origins);
          }
        }
      } catch { /* fall through */ }
    }
    const out = {};
    for (const [k, v] of Object.entries(submission.observations)) {
      out[k] = (v && typeof v === "object") ? v : { value: v };
    }
    return out;
  }
  // Empty submission: the catalog stub stands in only when the peer is empty too,
  // else an empty map yields genuine added/removed, not one "added" per catalog id.
  return applyEmptyFallback ? (_playbookArtifactCatalog(runner, playbookId) || {}) : {};
}
function normalizedSignalOverrides(submission, runner, playbookId, applyEmptyFallback = true) {
  if (!submission || typeof submission !== "object") {
    return applyEmptyFallback ? (_playbookSignalCatalog(runner, playbookId) || {}) : {};
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
  // Same peer-symmetric gate as normalizedArtifacts.
  return applyEmptyFallback ? (_playbookSignalCatalog(runner, playbookId) || {}) : {};
}

/**
 * Order-insensitive serializer for the per-field artifact comparison: keys sort
 * recursively, matching the canonical form evidence_hash uses, so `{captured, value}`
 * and `{value, captured}` don't report "changed" against a status of "unchanged".
 * Depth-bounded — a throw means "cannot canonicalize", and the caller falls back.
 */
function stableArtifactStringify(v, depth = 0) {
  if (depth > 200) throw new Error("artifact too deep to canonicalize");
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) {
    return "[" + v.map((x) => stableArtifactStringify(x, depth + 1)).join(",") + "]";
  }
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableArtifactStringify(v[k], depth + 1)).join(",") + "}";
}

function artifactsDiffer(av, bv) {
  try {
    return stableArtifactStringify(av) !== stableArtifactStringify(bv);
  } catch {
    // Canonicalization bailed; an order-sensitive compare never masks a difference.
    return JSON.stringify(av) !== JSON.stringify(bv);
  }
}

/** Per-artifact diff keyed by artifact id, so `attest diff` gives field context. */
function diffArtifacts(a, b) {
  a = a || {}; b = b || {};
  const allIds = new Set([...Object.keys(a), ...Object.keys(b)]);
  // total_compared disambiguates all-zero counts: "0 unchanged of how many?"
  const out = { total_compared: allIds.size, added: [], removed: [], changed: [], unchanged_count: 0 };
  for (const id of allIds) {
    const av = a[id], bv = b[id];
    if (!av && bv) {
      out.added.push({ id, captured: !!bv.captured, value_preview: artifactPreview(bv) });
    } else if (av && !bv) {
      out.removed.push({ id, captured: !!av.captured, value_preview: artifactPreview(av) });
    } else if (av && bv && artifactsDiffer(av, bv)) {
      out.changed.push({
        id,
        a_captured: !!av.captured, b_captured: !!bv.captured,
        a_value_preview: artifactPreview(av), b_value_preview: artifactPreview(bv),
      });
    } else if (av && bv) {
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
    // Deep and order-insensitive: signal_overrides hold OBJECT values (the
    // `__fp_checks` maps), where `!==` reports identical content as "changed".
    if (artifactsDiffer(a[id], b[id])) out.changed.push({ id, a: a[id] ?? null, b: b[id] ?? null });
    else out.unchanged_count++;
  }
  return out;
}

function previewValue(v) {
  if (v === null || v === undefined) return null;
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 80 ? s.slice(0, 80) + "…" : s;
}

// `.value` is the canonical carrier, but an observation may store its match under
// another key, so the fallback previews every evidence-bearing key: otherwise a
// non-`value` carrier renders null and hides content the compare flagged.
function artifactPreview(art) {
  if (art === null || typeof art !== "object" || Array.isArray(art)) return previewValue(art);
  if (art.value !== undefined && art.value !== null) return previewValue(art.value);
  const { captured, captured_at, _captured_at, value, ...evidence } = art;
  const keys = Object.keys(evidence);
  if (keys.length === 0) return null;
  return previewValue(evidence);
}

// Context-aware playbook recommender: sniffs the cwd, reads /etc/os-release on Linux.
function cmdDiscover(runner, args, runOpts, pretty) {
  let cwd = process.cwd();
  // `--cwd ""` is falsy: without this branch it scans process.cwd() instead.
  if (args.cwd === "") {
    return emitError(`discover: --cwd was given an empty value; pass an existing directory path`, { verb: "discover" }, pretty);
  }
  if (args.cwd) {
    const resolved = path.resolve(String(args.cwd));
    let stat;
    try { stat = fs.statSync(resolved); }
    catch (e) { return emitError(`discover: --cwd "${args.cwd}" does not exist (${e.message})`, { verb: "discover", provided_cwd: args.cwd }, pretty); }
    if (!stat.isDirectory()) return emitError(`discover: --cwd "${args.cwd}" is not a directory`, { verb: "discover", provided_cwd: args.cwd }, pretty);
    cwd = resolved;
  }
  const wantJson = !!args.json || !!args.pretty;
  const indent = !!args.pretty;

  // Each probe swallows its own errors, so one permission error cannot poison
  // the whole detection.
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

  try {
    const tfFiles = fs.readdirSync(cwd).filter(f => f.endsWith(".tf"));
    if (tfFiles.length) detected.push(`*.tf (${tfFiles.length})`);
  } catch { /* swallow */ }

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

  const hostPlatform = process.platform;
  let hostDistro = null;
  if (hostPlatform === "linux") {
    try {
      const osRelease = fs.readFileSync("/etc/os-release", "utf8");
      if (osRelease) {
        const idMatch = osRelease.match(/^ID=(.+)$/m);
        const verMatch = osRelease.match(/^VERSION_ID=(.+)$/m);
        const prettyMatch = osRelease.match(/^PRETTY_NAME=(.+)$/m);
        hostDistro = {
          id: idMatch ? idMatch[1].replace(/^"|"$/g, "") : null,
          version_id: verMatch ? verMatch[1].replace(/^"|"$/g, "") : null,
          pretty_name: prettyMatch ? prettyMatch[1].replace(/^"|"$/g, "") : null,
        };
      }
    } catch { /* swallow */ }
  }

  const isRepo = detected.includes(".git/");
  const hasNodeManifest = detected.includes("package.json");
  const hasNodeLockfile = detected.includes("package-lock.json")
    || detected.includes("yarn.lock") || detected.includes("pnpm-lock.yaml");
  const hasNode = hasNodeManifest || hasNodeLockfile;
  const hasPython = detected.includes("pyproject.toml") || detected.includes("requirements.txt")
    || detected.includes("Pipfile");
  const hasRust = detected.includes("Cargo.toml");
  const hasGo = detected.includes("go.mod");
  const hasProject = hasNode || hasPython || hasRust || hasGo;
  // The root-only probes above miss a subdir Dockerfile, so this delegates to what
  // the containers collector walks; otherwise discover under-recommends it.
  let containerArtifacts = [];
  try {
    const containersMod = require(path.join(PKG_ROOT, "lib", "collectors", "containers.js"));
    if (typeof containersMod.hasContainerArtifacts === "function") {
      containerArtifacts = containersMod.hasContainerArtifacts(cwd);
    }
  } catch { /* best-effort detection; never break discover on a walk error */ }
  if (containerArtifacts.length && !detected.includes("Dockerfile")
      && !detected.includes("docker-compose.yml") && !detected.includes("docker-compose.yaml")) {
    detected.push(`container-config (${containerArtifacts[0]})`);
  }
  const hasContainers = detected.includes("Dockerfile") || detected.includes("docker-compose.yml")
    || detected.includes("docker-compose.yaml") || containerArtifacts.length > 0;
  const isLinux = hostPlatform === "linux";

  let hasGithubWorkflows = false;
  try {
    const wfDir = path.join(cwd, ".github", "workflows");
    if (fs.existsSync(wfDir) && fs.statSync(wfDir).isDirectory()) {
      const entries = fs.readdirSync(wfDir).filter(f => /\.(ya?ml)$/i.test(f));
      if (entries.length > 0) hasGithubWorkflows = true;
    }
  } catch { /* swallow */ }

  let hasMcpClientConfig = false;
  const homeForProbe = process.env.HOME || process.env.USERPROFILE || null;
  if (homeForProbe) {
    const mcpProbes = [
      path.join(homeForProbe, ".cursor", "mcp.json"),
      path.join(homeForProbe, ".config", "claude"),
      path.join(homeForProbe, ".claude"),
      path.join(homeForProbe, ".codeium", "windsurf", "mcp_config.json"),
      path.join(homeForProbe, ".gemini", "settings.json"),
    ];
    for (const p of mcpProbes) {
      try { if (fs.existsSync(p)) { hasMcpClientConfig = true; break; } } catch { /* swallow */ }
    }
  }

  // A proxy for a shell-driven workflow that might export AI API keys; the ai-api
  // collector checks rc files and dotfiles regardless.
  let hasShellRc = false;
  if (homeForProbe) {
    const rcProbes = [".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile"];
    for (const f of rcProbes) {
      try { if (fs.existsSync(path.join(homeForProbe, f))) { hasShellRc = true; break; } } catch { /* swallow */ }
    }
  }

  const recs = [];
  const seen = new Set();
  function recommend(id, reason) {
    if (seen.has(id)) return;
    seen.add(id);
    recs.push({ id, reason });
  }

  if (isRepo && hasProject) {
    const langs = [hasNode && "node", hasPython && "python", hasRust && "rust", hasGo && "go"]
      .filter(Boolean).join("/");
    recommend("secrets", `git repo + ${langs} project → check for committed credentials`);
    recommend("sbom", `git repo + ${langs} project → SBOM + supply-chain integrity`);
    recommend("library-author", `git repo + ${langs} project → publisher-side audit`);
    recommend("crypto-codebase", `git repo + ${langs} project → cryptographic primitive review`);
  }
  if (hasContainers) {
    recommend("containers", "Dockerfile / docker-compose present → container security review");
  }
  if (hasGithubWorkflows) {
    recommend("cicd-pipeline-compromise", ".github/workflows/ present → CI/CD posture (fork-PR / OIDC / floating-tag)");
  }
  if (hasMcpClientConfig) {
    recommend("mcp", "MCP client config present in home → MCP supply-chain audit");
  }
  if (hasShellRc) {
    recommend("ai-api", "shell rc present in home → AI API key + cred-carrier audit");
  }
  if (isLinux) {
    recommend("kernel", "Linux host detected → kernel LPE / privilege escalation triage");
    recommend("hardening", "Linux host detected → system hardening review");
    recommend("runtime", "Linux host detected → runtime behavior review");
    recommend("cred-stores", "Linux host detected → credential store review");
    recommend("crypto", "Linux host detected → host crypto posture (OpenSSL / sshd PQC readiness)");
  }
  recommend("framework", "cross-cutting: framework correlation always applicable");

  // Each recommendation carries whether a collector exists, so the operator sees
  // one pipe away from running it.
  const collectorsDir = path.join(PKG_ROOT, "lib", "collectors");
  for (const rec of recs) {
    const collectorPath = path.join(collectorsDir, rec.id + ".js");
    const hasCollector = fs.existsSync(collectorPath);
    rec.collector_available = hasCollector;
    rec.collect_cmd = hasCollector ? `exceptd collect ${rec.id}` : null;
  }

  // Conditional: `run --scope code` from a cwd with no code runs every code-scoped
  // playbook against an empty tree.
  const recHasCodeScope = recs.some(r => ["secrets", "sbom", "library-author", "crypto-codebase", "containers", "cicd-pipeline-compromise"].includes(r.id));
  const nextSteps = [
    "exceptd brief <playbook>       # learn what a playbook checks",
    "exceptd run <playbook>          # run it",
  ];
  if (recHasCodeScope) {
    nextSteps.push("exceptd run --scope code        # run all code-scoped playbooks (those applicable to this cwd)");
    nextSteps.push("exceptd ci --scope code         # CI-gate against all code-scoped playbooks");
  }

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

  // The orchestrator runs as a subprocess, so one bad scanner cannot kill discover.
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

  const lines = [];
  lines.push("exceptd discover");
  lines.push(`  cwd:            ${cwd}`);
  if (gitRemote) lines.push(`  git remote:     ${gitRemote}`);
  lines.push(`  platform:       ${hostPlatform}${hostDistro && hostDistro.pretty_name ? "  (" + hostDistro.pretty_name + ")" : ""}`);
  lines.push(`  detected:       ${detected.length ? detected.join(", ") : "(nothing recognized)"}`);
  lines.push("");
  lines.push(`Recommended playbooks (${recs.length}):`);
  for (const r of recs) {
    const tag = r.collector_available ? " [collector]" : "";
    lines.push(`  - ${(r.id + tag).padEnd(32)} ${r.reason}`);
    if (r.collector_available) {
      lines.push(`      → ${r.collect_cmd} | exceptd run ${r.id} --evidence -`);
    }
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

// One-shot health check: signatures + currency + cve/rfc catalogs + signing status.
// Each subcheck is fault-tolerant — a failure surfaces in the JSON, never a crash.
function cmdDoctor(runner, args, runOpts, pretty) {
  const wantJson = !!args.json || !!args.pretty;
  const indent = !!args.pretty;

  // An unknown flag is refused rather than falling through to the full default
  // scan, which exits 0 while the operator believes they ran a targeted check.
  const KNOWN_DOCTOR_FLAGS = new Set([
    "json", "pretty", "fix", "air-gap",
    "signatures", "currency", "cves", "rfcs", "registry-check",
    "ai-config", "collectors", "exit-codes", "shipped-tarball",
    // Global flags the parser injects on any verb; in sync with
    // VERB_FLAG_ALLOWLIST._global in lib/flag-suggest.js.
    "_", "json-stdout-only", "_jsonMode", "quiet", "verbose",
  ]);
  const unknownFlags = Object.keys(args).filter(k => !KNOWN_DOCTOR_FLAGS.has(k));
  if (unknownFlags.length > 0) {
    const dym = unknownFlags.map(f => {
      const candidates = [...KNOWN_DOCTOR_FLAGS].filter(k => typeof k === "string" && k.length >= 2 && (k.includes(f) || f.includes(k) || levenshtein1(f, k) <= 1));
      return { flag: `--${f}`, did_you_mean: candidates.slice(0, 3).map(c => `--${c}`) };
    });
    return emitError(`doctor: unknown flag(s): ${unknownFlags.map(f => `--${f}`).join(", ")}`,
      { verb: "doctor", unknown_flags: dym, known_flags: [...KNOWN_DOCTOR_FLAGS].filter(k => k !== "_" && !k.startsWith("_") && k !== "json-stdout-only").sort().map(k => `--${k}`) },
      pretty);
  }

  // Dumps the canonical exit-code table, so docs cannot drift from runtime.
  if (args["exit-codes"]) {
    emit({ verb: "doctor", exit_codes: listExitCodes() }, pretty);
    return;
  }

  // Selective subchecks: any flag runs only what it names; none runs the default set.
  const onlySigs = !!args.signatures;
  const onlyCurrency = !!args.currency;
  const onlyCves = !!args.cves;
  const onlyRfcs = !!args.rfcs;
  const onlyAiConfig = !!args["ai-config"];
  const onlyCollectors = !!args.collectors;
  const anySelected = onlySigs || onlyCurrency || onlyCves || onlyRfcs || onlyAiConfig || onlyCollectors;
  // --shipped-tarball runs inside the signatures check, so it implies it:
  // `doctor --shipped-tarball --cves` would otherwise skip the round-trip.
  const runSigs = !anySelected || onlySigs || !!args["shipped-tarball"];
  const runCurrency = !anySelected || onlyCurrency;
  const runCves = !anySelected || onlyCves;
  const runRfcs = !anySelected || onlyRfcs;
  const runCollectors = !anySelected || onlyCollectors;
  const runSigning = !anySelected;
  // Opt-in: probing AI-assistant config permissions never happens by default.
  const runAiConfig = onlyAiConfig;

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

      // The verify-as-shipped gate: sign, pack, extract, verify. A source-tree verify
      // can pass while the shipped tarball fails, and only this catches that class.
      // Opt-in because npm pack costs seconds and tempdir churn.
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
        // The tier boundary lives in lib/currency-severity.js, testable without a
        // manifest whose dates move under the test.
        const { classifyCurrency } = require(path.join(PKG_ROOT, "lib", "currency-severity.js"));
        const { ok, severity, stale, drifting, actionable, critical } =
          classifyCurrency(parsed.currency_report, parsed.action_required);
        // Freshest and stalest last_threat_review, so "is my data stale?" is
        // answerable without the full report; null when the report omits the date.
        const dates = parsed.currency_report
          .map(s => s.last_threat_review)
          .filter(d => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d))
          .sort();
        const minDaysSince = dates.length ? Math.floor((Date.now() - new Date(dates[0]).getTime()) / 86400000) : null;
        checks.currency = {
          ok,
          // Drift with nothing past its review window warns: `all_green:false`
          // surfaces it while the exit code stays 0.
          ...(severity ? { severity } : {}),
          total_skills: parsed.currency_report.length,
          stale_skills: stale.map(s => s.skill),
          drifting_skills: drifting.map(s => s.skill),
          action_required_skills: actionable.map(s => s.skill),
          critical_stale: critical.map(s => s.skill),
          critical_count: parsed.critical_count || 0,
          oldest_last_threat_review: dates[0] || null,
          newest_last_threat_review: dates[dates.length - 1] || null,
          max_days_since_review: minDaysSince,
          checked_at: new Date().toISOString(),
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
      // validate-cves doesn't emit JSON; parse text for drift signal.
      const res = spawnSync(process.execPath, [orchPath, "validate-cves", "--offline"], {
        encoding: "utf8",
        cwd: PKG_ROOT,
        timeout: 30000,
      });
      const text = (res.stdout || "") + (res.stderr || "");
      const driftMatch = text.match(/drift[:\s]+(\d+)/i);
      const ok = res.status === 0;
      // The totals come from the catalog file, not the validate-cves text: scraping
      // counts CVE-* only, so MAL-* and other families vanish from the report.
      let total = null;
      let cve_count = null;
      let mal_count = null;
      let by_prefix = null;
      try {
        const catalog = require(path.join(PKG_ROOT, "data", "cve-catalog.json"));
        const keys = Object.keys(catalog).filter((k) => !k.startsWith("_"));
        cve_count = keys.filter((k) => k.startsWith("CVE-")).length;
        mal_count = keys.filter((k) => k.startsWith("MAL-")).length;
        total = keys.length;
        // Enumerated from the data, so a new prefix surfaces in the breakdown
        // instead of vanishing into the total-minus-named-prefixes gap.
        by_prefix = {};
        for (const k of keys) {
          const m = k.match(/^([A-Z]+)-/);
          const p = m ? m[1] : "OTHER";
          by_prefix[p] = (by_prefix[p] || 0) + 1;
        }
      } catch { /* fall through with nulls */ }
      checks.cves = {
        ok,
        total,
        cve_count,
        mal_count,
        by_prefix,
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
      const driftMatch = text.match(/drift[:\s]+(\d+)/i);
      const ok = res.status === 0;
      // Counted from the catalog, as in the CVE subcheck: scraping `^RFC-\d+` rows
      // drops the CSAF / DRAFT / ISO families entirely.
      const rfcCatalogPath = path.join(PKG_ROOT, "data", "rfc-references.json");
      let rfcTotal = 0;
      const byPrefix = {};
      let rfcMtime = null;
      let rfcAgeDays = null;
      try {
        const catalog = JSON.parse(fs.readFileSync(rfcCatalogPath, "utf8"));
        for (const k of Object.keys(catalog)) {
          if (k.startsWith("_")) continue;
          rfcTotal++;
          const prefix = (k.match(/^[A-Za-z]+/) || ["?"])[0].toUpperCase();
          byPrefix[prefix] = (byPrefix[prefix] || 0) + 1;
        }
        const st = fs.statSync(rfcCatalogPath);
        rfcMtime = st.mtime.toISOString();
        rfcAgeDays = Math.floor((Date.now() - st.mtimeMs) / 86400000);
      } catch { /* file may be absent on exotic installs — total stays 0 */ }
      checks.rfcs = {
        ok,
        total: rfcTotal,
        by_prefix: byPrefix,
        drift: driftMatch ? Number(driftMatch[1]) : 0,
        index_last_modified: rfcMtime,
        index_age_days: rfcAgeDays,
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
      // PKG_ROOT only — the path maybeSignAttestation() and `attest verify` use.
      // A cwd-resident key would read as "signing enabled" while verification
      // uses a different key.
      const keyPath = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath);
      // A consumer install has no business signing, so the missing-key warning
      // would read as a problem on a fresh global install. Two signals, either
      // sufficient, because a node_modules check alone is fragile under
      // symlink-resolved paths (npm link, workspaces). A contributor checkout keeps
      // severity:warn: the attestation pipeline writes unsigned files without a key.
      const pkgRootSegments = PKG_ROOT.split(/[\\/]/);
      const containsNodeModulesSegment = pkgRootSegments.includes("node_modules");
      const parentIsBlamejsScope = path.basename(path.dirname(PKG_ROOT)) === "@blamejs";
      const isConsumerInstall = containsNodeModulesSegment || parentIsBlamejsScope;
      checks.signing = {
        ok: present, // not green if the key is missing on a contributor checkout
        severity: present
          ? "info"
          : (isConsumerInstall ? "info" : "warn"),
        private_key_present: present,
        can_sign_attestations: present,
        install_mode: isConsumerInstall ? "consumer" : "contributor",
        ...(present
          ? {}
          : isConsumerInstall
            ? { hint: "consumer install — signing is intentionally not enabled. Set up a contributor checkout if you need to sign your own evidence bundles or skill bodies." }
            : { hint: "run `exceptd doctor --fix` to generate an Ed25519 keypair and sign skills (or `node $(exceptd path)/lib/sign.js generate-keypair` from a contributor checkout)" }),
      };
    } catch (e) {
      checks.signing = { ok: false, error: e.message };
    }
  }

  // --registry-check queries npm for the latest published version and days behind.
  // Opt-in; routed through a child process to keep cmdDoctor synchronous and bound
  // the network timeout.
  if (args["registry-check"]) {
    // Skipped, not errored: the operator chose air-gap, and a network-error result
    // would read as a failure.
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

  // AI-assistant config permission audit (NEW-CTRL-050): walks the vendor config
  // roots for files holding MCP tokens or API keys and reports any not at 0600.
  // MAL-2026-SHAI-HULUD-OSS reads these at unprivileged-process scope.
  if (runAiConfig) {
    const os = require('os');
    const HOME = os.homedir();
    const AI_CONFIG_DIRS = [
      { dir: '.claude', display: '~/.claude' },
      { dir: '.cursor', display: '~/.cursor' },
      { dir: '.codeium', display: '~/.codeium' },
      { dir: '.aider', display: '~/.aider' },
      { dir: '.continue', display: '~/.continue' },
    ];
    // Both mcp_config forms are needed: the bare filename Windsurf installs, and
    // the trailing `.mcp_config.json` for vendor variants that prefix a tag.
    const SENSITIVE_PATTERNS = [
      /^settings\.json$/,
      /^mcp\.json$/,
      /^mcp_config\.json$/,
      /\.mcp_config\.json$/,
      /^api_key/,
      /\.token$/,
      /\.credentials$/,
    ];
    const findings = [];
    let scannedDirs = 0;
    let scannedFiles = 0;
    let walkAborted = false;
    // The walk is bounded: unbounded, it reads tens of thousands of conversation
    // logs and cache entries under ~/.claude. Every SENSITIVE_PATTERNS file sits
    // within ~3 levels of a config root; the skipped dirs carry no credentials.
    const MAX_DEPTH = 4;
    const MAX_FILES = 5000;
    const SKIP_DIR_NAMES = new Set([
      'node_modules', '.git', '.cache', 'logs', 'log',
      'sessions', 'session', 'transcripts', 'transcript',
      'conversations', 'history', 'tmp', 'temp', 'cache',
    ]);
    function walk(absDir, displayRoot, rel, depth = 0) {
      if (walkAborted) return;
      if (depth > MAX_DEPTH) return;
      if (scannedFiles > MAX_FILES) {
        walkAborted = true;
        return;
      }
      if (!fs.existsSync(absDir)) return;
      let entries;
      try { entries = fs.readdirSync(absDir, { withFileTypes: true }); }
      catch { return; }
      for (const e of entries) {
        if (walkAborted) return;
        if (e.isDirectory() && SKIP_DIR_NAMES.has(e.name.toLowerCase())) continue;
        const childAbs = path.join(absDir, e.name);
        const childRel = rel ? rel + '/' + e.name : e.name;
        if (e.isDirectory()) {
          walk(childAbs, displayRoot, childRel, depth + 1);
        } else if (e.isFile()) {
          scannedFiles++;
          // Checked right after the increment: waiting for the next recursive call
          // lets one large directory run past the bound.
          if (scannedFiles > MAX_FILES) {
            walkAborted = true;
            return;
          }
          if (!SENSITIVE_PATTERNS.some((re) => re.test(e.name))) continue;
          let st;
          try { st = fs.statSync(childAbs); } catch { continue; }
          if (process.platform === 'win32') {
            const aclCheck = checkWindowsAcl(childAbs);
            if (aclCheck.ok) continue;
            // No fix_command unless the grant principal resolves: an unset USERNAME
            // interpolates "undefined:F", and icacls applies /inheritance:r before
            // failing on the account — stripping every inherited entry and locking
            // the file out. os.userInfo() resolves when the env var is absent.
            const aclUser = process.env.USERNAME || (() => {
              try { return require('os').userInfo().username; } catch { return null; }
            })();
            findings.push({
              path: `${displayRoot}/${childRel}`,
              mode: null,
              severity: 'warn',
              issue: 'broader_than_user_only_acl',
              acl_extra_principals: aclCheck.extraPrincipals,
              hint: `icacls "${childAbs}" /inheritance:r /grant:r %USERNAME%:F  # NEW-CTRL-050: AI-assistant configs holding MCP tokens / API keys must restrict ACL to the workstation user`,
              ...(aclUser
                ? { fix_command: ['icacls', childAbs, '/inheritance:r', '/grant:r', `${aclUser}:F`] }
                : { fix_unavailable: 'current user name unresolvable (USERNAME unset); apply the hint manually' }),
            });
            continue;
          }
          const mode = st.mode & 0o777;
          if ((mode & 0o077) !== 0) {
            findings.push({
              path: `${displayRoot}/${childRel}`,
              mode: '0' + mode.toString(8),
              severity: 'warn',
              issue: 'group_or_other_readable',
              hint: `chmod 600 '${childAbs}'  # NEW-CTRL-050: AI-assistant configs holding MCP tokens / API keys must be 0600 to defeat unprivileged exfil`,
              fix_chmod: 0o600,
              fix_abs_path: childAbs,
            });
          }
        }
      }
    }
    for (const d of AI_CONFIG_DIRS) {
      const abs = path.join(HOME, d.dir);
      if (fs.existsSync(abs)) {
        scannedDirs++;
        walk(abs, d.display, '');
      }
    }
    const errorFindings = findings.filter((f) => f.severity === 'warn');

    // --fix applies the per-finding command (chmod 600 on POSIX, icacls on Windows)
    // and records the attempt, so the report shows which fixes landed.
    let fixesApplied = 0;
    let fixesFailed = 0;
    if (args.fix && errorFindings.length > 0) {
      const childProc = require('child_process');
      for (const f of errorFindings) {
        if (f.fix_chmod && f.fix_abs_path) {
          try {
            fs.chmodSync(f.fix_abs_path, f.fix_chmod);
            f.fix_status = 'chmod_applied';
            fixesApplied++;
          } catch (e) {
            f.fix_status = 'chmod_failed';
            f.fix_error = e.message;
            fixesFailed++;
          }
          continue;
        }
        if (f.fix_command) {
          try {
            childProc.execFileSync(f.fix_command[0], f.fix_command.slice(1), {
              stdio: ['ignore', 'ignore', 'pipe'],
              timeout: 5000,
            });
            f.fix_status = 'icacls_applied';
            fixesApplied++;
          } catch (e) {
            f.fix_status = 'icacls_failed';
            f.fix_error = (e && e.message) || String(e);
            fixesFailed++;
          }
        }
      }
    }

    // A truncated walk means the audit is INCOMPLETE — a sensitive file past the
    // cap went unseen — so it warns rather than reporting a clean pass.
    const baseSeverity = errorFindings.length > 0 && fixesFailed > 0 ? 'warn' : (errorFindings.length > 0 && !args.fix ? 'warn' : 'info');
    checks.ai_config = {
      ok: (errorFindings.length === 0 || (args.fix && fixesFailed === 0)) && !walkAborted,
      severity: walkAborted && baseSeverity === 'info' ? 'warn' : baseSeverity,
      scanned_dirs: scannedDirs,
      scanned_files: scannedFiles,
      walk_truncated: walkAborted,
      walk_caps: { max_depth: MAX_DEPTH, max_files: MAX_FILES },
      directories_inspected: AI_CONFIG_DIRS.map((d) => d.display),
      sensitive_patterns: ['settings.json', 'mcp.json', '*.mcp_config.json', 'api_key*', '*.token', '*.credentials'],
      findings,
      platform: process.platform,
      control_reference: 'NEW-CTRL-050 (MAL-2026-SHAI-HULUD-OSS lesson)',
      ...(args.fix ? { fix_applied: fixesApplied, fix_failed: fixesFailed } : {}),
    };
    if (errorFindings.length > 0 && (!args.fix || fixesFailed > 0)) issues.push('ai_config');
  }

  // Collector-layer health gate: every playbook needs `lib/collectors/<id>.js` whose
  // `playbook_id` matches the filename and which exports `collect`. policy_skips is
  // the catalogued set of judgement-shaped playbooks that have none by design.
  if (runCollectors) {
    try {
      const playbookDir = path.join(PKG_ROOT, "data", "playbooks");
      const collectorDir = path.join(PKG_ROOT, "lib", "collectors");
      const POLICY_SKIPS = [
        "framework", "ransomware", "ai-discovered-cve-triage",
        "cloud-iam-incident", "idp-incident", "identity-sso-compromise",
        "llm-tool-use-exfil", "supply-chain-recovery",
        "post-quantum-migration", "webhook-callback-abuse",
        "vc-wallet-trust", "mail-server-hardening", "network-trust",
        "audit-log-integrity", "self-update-integrity", "multitenancy-isolation",
        "decompression-dos", "log-injection-telemetry", "privacy-consent-ops",
      ];
      const playbookFiles = fs.readdirSync(playbookDir)
        .filter(f => f.endsWith(".json") && !f.startsWith("_"))
        .map(f => f.replace(/\.json$/, ""))
        .sort();
      const without_collector = [];
      const load_errors = [];
      let with_collector = 0;
      for (const pid of playbookFiles) {
        const collectorPath = path.join(collectorDir, pid + ".js");
        if (!fs.existsSync(collectorPath)) { without_collector.push(pid); continue; }
        try {
          delete require.cache[require.resolve(collectorPath)];
          const mod = require(collectorPath);
          if (mod.playbook_id !== pid) {
            load_errors.push({ id: pid, error: `playbook_id mismatch: module exports "${mod.playbook_id}"` });
          } else if (typeof mod.collect !== "function") {
            load_errors.push({ id: pid, error: "collect is not a function" });
          } else {
            with_collector++;
          }
        } catch (e) {
          load_errors.push({ id: pid, error: `require failed: ${e.message}` });
        }
      }
      const ok = load_errors.length === 0;
      // `without_collector` equalling POLICY_SKIPS is coincidence, not invariant: a
      // playbook can lose a collector by accident, or a skipped one gain one.
      // `unexplained_missing_collectors` is the operator-actionable difference.
      const policySkipSet = new Set(POLICY_SKIPS);
      const unexplained_missing_collectors = without_collector.filter(p => !policySkipSet.has(p));
      // An unexplained missing collector fails the check, or automation misses the
      // regression the field exists for. Load errors are "error"; a missing
      // collector is "warn" — a build-time gap, not a crash.
      const collectorOk = ok && unexplained_missing_collectors.length === 0;
      const collectorSeverity = load_errors.length > 0 ? "error"
        : unexplained_missing_collectors.length > 0 ? "warn"
        : "info";
      checks.collectors = {
        ok: collectorOk,
        severity: collectorSeverity,
        total_playbooks: playbookFiles.length,
        with_collector,
        without_collector,
        unexplained_missing_collectors,
        load_errors,
        policy_skips: POLICY_SKIPS.sort(),
      };
      if (!collectorOk) issues.push("collectors");
    } catch (e) {
      checks.collectors = { ok: false, severity: "error", error: e.message };
      issues.push("collectors");
    }
  }

  // Checks split into errors and warnings; all_green requires zero of both. The rule
  // is severity-first and lives in lib/doctor-bucketing.js: a check with `ok: false`
  // and `severity: "warn"` routes to warning_checks. Checking `ok === false` first
  // makes a fresh global install report failed_checks:["signing"] with 0 warnings.
  const { bucketChecks } = require(path.join(PKG_ROOT, "lib", "doctor-bucketing.js"));
  let { warnList, errorList } = bucketChecks(checks);
  let allGreen = errorList.length === 0 && warnList.length === 0;
  let localVersion = null;
  try {
    localVersion = require(path.join(PKG_ROOT, "package.json")).version || null;
  } catch { /* package.json unreadable — fall through */ }
  const out = {
    verb: "doctor",
    local_version: localVersion,
    checks,
    summary: {
      all_green: allGreen,
      issues_count: errorList.length,
      warnings_count: warnList.length,
      failed_checks: errorList,
      warning_checks: warnList,
    },
  };

  // --fix runs BEFORE the JSON early-return, so `doctor --fix --json` fixes rather
  // than reports, and the JSON reflects the post-fix state. lib/sign.js refuses to
  // generate over an existing keys/public.pem — that orphans every shipped
  // signature. Key generation chains sign-all, or doctor reports 0/N passing.
  if (args.fix && checks.signing && !checks.signing.private_key_present) {
    const pubKeyExists = fs.existsSync(path.join(PKG_ROOT, "keys", "public.pem"));
    const fingerprintPinExists = fs.existsSync(path.join(PKG_ROOT, "keys", "EXPECTED_FINGERPRINT"));
    if (pubKeyExists) {
      out.summary.fix_attempted = "ed25519_keypair_generation_declined";
      out.summary.fix_decline_reason = "keys/public.pem already exists but no matching private key. Generating a fresh keypair would overwrite the public key and orphan every shipped signature. If you intend to establish a new signing identity, run `node $(exceptd path)/lib/sign.js generate-keypair --rotate` followed by sign-all.";
      process.stderr.write("[doctor --fix] refused: keys/public.pem present without matching private key. Pass --rotate via the underlying lib/sign.js if a new identity is intended.\n");
    } else if (fingerprintPinExists) {
      // A committed EXPECTED_FINGERPRINT with no keys/public.pem is a corrupted
      // checkout of a project that HAS a signing identity: generating here writes a
      // key whose fingerprint can never match the pin, so verify refuses forever.
      out.summary.fix_attempted = "ed25519_keypair_generation_declined";
      out.summary.fix_decline_reason = "keys/EXPECTED_FINGERPRINT is present but keys/public.pem is missing — this is a corrupted checkout of a project with a committed signing identity, not a fresh contributor checkout. Generating a keypair would produce a public key whose fingerprint cannot match the pin, so verify would refuse forever. Restore keys/public.pem from version control instead (git checkout -- keys/public.pem).";
      process.stderr.write("[doctor --fix] refused: keys/EXPECTED_FINGERPRINT present without keys/public.pem. Restore the committed public key (git checkout -- keys/public.pem) rather than generating a new identity.\n");
    } else {
      process.stderr.write("[doctor --fix] generating Ed25519 keypair...\n");
      const r = require("child_process").spawnSync(process.execPath, [path.join(PKG_ROOT, "lib", "sign.js"), "generate-keypair"], {
        stdio: ["ignore", "pipe", "pipe"], cwd: PKG_ROOT,
      });
      if (r.status === 0) {
        process.stderr.write("[doctor --fix] keypair generated — signing skills + manifest...\n");
        const s = require("child_process").spawnSync(process.execPath, [path.join(PKG_ROOT, "lib", "sign.js"), "sign-all"], {
          stdio: ["ignore", "pipe", "pipe"], cwd: PKG_ROOT,
        });
        const keyPath = path.join(PKG_ROOT, ".keys", "private.pem");
        const present = fs.existsSync(keyPath);
        checks.signing = { ok: present, severity: present ? "info" : "warn", private_key_present: present, can_sign_attestations: present };
        out.checks = checks;
        if (s.status === 0) {
          out.summary.fix_applied = "ed25519_keypair_generated_and_skills_signed";
          process.stderr.write("[doctor --fix] keypair + sign-all complete — re-checking signing status.\n");
        } else {
          out.summary.fix_applied = "ed25519_keypair_generated";
          out.summary.fix_partial = "sign_all_failed";
          out.summary.sign_all_exit_code = s.status;
          process.stderr.write(`[doctor --fix] WARNING: keypair generated but sign-all failed (exit=${s.status}). Skills carry signatures from a different key; verify will report mismatches.\n`);
        }
      } else {
        out.summary.fix_attempted = "ed25519_keypair_generation_failed";
        out.summary.fix_exit_code = r.status;
        process.stderr.write(`[doctor --fix] generation failed (exit=${r.status}); run \`node $(exceptd path)/lib/sign.js generate-keypair\` manually.\n`);
      }
    }
  }

  // Post-rotation: a private key IS present but signatures fail, because manifest
  // and skills still carry the old keypair. Without this branch, a `--rotate`
  // flow's remediation step is a no-op.
  if (args.fix && checks.signing && checks.signing.private_key_present && checks.signatures && checks.signatures.ok === false && !out.summary.fix_applied && !out.summary.fix_attempted) {
    process.stderr.write("[doctor --fix] private key present, signatures failing — running sign-all to re-sign skills + manifest...\n");
    const s = require("child_process").spawnSync(process.execPath, [path.join(PKG_ROOT, "lib", "sign.js"), "sign-all"], {
      stdio: ["ignore", "pipe", "pipe"], cwd: PKG_ROOT,
    });
    if (s.status === 0) {
      out.summary.fix_applied = "skills_resigned_against_current_keypair";
      process.stderr.write("[doctor --fix] sign-all complete — re-run `exceptd doctor` to confirm.\n");
    } else {
      out.summary.fix_attempted = "sign_all_failed";
      out.summary.sign_all_exit_code = s.status;
      process.stderr.write(`[doctor --fix] sign-all failed (exit=${s.status}); run \`node $(exceptd path)/lib/sign.js sign-all\` manually.\n`);
    }
  }

  // After a --fix that re-signed, `checks.signatures` is STALE — taken before any
  // key existed. Re-verifying and re-bucketing is what makes a successful --fix
  // exit 0 instead of carrying the pre-fix failure through.
  if (args.fix
      && (out.summary.fix_applied === "ed25519_keypair_generated_and_skills_signed"
          || out.summary.fix_applied === "skills_resigned_against_current_keypair")) {
    try {
      const verifyPath = path.join(PKG_ROOT, "lib", "verify.js");
      const rv = spawnSync(process.execPath, [verifyPath], { encoding: "utf8", cwd: PKG_ROOT, timeout: 30000 });
      const rvText = (rv.stdout || "") + (rv.stderr || "");
      const rvMatch = rvText.match(/(\d+)\/(\d+)\s+skills?\s+passed/i);
      const rvFp = rvText.match(/SHA256:\s*([A-Za-z0-9+/=]+)/);
      const rvOk = rv.status === 0;
      checks.signatures = {
        ok: rvOk,
        skills_passed: rvMatch ? Number(rvMatch[1]) : null,
        skills_total: rvMatch ? Number(rvMatch[2]) : null,
        fingerprint_sha256: rvFp ? rvFp[1] : null,
        ...(rvOk ? {} : { exit_code: rv.status, raw: rvText.slice(0, 500) }),
      };
      out.checks = checks;
      ({ warnList, errorList } = bucketChecks(checks));
      allGreen = errorList.length === 0 && warnList.length === 0;
      out.summary.failed_checks = errorList;
      out.summary.warning_checks = warnList;
      out.summary.all_green = allGreen;
    } catch { /* re-verify best-effort; leave the pre-fix state if it throws */ }
  }

  // --fix with nothing to fix reports a structured fix_status, so a caller can tell
  // "already healthy" from "failed silently". The ai-config branch records its
  // remediations on checks.ai_config, so that signal counts here too — else a
  // chmod/icacls run reports fix_applied > 0 and "already_present" at once.
  const aiConfigFixed = !!(checks.ai_config && ((checks.ai_config.fix_applied || 0) > 0 || (checks.ai_config.fix_failed || 0) > 0));
  if (args.fix && !out.summary.fix_applied && !out.summary.fix_attempted && !out.summary.fix_partial && !out.summary.fix_decline_reason && !aiConfigFixed) {
    out.summary.fix_status = "already_present";
    out.summary.fix_skipped_reason = "Signing key + skill signatures are already valid; nothing to remediate.";
  }

  if (wantJson) {
    emit(out, indent);
    // Gates on errorList only, matching the human path: a warn-only nudge must not
    // exit 1, and the body still carries all_green and warning_checks. A real
    // verification failure sets ok:false WITHOUT severity:"warn".
    if (errorList.length > 0) process.exitCode = EXIT_CODES.GENERIC_FAILURE;
    return;
  }

  const lines = [];
  lines.push(`exceptd doctor${localVersion ? ` (v${localVersion})` : ""}`);
  function mark(c, render) {
    if (!c) return;
    // A skipped check (air-gap disabled the probe) renders [info], not a failure.
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
  mark(checks.currency, c => {
    // Three states, not two: the drift tier renders under a warn icon, so "all
    // green" here would contradict the icon beside it.
    if (c.ok && c.severity === "warn") {
      const n = c.drifting_skills?.length ?? "?";
      const names = (c.drifting_skills || []).join(", ");
      return `skill currency: ${n} approaching review window${names ? ` (${names})` : ""}, 0 past it`;
    }
    if (c.ok) return `skill currency: all green (${c.total_skills ?? "?"} skills)`;
    return `skill currency: ${c.action_required_skills?.length ?? c.stale_skills?.length ?? "?"} past review window, ${c.critical_count ?? 0} critical`;
  });
  mark(checks.cves, c => {
    if (!c.ok) return `CVE catalog FAILED (exit=${c.exit_code ?? "?"})`;
    const total = c.total ?? "?";
    // Every prefix, so the breakdown sums to total; CVE + MAL is the fallback
    // for a check that produced no by_prefix.
    const breakdown = c.by_prefix
      ? ` (${Object.entries(c.by_prefix).sort().map(([p, n]) => `${n} ${p}`).join(" + ")})`
      : (c.cve_count != null && c.mal_count != null)
      ? ` (${c.cve_count} CVE + ${c.mal_count} MAL)`
      : "";
    return `CVE catalog: ${total} entries${breakdown}, drift ${c.drift ?? 0}`;
  });
  mark(checks.rfcs, c =>
    c.ok
      ? `RFC catalog: ${c.total ?? "?"} entries, drift ${c.drift ?? 0}`
      : `RFC catalog FAILED (exit=${c.exit_code ?? "?"})`
  );
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
    return "npm registry: could not compare versions (registry unreachable, offline, or no published version yet). Run `npm view @blamejs/exceptd-skills version` to see the latest, then `npm install -g @blamejs/exceptd-skills@latest` if you are behind.";
  });
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
    // The icon reads the bucketing severity, not .ok — info is a consumer install
    // where no key is expected, warn a contributor nudge, error a real failure.
    // Keying on !private_key_present puts [!!] beside "all checks green".
    if (checks.signing.private_key_present) {
      lines.push(`  [ok] attestation signing: private key present (.keys/private.pem)`);
    } else if (checks.signing.severity === "warn") {
      lines.push(`  [!]  attestation signing: private key absent (contributor checkout — run \`exceptd doctor --fix\` to enable signed attestations)`);
    } else if (checks.signing.severity === "info") {
      lines.push(`  [ok] attestation signing: consumer install (signing is contributor-only; this is the expected state)`);
    } else {
      lines.push(`  [!!] attestation signing: private key MISSING (.keys/private.pem) — run \`exceptd doctor --fix\` to enable`);
    }
  }
  if (checks.collectors) {
    const c = checks.collectors;
    const icon = c.ok ? "[ok]" : "[!!]";
    const skipNote = Array.isArray(c.policy_skips) && c.policy_skips.length > 0
      ? ` (${c.policy_skips.length} judgement-shaped playbooks intentionally without a collector — see AGENTS.md)`
      : "";
    lines.push(`  ${icon} collector layer: ${c.with_collector ?? "?"}/${c.total_playbooks ?? "?"} playbooks have collectors${skipNote}`);
    // Named here too, so text mode carries the same information as the JSON.
    if (Array.isArray(c.policy_skips) && c.policy_skips.length > 0) {
      const shown = c.policy_skips.slice(0, 5).join(", ");
      const more = c.policy_skips.length > 5 ? `, … +${c.policy_skips.length - 5} more` : "";
      lines.push(`       policy-skipped: ${shown}${more}`);
    }
    if (Array.isArray(c.load_errors) && c.load_errors.length > 0) {
      lines.push(`       ${c.load_errors.length} collector(s) failed to load:`);
      for (const e of c.load_errors.slice(0, 5)) {
        lines.push(`       [!!] ${e.id}: ${e.error}`);
      }
      if (c.load_errors.length > 5) lines.push(`       … and ${c.load_errors.length - 5} more (use --json for full list)`);
    }
  }
  if (checks.ai_config) {
    const c = checks.ai_config;
    const findings = Array.isArray(c.findings) ? c.findings : [];
    const icon = findings.length === 0 ? "[ok]" : "[!!]";
    const dirCount = c.scanned_dirs ?? 0;
    const fileCount = c.scanned_files ?? 0;
    lines.push(`  ${icon} AI-assistant config audit: scanned ${fileCount} file(s) across ${dirCount} dir(s) of ${(c.directories_inspected || []).length} candidate root(s); ${findings.length} finding(s)`);
    if (c.platform === "win32" && findings.length === 0 && fileCount > 0) {
      lines.push(`       (Windows: ACL inspected via icacls; every sensitive file restricted to the workstation user)`);
    }
    if (c.walk_truncated) {
      lines.push(`       (walk truncated at ${c.walk_caps?.max_files || "?"} file(s) / depth ${c.walk_caps?.max_depth || "?"}; rerun under a narrower path if you need exhaustive coverage)`);
    }
    for (const f of findings.slice(0, 5)) {
      const sev = f.severity === "error" ? "[!!]" : f.severity === "warn" ? "[warn]" : "[info]";
      lines.push(`       ${sev} ${f.path || "?"}: ${f.reason || f.note || "(no detail)"}`);
    }
    if (findings.length > 5) lines.push(`       … and ${findings.length - 5} more (use --json for full list)`);
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
  // --fix already ran above the JSON early-return; this echoes its state.
  if (out.summary.fix_applied) {
    process.stdout.write(`\n[doctor --fix] ${out.summary.fix_applied} — re-run \`exceptd doctor\` to confirm.\n`);
  } else if (out.summary.fix_attempted) {
    if (out.summary.fix_decline_reason) {
      process.stdout.write(`\n[doctor --fix] ${out.summary.fix_attempted}: ${out.summary.fix_decline_reason}\n`);
    } else {
      process.stdout.write(`\n[doctor --fix] ${out.summary.fix_attempted} (exit=${out.summary.fix_exit_code}); run \`node $(exceptd path)/lib/sign.js generate-keypair\` from a contributor checkout if needed.\n`);
    }
    process.exitCode = EXIT_CODES.GENERIC_FAILURE;
    return;
  }
  if (errorList.length > 0) process.exitCode = EXIT_CODES.GENERIC_FAILURE;
  // Warnings alone do NOT force exit 1: a CI gate reads exit 0 as "ran".
}

function cmdListAttestations(runner, args, runOpts, pretty) {
  // --playbook is registered `multi:`, so it arrives as an array: a strict equality
  // filter against it is always false and yields count: 0.
  const playbookFilter = (() => {
    if (args.playbook == null) return null;
    const list = Array.isArray(args.playbook) ? args.playbook : [args.playbook];
    return new Set(list.filter(x => typeof x === "string" && x.length > 0));
  })();
  // An unvalidated --since compares lexically against captured_at, matching all
  // or none depending on the string.
  if (args.since != null) {
    const sinceErr = validateIsoSince(args.since);
    if (sinceErr) return emitError(`attest list: ${sinceErr}`, null, pretty);
  }
  // Both roots, including ones that don't exist, so the output can say
  // scanned-and-empty rather than never-created.
  const roots = [...new Set([resolveAttestationRoot(runOpts), path.join(process.cwd(), ".exceptd", "attestations")])];
  const entries = [];
  const seenRoots = new Set();
  const rootsEvaluated = roots.map(r => ({ root: r, exists: fs.existsSync(r) }));
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
          // Replay records share the session dir but are not sessions; gated on
          // the parsed `kind`, so a rename cannot smuggle one in.
          if (j && j.kind === "replay") continue;
          if (playbookFilter && !playbookFilter.has(j.playbook_id)) continue;
          if (args.since && (j.captured_at || "") < args.since) continue;
          // `signed` distinguishes a real Ed25519 sidecar from the "unsigned" marker
          // written without a key: both are a .sig on disk, so presence cannot.
          const sigPath = path.join(sdir, f + ".sig");
          let signed = false;
          if (fs.existsSync(sigPath)) {
            try {
              const sigDoc = JSON.parse(fs.readFileSync(sigPath, "utf8"));
              signed =
                !!sigDoc &&
                sigDoc.algorithm === "Ed25519" &&
                typeof sigDoc.signature_base64 === "string" &&
                sigDoc.signature_base64.length > 0;
            } catch { /* unreadable sidecar treated as unsigned */ }
          }
          entries.push({
            session_id: sid,
            playbook_id: j.playbook_id,
            directive_id: j.directive_id,
            evidence_hash: j.evidence_hash ? j.evidence_hash.slice(0, 16) + "..." : null,
            captured_at: j.captured_at || null,
            attestation_root: root,
            file: path.join(sdir, f),
            signed,
          });
        } catch { /* skip malformed */ }
      }
    }
  }
  entries.sort((a, b) => (b.captured_at || "").localeCompare(a.captured_at || ""));
  const total = entries.length;
  // --limit caps both surfaces. Without it, JSON returns every session and the
  // table shows the first 50 with an "… and N more" footer.
  let limitN = null;
  if (args.limit != null) {
    limitN = Number(args.limit);
    if (!Number.isInteger(limitN) || limitN < 0) {
      return emitError(
        `attest list: --limit must be a non-negative integer; got ${JSON.stringify(String(args.limit))}.`,
        { verb: "attest list", provided: args.limit },
        pretty,
      );
    }
  }
  const shown = limitN != null ? entries.slice(0, limitN) : entries;
  emit({
    ok: true,
    attestations: shown,
    count: total,
    shown: shown.length,
    limit: limitN,
    filter: { playbook: playbookFilter ? [...playbookFilter] : null, since: args.since || null },
    roots_searched: [...seenRoots],
    // Every candidate root plus whether it existed.
    roots_evaluated: rootsEvaluated,
  }, pretty, (obj) => {
    const lines = [`attest list — ${obj.count} attestation(s)`];
    if (obj.count === 0) {
      const evald = obj.roots_evaluated || [];
      if (evald.length === 0) {
        lines.push(`  (no attestation root resolved; set EXCEPTD_HOME or run from a project with .exceptd/)`);
      } else {
        lines.push(`  candidate roots evaluated:`);
        for (const r of evald) {
          lines.push(`    ${r.exists ? '[scanned-empty]' : '[not-present]'} ${r.root}`);
        }
      }
      return lines.join("\n");
    }
    lines.push(`  ${"session-id".padEnd(20)}  ${"playbook".padEnd(16)}  ${"captured-at".padEnd(20)}  evidence-hash`);
    lines.push(`  ${"-".repeat(20)}  ${"-".repeat(16)}  ${"-".repeat(20)}  ${"-".repeat(20)}`);
    // obj.attestations is already capped when --limit was given.
    const rows = obj.limit != null ? obj.attestations : obj.attestations.slice(0, 50);
    for (const e of rows) {
      lines.push(`  ${(e.session_id || "?").padEnd(20)}  ${(e.playbook_id || "?").padEnd(16)}  ${(e.captured_at || "").slice(0, 19).padEnd(20)}  ${e.evidence_hash || ""}`);
    }
    if (obj.limit != null) {
      if (obj.count > rows.length) lines.push(`  showing ${rows.length} of ${obj.count} (raise --limit or use --json for the full list)`);
    } else if (obj.count > 50) {
      lines.push(`  … and ${obj.count - 50} more (use --limit <n> or --json for the full list)`);
    }
    return lines.join("\n");
  });
}

/**
 * Streaming JSONL contract for AI-driven runs: one JSON object per line on stdout as
 * the phases progress, reading {"event":"evidence","payload":{observations,verdict}}
 * from stdin once await_evidence is announced. --no-stream returns a single JSON
 * document combining every phase.
 */
function cmdAiRun(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  if (!playbookId) {
    return emitError("ai-run: missing <playbook> positional argument.", null, pretty);
  }
  // `--evidence ""` is falsy, so --no-stream would fall through to the stdin
  // branch and run an empty submission to ok:true at exit 0.
  if (args.evidence === "") {
    return emitError("ai-run: --evidence was given an empty value; pass a file path, '-' for stdin, or omit --evidence to read evidence from the stream", { verb: "ai-run" }, pretty);
  }
  if (refuseInvalidPlaybookId("ai-run", playbookId, pretty)) return;
  let pb;
  try { pb = runner.loadPlaybook(playbookId); }
  catch (e) { return emitError(`ai-run: ${e.message}`, { playbook: playbookId }, pretty); }
  const directiveId = args.directive || (pb.directives[0] && pb.directives[0].id);
  if (!directiveId) {
    return refuseNoDirectives("ai-run", playbookId, pretty);
  }

  // Both stream and no-stream modes share the informational phases.
  let governPhase, directPhase, lookPhase;
  try {
    governPhase = runner.govern(playbookId, directiveId, runOpts);
    directPhase = runner.direct(playbookId, directiveId);
    lookPhase = runner.look(playbookId, directiveId, runOpts);
  } catch (e) {
    // A framed event, not bare text: a host AI reading this stream sees structured
    // frames or nothing. `process.exitCode` — the frame has to drain.
    process.stdout.write(JSON.stringify({ event: "error", reason: e.message, phase: "info", playbook_id: playbookId, directive_id: directiveId }) + "\n");
    process.exitCode = EXIT_CODES.GENERIC_FAILURE;
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

  if (args["no-stream"]) {
    let payload = { observations: {}, verdict: {} };
    if (args.evidence) {
      // The shape guard `run` applies at its read boundary: without it, `null` /
      // `[]` / a scalar runs as if empty. The streaming path is unaffected.
      try { payload = asEvidenceObject(readEvidence(args.evidence)); }
      catch (e) { return emitError(`ai-run: failed to read --evidence: ${e.message}`, null, pretty); }
    } else if (hasReadableStdin()) {
      // hasReadableStdin() fstat-probes first; a wrapped-stdin harness hangs on
      // a bare readFileSync(0).
      let buf = "";
      try { buf = fs.readFileSync(0, "utf8"); }
      catch { /* stdin empty / unreadable — fall through with empty payload */ }
      if (buf.trim()) {
        // stdin is tried as a single JSON document first — the common
        // `echo '<json>' | ai-run … --no-stream` shape — so the --evidence guard
        // applies: a bare `null` / `[]` / scalar is malformed, not "no evidence".
        let single;
        let singleParsed = false;
        try { single = JSON.parse(buf); singleParsed = true; } catch { /* not a single doc — fall to JSONL scan */ }
        if (singleParsed) {
          // An evidence-event wrapper is the one shape that is NOT itself the
          // submission, so it is unwrapped before the guard.
          if (single && typeof single === "object" && !Array.isArray(single) && single.event === "evidence" && single.payload) {
            payload = single.payload;
          } else {
            try { payload = asEvidenceObject(single); }
            catch (e) { return emitError(`ai-run: failed to read evidence from stdin: ${e.message}`, null, pretty); }
            if (!payload.observations && (payload.artifacts || payload.signal_overrides || payload.signals)) {
              payload = { observations: { ...(payload.artifacts || {}), ...(payload.signal_overrides || {}) }, verdict: payload.signals || {} };
            }
          }
        } else {
          // JSONL: scan for the first evidence event or bare submission, ignoring
          // the status frames a host AI may interleave.
          for (const line of buf.split(/\r?\n/)) {
            const t = line.trim();
            if (!t) continue;
            try {
              const parsed = JSON.parse(t);
              if (parsed && parsed.event === "evidence" && parsed.payload) {
                payload = parsed.payload;
                break;
              }
              if (parsed && (parsed.observations || parsed.artifacts || parsed.signal_overrides)) {
                payload = parsed.observations
                  ? parsed
                  : { observations: { ...(parsed.artifacts || {}), ...(parsed.signal_overrides || {}) }, verdict: parsed.signals || {} };
                break;
              }
            } catch { /* skip non-JSON lines */ }
          }
        }
      }
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
      // Through emit(), so the body lands on stdout beside the success path and
      // the shared ok:false fallback sets exitCode — one stream, not two.
      emit(result || { ok: false, error: 'ai-run returned empty result' }, pretty);
      return;
    }
    // The attestation must persist here, or the emitted session_id resolves for
    // neither `attest show / verify / diff` nor `reattest`.
    if (result.session_id) {
      // As in cmdRun: operator_consent is gated on classification=detected.
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
        // Reported through the same JSONL contract, with the three exit-code
        // classes, so a driver branches without parsing the reason string.
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
    // Same envelope as `run` — phases under `phases.*` — so one JSONPath query
    // works whichever verb produced the payload.
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

  const writeLine = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");
  writeLine(governEvent);
  writeLine(directEvent);
  writeLine(lookEvent);
  writeLine({ phase: "await_evidence", submission_shape: submissionShape });

  let handled = false;
  let buf = "";

  // exitCode plus pausing stdin, never process.exit(): the JSONL frames must drain
  // before the loop ends, and `handled` plus the pause block re-entry.
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
      return finish(EXIT_CODES.GENERIC_FAILURE);
    }
    if (!parsed || parsed.event !== "evidence" || !parsed.payload) {
      // Non-evidence frames are ignored, so a host AI can interleave status
      // events; only an "evidence" event triggers phases 4-7.
      return;
    }
    handled = true;
    const submission = buildSubmissionFromPayload(parsed.payload);
    let result;
    try {
      result = runner.run(playbookId, directiveId, submission, runOpts);
    } catch (e) {
      writeLine({ event: "error", reason: `runner threw: ${e.message}` });
      return finish(EXIT_CODES.GENERIC_FAILURE);
    }
    if (!result || result.ok === false) {
      writeLine({ event: "error", reason: result?.reason || "runner returned ok:false", result });
      return finish(EXIT_CODES.GENERIC_FAILURE);
    }
    writeLine({ phase: "detect", ...result.phases?.detect });
    writeLine({ phase: "analyze", ...result.phases?.analyze });
    writeLine({ phase: "validate", ...result.phases?.validate });
    writeLine({ phase: "close", ...result.phases?.close });
    // Streaming mode persists too, or the `done` frame's session_id resolves
    // for neither `attest` nor `reattest`.
    if (result.session_id) {
      // As in cmdRun: operator_consent is gated on classification=detected.
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
    return finish(EXIT_CODES.SUCCESS);
  };

  // A TTY means nothing was piped, so the hint replaces a hung process.
  if (process.stdin.isTTY) {
    writeLine({ event: "error", reason: "ai-run streaming mode requires evidence on stdin; pipe {\"event\":\"evidence\",\"payload\":{...}} or use --no-stream." });
    process.exitCode = EXIT_CODES.GENERIC_FAILURE;
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
    // Final flush: a trailing line with no newline.
    const tail = buf.trim();
    if (tail) handleLine(tail);
    if (!handled) {
      // stdin closed with no evidence event. Before erroring, try the raw text as a
      // bare submission — `echo '{...}' | ai-run secrets` pipes the body unwrapped.
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
      process.exitCode = EXIT_CODES.GENERIC_FAILURE;
      return;
    }
  });

  // Capture stdin for the post-close fallback.
  process.stdin._allText = "";
  process.stdin.on("data", chunk => { process.stdin._allText += chunk.toString(); });
}

/**
 * Coerces a stdin payload into the runner submission shape. Accepts the flat ai-run
 * shape (observations + verdict) and the nested one (artifacts + signal_overrides
 * + signals).
 */
function buildSubmissionFromPayload(payload) {
  if (!payload || typeof payload !== "object") return { artifacts: {}, signal_overrides: {}, signals: {} };
  if (payload.artifacts || payload.signal_overrides || payload.signals) {
    return {
      artifacts: payload.artifacts || {},
      signal_overrides: payload.signal_overrides || {},
      signals: payload.signals || {},
      precondition_checks: payload.precondition_checks || undefined,
    };
  }
  // Flat shape: observations feeds BOTH artifacts and signal_overrides (the runner
  // sorts them in normalizeSubmission), and verdict becomes signals.
  return {
    artifacts: payload.observations || {},
    signal_overrides: payload.observations || {},
    signals: payload.verdict || {},
    precondition_checks: payload.precondition_checks || undefined,
  };
}

// `recipes` lists the curated workflows from data/_indexes/recipes.json;
// `recipes <id>` expands one.
function cmdRecipes(runner, args, runOpts, pretty) {
  let catalog;
  try {
    catalog = require(path.join(PKG_ROOT, "data", "_indexes", "recipes.json"));
  } catch (e) {
    return emitError(`recipes: could not load recipe catalog: ${e.message}`, null, pretty);
  }
  const recipes = Array.isArray(catalog.recipes) ? catalog.recipes : [];
  const id = args._[0];

  if (id) {
    const recipe = recipes.find(r => r.id === id);
    if (!recipe) {
      return emitError(
        `recipes: unknown recipe "${id}". Run \`exceptd recipes\` to list available recipes.`,
        { verb: "recipes", available: recipes.map(r => r.id) },
        pretty,
      );
    }
    return emit({ verb: "recipes", recipe }, pretty, (obj) => {
      const r = obj.recipe;
      const lines = [];
      lines.push(`Recipe: ${r.name} (${r.id})`);
      if (r.description) lines.push(`\n${r.description}`);
      if (r.when_to_use) lines.push(`\nWhen to use: ${r.when_to_use}`);
      if (Array.isArray(r.typical_jurisdictions) && r.typical_jurisdictions.length) {
        lines.push(`Typical jurisdictions: ${r.typical_jurisdictions.join(", ")}`);
      }
      lines.push(`\nSkill chain (${r.skill_count ?? (r.skill_chain || []).length}):`);
      const steps = Array.isArray(r.steps) && r.steps.length ? r.steps : (r.skill_chain || []).map(s => ({ skill: s }));
      steps.forEach((s, i) => {
        lines.push(`  ${i + 1}. ${s.skill}`);
        if (s.why) lines.push(`     ${s.why}`);
      });
      lines.push(`\nRun a skill: exceptd skill <name>`);
      return lines.join("\n");
    });
  }

  return emit({ verb: "recipes", count: recipes.length, recipes: recipes.map(r => ({
    id: r.id, name: r.name, when_to_use: r.when_to_use, skill_count: r.skill_count ?? (r.skill_chain || []).length,
  })) }, pretty, (obj) => {
    const lines = [`Curated recipes (${obj.count}) — multi-skill workflows for common engagements:`, ""];
    for (const r of obj.recipes) {
      lines.push(`  ${r.id}  (${r.skill_count} skills)`);
      lines.push(`    ${r.name}`);
      if (r.when_to_use) lines.push(`    when: ${r.when_to_use.length > 140 ? r.when_to_use.slice(0, 140) + "…" : r.when_to_use}`);
    }
    lines.push(`\nExpand one: exceptd recipes <id>`);
    return lines.join("\n");
  });
}

/**
 * Plain-English routing: scores every playbook by token overlap against a broad
 * index (id, domain fields, TTP and CWE refs, theater claims, threat_context, skill
 * chain, asset scope) and returns the top matches with a confidence score.
 */
function cmdAsk(runner, args, runOpts, pretty) {
  const question = (args._ || []).join(" ").trim();
  if (!question) {
    return emitError("ask: usage: exceptd ask \"<plain-English question>\"", null, pretty);
  }
  // ask routes to playbooks; a question naming a CVE or RFC belongs to the resolvers.
  const cveTok = question.match(/\bCVE-\d{4}-\d{3,}\b/i);
  const rfcTok = question.match(/\bRFC[-\s]?(\d{1,6})\b/i);
  if (cveTok) process.stderr.write(`[exceptd] tip: to validate that identifier directly, run \`exceptd cve ${cveTok[0].toUpperCase()}\`.\n`);
  if (rfcTok) process.stderr.write(`[exceptd] tip: to resolve that RFC directly, run \`exceptd rfc ${rfcTok[1]}\`.\n`);
  const ids = runner.listPlaybooks();
  const q = question.toLowerCase();

  // Operator phrasing → playbook-relevant tokens, so cmdAsk stays dependency-free.
  const SYNONYMS = {
    "credential": ["secret", "key", "token", "password", "cred", "secrets"],
    "credentials": ["secret", "key", "token", "password", "cred", "secrets"],
    "api key": ["secret", "credential", "secrets"],
    "api keys": ["secret", "credential", "secrets"],
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
    "phish": ["identity-sso-compromise", "idp-incident", "sso", "bec"],
    "phishing": ["identity-sso-compromise", "idp-incident", "sso", "bec"],
    "phished": ["identity-sso-compromise", "idp-incident", "sso", "bec"],
    "sso": ["identity-sso-compromise", "idp-incident", "okta", "azure-ad", "entra"],
    "oauth": ["identity-sso-compromise", "idp-incident", "openid", "oidc"],
    "saml": ["identity-sso-compromise", "idp-incident"],
    "okta": ["identity-sso-compromise", "idp-incident", "sso"],
    "entra": ["identity-sso-compromise", "idp-incident", "azure-ad", "sso"],
    "bec": ["identity-sso-compromise", "phish"],
    "deepfake": ["identity-sso-compromise", "phish", "ai-c2"],
    "left-pad": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "left pad": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "event-stream": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "shai-hulud": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "ransomware": ["ransomware", "kernel", "runtime"],
    "rogue": ["ai-c2", "llm-tool-use-exfil"],
    "agentic": ["ai-c2", "llm-tool-use-exfil", "mcp"],
    "credential theft": ["cred-stores", "secrets"],
    "cred theft": ["cred-stores", "secrets"],
    "credential exfil": ["cred-stores", "llm-tool-use-exfil"],
    "developer laptop": ["cred-stores", "hardening"],
    // Without these the supply-chain playbooks out-rank cicd-pipeline-compromise
    // on the shared tokens.
    "oidc": ["cicd-pipeline-compromise", "ci", "pipeline", "runner", "signing"],
    "cicd": ["cicd-pipeline-compromise", "ci", "pipeline"],
    "ci/cd": ["cicd-pipeline-compromise", "pipeline"],
    "runner": ["cicd-pipeline-compromise", "ci"],
    "pipeline": ["cicd-pipeline-compromise"],
    // Needed because llm-tool-use-exfil otherwise wins a long C2 sentence.
    "c2": ["ai-api", "ai-c2"],
    "command and control": ["ai-api", "ai-c2"],
    "command-and-control": ["ai-api", "ai-c2"],
  };

  // Filtered AFTER synonym expansion, so a stopword-adjacent phrase still pulls
  // in its canonical tokens.
  const STOPWORDS = new Set([
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
    "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy",
    "did", "its", "let", "put", "say", "she", "too", "use", "any", "got",
    "from", "this", "that", "with", "have", "they", "what", "your", "when",
    "which", "would", "could", "should", "there", "their", "about", "into",
    "than", "then", "them", "some", "more", "most", "very", "much", "such",
    "been", "were", "want", "well", "back", "good", "make", "made", "take",
    "took", "give", "gave", "find", "found", "know", "knew", "told", "ago",
    // 2-char English fillers the length>=2 filter admits. Excludes the
    // security-meaningful ones: ai, ml, ci, c2, k8s.
    "do", "is", "my", "it", "me", "to", "of", "on", "or", "an", "as", "at",
    "be", "by", "we", "up", "so", "no", "if", "in",
  ]);

  const baseTokens = q.split(/\W+/).filter(t => t.length >= 2);
  const expanded = new Set(baseTokens);
  for (const [phrase, syns] of Object.entries(SYNONYMS)) {
    if (q.includes(phrase)) for (const s of syns) expanded.add(s);
  }
  for (const t of baseTokens) {
    if (SYNONYMS[t]) for (const s of SYNONYMS[t]) expanded.add(s);
  }
  for (const sw of STOPWORDS) expanded.delete(sw);
  const tokens = [...expanded];

  const scored = [];
  for (const id of ids) {
    let pb;
    try { pb = runner.loadPlaybook(id); } catch { continue; }
    const haystackText = [
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
    // Whole-token membership, NOT substring: substrings match "the" inside
    // "authentication".
    const haystackTokens = new Set(haystackText.split(/\W+/).filter(t => t.length >= 2));
    let score = 0;
    for (const t of tokens) if (haystackTokens.has(t)) score++;
    // An id match weighs heavier, so "secrets" reaches the secrets playbook.
    if (tokens.some(t => (pb._meta?.id || id) === t)) score += 3;
    scored.push({ id: pb._meta?.id || id, score });
  }
  // Ties break on whether the question names the playbook id, then original order:
  // alphabetical lets the first few playbooks dominate every vague query.
  scored.forEach((s, i) => { s._origIdx = i; });
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const aIdMatch = tokens.includes(a.id) ? 1 : 0;
    const bIdMatch = tokens.includes(b.id) ? 1 : 0;
    if (aIdMatch !== bIdMatch) return bIdMatch - aIdMatch;
    return a._origIdx - b._origIdx;
  });
  const top = scored.filter(s => s.score > 0).slice(0, 5);

  if (top.length === 0) {
    const result = {
      verb: "ask",
      question,
      routed_to: [],
      hint: "No playbook matched. Try `exceptd brief --all` to see what's available, or `exceptd discover` to detect what's in your cwd.",
    };
    // --pretty implies structured output, as in discover and doctor.
    if (args.json || args.pretty) return emit(result, pretty);
    process.stdout.write(`ask: ${question}\n  no playbook matched.\n  try: exceptd discover  (auto-detect what's in your cwd)\n`);
    return;
  }

  // discover's collector lookup, so an operator sees which alternates have a
  // collect|run pipe and which need AI-driven evidence.
  const collectorsDir = path.join(PKG_ROOT, "lib", "collectors");
  for (const t of top) {
    const collectorPath = path.join(collectorsDir, t.id + ".js");
    t.collector_available = fs.existsSync(collectorPath);
  }

  // Confidence divides by the tie spread, so a five-way tie at score 3 reports
  // ~0.2x what a clean winner at score 3 does.
  const topScore = top[0].score;
  const tieCount = scored.filter(s => s.score === topScore).length;
  const baseConfidence = Math.min(1, topScore / Math.max(2, tokens.length));
  const tiePenalty = tieCount > 1 ? 1 / tieCount : 1;
  const confidence = Math.round(baseConfidence * tiePenalty * 100) / 100;
  // Terms with no playbook home: the router otherwise returns a confident-looking
  // wrong playbook ("DMARC" → llm-tool-use-exfil) instead of the covering skill.
  const SKILL_ONLY_DOMAINS = [
    { skill: "email-security-anti-phishing", re: /\b(dmarc|dkim|\bspf\b|bimi|mta-sts|email spoof|email security|sender auth|business email compromise)\b/i },
    { skill: "age-gates-child-safety", re: /\b(age[\s-]?gate|age verification|coppa|child safety|children'?s code|\bkosa\b|\baadc\b|minor protection)\b/i },
    { skill: "sector-healthcare", re: /\b(hipaa|\bphi\b|hitrust|healthcare security|45 cfr)\b/i },
    { skill: "dlp-gap-analysis", re: /\b(data loss prevention|\bdlp\b)\b/i },
  ];
  const skillDomain = SKILL_ONLY_DOMAINS.find(d => d.re.test(question));
  const confidence0 = confidence;
  const lowConfidence = confidence0 < 0.15;
  const result = {
    verb: "ask",
    question,
    routed_to: top.map(t => t.id),
    confidence,
    confidence_factors: { base: Math.round(baseConfidence * 100) / 100, tie_count: tieCount },
    next_step: `exceptd run ${top[0].id}    # or: exceptd brief ${top[0].id} to learn first`,
    ...(skillDomain ? { skill_suggestion: skillDomain.skill, skill_suggestion_note: `This topic is covered by the "${skillDomain.skill}" skill, not a playbook. Run \`exceptd skill ${skillDomain.skill}\`.` } : {}),
    ...((!skillDomain && lowConfidence) ? { low_confidence: true, fallback_hint: "Low-confidence match — this may be a skill-only domain (no dedicated playbook). Browse `exceptd help` for skills, or `exceptd recipes` for curated multi-skill workflows." } : {}),
    full_match_list: top,
  };
  if (args.json || args.pretty) return emit(result, pretty);
  const topGlyph = top[0].collector_available ? " [collector]" : "";
  const altLine = top.slice(1).map(t => t.id + (t.collector_available ? " [collector]" : "")).join(", ") || "(none)";
  process.stdout.write(`ask: ${question}\n  top match: ${top[0].id}${topGlyph} (score ${top[0].score})\n  next: ${result.next_step}\n  alternates: ${altLine}\n`);
  if (skillDomain) process.stdout.write(`  note: ${result.skill_suggestion_note}\n`);
  else if (lowConfidence) process.stdout.write(`  note: ${result.fallback_hint}\n`);
}

/** Top-level CI gate — `run --all --ci` as a verb. Exit codes: `exceptd ci --help`. */
function cmdCi(runner, args, runOpts, pretty) {
  const scope = args.scope;
  // A value-less `--max-rwep` parses as `true`, which Number() turns into 1 — a
  // finite, non-negative cap that passes the guard below and gates at 1.
  if (args["max-rwep"] === true) {
    return emitError(
      "ci: --max-rwep requires a non-negative number.",
      { verb: "ci", flag: "max-rwep" },
      pretty,
    );
  }
  const maxRwep = args["max-rwep"] !== undefined ? Number(args["max-rwep"]) : null;
  // A non-numeric cap must not coerce: `--max-rwep abc` is NaN, degenerating the
  // gate to "block everything" with no error.
  if (maxRwep !== null && (!Number.isFinite(maxRwep) || maxRwep < 0)) {
    return emitError(
      `ci: --max-rwep must be a non-negative number; got ${JSON.stringify(String(args["max-rwep"]))}.`,
      { verb: "ci", provided: args["max-rwep"] },
      pretty,
    );
  }
  // An empty value is falsy: the reads below skip, the bundle stays {}, and the
  // gate reports PASS at exit 0 over evidence-free runs.
  if (args.evidence === "") {
    return emitError(
      "ci: --evidence was given an empty value; pass a file path, '-' for stdin, or omit --evidence for a no-evidence run",
      { verb: "ci", flag: "evidence" },
      pretty,
    );
  }
  if (args["evidence-dir"] === "") {
    return emitError(
      "ci: --evidence-dir was given an empty value; pass an existing directory, or omit --evidence-dir",
      { verb: "ci", flag: "evidence-dir" },
      pretty,
    );
  }
  const blockOnClock = !!args["block-on-jurisdiction-clock"];

  // Playbook selection. Positional args act as an inline --required; bare
  // `exceptd ci` falls through to cwd autodetect. Combining selectors is refused:
  // `ci kernel --scope code` would drop `kernel` and PASS on a playbook never run.
  let ids;
  const positional = Array.isArray(args._) ? args._.filter(s => typeof s === 'string' && s.length > 0) : [];
  if (positional.length > 0) {
    const conflicting = [];
    if (args.required) conflicting.push('--required');
    if (args.all) conflicting.push('--all');
    if (args.scope) conflicting.push('--scope');
    if (conflicting.length > 0) {
      return emitError(
        `ci: positional playbook arg(s) ${JSON.stringify(positional)} cannot be combined with ${conflicting.join(' / ')}. Pick one selector: either positional playbook IDs, OR --required <list>, OR --all, OR --scope <type>.`,
        { positional, conflicting_flags: conflicting },
        pretty,
      );
    }
    const all = runner.listPlaybooks();
    const unknown = positional.filter(r => !all.includes(r));
    if (unknown.length > 0) {
      return emitError(
        `ci: unknown playbook ID(s) ${JSON.stringify(unknown)} on positional args. Known: ${all.join(", ")}. Pass --all for every playbook, --scope <type> for a class, or omit positional args to auto-detect from cwd.`,
        { unknown, accepted: all },
        pretty,
      );
    }
    ids = positional;
  } else if (args.required !== undefined) {
    // Presence, not truthiness: an empty `--required ""` would fall through to
    // cwd auto-detect and gate an unrequested playbook set.
    const conflictingFlags = [];
    if (args.all) conflictingFlags.push('--all');
    if (args.scope) conflictingFlags.push('--scope');
    if (conflictingFlags.length > 0) {
      return emitError(
        `ci: --required cannot be combined with ${conflictingFlags.join(' / ')}. Pick one selector: either --required <list>, OR --all, OR --scope <type>.`,
        { conflicting_flags: ['--required', ...conflictingFlags] },
        pretty,
      );
    }
    const requestedRaw = Array.isArray(args.required) ? args.required.join(",") : String(args.required);
    const requested = requestedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (requested.length === 0) {
      return emitError(
        `ci --required: empty playbook list. Pass at least one playbook id (e.g. --required secrets,containers), or use --all / --scope <type>.`,
        null,
        pretty,
      );
    }
    const all = runner.listPlaybooks();
    const unknown = requested.filter(r => !all.includes(r));
    if (unknown.length > 0) {
      return emitError(`ci --required: unknown playbook ID(s) ${JSON.stringify(unknown)}. Known: ${all.join(", ")}.`, null, pretty);
    }
    ids = requested;
  } else if (args.all) {
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    ids = runner.listPlaybooks().filter(id =>
      includeJudgementShaped || !POLICY_SKIPPED_PLAYBOOKS.has(id)
    );
  } else if (scope !== undefined) {
    // Presence, not truthiness: an empty `--scope ""` must reach
    // filterPlaybooksByScope for its accepted-set refusal, not cwd auto-detect.
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    try { ids = filterPlaybooksByScope(runner, scope, { includeJudgementShaped }); }
    catch (e) { return emitError(`ci: ${e.message}`, { provided_scope: scope }, pretty); }
    // Cross-cutting playbooks run whatever the scope.
    const cross = filterPlaybooksByScope(runner, "cross-cutting", { includeJudgementShaped });
    ids = [...new Set([...ids, ...cross])];
    // sbom is system-scope but repo-relevant, so code-scope on a repo pulls it in
    // and ci matches what discover recommended.
    if (scope === "code" && fs.existsSync(path.join(process.cwd(), ".git"))) {
      const hasLockfile = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "Cargo.lock", "go.sum"]
        .some(f => fs.existsSync(path.join(process.cwd(), f)));
      if (hasLockfile && runner.listPlaybooks().includes("sbom") && !ids.includes("sbom")) {
        ids.push("sbom");
      }
    }
  } else {
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    const scopes = detectScopes();
    ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s, { includeJudgementShaped }));
    ids = [...new Set(ids)];
  }
  if (!ids || ids.length === 0) {
    return emitError("ci: no playbooks matched. Pass --all, --scope <type>, or run from a repo/Linux-host context.", null, pretty);
  }

  const sessionId = runOpts.session_id || require("crypto").randomBytes(8).toString("hex");

  // Both flags produce a bundle keyed by playbook id; an id with no key gets {}.
  let bundle = {};
  if (args.evidence) {
    try { bundle = readEvidence(args.evidence); }
    catch (e) { return emitError(`ci: failed to read --evidence: ${e.message}`, null, pretty); }
  }
  if (args["evidence-dir"] === "") {
    return emitError("ci: --evidence-dir was given an empty value; pass an existing directory, or omit --evidence-dir", { verb: "ci", flag: "evidence-dir" }, pretty);
  }
  if (args["evidence-dir"]) {
    const dir = args["evidence-dir"];
    if (typeof dir !== "string") {
      return emitError("ci: --evidence-dir must be a string.", null, pretty);
    }
    if (!fs.existsSync(dir)) {
      return emitError(`ci: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    const er = readEvidenceDir(dir, "ci");
    if (!er.ok) return emitError(er.error, er.extra, pretty);
    Object.assign(bundle, er.bundle);
  }

  // `ci` keys its bundle by playbook id, so `ci <pb> --evidence -` carrying the
  // plain shape `run` accepts would land as bundle[<pb>]=undefined and PASS empty.
  // With one playbook in scope and no id key, the bundle IS its evidence.
  if (ids.length === 1 && Object.keys(bundle).length > 0 && !(ids[0] in bundle)) {
    const allIds = new Set(runner.listPlaybooks());
    const looksLikeBundle = Object.keys(bundle).some(k => allIds.has(k));
    if (!looksLikeBundle) bundle = { [ids[0]]: bundle };
  }

  const results = [];
  let fail = false;
  let failReasons = [];
  // Tracked apart from FAIL so the exit code separates escalation (2) from a
  // running regulatory clock (5).
  let clockStartedFail = false;
  let clockStartedReasons = [];

  // The requested format seeds each run's signals._bundle_formats, or close() builds
  // only the playbook's PRIMARY format and `ci --format sarif` filters out every
  // playbook whose primary differs — a silently empty result. The `_` prefix keeps
  // it out of evidence_hash, so attest/reattest are unperturbed.
  let ciFormatRaw = args.format;
  if (Array.isArray(ciFormatRaw)) ciFormatRaw = ciFormatRaw[0];
  const ciBundleFormat = (ciFormatRaw === 'csaf' || ciFormatRaw === 'csaf-2.0') ? 'csaf-2.0'
    : (ciFormatRaw === 'sarif' || ciFormatRaw === 'openvex') ? ciFormatRaw : null;

  for (const id of ids) {
    // Validated as in cmdRunMulti: a malformed catalog id would otherwise reach
    // loadPlaybook unchecked.
    const idCheck = validateIdComponent(id, "playbook");
    if (!idCheck.ok) {
      results.push({ playbook_id: id, ok: false, error: idCheck.reason });
      fail = true;
      continue;
    }
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
    if (ciBundleFormat) {
      // Cloned before injecting so the shared bundle is not mutated, and merged
      // with any operator-supplied _bundle_formats.
      const existing = Array.isArray(submission.signals && submission.signals._bundle_formats)
        ? submission.signals._bundle_formats : [];
      submission.signals = {
        ...(submission.signals || {}),
        _bundle_formats: existing.includes(ciBundleFormat) ? existing : [...existing, ciBundleFormat],
      };
    }
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
    // On an inconclusive classification only the RWEP DELTA counts against the cap:
    // absolute RWEP fails every evidence-free run on catalog baseline alone, since
    // a KEV-listed kernel CVE sits at 90 against a cap of 80 for facts the operator
    // has not weighed in on. A detected run still fails on absolute RWEP.
    if (cls === "detected" && rwepAdj >= cap) {
      // Already failed above.
    } else if (cls === "inconclusive" && rwepAdj - rwepBase >= cap) {
      fail = true;
      failReasons.push(`${id}: rwep_delta=${rwepAdj - rwepBase} >= cap=${cap} (classification=inconclusive; operator evidence raised the score)`);
    }
    if (blockOnClock && clockStarted) {
      clockStartedFail = true;
      clockStartedReasons.push(`${id}: jurisdiction clock started`);
    }
  }

  const rwepValues = results.map(r => r.phases?.analyze?.rwep?.adjusted ?? 0);
  const maxRwepObserved = rwepValues.length ? Math.max(...rwepValues) : 0;

  // The verdict is computed against the same matrix the exit code uses, so a
  // consumer reading one surface cannot reach the opposite conclusion.
  const suppliedEvidenceForVerdict = args.evidence || args["evidence-dir"];
  const blockedCount = results.filter(r => r && r.ok === false).length;
  const inconclusiveCount = results.filter(r => r.phases?.detect?.classification === "inconclusive").length;
  const totalForVerdict = results.length;
  const noEvidenceAllInconclusive = !suppliedEvidenceForVerdict && totalForVerdict > 0 && inconclusiveCount === totalForVerdict;
  // BLOCKED > CLOCK_STARTED > FAIL > NO_EVIDENCE > PASS. CLOCK_STARTED outranks
  // FAIL because the operator opted into that gate and wants the deadline as the
  // top line; a detected finding is still in the body to act on.
  const computedVerdict = blockedCount > 0
    ? "BLOCKED"
    : clockStartedFail
      ? "CLOCK_STARTED"
      : fail
        ? "FAIL"
        : noEvidenceAllInconclusive
          ? "NO_EVIDENCE"
          : "PASS";

  // Per-playbook framework_gap mappings rolled up to one entry per (framework,
  // claimed_control), carrying the playbooks that flagged it.
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
          // The explanatory text lives in `actual_gap`.
          why_insufficient: g.actual_gap || g.why_insufficient || null,
          required_control: g.required_control || null,
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
    jurisdiction_clock_rollup: buildJurisdictionClockRollup(results),
    verdict: computedVerdict,
    fail_reasons: failReasons,
    clock_started_reasons: clockStartedReasons,
  };

  // Every run() surfaces session-level conditions into its own
  // phases.analyze.runtime_errors, so N playbooks repeat one warning N times.
  const warningSeen = new Set();
  const runtimeWarningsDedup = [];
  for (const r of results) {
    const errs = r?.phases?.analyze?.runtime_errors || [];
    for (const e of errs) {
      const key = `${e.kind || ""}::${e.reason || ""}`;
      if (warningSeen.has(key)) continue;
      warningSeen.add(key);
      runtimeWarningsDedup.push({
        kind: e.kind || null,
        reason: e.reason || null,
        remediation: e.remediation || null,
      });
    }
  }
  summary.runtime_warnings = runtimeWarningsDedup;
  summary.runtime_warnings_count = runtimeWarningsDedup.length;

  // The selection rule reaches the summary, separating scoped from auto-included.
  if (scope) {
    summary.scope_request = scope;
    summary.scope_inclusion_rules = [
      `--scope ${scope} selected playbooks with _meta.scope === "${scope}"`,
      `cross-cutting playbooks are always added (apply to every scope by design)`,
    ];
    if (scope === "code") {
      summary.scope_inclusion_rules.push("--scope code also adds sbom when the cwd is a git repo with a lockfile");
    }
  }

  // The same --format shortcuts `run` honours.
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
    // ci spans N playbooks, so there is no single conformant document: this is a
    // bare JSON ARRAY of verbatim ones. NOT through emit(), whose top-level `ok`
    // is invalid in all three schemas.
    const bundles = results.map(r => r.phases?.close?.evidence_package?.bundles_by_format?.[fmt === "csaf" ? "csaf-2.0" : fmt]).filter(Boolean);
    process.stdout.write(JSON.stringify(bundles, null, pretty ? 2 : 0) + "\n");
  } else if (fmt && fmt !== "json") {
    // A format typo is operator error (GENERIC_FAILURE), not DETECTED_ESCALATE;
    // emitError's ok:false contract carries that code.
    const CI_FORMATS = ["summary", "markdown", "csaf-2.0", "sarif", "openvex", "json"];
    const dym = suggestFlag(String(fmt), CI_FORMATS);
    const hint = dym ? ` Did you mean "${dym}"?` : '';
    emitError(
      `ci: --format "${fmt}" not in accepted set ${JSON.stringify(CI_FORMATS)}.${hint}`,
      { verb: "ci", provided: fmt, accepted: CI_FORMATS, did_you_mean: dym ? [dym] : [] },
      pretty
    );
    return;
  } else {
    emit({ verb: "ci", session_id: sessionId, playbooks_run: ids, summary, results }, pretty, (obj) => {
      const s = obj.summary;
      const lines = [];
      lines.push(`ci: ${obj.playbooks_run.length} playbook(s)  session-id: ${obj.session_id}`);
      const verdictIcon = s.verdict === "PASS"
        ? "[ok]"
        : s.verdict === "BLOCKED"
          ? "[!! BLOCKED]"
          : s.verdict === "CLOCK_STARTED"
            ? "[!! CLOCK]"
            : s.verdict === "NO_EVIDENCE"
              ? "[i  NO_EVIDENCE]"
              : "[!! FAIL]";
      lines.push(`\n${verdictIcon}  verdict=${s.verdict}  detected=${s.detected}  inconclusive=${s.inconclusive}  clean=${s.not_detected}  blocked=${s.blocked}  max_rwep=${s.max_rwep_observed}`);

      const rows = (obj.results || []).map(r => {
        if (r && r.ok === false) {
          return {
            id: r.playbook_id || "?",
            verdict: "blocked",
            rwep: "-",
            evidence: r.evidence_completeness || "not-evaluated",
            top: r.blocked_by || r.reason || r.error || "",
          };
        }
        const cls = r?.phases?.detect?.classification || r?.verdict || "?";
        return {
          id: r.playbook_id || "?",
          verdict: cls,
          rwep: (r?.rwep_score != null) ? String(r.rwep_score) : "-",
          evidence: r?.evidence_completeness || "unknown",
          top: r?.top_finding || "",
        };
      });
      const wId = Math.max(8, ...rows.map(r => r.id.length));
      const wV = Math.max(8, ...rows.map(r => r.verdict.length));
      const wR = Math.max(4, ...rows.map(r => r.rwep.length));
      const wE = Math.max(8, ...rows.map(r => r.evidence.length));
      const pad = (s, w) => (s + " ".repeat(w)).slice(0, w);
      lines.push("");
      lines.push(`  ${pad("playbook", wId)}  ${pad("verdict", wV)}  ${pad("rwep", wR)}  ${pad("evidence", wE)}  finding`);
      lines.push(`  ${"-".repeat(wId)}  ${"-".repeat(wV)}  ${"-".repeat(wR)}  ${"-".repeat(wE)}  -------`);
      for (const row of rows) {
        const finding = row.top.length > 80 ? row.top.slice(0, 77) + "..." : row.top;
        lines.push(`  ${pad(row.id, wId)}  ${pad(row.verdict, wV)}  ${pad(row.rwep, wR)}  ${pad(row.evidence, wE)}  ${finding}`);
      }

      if (s.runtime_warnings && s.runtime_warnings.length) {
        lines.push(`\nSession warnings (${s.runtime_warnings_count}):`);
        for (const w of s.runtime_warnings) {
          const reason = (w.reason || "").length > 200 ? (w.reason || "").slice(0, 197) + "..." : (w.reason || "");
          lines.push(`  [${w.kind || "warning"}] ${reason}`);
          if (w.remediation) lines.push(`    → ${w.remediation}`);
        }
      }

      if (s.scope_inclusion_rules && s.scope_inclusion_rules.length) {
        lines.push(`\nScope selection (${s.scope_request}):`);
        for (const rule of s.scope_inclusion_rules) lines.push(`  - ${rule}`);
      }

      if (s.jurisdiction_clocks_started > 0) {
        lines.push(`\nJurisdiction clocks started: ${s.jurisdiction_clocks_started}`);
        const clocks = s.jurisdiction_clock_rollup || [];
        for (const n of clocks.slice(0, 5)) {
          lines.push(`  ${n.jurisdiction || "?"}/${n.regulation || "?"} → deadline ${n.deadline || "?"}`);
        }
        if (clocks.length > 5) lines.push(`  … ${clocks.length - 5} more (--json for all)`);
      }

      if (s.framework_gap_count > 0) {
        lines.push(`\nFramework gaps (${s.framework_gap_count}):`);
        const fgaps = s.framework_gap_rollup || [];
        for (const g of fgaps.slice(0, 5)) {
          lines.push(`  ${g.framework || "?"} :: ${g.claimed_control || "?"}  (${g.playbooks.length} playbook(s))`);
        }
        if (fgaps.length > 5) lines.push(`  … ${fgaps.length - 5} more (--json for all)`);
      }

      if (s.fail_reasons && s.fail_reasons.length) {
        lines.push(`\nFail reasons:`);
        for (const r of s.fail_reasons) lines.push(`  - ${r}`);
      }

      // Next-step guidance, keyed on verdict.
      const blockedRows = (obj.results || []).filter(r => r && r.ok === false);
      // The id pads to a common width so the trailing `#` comments align.
      const lintCmd = (id, w) => `  exceptd lint ${(id + " ".repeat(w)).slice(0, w)} -   # paste {} on stdin, get exact JSON paths`;
      if (s.verdict === "BLOCKED" && blockedRows.length) {
        lines.push(`\nNext steps (unblock the ${blockedRows.length} halted playbook(s)):`);
        const shown = blockedRows.slice(0, 4);
        const wLint = Math.max(...shown.map(r => (r.playbook_id || "?").length));
        for (const row of shown) {
          lines.push(lintCmd(row.playbook_id || "?", wLint));
        }
        lines.push(`  exceptd run <playbook> --evidence <file>     # re-run after filling in evidence`);
      } else if (s.verdict === "NO_EVIDENCE") {
        const firstId = (obj.results[0] && obj.results[0].playbook_id) || (obj.playbooks_run[0]) || "<playbook>";
        lines.push(`\nNext steps (every playbook ran inconclusive — no evidence supplied):`);
        lines.push(lintCmd(firstId, firstId.length));
        lines.push(`  exceptd ci --scope <type> --evidence-dir <dir>  # gate again with real submissions`);
      } else if (s.verdict === "FAIL") {
        // FAIL has two shapes: a detected classification, or an inconclusive
        // playbook whose rwep_delta crossed the cap with s.detected still 0.
        if (s.detected > 0) {
          // One row per detected id, not just the first.
          const detectedIds = (obj.results || [])
            .filter(r => r && r.ok !== false && r.phases?.detect?.classification === "detected")
            .map(r => r.playbook_id)
            .filter(Boolean);
          const ids = detectedIds.length ? detectedIds : ["<playbook>"];
          lines.push(`\nNext steps (review the ${s.detected} detected finding(s) in ${detectedIds.join(", ") || "<playbook>"}):`);
          for (const id of ids) {
            lines.push(`  exceptd run ${id} --format markdown    # operator-readable digest`);
          }
          for (const id of ids) {
            lines.push(`  exceptd run ${id} --format csaf-2.0    # advisory bundle for downstream`);
          }

          // Pending obligations roll up here, so gating a PR gives the same
          // regulatory-clock visibility a single `run` does.
          const pendingByEvent = {};
          let pendingTotal = 0;
          for (const r of obj.results || []) {
            if (r?.phases?.detect?.classification !== "detected") continue;
            const notif = r?.phases?.close?.notification_actions || [];
            for (const n of notif) {
              if (n.clock_started_at) continue;
              const ev = n.clock_start_event || "unspecified";
              if (!pendingByEvent[ev]) pendingByEvent[ev] = new Set();
              pendingByEvent[ev].add(`${n.jurisdiction || "?"}/${n.regulation || "?"} (${n.window_hours || "?"}h)`);
              pendingTotal++;
            }
          }
          if (pendingTotal > 0) {
            lines.push(`\nPending jurisdiction obligations across detected playbook(s) (${pendingTotal}) — clock starts on operator action:`);
            for (const [ev, refs] of Object.entries(pendingByEvent)) {
              lines.push(`  on ${ev}:  ${[...refs].join(", ")}`);
            }
          }
        } else {
          // Operator evidence pushed RWEP past --max-rwep on an inconclusive run:
          // the choice is escalate, or raise the cap.
          const inconclusivePb = (obj.results || [])
            .filter(r => r && r.ok !== false && r.phases?.detect?.classification === "inconclusive")
            .map(r => r.playbook_id)
            .filter(Boolean);
          const exampleId = inconclusivePb[0] || (obj.playbooks_run && obj.playbooks_run[0]) || "<playbook>";
          lines.push(`\nNext steps (RWEP-delta cap exceeded — no playbook hit "detected", but operator evidence raised at least one score past --max-rwep):`);
          lines.push(`  exceptd run ${exampleId} --pretty           # inspect phases.analyze.rwep.base + adjusted to see which signal moved the score`);
          lines.push(`  exceptd ci ... --max-rwep <higher>           # raise the cap if the evidence-driven escalation is acceptable for your gate`);
        }
      } else if (s.verdict === "CLOCK_STARTED") {
        lines.push(`\nNext steps (jurisdiction clock running — notification deadlines above):`);
        lines.push(`  exceptd run <playbook> --format csaf-2.0    # draft the operator-of-record advisory`);
      }

      lines.push(`\nFull structured result: --json (or --pretty for indented JSON).`);
      return lines.join("\n");
    });
  }
  // BLOCKED is checked BEFORE FAIL: the loop pushes blocked entries onto
  // failReasons, so an earlier `if (fail)` reports exit 2 (detected) for a playbook
  // that never evaluated a signal. Precedence matches --help.
  if (summary.blocked > 0) {
    const blockedReasons = failReasons.filter(r => r.includes("blocked"));
    process.stderr.write(`[exceptd ci] BLOCKED: ${summary.blocked}/${summary.total} playbook(s) halted before detect. Exit ${EXIT_CODES.BLOCKED}. Reasons:\n  ${blockedReasons.join("\n  ")}\n`);
    process.exitCode = EXIT_CODES.BLOCKED;
    return;
  }
  if (clockStartedFail) {
    process.stderr.write(`[exceptd ci] CLOCK_STARTED: ${clockStartedReasons.join("; ")}. Exit ${EXIT_CODES.JURISDICTION_CLOCK_STARTED}.\n`);
    process.exitCode = EXIT_CODES.JURISDICTION_CLOCK_STARTED;
    return;
  }
  if (fail) {
    process.stderr.write(`[exceptd ci] FAIL: ${failReasons.join("; ")}\n`);
    // `process.exitCode`, not `process.exit()` — emit()'s stdout must flush.
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

module.exports = {
  COMMANDS, PKG_ROOT, PLAYBOOK_VERBS, persistAttestation,
  // internal helpers exposed for tests
  _isTamperedSidecarVerify: isTamperedSidecarVerify,
  _classifySidecarVerify: classifySidecarVerify,
  _verifyAttestationSidecar: verifyAttestationSidecar,
  _emit: emit,
  _diffArtifacts: diffArtifacts,
  _diffSignalOverrides: diffSignalOverrides,
  _resolveSelfAttestation: resolveSelfAttestation,
  _readEvidenceDir: readEvidenceDir,
};
