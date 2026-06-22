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
 *   brief [--all]         Phases 1-3 (govern/direct/look) in one info doc.
 *     <playbook>          Add --phase govern|direct|look for a single phase.
 *   run <playbook>        Phases 4-7 (detect/analyze/validate/close) from
 *                         agent submission JSON.
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
const { EXIT_CODES, listExitCodes, safeExit } = require(path.join(PKG_ROOT, "lib", "exit-codes.js"));
const { validateIdComponent } = require(path.join(PKG_ROOT, "lib", "id-validation.js"));
const { suggestFlag, flagsFor, VERB_FLAG_ALLOWLIST } = require(path.join(PKG_ROOT, "lib", "flag-suggest.js"));
const codepointClass = require(path.join(PKG_ROOT, "vendor", "blamejs", "codepoint-class.js"));

// Union of every flag known to ANY verb. A flag that is valid somewhere but
// not on the active verb (e.g. `--csaf-status` on `brief`) is cross-verb
// misuse, not a typo — it falls through to the verb handler, which emits a
// tailored "that flag belongs on a run-class verb" message. Only a flag that
// is unknown EVERYWHERE is refused outright as a typo/garbage at the
// dispatcher. Kept module-scope so it is computed once.
const ALL_KNOWN_FLAGS = new Set(
  Object.values(VERB_FLAG_ALLOWLIST).flat()
);

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
  // Citation resolvers — answer "is this CVE/RFC citation valid?" offline-first
  // (catalog/index -> resolved cache -> opt-in single network lookup, cached).
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

// Levenshtein-1 did-you-mean for unknown verbs.
// Catches common single-char / transposition typos against the COMMANDS
// table without false-positive flood: only suggests verbs within distance
// 1 (one insert / delete / substitute / transpose). For typed-distance 2+
// the operator probably mistyped intent and `exceptd help` is the right
// route. The function is exported via the closure into the dispatch
// site; no module.exports — bin/exceptd.js is the CLI entry, not a library.
function levenshtein1(a, b) {
  if (a === b) return 0;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return 2; // short-circuit: can't be ≤ 1
  // single-edit distance check, early-out at first 2nd mismatch
  let i = 0, j = 0, edits = 0;
  while (i < la && j < lb) {
    if (a.charCodeAt(i) !== b.charCodeAt(j)) {
      if (++edits > 1) return 2;
      // adjacent-swap transposition (e.g. "discoer" ↔ "discover") counts
      // as a single edit operationally, even though pure-Levenshtein
      // distance would be 2. Detect + treat as 1.
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
// v0.11.0 introduces: brief (collapses plan/govern/direct/look), discover (scan + dispatch),
// doctor (currency + verify + validate-cves + validate-rfcs), ci (CI gate),
// ai-run (streaming JSONL), ask (plain-English routing).
//
// v0.13.0 removed the v0.10.x phase-name aliases (plan, govern, direct,
// look, ingest). They were deprecation-bannered since v0.11.0 and
// slated-for-removal-in-v0.13 since v0.12.0; v0.13 honors that contract.
// REMOVED_VERBS below carries the rename map for operator-facing refusal
// hints. `reattest` and `list-attestations` are preserved as canonical
// routings — they're short forms of `attest diff` / `attest list` that
// remain operationally useful and have substantial test coverage.
const PLAYBOOK_VERBS = new Set([
  "brief", "run", "ai-run", "attest", "discover", "doctor", "ci", "ask",
  "verify-attestation", "run-all", "lint", "collect",
  "reattest", "list-attestations", "recipes",
]);

// v0.13.0: hard-removed legacy verbs. The dispatcher refuses the verb
// with an actionable replacement hint instead of routing it. Pre-v0.13
// these were soft-deprecated (banner + still functional); v0.13 removes
// the routing entirely. Operators upgrading from v0.10.x → v0.13 see
// the same hint that the deprecation banner previously surfaced, but
// non-zero exit so scripts noticing pinned-name use fail loudly instead
// of silently invoking the alias.
const REMOVED_VERBS = {
  plan: "brief --all",
  govern: "brief <pb> --phase govern",
  direct: "brief <pb> --phase direct",
  look: "brief <pb> --phase look",
  ingest: "run",
};

/**
 * v0.13.5: Windows ACL audit helper for `doctor --ai-config`. Replaces
 * the v0.13.3 "manual review" placeholder with a real check.
 *
 * Runs `icacls <path>` and parses the output for any principal beyond
 * the current user. Anything other than the running USERNAME, NT
 * AUTHORITY\SYSTEM, and BUILTIN\Administrators on the ACL counts as
 * "broader than user-only" — typical offenders are inherited entries
 * for BUILTIN\Users, Authenticated Users, or Everyone.
 *
 * Returns { ok: boolean, extraPrincipals: string[], error?: string }.
 * On non-Windows hosts (defensive — only invoked from the win32 branch
 * in cmdDoctor anyway), returns { ok: true, extraPrincipals: [] }.
 */
function checkWindowsAcl(targetPath) {
  if (process.platform !== 'win32') return { ok: true, extraPrincipals: [] };
  const childProc = require('child_process');
  const user = (process.env.USERNAME || '').toLowerCase();
  // Principals that are EXPECTED on every Windows ACL and don't count
  // as "broader than user-only" — admins legitimately need access for
  // system maintenance; SYSTEM is required for backup/restore.
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
  // icacls output format: each principal on its own line, prefixed by
  // whitespace and ending with permission bits in parens. Lines for
  // the file itself (target path) and the "Successfully processed"
  // footer are skipped.
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.toLowerCase().startsWith('successfully processed')) continue;
    // The first line is the path; principal lines start with NT AUTHORITY,
    // BUILTIN, or a domain\user. Match `name:(perms)` shape.
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

  // --json-stdout-only: silence ALL stderr emissions (deprecation banners,
  // unsigned-attestation warnings, hook output). Operators piping the JSON
  // result through `jq` or scripting around exit codes want clean stdout
  // exclusively. Handled here at top of main so the deprecation banner +
  // unsigned warning are suppressed before they fire.
  if (argv.includes("--json-stdout-only")) {
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
    // Route the canonical error envelope (emitError) to STDOUT under this flag.
    // Without it, --json-stdout-only sends all diagnostics to stderr and then
    // suppresses non-"Error"-prefixed stderr — but emitError's ok:false body is
    // neither stdout-bound nor "Error"-prefixed, so an error invocation produced
    // NO diagnostic on stdout OR stderr (just an exit code). A `| jq` consumer
    // reading stdout would see an empty document on every failure. Set a
    // dedicated global so emitError can detect the flag and write its JSON
    // envelope to stdout (where the consumer is already reading) instead.
    global.__exceptdJsonStdoutOnly = true;
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, encoding, cb) => {
      // Let actual error frames through (uncaught exceptions need to surface
      // for debugging); suppress framework stderr.
      if (typeof chunk === "string" && chunk.startsWith("Error")) return origStderrWrite(chunk, encoding, cb);
      if (typeof cb === "function") cb();
      return true;
    };
  }

  // --quiet: suppress advisory stderr chatter — the "[exceptd] note:" and
  // "[exceptd] tip:" lines, the deprecation banner, and the unsigned-
  // attestation warning — while keeping the actual result on stdout and all
  // errors on stderr. Narrower than --json-stdout-only, which silences ALL
  // stderr and forces JSON output; --quiet preserves human-readable output and
  // exit codes and only drops the non-essential advisories. Skipped when
  // --json-stdout-only is also present (that flag already silenced everything
  // and patched stderr first; double-wrapping would be redundant).
  if (argv.includes("--quiet") && !argv.includes("--json-stdout-only")) {
    global.__exceptdQuiet = true;
    process.env.EXCEPTD_DEPRECATION_SHOWN = "1";
    process.env.EXCEPTD_UNSIGNED_WARNED = "1";
    const origStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, encoding, cb) => {
      // Drop only the advisory-prefixed lines. Contract-violation notes
      // ("[exceptd run] ..."), error frames, and uncaught exceptions still
      // surface so --quiet never hides why a run failed or exited non-zero.
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
    // `exceptd help <verb>` previously dropped the
    // verb argument and printed the top-level help. Route through the same
    // printPlaybookVerbHelp() that `exceptd <verb> --help` already uses so
    // operators get a consistent verb-specific help surface regardless of
    // which way they reached it.
    if (rest.length > 0 && typeof rest[0] === 'string' && rest[0].length > 0) {
      const verb = rest[0];
      // A removed verb has no live help. Refuse with the same structured
      // removal error the bare verb emits, so `help <removed>` and
      // `<removed> --help` agree (both exit non-zero, both name the
      // replacement) instead of printing stale help for a verb that no
      // longer dispatches.
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
      // Verb not found — emit a one-line note pointing at the top-level
      // help so operators don't silently see the wrong content.
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
        safeExit(EXIT_CODES.SUCCESS); return;
      }
      process.stderr.write(`[exceptd path] copy: no clipboard tool available (tried: ${tried.join(", ")}). Path printed to stdout instead.\n`);
      process.stdout.write(PKG_ROOT + "\n");
      safeExit(EXIT_CODES.SUCCESS); return;
    }
    process.stdout.write(PKG_ROOT + "\n");
    safeExit(EXIT_CODES.SUCCESS); return;
  }

  // v0.13.0: hard-refuse the v0.10.x legacy verbs that were
  // deprecation-bannered since v0.11.0. Pre-v0.13 these silently routed
  // to their v0.11+ replacements with a soft banner; v0.13 honors the
  // long-advertised removal. Operators upgrading from v0.10.x get a
  // structured error with the replacement command, suitable for
  // grep / scripted handling.
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
    // so the stderr JSON drains before teardown; promote the exit code to
    // UNKNOWN_COMMAND (10) afterwards. Cycle 9 split this away from
    // DETECTED_ESCALATE (2) — the two semantics had collided since v0.12.24.
    //
    // add a did-you-mean suggestion when the
    // unknown verb is within Levenshtein-1 of a real verb (catches the
    // common single-char typos: `discoer` → `discover`, `attst` → `attest`,
    // `valdiate-cves` → `validate-cves`).
    // Union of every verb the dispatcher knows: standalone COMMANDS (scan,
    // currency, build-indexes, etc.), in-process PLAYBOOK_VERBS (run, ci,
    // discover, attest, ...), and ORCHESTRATOR_PASSTHROUGH. Strip the
    // flag-aliases (--version/-v/--help/-h) which already get caught above
    // the dispatch path. De-dup via Set — these collections deliberately
    // overlap (scan/dispatch/etc appear in both COMMANDS and
    // ORCHESTRATOR_PASSTHROUGH) and a naive union would surface duplicate
    // suggestions like `did_you_mean: ["scan", "scan"]`. (codex P2,
    // v0.12.37 follow-up.)
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
    // emitError + exitCode rather than stderr + exit() so the JSON drains.
    emitError(
      `command "${cmd}" not available — expected ${path.relative(PKG_ROOT, script)} in the installed package.`,
      { verb: cmd }
    );
    process.exitCode = EXIT_CODES.UNKNOWN_COMMAND;
    return;
  }

  // `skill` and `framework-gap` are spawned subcommands that never reach the
  // in-process per-verb --help, and (unlike `refresh`/`prefetch`, which print
  // their own help) the orchestrator forwards `--help` as a positional —
  // `skill --help` tried to resolve a skill literally named "--help"
  // ("Skill not found: --help") and `framework-gap --help` errored on missing
  // args. Intercept --help for just these so they honor it. Scoped to the
  // verbs that lack their own help handler, so spawns that do (refresh,
  // prefetch) keep their detailed usage.
  const SPAWN_HELP_USAGE = {
    skill: "exceptd skill <name>          Show the full context document for one skill. Run `exceptd skill` with no arguments to list all skill IDs.",
    "framework-gap": "exceptd framework-gap <framework> <cve-or-scenario>   One-framework gap analysis.",
    "framework-gap-analysis": "exceptd framework-gap <framework> <cve-or-scenario>   One-framework gap analysis.",
    cve: "exceptd cve <CVE-ID> [--json] [--air-gap|--no-network]   Resolve a CVE: published/rejected/disputed/fabricated/nonexistent (catalog -> cache -> NVD). Exit 2 when the citation won't stand up (rejected/fabricated/nonexistent/withdrawn).",
    rfc: "exceptd rfc <number> [--check \"<title>\"] [--json] [--air-gap]   Resolve an RFC number -> title + status (local index, offline). Exit 2 when nonexistent or --check title MISMATCH.",
    // watch MUST be here: without the interception `watch --help` falls through
    // to spawning the blocking daemon, hanging the operator's terminal.
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

  // Orchestrator subcommands need the subcommand name preserved as argv[0]
  // for orchestrator/index.js's switch statement.
  const finalArgs = ORCHESTRATOR_PASSTHROUGH.has(effectiveCmd) ? [script, effectiveCmd, ...effectiveRest] : [script, ...effectiveRest];
  const res = spawnSync(process.execPath, finalArgs, { stdio: "inherit", cwd: PKG_ROOT });
  if (res.error) {
    // emitError + exitCode rather than stderr + exit() so the JSON drains.
    emitError(`failed to run ${cmd}: ${res.error.message}`, { verb: cmd });
    process.exitCode = EXIT_CODES.UNKNOWN_COMMAND;
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
    process.exitCode = EXIT_CODES.GENERIC_FAILURE;
  }
  // v0.13.0 envelope harmonization: every emitted body has a top-level
  // `ok` field — defaults to true when not set, matching the symmetric
  // ok:false → exitCode=1 fallback above. Consumers that parse stdout
  // can now assume the envelope shape regardless of which verb produced
  // the body. Per-site `verb: "<name>"` is set at the call site; this
  // helper guarantees the `ok` field's presence but does not synthesize
  // verb (the caller knows its own name).
  //
  // Arrays are excluded: spreading an array into an object literal would
  // produce numeric string keys ({"0":…,"1":…}) plus a spurious ok:true
  // envelope, corrupting array-shaped output. Array bodies (standard
  // documents like SARIF results / OpenVEX statements) pass through
  // verbatim — matching the verbatim-write path those documents already
  // use, which deliberately strips the envelope rather than injecting it.
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
  // Stderr + exitCode + return (defends stdout drain under piped
  // consumers — same class as emit()'s v0.11.13 fix).
  //
  // Output shape branches on whether stderr is attached to a TTY:
  //   - piped (CI parsers, smart-agent retry, tests using
  //     `tryJson(r.stderr)`): JSON envelope — the load-bearing
  //     contract for programmatic consumers.
  //   - interactive (operator at a terminal): human-readable
  //     "error: <msg>" + indented helper lines. Operators wanting
  //     the structured envelope explicitly can pass --json.
  // Explicit --json / --pretty / --json-stdout-only also force JSON
  // regardless of TTY (e.g. an operator redirecting to a file).
  const body = Object.assign({ ok: false, error: msg }, extra || {});
  // --json-stdout-only routes the envelope to stdout (below), so the envelope
  // MUST be JSON. For a top-level error raised before flag parsing sets
  // __exceptdWantJson (an unknown/removed verb), the stdout-only flag is the
  // only signal present — fold it into the JSON selection so a human string is
  // never written to the machine-readable stdout channel (breaking `| jq`).
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
  // Under --json-stdout-only, route the JSON error envelope to STDOUT (where the
  // consumer is already reading machine-readable output) instead of the
  // suppressed stderr channel — otherwise the error would surface on neither
  // stream. The flag forces JSON (global.__exceptdWantJson is set via
  // args._jsonMode), so `s` here is already the JSON envelope, not human text.
  if (global.__exceptdJsonStdoutOnly) {
    process.stdout.write(s + "\n");
  } else {
    process.stderr.write(s + "\n");
  }
  process.exitCode = EXIT_CODES.GENERIC_FAILURE;
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

// Evidence must be a JSON object. `null`, an array, or a scalar parse as valid
// JSON but are not a submission — without this guard `null` NPE'd deep in the
// runner ("internal error") and `[]` / a wrong-typed field were silently
// accepted and run as if empty, so an operator believed a malformed submission
// was evaluated. Reject at the read boundary with an actionable message.
function asEvidenceObject(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    const got = parsed === null ? "null" : Array.isArray(parsed) ? "array" : typeof parsed;
    throw new Error(`evidence must be a JSON object (e.g. {"artifacts": {...}, "signal_overrides": {...}}); got ${got}. Run \`exceptd brief <playbook>\` for the expected shape.`);
  }
  return parsed;
}

function readEvidence(evidenceFlag, opts = {}) {
  if (!evidenceFlag) return {};
  // v0.12.12: file-path branch enforces a max size to defend against an
  // operator accidentally passing a multi-gigabyte file (binary, log, or
  // adversarial JSON bomb). 32 MB is well beyond any legitimate
  // submission and still drains in a single read on modern hardware.
  // v0.12.35 (cycle 15 security F1): apply the SAME cap to the stdin
  // branch. Pre-fix `--evidence -` was uncapped — an attacker piping
  // multi-GB JSON would OOM the runner. Read in 1 MB chunks and bail
  // at the limit rather than letting Node grow the heap unbounded.
  const MAX_EVIDENCE_BYTES = 32 * 1024 * 1024;
  if (evidenceFlag === "-") {
    // fs.readFileSync(0) does NOT respect a maxBuffer option, so we read
    // incrementally to enforce the cap. Stdin is a pipe / fifo on every
    // platform; reading until EOF in chunks is correct.
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
      // pre-fix empty stdin silently became {}
      // — operator got a "successful" run on no evidence with no warning,
      // and the evidence_hash for `{}` is deterministic so subsequent
      // runs didn't even reveal the mistake. Emit a stderr nudge so the
      // operator at least sees that stdin was empty when they almost
      // certainly meant to pipe something. Don't change exit semantics;
      // the empty-payload path is still legitimately useful for posture-
      // only playbooks (govern + direct + look-only walks).
      //
      // Only nudge when `--evidence -` was EXPLICITLY requested. On the stdin
      // auto-promotion path (no --evidence flag, just a non-TTY handle such as
      // `run kernel </dev/null` or a CI runner) the operator never asked to
      // read stdin, so an empty read is not a mistake to flag — and emitting to
      // stderr there corrupted `run ... 2>&1 | jq` pipelines that worked at a
      // TTY but broke in CI.
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
  // Route through readJsonFile() for UTF-8-BOM / UTF-16 tolerance.
  // Windows-tool-emitted JSON commonly carries these markers; the raw "utf8"
  // decode in readFileSync chokes on the leading 0xFEFF.
  return asEvidenceObject(readJsonFile(evidenceFlag));
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
  // `echo {...} | exceptd run|ai-run` invocation.
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
function validateIsoSince(raw, flagName = "--since") {
  if (typeof raw !== "string" || !ISO_DATE_RE.test(raw) || isNaN(Date.parse(raw))) {
    return `${flagName} must be a parseable ISO-8601 calendar timestamp (e.g. 2026-05-01 or 2026-05-01T00:00:00Z). Got: ${JSON.stringify(String(raw)).slice(0, 80)}`;
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
    safeExit(EXIT_CODES.SUCCESS); return;
  }

  const args = parseArgs(argv, {
    bool:  ["pretty", "air-gap", "force-stale", "all", "flat", "directives",
            "ci", "latest", "diff-from-latest", "explain", "signal-list", "ack",
            "force-overwrite", "no-stream", "block-on-jurisdiction-clock",
            "force-replay",
            "json-stdout-only", "fix", "human", "json", "strict-preconditions",
            // v0.12.27: --bundle-deterministic opts the bundle build into
            // byte-stable output (frozen timestamps, deterministic session_id
            // fallback, sorted vulnerabilities[] / statements[]). Pairs with
            // --bundle-epoch <ISO> for the frozen timestamp value.
            "bundle-deterministic",
            // v0.12.9: doctor --shipped-tarball runs the verify-shipped-tarball
            // gate alongside --signatures. doctor --registry-check + --signatures
            // were already accepted; explicit registration removes the silent
            // "unknown bool flag" surface in parseArgs.
            "shipped-tarball", "registry-check", "signatures", "currency", "cves", "rfcs",
            // doctor --collectors health-checks the collector layer.
            "collectors",
            // doctor --exit-codes dumps the canonical exit-code table.
            "exit-codes",
            // ci / run --include-judgement-shaped opts the operator in to
            // policy-skipped playbooks (governance / incident) that the
            // default scope filter excludes.
            "include-judgement-shaped"],
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
    "cwd",  // exceptd collect <pb> --cwd <path>
    "limit",  // exceptd attest list --limit <n>
    "required",  // exceptd ci --required <pb,pb> — value-less form must refuse, not `true.split(",")`
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
    // A flag valid on SOME other verb (e.g. `--csaf-status` on `brief`) is
    // cross-verb misuse — fall through so the verb handler can emit its
    // tailored "that flag belongs on a run-class verb" guidance rather than
    // a blanket refusal here.
    if (ALL_KNOWN_FLAGS.has(key)) continue;
    // Unknown everywhere — refuse it as a typo / unsupported flag. Silently
    // ignoring an unrecognized flag let a mistyped cap or output-format flag
    // look like it applied when it did nothing. Surface a suggestion
    // when one is close, and always list the accepted flags so the operator
    // can self-correct. Adding a new flag to a verb means appending it to
    // that verb's allowlist (or PASSTHROUGH_FLAGS) — the test suite exercises
    // every shipped flag, so a missing registration fails CI rather than
    // silently breaking the flag.
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
  if (args["session-id"] !== undefined) {
    // --session-id is a filesystem path component (resolves to
    // .exceptd/attestations/<id>/attestation.json). Operator-supplied input
    // with `..` or path separators escapes the attestation root. Route
    // through the shared validateIdComponent('session') helper so the regex
    // + all-dots refusal stay aligned with persistAttestation /
    // validateSessionIdForRead.
    //
    // Presence-gated (`!== undefined`), not truthy-gated: `--session-id ""`
    // / `--session-id=` carry an explicit empty value the operator meant to
    // pin. A truthy gate skips the validator for "", silently substituting a
    // random id and discarding the operator's intent. validateIdComponent
    // rejects "" with "must not be empty", matching the --operator empty
    // refusal below.
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
    // v0.12.12: --attestation-root must resolve to an absolute path the
    // operator owns. Reject `..`-bearing relatives at input so a misconfigured
    // env doesn't write outside the intended root. Final resolution still
    // happens in resolveAttestationRoot — this is the input-validation layer.
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
    // All-dots segments (`.`, `..`, `...`, etc.) all resolve into or above
    // the intended parent directory, defeating the attestation-root
    // confinement check. Refuse any non-empty segment that is entirely dots
    // — the leading-`.` empty segment of an absolute POSIX path is allowed,
    // and a single `.` mid-path means "this dir" but is collapsed by
    // path.resolve anyway; explicit refusal is cheaper than reasoning about
    // every collapsed-equivalent shape.
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
    // Bug #33: validate that --session-key is hex. Previously any string was
    // silently accepted; HMAC signing then either failed silently or produced
    // an unverifiable signature.
    if (!/^[0-9a-fA-F]+$/.test(args["session-key"])) {
      return emitError(`${cmd}: --session-key must be hex characters only (0-9, a-f). Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`, { verb: cmd, provided_length: args["session-key"].length }, pretty);
    }
    if (args["session-key"].length < 16) {
      return emitError(`${cmd}: --session-key is too short (need at least 16 hex chars / 64 bits of entropy).`, { verb: cmd, provided_length: args["session-key"].length }, pretty);
    }
    runOpts.session_key = args["session-key"];
  }
  if (args.mode !== undefined) {
    // Bug #32: validate --mode against the accepted set. Previously
    // `--mode garbage` was silently accepted. Gate on `!== undefined` (not
    // truthiness) so `--mode ""` is also rejected by the set check below rather
    // than silently slipping past as a falsy value.
    const VALID_MODES = ["self_service", "authorized_pentest", "ir_response", "ctf", "research", "compliance_audit"];
    if (!VALID_MODES.includes(args.mode)) {
      // v0.13.2: did-you-mean on flag-value typos (Levenshtein ≤ 2).
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
    // The ASCII-only control-char regex above misses Unicode categories
    // Cc / Cf / Co / Cn — bidi overrides (U+202E "RTL OVERRIDE"),
    // zero-width joiners (U+200B-D), invisible format chars, private-use
    // codepoints, unassigned codepoints. An operator string like
    // allow:bidi-codepoint-literal — illustrative bidi-forgery example in the --operator reject-path doc comment
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
      // \p{C} (Cc/Cf/Cs/Co/Cn) is the reject gate — it is strictly broader
      // than the named family regexes (bidi / C0-control / zero-width / null),
      // so it stays the backstop and catches the divergent remainder the
      // family tables miss (U+007F, U+0080-009F, private-use, unassigned).
      // The vendored codepoint tables only CLASSIFY the first offending
      // codepoint into a human family name for the hint.
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

  // --csaf-status and --publisher-namespace shape the CSAF bundle emitted by
  // phases 5-7. Verbs that don't drive those phases (brief, attest,
  // list-attestations, discover, doctor, lint, ask, verify-attestation,
  // reattest) never assemble a bundle, so silently consuming these flags is
  // a UX trap. Refuse on those verbs so the operator knows the flag was
  // discarded — same pattern as --ack. Error message templates and emitError
  // prefixes use the in-scope `cmd` verb so a brief invocation says "brief:"
  // rather than misattributing the flag to run.
  const BUNDLE_FLAG_RELEVANT_VERBS = new Set([
    "run", "ci", "run-all", "ai-run",
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

  // --tlp stamps the bundle's distribution marking (CSAF document.distribution
  // TLP). Previously this flag was allowlisted but never wired into runOpts, so
  // it was a silent no-op; the runner already emits distribution from
  // runOpts.tlp. Validate against TLP 2.0 labels and refuse on info-only verbs,
  // matching --csaf-status.
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

  // --bundle-deterministic + --bundle-epoch (v0.12.27): opt-in deterministic
  // bundle emit. When set, CSAF / OpenVEX / close-envelope timestamps freeze
  // to the supplied epoch (or the playbook's last_threat_review fallback),
  // the auto-generated session_id derives from sha256(playbook + evidence_hash
  // + engine_version) when the operator did not pass --session-id, and
  // vulnerabilities[] / statements[] sort deterministically. Opt-in so the
  // default emit path stays byte-identical to pre-v0.12.27 output.
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
    // Reuse validateIsoSince — the same calendar-shape gate used for --since.
    const isoErr = validateIsoSince(epoch);
    if (isoErr) {
      return emitError(
        `${cmd}: --bundle-epoch must be a parseable ISO-8601 calendar timestamp (e.g. 2026-01-01T00:00:00Z). Got: ${JSON.stringify(epoch).slice(0, 80)}`,
        { verb: cmd, flag: "bundle-epoch", provided: epoch.slice(0, 80) },
        pretty
      );
    }
    // Normalise to a full ISO timestamp so downstream consumers don't have
    // to handle the date-only shape. Date-only inputs render as
    // YYYY-MM-DDT00:00:00.000Z; full timestamps round-trip unchanged modulo
    // ms precision (Date.prototype.toISOString always emits ms).
    runOpts.bundleEpoch = new Date(epoch).toISOString();
  }

  // --ack: operator acknowledges the jurisdiction obligations surfaced by
  // govern. Captured in attestation; downstream tooling can check whether
  // consent was explicit vs. implicit. AGENTS.md says the AI should surface
  // and wait for ack — this is how the ack gets recorded.
  //
  // --ack only makes sense on verbs that drive phases 5-7 (run / ai-run /
  // ci / run-all / reattest). Info-only verbs (brief, attest,
  // list-attestations, discover, doctor, lint, ask, verify-attestation)
  // never consume an attestation clock — accepting --ack silently is a UX
  // trap where operators believe they have recorded consent. Refuse on those
  // verbs so the operator knows the flag is irrelevant.
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

  // Relevance guard for PASSTHROUGH_FLAGS that are meaningful on only a subset
  // of verbs. PASSTHROUGH_FLAGS short-circuits the typo loop above so it never
  // reaches the cross-verb guidance fall-through — which meant a run-class flag
  // (e.g. --max-rwep, consumed only by `ci`) parked there was silently dropped
  // (exit 0, output unchanged) when supplied to an info-only verb, instead of
  // refused with the same "pass it on a run-class verb" guidance the bundle
  // flags (--csaf-status / --tlp / --ack) already give. Each entry maps the
  // flag to the verbs that actually consume it; supplying it elsewhere is an
  // irrelevant-flag refusal.
  const SINGLE_VERB_PASSTHROUGH = {
    "max-rwep": ["ci"],
    "diff-from-latest": ["run"],
    "upstream-check": ["run"],
    // --cwd is only consumed by collect/discover (which scan a directory). On
    // run/ci/etc. it was silently accepted-and-ignored, so `run secrets --cwd
    // /target` returned a falsely-clean result for a directory never inspected.
    "cwd": ["collect", "discover"],
  };
  for (const [flag, relevantVerbs] of Object.entries(SINGLE_VERB_PASSTHROUGH)) {
    // A value-less boolean flag parses as `true`; a value-bearing one as its
    // string. Either way, presence (not absence) is what we gate on. `false`
    // never occurs from the parser but is treated as "not supplied" for safety.
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
    // v0.11.14 (#131): when the operator typed a skill name (kernel-lpe-triage)
    // and got "Playbook not found," surface the playbooks that load that skill.
    // Playbooks and skills are a many-to-many mapping: operators routinely
    // confuse the two because the website (and AGENTS.md) describe both as
    // runnable.
    const m = e && e.message && e.message.match(/^Playbook not found: ([^\s(]+)/);
    if (m) {
      const wanted = m[1];
      const hint = buildSkillToPlaybookHint(runner, wanted);
      if (hint) {
        return emitError(`Playbook not found: "${wanted}". ${hint}`, { verb: cmd, wanted, type: "playbook_not_found" }, pretty);
      }
    }
    // Distinguish an operator-input validation error from a genuine internal
    // fault. A validation message ("--scope must be one of […]", "must match
    // …") is the operator's to fix — emit it plainly instead of labeling it an
    // "internal error" and inviting a bug report. The NPE/typeerror guards keep
    // real internal faults (that happen to contain "invalid") on the bug path.
    const msg = e && e.message ? String(e.message) : String(e);
    if (
      /\b(must be|must match|not in accepted set|is not a valid|unrecognized)\b|\binvalid /i.test(msg) &&
      msg.length < 300 &&
      !/cannot read prop|is not a function|is not defined|undefined \(reading|maximum call stack/i.test(msg)
    ) {
      return emitError(`${cmd}: ${msg}`, { verb: cmd, type: "validation_error" }, pretty);
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
             `Tip: \`exceptd brief --all\` lists all ${ids.length} playbooks; \`exceptd watch\` lists skills.`;
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
    return `Run \`exceptd brief --all\` to list the ${ids.length} playbooks.`;
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
  // return whether a verb-specific help block was
  // found so the `exceptd help <verb>` caller can decide whether to fall
  // through to the top-level help (verb unknown) or stop here (verb known).
  if (cmds[verb]) {
    process.stdout.write(cmds[verb] + "\n");
    return true;
  }
  process.stdout.write(`${verb} — no per-verb help available; see \`exceptd help\` for the full list.\n`);
  return false;
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

  // Resolve the collector module under lib/collectors/<id>.js.
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

  // --cwd <path> overrides process.cwd(). Validated as an existing
  // directory; non-existent / non-directory cwd is operator error.
  let cwd = process.cwd();
  // An explicit empty value (`--cwd ""`) would otherwise be falsy and silently
  // scan process.cwd() — the wrong directory — reported as a successful run.
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

  // Skip-disclosure on stderr when a precondition gate returned
  // false (typically a platform gate — `linux-platform: false` on
  // win32 / macOS). Without this, the empty signal_overrides on a
  // gated collector looks indistinguishable from "the collector
  // ran but found nothing". Operators get one stderr line per
  // platform-skipped run.
  const failedPre = Object.entries(submission.precondition_checks || {})
    .filter(([, v]) => v === false)
    .map(([k]) => k);
  if (failedPre.length > 0) {
    // Warn on ANY failed precondition, not only when signal_overrides is empty.
    // A collector that gathers artifacts but fails a consent/ownership gate
    // (e.g. cicd-pipeline-compromise's operator-owns-ci-fleet) emits a populated
    // submission yet `run` will block at preflight — surface that up front so
    // the operator isn't surprised by the downstream "verdict: blocked".
    const emptySignals = !submission.signal_overrides || Object.keys(submission.signal_overrides).length === 0;
    const tail = emptySignals
      ? "empty submission emitted (collector skipped on this host)"
      : "submission emitted, but `run` will block at preflight until this precondition is satisfied";
    process.stderr.write(`[collect ${playbookId}] precondition not satisfied: ${failedPre.join(", ")} — ${tail}\n`);
  }

  // Emit the submission JSON to stdout. The operator pipes this into
  // `exceptd run <playbook> --evidence -` to drive a real verdict.
  // Human-rendered version is concise so an interactive operator can
  // see what the collector found without parsing the JSON.
  // Audit 3 A.4: surface air_gap_mode on the collect envelope so the
  // downstream `run --evidence -` sees the mode propagating from the
  // collection step. Collectors themselves currently make no network
  // calls — but the flag's intent is to flag the collection context for
  // any future collector that might.
  // Also honor _meta.air_gap_mode on the playbook itself — playbooks
  // like secrets / cred-stores / containers declare air-gap intrinsically
  // and `run` honors that even without --air-gap. Collect must mirror so
  // automation downstream sees the same intrinsic mode.
  let pbMetaAirGap = false;
  try { pbMetaAirGap = !!(runner.loadPlaybook(playbookId)?._meta?.air_gap_mode); }
  catch { /* playbook load shouldn't fail here — collector exists — but be defensive */ }
  const collectAirGap = !!(runOpts.airGap || process.env.EXCEPTD_AIR_GAP === "1" || pbMetaAirGap);

  // --resolve: resolve the citations the offline catalog couldn't confirm,
  // flipping their parked signals instead of leaving them inconclusive for the
  // operator to research. Opt-in, collector-specific (only citation-hygiene
  // exposes applyResolution). Honors the collect air-gap disposition.
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

  // Spread `submission` first, then explicit fields, so a submission key
  // named `air_gap_mode` (currently always undefined but defensive against
  // future collector contracts) can't clobber the envelope marker.
  const collectBody = { verb: "collect", playbook_id: playbookId, ...submission, air_gap_mode: collectAirGap };
  // collect's primary purpose is the pipe `exceptd collect <pb> | exceptd run
  // <pb> --evidence -`. When stdout is NOT a TTY (a pipe / redirect), emit JSON
  // so that one-liner just works; the human summary is only for an interactive
  // operator at a terminal. Explicit --json / --pretty force JSON regardless.
  // Without this gate, emit()'s default-human behavior printed a prose summary
  // into the pipe and the downstream `run --evidence -` failed to parse it.
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

  // After normalize, validation walks the canonical nested shape. Distinguish
  // a truly-absent required artifact (no entry — operator should add it) from
  // one that is PRESENT but uncaptured (entry with captured:false + a reason,
  // e.g. a collector's "skipped on win32 — POSIX mode bits not meaningful").
  // Conflating them told the operator to "add" an artifact that is already
  // there.
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

  // Symmetric to unknownArtifactKeys/unknownSignalKeys: flag precondition_checks
  // keys the playbook does not declare. Pre-fix, the flat `observations` shape
  // surfaced a foreign precondition id (e.g. crypto collector attesting
  // `linux-platform`, which belongs to kernel/runtime/hardening) as an
  // unknown_observation_key, but the nested `precondition_checks` shape every
  // collector actually emits was never checked — so collector↔playbook
  // precondition-id drift was silent on the canonical collect→lint path.
  const unknownPreconditionKeys = [...new Set([
    ...Object.keys(submission.precondition_checks || {}),
    ...Object.keys(normalized.precondition_checks || {}),
  ])].filter(k => !knownPreconditions.has(k));

  const issues = [];
  // v0.11.6 (#94): missing_required_artifact downgraded from error to warn.
  // The runner doesn't refuse a submission missing required artifacts — it
  // runs with the indicators that have data and marks the rest inconclusive.
  // Lint was stricter than runner; users got errors on submissions the runner
  // accepted. Now: lint warns about missing artifacts but doesn't fail.
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
  } else {
    // Nested submission with artifacts but no signal_overrides lands
    // every indicator on inconclusive — same trapdoor the flat-shape
    // branch above surfaces. Detect() needs signal_overrides (or a
    // verdict override) to drive an indicator hit/miss; artifact
    // presence alone is not enough. Surface the JSON shape explicitly
    // so the operator/AI knows what to populate.
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
  if (!ok) process.exitCode = EXIT_CODES.GENERIC_FAILURE;
}

function cmdBrief(runner, args, runOpts, pretty) {
  const playbookId = args._[0];
  // Preserve an explicit empty string (don't coerce "" -> null) so the
  // accepted-set check below rejects `--phase ""` instead of silently treating
  // it as "no filter" and emitting the full brief. Only an OMITTED flag is null.
  const onlyPhase = args.phase === undefined ? null : args.phase;

  // v0.12.9 (P2 #7 from production smoke): refuse garbage values to --phase.
  // Pre-v0.12.9 `brief secrets --phase foo` silently accepted any string and
  // emitted the full brief — operators got no signal the flag was misused.
  // The legacy-compat surface is exactly the three v0.10.x verb names
  // (govern | direct | look); anything else is a typo or a misunderstanding.
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
  // Reject an empty --playbook value rather than letting the truthy gate below
  // coerce it to null and silently plan across ALL playbooks (wrong scope).
  if (args.playbook === "" || (Array.isArray(args.playbook) && args.playbook.some(p => p === ""))) {
    return emitError("plan: --playbook was given an empty value; pass a playbook id, or omit --playbook to plan across all.", { verb: "plan", flag: "playbook" }, pretty);
  }
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
  emit(plan, pretty, (obj) => {
    // Human renderer for `brief` / `brief --all`. Pre-fix this
    // verb dumped 36+ KB of JSON to the terminal — operators running
    // `exceptd brief` to explore had no scannable view.
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

    // Group by scope when grouped output is available; else flat list.
    // grouped_by_scope is `{ scope: [<playbook-id>, ...] }` — look up
    // domain.name + threat_currency_score from the flat playbooks list.
    const byId = {};
    for (const pb of obj.playbooks || []) {
      if (pb && pb.id) byId[pb.id] = pb;
    }
    // Render directive sub-bullets when each playbook entry carries a
    // directives[] array (set by cmdPlan when --directives is on).
    // Without this, the documented contract of --directives — expand
    // directive metadata — is silently dropped in default human mode.
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
      // Flat list (filtered or --flat). No scope buckets.
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

// v0.12.15: --scope must validate against the accepted
// set. The prior shape silently returned [] for any unknown scope, which
// in `run --scope nonsense` produced `count: 0` + exit 0 (cmd reports
// "ran 0 playbooks") and in `ci --scope nonsense` silently ran only the
// cross-cutting set (the union with `framework` produced a false-positive
// PASS). Both are operator-intent loss patterns of the
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
    // A case-only typo (`run SECRETS`) fails the lowercase-only id regex
    // before the fuzzy "did you mean" path ever runs. If lowercasing yields a
    // real playbook, suggest it — the most common id typo shouldn't get the
    // least helpful error.
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

// Playbooks whose halt-preconditions require operator-attested
// evidence the runner cannot derive in a CI gate (incident /
// governance / migration playbooks). These DECLARE a scope but
// their preconditions are gated on operator-attested booleans
// like `incident_confirmed == true`, `tenant_ownership_attested
// == true`, `operator_owns_migration_programme == true` — values
// no CI gate can infer. Without excluding them, `ci --scope code`
// / `ci --all` halt at preflight on at least one playbook.
//
// `framework` is intentionally NOT in this list — it's analyze-only
// (its single precondition is `on_fail: warn`) and SHOULD run in
// every CI invocation to correlate framework findings.
// `cicd-pipeline-compromise` is NOT in this list — its operator-
// owns-ci-fleet halt is opt-in via the collector's --attest-
// ownership flag, and ci consumers who run with evidence-dir
// supply the precondition themselves.
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
      // Default-exclude judgement-shaped playbooks from scope filters.
      // Operator can opt in via --include-judgement-shaped when they
      // genuinely want to run the AI-attestation-required set.
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
  // --evidence-dir is a contract input: cmdRunMulti reads one
  // <playbook-id>.json per playbook in an --all / --scope run. With a single
  // named playbook it was silently ignored, so `run secrets --evidence-dir ./ev`
  // ran against EMPTY evidence and reported a clean "not_detected" verdict — a
  // falsely-reassuring result from a security tool. Refuse loudly and point the
  // operator at the flag that actually loads evidence for one playbook.
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
  // An explicit empty value (`--evidence ""`) is operator error: it would
  // otherwise be falsy and silently produce a no-evidence "not_detected" run at
  // exit 0, masking the fact that the intended evidence never loaded.
  if (args.evidence === "") {
    return emitError("run: --evidence was given an empty value; pass a file path, '-' for stdin, or omit --evidence for a no-evidence run", { verb: "run" }, pretty);
  }
  const autoStdin = !args.evidence && hasReadableStdin();
  if (autoStdin) {
    args.evidence = "-";
  }
  if (args.evidence) {
    try {
      // explicit:false on the auto-promotion path suppresses the empty-stdin
      // nudge (which otherwise writes to stderr and breaks `run ... 2>&1 | jq`
      // on every no-evidence CI run); an explicit `--evidence -` still nudges.
      submission = readEvidence(args.evidence, { explicit: !autoStdin });
    } catch (e) {
      return emitError(`run: failed to read evidence: ${e.message}`, { evidence: args.evidence }, pretty);
    }
  }

  // Note: precondition_checks are NOT lifted into runOpts. run() derives the
  // effective precondition set from the submission itself (its mergedPCs feeds
  // preflight), so copying them into runOpts is redundant — and it made every
  // submission-supplied precondition report provenance "merged" (present in
  // both the submission and runOpts) instead of "submission". The submission
  // carries them to run() directly.

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
    // Audit 3 A.6: --air-gap must refuse the registry probe. The
    // upstream-check helper has no air-gap awareness of its own; the
    // central refusal lives here so any future caller of --upstream-check
    // inherits it. Mirror the line-3444 hoist: an intrinsically air-gapped
    // playbook (_meta.air_gap_mode — secrets / cred-stores / containers) must
    // refuse the egress too, even without the explicit --air-gap flag.
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

  // Audit 3 A.2: surface air_gap_mode at the top of the envelope so
  // stdout-parsing consumers can detect that the run honored --air-gap
  // (or the playbook's _meta.air_gap_mode flag) without descending into
  // phases.govern. Mirrors the run-result hoist pattern (verdict,
  // rwep_score, evidence_completeness, attestation_path).
  if (result) {
    result.air_gap_mode = !!(pb._meta?.air_gap_mode || runOpts.airGap);
  }

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
    // Surface the persisted file path on the result so the human
    // renderer can echo it and the attest verify / attest diff hint
    // lands on an artifact the operator can actually find.
    if (persistResult.attestation_path) {
      result.attestation_path = persistResult.attestation_path;
    }
  }

  if (result && result.ok === false) {
    // Align preflight-halt exit code between `run --ci` and `ci`: both use
    // 4 (BLOCKED) when --ci is in effect so operators can wire one set of
    // exit-code expectations regardless of which verb they call. Without
    // --ci the legacy exit 1 is preserved (ok:false bodies are framework
    // signals when no CI gating is requested).
    // Set exitCode BEFORE emit(): emit's ok:false fallback only fires when
    // exitCode is not already set, so the BLOCKED override survives.
    process.exitCode = args.ci ? EXIT_CODES.BLOCKED : EXIT_CODES.GENERIC_FAILURE;
    emit(result, pretty, (obj) => {
      // Human renderer for a halted run. Without this, a blocked verdict
      // (preflight precondition unmet, mutex conflict, stale currency,
      // corrupt catalog) dumped the raw ok:false JSON envelope even in human
      // mode — so a non-Linux operator's first `run` against any Linux-gated
      // playbook was a wall of JSON instead of one line saying why it stopped
      // and what to do. --json / --pretty still return the full envelope.
      const v = obj.verdict || "error";
      const tag = v === "blocked" ? "[blocked]" : "[error]";
      const lines = [`${tag}  ${obj.playbook_id || "run"}${obj.directive_id ? ` (${obj.directive_id})` : ""}`];
      // summary_line is already a complete sentence ("<pb>: blocked at
      // preflight (<cause>) — <reason>"); prefer it, else fall back to reason.
      const detail = obj.summary_line || obj.reason;
      if (detail) lines.push(`  ${detail}`);
      // remediation is the engine's own actionable next step when it has one;
      // otherwise synthesize a hint from blocked_by so the operator never hits
      // a dead end. Hints reference only current verbs (plan/direct were
      // removed in v0.13.0; brief --all is the replacement listing verb).
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

  // v0.11.6 (#96): --strict-preconditions escalates warn-level preflight
  // issues to exit 1. Default (without the flag) preserves the existing
  // behavior where warn-level issues stay informational. CI gates wanting
  // "fail on any unverified precondition" pass this flag.
  if (args["strict-preconditions"] && result && Array.isArray(result.preflight_issues)) {
    // precondition_skip MUST be included: a false skip_phase precondition
    // means detect never ran, so a CI gate relying on --strict-preconditions
    // ("any precondition_check returning false fails the run", per --help) would
    // otherwise silently pass (verdict:skipped, exit 0) — the exact gap the
    // flag exists to close.
    const warnIssues = result.preflight_issues.filter(i =>
      i.kind === "precondition_unverified" || i.kind === "precondition_warn" || i.kind === "precondition_skip"
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
    // --format wins over --json (one stdout document). Note it rather than
    // silently discarding --json — a script that pipes for JSON and later adds
    // --format markdown for a human would otherwise get non-JSON with no signal.
    if ((args.json || global.__exceptdWantJson) && requested !== "json") {
      process.stderr.write(
        `[exceptd] note: --format "${requested}" overrides --json; stdout is the ${requested} document, not the JSON envelope.\n`
      );
    }
    // Only one document can be written to stdout. When several --format values
    // are given, emit the first and tell the operator where the rest live so
    // the extras aren't silently dropped.
    if (requestedAll.length > 1) {
      process.stderr.write(
        `[exceptd] note: ${requestedAll.length} --format values given; emitting "${requested}" to stdout. ` +
        `All requested bundles are embedded under phases.close.evidence_package.bundles_by_format — ` +
        `re-run with --json to see them.\n`
      );
    }
    // `json` means "the full run result as JSON" — the same body the default
    // (no --format) path emits. Without this it fell through to the bundle
    // lookup, found the runner's "unknown format" stub under
    // bundles_by_format.json, and emitted that 150-byte stub instead of the
    // scan — silently discarding the result with a success exit code.
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
    // CSAF/SARIF/OpenVEX bundles live under close.evidence_package — the
    // runner writes them under canonical keys ("csaf-2.0", "sarif",
    // "openvex"). Normalize the user-supplied shortcuts.
    const formatNorm = requested === "csaf" ? "csaf-2.0" : requested;
    const bbf = result.phases?.close?.evidence_package?.bundles_by_format || {};
    const body = bbf[formatNorm] || result.phases?.close?.evidence_package?.bundle_body;
    if (body) {
      // SARIF / CSAF / OpenVEX are self-describing standard documents. Write
      // them verbatim rather than through emit(), which prepends the tool's
      // own `ok` envelope key — `ok` is not a permitted top-level property in
      // any of these schemas and makes strict validators (GitHub code-scanning
      // SARIF upload, a CSAF trusted-provider check) reject the output. The
      // namespaced `exceptd_extension` block (CSAF vendor extension carrying
      // publisher-namespace provenance) is preserved intentionally.
      const { ok: _ok, ...spec } = body;
      process.stdout.write(JSON.stringify(spec, null, pretty ? 2 : 0) + "\n");
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
    // Surface evidence_completeness on the verdict line so operators
    // distinguish "ran every indicator and found nothing" from
    // "couldn't evaluate, no evidence supplied" — without this they
    // look identical at the terminal. Also break out decisive vs.
    // inconclusive indicator counts: a run where every indicator
    // landed inconclusive is mathematically "complete" (engine ran
    // them all) but operationally "no decision was made" — the prose
    // must distinguish those, otherwise an inconclusive verdict with
    // sparse signal_overrides reads as "complete coverage, no hits".
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
    // F11: surface --diff-from-latest verdict in the human renderer so
    // operators see whether the run drifted from the previous attestation
    // without adding --json. One summary line follows the classification.
    // Marker text is grep-matched by tests/audit-i-l-m-fixes.test.js F11.
    // - unchanged: same evidence_hash as prior → reassuring single line.
    // - drifted: evidence differs → loud DRIFTED marker.
    // - no_prior_attestation_for_playbook: explicit "no prior" line so
    //   an operator who passed --diff-from-latest doesn't wonder
    //   whether the flag took effect. Without this, a fresh attestation
    //   directory produced no diff output — the flag looked broken.
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
    // --upstream-check fired a network call; surface the result so the
    // operator who asked "am I current?" gets a one-line answer at the
    // terminal without grepping the JSON envelope.
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
      // No evidence correlated to any CVE — clarify rather than implying the
      // operator is affected by the catalog enumeration. Pre-fix output read
      // like a hit list; explicit zero + scan-coverage callout fixes that.
      lines.push(`\nNo CVEs correlated to your evidence. Playbook catalog (informational): ${baseline.length} CVE(s) this playbook scans for.`);
    }
    const indicators = obj.phases?.detect?.indicators || [];
    const hits = indicators.filter(i => i.verdict === "hit");
    if (hits.length) {
      lines.push(`\nIndicators that fired (${hits.length}):`);
      for (const i of hits.slice(0, 8)) {
        // Don't double-print "deterministic/deterministic" when confidence is
        // already the literal "deterministic".
        const detSuffix = (i.deterministic && i.confidence !== "deterministic") ? "/deterministic" : "";
        lines.push(`  ${i.id}  (${i.confidence}${detSuffix})`);
      }
      if (hits.length > 8) lines.push(`  … ${hits.length - 8} more`);
    }
    // selected_remediation is informational on non-detect runs:
    // validate() always picks the highest-priority remediation path
    // as a "what you'd do IF you found something" anchor, even when
    // classification is not_detected / inconclusive. Tag the prose
    // conditionally so the label matches the verdict — labeling it
    // "Recommended remediation:" on a not_detected run misleads
    // operators into thinking action is required.
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
    // Surface BOTH started and pending notification clocks on detected
    // runs. The detection IS the regulatory event for the obligations
    // exceptd tracks — pending obligations waiting on detect_confirmed
    // / analyze_complete are exactly what the operator needs to see
    // before taking the action that starts the clock.
    const allNotif = obj.phases?.close?.notification_actions || [];
    const startedNotif = allNotif.filter(n => n.clock_started_at);
    const pendingNotif = allNotif.filter(n => !n.clock_started_at);
    if (startedNotif.length) {
      lines.push(`\nNotification clocks started (${startedNotif.length}):`);
      for (const n of startedNotif) lines.push(`  ${n.obligation_ref} → deadline ${n.deadline}`);
    }
    if (pendingNotif.length && cls === "detected") {
      lines.push(`\nPending jurisdiction obligations (${pendingNotif.length}) — clock starts on operator action:`);
      // Group by clock_start_event so the operator sees what to do
      // ONCE per event class, not once per regulation.
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

    // Tell the operator WHERE the attestation went and HOW to verify
    // / diff it. Without this, the attestation goes to
    // ~/.exceptd/attestations/<repo>@<branch>/<sid>/attestation.json
    // and a follow-up `attest verify <sid>` from a different cwd
    // fails with "no session dir" because the lookup is cwd-tagged.
    if (obj.attestation_path) {
      lines.push(`\nAttestation written: ${obj.attestation_path}`);
      lines.push(`  exceptd attest verify ${obj.session_id}     # tamper check`);
      lines.push(`  exceptd attest diff ${obj.session_id}       # vs. most-recent prior for this playbook`);
    }
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
        // precondition_warn issues carry their text in `message`; without it in
        // the fallback chain they rendered "(no detail)".
        const detail = i.check || i.description || i.reason || i.message || "(no detail)";
        lines.push(`  ${tag}${i.id}: ${detail}`);
      }
    }
    // Surface runtime_errors at the operator level so a malformed
    // submission (e.g. `signal_overrides: "not-an-object"`) doesn't
    // silently complete with a misleading [ok] verdict. Pre-fix, these
    // entries lived only in phases.analyze.runtime_errors and were
    // invisible at the terminal.
    const runtimeErrors = obj.phases?.analyze?.runtime_errors || [];
    if (runtimeErrors.length) {
      lines.push(`\nRuntime warnings (${runtimeErrors.length}):`);
      for (const e of runtimeErrors) {
        // Some runtime-warning kinds (e.g. csaf_branch_unparseable) carry no
        // `reason` but do carry context fields (component / cve_id); compose
        // from those rather than rendering a blank line.
        const rawReason = e.reason || [e.component, e.cve_id].filter(Boolean).join(" / ") || "(no detail)";
        const reason = rawReason.length > 180 ? rawReason.slice(0, 177) + "..." : rawReason;
        lines.push(`  [${e.kind || "warning"}] ${reason}`);
        if (e.remediation) lines.push(`    → ${e.remediation}`);
      }
    }
    // Surface collector_warnings (e.g. a file skipped for exceeding the
    // scan-size limit) on the default human surface too. Without this an
    // operator reading the render sees "evidence: complete" with no hint that
    // the collector could not scan part of the tree — the skip lives only in
    // --json's collector_warnings, invisible to the human reader.
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

// Shared, hardened reader for `--evidence-dir <dir>`. Both `run` (cmdRunMulti)
// and `ci` (cmdCi) accept --evidence-dir; the symlink / junction / O_NOFOLLOW /
// realpath-containment / playbook-id defenses must apply identically to both.
// Previously cmdCi read entries with a bare fs.readFileSync, so a `<pb>.json`
// symlink/junction inside the dir bypassed every containment check that `run`
// applies. Factor the read into one helper so the class is fixed once and a
// future third caller can't regress.
//
// Returns { ok: true, bundle } on success, or
// { ok: false, error: <msg>, extra: <obj|null> } on the first refusal — the
// caller routes the error through its own emitError() so the verb-prefixed
// message ("run: ..." vs "ci: ...") is preserved. The directory's existence /
// type and the empty-string guard are the caller's responsibility (the two
// verbs surface those with verb-specific wording).
function readEvidenceDir(dir, verb) {
  const bundle = {};
  const resolvedDir = path.resolve(dir);
  // Resolve the directory's realpath ONCE so the per-entry containment gate
  // below compares like-for-like. On macOS the tmpdir — and many operator
  // directories anywhere — live under a symlinked ancestor (e.g. /var ->
  // /private/var, or a symlinked mount/home). Without resolving the base, a
  // legitimate <pb-id>.json whose realpath is /private/var/.../f fails a
  // `startsWith(resolvedDir)` test against /var/.../ and every evidence file is
  // wrongly refused. Resolving the base keeps the junction/symlink-escape
  // defense (an entry whose target leaves the resolved dir still fails) while
  // accepting files that merely sit under a symlinked parent.
  let realResolvedDir;
  try { realResolvedDir = fs.realpathSync(resolvedDir); }
  catch { realResolvedDir = resolvedDir; }
  // Only `<playbook-id>.json` entries are honored. Reject anything where the
  // filename strip leaves traversal segments — npm refuses to write such
  // filenames so the realistic risk is an operator symlink/junction inside the
  // dir, but the filter is cheap.
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
    const pbId = f.replace(/\.json$/, "");
    // Reuse the shared playbook-id validator so the --evidence-dir entry
    // filter agrees with the runtime playbook-id allowlist. Rejects
    // dots / underscores / uppercase that no real playbook id uses, which would
    // otherwise silently absorb a typo'd filename as a "valid" entry that
    // loadPlaybook then refused mid-loop.
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
    // The path.resolve check above only catches `..` traversal in the joined
    // path; reading the path would still follow symlinks, so a
    // `<pb-id>.json -> /etc/shadow` symlink inside the dir would slurp the
    // target. Rather than lstat/realpath the PATH and then re-open it (a
    // check-then-use TOCTOU window), open a single O_NOFOLLOW descriptor FIRST
    // and make every subsequent decision about that exact descriptor.
    // O_NOFOLLOW refuses a symlinked leaf at open (ELOOP) on POSIX; on Windows
    // it is a no-op, so the fstat type check + lstat + realpath gate below carry
    // the junction/symlink defense. Opening before any path stat means the bytes
    // read come from the inode we validated, not a path that could be re-pointed
    // between check and read.
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
      // Hardlink defense in depth: no clean cross-platform refusal exists —
      // hardlinks are indistinguishable from regular files at the inode level.
      // Surface a stderr warning when nlink > 1 so the operator is aware a
      // second name may point at the same file. Not a refusal — legitimate use
      // cases (atomic rename, package-manager dedup) produce nlink > 1 without
      // malicious intent.
      if (st.nlink > 1) {
        process.stderr.write(`[exceptd ${verb} --evidence-dir] WARNING: ${f} has nlink=${st.nlink}; a hardlink to this file exists elsewhere on the filesystem. Hardlinks cannot be refused cross-platform — confirm the file content is what you expect.\n`);
      }
      // Read the bytes from `efd` FIRST — the descriptor was opened O_NOFOLLOW
      // and fstat-confirmed a regular file, so this reads the exact inode we
      // validated. Reading before the realpath gate (rather than checking the
      // path then reading) means there is no check-then-use window at all; the
      // containment gate below decides whether to USE the bytes, and discards
      // them otherwise.
      const raw = fs.readFileSync(efd, "utf8");
      // Symlink refusal. O_NOFOLLOW already rejects a symlinked leaf at open on
      // POSIX (ELOOP), but it is a no-op on Windows, where the open follows the
      // link. Detect and refuse a symlink explicitly via lstat — regardless of
      // where it points — so a symlinked entry is never accepted. This runs
      // AFTER the descriptor read (the bytes are dropped on refusal), so there
      // is no path-check-before-read TOCTOU window.
      let lst;
      try { lst = fs.lstatSync(entryPath); }
      catch (e) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f}: lstat failed: ${e.message}`, extra: null };
      }
      if (lst.isSymbolicLink()) {
        return { ok: false, error: `${verb}: --evidence-dir entry ${f} is a symbolic link; refusing (symlinks bypass the directory-confinement check).`, extra: { entry: f } };
      }
      // Windows directory junctions are reparse-point dirs that
      // lstat().isSymbolicLink() returns FALSE for, and O_NOFOLLOW is a no-op
      // there; realpath resolves the entry and confirms it still lives under the
      // resolved evidence-dir. A target that escapes the dir is refused and the
      // already-read bytes are dropped unused.
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
      bundle[pbId] = JSON.parse(raw);
    } catch (e) {
      // A refusal object thrown by JSON.parse / readFileSync lands here; surface
      // it with the entry name. (The explicit refusals above return directly and
      // never reach this catch.)
      return { ok: false, error: `${verb}: failed to read --evidence-dir entry ${f}: ${e.message}`, extra: null };
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
  // An explicit empty value (--evidence "" / --evidence= / an unset shell
  // variable) is falsy, so the truthiness-gated reads below would skip
  // entirely, the bundle would stay {}, every playbook would run with no
  // evidence, and the contract would report a clean not_detected at exit 0 —
  // a false-clean that hides the fact the operator's intended evidence never
  // loaded. Mirror the single-playbook run / ci empty-value guards: refuse
  // the empty value loudly rather than running a vacuous contract. Presence,
  // not truthiness, is the test.
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
  // --evidence-dir <dir>: each <playbook-id>.json under the directory is read
  // as that playbook's submission. Lets operators wire up one cron job that
  // collects per-playbook evidence into a directory, then runs the whole
  // contract in one pass. The empty-string form is already refused above; the
  // truthy gate here only ever sees a non-empty directory path.
  if (args["evidence-dir"]) {
    const dir = args["evidence-dir"];
    if (typeof dir !== "string") {
      return emitError("run: --evidence-dir must be a string.", null, pretty);
    }
    if (!fs.existsSync(dir)) {
      return emitError(`run: --evidence-dir ${dir} does not exist.`, null, pretty);
    }
    // Hardened read (symlink / junction / O_NOFOLLOW / realpath-containment /
    // playbook-id gate) lives in the shared readEvidenceDir() helper so `run`
    // and `ci` apply identical defenses.
    const er = readEvidenceDir(dir, "run");
    if (!er.ok) return emitError(er.error, er.extra, pretty);
    Object.assign(bundle, er.bundle);
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
  }, pretty, (obj) => {
    // Per-playbook summary table. Without this renderer a multi-run dumped its
    // entire (often hundreds-of-KB) JSON even in default human mode.
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
  // v0.11.9 (#100): cmdRunMulti exits non-zero when any individual run
  // returned ok:false. Pre-0.11.9 the aggregate result had {ok:false} in
  // the body but exit code stayed 0 — CI gates couldn't distinguish "ran
  // clean" from "blocked." v0.12.8: use exitCode (not process.exit()) so
  // the aggregate JSON emitted above is allowed to fully drain.
  //
  // Aggregate exit-code precedence: LOCK_CONTENTION > STORAGE_EXHAUSTED >
  // SESSION_ID_COLLISION > GENERIC_FAILURE. Lock contention is transient
  // (retry-from-outside fixes it); storage exhaustion is an infra event
  // requiring operator action; a session-id collision mirrors the single-run
  // code; any remaining ok:false per-playbook result yields GENERIC_FAILURE
  // (exit 1) — distinct from the single-run BLOCKED (4) path. Surfacing the
  // most-specific code first means a CI gate can branch on the right
  // remediation without parsing the body.
  const anyLockBusy = results.some(r => r.attestation_persist && r.attestation_persist.lock_contention === true);
  const anyStorageExhausted = results.some(r => r.attestation_persist && r.attestation_persist.storage_exhausted === true);
  // A persist failure that is neither lock-contention nor storage-exhaustion is
  // a session-id collision (the single-run path exits 7 for the same
  // condition). Pre-fix a batch where every attestation refused to overwrite
  // exited 0, so a re-run with a reused --session-id silently persisted nothing
  // while reporting success. Surface it with the same code as the single-run
  // path so a CI gate sees it.
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
      error: `Refusing to persist attestation with unsafe filename: ${String(JSON.stringify(filename)).slice(0, 80)}.`,
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
      // Atomic write: the body and its .sig are written to fsync'd tmp files,
      // then placed with linkSync (create) / rename (force-overwrite) so a
      // crash mid-write can never leave a TRUNCATED attestation.json, and the
      // body never appears partially written. linkSync preserves the O_EXCL
      // collision guarantee the old "wx" flag gave: it throws EEXIST when the
      // slot is taken (one winner + one EEXIST loser on concurrent same-
      // session-id runs), and the placed file has the full content instantly.
      //
      // v0.12.38: mode 0o600 + Windows ACL hardening — attestations carry the
      // operator's evidence, jurisdiction obligations, and consent records and
      // must not be world-readable on multi-tenant hosts.
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
      // Sidecar is computed over the SAME normalized bytes that will land, so
      // the sig always matches the placed body.
      const sidecarBytes = computeSidecarBytes(normalizeAttestationBytes(jsonStr));
      writeFsync(jsonTmp, jsonStr);
      writeFsync(sigTmp, sidecarBytes);
      try {
        if (flag === "wx") {
          // Atomic create + collision detection.
          try {
            fs.linkSync(jsonTmp, filePath);
          } catch (linkErr) {
            if (linkErr.code === "EEXIST") throw linkErr; // collision — outer handler decides
            // Filesystems without hard-link support (EPERM/EXDEV/ENOSYS): fall
            // back to an existsSync collision check + atomic rename. Narrow
            // TOCTOU window, only on such filesystems.
            if (fs.existsSync(filePath)) { const e = new Error("EEXIST"); e.code = "EEXIST"; throw e; }
            fs.renameSync(jsonTmp, filePath);
          }
          // Slot won — place the sidecar (sigPath is fresh on a create).
          try {
            fs.renameSync(sigTmp, sigPath);
          } catch (sigErr) {
            // The body landed but its sidecar did not. Left in place, the
            // orphaned unsigned body would hold the slot forever: every
            // retry collides with EEXIST and verification reports the
            // attestation unsigned. Release the slot before rethrowing so
            // the create can be retried cleanly.
            try { fs.unlinkSync(filePath); } catch { /* best-effort slot release */ }
            throw sigErr;
          }
          try { fs.unlinkSync(jsonTmp); } catch { /* hard-link path leaves a second name */ }
        } else {
          // Force-overwrite, under the persist lock: atomic replace of both.
          // Both tmps are fully written + fsync'd, so the new body and its
          // matching new sidecar are placed back-to-back.
          fs.renameSync(jsonTmp, filePath);
          fs.renameSync(sigTmp, sigPath);
        }
      } catch (placeErr) {
        // Clean up tmps on any placement failure (incl. EEXIST collision) so
        // a failed/refused write never leaves orphan tmp files at the slot.
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
      // Return the absolute path so the caller can echo it in the
      // human renderer — operators need to know where the file went
      // for follow-up `attest verify` / `attest diff` calls.
      return { ok: true, prior_session_id: null, overwrote_at: null, attestation_path: filePath };
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
          attestation_path: filePath,
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

// Compute the `.sig` sidecar bytes for an attestation's (already-normalized)
// content. Pure — does NOT write any file; the persist path writes the
// returned string to a tmp and atomically renames it into place alongside the
// attestation body, so the body never lands without its sidecar bytes ready.
// Emits the one-time-per-process unsigned warning.
function computeSidecarBytes(contentNormalized) {
  const crypto = require("crypto");
  // v0.12.9: keep the sign key aligned with the VERIFY key. `attest verify`
  // checks signatures against PKG_ROOT/keys/public.pem; signing with a
  // cwd-local key would verify INVALID. PKG_ROOT-only resolution is correct.
  const privKeyPath = path.join(PKG_ROOT, ".keys", "private.pem");
  // One-time-per-process unsigned warning so cron jobs don't spam stderr.
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
      // The Ed25519 signature covers ONLY the attestation file bytes; no
      // replay-rewritable metadata travels in the sidecar.
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
    // Signing failure must not block the run — fall back to an unsigned marker
    // so the sidecar always exists alongside the body.
    return JSON.stringify({
      algorithm: "unsigned",
      signed: false,
      note: "Signing failed at write time; attestation is hash-stable but unsigned.",
    }, null, 2);
  }
}

// Sign an already-written file in place by computing + writing its `.sig`
// sidecar. The main attestation-persist path writes the sidecar atomically
// alongside the body (via computeSidecarBytes); this helper serves the
// replay-record path, which writes a uniquely-named file and so needs no
// atomic-collision handling. Best-effort: a sign-time failure leaves the
// record unsigned (still a valid audit entry) rather than aborting.
function maybeSignAttestation(filePath) {
  const content = normalizeAttestationBytes(fs.readFileSync(filePath, "utf8"));
  const sidecar = computeSidecarBytes(content);
  fs.writeFileSync(filePath + ".sig", sidecar, { mode: 0o600 });
  try { require(path.join(PKG_ROOT, "lib", "sign.js")).restrictWindowsAcl(filePath + ".sig"); } catch { /* best-effort */ }
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
        // Filter on an explicitly-supplied playbook id. `!= null` (not a
        // truthiness check) so a future caller that threads an empty-string
        // id can't silently disable the filter and widen the match to every
        // playbook; the only legitimate "no filter" is `null`/`undefined`.
        if (opts.playbookId != null && j.playbook_id !== opts.playbookId) continue;
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
      // A pin mismatch means the host's public key is NOT the published
      // one — verification against it would prove nothing. Carry a tamper
      // class so consumers (reattest's refusal predicate, the sidecar
      // classifier) treat this as tamper evidence, not a benign
      // unsigned-attestation config state.
      return { file: attFile, signed: false, verified: false, tamper_class: "fingerprint-mismatch", reason: pinError };
    }
  }
  if (!fs.existsSync(sigPath)) {
    // A missing sidecar is benign ONLY when none was ever expected (the
    // attestation was written on a keyless host and no peer in the same
    // session is signed). When a sig SHOULD exist — a signing key is present,
    // or a signed peer attestation sits beside this one — an absent sidecar is
    // a deletion-to-evade-tamper signal. Carry the tamper_class so `attest
    // diff` and `reattest` refuse a forged attestation whose .sig was stripped,
    // matching `attest verify`. The keyless case stays benign so keyless CI is
    // unaffected.
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

/**
 * Resolve the A-side ("self") attestation for `attest diff` to its actual
 * on-disk file, NOT a hardcoded attestation.json.
 *
 * The two diff branches (`--against` and the auto-prior default) both need
 * the A-side's real signed file to route its sidecar through the tamper
 * refusal. A single-`run` / `reattest` session writes attestation.json; a
 * multi-playbook (run-all) session writes per-playbook `<id>.json` +
 * `<id>.json.sig` with no attestation.json. Selection mirrors the B-side
 * resolution: prefer attestation.json when present, else the newest by
 * captured_at. Returns { parsed, file } or null when no attestation exists.
 *
 * `attestations[i]` is paired with `files[i]` (the partition loop pushes
 * them in lockstep), so this never has to re-read the directory.
 */
function resolveSelfAttestation(dir, attestations, files) {
  if (!Array.isArray(attestations) || attestations.length === 0) return null;
  const canonicalPath = path.join(dir, "attestation.json");
  const canonicalIdx = files.indexOf(canonicalPath);
  if (canonicalIdx !== -1) {
    return { parsed: attestations[canonicalIdx], file: files[canonicalIdx] };
  }
  // No canonical attestation.json (run-all session) — pick the newest entry
  // by captured_at, keeping its paired path so the sidecar verify is exact.
  let best = { parsed: attestations[0], file: files[0] };
  for (let i = 1; i < attestations.length; i++) {
    const cur = attestations[i].captured_at || "";
    const bestCap = best.parsed.captured_at || "";
    if (cur.localeCompare(bestCap) > 0) best = { parsed: attestations[i], file: files[i] };
  }
  return best;
}

/**
 * `attest prune --all-older-than <ISO>` — GC for attestation growth.
 *
 * One attestation is written per `run`, with no cleanup, so the store grows
 * monotonically (tests alone pile up thousands). This removes whole session
 * directories whose attestation `captured_at` predates the cutoff. `--dry-run`
 * previews without deleting. Deletion is confined to direct child dirs of the
 * resolved attestation roots — never traverses outside them.
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

  // Canonicalize before dedup. A plain Set over the two root strings only
  // collapses byte-identical paths, so when the default root and the cwd-
  // relative root resolve to the SAME directory via different strings (e.g. a
  // relative EXCEPTD_HOME like `.exceptd`, or the home-mkdir-fail fallback),
  // both survive and every session under that dir is scanned twice — inflating
  // scanned/kept/pruned_count and double-listing each session in the preview.
  // realpathSync resolves symlinks + makes absolute for an existing dir; for a
  // not-yet-created root it throws, so fall back to path.resolve (absolute +
  // normalized). Mirrors the realpath confinement used at delete time below.
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
      // Determine the session's captured_at from its newest non-replay
      // attestation. A session with no parseable captured_at is left alone
      // (never delete something we can't date).
      let captured = null;
      let replayFallback = null;
      try {
        for (const f of fs.readdirSync(sdir)) {
          if (!f.endsWith(".json") || f.endsWith(".sig")) continue;
          let j; try { j = JSON.parse(fs.readFileSync(path.join(sdir, f), "utf8")); } catch { continue; }
          if (!j) continue;
          if (j.kind === "replay") {
            // A session holding only replay records (its attestation was
            // removed) would otherwise be undateable and never GC'd, so the
            // store grows without bound. Fall back to the newest replay
            // timestamp so prune can still age such a session out.
            if (typeof j.replayed_at === "string" && (!replayFallback || j.replayed_at > replayFallback)) replayFallback = j.replayed_at;
            continue;
          }
          if (typeof j.captured_at === "string" && (!captured || j.captured_at > captured)) captured = j.captured_at;
        }
      } catch { continue; }
      // Prefer the signed attestation's captured_at; fall back to the newest
      // replay timestamp for replay-only sessions.
      const dateStr = captured || replayFallback;
      const ts = dateStr ? Date.parse(dateStr) : NaN;
      if (!Number.isFinite(ts)) { kept++; continue; }
      if (ts < cutoffMs) {
        // Confinement: resolve and confirm sdir is a direct child of root
        // before it can be deleted, so a crafted session name can't escape the
        // root. Evaluate this in BOTH modes so the dry-run preview lists exactly
        // the set a real run will remove — a session the real run would refuse
        // (realpath escapes the root, or realpathSync throws) must not show up
        // as [would-delete]. realDir is reused for the rmSync below so the
        // delete and the gate operate on the same canonical path (no TOCTOU
        // between the check and the removal).
        let realDir = null;
        try {
          const realRoot = fs.realpathSync(root);
          const candidate = fs.realpathSync(sdir);
          if (path.dirname(candidate) === realRoot) realDir = candidate;
        } catch { /* unresolvable -> not deletable */ }
        if (realDir === null) { kept++; continue; }
        if (!dryRun) {
          // Real run: count the session as pruned only after the delete
          // succeeds, so pruned_count is a post-condition (sessions actually
          // removed from disk), never a candidate tally.
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
  // Normalize --playbook (registered `multi:`, so a single value arrives as a
  // one-element array) and refuse an empty value. `--playbook ""` would
  // otherwise unwrap to "" and slip past walkAttestationDir's truthy filter
  // guard — silently widening --latest to the newest attestation across ALL
  // playbooks rather than the requested one. Refuse explicitly, the same way
  // --since refuses a malformed value above, so the operator sees the bad
  // input instead of an unintended cross-playbook match.
  let playbookFilter = null;
  if (args.playbook != null) {
    playbookFilter = Array.isArray(args.playbook) ? args.playbook[0] : args.playbook;
    if (typeof playbookFilter !== "string" || playbookFilter === "") {
      return emitError("reattest: --playbook was given an empty value. Pass a playbook id (e.g. --playbook kernel) or omit --playbook to match across all playbooks.", { verb: "reattest", flag: "playbook" }, pretty);
    }
  }
  // --latest [--playbook <id>] [--since <ISO>] — find prior attestation
  // without requiring the operator to know the session-id.
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
  // Validate the session-id BEFORE it is joined into a filesystem path. The
  // other read verbs (attest show/verify/diff --against) gate on this; reattest
  // did not, so `findSessionDir` returning null let the `||` fallback join an
  // unvalidated `../`-bearing id straight onto the attestation root — escaping
  // it to read a forged attestation and write a signed replay record outside
  // the root. Ids resolved from the store via the latest-match path are already
  // safe; an operator-supplied id is the one that must be checked.
  try { validateSessionIdForRead(sessionId); }
  catch (e) { return emitError(`reattest: ${e.message}`, { session_id_input: typeof sessionId === "string" ? sessionId.slice(0, 80) : typeof sessionId }, pretty); }
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
  // Replay the ORIGINAL persisted submission, not a hardcoded empty one.
  // Replaying empty made the replay's evidence_hash differ from the prior hash
  // for every session whose original evidence wasn't byte-identical to that
  // empty stub — i.e. essentially all of them — so reattest reported a false
  // "drifted" on unchanged sessions. Replaying the prior submission reproduces
  // the prior hash for unchanged evidence; a mismatch then genuinely means the
  // hash/canonicalization (or the derived verdict) drifted.
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
  const replay = runner.run(prior.playbook_id, prior.directive_id, replaySubmission, replayOpts);

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
        // v0.12.38 cycle 18 P1 F2: mode 0o600 + Windows ACL hardening
        // (matches the primary attestation write site).
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
  }, pretty, (obj) => {
    // Human renderer for `attest diff` (reattest path) — one-screen
    // answer to "did anything change since the last run?" so the
    // operator doesn't have to parse the JSON envelope.
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
 * map a verifyAttestationSidecar() result to a one-token
 * classification label. The label is persisted alongside the full
 * sidecar_verify object so auditors can filter override events by class
 * without regexing the human-readable reason string.
 */
/**
 * Tamper predicate over a verifyAttestationSidecar() result. Collapses
 * tamper-class detection: any non-benign sidecar state refuses replay
 * unless --force-replay is set. A predicate of only
 * `verify.signed && !verify.verified` would miss corrupt-JSON sidecars,
 * substituted "unsigned" sidecars on a host WITH a private key,
 * downgrade-bait algorithm shapes, and a keys/public.pem failing the
 * EXPECTED_FINGERPRINT pin — each of which would let replay proceed
 * against forged input. Keeping the class list HERE (one shared helper)
 * means a new tamper class added to the verifier has exactly one refusal
 * site to extend.
 */
function isTamperedSidecarVerify(verify) {
  if (!verify || typeof verify !== "object") return false;
  const isSignedTamper = verify.signed && !verify.verified;
  const isClassTamper = !verify.signed && (
    verify.tamper_class === "sidecar-corrupt"
    || verify.tamper_class === "unsigned-substitution"
    // Anything other than "Ed25519" or "unsigned": a sidecar that throws
    // inside crypto.verify (e.g. signature_base64 missing on a
    // downgrade-bait shape) would otherwise emerge as signed:true +
    // verified:false through the catch block by accident. The strict
    // pre-check surfaces the class directly; refuse on it too.
    || verify.tamper_class === "algorithm-unsupported"
    // A keys/public.pem that fails the EXPECTED_FINGERPRINT pin is the
    // key-swap attack the pin exists for — verification "against" the
    // swapped key proves nothing, so replay refuses exactly like the
    // other tamper classes (attest verify already refuses on this).
    || verify.tamper_class === "fingerprint-mismatch"
    // A sidecar that should exist (a signing key is present, or a signed peer
    // attestation sits in the same session) but is absent is a
    // deletion-to-evade-tamper signal — refuse exactly as reattest and attest
    // verify already do, so a forged attestation can't dodge the diff gate by
    // stripping its .sig.
    || verify.tamper_class === "sidecar-missing"
  );
  return Boolean(isSignedTamper || isClassTamper);
}

function classifySidecarVerify(verify) {
  if (!verify || typeof verify !== "object") return "unknown";
  if (verify.signed && verify.verified) return "verified";
  if (verify.signed && !verify.verified) return "tampered";
  if (verify.tamper_class === "sidecar-corrupt") return "sidecar-corrupt";
  if (verify.tamper_class === "unsigned-substitution") return "unsigned-substitution";
  // `algorithm-unsupported` is its own class label so log scrapers /
  // dashboards can filter downgrade-bait events without parsing the reason.
  if (verify.tamper_class === "algorithm-unsupported") return "algorithm-unsupported";
  if (verify.tamper_class === "fingerprint-mismatch") return "fingerprint-mismatch";
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
// Shared one-screen renderer for `attest diff` (both the --against and the
// no-against/most-recent-prior branches). Reads only fields off the emitted
// object so both call sites render identically; the sidecar line is shown only
// when a sidecar verification was performed (the --against path may omit it).
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
    // Use the canonical classifier, which checks tamper_class BEFORE the reason
    // strings. The previous inline logic matched reason.includes("explicitly
    // unsigned") first, so an unsigned-SUBSTITUTION attack (whose reason also
    // contains "explicitly unsigned" but carries tamper_class:
    // 'unsigned-substitution') was mislabeled as the benign 'explicitly-unsigned'
    // — hiding the substitution signal in the human diff output.
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
  // Validate subverb membership BEFORE the session-id branch so a typo
  // (`attest verfy sid`) gets the did-you-mean response, not the
  // misleading "no session dir for sid" downstream. Pre-fix the
  // session-id resolution ran first and a valid-but-unrecognized
  // subverb collapsed into a session-lookup failure.
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
  // `list` doesn't require a session-id positional.
  if (subverb === "list") {
    return cmdListAttestations(runner, args, runOpts, pretty);
  }
  // `prune` is the GC for attestation growth — also no session-id positional.
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
  const attestationFiles = [];
  const replays = [];
  for (const f of files) {
    let parsed;
    const fp = path.join(dir, f);
    try { parsed = JSON.parse(fs.readFileSync(fp, "utf8")); }
    catch { continue; }
    if (!parsed) continue;
    if (parsed.kind === "replay") replays.push(parsed);
    // Track the on-disk path alongside the parsed attestation so the A-side
    // sidecar verify resolves the ACTUAL signed file. A multi-playbook
    // (run-all) session writes per-playbook `<id>.json` + `<id>.json.sig`
    // and NEVER an attestation.json — so a hardcoded attestation.json path
    // would point at a non-existent file and silently report "no .sig
    // sidecar", letting a forged run-all A-side pass diff at exit 0.
    else { attestations.push(parsed); attestationFiles.push(fp); }
  }

  if (subverb === "show") {
    emit({ verb: "attest show", session_id: sessionId, attestations, attestation_replays: replays }, pretty);
    return;
  }

  if (subverb === "diff") {
    // `attest diff <session-id> [--against <other-session-id>]` — drift
    // comparison. Without --against, replays current state against prior
    // session (= reattest). With --against, compares two sessions A vs B
    // by evidence_hash + artifact-level field diff.
    //
    // An empty `--against ""` / `--against=` parses to the empty string, which
    // is falsy — without this guard it would skip the explicit two-session
    // branch and silently fall through to the auto-prior path, comparing
    // against a DIFFERENT baseline than the operator named (a `--against
    // "$VAR"` that expanded to empty is the common footgun). REQUIRES_VALUE
    // only catches the value-less `--against` (parsed as `true`), not the
    // empty-string form. Refuse explicitly so the dropped target is signalled
    // rather than swapped under the operator.
    if (args.against === "") {
      return emitError(
        'attest diff: --against was given an empty value; pass a session-id, or omit --against to diff against the most-recent prior.',
        { verb: "attest diff", flag: "against" },
        pretty
      );
    }
    if (args.against) {
      // Validate the --against id with the same gate as the primary sid, so a
      // traversal/garbage value (`../../etc/passwd`) gets the explicit "invalid
      // session-id" message rather than a misleading "no session dir found".
      try { validateSessionIdForRead(args.against); }
      catch (e) {
        return emitError(`attest diff --against: ${e.message}`, { against_input: typeof args.against === "string" ? args.against.slice(0, 80) : typeof args.against }, pretty);
      }
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
        // Session dir contains only replay records, no attestation —
        // diff has nothing to compare on the A side.
        return emitError(
          `attest diff ${sessionId}: no attestation found in session dir (only replay records). The session may be replay-only; verify with \`exceptd attest show ${sessionId}\`.`,
          { verb: "attest diff", session_id: sessionId, attestation_count: 0, replay_count: replays.length },
          pretty
        );
      }
      // Verify BOTH attestations' sidecars — the --against (B-side) drives the
      // drift verdict as much as the A-side, so a forged comparison attestation
      // must be refused too, not silently diffed under an A-only green sidecar
      // line. Mirrors reattest's tamper-refusal contract (exit TAMPERED unless
      // --force-replay); surfaces a_/b_sidecar_verify either way. The A-side
      // verifies its RESOLVED file (selfResolved.file) so a run-all session,
      // whose real signed sidecar is `<id>.json.sig` not attestation.json.sig,
      // is checked against its actual signature rather than a missing path.
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
        // v0.11.8 (#102): normalize submissions before diffing so flat-shape
        // (observations + verdict) submissions emit meaningful artifact_diff
        // counts. Pre-0.11.8 (self.submission||{}).artifacts was undefined
        // for flat submissions; the diff returned all zeros even when
        // artifacts were present in observations.
        // The catalog stub stands in for an empty side ONLY when BOTH sides
        // are empty — substituting it for one empty side while the peer passes
        // through its real keys manufactures phantom drift (every catalog id
        // the populated side did not submit reads as added/changed).
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
    // No --against: find the most-recent prior attestation for the
    // SAME playbook as `sessionId` and diff against that. Pure
    // comparison — no replay.
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
    // Verify BOTH sidecars and apply the same dual-side tamper refusal as the
    // --against branch. Pre-fix this branch verified only the A-side and never
    // the auto-selected prior, so a forged prior (or a forged run-all A-side,
    // which the hardcoded attestation.json path missed entirely) produced a
    // drift verdict at exit 0 under a green sidecar line. The A-side uses its
    // RESOLVED file; the B-side uses the prior's actual on-disk path
    // (prior.file), so a run-all prior is checked against its real signature.
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
      // Retain `sidecar_verify` (A-side) for back-compat; add a_/b_ pair so the
      // default branch's output shape matches the --against branch.
      sidecar_verify: aSidecarVerify,
      a_sidecar_verify: aSidecarVerify,
      b_sidecar_verify: bSidecarVerify,
      // Catalog stub stands in for an empty side only when BOTH sides are
      // empty (same peer-symmetric gate as the --against branch); real-vs-empty
      // diffs the populated side's keys against {}, not against the full catalog.
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
    // Does any sidecar in this session dir carry a real Ed25519 signature? If
    // so, a sibling attestation with NO sidecar is suspicious (a sig was
    // expected). Combined with hasPrivKey, this lets default `attest verify`
    // treat a deleted sidecar as tamper — agreeing with `reattest`, which
    // already refuses. The keyless case (no key, all-unsigned peers) stays
    // benign so keyless CI is unaffected.
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

    // Sidecar-verify helper shared by both the attestations[] and
    // replay-records[] partitions. Centralising the per-file verify
    // logic means a future tamper-class addition lands in one place
    // instead of two parallel branches.
    const verifySidecar = (f) => {
      const sigPath = path.join(dir, f + ".sig");
      if (!fs.existsSync(sigPath)) {
        // A missing sidecar is benign ONLY when none was ever expected (the
        // attestation was written on a keyless host and no peer is signed).
        // When a sig SHOULD exist, an absent one is a deletion-to-evade-tamper
        // signal — flag it so default verify matches reattest's refusal.
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
      // Replay-record tamper is an audit-trail signal but not an
      // attestation-integrity violation; surface a warning so operators
      // see the corruption without promoting the exit code.
      body.replay_tamper = true;
      body.warnings = ["one or more replay records failed Ed25519 verification — audit-trail corruption suspected, regenerate via reattest"];
    }
    // --require-signed: in an audit context an UNSIGNED or sidecar-stripped
    // attestation is not acceptable, even though it isn't tamper per se.
    // Without this, `attest verify` returns exit 0 for an unsigned attestation
    // — so an attacker who tampers the body AND deletes the .sig evades the
    // exit-6 tamper signal. Strict mode makes "not Ed25519-verified" a failure
    // (exit 1 via the ok:false contract, distinct from tamper's exit 6).
    if (!attTampered && args["require-signed"] && (attResults.length === 0 || !attResults.every(r => r.verified))) {
      body.ok = false;
      body.require_signed = true;
      // attResults.length === 0 → the session dir has no attestation at all
      // (only replay records, or the JSON was deleted); `[].every()` is
      // vacuously true, so without the length check an empty session would
      // pass strict mode. A strict audit gate must reject "nothing to verify".
      body.error = attResults.length === 0
        ? "attest verify --require-signed: no signed attestation present for this session — refusing under strict mode"
        : "attest verify --require-signed: one or more attestations are not Ed25519-verified (unsigned or missing .sig sidecar) — refusing under strict mode";
    }
    // Human renderer for `attest verify` — one-line answer to "did
    // anyone tamper with my evidence since I ran it?" so the operator
    // doesn't have to parse the JSON envelope.
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
      // "Clean enough to proceed" = no tamper signal. Explicitly-unsigned
      // attestations are NOT a tamper (the operator's environment lacks
      // .keys/private.pem; this is the default on CI runners and on hosts
      // doing posture-only walks). Distinguish from real verification
      // failures (tamper_class present) so the next-step block still fires.
      const noTamper = att.every(r => !r.tamper_class) && rep.every(r => !r.tamper_class);
      const allVerified = att.every(r => r.verified) && rep.every(r => r.verified);
      const icon = obj.ok === false ? (obj.require_signed ? "[!! UNSIGNED-REJECTED]" : "[!! TAMPERED]") : (obj.replay_tamper ? "[i  REPLAY_TAMPER]" : (allVerified ? "[ok]" : "[i  UNSIGNED]"));
      lines.push(`\n${icon}  ${att.filter(r => r.verified).length}/${att.length} attestation(s) verified, ${rep.filter(r => r.verified).length}/${rep.length} replay record(s) verified`);
      // Status icon precedence: verified → [ok]. tamper_class set →
      // [!! <CLASS>] (real tamper signal). signed=false AND no
      // tamper_class → [i UNSIGNED] (not a failure — the attestation
      // was legitimately written without a key, e.g. on a CI runner
      // without .keys/private.pem). signed=true but verified=false
      // without a tamper_class indicates a verify error (missing pub
      // key, read error) — [i  VERIFY-ERROR].
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
        // allVerified → signed + verified; noTamper → unsigned but not
        // tampered (legitimate CI / posture-only state). Both states are
        // safe to keep working with, so point at the same next-step
        // commands.
        lines.push(`\n  → next: exceptd attest diff ${obj.session_id}            # compare against prior session for this playbook`);
        lines.push(`         exceptd attest show ${obj.session_id} --pretty     # inspect the persisted attestation`);
      }
      return lines.join("\n");
    });
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
      // signal_overrides are operator-controllable: the contract canonicalizes
      // hit/miss/inconclusive verdicts but does NOT reject free-form values
      // (an unrecognized value surfaces a signal_override_unrecognized runtime
      // error yet is still stored verbatim in the submission), and the sibling
      // `<id>__fp_checks` keys carry arbitrary operator attestation maps. Under
      // a bundle labelled "redacted ... suitable for audit submission" the only
      // audit-meaningful content is the indicator verdict itself, so keep an
      // exact hit/miss/inconclusive value and replace everything else (free-form
      // strings, captured-data values, __fp_checks objects) with "[redacted]".
      // Apply the same keyname denylist as signals_redacted so an obviously-
      // sensitive key can't ride through under this field either. Matches the
      // signal-value-redaction contract asserted in tests/cli-coverage.js.
      signal_overrides: Object.fromEntries(Object.entries((a.submission && a.submission.signal_overrides) || {})
        .filter(([k]) => !/_filter$|_key$|token|secret|password/i.test(k))
        .map(([k, v]) => [k, (v === "hit" || v === "miss" || v === "inconclusive") ? v : "[redacted]"])),
      // Redact the VALUES, not just drop obviously-sensitive keys: a submitted
      // signal value can hold operator data (e.g. a captured credential string),
      // and this field is labelled "redacted". The keyname denylist still drops
      // the obviously-sensitive keys entirely; every retained key keeps only a
      // "[redacted]" placeholder value, matching artifacts_redacted above.
      signals_redacted: Object.fromEntries(Object.entries((a.submission && a.submission.signals) || {})
        .filter(([k]) => !/_filter$|_key$|token|secret|password/i.test(k))
        .map(([k]) => [k, "[redacted]"])),
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
        redaction_policy: "v0.10.3-default — artifact values stripped; signal_overrides reduced to hit/miss/inconclusive verdicts (free-form values redacted); precondition_checks + evidence_hash + signature preserved.",
        attestations: redacted,
      }, pretty);
    }
    return;
  }

  // Unreachable — front-loaded subverb membership check above handles
  // unknown subverbs. Defensive return so future refactors that move
  // the gate don't silently fall through.
  return emitError(`attest: unknown subverb "${subverb}".`, { verb: "attest", subverb_input: subverb }, pretty);
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
    const inds = (pb.phases?.detect?.indicators || []).filter(i => i && i.id);
    if (inds.length === 0) return null;
    return Object.fromEntries(inds.map(i => [i.id, 'inconclusive']));
  } catch { return null; }
}
// A submission carries real operator data for a diff when it supplied
// artifacts, signal_overrides, OR observations. The empty case ({} or
// {observations:{}}) is "no operator data was supplied." Diff symmetry hinges
// on this predicate: the playbook catalog stub may only stand in for an empty
// side when BOTH sides are empty (so the count reflects "N catalog ids,
// uniformly empty on both sides"). Substituting the full catalog for one empty
// side while the peer passes through its real keys manufactures phantom drift —
// every catalog id the populated side did not submit shows up as "added"
// (artifacts) or "changed" (signals). See callers for the bothEmpty gate.
function submissionHasData(submission) {
  if (!submission || typeof submission !== "object") return false;
  const nonEmpty = (o) => o && typeof o === "object" && Object.keys(o).length > 0;
  return nonEmpty(submission.artifacts)
    || nonEmpty(submission.signal_overrides)
    || nonEmpty(submission.observations);
}
function normalizedArtifacts(submission, runner, playbookId, applyEmptyFallback = true) {
  if (!submission || typeof submission !== "object") {
    return applyEmptyFallback ? (_playbookArtifactCatalog(runner, playbookId) || {}) : {};
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
  // Empty submission ({} or {observations:{}}). The catalog stub may only
  // stand in when the PEER side is also empty (applyEmptyFallback). When the
  // peer carried real artifacts, return an empty map so the populated side's
  // keys diff against nothing — yielding genuine added/removed instead of one
  // fabricated "added" per catalog id the operator never submitted.
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
  // Empty submission — same peer-symmetric gate as normalizedArtifacts: only
  // stand in the inconclusive catalog stub when the peer is also empty, so a
  // real-vs-empty signal diff reports only the genuinely-differing indicators.
  return applyEmptyFallback ? (_playbookSignalCatalog(runner, playbookId) || {}) : {};
}

/**
 * Order-insensitive JSON serializer for the per-field artifact comparison.
 * Object keys are sorted recursively so two artifacts that differ ONLY in
 * key insertion order compare equal — matching the key-sorted canonical form
 * that evidence_hash (and therefore top-level `status`) already uses. Without
 * this, a side stored as nested `{captured, value}` (raw operator order) vs a
 * side normalized to `{value, captured}` serialized unequal under
 * JSON.stringify, so `artifact_diff.changed[]` reported a false "changed"
 * while `status` said "unchanged" — a self-contradicting diff. Depth-bounded
 * to defend against adversarial/cyclic input; callers treat a throw as
 * "cannot canonicalize" and fall back to raw stringify (diff output is
 * non-fatal context, never a gate).
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
    // Canonicalization bailed (too deep / cyclic) — fall back to the
    // order-sensitive comparison rather than masking a real difference.
    return JSON.stringify(av) !== JSON.stringify(bv);
  }
}

/**
 * Per-artifact diff between two submissions. Returns { added, removed, changed }
 * keyed by artifact id. Used by `attest diff` so operators get field-level
 * context instead of a binary evidence_hash signal.
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
    // Deep, order-insensitive compare — signal_overrides hold OBJECT values
    // (the `<indicator-id>__fp_checks` maps), so a reference-strict `!==` would
    // report byte-identical FP-check content as "changed", contradicting the
    // evidence_hash verdict. Reuse the same comparator diffArtifacts uses.
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

// Preview the evidence an artifact carries for the diff output. `.value` is the
// canonical carrier, but observations legitimately store their secret/path/match
// under other keys (path, matched, reason, or a custom key). When `.value` is
// absent, fall back to a preview of the remaining evidence-bearing keys (every
// key except the bookkeeping `captured`/`captured_at` flags) so non-`value`
// carriers still render instead of collapsing to a null preview — which hid the
// actual differing content even when the per-field equality compare correctly
// flagged the artifact as changed.
function artifactPreview(art) {
  if (art === null || typeof art !== "object" || Array.isArray(art)) return previewValue(art);
  if (art.value !== undefined && art.value !== null) return previewValue(art.value);
  const { captured, captured_at, _captured_at, value, ...evidence } = art;
  const keys = Object.keys(evidence);
  if (keys.length === 0) return null;
  return previewValue(evidence);
}

// ---------------------------------------------------------------------------
// v0.11.0: cmdDiscover — context-aware playbook recommender.
// Collapses scan + dispatch + recommend into one verb. Sniffs the cwd, reads
// /etc/os-release on Linux, and outputs a list of recommended playbooks.
// ---------------------------------------------------------------------------
function cmdDiscover(runner, args, runOpts, pretty) {
  // Honor --cwd so `discover --cwd <dir>` scans the target tree, not the
  // process cwd. Pre-fix it was silently ignored — recommendations were
  // computed for the wrong directory with no signal. Validated like collect.
  let cwd = process.cwd();
  // An explicit empty value (`--cwd ""`) would otherwise be falsy and silently
  // scan process.cwd() — the wrong directory — reported as a successful run.
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
      // Read the file directly instead of spawning `cat` (a process to do what
      // fs does, and a static-analysis "unnecessary use of cat" flag).
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

  // Build recommendation set. Dedup by playbook id so multi-trigger rules
  // don't double-list.
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
  // Container artifacts ANYWHERE in the tree (subdir Dockerfiles, compose
  // variants like docker-compose.test.yml) — not just a root-level exact-name
  // file. The root-only `probe()`s above miss them, so mirror exactly what the
  // containers collector walks/classifies, otherwise discover under-recommends
  // `containers` and an operator silently skips a relevant playbook.
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

  // .github/workflows/ directory probe — surfaces the CI/CD posture
  // playbook when present.
  let hasGithubWorkflows = false;
  try {
    const wfDir = path.join(cwd, ".github", "workflows");
    if (fs.existsSync(wfDir) && fs.statSync(wfDir).isDirectory()) {
      const entries = fs.readdirSync(wfDir).filter(f => /\.(ya?ml)$/i.test(f));
      if (entries.length > 0) hasGithubWorkflows = true;
    }
  } catch { /* swallow */ }

  // Home-resident MCP client config probe — surfaces the `mcp`
  // playbook when at least one supported client is configured on
  // this host. Best-effort: silently skip if home isn't readable.
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

  // Shell rc presence — proxy signal for "user has a shell-driven
  // workflow that might export AI API keys". The ai-api collector
  // checks rc files + vendor dotfiles regardless; surface the
  // recommendation when at least one rc file exists.
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
  // Always include cross-cutting framework correlation.
  recommend("framework", "cross-cutting: framework correlation always applicable");

  // Enrich each recommendation with whether a companion collector
  // exists for the playbook. Operators who discover a relevant
  // playbook for their cwd should see one pipe away from running
  // it (rather than having to translate the playbook's look phase
  // into a filesystem walk by hand).
  const collectorsDir = path.join(PKG_ROOT, "lib", "collectors");
  for (const rec of recs) {
    const collectorPath = path.join(collectorsDir, rec.id + ".js");
    const hasCollector = fs.existsSync(collectorPath);
    rec.collector_available = hasCollector;
    rec.collect_cmd = hasCollector ? `exceptd collect ${rec.id}` : null;
  }

  // Next-step suggestions are conditional on what discover detected.
  // From an empty / no-code-detected cwd, suggesting `run --scope code`
  // would silently run every code-scope playbook against an empty tree
  // and produce a multi-hundred-KB JSON dump for no useful reason.
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

// ---------------------------------------------------------------------------
// v0.11.0: cmdDoctor — one-shot health check.
// Collapses verify + currency + validate-cves + validate-rfcs + signing-status.
// Each subcheck is independently fault-tolerant: a single failure surfaces
// in the JSON but never crashes the verb.
// ---------------------------------------------------------------------------
function cmdDoctor(runner, args, runOpts, pretty) {
  const wantJson = !!args.json || !!args.pretty;
  const indent = !!args.pretty;

  // Refuse unknown flags rather than silently running the full default
  // scan. Pre-fix, typos and renamed-out flags all returned exit 0 with
  // the operator believing they'd run a targeted check.
  const KNOWN_DOCTOR_FLAGS = new Set([
    "json", "pretty", "fix", "air-gap",
    "signatures", "currency", "cves", "rfcs", "registry-check",
    "ai-config", "collectors", "exit-codes", "shipped-tarball",
    // Global flags the parser may inject regardless of verb. Keep in sync
    // with VERB_FLAG_ALLOWLIST._global in lib/flag-suggest.js — quiet/verbose
    // are accepted on every verb, so doctor must not refuse them as typos.
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

  // `doctor --exit-codes` dumps the canonical exit-code table as JSON so
  // operator-facing docs cannot drift from runtime behavior. Short-circuit
  // before the regular health checks since the dump is informational.
  if (args["exit-codes"]) {
    emit({ verb: "doctor", exit_codes: listExitCodes() }, pretty);
    return;
  }

  // Selective subchecks. If any of the four flags is passed, run only those.
  // If none are passed, run all four plus signing-status.
  // v0.13.3: --ai-config audits AI-assistant config-file permissions per
  // NEW-CTRL-050 (from the MAL-2026-SHAI-HULUD-OSS zeroday-lessons entry).
  // It's a separate flag because the check is opt-in — most operators
  // don't want their AI-config state probed by default.
  const onlySigs = !!args.signatures;
  const onlyCurrency = !!args.currency;
  const onlyCves = !!args.cves;
  const onlyRfcs = !!args.rfcs;
  const onlyAiConfig = !!args["ai-config"];
  const onlyCollectors = !!args.collectors;
  const anySelected = onlySigs || onlyCurrency || onlyCves || onlyRfcs || onlyAiConfig || onlyCollectors;
  // --shipped-tarball lives inside the signatures check, so it must imply it.
  // Pre-fix, `doctor --shipped-tarball --cves` made runSigs false (a selective
  // flag was set, but not --signatures), silently skipping the tarball
  // round-trip while the operator believed it ran.
  const runSigs = !anySelected || onlySigs || !!args["shipped-tarball"];
  const runCurrency = !anySelected || onlyCurrency;
  const runCves = !anySelected || onlyCves;
  const runRfcs = !anySelected || onlyRfcs;
  const runCollectors = !anySelected || onlyCollectors;
  const runSigning = !anySelected;
  // --ai-config is opt-in — never runs as part of the default no-flag
  // doctor pass. Operators ask for it explicitly.
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
        // Audit 3 B.7: surface the freshest + stalest last_threat_review
        // so operators can answer "is my data stale?" without parsing the
        // full report. Falls back gracefully when the upstream report
        // omits the per-skill date.
        const dates = parsed.currency_report
          .map(s => s.last_threat_review)
          .filter(d => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d))
          .sort();
        const minDaysSince = dates.length ? Math.floor((Date.now() - new Date(dates[0]).getTime()) / 86400000) : null;
        checks.currency = {
          ok,
          total_skills: parsed.currency_report.length,
          stale_skills: stale.map(s => s.skill),
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
      // v0.13.6: total comes from the catalog file directly. The
      // validate-cves text-scrape only ever counted CVE-* prefixes, so
      // MAL-* (malicious package) entries silently dropped from the
      // doctor report — operators reading "34 entries" assumed the
      // Shai-Hulud / TanStack worm intel had been removed when it was
      // present all along. Read the catalog and report all prefix
      // groups — the previous CVE+MAL-only enumeration silently dropped
      // any other prefix (BUG-*, SNYK-*, etc.) from the breakdown even
      // though they were summed into total. Same regression class as
      // the original CVE-only fix; this generalizes it.
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
        // Enumerate every prefix present so future additions (BUG-*,
        // SNYK-*, GHSA-*, RUSTSEC-*) surface in the breakdown instead
        // of vanishing into the total - sum-of-named-prefixes gap.
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
      // Count the catalog directly (same approach the CVE subcheck uses) rather
      // than scraping `^RFC-\d+` table rows from the validate-rfcs output. The
      // text scrape dropped every non-RFC family (CSAF / DRAFT / ISO entries),
      // undercounting the catalog and hiding those citation families. Read the
      // canonical file and emit a by_prefix breakdown.
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
      // v0.12.9 codex P1 (PR #4): report only PKG_ROOT — that's the path
      // maybeSignAttestation() and `attest verify` actually use. Pre-v0.12.9
      // doctor also reported cwd-resident keys as present, which gave a
      // false-positive "signing enabled" signal when the operator's cwd
      // key was misaligned with the PKG_ROOT-resident public key used at
      // verify time.
      const keyPath = path.join(PKG_ROOT, ".keys", "private.pem");
      const present = fs.existsSync(keyPath);
      // v0.13.13: distinguish consumer-install (npm install -g) from
      // contributor-checkout. Consumer installs live under node_modules/
      // and have no business signing — the doctor warning "private key
      // MISSING" reads as a problem on a fresh global install when it's
      // actually expected.
      //
      // Codex P1 on PR #53: single-signal detection (PKG_ROOT contains
      // "node_modules") is fragile against symlink-resolved paths
      // (npm link, workspaces). Two-signal detection: either signal
      // counts as consumer.
      //   (a) PKG_ROOT path contains a "node_modules" path segment —
      //       real `npm install -g` lays the package at
      //       <prefix>/lib/node_modules/@blamejs/exceptd-skills/
      //   (b) PKG_ROOT's parent directory is exactly "@blamejs" — the
      //       canonical scoped-npm-install marker, robust to symlink
      //       realpath() walks because the parent's basename of the
      //       published-tarball layout always carries the npm scope.
      // Contributor checkouts (PKG_ROOT outside node_modules AND
      // parent != @blamejs) keep severity:warn — Bug #61 (v0.11.2):
      // the attestation pipeline writes unsigned files when this is
      // absent and contributors need the nudge.
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

  // v0.13.3 — AI-assistant config-file permission audit per NEW-CTRL-050
  // (from the MAL-2026-SHAI-HULUD-OSS zeroday-lessons entry). Walks
  // ~/.claude/, ~/.cursor/, ~/.codeium/, ~/.aider/, ~/.continue/ for
  // sensitive config files (settings.json, mcp.json, *.mcp_config.json,
  // api_key*, *.token, *.credentials) and reports any not at mode 0600.
  // The MAL-2026-SHAI-HULUD-OSS framework reads these files at
  // unprivileged-process scope; tightening to 0600 forces npm/node-spawned
  // processes that don't share UID to fail the read.
  //
  // Opt-in only — never runs as part of the default no-flag doctor pass.
  // Operators request it via `exceptd doctor --ai-config`.
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
    // Files within those dirs that warrant the strict-mode check.
    // v0.13.7: prior `/\.mcp_config\.json$/` regex required a literal `.`
    // before `mcp_config.json`, so the real-world Windsurf install path
    // (`~/.codeium/windsurf/mcp_config.json` — no leading dot) was
    // silently missed by the audit. `^mcp_config\.json$` now matches the
    // bare filename, and the trailing `.mcp_config.json` form is kept
    // for vendor variants that prefix with a tag (e.g. `default.mcp_config.json`).
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
    // Audit 3 B.9: cap depth + file count to bound the walk. Without
    // these, doctor --ai-config can read 48k+ entries under ~/.claude
    // (conversation logs, cache dirs, plugin tarballs) before finishing.
    // The five SENSITIVE_PATTERNS files all live within ~3 levels of an
    // AI-assistant config root, so 4 is generous. The skipped dirs are
    // known non-config noise that shouldn't carry credentials.
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
          // Check the file cap immediately after the increment so a
          // single large directory doesn't process tens of thousands of
          // entries before the next recursive call catches the bound.
          if (scannedFiles > MAX_FILES) {
            walkAborted = true;
            return;
          }
          if (!SENSITIVE_PATTERNS.some((re) => re.test(e.name))) continue;
          let st;
          try { st = fs.statSync(childAbs); } catch { continue; }
          if (process.platform === 'win32') {
            // v0.13.5: real ACL check via icacls. Replaces the v0.13.3
            // "manual review" info-level placeholder. Confirms only the
            // current-user SID has any read entry. Anything else (Users,
            // Everyone, Authenticated Users, BUILTIN\Users, etc.) on the
            // ACL counts as "broader than user-only" and surfaces as a
            // warn finding. The `--fix` path applies `icacls /inheritance:r
            // /grant:r <USER>:F` to strip inherited entries.
            const aclCheck = checkWindowsAcl(childAbs);
            if (aclCheck.ok) continue;
            // Resolve the grant principal defensively: an unset USERNAME
            // would otherwise interpolate "undefined:F", and icacls applies
            // /inheritance:r BEFORE failing on the unresolvable account —
            // stripping every inherited entry and locking the file out.
            // os.userInfo() works even when the env var is absent.
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

    // v0.13.5: --fix path. When `doctor --ai-config --fix` is invoked
    // AND warn-severity findings exist, apply the per-finding fix
    // command (chmod 600 on POSIX; icacls /inheritance:r /grant:r on
    // Windows). The fix attempt is recorded per-finding so the report
    // surfaces which fixes landed vs which failed.
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

    // A truncated walk (hit the file/depth cap) means the audit is INCOMPLETE —
    // a sensitive file beyond the cap would be unseen. Don't report an
    // unqualified clean pass: downgrade to a warn so automation can branch on
    // incompleteness even when zero findings surfaced within the cap.
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

  // Collector-layer health gate. Walks every playbook, looks up the
  // matching `lib/collectors/<id>.js`, requires the module, verifies
  // `playbook_id` matches the file name AND `collect` is exported.
  // policy_skips is the catalogued set of judgement-shaped playbooks
  // (incident / governance / pure-analyze) that intentionally have no
  // collector per AGENTS.md — operators see "10 missing is by design,
  // not regression."
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
      // Audit 3 B.6: pre-fix `without_collector` was just "playbooks
      // missing a collector file" — which happened to equal POLICY_SKIPS
      // exactly because every policy-skipped playbook also has no
      // collector. That coincidence isn't an invariant: a future
      // playbook could lose its collector by accident OR a policy-skipped
      // playbook could gain a collector intentionally. Distinguish the
      // two: `without_collector` is now playbooks-missing-a-collector
      // that are NOT in the policy-skip allowlist — i.e. actual gaps
      // that need attention. The set-difference is what operators
      // should remediate.
      // Pre-fix `without_collector` was just "playbooks missing a
      // collector file" — which happened to equal POLICY_SKIPS exactly
      // because every policy-skipped playbook also has no collector.
      // That coincidence isn't an invariant: a future playbook could
      // lose its collector by accident OR a policy-skipped playbook
      // could gain one. The new `unexplained_missing_collectors`
      // field surfaces the operator-actionable set difference:
      // playbooks missing a collector that are NOT in the policy
      // allowlist. Existing `without_collector` retained for
      // back-compat.
      const policySkipSet = new Set(POLICY_SKIPS);
      const unexplained_missing_collectors = without_collector.filter(p => !policySkipSet.has(p));
      // Audit-3 codex P1 follow-up: when an unexplained missing collector
      // appears (a playbook that SHOULD have a collector but doesn't,
      // i.e. NOT in the policy-skip allowlist), the check fails. Without
      // this, automation and CI health checks would miss the exact
      // regression class that unexplained_missing_collectors exists to
      // surface. Load errors still fail at "error" severity; unexplained
      // missings fail at "warn" (they're a build-time gap, not a
      // runtime crash).
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

  // Walk every check and split: errors (severity error/missing/fail) vs warnings
  // (severity warn). all_green is true ONLY when zero errors AND zero warnings.
  // v0.13.11: bucketing logic extracted to lib/doctor-bucketing.js so the
  // severity-first rule is testable in isolation. A check that sets
  // `ok: false` but `severity: "warn"` (e.g. the signing-status check when
  // .keys/private.pem is absent on a non-contributor install — a nudge, not
  // a fail) must route to warning_checks, not failed_checks. Pre-v0.13.11,
  // the prior order fired the `ok === false` branch first and a fresh
  // global `npm install -g` reported `failed_checks: ["signing"]` with
  // `warnings_count: 0`, contradicting the [!! warn] text-mode icon.
  const { bucketChecks } = require(path.join(PKG_ROOT, "lib", "doctor-bucketing.js"));
  let { warnList, errorList } = bucketChecks(checks);
  let allGreen = errorList.length === 0 && warnList.length === 0;
  // Audit 3 B.11: surface the local version on the default doctor output
  // so operators answer both "is my install healthy?" AND "which version
  // am I running?" without having to invoke `exceptd version` separately.
  // The opt-in --registry-check augments this with the published comparison;
  // local_version alone is offline-clean.
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

  // --fix runs BEFORE the JSON early-return so `exceptd doctor --fix --json`
  // actually fixes (was a no-op pre-v0.11.6). Re-runs the signing check
  // after fix so the returned JSON reflects the post-fix state.
  //
  // Safety: lib/sign.js generateKeypair() refuses if keys/public.pem
  // already exists (overwriting it would orphan every shipped signature —
  // the v0.11.x regression class). Surface that refusal as a distinct
  // fix_attempted reason so operators see WHY the fix declined.
  // After successful key generation, chain sign-all so the manifest +
  // every shipped skill carries a signature paired with the new public
  // key. Without this chain, `doctor --fix` succeeds but the very next
  // `exceptd doctor` (signatures check) reports 0/N passing.
  if (args.fix && checks.signing && !checks.signing.private_key_present) {
    const pubKeyExists = fs.existsSync(path.join(PKG_ROOT, "keys", "public.pem"));
    const fingerprintPinExists = fs.existsSync(path.join(PKG_ROOT, "keys", "EXPECTED_FINGERPRINT"));
    if (pubKeyExists) {
      out.summary.fix_attempted = "ed25519_keypair_generation_declined";
      out.summary.fix_decline_reason = "keys/public.pem already exists but no matching private key. Generating a fresh keypair would overwrite the public key and orphan every shipped signature. If you intend to establish a new signing identity, run `node $(exceptd path)/lib/sign.js generate-keypair --rotate` followed by sign-all.";
      process.stderr.write("[doctor --fix] refused: keys/public.pem present without matching private key. Pass --rotate via the underlying lib/sign.js if a new identity is intended.\n");
    } else if (fingerprintPinExists) {
      // A committed EXPECTED_FINGERPRINT without keys/public.pem signals an
      // intended committed signing identity on a corrupted/partial checkout.
      // Generating a fresh keypair here would write a public.pem whose
      // fingerprint can never match the pin, leaving verify.js permanently
      // refusing (fingerprint-mismatch) while --fix claimed success. Decline
      // and tell the operator to restore the real public key.
      out.summary.fix_attempted = "ed25519_keypair_generation_declined";
      out.summary.fix_decline_reason = "keys/EXPECTED_FINGERPRINT is present but keys/public.pem is missing — this is a corrupted checkout of a project with a committed signing identity, not a fresh contributor checkout. Generating a keypair would produce a public key whose fingerprint cannot match the pin, so verify would refuse forever. Restore keys/public.pem from version control instead (git checkout -- keys/public.pem).";
      process.stderr.write("[doctor --fix] refused: keys/EXPECTED_FINGERPRINT present without keys/public.pem. Restore the committed public key (git checkout -- keys/public.pem) rather than generating a new identity.\n");
    } else {
      process.stderr.write("[doctor --fix] generating Ed25519 keypair...\n");
      const r = require("child_process").spawnSync(process.execPath, [path.join(PKG_ROOT, "lib", "sign.js"), "generate-keypair"], {
        stdio: ["ignore", "pipe", "pipe"], cwd: PKG_ROOT,
      });
      if (r.status === 0) {
        // Chain sign-all so the manifest + skills carry signatures paired
        // with the new keypair. Without this every shipped signature is
        // invalid against the new public key.
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

  // Second --fix path: private key IS present but the signatures check
  // FAILED. This is the post-rotation case (codex P2 v0.12.41): operator
  // ran `node $(exceptd path)/lib/sign.js generate-keypair --rotate`,
  // got a fresh keypair, but the manifest + skills still carry signatures
  // from the OLD keypair. Pre-fix doctor --fix's signing path only fired
  // when the private key was missing, so the rotation flow's remediation
  // step was a no-op. Chain sign-all here so the post-rotate doctor --fix
  // converges to a fully-verified state.
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

  // After a --fix that re-signed skills (keypair generation OR re-sign), the
  // captured `checks.signatures` is STALE — it was the verify.js result taken
  // before any key existed. Re-verify now and recompute the buckets, so a
  // successful --fix reports success (and exits 0) instead of carrying the
  // pre-fix "signatures FAILED" through to failed_checks + a non-zero exit.
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

  // Audit 3 B.3: --fix was passed but nothing to fix. Pre-fix this was
  // silently a no-op — operators couldn't distinguish "we tried and were
  // already healthy" from "we tried and failed silently." Now surfaces a
  // structured fix_status so callers reading the envelope can branch on
  // it.
  // The ai-config branch tracks its remediations on checks.ai_config
  // (fix_applied / fix_failed are nested there, not on out.summary), so
  // include that signal when deciding whether ANY fix actually ran.
  // Without this, doctor --ai-config --fix applying chmod/icacls would
  // simultaneously report checks.ai_config.fix_applied > 0 AND
  // summary.fix_status: "already_present", which is contradictory.
  const aiConfigFixed = !!(checks.ai_config && ((checks.ai_config.fix_applied || 0) > 0 || (checks.ai_config.fix_failed || 0) > 0));
  if (args.fix && !out.summary.fix_applied && !out.summary.fix_attempted && !out.summary.fix_partial && !out.summary.fix_decline_reason && !aiConfigFixed) {
    out.summary.fix_status = "already_present";
    out.summary.fix_skipped_reason = "Signing key + skill signatures are already valid; nothing to remediate.";
  }

  if (wantJson) {
    emit(out, indent);
    // Exit-code predicate must match the human path (gates on errorList only):
    // warnings alone do NOT force exit 1. The body still carries all_green,
    // warnings_count, and warning_checks for consumers that want the full
    // picture; only the exit code stops conflating a warn-only nudge (missing
    // private key on a consumer install, registry-behind) with a hard error.
    // A genuine signature-verification failure sets ok:false WITHOUT
    // severity:"warn", so bucketChecks routes it to errorList and it still
    // forces exit 1 here.
    if (errorList.length > 0) process.exitCode = EXIT_CODES.GENERIC_FAILURE;
    return;
  }

  // Default: human checklist. v0.11.0 redesign #5.
  const lines = [];
  lines.push(`exceptd doctor${localVersion ? ` (v${localVersion})` : ""}`);
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
  mark(checks.cves, c => {
    if (!c.ok) return `CVE catalog FAILED (exit=${c.exit_code ?? "?"})`;
    const total = c.total ?? "?";
    // Audit 3 B.2: enumerate every prefix so the sum equals total.
    // Falls back to the legacy CVE + MAL display only if by_prefix isn't
    // present (older catalog read paths).
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
    return "npm registry: could not compare versions (registry unreachable, offline, or no published version yet). Run `npm view @blamejs/exceptd-skills version` to see the latest, then `npm install -g @blamejs/exceptd-skills@latest` if you are behind.";
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
    // Icon picks from the bucketing severity, not from .ok:
    //   severity: info  → [ok]   (consumer install, no key expected)
    //   severity: warn  → [!]    (contributor checkout, key would
    //                             enable signed attestations; nudge,
    //                             not failure)
    //   severity: error → [!!]   (genuine signing failure)
    // Pre-fix the renderer used [!!] for any !private_key_present
    // path, including consumer installs where the summary said "all
    // checks green" — the icon contradicted the summary.
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
    // Enumerate the policy-skipped playbooks in text mode so it carries
    // the same operator-actionable information as the JSON envelope.
    // Pre-fix the count was visible but the names appeared only in the
    // structured output, forcing operators to parse JSON to learn which
    // playbooks are policy-skipped.
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
  // v0.11.6 (#97): --fix already ran above the JSON early-return. Echo the
  // applied/attempted state here for human readers.
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
  // also track candidate roots that didn't exist
  // so operators can tell whether the directory was scanned-and-empty or
  // simply never created. Pre-fix the human output said "(no attestations
  // under )" with no path — operators couldn't see where the verb looked.
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
          // replay-<isoZ>.json records share the session dir with
          // attestation.json but are not separate sessions. Gate on the
          // parsed `kind` field rather than filename so a rename cannot
          // smuggle a replay record into the listing.
          if (j && j.kind === "replay") continue;
          // v0.12.14: normalized array-set filter (see top of fn).
          if (playbookFilter && !playbookFilter.has(j.playbook_id)) continue;
          if (args.since && (j.captured_at || "") < args.since) continue;
          // Populate the `signed` field by reading the .sig sidecar.
          // The sidecar payload either carries algorithm: "Ed25519"
          // + signature_base64 (true signature) or algorithm: "unsigned"
          // (unsigned-fallback marker — written when no private key
          // was available at run time). Both forms ARE a .sig file on
          // disk; the field distinguishes them so operators can scan
          // the list for unsigned attestations without verifying every
          // one individually.
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
  // --limit caps the inventory (newest first). Without it, JSON returns every
  // session and the human table shows the first 50 with an "… and N more"
  // footer. With it, both surfaces honor the cap and report `total`.
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
    // every candidate root + whether it existed,
    // so JSON consumers can distinguish scanned-and-empty from never-created.
    // The human renderer below also surfaces this rather than printing
    // "(no attestations under )" with an empty path list.
    roots_evaluated: rootsEvaluated,
  }, pretty, (obj) => {
    // v0.11.6 (#95) human renderer for attest list: one row per session.
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
    // When --limit was given, obj.attestations is already capped; show all of
    // it. Otherwise show the first 50 and footer the remainder.
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
  // An explicit empty value (`--evidence ""`) is operator error, same as `run`.
  // The `--no-stream` path tests `args.evidence` for truthiness, so `""` fell
  // through to the stdin branch and — with empty/closed stdin — ran an empty
  // submission to ok:true at exit 0, masking that the intended evidence never
  // loaded. Reject it here so both stream and no-stream entry behave like `run`.
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

  // ----- single-shot path -----
  if (args["no-stream"]) {
    // Read any pre-supplied evidence from stdin OR from --evidence flag.
    let payload = { observations: {}, verdict: {} };
    if (args.evidence) {
      // Apply the same shape guard `run` enforces at its read boundary: a
      // submission must be a JSON object. Without this, `--no-stream` accepted
      // `null` / `[]` / a scalar and ran as if empty, so an operator believed a
      // malformed submission was evaluated (the streaming path is unaffected —
      // it only fires on a well-formed evidence event).
      try { payload = asEvidenceObject(readEvidence(args.evidence)); }
      catch (e) { return emitError(`ai-run: failed to read --evidence: ${e.message}`, null, pretty); }
    } else if (hasReadableStdin()) {
      // hasReadableStdin() probes via fstat before falling into
      // readFileSync(0). Wrapped-stdin test harnesses (isTTY===undefined,
      // size===0) would otherwise hang here.
      // Drain stdin for any evidence event.
      let buf = "";
      try { buf = fs.readFileSync(0, "utf8"); }
      catch { /* stdin empty / unreadable — fall through with empty payload */ }
      if (buf.trim()) {
        // First treat stdin as a single JSON document — the common
        // `echo '<json>' | ai-run … --no-stream` shape. If it parses as one
        // value we can apply the same shape guard `--evidence` gets: a bare
        // `null` / `[]` / scalar is a malformed submission, not "no evidence",
        // and must be rejected rather than silently run as empty.
        let single;
        let singleParsed = false;
        try { single = JSON.parse(buf); singleParsed = true; } catch { /* not a single doc — fall to JSONL scan */ }
        if (singleParsed) {
          // An evidence event wrapper is the one object shape that is NOT
          // itself the submission — unwrap it before guarding.
          if (single && typeof single === "object" && !Array.isArray(single) && single.event === "evidence" && single.payload) {
            payload = single.payload;
          } else {
            try { payload = asEvidenceObject(single); }
            catch (e) { return emitError(`ai-run: failed to read evidence from stdin: ${e.message}`, null, pretty); }
            // Normalize a bare submission into the {observations, verdict} shape.
            if (!payload.observations && (payload.artifacts || payload.signal_overrides || payload.signals)) {
              payload = { observations: { ...(payload.artifacts || {}), ...(payload.signal_overrides || {}) }, verdict: payload.signals || {} };
            }
          }
        } else {
          // JSONL / interleaved host-AI chatter: scan line-by-line for the
          // first evidence event or bare submission, ignoring non-matching
          // status frames the host may interleave.
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
      // Route through emit() so the body lands on stdout (per v0.12.39
      // envelope contracts) and exitCode is set by the shared ok:false
      // fallback. Pre-fix the body went to stderr, which split it from
      // the success path and made consumers parse two streams.
      emit(result || { ok: false, error: 'ai-run returned empty result' }, pretty);
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
      return finish(EXIT_CODES.GENERIC_FAILURE);
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
    return finish(EXIT_CODES.SUCCESS);
  };

  // Handle empty/closed stdin: emit a hint then exit cleanly so AI agents
  // calling ai-run without piping anything see a useful message rather than
  // a hung process.
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
      process.exitCode = EXIT_CODES.GENERIC_FAILURE;
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
// `recipes` — list the curated multi-skill workflows, or show one in full.
// The recipes are use-case curated (when_to_use → ordered skill_chain); they
// had no CLI surface before, so an operator could only reach them by reading
// data/_indexes/recipes.json. `recipes` lists them; `recipes <id>` expands one.
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

function cmdAsk(runner, args, runOpts, pretty) {
  const question = (args._ || []).join(" ").trim();
  if (!question) {
    return emitError("ask: usage: exceptd ask \"<plain-English question>\"", null, pretty);
  }
  // ask routes to playbooks, but a question naming a specific CVE / RFC ("is
  // CVE-… real", "what is RFC 9404") is answered directly by the resolver
  // verbs — point at them on stderr so the operator gets the right tool.
  const cveTok = question.match(/\bCVE-\d{4}-\d{3,}\b/i);
  const rfcTok = question.match(/\bRFC[-\s]?(\d{1,6})\b/i);
  if (cveTok) process.stderr.write(`[exceptd] tip: to validate that identifier directly, run \`exceptd cve ${cveTok[0].toUpperCase()}\`.\n`);
  if (rfcTok) process.stderr.write(`[exceptd] tip: to resolve that RFC directly, run \`exceptd rfc ${rfcTok[1]}\`.\n`);
  const ids = runner.listPlaybooks();
  const q = question.toLowerCase();

  // Synonym expansion — common operator phrasings → playbook-relevant tokens.
  // Keeps cmdAsk dependency-free; rich enough to cover the 80% of natural
  // queries listed in the operator report.
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
    // Audit 3 C.2: missing identity / phishing / SSO / BEC vocabulary.
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
    // Famous-attack vocabulary maps to library-author / sbom / supply-chain.
    "left-pad": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "left pad": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "event-stream": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "shai-hulud": ["library-author", "sbom", "supply-chain-recovery", "npm"],
    "ransomware": ["ransomware", "kernel", "runtime"],
    "rogue": ["ai-c2", "llm-tool-use-exfil"],
    "agentic": ["ai-c2", "llm-tool-use-exfil", "mcp"],
    // Credential theft from a developer laptop is cred-stores territory.
    "credential theft": ["cred-stores", "secrets"],
    "cred theft": ["cred-stores", "secrets"],
    "credential exfil": ["cred-stores", "llm-tool-use-exfil"],
    "developer laptop": ["cred-stores", "hardening"],
    // CI/CD + OIDC vocabulary → the dedicated cicd-pipeline-compromise playbook
    // (the supply-chain playbooks otherwise out-rank it on shared tokens).
    "oidc": ["cicd-pipeline-compromise", "ci", "pipeline", "runner", "signing"],
    "cicd": ["cicd-pipeline-compromise", "ci", "pipeline"],
    "ci/cd": ["cicd-pipeline-compromise", "pipeline"],
    "runner": ["cicd-pipeline-compromise", "ci"],
    "pipeline": ["cicd-pipeline-compromise"],
    // C2-over-AI-API → the dedicated ai-api playbook (llm-tool-use-exfil
    // otherwise wins on a long C2 sentence).
    "c2": ["ai-api", "ai-c2"],
    "command and control": ["ai-api", "ai-c2"],
    "command-and-control": ["ai-api", "ai-c2"],
  };

  // Audit 3 C.1: stopwords filtered after synonym expansion so common
  // English words don't drive false positives via raw substring matching.
  // "the the the the" used to route to ai-api because "the" substring-hit
  // "anthropic" in the haystack.
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
    // 2-char English fillers (the length>=2 token filter otherwise lets these
    // substring-hit a haystack — "do" matched ai-api). Deliberately excludes
    // security-meaningful 2-char tokens (ai, ml, ci, c2, k8s).
    "do", "is", "my", "it", "me", "to", "of", "on", "or", "an", "as", "at",
    "be", "by", "we", "up", "so", "no", "if", "in",
  ]);

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
  // Filter stopwords AFTER synonym expansion (synonym lookup may have
  // pulled in canonical tokens via a stopword-adjacent multi-word phrase).
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
    // Audit 3 C.1: tokenize the haystack and use Set membership instead
    // of raw substring matching. The substring approach matched "the" in
    // "authentication" and "got" inside larger words, allowing stopword
    // and partial-word false positives. Tokenized membership matches
    // whole tokens only.
    const haystackTokens = new Set(haystackText.split(/\W+/).filter(t => t.length >= 2));
    let score = 0;
    for (const t of tokens) if (haystackTokens.has(t)) score++;
    // ID match counts double — "secrets" should map to the secrets playbook.
    if (tokens.some(t => (pb._meta?.id || id) === t)) score += 3;
    scored.push({ id: pb._meta?.id || id, score });
  }
  // Audit 3 C.6: when scores tie, fall back to a deterministic but more
  // useful order than alphabetical playbook-id (which made the first-5
  // playbooks dominate every vague query). Secondary sort favors
  // playbooks whose id is referenced directly in the question (e.g.
  // "secrets" matching playbook id "secrets" outranks an alphabetical
  // accident). Tertiary is the original stable order.
  scored.forEach((s, i) => { s._origIdx = i; });
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const aIdMatch = tokens.includes(a.id) ? 1 : 0;
    const bIdMatch = tokens.includes(b.id) ? 1 : 0;
    if (aIdMatch !== bIdMatch) return bIdMatch - aIdMatch;
    return a._origIdx - b._origIdx;
  });
  const top = scored.filter(s => s.score > 0).slice(0, 5);

  // v0.11.2: default human-readable; --json for machine.
  if (top.length === 0) {
    const result = {
      verb: "ask",
      question,
      routed_to: [],
      hint: "No playbook matched. Try `exceptd brief --all` to see what's available, or `exceptd discover` to detect what's in your cwd.",
    };
    // Honor --pretty as an implicit opt-in to structured output, matching
    // the discover/doctor convention. Pre-fix `ask "..." --pretty` fell
    // into the human-text branch and silently ignored the flag.
    if (args.json || args.pretty) return emit(result, pretty);
    process.stdout.write(`ask: ${question}\n  no playbook matched.\n  try: exceptd discover  (auto-detect what's in your cwd)\n`);
    return;
  }

  // Enrich each match with whether a companion collector exists for
  // the playbook (same lookup discover uses). Operators see at a
  // glance which alternates have a collect|run pipe path vs. which
  // require AI-driven evidence.
  const collectorsDir = path.join(PKG_ROOT, "lib", "collectors");
  for (const t of top) {
    const collectorPath = path.join(collectorsDir, t.id + ".js");
    t.collector_available = fs.existsSync(collectorPath);
  }

  // Audit 3 C.7: penalize confidence by the tie spread at the top so a
  // 5-way tie at score 3 doesn't claim the same confidence as a single
  // clear winner at score 3. tieCount counts how many playbooks share
  // the top score (1 = clean winner; >1 = tie). Confidence divided
  // accordingly: a 5-way tie reports ~0.2x the base, a clean winner
  // reports the full base.
  const topScore = top[0].score;
  const tieCount = scored.filter(s => s.score === topScore).length;
  const baseConfidence = Math.min(1, topScore / Math.max(2, tokens.length));
  const tiePenalty = tieCount > 1 ? 1 / tieCount : 1;
  const confidence = Math.round(baseConfidence * tiePenalty * 100) / 100;
  // Some domains are covered by a SKILL, not a playbook — the router would
  // otherwise present a confident-looking wrong playbook (e.g. "DMARC" →
  // llm-tool-use-exfil, "HIPAA" → ransomware). Detect those by distinctive
  // keyword and surface the right skill so the operator is pointed at real
  // coverage instead of a mis-route. Keyed on terms with no playbook home.
  const SKILL_ONLY_DOMAINS = [
    { skill: "email-security-anti-phishing", re: /\b(dmarc|dkim|\bspf\b|bimi|mta-sts|email spoof|email security|sender auth|business email compromise)\b/i },
    { skill: "age-gates-child-safety", re: /\b(age[\s-]?gate|age verification|coppa|child safety|children'?s code|\bkosa\b|\baadc\b|minor protection)\b/i },
    { skill: "sector-healthcare", re: /\b(hipaa|\bphi\b|hitrust|healthcare security|45 cfr)\b/i },
    { skill: "dlp-gap-analysis", re: /\b(data loss prevention|\bdlp\b)\b/i },
  ];
  const skillDomain = SKILL_ONLY_DOMAINS.find(d => d.re.test(question));
  const confidence0 = confidence;
  // A weak top match also signals a likely no-playbook domain.
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
  // A value-less `--max-rwep` parses as boolean true and would coerce to
  // Number(true) === 1 — a finite, non-negative cap that slips past the
  // numeric guard below and silently sets an extraordinarily strict gate.
  // Treat the forgotten value as a usage error, same as a non-numeric one.
  if (args["max-rwep"] === true) {
    return emitError(
      "ci: --max-rwep requires a non-negative number.",
      { verb: "ci", flag: "max-rwep" },
      pretty,
    );
  }
  const maxRwep = args["max-rwep"] !== undefined ? Number(args["max-rwep"]) : null;
  // Reject a non-numeric / negative cap rather than silently coercing it.
  // `--max-rwep abc` previously became Number→NaN→0, degenerating the gate to
  // "block everything at RWEP 0" with no error — a silently-broken CI gate.
  if (maxRwep !== null && (!Number.isFinite(maxRwep) || maxRwep < 0)) {
    return emitError(
      `ci: --max-rwep must be a non-negative number; got ${JSON.stringify(String(args["max-rwep"]))}.`,
      { verb: "ci", provided: args["max-rwep"] },
      pretty,
    );
  }
  // An explicit empty value (`--evidence ""` / `--evidence=` / an unset shell
  // variable) is falsy, so the truthiness-gated evidence reads below skip
  // entirely, the bundle stays {}, every playbook runs with no evidence, and
  // the gate reports a clean PASS at exit 0 — a false-green that hides the fact
  // the operator's intended evidence never loaded. Mirror the run/collect/
  // discover empty-value guards: refuse the empty value loudly rather than
  // running a vacuous gate.
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

  // v0.11.9 (#115): --required <playbook,playbook,...> takes precedence over
  // --scope and --all. Operators specifying an explicit set get exactly that
  // set, no more, no less. Pre-0.11.9 the flag was silently ignored.
  let ids;
  // positional args (`exceptd ci kernel cred-stores`)
  // were silently ignored and the cwd-autodetect path ran instead. Operators
  // got a green PASS for playbooks that were never actually executed. Treat
  // positional args as an inline --required, with the same unknown-id refusal.
  // Bare `exceptd ci` (no positional, no flags) still falls through to scope
  // autodetect for backward compatibility.
  //
  // codex P1 (v0.12.31 follow-up): explicitly refuse `positional + --scope/--all/
  // --required` as ambiguous. Pre-fix the guard `!args.all && !args.scope`
  // would silently ignore the positional when a scope flag was also passed
  // (`exceptd ci kernel --scope code` ran code-scope, dropping `kernel`).
  // Combining selectors is operator error; surface it loudly.
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
    // Gate on PRESENCE, not truthiness: an empty `--required ""` is falsy and
    // previously fell through to the cwd auto-detect branch, emitting a green
    // PASS for an unrequested, auto-detected playbook set — a false green.
    // Refuse `--required + --all` / `--required + --scope` as ambiguous
    // (matches the positional-args refusal at top of cmdCi).
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
    // filterPlaybooksByScope (which rejects it with the accepted-set message),
    // not silently fall through to the cwd auto-detect branch below.
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    try { ids = filterPlaybooksByScope(runner, scope, { includeJudgementShaped }); }
    catch (e) { return emitError(`ci: ${e.message}`, { provided_scope: scope }, pretty); }
    // Always include cross-cutting playbooks regardless of scope choice.
    const cross = filterPlaybooksByScope(runner, "cross-cutting", { includeJudgementShaped });
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
    const includeJudgementShaped = args["include-judgement-shaped"] === true;
    const scopes = detectScopes();
    ids = scopes.flatMap(s => filterPlaybooksByScope(runner, s, { includeJudgementShaped }));
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
    // Hardened read (symlink / junction / O_NOFOLLOW / realpath-containment /
    // playbook-id gate) lives in the shared readEvidenceDir() helper so `ci`
    // and `run` apply identical defenses. Previously `ci` read entries with a
    // bare fs.readFileSync, so a `<pb>.json` symlink/junction inside the dir
    // bypassed every containment check `run` applies.
    const er = readEvidenceDir(dir, "ci");
    if (!er.ok) return emitError(er.error, er.extra, pretty);
    Object.assign(bundle, er.bundle);
  }

  // Flat-submission tolerance for a single positional playbook. `ci` keys its
  // bundle by playbook id (so --evidence-dir / multi-playbook bundles work),
  // but `ci <pb> --evidence -` with the SAME flat/nested submission shape that
  // `run` accepts would otherwise land as bundle[<pb>]=undefined → empty run →
  // a false PASS that silently ignores the operator's evidence. When exactly
  // one playbook is in scope and the bundle carries no playbook-id key (it's a
  // single submission, not a multi-playbook bundle), treat it as that
  // playbook's evidence.
  if (ids.length === 1 && Object.keys(bundle).length > 0 && !(ids[0] in bundle)) {
    const allIds = new Set(runner.listPlaybooks());
    const looksLikeBundle = Object.keys(bundle).some(k => allIds.has(k));
    if (!looksLikeBundle) bundle = { [ids[0]]: bundle };
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
    // defense-in-depth — validate id even though the catalog-iter
    // upstream is trusted. A corrupt catalog returning a malformed id would
    // otherwise reach loadPlaybook unchecked. Matches the cmdRunMulti pattern.
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
          // The explanatory text lives in `actual_gap`; the rollup previously
          // read a nonexistent `why_insufficient` key and so was always null.
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

  // Each `run()` call independently surfaces session-level runtime
  // conditions (e.g. bundle_publisher_unclaimed) into its own
  // phases.analyze.runtime_errors. On a ci run spanning N playbooks
  // the same warning would otherwise appear N times. Dedupe across
  // results by (kind, reason) so session-level conditions surface
  // once at the summary level, not once per playbook.
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

  // Document why each playbook was selected. --scope <s> always adds
  // cross-cutting; --scope code on a repo with a lockfile also adds
  // sbom. The selection rule is otherwise buried in code; surface it
  // in the summary so operators reading the output can see what was
  // scoped vs. auto-included.
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
    // Aggregate the per-run bundles_by_format if present. ci spans N playbooks,
    // so there is no single conformant CSAF/SARIF/OpenVEX document — emit a JSON
    // ARRAY of the pure documents. Critically, do NOT wrap them in an exceptd
    // envelope carrying a top-level `ok` key: that key is invalid in all three
    // standard formats, so a downstream CSAF/SARIF/OpenVEX consumer pointed at
    // `ci --format` output got a non-conformant top-level shape. Each array
    // element is now a verbatim, conformant document.
    const bundles = results.map(r => r.phases?.close?.evidence_package?.bundles_by_format?.[fmt === "csaf" ? "csaf-2.0" : fmt]).filter(Boolean);
    process.stdout.write(JSON.stringify(bundles, null, pretty ? 2 : 0) + "\n");
  } else if (fmt && fmt !== "json") {
    // v0.11.4 (#76): garbage format rejected with structured error, not silent empty stdout.
    // Route through emitError so the body propagates exit codes via the
    // emit() ok:false contract. ci-format-typo is operator-decision class
    // (GENERIC_FAILURE), not DETECTED_ESCALATE.
    // v0.13.2: did-you-mean on the unknown format value (Levenshtein ≤ 2).
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
    // Human renderer for `ci` default output. Shape (one screen for a
    // typical 9-playbook scope):
    //   - verdict line (PASS / FAIL / BLOCKED / CLOCK_STARTED / NO_EVIDENCE + counts)
    //   - per-playbook table (id | verdict | rwep | evidence | top_finding)
    //   - session-level runtime warnings (deduped by kind+reason)
    //   - scope inclusion rules when --scope was used
    //   - jurisdiction-clock + framework-gap rollup
    //   - fail reasons + per-verdict next-step block
    //   - footer pointing at --json / --format for the structured body
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

      // Per-playbook table.
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

      // Session-level deduped runtime warnings (B5).
      if (s.runtime_warnings && s.runtime_warnings.length) {
        lines.push(`\nSession warnings (${s.runtime_warnings_count}):`);
        for (const w of s.runtime_warnings) {
          const reason = (w.reason || "").length > 200 ? (w.reason || "").slice(0, 197) + "..." : (w.reason || "");
          lines.push(`  [${w.kind || "warning"}] ${reason}`);
          if (w.remediation) lines.push(`    → ${w.remediation}`);
        }
      }

      // Scope inclusion (B8 transparency).
      if (s.scope_inclusion_rules && s.scope_inclusion_rules.length) {
        lines.push(`\nScope selection (${s.scope_request}):`);
        for (const rule of s.scope_inclusion_rules) lines.push(`  - ${rule}`);
      }

      // Jurisdiction clocks.
      if (s.jurisdiction_clocks_started > 0) {
        lines.push(`\nJurisdiction clocks started: ${s.jurisdiction_clocks_started}`);
        const clocks = s.jurisdiction_clock_rollup || [];
        for (const n of clocks.slice(0, 5)) {
          lines.push(`  ${n.jurisdiction || "?"}/${n.regulation || "?"} → deadline ${n.deadline || "?"}`);
        }
        if (clocks.length > 5) lines.push(`  … ${clocks.length - 5} more (--json for all)`);
      }

      // Framework gap rollup.
      if (s.framework_gap_count > 0) {
        lines.push(`\nFramework gaps (${s.framework_gap_count}):`);
        const fgaps = s.framework_gap_rollup || [];
        for (const g of fgaps.slice(0, 5)) {
          lines.push(`  ${g.framework || "?"} :: ${g.claimed_control || "?"}  (${g.playbooks.length} playbook(s))`);
        }
        if (fgaps.length > 5) lines.push(`  … ${fgaps.length - 5} more (--json for all)`);
      }

      // Fail reasons.
      if (s.fail_reasons && s.fail_reasons.length) {
        lines.push(`\nFail reasons:`);
        for (const r of s.fail_reasons) lines.push(`  - ${r}`);
      }

      // Next-step guidance, keyed on verdict. An operator reading ci
      // output should never have to ask "what do I do now?" — the
      // verdict dictates the next move:
      //   BLOCKED        → operator must supply evidence asserting the
      //                    halted preconditions; `exceptd lint <pb> -`
      //                    emits the exact JSON paths to fill in.
      //   NO_EVIDENCE    → no --evidence was supplied and every playbook
      //                    returned inconclusive; same lint -> run loop.
      //   FAIL/detected  → look at the matched_cves + recommended
      //                    remediation in the per-playbook results.
      //   CLOCK_STARTED  → notification clock running; see deadline above.
      //   PASS           → nothing to do.
      const blockedRows = (obj.results || []).filter(r => r && r.ok === false);
      // Pad the playbook id to a common width so the trailing `#` comments line
      // up across variable-length ids instead of using a fixed space run.
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
        // FAIL fires in two distinct shapes:
        //   (a) at least one playbook classification=detected → s.detected > 0
        //   (b) inconclusive playbook(s) whose rwep_delta (operator
        //       evidence) crossed the cap → s.detected stays at 0
        // Both shapes need actionable Next-step guidance; key on the
        // shape, not on `s.detected > 0` alone.
        if (s.detected > 0) {
          // Name the specific detected playbook ids so the operator
          // can copy-paste rather than substitute `<playbook>`. When
          // multiple playbooks land detected, emit one row per id
          // for each format so operators don't miss follow-up for the
          // playbooks beyond detectedIds[0].
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

          // Surface pending jurisdiction obligations across all
          // detected playbooks at the ci summary level — operators
          // running ci to gate a PR / a release deserve the same
          // regulatory-clock visibility a single `run` would give them.
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
          // Operator evidence pushed RWEP across --max-rwep cap on an
          // otherwise-inconclusive run. The fix is to review which
          // signals moved the score and decide whether they warrant
          // escalation or whether the cap is set too low for the
          // current evidence quality.
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
