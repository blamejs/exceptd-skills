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
};

const ORCHESTRATOR_PASSTHROUGH = new Set([
  "scan", "dispatch", "skill", "currency", "report",
  "validate-cves", "validate-rfcs", "watchlist",
  "framework-gap", "framework-gap-analysis",
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

if (require.main === module) main();

module.exports = { COMMANDS, PKG_ROOT };
