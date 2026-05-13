#!/usr/bin/env node
"use strict";

/**
 * lib/upstream-check-cli.js
 *
 * Small wrapper that calls lib/upstream-check.fetchLatestPublished() and
 * emits the freshness report as JSON to stdout. Used internally by:
 *   - `exceptd doctor --registry-check`
 *   - `exceptd run --upstream-check`
 *   - `exceptd refresh --network`
 *
 * Runs in a child process so the parent verb stays synchronous and the
 * network timeout is bounded by the spawnSync timeout.
 *
 * Output: one JSON line to stdout. Exits 0 even when the registry is
 * unreachable (offline ≠ error — the freshness signal degrades gracefully).
 *
 * Flags:
 *   --timeout <ms>   override the default 5000 ms network timeout
 *   --raw            emit raw registry response instead of freshness report
 */

const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const { fetchLatestPublished, buildFreshnessReport } = require("./upstream-check.js");

function parseArgs(argv) {
  const out = { timeoutMs: 5000, raw: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") { out.timeoutMs = parseInt(argv[++i], 10) || 5000; }
    else if (a.startsWith("--timeout=")) { out.timeoutMs = parseInt(a.slice("--timeout=".length), 10) || 5000; }
    else if (a === "--raw") out.raw = true;
  }
  return out;
}

function readPkgVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).version;
  } catch { return "0.0.0"; }
}

function readManifest() {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  } catch { return null; }
}

(async () => {
  const opts = parseArgs(process.argv);
  const registry = await fetchLatestPublished({ timeoutMs: opts.timeoutMs });
  if (opts.raw) {
    process.stdout.write(JSON.stringify(registry) + "\n");
    return;
  }
  const report = buildFreshnessReport({
    localVersion: readPkgVersion(),
    registry,
    localManifest: readManifest(),
  });
  process.stdout.write(JSON.stringify(report) + "\n");
})();
