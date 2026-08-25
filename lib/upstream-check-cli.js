#!/usr/bin/env node
"use strict";

/**
 * Emits lib/upstream-check's freshness report as one JSON line on stdout.
 * Spawned as a child process so the calling verb stays synchronous and the
 * network timeout is bounded by the spawnSync timeout. Exits 0 even when the
 * registry is unreachable: callers parse the envelope off stdout, and absent
 * freshness data is a degraded signal rather than an error.
 */

const path = require("path");
const fs = require("fs");
const { safeExit } = require("./exit-codes");

const ROOT = path.resolve(__dirname, "..");
const { fetchLatestPublished, buildFreshnessReport } = require("./upstream-check.js");

// --flag base names this CLI accepts; drives the unknown-flag error message.
const KNOWN_FLAGS = Object.freeze(["--timeout", "--raw", "--air-gap"]);

function parseArgs(argv) {
  const out = { timeoutMs: 5000, raw: false, airGap: false, unknownFlags: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") { out.timeoutMs = parseInt(argv[++i], 10) || 5000; }
    else if (a.startsWith("--timeout=")) { out.timeoutMs = parseInt(a.slice("--timeout=".length), 10) || 5000; }
    else if (a === "--raw") out.raw = true;
    else if (a === "--air-gap") out.airGap = true;
    // Any remaining --flag is a typo; refused below, before any network work.
    // Only `--`-prefixed tokens are collected, matching lib/prefetch.js: a
    // single-dash `-air-gap` or an en-dashed `–air-gap` is not recognized here
    // and still reaches the registry probe.
    else if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      out.unknownFlags.push(eq === -1 ? a : a.slice(0, eq));
    }
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
  // Usage errors exit 2 on stderr, keeping stdout reserved for the one report
  // line callers parse. Checked before the air-gap branch and the probe.
  if (opts.unknownFlags.length > 0) {
    const uniq = [...new Set(opts.unknownFlags)];
    process.stderr.write(JSON.stringify({
      ok: false,
      source: "upstream-check",
      error: `upstream-check: unknown flag(s): ${uniq.join(", ")}`,
      unknown_flags: uniq,
      known_flags: KNOWN_FLAGS,
    }) + "\n");
    process.exitCode = 2;
    return;
  }
  // The registry probe is a network call, so air-gap mode answers with a
  // `skipped` envelope instead. `ok: null` is neither pass nor fail.
  if (process.env.EXCEPTD_AIR_GAP === "1" || opts.airGap) {
    process.stdout.write(JSON.stringify({
      ok: null,
      skipped: "air-gap",
      reason: "registry probe disabled in air-gap mode",
      source: "upstream-check",
    }) + "\n");
    safeExit(0);
    return;
  }
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
})().catch((err) => {
  // Any throw still yields one parseable JSON line and exit 0, per the
  // degradation contract above. String(...) coerces the error to a primitive so
  // this JSON.stringify cannot itself throw.
  process.stdout.write(JSON.stringify({
    ok: false,
    error: String((err && err.message) || err),
    source: "upstream-check",
  }) + "\n");
});
