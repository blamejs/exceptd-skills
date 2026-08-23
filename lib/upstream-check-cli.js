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

function parseArgs(argv) {
  const out = { timeoutMs: 5000, raw: false, airGap: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") { out.timeoutMs = parseInt(argv[++i], 10) || 5000; }
    else if (a.startsWith("--timeout=")) { out.timeoutMs = parseInt(a.slice("--timeout=".length), 10) || 5000; }
    else if (a === "--raw") out.raw = true;
    else if (a === "--air-gap") out.airGap = true;
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
