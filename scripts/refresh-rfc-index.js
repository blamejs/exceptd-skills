#!/usr/bin/env node
"use strict";
/**
 * Refreshes only the RFC catalog, leaving ATT&CK / ATLAS / D3FEND untouched.
 * Logic lives in scripts/refresh-upstream-catalogs.js#refreshRfc.
 *
 * `CAP=<n>` bounds how many NEW rows one run may add — the upstream RFC index
 * carries ~9000 entries, so an uncapped first run imports all of them at once.
 * Context backfill onto rows already curated is never capped.
 */
const { refreshRfc, capFromEnv, CAP_ERROR } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = capFromEnv(process.env.CAP);
if (cap === null) {
  console.error(`[err] ${CAP_ERROR} Got: ${JSON.stringify(process.env.CAP)}`);
  process.exitCode = 2;
} else {
  refreshRfc({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
}
