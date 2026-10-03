#!/usr/bin/env node
"use strict";
/**
 * Thin per-type wrapper for the MITRE ATLAS refresher; the logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAtlas. Wired as
 * `npm run refresh-mitre-atlas`, and takes --dry-run.
 *
 * `CAP=<n>` bounds how many NEW techniques one run may add, matching every
 * other per-type wrapper. Context backfill onto existing rows is never capped.
 */
const { refreshAtlas, capFromEnv, CAP_ERROR } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = capFromEnv(process.env.CAP);
if (cap === null) {
  console.error(`[err] ${CAP_ERROR} Got: ${JSON.stringify(process.env.CAP)}`);
  process.exitCode = 2;
} else {
  refreshAtlas({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
}
