#!/usr/bin/env node
"use strict";
/**
 * Thin wrapper for the MITRE D3FEND refresher; the logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshD3fend. Wired as
 * `npm run refresh-mitre-d3fend`.
 */
const { refreshD3fend, capFromEnv, CAP_ERROR } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = capFromEnv(process.env.CAP);
if (cap === null) {
  console.error(`[err] ${CAP_ERROR} Got: ${JSON.stringify(process.env.CAP)}`);
  process.exitCode = 2;
} else {
  refreshD3fend({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
}
