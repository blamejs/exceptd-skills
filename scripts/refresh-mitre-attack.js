#!/usr/bin/env node
"use strict";
/**
 * Refreshes only the MITRE ATT&CK catalog. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAttack.
 */
const { refreshAttack, capFromEnv, CAP_ERROR } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = capFromEnv(process.env.CAP);
if (cap === null) {
  console.error(`[err] ${CAP_ERROR} Got: ${JSON.stringify(process.env.CAP)}`);
  process.exitCode = 2;
} else {
  refreshAttack({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
}
