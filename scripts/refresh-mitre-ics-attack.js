#!/usr/bin/env node
"use strict";
/**
 * `npm run refresh-mitre-ics-attack [-- --dry-run]` — per-type wrapper for the
 * MITRE ICS-attack STIX refresher; the logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshIcsAttack.
 *
 * `CAP=<n>` bounds how many NEW techniques one run may add, matching every
 * other per-type wrapper. Context backfill onto existing rows is never capped.
 */
const { refreshIcsAttack, capFromEnv, CAP_ERROR } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = capFromEnv(process.env.CAP);
if (cap === null) {
  console.error(`[err] ${CAP_ERROR} Got: ${JSON.stringify(process.env.CAP)}`);
  process.exitCode = 2;
} else {
  refreshIcsAttack({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
}
