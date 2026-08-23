#!/usr/bin/env node
"use strict";
/**
 * Refreshes only the MITRE ATT&CK catalog. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAttack.
 */
const { refreshAttack } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = Number(process.env.CAP || Infinity);
refreshAttack({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
