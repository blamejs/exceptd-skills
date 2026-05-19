#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-mitre-attack.js
 *
 * Thin per-type wrapper for the MITRE ATT&CK refresher. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAttack.
 *
 *   node scripts/refresh-mitre-attack.js [--dry-run]
 *   CAP=200 node scripts/refresh-mitre-attack.js
 *
 * Wired as `npm run refresh-mitre-attack`.
 */
const { refreshAttack } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = Number(process.env.CAP || Infinity);
refreshAttack({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
