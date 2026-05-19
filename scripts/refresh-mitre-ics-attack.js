#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-mitre-ics-attack.js
 *
 * Thin per-type wrapper for the MITRE ICS-attack STIX refresher. Logic
 * lives in scripts/refresh-upstream-catalogs.js#refreshIcsAttack.
 *
 *   node scripts/refresh-mitre-ics-attack.js [--dry-run]
 *
 * Wired as `npm run refresh-mitre-ics-attack`.
 */
const { refreshIcsAttack } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshIcsAttack({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
