#!/usr/bin/env node
"use strict";
/**
 * `npm run refresh-mitre-ics-attack [-- --dry-run]` — per-type wrapper for the
 * MITRE ICS-attack STIX refresher; the logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshIcsAttack.
 */
const { refreshIcsAttack } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshIcsAttack({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
