#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-mitre-atlas.js
 *
 * Thin per-type wrapper for the MITRE ATLAS refresher. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAtlas.
 *
 *   node scripts/refresh-mitre-atlas.js [--dry-run]
 *
 * Wired as `npm run refresh-mitre-atlas`.
 */
const { refreshAtlas } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshAtlas({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
