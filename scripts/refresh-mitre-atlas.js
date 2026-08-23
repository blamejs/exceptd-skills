#!/usr/bin/env node
"use strict";
/**
 * Thin per-type wrapper for the MITRE ATLAS refresher; the logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshAtlas. Wired as
 * `npm run refresh-mitre-atlas`, and takes --dry-run.
 */
const { refreshAtlas } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshAtlas({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
