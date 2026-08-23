#!/usr/bin/env node
"use strict";
/**
 * Refreshes only the RFC catalog, leaving ATT&CK / ATLAS / D3FEND untouched.
 * Logic lives in scripts/refresh-upstream-catalogs.js#refreshRfc.
 */
const { refreshRfc } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshRfc({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
