#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-rfc-index.js
 *
 * Thin per-type wrapper for the RFC refresher. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshRfc. Use this entry when
 * you want to refresh only the RFC catalog without touching ATT&CK /
 * ATLAS / D3FEND.
 *
 *   node scripts/refresh-rfc-index.js [--dry-run]
 *
 * Wired as `npm run refresh-rfc-index`.
 */
const { refreshRfc } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
refreshRfc({ dry }).catch((e) => { console.error("[err]", e); process.exit(1); });
