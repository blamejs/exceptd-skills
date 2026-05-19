#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-mitre-d3fend.js
 *
 * Thin per-type wrapper for the MITRE D3FEND refresher. Logic lives in
 * scripts/refresh-upstream-catalogs.js#refreshD3fend.
 *
 *   node scripts/refresh-mitre-d3fend.js [--dry-run]
 *   CAP=120 node scripts/refresh-mitre-d3fend.js
 *
 * Wired as `npm run refresh-mitre-d3fend`.
 */
const { refreshD3fend } = require("./refresh-upstream-catalogs.js");
const dry = process.argv.includes("--dry-run");
const cap = Number(process.env.CAP || Infinity);
refreshD3fend({ dry, cap }).catch((e) => { console.error("[err]", e); process.exit(1); });
