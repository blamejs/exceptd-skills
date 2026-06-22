"use strict";


// ---- routed from catalog-data-integrity ----
require("node:test").describe("catalog-data-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a catalog data-integrity / curation pass:
 *
 *   - The AI supply-chain families (ShadowMQ, Triton auth-bypass) carry ATLAS
 *     mappings — they were unmapped while sibling family entries carried
 *     AML.T0049 (Hard Rule #7 coherence).
 *   - The active_exploitation "theoretical" status is an explicit entry in the
 *     RWEP scoring ladder (not an incidental `?? 0` fall-through).
 *   - The jurisdiction count is consistent across the stale-content and
 *     catalog-summaries builders and the README badge (all count GLOBAL → 35).
 *   - framework-control-gaps _meta.entry_count matches the actual entry count
 *     (a gate now enforces this).
 *   - Shipped playbook threat_currency_score stays within the documented band.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const cve = require(path.join(ROOT, "data", "cve-catalog.json"));
const atlas = require(path.join(ROOT, "data", "atlas-ttps.json"));
const gaps = require(path.join(ROOT, "data", "framework-control-gaps.json"));
const gf = require(path.join(ROOT, "data", "global-frameworks.json"));
const scoring = require(path.join(ROOT, "lib", "scoring.js"));

test("framework-control-gaps _meta.entry_count matches the actual entry count", () => {
  const actual = Object.keys(gaps).filter((k) => !k.startsWith("_")).length;
  assert.equal(gaps._meta.entry_count, actual,
    `_meta.entry_count (${gaps._meta.entry_count}) must equal the actual count (${actual})`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
