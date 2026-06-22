"use strict";


// ---- routed from builders-docs ----
require("node:test").describe("builders-docs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Coverage for the derived-index builders and the operator-facing report
 * surfaces they feed.
 *
 * - section-offsets: h3_count must skip "### " lines that live inside fenced
 *   code blocks, the same way the H2 section detector does. Output templates
 *   embedded in ```...``` are not real sub-sections.
 * - cwe-chains: the emitted chain must carry every dimension the module's
 *   own docstring promises, including dlp_refs.
 * - token-budget: the output shape must match the documented contract —
 *   corpus totals live under _meta, with no top-level by_recipe block.
 * - zero-day-response template: the blast-radius point range must match the
 *   live RWEP weight ceiling so a filled-in report does not undercount.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { buildSectionOffsets } = require(path.join(ROOT, 'scripts', 'builders', 'section-offsets.js'));
const { buildCweChains } = require(path.join(ROOT, 'scripts', 'builders', 'cwe-chains.js'));
const { buildTokenBudget } = require(path.join(ROOT, 'scripts', 'builders', 'token-budget.js'));

test('cwe-chains: emitted chain carries dlp_refs aggregated from referencing skills', () => {
  const skills = [
    {
      name: 'fixture-skill',
      cwe_refs: ['CWE-200'],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: [],
      d3fend_refs: [],
      rfc_refs: [],
      dlp_refs: ['DLP-EXFIL', 'DLP-EMAIL'],
    },
  ];
  const out = buildCweChains({
    skills,
    cweCatalog: { 'CWE-200': { name: 'Information Exposure', category: 'disclosure' } },
    atlasTtps: {},
    cveCatalog: {},
    frameworkGaps: {},
    d3fendCatalog: {},
    rfcCatalog: {},
  });
  const chain = out['CWE-200'].chain;
  // Presence paired with content shape: dlp_refs is an array carrying the
  // aggregated, sorted control ids — not merely defined.
  assert.ok(Array.isArray(chain.dlp_refs), 'chain.dlp_refs must be an array');
  assert.deepEqual(chain.dlp_refs, ['DLP-EMAIL', 'DLP-EXFIL'], 'dlp_refs aggregated + sorted');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
