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

test('token-budget: output matches the documented shape (totals under _meta, no by_recipe)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-tokbud-'));
  try {
    const rel = path.join('skills', 'fixture', 'skill.md');
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '# Fixture\n\nSome body text for the budget.\n');

    const out = buildTokenBudget({
      root: dir,
      skills: [{ name: 'fixture', path: rel }],
      sectionOffsets: { skills: {} },
    });

    // Totals are nested under _meta, never at the top level.
    assert.equal(typeof out._meta, 'object', '_meta block present');
    assert.equal(typeof out._meta.total_chars, 'number', 'total_chars under _meta');
    assert.equal(typeof out._meta.total_approx_tokens, 'number', 'total_approx_tokens under _meta');
    assert.equal(out.total_chars, undefined, 'no top-level total_chars');
    assert.equal(out.total_approx_tokens, undefined, 'no top-level total_approx_tokens');
    // by_recipe is documented nowhere and emitted nowhere.
    assert.equal(out.by_recipe, undefined, 'no top-level by_recipe');
    assert.equal(out._meta.by_recipe, undefined, 'no by_recipe under _meta');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
