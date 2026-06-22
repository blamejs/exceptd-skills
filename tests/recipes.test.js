"use strict";


// ---- routed from recipes-verb-and-ask-skill-fallback ----
require("node:test").describe("recipes-verb-and-ask-skill-fallback", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for the `recipes` verb + the `ask` skill-only-domain
 * suggestion:
 *
 *   recipes — lists the curated multi-skill workflows; `recipes <id>` expands
 *     one; an unknown id is refused. (Previously the curated recipes had no
 *     CLI surface at all.)
 *   ask — a question in a domain covered by a SKILL rather than a playbook
 *     (email-auth/DMARC, child-safety, HIPAA, DLP) surfaces a skill_suggestion
 *     pointing at the real skill, instead of only a confident wrong playbook.
 *
 * Discipline: exact field/exit assertions; each suggested skill must exist.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-recipesask-"));

test("recipes lists the curated recipes", () => {
  const r = cli(["recipes", "--json"]);
  const j = tryJson(r.stdout);
  assert.ok(j && j.ok !== false, "recipes must emit a successful result");
  assert.ok(Array.isArray(j.recipes) && j.recipes.length >= 5, `expected the curated recipe list; got ${j.recipes && j.recipes.length}`);
  for (const rec of j.recipes) {
    assert.equal(typeof rec.id, "string");
    assert.equal(typeof rec.skill_count, "number");
  }
});

test("recipes <id> expands a single recipe with its skill chain", () => {
  const list = tryJson(cli(["recipes", "--json"]).stdout);
  const id = list.recipes[0].id;
  const r = cli(["recipes", id, "--json"]);
  const j = tryJson(r.stdout);
  assert.ok(j && j.recipe, "must return the recipe object");
  assert.equal(j.recipe.id, id);
  assert.ok(Array.isArray(j.recipe.skill_chain) && j.recipe.skill_chain.length >= 1, "must include the skill chain");
});

test("recipes <unknown-id> is refused with the available list", () => {
  const r = cli(["recipes", "no-such-recipe", "--json"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body && body.ok === false, "must emit a structured refusal");
  assert.match(body.error, /unknown recipe/);
  assert.ok(Array.isArray(body.available) && body.available.length >= 1, "must list available recipe ids");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
