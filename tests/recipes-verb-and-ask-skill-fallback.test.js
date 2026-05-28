"use strict";

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

test("ask surfaces the right skill for skill-only domains (no playbook home)", () => {
  const cases = [
    ["DMARC email spoofing", "email-security-anti-phishing"],
    ["child safety age gate", "age-gates-child-safety"],
    ["HIPAA PHI healthcare security", "sector-healthcare"],
    ["data loss prevention policy", "dlp-gap-analysis"],
  ];
  const manifest = require("../manifest.json");
  const skillExists = (n) => manifest.skills.some(s => (s.name || s.id) === n);
  for (const [q, skill] of cases) {
    const j = tryJson(cli(["ask", q, "--json"]).stdout);
    assert.equal(j.skill_suggestion, skill, `"${q}" must suggest the ${skill} skill`);
    assert.ok(skillExists(skill), `${skill} must be a real skill`);
  }
});

test("ask does not attach a skill_suggestion to a genuine playbook query", () => {
  for (const q of ["kernel privilege escalation", "post-quantum crypto migration", "MCP server trust"]) {
    const j = tryJson(cli(["ask", q, "--json"]).stdout);
    assert.equal(j.skill_suggestion, undefined, `"${q}" routes to a playbook; no skill_suggestion expected`);
  }
});
