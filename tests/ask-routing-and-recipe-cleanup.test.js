"use strict";

/**
 * Regression suite for `ask` routing improvements + the dead-recipe-field
 * removal:
 *
 *   ask synonym gaps — a CI/OIDC question routes to cicd-pipeline-compromise
 *     (not the supply-chain playbooks), and an "AI command and control"
 *     question routes to ai-api (not llm-tool-use-exfil).
 *   ask stopword gap — a nonsense English question ("how do I bake bread")
 *     no longer produces a confident route via the 2-char filler token "do".
 *   recipe cleanup — byCve() no longer emits the always-empty `recipes` field
 *     (recipes are use-case curated, never CVE-keyed).
 *
 * Discipline: exact routed_to[0] assertions + presence checks.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-askroute-"));

function routedTop(question) {
  const r = cli(["ask", question, "--json"]);
  const j = tryJson(r.stdout);
  return j && Array.isArray(j.routed_to) ? j.routed_to[0] : undefined;
}

test("ask: a CI/OIDC question routes to cicd-pipeline-compromise", () => {
  assert.equal(routedTop("my CI runner leaked an OIDC token"), "cicd-pipeline-compromise");
});

test("ask: an 'AI command and control' question routes to ai-api", () => {
  assert.equal(routedTop("detect AI used as command and control"), "ai-api");
});

test("ask: a nonsense English question does not confidently route (stopword filtering)", () => {
  const r = cli(["ask", "how do I bake bread", "--json"]);
  const j = tryJson(r.stdout);
  assert.ok(j, "ask must emit JSON");
  // Either no route, or a clearly-low confidence — never a confident wrong match.
  if (Array.isArray(j.routed_to) && j.routed_to.length > 0) {
    assert.ok((j.confidence ?? 0) < 0.1, `a nonsense query must not route confidently; got confidence ${j.confidence}`);
  } else {
    assert.deepEqual(j.routed_to, [], "no match expected for a nonsense query");
  }
});

test("ask: existing routes are unregressed", () => {
  assert.equal(routedTop("post-quantum crypto migration"), "crypto");
  assert.equal(routedTop("kernel privilege escalation"), "kernel");
  assert.equal(routedTop("secret leaked in repo"), "secrets");
});

test("byCve() no longer emits the dead (always-empty) recipes field", () => {
  const xref = require("../lib/cross-ref-api.js");
  const r = xref.byCve("CVE-2025-53773");
  assert.ok(r, "byCve must return a result");
  assert.ok(!("recipes" in r), "the always-empty recipes field must be removed");
  // Other cross-reference fields remain intact (the removal was scoped to recipes).
  assert.ok("skills" in r && "framework_gaps" in r && "theater_tests" in r, "other xref fields must remain");
});
