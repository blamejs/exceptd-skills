'use strict';

/**
 * Subject coverage for the `ask` CLI verb (bin/exceptd.js cmdAsk): natural-
 * language question routing, synonym handling, and stopword filtering so a
 * nonsense query does not confidently route.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('ask-routing-and-recipe-cleanup', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const cli = makeCli(makeSuiteHome('exceptd-askroute-'));

  function routedTop(question) {
    const r = cli(['ask', question, '--json']);
    const j = tryJson(r.stdout);
    return j && Array.isArray(j.routed_to) ? j.routed_to[0] : undefined;
  }

  test('ask: a CI/OIDC question routes to cicd-pipeline-compromise', () => {
    assert.equal(routedTop('my CI runner leaked an OIDC token'), 'cicd-pipeline-compromise');
  });

  test("ask: an 'AI command and control' question routes to ai-api", () => {
    assert.equal(routedTop('detect AI used as command and control'), 'ai-api');
  });

  test('ask: a nonsense English question does not confidently route (stopword filtering)', () => {
    const r = cli(['ask', 'how do I bake bread', '--json']);
    const j = tryJson(r.stdout);
    assert.ok(j, 'ask must emit JSON');
    if (Array.isArray(j.routed_to) && j.routed_to.length > 0) {
      assert.ok((j.confidence ?? 0) < 0.1, `a nonsense query must not route confidently; got confidence ${j.confidence}`);
    } else {
      assert.deepEqual(j.routed_to, [], 'no match expected for a nonsense query');
    }
  });

  test('ask: existing routes are unregressed', () => {
    assert.equal(routedTop('post-quantum crypto migration'), 'crypto');
    assert.equal(routedTop('kernel privilege escalation'), 'kernel');
    assert.equal(routedTop('secret leaked in repo'), 'secrets');
  });
});
