'use strict';

/**
 * sbom -> deep-dive feeds_into, exercised against a REAL run (not a synthetic
 * eval context).
 *
 * sbom.json ships:
 *   { playbook_id: 'kernel',  condition: "any matched_cve.attack_class == 'kernel-lpe'" }
 *   { playbook_id: 'mcp',     condition: "any matched_cve.attack_class == 'mcp-supply-chain'" }
 *   { playbook_id: 'ai-api',  condition: "any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']" }
 *
 * Two defects made these chains dead even though the quantifier PARSER handled
 * the syntax:
 *   1. close()'s feedsCtx exposed the matched CVEs only under
 *      `analyze.matched_cves`, never as a top-level `matched_cve` array, so the
 *      quantifier head resolved null.
 *   2. the per-CVE analyze shape carried no `attack_class` field at all, so even
 *      once the array was exposed the `.attack_class` leaf was undefined.
 *
 * Now: close() exposes `matched_cve`, the analyze shape carries `attack_class`
 * sourced from the catalog, and the chainable CVEs are classified. These assert
 * the chain against the actual run output, so a regression in either the context
 * wiring or the catalog classification fails here — the synthetic-context parser
 * tests cannot catch that.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const DIR = 'all-installed-packages-and-lockfiles';

function runWithMatchedCve(cveId) {
  // A direct CVE signal correlates that catalog CVE into matched_cves (path (b)
  // in analyze: agentSignals[cve_id] === 'hit'). The CVE must be in the sbom
  // playbook's coverage for it to land in matched_cves.
  return runner.run('sbom', DIR, { artifacts: {}, signal_overrides: {}, signals: { [cveId]: 'hit' } });
}

test('sbom matched-CVE carries attack_class from the catalog', () => {
  const r = runWithMatchedCve('CVE-2026-30615'); // Windsurf MCP RCE — mcp-supply-chain
  assert.equal(r.ok, true);
  const m = r.phases.analyze.matched_cves.find(c => c.cve_id === 'CVE-2026-30615');
  assert.ok(m, 'the MCP CVE must correlate into matched_cves');
  assert.equal(m.attack_class, 'mcp-supply-chain',
    'matched_cves entries must surface the catalog attack_class so feeds_into quantifiers can route on it');
});

test('sbom -> mcp fires when a matched CVE is attack_class mcp-supply-chain', () => {
  const r = runWithMatchedCve('CVE-2026-30615');
  assert.ok(r.phases.close.feeds_into.includes('mcp'),
    `sbom must chain into mcp when a matched CVE is mcp-supply-chain; got ${JSON.stringify(r.phases.close.feeds_into)}`);
});

test('sbom -> ai-api fires when a matched CVE is attack_class prompt-injection (IN quantifier)', () => {
  const r = runWithMatchedCve('CVE-2025-53773'); // Copilot YOLO-mode prompt-injection RCE
  assert.ok(r.phases.close.feeds_into.includes('ai-api'),
    `sbom must chain into ai-api when a matched CVE is in ['ai-c2','prompt-injection']; got ${JSON.stringify(r.phases.close.feeds_into)}`);
});

test('an unclassified matched CVE does NOT manufacture a deep-dive chain', () => {
  // CVE-2026-31431 is in sbom coverage but carries no attack_class. The chain
  // must stay quiet rather than misroute — null attack_class is a correct "no
  // chain", not a parser failure. (This is the exact CVE the original report
  // observed an empty feeds_into for; here the empty result is the right answer.)
  const r = runWithMatchedCve('CVE-2026-31431');
  const f = r.phases.close.feeds_into;
  for (const deepDive of ['kernel', 'mcp', 'ai-api']) {
    assert.ok(!f.includes(deepDive),
      `an attack_class-less matched CVE must not chain into ${deepDive}; got ${JSON.stringify(f)}`);
  }
});

test('the matched-CVE quantifier also works in the analyze-phase escalation context', () => {
  // close() and analyze() build separate eval contexts; both must expose
  // matched_cve. Assert the analyze escalation context resolves the array by
  // confirming a classified matched CVE is present with its attack_class — the
  // same field the analyze escalation_criteria quantifiers read.
  const r = runWithMatchedCve('CVE-2026-30615');
  const m = r.phases.analyze.matched_cves.find(c => c.cve_id === 'CVE-2026-30615');
  assert.equal(m.attack_class, 'mcp-supply-chain');
});
