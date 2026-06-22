'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// --- #39 dispatcher dedupe by full-finding fingerprint ---------------------

test('#39 two MCP servers under one config route to mcp-agent-trust as DISTINCT plan entries', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
      skill_hint: 'mcp-agent-trust', server_name: 'server-a',
      action_required: 'verify provenance of server-a',
    },
    {
      domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
      skill_hint: 'mcp-agent-trust', server_name: 'server-b',
      action_required: 'verify provenance of server-b',
    },
  ];
  const { plan, summary } = dispatch(findings);
  const entries = plan.filter((p) => p.skill_name === 'mcp-agent-trust');
  // Pre-fix: both findings have no cve_id, so the key fell back to the shared
  // `signal` (mcp_server_detected) and the second was silently dropped → 1.
  assert.equal(entries.length, 2, 'two distinct MCP servers must each produce a plan entry');
  assert.equal(summary.skills_to_invoke, 2, 'summary count must reflect both entries');
  const actions = entries.map((p) => p.action_required).sort();
  assert.deepEqual(
    actions,
    ['verify provenance of server-a', 'verify provenance of server-b'],
    'each entry must carry its own distinct action_required (not a collapsed single)',
  );
});

test('#39 two AI-API dependencies route to ai-c2-detection as DISTINCT plan entries', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'ai_api', signal: 'ai_api_dependency_detected', severity: 'info',
      skill_hint: 'ai-c2-detection', api_name: 'openai',
      action_required: 'openai detected',
    },
    {
      domain: 'ai_api', signal: 'ai_api_dependency_detected', severity: 'info',
      skill_hint: 'ai-c2-detection', api_name: 'anthropic',
      action_required: 'anthropic detected',
    },
  ];
  const { plan } = dispatch(findings);
  const entries = plan.filter((p) => p.skill_name === 'ai-c2-detection');
  assert.equal(entries.length, 2, 'openai and anthropic must each produce a plan entry');
  assert.deepEqual(
    entries.map((p) => p.action_required).sort(),
    ['anthropic detected', 'openai detected'],
  );
});

test('#39 two mcp_config_parse_error findings at different paths stay distinct', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low',
      skill_hint: 'mcp-agent-trust', config_path: '/a/mcp.json',
      action_required: 'parse error at /a/mcp.json',
    },
    {
      domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low',
      skill_hint: 'mcp-agent-trust', config_path: '/b/mcp.json',
      action_required: 'parse error at /b/mcp.json',
    },
  ];
  const { plan } = dispatch(findings);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    2,
    'two parse errors at different paths must each produce a plan entry',
  );
});

test('#39 a true duplicate (same content twice) still folds to one entry', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const finding = {
    domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
    skill_hint: 'mcp-agent-trust', server_name: 'server-a',
    action_required: 'verify provenance of server-a',
  };
  const { plan } = dispatch([finding, finding]);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    1,
    'identical findings must still dedupe to a single entry',
  );
});

test('#39 fingerprint is key-order-independent (folds reordered-but-equal content)', () => {
  const { dispatch, stableStringify } = require('../orchestrator/dispatcher.js');
  // stableStringify must be deterministic regardless of insertion order.
  assert.equal(
    stableStringify({ a: 1, b: 2 }),
    stableStringify({ b: 2, a: 1 }),
    'stableStringify must sort keys so reordered objects serialize identically',
  );
  const f1 = {
    domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
    skill_hint: 'mcp-agent-trust', server_name: 'x', action_required: 'y',
  };
  const f2 = {
    action_required: 'y', server_name: 'x', skill_hint: 'mcp-agent-trust',
    severity: 'high', signal: 'mcp_server_detected', domain: 'mcp',
  };
  const { plan } = dispatch([f1, f2]);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    1,
    'two findings with identical content but reordered keys must fold to one',
  );
});

test('dispatcher preserves two distinct CVEs that route to the same skill (no dedupe-by-skill data loss)', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2026-31431', rwep_score: 90 },
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2025-53773', rwep_score: 80 },
  ];
  const { plan } = dispatch(findings);
  const kernelEntries = plan.filter((p) => p.skill_name === 'kernel-lpe-triage');
  assert.equal(kernelEntries.length, 2, 'both distinct CVEs routing to the same skill must produce a plan entry each');
  const cveIds = kernelEntries.map((p) => p.evidence && p.evidence.cve_id).sort();
  assert.deepEqual(cveIds, ['CVE-2025-53773', 'CVE-2026-31431'], 'each entry carries its own CVE evidence');

  // A genuine duplicate (same skill + same CVE) is still folded to one entry.
  const dup = dispatch([findings[0], findings[0]]);
  assert.equal(dup.plan.filter((p) => p.skill_name === 'kernel-lpe-triage').length, 1, 'a true duplicate is still deduped');
});

test('scanner mcp_config_parse_error finding carries a direct skill_hint', () => {
  // Behavioral routing: a parse-error finding shaped like the scanner emits must
  // route directly to mcp-agent-trust via skill_hint, independent of the domain
  // table.
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const { plan } = dispatch([{ domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low', skill_hint: 'mcp-agent-trust', action_required: 'x' }]);
  assert.ok(plan.some((p) => p.skill_name === 'mcp-agent-trust'), 'parse-error must route to mcp-agent-trust via skill_hint');
  // And the scanner source actually sets that skill_hint on the finding.
  const SRC = fs.readFileSync(path.join(ROOT, 'orchestrator', 'scanner.js'), 'utf8');
  const block = SRC.slice(SRC.indexOf('mcp_config_parse_error'), SRC.indexOf('mcp_config_parse_error') + 400);
  assert.match(block, /skill_hint:\s*'mcp-agent-trust'/, 'the parse-error finding literal must set skill_hint');
});


// ---- routed from dispatch-collector-scoring-fixes ----
require("node:test").describe("dispatch-collector-scoring-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Routing / collector / scoring correctness from the adjacent-area hunt:
 *  - dispatcher must preserve distinct findings that route to the same skill
 *    (de-dupe by skill+finding, not skill alone) so per-CVE evidence survives;
 *  - scanner's mcp_config_parse_error finding carries a skill_hint so it routes
 *    directly, not only via the brittle domain table;
 *  - library-author's action-ref scan flags a floating ref even with a trailing
 *    YAML comment (the `$`-anchored pattern silently missed those);
 *  - scoring.validate() honors the reboot_required alias when recomputing the
 *    expected RWEP, so a top-level reboot_required does not create false drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

test('dispatcher preserves two distinct CVEs that route to the same skill (no dedupe-by-skill data loss)', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2026-31431', rwep_score: 90 },
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2025-53773', rwep_score: 80 },
  ];
  const { plan } = dispatch(findings);
  const kernelEntries = plan.filter((p) => p.skill_name === 'kernel-lpe-triage');
  assert.equal(kernelEntries.length, 2, 'both distinct CVEs routing to the same skill must produce a plan entry each');
  const cveIds = kernelEntries.map((p) => p.evidence && p.evidence.cve_id).sort();
  assert.deepEqual(cveIds, ['CVE-2025-53773', 'CVE-2026-31431'], 'each entry carries its own CVE evidence');

  // A genuine duplicate (same skill + same CVE) is still folded to one entry.
  const dup = dispatch([findings[0], findings[0]]);
  assert.equal(dup.plan.filter((p) => p.skill_name === 'kernel-lpe-triage').length, 1, 'a true duplicate is still deduped');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-I-orchestrator ----
require("node:test").describe("hunt-fix-I-orchestrator", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the orchestrator cluster hunt fixes:
 *
 *  #39 dispatcher.js — dedupe identity keys on skill + a FULL-finding
 *      fingerprint, not skill + a single optional field (cve_id). Two distinct
 *      findings that route to the same skill and differ only by a non-cve field
 *      (server_name, api_name, config_path) must each keep a plan entry; a true
 *      duplicate (identical content) still folds.
 *
 *  #40 scanner.js — the air-gap CLI flag (--air-gap / --offline / --no-network)
 *      suppresses the outbound TLS probe, equivalently to EXCEPTD_AIR_GAP=1.
 *      Proven with the env var DELETED so it is the FLAG, not the env, that
 *      drives suppression — and the real-CLI spawn confirms no `openssl
 *      s_client` egress fires.
 *
 *  #41 pipeline.js — a malformed last_threat_review ("2026-13-99": ISO-shaped
 *      but not a real calendar date) maps to maximally STALE (score 0,
 *      action_required true) and surfaces unparseable_review_date, instead of
 *      masquerading as 100% current via a NaN day-delta. _currencyScore(NaN)
 *      maps to 0 (the safe value), never 100 (the safe-LOOKING value).
 *
 *  #42 pipeline.js — buildHandoff throws a NAMED TypeError on a null /
 *      non-object / array stageOutput, not an opaque "Cannot use 'in' operator"
 *      deref deep inside validateHandoff.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// --- #39 dispatcher dedupe by full-finding fingerprint ---------------------






// --- #40 air-gap FLAG (not just env) suppresses the TLS probe ---------------




// --- #41 malformed last_threat_review → maximally stale, observable --------




// --- #42 buildHandoff named guard on non-object stageOutput ----------------

test('#39 two MCP servers under one config route to mcp-agent-trust as DISTINCT plan entries', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
      skill_hint: 'mcp-agent-trust', server_name: 'server-a',
      action_required: 'verify provenance of server-a',
    },
    {
      domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
      skill_hint: 'mcp-agent-trust', server_name: 'server-b',
      action_required: 'verify provenance of server-b',
    },
  ];
  const { plan, summary } = dispatch(findings);
  const entries = plan.filter((p) => p.skill_name === 'mcp-agent-trust');
  // Pre-fix: both findings have no cve_id, so the key fell back to the shared
  // `signal` (mcp_server_detected) and the second was silently dropped → 1.
  assert.equal(entries.length, 2, 'two distinct MCP servers must each produce a plan entry');
  assert.equal(summary.skills_to_invoke, 2, 'summary count must reflect both entries');
  const actions = entries.map((p) => p.action_required).sort();
  assert.deepEqual(
    actions,
    ['verify provenance of server-a', 'verify provenance of server-b'],
    'each entry must carry its own distinct action_required (not a collapsed single)',
  );
});

test('#39 two AI-API dependencies route to ai-c2-detection as DISTINCT plan entries', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'ai_api', signal: 'ai_api_dependency_detected', severity: 'info',
      skill_hint: 'ai-c2-detection', api_name: 'openai',
      action_required: 'openai detected',
    },
    {
      domain: 'ai_api', signal: 'ai_api_dependency_detected', severity: 'info',
      skill_hint: 'ai-c2-detection', api_name: 'anthropic',
      action_required: 'anthropic detected',
    },
  ];
  const { plan } = dispatch(findings);
  const entries = plan.filter((p) => p.skill_name === 'ai-c2-detection');
  assert.equal(entries.length, 2, 'openai and anthropic must each produce a plan entry');
  assert.deepEqual(
    entries.map((p) => p.action_required).sort(),
    ['anthropic detected', 'openai detected'],
  );
});

test('#39 two mcp_config_parse_error findings at different paths stay distinct', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    {
      domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low',
      skill_hint: 'mcp-agent-trust', config_path: '/a/mcp.json',
      action_required: 'parse error at /a/mcp.json',
    },
    {
      domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low',
      skill_hint: 'mcp-agent-trust', config_path: '/b/mcp.json',
      action_required: 'parse error at /b/mcp.json',
    },
  ];
  const { plan } = dispatch(findings);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    2,
    'two parse errors at different paths must each produce a plan entry',
  );
});

test('#39 a true duplicate (same content twice) still folds to one entry', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const finding = {
    domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
    skill_hint: 'mcp-agent-trust', server_name: 'server-a',
    action_required: 'verify provenance of server-a',
  };
  const { plan } = dispatch([finding, finding]);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    1,
    'identical findings must still dedupe to a single entry',
  );
});

test('#39 fingerprint is key-order-independent (folds reordered-but-equal content)', () => {
  const { dispatch, stableStringify } = require('../orchestrator/dispatcher.js');
  // stableStringify must be deterministic regardless of insertion order.
  assert.equal(
    stableStringify({ a: 1, b: 2 }),
    stableStringify({ b: 2, a: 1 }),
    'stableStringify must sort keys so reordered objects serialize identically',
  );
  const f1 = {
    domain: 'mcp', signal: 'mcp_server_detected', severity: 'high',
    skill_hint: 'mcp-agent-trust', server_name: 'x', action_required: 'y',
  };
  const f2 = {
    action_required: 'y', server_name: 'x', skill_hint: 'mcp-agent-trust',
    severity: 'high', signal: 'mcp_server_detected', domain: 'mcp',
  };
  const { plan } = dispatch([f1, f2]);
  assert.equal(
    plan.filter((p) => p.skill_name === 'mcp-agent-trust').length,
    1,
    'two findings with identical content but reordered keys must fold to one',
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
