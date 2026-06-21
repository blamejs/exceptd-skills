'use strict';

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

// --- #40 air-gap FLAG (not just env) suppresses the TLS probe ---------------

test('#40 isAirGap honors opts, env, and the --air-gap/--offline/--no-network argv flags', () => {
  const prevEnv = process.env.EXCEPTD_AIR_GAP;
  const prevArgv = process.argv;
  delete require.cache[require.resolve('../orchestrator/scanner.js')];
  try {
    delete process.env.EXCEPTD_AIR_GAP;
    const { isAirGap } = require('../orchestrator/scanner.js');

    // No signal anywhere → false.
    process.argv = ['node', 'orchestrator/index.js', 'scan', '--json'];
    assert.equal(isAirGap(), false, 'no air-gap signal → false');

    // opts.airGap → true.
    assert.equal(isAirGap({ airGap: true }), true, 'opts.airGap drives true');

    // each CLI flag on argv → true (env stays unset).
    for (const flag of ['--air-gap', '--offline', '--no-network']) {
      process.argv = ['node', 'orchestrator/index.js', 'scan', flag];
      assert.equal(isAirGap(), true, `${flag} on argv must drive air-gap with env unset`);
    }

    // env var → true even with no flag.
    process.argv = ['node', 'orchestrator/index.js', 'scan'];
    process.env.EXCEPTD_AIR_GAP = '1';
    assert.equal(isAirGap(), true, 'EXCEPTD_AIR_GAP=1 drives true');
  } finally {
    process.argv = prevArgv;
    if (prevEnv === undefined) delete process.env.EXCEPTD_AIR_GAP;
    else process.env.EXCEPTD_AIR_GAP = prevEnv;
    delete require.cache[require.resolve('../orchestrator/scanner.js')];
  }
});

test('#40 scan({airGap:true}) skips the TLS probe with EXCEPTD_AIR_GAP deleted', async () => {
  const prevEnv = process.env.EXCEPTD_AIR_GAP;
  const prevArgv = process.argv;
  delete require.cache[require.resolve('../orchestrator/scanner.js')];
  try {
    delete process.env.EXCEPTD_AIR_GAP;
    process.argv = ['node', 'orchestrator/index.js', 'scan']; // no flag — only opts
    const { scan } = require('../orchestrator/scanner.js');
    const result = await scan({ airGap: true });
    const tls = result.findings.find((f) => f.signal === 'tls_probe');
    assert.ok(tls, 'a tls_probe finding must still appear');
    assert.equal(tls.probe, 'skipped (air-gap)', 'opts.airGap must suppress the probe');
    // And it must NOT carry a live protocol value (which only the real probe path emits).
    assert.equal(tls.value, undefined, 'air-gap probe must not carry a TLS protocol value');
  } finally {
    process.argv = prevArgv;
    if (prevEnv === undefined) delete process.env.EXCEPTD_AIR_GAP;
    else process.env.EXCEPTD_AIR_GAP = prevEnv;
    delete require.cache[require.resolve('../orchestrator/scanner.js')];
  }
});

test('#40 real CLI `scan --air-gap --json` suppresses the probe with EXCEPTD_AIR_GAP deleted', () => {
  // End-to-end proof: spawn the real orchestrator entry with the flag and the
  // env var explicitly removed from the child env. The flag MUST drive the
  // air-gap disposition; if it did not, the scanner would attempt an
  // `openssl s_client` egress and the finding would carry a live TLS value.
  const childEnv = { ...process.env };
  delete childEnv.EXCEPTD_AIR_GAP;
  childEnv.EXCEPTD_SUPPRESS_DEPRECATION = '1';

  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'orchestrator', 'index.js'), 'scan', '--air-gap', '--json'],
    { env: childEnv, encoding: 'utf8', timeout: 60_000 },
  );

  assert.equal(res.status, 0, `scan --air-gap --json must exit 0; stderr=${res.stderr}`);

  // The last non-empty stdout line is the JSON envelope.
  const lines = String(res.stdout).split('\n').map((l) => l.trim()).filter(Boolean);
  const jsonLine = lines.reverse().find((l) => l.startsWith('{'));
  assert.ok(jsonLine, `expected a JSON line on stdout; got: ${res.stdout}`);
  const parsed = JSON.parse(jsonLine);
  assert.equal(parsed.ok, true, 'envelope ok must be true');

  const tls = (parsed.findings || []).find((f) => f.signal === 'tls_probe');
  assert.ok(tls, 'a tls_probe finding must be present');
  assert.equal(tls.probe, 'skipped (air-gap)', '--air-gap flag must suppress the probe (env deleted)');
  // Hard proof no live probe ran: the air-gap finding has no `value` and no TLS protocol.
  assert.equal(tls.value, undefined, 'air-gap finding must not carry a live TLS protocol value');
});

// --- #41 malformed last_threat_review → maximally stale, observable --------

test('#41 _currencyScore(NaN) === 0 (safe value, not the safe-LOOKING 100)', () => {
  const pipeline = require('../orchestrator/pipeline.js');
  assert.equal(pipeline._currencyScore(NaN), 0);
  assert.equal(typeof pipeline._currencyScore(NaN), 'number');
});

test('#41 _skillCurrencyRow over a malformed date yields stale + observable flag', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-13-99', forward_watch: [] },
    now,
  );
  assert.equal(row.currency_score, 0, 'a malformed date must score maximally stale (0)');
  assert.equal(typeof row.currency_score, 'number');
  assert.equal(row.action_required, true, 'a malformed date must trip action_required');
  assert.equal(row.unparseable_review_date, true, 'the misformat must be surfaced (observable)');
  assert.equal(typeof row.unparseable_review_date, 'boolean');
});

test('#41 _skillCurrencyRow over a fresh valid date stays current and not flagged', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-06-19', forward_watch: [] },
    now,
  );
  assert.equal(row.unparseable_review_date, false, 'a valid date must not be flagged unparseable');
  assert.equal(row.currency_score, 100, 'a 1-day-old review is fully current');
  assert.equal(row.action_required, false);
});

// --- #42 buildHandoff named guard on non-object stageOutput ----------------

test('#42 buildHandoff throws a NAMED TypeError on null/number/string stageOutput', () => {
  const { initPipeline, buildHandoff } = require('../orchestrator/pipeline.js');
  const run = initPipeline('manual', {});
  const re = /stageOutput .* must be a non-null object/;
  assert.throws(() => buildHandoff(run, 0, null), re, 'null payload → named error');
  assert.throws(() => buildHandoff(run, 0, 42), re, 'number payload → named error');
  assert.throws(() => buildHandoff(run, 0, 'str'), re, 'string payload → named error');
  assert.throws(() => buildHandoff(run, 0, []), re, 'array payload → named error');
  // Specifically NOT the opaque deref message.
  assert.throws(
    () => buildHandoff(run, 0, null),
    (err) => err instanceof TypeError && !/in.*operator/.test(err.message),
    'must be the named TypeError, not the opaque "in operator" deref',
  );
});
