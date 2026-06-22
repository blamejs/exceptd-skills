'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
