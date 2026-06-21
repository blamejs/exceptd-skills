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
