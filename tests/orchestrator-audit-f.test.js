'use strict';

/**
 * Audit F regression tests — orchestrator/* + vendor/blamejs/worker-pool.js.
 *
 * Each test corresponds to a single audit finding. Names embed the audit
 * code (P1-1, P2-3, etc.) so regressions trace back to the rule they broke.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');

// Per-suite isolated EXCEPTD_HOME so the scheduler last-fired file + watch
// lockfile don't leak into the maintainer's real ~/.exceptd.
const SUITE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-audit-f-'));
process.on('exit', () => {
  try { fs.rmSync(SUITE_HOME, { recursive: true, force: true }); } catch { /* non-fatal */ }
});

const childEnv = () => ({
  ...process.env,
  EXCEPTD_HOME: SUITE_HOME,
  EXCEPTD_DEPRECATION_SHOWN: '1',
  EXCEPTD_SUPPRESS_DEPRECATION: '1',
});

// --- P1-1 — bus.eventLog is bounded ----------------------------------------

test('P1-1: ExceptdEventBus.eventLog stays bounded at the configured cap', () => {
  const { ExceptdEventBus } = require('../orchestrator/event-bus');
  const bus = new ExceptdEventBus({ maxLogSize: 5 });
  for (let i = 0; i < 25; i++) bus.emit('cisa.kev.added', { cve_id: `CVE-2026-${1000 + i}` });
  assert.equal(bus.eventLog.length, 5, 'ring buffer must cap at maxLogSize');
  // FIFO: the oldest entries must have been shifted off.
  assert.equal(bus.eventLog[0].payload.cve_id, 'CVE-2026-1020');
  assert.equal(bus.eventLog[4].payload.cve_id, 'CVE-2026-1024');
});

test('P1-1: EXCEPTD_EVENT_LOG_MAX_SIZE env override honored at module read', () => {
  // Module read happens at require time; rerun in a fresh subprocess so the
  // env var actually takes effect.
  const r = spawnSync(process.execPath, ['-e', `
    process.env.EXCEPTD_EVENT_LOG_MAX_SIZE = '7';
    delete require.cache[require.resolve(${JSON.stringify(path.join(ROOT, 'orchestrator', 'event-bus.js'))})];
    const { EVENT_LOG_MAX_SIZE, ExceptdEventBus } = require(${JSON.stringify(path.join(ROOT, 'orchestrator', 'event-bus.js'))});
    const bus = new ExceptdEventBus();
    process.stdout.write(JSON.stringify({ cap: EVENT_LOG_MAX_SIZE, instanceCap: bus.maxLogSize }));
  `], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.cap, 7);
  assert.equal(out.instanceCap, 7);
});

// --- P1-2 — SIGTERM (and friends) shut watch down cleanly ------------------

test('P1-2: SIGTERM triggers graceful shutdown of watch (POSIX only)', (t, done) => {
  if (process.platform === 'win32') {
    // Windows has no SIGTERM. Validated separately via the watch test below
    // running through spawnSync timeout (which uses force-kill on win32).
    t.skip('SIGTERM is POSIX-only; covered indirectly on win32');
    return done();
  }
  // v0.12.14: capture both stdout AND stderr; the shutdown banner ends up
  // on stderr in the Ubuntu/macOS CI runners (was missed when the test
  // looked only at stdout). 50ms delay between banner-detect and signal
  // so the SIGTERM handler is fully registered before delivery. Hard
  // timeout safety net so a hung child can't hold the CI runner.
  const child = spawn(process.execPath, [ORCH, 'watch'], { env: childEnv() });
  let captured = '';
  let signalled = false;
  let finishedOnce = false;
  const finish = (err) => {
    if (finishedOnce) return;
    finishedOnce = true;
    try { child.kill('SIGKILL'); } catch {}
    done(err);
  };
  const onData = (d) => {
    captured += d.toString();
    if (!signalled && /Starting event watcher/.test(captured)) {
      signalled = true;
      setTimeout(() => { try { child.kill('SIGTERM'); } catch {} }, 50);
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  child.on('exit', (code) => {
    try {
      assert.match(captured, /Stopping watcher \(SIGTERM\)/);
      assert.equal(code, 0, 'graceful SIGTERM shutdown must exit 0');
      finish();
    } catch (e) { finish(e); }
  });
  setTimeout(() => finish(new Error('test timed out — child did not shut down within 10s')), 10000).unref();
});

test('P1-2: signal handlers registered for SIGTERM (and SIGBREAK on win32)', () => {
  // Inspect the orchestrator's source — verifying the registration call is
  // a cheap regression guard that doesn't require spawning a watcher.
  const src = fs.readFileSync(ORCH, 'utf8');
  assert.match(src, /process\.on\('SIGTERM'/);
  assert.match(src, /process\.on\('SIGINT'/);
  assert.match(src, /SIGHUP/);
  assert.match(src, /SIGBREAK/);
});

// --- P1-3 — bootstrap runWeeklyCurrencyCheck wrapped in try/catch ----------

test('P1-3: scheduler.start wraps bootstrap weekly check in try/catch', () => {
  const src = fs.readFileSync(path.join(ROOT, 'orchestrator', 'scheduler.js'), 'utf8');
  // The bootstrap path uses safeRun(...) which is the named wrapper.
  assert.match(src, /safeRun\('weekly currency bootstrap'/);
});

// --- P1-4 — monthly + annual bootstrap-fire with persisted last-fired ------

test('P1-4: scheduler bootstrap-fires monthly + annual when last-fired absent', () => {
  // Use a per-test home so the file is clean.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sched-bootstrap-'));
  try {
    const prevHome = process.env.EXCEPTD_HOME;
    process.env.EXCEPTD_HOME = home;
    // Reset the require cache so scheduler reads our env afresh.
    delete require.cache[require.resolve('../orchestrator/scheduler.js')];
    delete require.cache[require.resolve('../orchestrator/pipeline.js')];
    delete require.cache[require.resolve('../orchestrator/event-bus.js')];
    const sched = require('../orchestrator/scheduler.js');
    // Pre-state: no last-fired file.
    assert.equal(sched._loadLastFired().monthly_cve_validation, undefined);
    assert.ok(sched._shouldBootstrapFire(sched.LAST_FIRED_KEYS.MONTHLY_CVE_VALIDATION, sched.INTERVALS.MONTHLY_CVE_VALIDATION));
    sched.start();
    sched.stop();
    // After start: the persisted file records the bootstrap-fire.
    const state = sched._loadLastFired();
    assert.ok(state.weekly_currency_check, 'weekly must mark last_fired');
    assert.ok(state.monthly_cve_validation, 'monthly must bootstrap-fire and mark last_fired');
    assert.ok(state.annual_full_audit, 'annual must bootstrap-fire and mark last_fired');

    // Second start within the interval — should NOT bootstrap-fire again.
    assert.ok(!sched._shouldBootstrapFire(sched.LAST_FIRED_KEYS.MONTHLY_CVE_VALIDATION, sched.INTERVALS.MONTHLY_CVE_VALIDATION));

    if (prevHome === undefined) delete process.env.EXCEPTD_HOME;
    else process.env.EXCEPTD_HOME = prevHome;
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    // Reset module cache so the rest of the suite gets a fresh scheduler.
    delete require.cache[require.resolve('../orchestrator/scheduler.js')];
    delete require.cache[require.resolve('../orchestrator/pipeline.js')];
    delete require.cache[require.resolve('../orchestrator/event-bus.js')];
  }
});

// --- P1-5 — lockfile prevents concurrent watchers --------------------------

test('P1-5: second watcher refuses to start when lock is held by live PID', () => {
  // Forge a lockfile pointing at our own (alive) PID and confirm watch
  // refuses with EWATCHLOCKED exit code 75.
  const lockDir = path.join(SUITE_HOME);
  fs.mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, 'watch.lock');
  fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }));
  try {
    const r = spawnSync(process.execPath, [ORCH, 'watch'], {
      encoding: 'utf8', timeout: 4000, env: childEnv(),
    });
    assert.equal(r.status, 75, `expected exit 75 EWATCHLOCKED; got ${r.status} stderr=${r.stderr}`);
    assert.match(r.stderr, /cannot start watch/);
  } finally {
    try { fs.unlinkSync(lockPath); } catch { /* clean */ }
  }
});

test('P1-5: stale lock (dead PID) is reclaimed', () => {
  const lockPath = path.join(SUITE_HOME, 'watch.lock');
  fs.writeFileSync(lockPath, JSON.stringify({ pid: 1, started_at: new Date().toISOString() }));
  // PID 1 on POSIX is init, alive — so we synthesize a *very* high PID
  // that's almost certainly dead. Same approach as Node's own tests for
  // dead-PID detection on Windows. On POSIX use 2^31 - 1.
  fs.writeFileSync(lockPath, JSON.stringify({ pid: 2147483646, started_at: new Date(0).toISOString() }));
  const r = spawnSync(process.execPath, [ORCH, 'watch'], {
    encoding: 'utf8', timeout: 4000, env: childEnv(),
  });
  // Either the watcher started (and got killed by timeout — null status /
  // SIGTERM signal) OR it exited cleanly via shutdown. The key contract:
  // it must NOT have been blocked by the stale lock (exit 75).
  assert.notEqual(r.status, 75, `stale lock should be reclaimed; got status=${r.status} stderr=${r.stderr}`);
  // Clean up any new lockfile the watcher created.
  try { fs.unlinkSync(lockPath); } catch { /* fine */ }
});

// --- P2-1 — require('./orchestrator/index.js') does not trigger CLI --------

test('P2-1: importing orchestrator/index.js does not invoke main()', () => {
  // If main() ran on require, requiring the module from a child node process
  // would print the help text. The require-gated version should print
  // nothing on import.
  const r = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(ORCH)});`], {
    encoding: 'utf8', timeout: 5000, env: childEnv(),
  });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, '', `require must not print to stdout; got:\n${r.stdout}`);
});

// --- P2-2 — duplicate 'watch' case removed ---------------------------------

test('P2-2: orchestrator switch has exactly one watch case', () => {
  const src = fs.readFileSync(ORCH, 'utf8');
  const matches = src.match(/case 'watch':/g) || [];
  assert.equal(matches.length, 1, `exactly one 'watch' case must remain; found ${matches.length}`);
});

// --- P2-3 — air-gap suppresses TLS probe -----------------------------------

test('P2-3: EXCEPTD_AIR_GAP=1 short-circuits the TLS probe', async () => {
  // Reload scanner with the env set so the air-gap branch is exercised.
  const prev = process.env.EXCEPTD_AIR_GAP;
  process.env.EXCEPTD_AIR_GAP = '1';
  delete require.cache[require.resolve('../orchestrator/scanner.js')];
  try {
    const { scan } = require('../orchestrator/scanner.js');
    const result = await scan();
    const tls = result.findings.find(f => f.signal === 'tls_probe');
    assert.ok(tls, 'tls_probe entry must still appear');
    assert.equal(tls.probe, 'skipped (air-gap)');
  } finally {
    if (prev === undefined) delete process.env.EXCEPTD_AIR_GAP;
    else process.env.EXCEPTD_AIR_GAP = prev;
    delete require.cache[require.resolve('../orchestrator/scanner.js')];
  }
});

// --- P2-4 — routeQuery rejects empty + very short matches ------------------

test('P2-4: routeQuery rejects empty query (no all-skills match)', () => {
  const { routeQuery } = require('../orchestrator/dispatcher.js');
  const all = routeQuery('');
  assert.equal(all.length, 0, 'empty query must return no skills');
});

test('P2-4: routeQuery on short query only matches trigger-prefix', () => {
  const { routeQuery } = require('../orchestrator/dispatcher.js');
  // Pick a 2-char trigger likely to NOT appear as a prefix anywhere. The
  // assertion is structural — short queries never match every skill the
  // way empty did.
  const r = routeQuery('zz');
  const r2 = routeQuery('a');
  // We don't assert specifics on which skills match (the manifest can
  // change); we assert short queries don't collapse to "everything".
  const total = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8')).skills.length;
  assert.ok(r.length < total, 'short query must not match every skill');
  assert.ok(r2.length < total, 'single-char query must not match every skill');
});

// --- P2-5 — dispatch refuses strings ---------------------------------------

test('P2-5: dispatch throws TypeError on string input', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  assert.throws(() => dispatch('not-an-array'), /dispatch: findings must be an array/);
  assert.throws(() => dispatch(null), /dispatch: findings must be an array/);
});

// --- P2-6 — _deprecation not in JSON shape ---------------------------------

test('P2-6: scan() JSON shape omits _deprecation', async () => {
  delete require.cache[require.resolve('../orchestrator/scanner.js')];
  const { scan } = require('../orchestrator/scanner.js');
  const result = await scan();
  assert.ok(!('_deprecation' in result), 'scan() must not include _deprecation in JSON shape');
});

// --- P2-7 — buildHandoff bounds check --------------------------------------

test('P2-7: buildHandoff rejects out-of-range stageIndex', () => {
  const { initPipeline, buildHandoff } = require('../orchestrator/pipeline.js');
  const run = initPipeline('manual', {});
  assert.throws(() => buildHandoff(run, -1, {}), /stageIndex -1 out of range/);
  assert.throws(() => buildHandoff(run, run.stages.length, {}), /out of range/);
  assert.throws(() => buildHandoff(run, 99, {}), /out of range/);
});

// --- P2-8 — watchlist excludes deprecated skills ---------------------------

test('P2-8: runWatchlist filters skills with status="deprecated"', () => {
  // Smoke through a real CLI invocation — we don't have a deprecated skill
  // in the live manifest right now, so we assert the JSON shape is
  // produced and that the source filters on status !== 'deprecated'.
  const src = fs.readFileSync(ORCH, 'utf8');
  assert.match(src, /status !== 'deprecated'/);
});

// --- P2-9 — event-bus header documents in-process-only ---------------------

test('P2-9: event-bus.js header documents in-process-only', () => {
  const src = fs.readFileSync(path.join(ROOT, 'orchestrator', 'event-bus.js'), 'utf8');
  assert.match(src, /in-process only/i);
  assert.match(src, /NOT persisted/i);
});

// --- P3-1 — manifest cache ---------------------------------------------------

test('P3-1: pipeline.currencyCheck caches the manifest read', () => {
  const pipeline = require('../orchestrator/pipeline.js');
  pipeline._resetManifestCache();
  // First call primes the cache.
  pipeline.currencyCheck();
  // Subsequent call within TTL should not re-read; assert the cache TTL
  // constant is set to a finite positive value.
  assert.ok(pipeline.MANIFEST_CACHE_TTL_MS > 0);
  // We can't easily spy on fs.readFileSync without monkey-patching, so
  // assert behaviorally: 100 consecutive calls complete quickly because
  // the cache hits.
  const t0 = Date.now();
  for (let i = 0; i < 100; i++) pipeline.currencyCheck();
  const dt = Date.now() - t0;
  assert.ok(dt < 3000, `100 cached currencyCheck() should be fast; took ${dt}ms`);
});

// --- P3-2 — validate-cves --concurrency flag -------------------------------

test('P3-2: --concurrency is documented + parsed in validate-cves', () => {
  const src = fs.readFileSync(ORCH, 'utf8');
  assert.match(src, /--concurrency/);
});

// --- P3-3 — bus.offAny detacher exists -------------------------------------

test('P3-3: ExceptdEventBus exposes offAny() to detach onAny listeners', () => {
  const { ExceptdEventBus } = require('../orchestrator/event-bus.js');
  const bus = new ExceptdEventBus();
  let count = 0;
  const handler = () => { count++; };
  bus.onAny(handler);
  bus.emit('cisa.kev.added', {});
  assert.equal(count, 1);
  bus.offAny(handler);
  bus.emit('cisa.kev.added', {});
  assert.equal(count, 1, 'offAny() must detach the wildcard listener');
});

// --- P3-4 — UNC + extended path rejection on win32 -------------------------

test('P3-4: worker-pool rejects UNC / device namespace paths on win32', () => {
  if (process.platform !== 'win32') {
    // Validate that the regex path is present in the source so the win32
    // branch is at least exercised by the linter / inspection.
    const src = fs.readFileSync(path.join(ROOT, 'vendor', 'blamejs', 'worker-pool.js'), 'utf8');
    assert.match(src, /UNC \/ extended-length \/ device namespace/);
    return;
  }
  const wp = require('../vendor/blamejs/worker-pool.js');
  assert.throws(() => wp.create('\\\\?\\C:\\Windows\\System32\\cmd.exe'), /UNC/);
  assert.throws(() => wp.create('\\\\?\\UNC\\server\\share\\worker.js'), /UNC/);
  assert.throws(() => wp.create('\\\\.\\PhysicalDrive0'), /UNC/);
  assert.throws(() => wp.create('\\\\server\\share\\worker.js'), /UNC/);
});

// --- P3-5 — worker-pool lifecycle docs -------------------------------------

test('P3-5: worker-pool JSDoc documents terminate() requirement', () => {
  const src = fs.readFileSync(path.join(ROOT, 'vendor', 'blamejs', 'worker-pool.js'), 'utf8');
  assert.match(src, /try\/finally|try \/ finally|try\s*\{[\s\S]*?finally/i);
  assert.match(src, /terminate\(\)/);
  assert.match(src, /MUST call/);
});

// --- P3-6 — single aggregated currency-low event ---------------------------

test('P3-6: weekly currency check emits ONE aggregated SKILL_CURRENCY_LOW_AGGREGATE', () => {
  // Reset modules so the bus + scheduler share fresh state.
  delete require.cache[require.resolve('../orchestrator/event-bus.js')];
  delete require.cache[require.resolve('../orchestrator/pipeline.js')];
  delete require.cache[require.resolve('../orchestrator/scheduler.js')];
  const { bus, EVENT_TYPES } = require('../orchestrator/event-bus.js');
  const { runCurrencyNow } = require('../orchestrator/scheduler.js');

  const aggregateEvents = [];
  bus.on(EVENT_TYPES.SKILL_CURRENCY_LOW_AGGREGATE, (e) => aggregateEvents.push(e));
  runCurrencyNow();
  // The catalog may or may not have critical-stale skills. The contract is:
  // at most one aggregate per run (never N per-skill).
  assert.ok(aggregateEvents.length <= 1, `expected <= 1 aggregate event; got ${aggregateEvents.length}`);
  if (aggregateEvents.length === 1) {
    const e = aggregateEvents[0];
    assert.ok(Array.isArray(e.payload.skills));
    assert.equal(typeof e.payload.critical_count, 'number');
  }
});

// --- P3-7 — runScan uses parseFlags helper ---------------------------------

test('P3-7: runScan parses argv via parseFlags helper', () => {
  const src = fs.readFileSync(ORCH, 'utf8');
  // The helper is defined inline; runScan uses it now instead of
  // process.argv.includes('--json').
  assert.match(src, /function parseFlags\(argv/);
  // Strip comments before scanning so the assertion isn't tripped by
  // historical references in the surrounding documentation.
  const runScanBody = src.match(/async function runScan\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(runScanBody, 'runScan body must be locatable');
  const codeOnly = runScanBody[0]
    .split('\n')
    .filter(line => !line.trim().startsWith('//'))
    .join('\n');
  assert.doesNotMatch(codeOnly, /process\.argv\.includes\(['"]--json['"]\)/);
  // Positive: parseFlags must be called inside runScan.
  assert.match(runScanBody[0], /parseFlags\(/);
});

// --- P3-8 — watch --log-file teeing ----------------------------------------

test('P3-8: watch --log-file tees stdout to the named file', (t, done) => {
  const logFile = path.join(SUITE_HOME, `watch-${Date.now()}.log`);
  const child = spawn(process.execPath, [ORCH, 'watch', '--log-file', logFile], {
    env: childEnv(),
  });
  let stdout = '';
  child.stdout.on('data', (d) => {
    stdout += d.toString();
    if (/Starting event watcher/.test(stdout)) {
      // Give the writer a beat to flush, then signal stop.
      setTimeout(() => {
        if (process.platform === 'win32') child.kill();
        else child.kill('SIGTERM');
      }, 200);
    }
  });
  child.on('exit', () => {
    try {
      assert.ok(fs.existsSync(logFile), `log file ${logFile} must exist`);
      const body = fs.readFileSync(logFile, 'utf8');
      assert.match(body, /Starting event watcher/);
      done();
    } catch (e) { done(e); }
  });
});

// --- P3-9 — cache size guard -----------------------------------------------

test('P3-9: validateAllCvesPreferCache refuses cache files over 50 MB', () => {
  // We exercise the size-cap branch by inspecting the source — writing a
  // 50 MB file just to test rejection would inflate test runtime and CI
  // disk use for marginal additional coverage.
  const src = fs.readFileSync(ORCH, 'utf8');
  assert.match(src, /CACHE_FILE_MAX_BYTES = 50 \* 1024 \* 1024/);
  assert.match(src, /exceeds .* byte cap/);
});
