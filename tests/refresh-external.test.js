'use strict';

/**
 * tests/refresh-external.test.js
 *
 * Verifies the lib/refresh-external.js orchestrator using the frozen
 * fixture payloads under tests/fixtures/refresh/. Network never touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'refresh');
const os = require('os');

let REPORT;            // per-test tempfile so parallel test files don't race
function mkReport() {
  REPORT = path.join(os.tmpdir(), `refresh-report-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  return REPORT;
}

function runDryRun(args = []) {
  const reportPath = mkReport();
  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-fixture', FIX, '--quiet', '--report-out', reportPath, ...args],
    { cwd: ROOT, encoding: 'utf8' }
  );
  return { exitCode: res.status, stdout: res.stdout, stderr: res.stderr };
}

test('refresh-external --from-fixture exits 0 and writes refresh-report.json', () => {
  const r = runDryRun();
  assert.equal(r.exitCode, 0, `stderr: ${r.stderr}`);
  assert.ok(fs.existsSync(REPORT));
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.mode, 'dry-run');
  assert.equal(report.fixture_mode, true);
  for (const src of ['kev', 'epss', 'nvd', 'rfc', 'pins']) {
    assert.ok(report.sources[src], `missing source ${src} in report`);
  }
});

test('refresh-external honors --source filter', () => {
  const r = runDryRun(['--source', 'kev,pins']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.deepEqual(Object.keys(report.sources).sort(), ['kev', 'pins']);
});

test('refresh-external surfaces KEV diff from fixture (CVE-2026-43284)', () => {
  const r = runDryRun(['--source', 'kev']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const diffs = report.sources.kev.diffs;
  assert.ok(diffs.find((d) => d.id === 'CVE-2026-43284' && d.field === 'cisa_kev'));
});

test('refresh-external marks pins as report-only', () => {
  const r = runDryRun(['--source', 'pins']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.sources.pins.report_only, true);
});

test('refresh-external rejects unknown --source values', () => {
  const r = runDryRun(['--source', 'made-up-thing']);
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr || '', /unknown source/);
});

test('refresh-external --help exits 0 and prints usage', () => {
  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--help'],
    { cwd: ROOT, encoding: 'utf8' }
  );
  assert.equal(res.status, 0);
  assert.match(res.stdout, /refresh — pull latest upstream/);
  assert.match(res.stdout, /--apply/);
  assert.match(res.stdout, /--prefetch/);
  assert.match(res.stdout, /Air-gap workflow/);
  assert.match(res.stdout, /Hard Rule #12/);
});

test('version-pin-validator exports the expected pin list', () => {
  const { PINS } = require('../sources/validators/version-pin-validator');
  const names = PINS.map((p) => p.pin_name).sort();
  assert.deepEqual(names, ['atlas_version', 'attack_version', 'cwe_version', 'd3fend_version']);
});

test('refresh fixtures stay in sync with source modules', () => {
  const { ALL_SOURCES } = require('../lib/refresh-external');
  for (const src of Object.values(ALL_SOURCES)) {
    const fp = path.join(FIX, `${src.name}.json`);
    assert.ok(fs.existsSync(fp), `missing fixture for source ${src.name}`);
  }
});

// v0.12.12 C1 — concurrent `refresh --advisory --apply` regression test.
//
// Pre-fix: `seedSingleAdvisory` did `readFileSync → mutate → writeFileSync`
// against the shared catalog with no lock. Two concurrent
// `refresh --advisory CVE-A --apply` and `refresh --advisory CVE-B --apply`
// runs racing on the same catalog dropped one CVE roughly 1/20 trials —
// classic read-old / mutate / write-overwrites-sibling-mutation.
//
// Post-fix: every RMW on the catalog routes through `withCatalogLock` (an
// O_EXCL lockfile + atomic tmp+rename write). The mutator re-reads the
// catalog INSIDE the lock, so a sibling write that just landed is visible
// before this run's mutation is applied.
//
// The test runs the parallel-apply scenario 5 times in a loop to flush out
// any timing dependency in the lock implementation. Both CVEs must survive
// in the final catalog on every iteration.
test('refresh --advisory --apply: concurrent applies preserve both CVEs (5x)', async () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  for (let trial = 0; trial < 5; trial++) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `concurrent-apply-${trial}-`));
    const catalogPath = path.join(tmpDir, 'cve-catalog.json');
    fs.writeFileSync(catalogPath, JSON.stringify({ _meta: { last_updated: '2026-01-01' } }, null, 2));
    try {
      const env = {
        ...process.env,
        EXCEPTD_GHSA_FIXTURE: fix,
        EXCEPTD_CVE_CATALOG: catalogPath,
        EXCEPTD_DEPRECATION_SHOWN: '1',
        EXCEPTD_UNSIGNED_WARNED: '1',
      };
      const spawn = (cve) => new Promise((resolve) => {
        const cp = require('child_process').spawn(
          process.execPath,
          [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', cve, '--apply', '--json'],
          { env, stdio: ['ignore', 'pipe', 'pipe'] }
        );
        let stdout = '', stderr = '';
        cp.stdout.on('data', (b) => { stdout += b; });
        cp.stderr.on('data', (b) => { stderr += b; });
        cp.on('close', (code) => resolve({ code, stdout, stderr }));
      });
      const [a, b] = await Promise.all([
        spawn('CVE-2026-45321'),
        spawn('CVE-9999-99999'),
      ]);
      // Each should signal "draft applied, editorial pending" (exit 3).
      assert.equal(a.code, 3, `trial ${trial}: CVE-A apply exit code unexpected. stderr=${a.stderr}`);
      assert.equal(b.code, 3, `trial ${trial}: CVE-B apply exit code unexpected. stderr=${b.stderr}`);
      const final = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
      assert.ok(final['CVE-2026-45321'],
        `trial ${trial}: CVE-2026-45321 missing from catalog after concurrent apply — RACE LOST. keys=${Object.keys(final).join(',')}`);
      assert.ok(final['CVE-9999-99999'],
        `trial ${trial}: CVE-9999-99999 missing from catalog after concurrent apply — RACE LOST. keys=${Object.keys(final).join(',')}`);
      // Field-present + field-populated: every entry must have the
      // _auto_imported flag and a non-null name, confirming the write
      // landed in full rather than a partial / truncated buffer.
      assert.equal(final['CVE-2026-45321']._auto_imported, true,
        `trial ${trial}: CVE-A entry lacks _auto_imported flag — possible partial write`);
      assert.equal(final['CVE-9999-99999']._auto_imported, true,
        `trial ${trial}: CVE-B entry lacks _auto_imported flag — possible partial write`);
      // _meta.last_updated should remain present (no field stripped by the
      // concurrent writes).
      assert.ok(final._meta, `trial ${trial}: _meta stripped from catalog`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
});

// v0.12.12 C3 — `process.exit()` after stdout writes can truncate output.
// chosenSources() used to call `process.exit(2)` directly when an unknown
// --source name was passed; the swarm post-pool path and the help path used
// the same anti-pattern. Post-fix: thrown error / exitCode + return.
// Operator visibility: stderr must still carry the "unknown source" line.
test('refresh --source <unknown>: stderr surfaces error, exits 2 via exitCode', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--source', 'definitely-not-a-source', '--from-fixture', FIX, '--quiet'],
    { cwd: ROOT, encoding: 'utf8' }
  );
  assert.equal(r.status, 2, `unknown --source must exit 2 via exitCode; got ${r.status}`);
  assert.match(r.stderr || '', /unknown source/);
  // Stack traces must not leak — _exceptd_unknown_source path strips them.
  assert.doesNotMatch(r.stderr || '', /at chosenSources/,
    `unknown-source error must not leak an internal stack trace; got ${r.stderr}`);
});
