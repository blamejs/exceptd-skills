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
