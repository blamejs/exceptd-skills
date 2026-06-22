'use strict';

/**
 * upstream-check regression suite (lib/upstream-check-cli.js + lib/upstream-check.js).
 *
 * The CLI must catch any unexpected throw and emit one parseable JSON envelope
 * on stdout (exit 0 — offline is not an error), not surface an unhandled
 * rejection with a raw stack trace.
 *
 * Discipline: assert EXACT exit codes (never notEqual(0)); pair every
 * field-presence check with a value/type assertion. The spawned CLI runs with a
 * preload module written into an isolated tempdir so the repo tree is never
 * mutated and the network is never touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const UPSTREAM_CLI = path.join(ROOT, 'lib', 'upstream-check-cli.js');
const { fetchLatestPublished, buildFreshnessReport } = require(path.join(ROOT, 'lib', 'upstream-check.js'));

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function makeIsolatedDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ===================================================================
// upstream-check-cli.js catches unexpected throws -> JSON envelope
// ===================================================================

test('#49 upstream-check-cli emits a parseable ok:false envelope on an unexpected throw (no unhandled rejection)', () => {
  const dir = makeIsolatedDir('k49-');
  try {
    // Preload module that monkeypatches fetchLatestPublished to throw. The throw
    // propagates out of the awaited call into the IIFE; pre-fix that surfaced as
    // an unhandled rejection (raw stack on stderr, non-zero exit). Post-fix the
    // .catch() emits one JSON line on stdout and exits 0.
    const preload = path.join(dir, 'preload.js');
    fs.writeFileSync(
      preload,
      'const u = require(' + JSON.stringify(path.join(ROOT, 'lib', 'upstream-check.js')) + ');\n' +
      'u.fetchLatestPublished = async () => { throw new Error("forced-throw-for-test"); };\n',
    );
    const out = spawnSync(process.execPath, ['-r', preload, UPSTREAM_CLI], { encoding: 'utf8' });
    assert.equal(out.status, 0, `expected exit 0 (offline != error); got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be parseable JSON, never a raw stack trace; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(typeof body.source, 'string');
    assert.equal(body.source, 'upstream-check');
    assert.equal(body.error, 'forced-throw-for-test');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ===================================================================
// fetchLatestPublished fixture branch: missing version must refuse
// (symmetric with the network branch's `if (!version)` hard gate).
// ===================================================================

test('fetchLatestPublished fixture branch returns ok:false (not ok:true/version:undefined) when the fixture lacks dist-tags.latest AND version', async () => {
  const dir = makeIsolatedDir('k-fixnover-');
  const prev = process.env.EXCEPTD_REGISTRY_FIXTURE;
  try {
    // Fixture with a `time` block but NO dist-tags.latest and NO top-level
    // version. Pre-fix: ok:true with version:undefined leaked through.
    const fixture = path.join(dir, 'fixture.json');
    fs.writeFileSync(fixture, JSON.stringify({ time: { modified: '2026-01-01T00:00:00.000Z' } }));
    process.env.EXCEPTD_REGISTRY_FIXTURE = fixture;
    const r = await fetchLatestPublished();
    assert.equal(r.ok, false, 'a versionless fixture must degrade to ok:false, not ok:true');
    assert.equal(typeof r.error, 'string');
    assert.equal(r.error, 'fixture missing dist-tags.latest / version');
    assert.equal(r.source, 'offline');
    assert.equal('version' in r ? r.version : undefined, undefined,
      'no version field should be emitted on the refusal envelope');
  } finally {
    if (prev === undefined) delete process.env.EXCEPTD_REGISTRY_FIXTURE;
    else process.env.EXCEPTD_REGISTRY_FIXTURE = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('fetchLatestPublished fixture branch still returns ok:true with the version when dist-tags.latest is present', async () => {
  const dir = makeIsolatedDir('k-fixok-');
  const prev = process.env.EXCEPTD_REGISTRY_FIXTURE;
  try {
    const fixture = path.join(dir, 'fixture.json');
    fs.writeFileSync(fixture, JSON.stringify({
      'dist-tags': { latest: '0.18.10' },
      time: { '0.18.10': '2026-06-20T00:00:00.000Z' },
    }));
    process.env.EXCEPTD_REGISTRY_FIXTURE = fixture;
    const r = await fetchLatestPublished();
    assert.equal(r.ok, true);
    assert.equal(r.version, '0.18.10');
    assert.equal(r.published_at, '2026-06-20T00:00:00.000Z');
    assert.equal(r.source, 'fixture');
  } finally {
    if (prev === undefined) delete process.env.EXCEPTD_REGISTRY_FIXTURE;
    else process.env.EXCEPTD_REGISTRY_FIXTURE = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ===================================================================
// buildFreshnessReport: an unparseable published_at degrades
// days_since_latest_publish to null, never NaN.
// ===================================================================

test('buildFreshnessReport sets days_since_latest_publish to null (not NaN) for an unparseable published_at', () => {
  const report = buildFreshnessReport({
    localVersion: '0.18.0',
    registry: { ok: true, source: 'npm-registry', version: '0.18.10', published_at: 'not-a-real-date' },
    localManifest: null,
  });
  assert.equal(report.ok, true);
  assert.equal(report.days_since_latest_publish, null,
    'an unparseable date must degrade to the explicit null branch');
  assert.equal(Number.isNaN(report.days_since_latest_publish), false,
    'days_since_latest_publish must never be NaN');
});

test('buildFreshnessReport still computes a finite days_since_latest_publish for a valid published_at', () => {
  const published = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString();
  const report = buildFreshnessReport({
    localVersion: '0.18.0',
    registry: { ok: true, source: 'npm-registry', version: '0.18.10', published_at: published },
    localManifest: null,
  });
  assert.equal(typeof report.days_since_latest_publish, 'number');
  assert.equal(Number.isFinite(report.days_since_latest_publish), true);
  assert.equal(report.days_since_latest_publish, 3);
});

test('buildFreshnessReport keeps days_since_latest_publish null when published_at is absent', () => {
  const report = buildFreshnessReport({
    localVersion: '0.18.0',
    registry: { ok: true, source: 'npm-registry', version: '0.18.10', published_at: null },
    localManifest: null,
  });
  assert.equal(report.days_since_latest_publish, null);
});
