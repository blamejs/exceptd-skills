'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

test('prefetch --no-network --quiet reports a plan without writing the cache', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--cache-dir', tmp, '--quiet'],
      { encoding: 'utf8' }
    );
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    // Dry-run must not have written any payload to the cache.
    const entries = fs.readdirSync(tmp);
    assert.deepEqual(entries, [], `cache dir should be empty after --no-network; got: ${entries.join(',')}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch --no-network --source <name> respects the source filter', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--source', 'kev', '--cache-dir', tmp],
      { encoding: 'utf8' }
    );
    assert.equal(r.status, 0);
    assert.match(r.stdout, /\[kev\]/);
    assert.doesNotMatch(r.stdout, /\[nvd\]/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch SOURCES has exactly the five expected sources', () => {
  const { SOURCES } = require('../lib/prefetch');
  assert.deepEqual(Object.keys(SOURCES).sort(), ['epss', 'kev', 'nvd', 'pins', 'rfc']);
});

test('prefetch readCached returns null on miss and on stale entries past --max-age', () => {
  const { readCached } = require('../lib/prefetch');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-test-'));
  try {
    // No cache at all → null.
    assert.equal(readCached(tmp, 'kev', 'whatever'), null);
    // Write a synthetic entry that's "60 seconds old", then test maxAgeMs.
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify({ vulnerabilities: [] }));
    const olderIso = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({
      generated_at: olderIso,
      entries: {
        'kev/known_exploited_vulnerabilities': { fetched_at: olderIso, etag: null, url: 'x', sha256: 'x' },
      },
    }));
    // 24h default is plenty fresh.
    const fresh = readCached(tmp, 'kev', 'known_exploited_vulnerabilities');
    assert.ok(fresh && fresh.data);
    // 30s threshold → stale.
    const stale = readCached(tmp, 'kev', 'known_exploited_vulnerabilities', { maxAgeMs: 30_000 });
    assert.equal(stale, null);
    // allowStale opt-in returns the entry anyway.
    const forced = readCached(tmp, 'kev', 'known_exploited_vulnerabilities', { maxAgeMs: 30_000, allowStale: true });
    assert.ok(forced && forced.data);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('prefetch refuses unknown --source values', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--source', 'made-up'],
    { encoding: 'utf8' }
  );
  assert.notEqual(r.status, 0);
  assert.match(r.stderr || '', /unknown source/);
});
