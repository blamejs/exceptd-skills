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

// Regression: every entry in the `pins` registry must resolve to a real
// GitHub Releases endpoint. Previously `d3fend__d3fend-data__releases`
// and `mitre__cwe__releases` were 404 on every refresh (their upstream
// projects don't publish via GitHub Releases), surfacing as "2 error(s)"
// in the prefetch summary on a clean install. Pin every id we ship to
// the two MITRE repos that actually have a Releases feed.
test('prefetch pins source contains only repos that publish GitHub Releases', () => {
  const { SOURCES } = require('../lib/prefetch');
  const entries = SOURCES.pins.expand();
  const ids = entries.map((e) => e.id).sort();
  assert.deepEqual(
    ids,
    ['mitre-atlas__atlas-data__releases', 'mitre-attack__attack-stix-data__releases'],
    `pins registry must contain only repos with a real GitHub Releases feed (D3FEND distributes via d3fend-ontology without tagged releases; CWE ships XML from cwe.mitre.org, not GitHub). Got: ${ids.join(',')}`
  );
  // Every URL must target api.github.com/repos/<org>/<repo>/releases —
  // any other shape means we re-introduced the 404 class of bug.
  for (const e of entries) {
    assert.match(e.url, /^https:\/\/api\.github\.com\/repos\/[^/]+\/[^/]+\/releases\?/,
      `pins entry "${e.id}" must point at a GitHub Releases endpoint; got ${e.url}`);
  }
});

// Regression: the libuv `UV_HANDLE_CLOSING` assertion on Windows + Node 25.
// Pre-fix, `node lib/prefetch.js` (or the `refresh --no-network` route
// through bin/exceptd.js) emitted the summary line and then crashed with
// `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file
// src\win\async.c, line 76` and exited 3221226505. The post-fix contract
// is: clean exit code 0 when every source is fresh / dry-run completed,
// no assertion line on stderr. We assert BOTH — checking exit alone would
// have missed the regression on the platforms where the assertion fires
// but the parent shell still reports 0 (which happened when stdout was
// piped).
// v0.12.12 C2 — concurrent prefetch index-merge regression test.
//
// Pre-fix: each prefetch run did `loadIndex → mutate-in-memory → saveIndex`
// at end. Two concurrent runs against the same cache dir both loaded the
// index at start, accumulated their entries in their own in-memory copies,
// then wrote at the end — the second writer overwrote the first run's
// sibling entries.
//
// Post-fix: every per-entry success updates _index.json under a sidecar
// lockfile, merging with whatever the on-disk index currently has. The
// final saveIndex() does the same merge.
//
// The test uses the prefetch API directly rather than spawning subprocesses
// — `withIndexLock` is exercised on the in-process path too, and we don't
// need real network to validate the locking contract. We simulate two
// runs by directly invoking `withIndexLock` from two interleaved
// promises with overlapping writes; the merged result must contain both
// runs' entries.
test('prefetch _index.json: concurrent writers preserve all entries (5x)', async () => {
  // Re-require the module so we get a fresh handle; the helper isn't
  // exported, so we test the contract via two parallel saveIndex-equivalent
  // mutations through the public `prefetch` flow's lock layer. The simplest
  // shape is a direct functional probe of the lock by importing the module
  // and using its readCached + loadIndex round-trip after a synthetic
  // pair of parallel writers.
  for (let trial = 0; trial < 5; trial++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `pf-race-${trial}-`));
    try {
      // Each "writer" emulates a prefetch run by repeatedly mutating the
      // _index.json: it writes 20 entries, racing against a sibling that
      // writes a different 20 entries. Pre-fix this produced a 20-entry
      // result; post-fix it produces a 40-entry result.
      const writer = (prefix) => new Promise((resolve, reject) => {
        const cp = require('child_process').fork(
          path.join(ROOT, 'tests', '_helpers', 'concurrent-prefetch-index-writer.js'),
          [tmp, prefix, '20'],
          { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }
        );
        let err = '';
        cp.stderr.on('data', (b) => { err += b; });
        cp.on('close', (code) => code === 0 ? resolve() : reject(new Error(`writer ${prefix} exited ${code}: ${err}`)));
      });
      await Promise.all([writer('A'), writer('B')]);
      const idxPath = path.join(tmp, '_index.json');
      assert.ok(fs.existsSync(idxPath), `trial ${trial}: _index.json must exist after concurrent writes`);
      const idx = JSON.parse(fs.readFileSync(idxPath, 'utf8'));
      const keys = Object.keys(idx.entries);
      const aCount = keys.filter((k) => k.startsWith('test/A-')).length;
      const bCount = keys.filter((k) => k.startsWith('test/B-')).length;
      assert.equal(aCount, 20, `trial ${trial}: writer A wrote 20 entries, ${aCount} survived in merged index`);
      assert.equal(bCount, 20, `trial ${trial}: writer B wrote 20 entries, ${bCount} survived in merged index`);
      // Field-present + populated: every entry must have a fetched_at
      // timestamp, confirming the on-disk JSON wasn't truncated.
      for (const k of keys) {
        assert.ok(idx.entries[k].fetched_at, `trial ${trial}: entry ${k} missing fetched_at`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
});

test('prefetch exits cleanly with no libuv assertion (Win + Node 25 regression)', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--quiet'],
    { encoding: 'utf8' }
  );
  assert.equal(r.status, 0,
    `prefetch --no-network --quiet must exit 0 — got status=${r.status}, stderr=${JSON.stringify(r.stderr)}`);
  assert.doesNotMatch(r.stderr || '', /Assertion failed/,
    `stderr must not contain the libuv UV_HANDLE_CLOSING assertion line — got ${JSON.stringify(r.stderr)}`);
  assert.doesNotMatch(r.stderr || '', /UV_HANDLE_CLOSING/,
    `stderr must not contain UV_HANDLE_CLOSING — got ${JSON.stringify(r.stderr)}`);
});
