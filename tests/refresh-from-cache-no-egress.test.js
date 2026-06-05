'use strict';

/**
 * --from-cache is the offline ingest path: every source reads only local
 * cache files and never the network. GHSA and OSV have no cache layer, so
 * they previously fell through to a live api.github.com / osv.dev fetch when
 * a cacheDir was set but --air-gap was not — silently egressing on a host the
 * operator believed was isolated. Both must now return a structured skip
 * whenever ctx.cacheDir is present.
 *
 * The source network calls are never stubbed here: the cache-skip branch
 * returns before the source module that would issue the HTTPS GET is even
 * required, so a regression that re-enabled egress would have to reach a real
 * network and could not produce the asserted skip summary.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));

test('GHSA fetchDiff returns a structured cache skip (no live fetch) when cacheDir is set', async () => {
  const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false };
  const r = await ALL_SOURCES.ghsa.fetchDiff(ctx);
  assert.equal(r.status, 'unreachable');
  assert.equal(r.errors, 0);
  assert.deepEqual(r.diffs, []);
  assert.equal(typeof r.summary, 'string');
  assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
});

test('OSV fetchDiff returns a structured cache skip (no live fetch) when cacheDir is set', async () => {
  const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false };
  const r = await ALL_SOURCES.osv.fetchDiff(ctx);
  assert.equal(r.status, 'unreachable');
  assert.equal(r.errors, 0);
  assert.deepEqual(r.diffs, []);
  assert.equal(typeof r.summary, 'string');
  assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
});

test('cache skip holds even when osv_ids would otherwise drive a live lookup', async () => {
  // ctx.osv_ids populated is the only thing that makes OSV reach the network;
  // the cache-skip branch must win so a seeded id never egresses offline.
  const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false, osv_ids: ['MAL-2026-0001'] };
  const r = await ALL_SOURCES.osv.fetchDiff(ctx);
  assert.equal(r.status, 'unreachable');
  assert.deepEqual(r.diffs, []);
  assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
});

test('air-gap fixture path is unaffected by the cache-skip branch (fixtures win)', async () => {
  // A configured GHSA fixture must still be honored; the cache skip only
  // fires when there is no fixture for the source.
  const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: true, fixtures: {} };
  // No ghsa fixture configured -> cache skip applies.
  const r = await ALL_SOURCES.ghsa.fetchDiff(ctx);
  assert.equal(r.status, 'unreachable');
  assert.match(r.summary, /no cache layer/);
});
