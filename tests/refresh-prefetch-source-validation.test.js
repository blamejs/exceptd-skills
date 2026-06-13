'use strict';

/**
 * refresh --prefetch / --no-network validates --source against the
 * prefetchable (cache-backed) subset before delegating to the prefetch cache
 * warmer.
 *
 * The prefetch cache layer only covers kev/nvd/epss/rfc/pins. The refresh
 * orchestrator additionally exposes ghsa/osv/advisories/cve-regression-watcher,
 * which resolve advisories by live id lookup and have no cache to warm.
 * Scoping a cache-warm to one of those previously forwarded it verbatim and
 * died with `prefetch: fatal: unknown source "osv"` — leaking the internal
 * cache-warmer's verb name (the operator typed `refresh`) and calling a source
 * "unknown" that the refresh help just listed as valid.
 *
 * Now the delegation refuses with a refresh-prefixed, actionable message that
 * names the live-only source and lists the prefetchable subset, never the
 * `prefetch: fatal` string. A still-valid scope (kev) delegates normally.
 *
 * Offline only: every case runs --no-network (dry-run); no live fetch occurs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const REFRESH = path.join(ROOT, 'lib', 'refresh-external.js');

function run(args) {
  return spawnSync(process.execPath, [REFRESH, ...args], { encoding: 'utf8' });
}

function lastJson(stream) {
  const line = (stream || '').trim().split('\n').pop();
  try { return JSON.parse(line); } catch { return null; }
}

for (const src of ['osv', 'ghsa', 'advisories', 'cve-regression-watcher']) {
  test(`refresh --prefetch --source ${src} refuses with a refresh-prefixed message, not "prefetch: fatal"`, () => {
    const r = run(['--prefetch', '--source', src, '--no-network']);
    assert.equal(r.status, 2, `${src} must exit exactly 2; stderr=${r.stderr}`);
    assert.doesNotMatch(r.stderr || '', /prefetch: fatal/,
      'must not leak the internal cache-warmer verb name');
    const body = lastJson(r.stderr);
    assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'refresh');
    assert.match(body.error, new RegExp(src.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')),
      'the error must name the unsupported source');
    assert.match(body.error, /prefetchable sources: kev,nvd,epss,rfc,pins/,
      'the error must list the prefetchable subset');
  });
}

test('refresh --prefetch --source kev,osv reports only osv as unsupported (the valid one is not the complaint)', () => {
  const r = run(['--prefetch', '--source', 'kev,osv', '--no-network']);
  assert.equal(r.status, 2, `mixed scope must exit 2; stderr=${r.stderr}`);
  const body = lastJson(r.stderr);
  assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
  assert.match(body.error, /osv/, 'osv (the unsupported one) must be named');
  assert.doesNotMatch(body.error, /"kev"/, 'kev (the valid one) must not be flagged');
});

test('refresh --prefetch --source bogus reports a genuinely-unknown source distinctly', () => {
  const r = run(['--prefetch', '--source', 'bogus', '--no-network']);
  assert.equal(r.status, 2, `unknown source must exit 2; stderr=${r.stderr}`);
  const body = lastJson(r.stderr);
  assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
  assert.equal(body.verb, 'refresh');
  assert.match(body.error, /unknown source "bogus"/);
  assert.doesNotMatch(r.stderr || '', /prefetch: fatal/);
});

test('refresh --prefetch --source kev (a prefetchable source) delegates normally and exits 0', () => {
  const r = run(['--prefetch', '--source', 'kev', '--no-network']);
  assert.equal(r.status, 0, `kev is cacheable; --no-network dry-run must exit 0; stderr=${r.stderr}`);
  // The cache warmer ran (its dry-run summary surfaces) — proof the valid
  // scope was forwarded rather than rejected.
  assert.match(r.stdout, /\[kev\]/, 'the kev source must have been planned by the cache warmer');
});
