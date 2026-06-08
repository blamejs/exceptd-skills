'use strict';

/**
 * Regression: prefetch's warm-cache use must tolerate a few transient per-entry
 * fetch errors without failing the whole refresh.
 *
 * prefetch fans out hundreds (daily) to ~9.7k (Monday) per-CVE/per-RFC fetches
 * against rate-limited public APIs. The errors counter is incremented only
 * after the job queue exhausts its retries, but even so a handful of transient
 * misses per run is expected. Previously `process.exitCode = errors > 0 ? 1 : 0`
 * meant a single transient miss exited 1, and the warm-cache workflow step
 * (bash -e) failed the entire External Data Refresh before the dry-run/apply
 * ever read the cache. `--max-errors <N|N%>` is the tolerance; the default 0
 * preserves the strict any-error-exits-1 contract for a manual operator.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { exitCodeForResult, parseErrorThreshold, formatSummary, parseArgs } = require('../lib/prefetch');

function result(fetched, errors, by_source) {
  return { fetched, skipped_fresh: 0, errors, by_source: by_source || {} };
}

test('exitCodeForResult: default budget 0 keeps the strict manual-operator contract (any error -> 1)', () => {
  assert.equal(exitCodeForResult(result(850, 1), { maxErrors: 0 }), 1);
  // No opts at all must equal the old `errors > 0 ? 1 : 0`.
  assert.equal(exitCodeForResult(result(9737, 1)), 1);
  assert.equal(exitCodeForResult(result(9737, 0)), 0);
});

test('exitCodeForResult: zero errors is always exit 0', () => {
  assert.equal(exitCodeForResult(result(9737, 0), { maxErrors: 0 }), 0);
  assert.equal(exitCodeForResult(result(851, 0), { maxErrors: '50%' }), 0);
});

test('exitCodeForResult: the diagnosed transient runs (1/2/23 errors) pass under the warm-cache tolerance', () => {
  // The exact error counts from the failing refresh runs.
  assert.equal(exitCodeForResult(result(9737, 1), { maxErrors: 50 }), 0, 'Monday full sweep, 1 error');
  assert.equal(exitCodeForResult(result(851, 2), { maxErrors: 50 }), 0, '06-07 daily, 2 errors');
  assert.equal(exitCodeForResult(result(830, 23), { maxErrors: 50 }), 0, '06-06 daily, 23 errors');
});

test('exitCodeForResult: absolute budget is inclusive at the boundary, strict above it', () => {
  assert.equal(exitCodeForResult(result(100, 50), { maxErrors: 50 }), 0, '50 <= 50 passes');
  assert.equal(exitCodeForResult(result(100, 51), { maxErrors: 50 }), 1, '51 > 50 fails');
});

test('exitCodeForResult: a systemic outage still fails over a percentage budget', () => {
  // planned = fetched + skipped_fresh + errors. 50% of 853 -> floor 426.
  assert.equal(exitCodeForResult(result(427, 426), { maxErrors: '50%' }), 0, '426 == floor(0.5*853) passes');
  assert.equal(exitCodeForResult(result(426, 427), { maxErrors: '50%' }), 1, '427 > floor(0.5*853) fails');
  assert.equal(exitCodeForResult(result(353, 500), { maxErrors: '50%' }), 1, 'half-dead upstream fails');
});

test('parseErrorThreshold + parseArgs accept integer and percentage; default is 0', () => {
  assert.equal(parseErrorThreshold('50'), 50);
  assert.equal(parseErrorThreshold('5%'), '5%');
  assert.equal(parseArgs(['node', 'prefetch.js']).maxErrors, 0);
  assert.equal(parseArgs(['node', 'prefetch.js', '--max-errors', '50']).maxErrors, 50);
  assert.equal(parseArgs(['node', 'prefetch.js', '--max-errors=5%']).maxErrors, '5%');
});

test('parseErrorThreshold throws on a malformed value (drives exit 2 in main)', () => {
  assert.throws(() => parseErrorThreshold('abc'));
  assert.throws(() => parseErrorThreshold('50%%'));
  assert.throws(() => parseErrorThreshold('-5'));
  // parseArgs records the error rather than throwing, so main() can refuse.
  assert.ok(parseArgs(['node', 'prefetch.js', '--max-errors', 'abc'])._argError);
});

test('a malformed --max-errors exits 2 (usage error), not 1 or a silent unbounded tolerance', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'prefetch.js'), '--no-network', '--max-errors', 'abc'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr || r.stdout || '', /invalid --max-errors/);
});

test('formatSummary names the per-source error counts so a --quiet log is actionable', () => {
  const line = formatSummary(result(830, 23, { nvd: { errors: 20 }, epss: { errors: 3 }, kev: { errors: 0 } }), {});
  assert.match(line, /23 error\(s\)/);
  assert.match(line, /nvd=20/);
  assert.match(line, /epss=3/);
  assert.doesNotMatch(line, /kev=/, 'sources with zero errors are omitted from the breakdown');
  // No breakdown bracket when there are no errors.
  assert.doesNotMatch(formatSummary(result(853, 0, { nvd: { errors: 0 } }), {}), /\[/);
});

test('the refresh workflow warm-cache step carries the --max-errors tolerance', () => {
  const yaml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.match(
    yaml,
    /node lib\/prefetch\.js --quiet --max-errors 50\b/,
    'the warm-cache prefetch invocation must pass --max-errors so a transient per-entry miss no longer fails the whole refresh',
  );
});
