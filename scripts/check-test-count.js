#!/usr/bin/env node
'use strict';

/**
 * scripts/check-test-count.js — v0.13.2 canonical-test-count predeploy gate.
 *
 * Why this exists. The v0.12 audit flagged that nothing in the suite asserts
 * "we expect N tests today." A deleted test file, a removed `test(` call, or a
 * misnamed file glob-excluded would all silently drop tests without anyone
 * noticing. The lint + diff-coverage gates catch source changes; this gate
 * catches test-set shrinkage.
 *
 * Scope + blind spot. This counts test DECLARATIONS, so it detects deleted
 * files / removed `test(`/`it(` calls / glob-exclusions. It does NOT detect a
 * test neutered in place: `test('name', { skip: true }, fn)`, `test.skip(`,
 * and `it.skip(` all still count as one declaration, so flipping a running
 * test to permanently skipped leaves the count unchanged. Guarding against
 * skip-in-place would need runnable-vs-skipped tracking; that is out of scope
 * for this gate.
 *
 * Mechanism: count `test(`/`it(` declarations (including the `.only`/`.skip`
 * variants) across `tests/*.test.js` via static analysis (faster than
 * running). node:test supports both `test()` and the BDD-style `it()`/
 * `describe()` aliases as first-class declarations, and the suite mixes both,
 * so counting only `test(` was blind to every `it(` test. `describe(` is NOT
 * counted — those are containers, not tests, so counting them would inflate
 * the total and conflate removing a grouping block with removing a test.
 * Compare to a baseline pinned in `tests/.test-count-baseline.json`. Fail if
 * the observed count drops MORE than the configured tolerance (default 1)
 * below the baseline. Growth above baseline is fine; if the count grows by
 * more than `update_baseline_when_growth_exceeds`, surface a notice that the
 * baseline file should be refreshed (operator commits the refresh as part
 * of the release that added the tests).
 *
 * Output:
 *   stdout: structured JSON when --json, else a one-line summary
 *   exit 0: observed count is at or above baseline minus tolerance
 *   exit 1: observed count dropped beyond tolerance — fail predeploy
 *   exit 2: baseline file missing or malformed
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TESTS_DIR = path.join(ROOT, 'tests');
const BASELINE_PATH = path.join(TESTS_DIR, '.test-count-baseline.json');

function listTestFiles(dir) {
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === '_helpers' || e.name === 'fixtures' || e.name === 'e2e-scenarios') continue;
      out.push(...listTestFiles(p));
    } else if (e.isFile() && e.name.endsWith('.test.js')) {
      out.push(p);
    }
  }
  return out;
}

function countTests(filePath) {
  let text = fs.readFileSync(filePath, 'utf8');
  // Strip block comments first so a `/* test('x'); */`-disabled test is not
  // counted — the most common "temporarily disable" action, which previously
  // defeated this gate's entire purpose (it only stripped whole-line `//`).
  text = text.replace(/\/\*[\s\S]*?\*\//g, '');
  let count = 0;
  for (const rawLine of text.split('\n')) {
    // Blank out single-line string/template literal BODIES first so a `test(`
    // mentioned inside a string (e.g. an assertion on output text, or this very
    // file's docstring examples) is not miscounted as a declaration — that
    // phantom inflated the baseline and could mask a real test deletion.
    const noStrings = rawLine.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''");
    // Drop a trailing line comment too (`test('x'); // disabled`).
    const stripped = noStrings.replace(/\/\/.*$/, '').trim();
    if (!stripped) continue;
    if (/(?<![A-Za-z0-9_$.])(?:test|it)(?:\.only|\.skip)?\s*\(/.test(stripped)) count++;
  }
  return count;
}

function main() {
  const wantJson = process.argv.includes('--json');
  const wantUpdate = process.argv.includes('--update-baseline');

  // Read the baseline once and branch on the read RESULT, not on a prior
  // existsSync probe. A separate existsSync(BASELINE_PATH)-then-read opens a
  // check-then-use window (CodeQL js/file-system-race) where the file the
  // gate decides about is not the file it later reads. ENOENT from the single
  // read IS the "missing" signal — no second path access needed.
  let baselineRaw = null;
  try {
    baselineRaw = fs.readFileSync(BASELINE_PATH, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`[check-test-count] cannot read baseline: ${e.message}`);
      process.exit(2);
    }
    // ENOENT — baseline absent.
    if (wantUpdate) {
      const files = listTestFiles(TESTS_DIR);
      const observed = files.reduce((n, f) => n + countTests(f), 0);
      // Exclusive create ('wx'): fails with EEXIST if the file appeared
      // between the read above and this write, so we never clobber a baseline
      // a concurrent run just produced — atomic, no check-then-write window.
      fs.writeFileSync(BASELINE_PATH, JSON.stringify({
        baseline: observed,
        tolerance: 1,
        update_baseline_when_growth_exceeds: 20,
        notes: 'Operator-pinned canonical test count. Bump when new test files land in a release. See scripts/check-test-count.js for the contract.',
        recorded_at: new Date().toISOString().slice(0, 10),
      }, null, 2) + '\n', { encoding: 'utf8', flag: 'wx' });
      console.error(`[check-test-count] wrote initial baseline: ${observed}`);
      process.exit(0);
    }
    console.error(`[check-test-count] baseline missing at ${path.relative(ROOT, BASELINE_PATH)}. Run with --update-baseline to create it.`);
    process.exit(2);
  }

  let baselineFile;
  try { baselineFile = JSON.parse(baselineRaw); }
  catch (e) {
    console.error(`[check-test-count] cannot parse baseline: ${e.message}`);
    process.exit(2);
  }
  const baseline = baselineFile.baseline;
  const tolerance = baselineFile.tolerance || 1;
  const updateThreshold = baselineFile.update_baseline_when_growth_exceeds || 20;
  if (typeof baseline !== 'number' || baseline <= 0) {
    console.error(`[check-test-count] baseline value invalid: ${baseline}`);
    process.exit(2);
  }

  const files = listTestFiles(TESTS_DIR);
  const observed = files.reduce((n, f) => n + countTests(f), 0);

  if (wantUpdate) {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify({
      ...baselineFile,
      baseline: observed,
      recorded_at: new Date().toISOString().slice(0, 10),
    }, null, 2) + '\n', 'utf8');
    console.error(`[check-test-count] baseline updated: ${baseline} -> ${observed}`);
    process.exit(0);
  }

  const delta = observed - baseline;
  const status = delta < -tolerance
    ? 'shrunk_beyond_tolerance'
    : delta > updateThreshold
      ? 'grew_beyond_threshold_consider_bump'
      : 'ok';

  if (wantJson) {
    process.stdout.write(JSON.stringify({
      ok: status === 'ok' || status === 'grew_beyond_threshold_consider_bump',
      verb: 'check-test-count',
      observed,
      baseline,
      tolerance,
      delta,
      status,
      files_scanned: files.length,
    }) + '\n');
  } else {
    console.log(`[check-test-count] observed=${observed} baseline=${baseline} delta=${delta >= 0 ? '+' : ''}${delta} tolerance=${tolerance} files=${files.length} status=${status}`);
  }

  if (status === 'shrunk_beyond_tolerance') {
    console.error(`[check-test-count] FAIL - test count dropped from ${baseline} to ${observed} (delta ${delta}, tolerance -${tolerance}).`);
    console.error('[check-test-count] Either a test file was accidentally removed, a test()/it() invocation was deleted, OR the baseline is stale.');
    console.error('[check-test-count] If the drop is intentional, run: node scripts/check-test-count.js --update-baseline');
    // exitCode + return (not process.exit) so the buffered stdout write above
    // (the --json result / one-line summary) drains before the event loop ends
    // — process.exit() can truncate piped output.
    process.exitCode = 1;
    return;
  }
  if (status === 'grew_beyond_threshold_consider_bump') {
    console.error(`[check-test-count] NOTICE - test count grew by ${delta} (above the ${updateThreshold} notice threshold). Consider refreshing the baseline: node scripts/check-test-count.js --update-baseline`);
  }
  process.exitCode = 0;
}

module.exports = { countTests, listTestFiles };

if (require.main === module) main();
