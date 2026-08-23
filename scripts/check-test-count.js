#!/usr/bin/env node
'use strict';

/**
 * Canonical-test-count predeploy gate: catches test-set shrinkage the lint and
 * diff-coverage gates cannot see.
 *
 * Counts DECLARATIONS statically across `tests/*.test.js` — `test(` and `it(`
 * with their `.only` / `.skip` variants. `describe(` is NOT counted: a container
 * is not a test. Blind spot: a test neutered in place still counts as one.
 *
 * exit 0 at or above baseline minus tolerance, 1 when it drops further, 2 when
 * the baseline file is missing or malformed.
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
  // Strip block comments first: commenting a test out is the usual way to
  // disable one, and counting it anyway defeats the gate.
  text = text.replace(/\/\*[\s\S]*?\*\//g, '');
  let count = 0;
  for (const rawLine of text.split('\n')) {
    // Blank string and template bodies first, so a `test(` inside a string
    // literal is not read as a declaration — a phantom inflates the baseline.
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

  // Branch on the read RESULT, never on a prior existsSync probe: ENOENT from
  // this single read IS the "missing" signal.
  let baselineRaw = null;
  try {
    baselineRaw = fs.readFileSync(BASELINE_PATH, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`[check-test-count] cannot read baseline: ${e.message}`);
      process.exit(2);
    }
    if (wantUpdate) {
      const files = listTestFiles(TESTS_DIR);
      const observed = files.reduce((n, f) => n + countTests(f), 0);
      // Exclusive create: EEXIST rather than clobbering a concurrent run's baseline.
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
    // `process.exitCode`, not `process.exit()`: the buffered stdout write must drain.
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
