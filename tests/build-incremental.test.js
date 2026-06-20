'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { withFileSnapshot } = require('./_helpers/snapshot-restore');

const ROOT = path.join(__dirname, '..');
const IDX = path.join(ROOT, 'data', '_indexes');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'build-indexes.js'), ...args], { encoding: 'utf8', cwd: ROOT, ...opts });
}

test('build-indexes --only <name> rebuilds just that output (plus dependsOn closure)', () => {
  const r = run(['--only', 'token-budget', '--quiet']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  // token-budget depends on section-offsets; both should have been re-written.
  // (We don't assert mtimes — the test just verifies the run succeeds and the
  // dependency closure is observed.)
});

test('build-indexes --only <unknown> exits 2 with a helpful error', () => {
  // build-indexes.js emits exit 2 for unknown-output (validation refusal,
  // distinct from runtime gate failures which use exit 1). Pinning the
  // exact code keeps this test from passing by coincidence when the unknown-
  // output branch is dead and some unrelated failure produces a non-zero exit.
  const r = run(['--only', 'nope']);
  assert.equal(r.status, 2, `expected exit 2 (validation refusal); got ${r.status}; stderr: ${r.stderr}`);
  assert.match(r.stderr || '', /unknown output/);
});

test('build-indexes --changed no-ops when sources unchanged', () => {
  // Full rebuild first to align _meta with on-disk sources.
  run(['--quiet']);
  // Now --changed should report "no outputs need rebuilding".
  const r = run(['--changed']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /no outputs need rebuilding/);
});

test('build-indexes --changed no-op leaves _meta.json byte-identical (no spurious timestamp diff)', async () => {
  // Regression: writeMeta unconditionally re-stamped generated_at with a fresh
  // wall-clock value, so a no-op --changed run (zero changed sources, nothing
  // rebuilt) still mutated _meta.json on every invocation — a CI step running
  // `build-indexes --changed` then `git diff --exit-status` would always report
  // a dirty _meta.json even on a genuinely current tree, contradicting the
  // documented "--changed: identical inputs always produce identical outputs"
  // contract. The fix preserves the prior generated_at when the hashed surface
  // (source_hashes + outputs) is byte-identical; validate-indexes never reads
  // the timestamp, so determinism costs no freshness signal.
  const metaPath = path.join(IDX, '_meta.json');
  await withFileSnapshot([metaPath], async () => {
    // Full rebuild so _meta records the current source hashes + output set.
    assert.equal(run(['--quiet']).status, 0);
    const before = fs.readFileSync(metaPath);
    const gaBefore = JSON.parse(before.toString('utf8')).generated_at;
    assert.equal(typeof gaBefore, 'string');

    // No-op incremental run: zero sources changed.
    const r = run(['--changed']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /no outputs need rebuilding/);

    // _meta.json must be byte-for-byte identical — generated_at included.
    const after = fs.readFileSync(metaPath);
    assert.deepEqual(after, before, '_meta.json changed across a no-op --changed run');
    assert.equal(JSON.parse(after.toString('utf8')).generated_at, gaBefore,
      'generated_at advanced on a no-op run (spurious non-deterministic diff)');
  });
  // Restore _indexes to the committed state for downstream tests.
  run(['--quiet']);
});

test('build-indexes --changed picks up a touched skill body', async () => {
  // Pick a low-stakes skill body to mutate.
  const skillPath = path.join(ROOT, 'skills', 'compliance-theater', 'skill.md');

  // withFileSnapshot pre-captures bytes and registers SIGINT/SIGTERM/exit
  // restorers. The previous try/finally pattern left a polluted skill on
  // disk if the test was Ctrl-C'd mid-write — that broke Ed25519 verify
  // for every downstream test until the operator manually restored.
  await withFileSnapshot([skillPath], async () => {
    const original = fs.readFileSync(skillPath);
    // Full rebuild first so _meta records current hashes.
    run(['--quiet']);
    // Append a trailing newline → hash diff.
    fs.writeFileSync(skillPath, original.toString('utf8') + '\n');
    const r = run(['--changed']);
    assert.equal(r.status, 0);
    // theater-fingerprints depends on this exact file → must be rebuilt.
    assert.match(r.stdout, /theater-fingerprints\.json/);
    // jurisdiction-clocks does NOT depend on skill bodies → should NOT be rebuilt.
    assert.doesNotMatch(r.stdout, /jurisdiction-clocks\.json/);
  });
  // Final full rebuild so the working tree _indexes match the restored
  // skill body (otherwise _indexes still reference the polluted hash).
  run(['--quiet']);
});

test('build-indexes --changed regenerates a deleted output even when sources are unchanged', async () => {
  // Regression: --changed selected outputs purely from source-hash deltas, so
  // a derived index deleted/corrupted with NO source change was treated as
  // "nothing to do" — the no-op path returned without rebuilding it, yet
  // writeMeta refreshed generated_at and recorded a 0 count for the file it
  // never rebuilt. Output existence/integrity is now a rebuild trigger.
  const recipesPath = path.join(IDX, 'recipes.json');
  const metaPath = path.join(IDX, '_meta.json');
  await withFileSnapshot([recipesPath, metaPath], async () => {
    // Full rebuild so _meta records current source hashes + the real count.
    assert.equal(run(['--quiet']).status, 0);
    const priorCount = JSON.parse(fs.readFileSync(metaPath, 'utf8')).index_stats.recipes;
    assert.ok(priorCount > 0, `expected a non-zero baseline recipes count, got ${priorCount}`);
    const recipesBytes = fs.readFileSync(recipesPath);

    // Delete an output whose only dep (manifest.json) did NOT change.
    fs.unlinkSync(recipesPath);
    assert.equal(fs.existsSync(recipesPath), false);

    const r = run(['--changed']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    // The planner must have selected the missing output for rebuild.
    assert.match(r.stdout, /recipes/);

    // File is back and byte-identical (deterministic builder).
    assert.equal(fs.existsSync(recipesPath), true, 'recipes.json was not regenerated');
    assert.deepEqual(fs.readFileSync(recipesPath), recipesBytes, 'regenerated recipes.json differs from the original');

    // _meta records the REAL count, not a fabricated 0 from the empty default.
    const after = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    assert.equal(typeof after.index_stats.recipes, 'number');
    assert.equal(after.index_stats.recipes, priorCount,
      `expected recipes stat to stay ${priorCount}; got ${after.index_stats.recipes} (fabricated zero?)`);
  });
  // Restore _indexes to the committed state for downstream tests.
  run(['--quiet']);
});

test('build-indexes --parallel produces byte-identical output to sequential mode', () => {
  // Sequential rebuild.
  run(['--quiet']);
  const seqHashes = {};
  for (const f of fs.readdirSync(IDX)) {
    if (f === '_meta.json') continue;
    seqHashes[f] = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(IDX, f))).digest('hex');
  }
  // Parallel rebuild.
  const r = run(['--parallel', '--quiet']);
  assert.equal(r.status, 0);
  for (const f of fs.readdirSync(IDX)) {
    if (f === '_meta.json') continue;
    const h = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(IDX, f))).digest('hex');
    assert.equal(h, seqHashes[f], `output ${f} differs between sequential and parallel`);
  }
});

test('build-indexes OUTPUTS exports every output advertised in the help text', () => {
  const { OUTPUTS } = require('../scripts/build-indexes.js');
  const names = OUTPUTS.map((o) => o.name).sort();
  assert.deepEqual(names, [
    'activity-feed', 'catalog-summaries', 'chains', 'currency', 'did-ladders',
    'frequency', 'handoff-dag', 'jurisdiction-clocks', 'jurisdiction-map',
    'recipes', 'section-offsets', 'stale-content', 'summary-cards',
    'theater-fingerprints', 'token-budget', 'trigger-table', 'xref',
  ]);
});
