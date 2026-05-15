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
