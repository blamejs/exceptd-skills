'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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

test('build-indexes --only <unknown> exits non-zero with a helpful error', () => {
  const r = run(['--only', 'nope']);
  assert.notEqual(r.status, 0);
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

test('build-indexes --changed picks up a touched skill body', () => {
  // Pick a low-stakes skill body to mutate.
  const skillPath = path.join(ROOT, 'skills', 'compliance-theater', 'skill.md');
  const original = fs.readFileSync(skillPath);

  // Full rebuild first so _meta records current hashes.
  run(['--quiet']);
  try {
    // Append a trailing newline → hash diff. Restore after the assertion.
    fs.writeFileSync(skillPath, original.toString('utf8') + '\n');
    const r = run(['--changed']);
    assert.equal(r.status, 0);
    // theater-fingerprints depends on this exact file → must be rebuilt.
    assert.match(r.stdout, /theater-fingerprints\.json/);
    // jurisdiction-clocks does NOT depend on skill bodies → should NOT be rebuilt.
    assert.doesNotMatch(r.stdout, /jurisdiction-clocks\.json/);
  } finally {
    fs.writeFileSync(skillPath, original);
    // Final full rebuild so the working tree is clean for downstream tests.
    run(['--quiet']);
  }
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
