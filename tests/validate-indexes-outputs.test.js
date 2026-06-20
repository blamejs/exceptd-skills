'use strict';

/**
 * idx freshness gate: the derived index OUTPUTS must be checked for
 * existence + parseability, not just the source-hash table. A clean source
 * tree with a deleted/truncated/corrupted index file previously passed the
 * freshness gate as "current" because only source hashes were compared.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const { verifyOutputs } = require('../lib/validate-indexes.js');

test('verifyOutputs: passes when every named output exists and parses', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-ok-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1}');
    fs.writeFileSync(path.join(dir, 'b.json'), '[]');
    assert.deepEqual(verifyOutputs(dir, ['a.json', 'b.json']), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyOutputs: reports a deleted output file (source-hash drift would miss it)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-missing-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.json'), '{}');
    const issues = verifyOutputs(dir, ['a.json', 'gone.json']);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /derived index file missing: data\/_indexes\/gone\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyOutputs: reports a truncated/corrupt output that no longer parses', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-corrupt-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1'); // truncated — invalid JSON
    const issues = verifyOutputs(dir, ['a.json']);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /does not parse: data\/_indexes\/a\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validate-indexes passes on the real tree and records the outputs list', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-indexes.js')], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `validate-indexes must pass on the current tree; stderr: ${r.stderr.slice(0, 400)}`);
  const meta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', '_indexes', '_meta.json'), 'utf8'));
  assert.ok(Array.isArray(meta.outputs) && meta.outputs.length >= 1,
    '_meta.json must record the derived index outputs list');
});
