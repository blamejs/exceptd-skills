"use strict";


// ---- routed from validate-indexes-outputs ----
require("node:test").describe("validate-indexes-outputs", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
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
});


// ---- routed from validate-indexes-source-hash-guards ----
require("node:test").describe("validate-indexes-source-hash-guards", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * The source-hash check must fail CLOSED, never crash, on a degraded tree:
 *  - a source that vanished between discovery and hashing (TOCTOU) is reported
 *    as missing, not an unhandled ENOENT that aborts the whole gate;
 *  - a non-string recorded hash (corrupted _meta.json source_hashes) is reported
 *    as drift, not a TypeError from .slice() of a non-string.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { checkSourceHashes } = require('../lib/validate-indexes.js');

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

test('a source that disappears before hashing is reported missing, not an ENOENT crash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-toctou-'));
  try {
    const absFn = (p) => path.join(dir, p);
    // recorded references a file that does not exist on disk.
    const recorded = { 'data/gone.json': 'deadbeef'.repeat(8) };
    let res;
    assert.doesNotThrow(() => {
      res = checkSourceHashes(new Set(['data/gone.json']), recorded, absFn);
    }, 'a vanished source must not throw');
    assert.equal(res.drift.length, 0);
    assert.equal(res.missing.length, 1);
    assert.match(res.missing[0], /disappeared between discovery and hashing: data\/gone\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a non-string recorded hash (corrupted _meta) is reported as drift, not a .slice() TypeError', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-corrupt-'));
  try {
    const absFn = (p) => path.join(dir, p);
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1}');
    // recorded[a.json] is null — the corrupted-metadata case.
    const recorded = { 'a.json': null };
    let res;
    assert.doesNotThrow(() => {
      res = checkSourceHashes(new Set(['a.json']), recorded, absFn);
    }, 'a non-string recorded hash must not crash on .slice()');
    assert.equal(res.missing.length, 0);
    assert.equal(res.drift.length, 1);
    assert.match(res.drift[0], /recorded entry is not a string: null/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a genuine hash match produces no drift/missing (no false positive)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-ok-'));
  try {
    const absFn = (p) => path.join(dir, p);
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1}');
    const recorded = { 'a.json': sha256(fs.readFileSync(path.join(dir, 'a.json'))) };
    const res = checkSourceHashes(new Set(['a.json']), recorded, absFn);
    assert.deepEqual(res, { drift: [], missing: [] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a real hash mismatch is still reported as drift (the guard does not mask true drift)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vidx-drift-'));
  try {
    const absFn = (p) => path.join(dir, p);
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":2}');
    const recorded = { 'a.json': sha256(Buffer.from('{"x":1}')) };
    const res = checkSourceHashes(new Set(['a.json']), recorded, absFn);
    assert.equal(res.missing.length, 0);
    assert.equal(res.drift.length, 1);
    assert.match(res.drift[0], /hash drift: a\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
});
