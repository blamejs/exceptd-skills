'use strict';

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
