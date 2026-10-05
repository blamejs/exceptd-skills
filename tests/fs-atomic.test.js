'use strict';

/**
 * lib/fs-atomic.js: renameWithRetry retries EPERM, EACCES and EBUSY, throws any
 * other error at once, and every rename in the shipped code goes through it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { renameWithRetry, TRANSIENT_RENAME_CODES } = require(path.join(ROOT, 'lib', 'fs-atomic.js'));

function failing(codes) {
  const calls = [];
  const rename = (from, to) => {
    calls.push([from, to]);
    const code = codes[calls.length - 1];
    if (code) { const e = new Error(`${code}: rename`); e.code = code; throw e; }
  };
  return { calls, rename };
}

test('renameWithRetry retries each transient code and then succeeds', () => {
  for (const code of ['EPERM', 'EACCES', 'EBUSY']) {
    const f = failing([code, code]);
    renameWithRetry('a', 'b', { rename: f.rename });
    assert.equal(f.calls.length, 3, code);
    assert.deepEqual(f.calls[2], ['a', 'b']);
  }
  assert.deepEqual([...TRANSIENT_RENAME_CODES].sort(), ['EACCES', 'EBUSY', 'EPERM']);
});

test('renameWithRetry throws any other error on the first attempt', () => {
  for (const code of ['ENOENT', 'EXDEV', 'EISDIR']) {
    const f = failing([code]);
    assert.throws(() => renameWithRetry('a', 'b', { rename: f.rename }), (e) => e.code === code);
    assert.equal(f.calls.length, 1, code);
  }
});

test('renameWithRetry throws the last transient error after the final attempt', () => {
  const f = failing(['EPERM', 'EPERM', 'EBUSY']);
  assert.throws(() => renameWithRetry('a', 'b', { rename: f.rename, attempts: 3 }), (e) => e.code === 'EBUSY');
  assert.equal(f.calls.length, 3);
});

test('renameWithRetry moves a temp file over an existing target', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-atomic-'));
  try {
    const target = path.join(dir, 'out.json');
    const tmp = `${target}.tmp`;
    fs.writeFileSync(target, '{"old":true}\n');
    fs.writeFileSync(tmp, '{"new":true}\n');
    renameWithRetry(tmp, target);
    assert.equal(fs.existsSync(tmp), false);
    assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf8')), { new: true });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('no shipped or build code calls fs.renameSync or fs.rename outside lib/fs-atomic.js', () => {
  const offenders = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p); continue; }
      if (!/\.(?:js|mjs|cjs)$/.test(e.name)) continue;
      const rel = path.relative(ROOT, p).split(path.sep).join('/');
      if (rel === 'lib/fs-atomic.js') continue;
      const src = fs.readFileSync(p, 'utf8');
      if (/\bfs\.(?:renameSync|rename|promises\.rename)\s*\(/.test(src)) offenders.push(rel);
    }
  };
  for (const d of ['lib', 'bin', 'orchestrator', 'scripts']) walk(path.join(ROOT, d));
  assert.deepEqual(offenders, []);
});
