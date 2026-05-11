'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WorkerPool, runAll, DEFAULT_SIZE } = require('../lib/worker-pool');

// Write a tiny worker script to a tempfile; the pool requires an absolute path.
function tempWorker(body) {
  const p = path.join(os.tmpdir(), `wp-test-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.js`);
  fs.writeFileSync(p, body, 'utf8');
  return p;
}

test('WorkerPool: dispatches a single task and returns its result', async () => {
  const worker = tempWorker(`
    const { parentPort } = require('worker_threads');
    parentPort.on('message', (msg) => {
      try {
        const result = msg.a + msg.b;
        parentPort.postMessage({ ok: true, result });
      } catch (e) {
        parentPort.postMessage({ ok: false, message: e.message });
      }
    });
  `);
  try {
    const pool = new WorkerPool({ runnerPath: worker, size: 2 });
    const r = await pool.run({ a: 2, b: 3 });
    assert.equal(r, 5);
    await pool.terminate();
  } finally {
    fs.unlinkSync(worker);
  }
});

test('WorkerPool: parallelizes across multiple workers', async () => {
  const worker = tempWorker(`
    const { parentPort } = require('worker_threads');
    parentPort.on('message', (msg) => {
      const start = Date.now();
      // Crude busy wait so two workers MUST overlap if pooling works.
      while (Date.now() - start < msg.ms) {}
      parentPort.postMessage({ ok: true, result: msg.ms });
    });
  `);
  try {
    const t0 = Date.now();
    const results = await runAll(
      [{ ms: 80 }, { ms: 80 }, { ms: 80 }, { ms: 80 }],
      { runnerPath: worker, size: 4 }
    );
    const elapsed = Date.now() - t0;
    assert.deepEqual(results, [80, 80, 80, 80]);
    // Serial would be ~320ms; parallel with size=4 should finish in ~80-160ms.
    // Allow generous headroom for spawn cost on slow CI.
    assert.ok(elapsed < 280, `expected parallel < 280ms, got ${elapsed}ms`);
  } finally {
    fs.unlinkSync(worker);
  }
});

test('WorkerPool: surfaces worker-reported errors', async () => {
  const worker = tempWorker(`
    const { parentPort } = require('worker_threads');
    parentPort.on('message', () => {
      parentPort.postMessage({ ok: false, message: 'worker said no' });
    });
  `);
  try {
    const pool = new WorkerPool({ runnerPath: worker, size: 1 });
    await assert.rejects(async () => pool.run({}), /worker said no/);
    await pool.terminate();
  } finally {
    fs.unlinkSync(worker);
  }
});

test('WorkerPool: rejects a non-absolute scriptPath', () => {
  assert.throws(() => new WorkerPool({ runnerPath: 'relative/path.js' }), /absolute path/);
});

test('WorkerPool: DEFAULT_SIZE is clamped to a reasonable range', () => {
  assert.ok(DEFAULT_SIZE >= 1 && DEFAULT_SIZE <= 8);
});
