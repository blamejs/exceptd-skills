'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WorkerPool, runAll, DEFAULT_SIZE } = require('../lib/worker-pool');

// Write a tiny worker script to a tempfile; the pool requires an absolute path.
function tempWorker(body) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wp-test-')), 'worker.js');
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

require("node:test").describe("worker-pool drain settles after a respawn (round-2)", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const fs = require("node:fs"), path = require("node:path");
  const SRC = fs.readFileSync(path.join(__dirname, "..", "vendor", "blamejs", "worker-pool.js"), "utf8");
  test("_onWorkerExit settles pending drain() waiters on BOTH the respawn and no-respawn branches", () => {
    const i = SRC.indexOf("function _onWorkerExit");
    assert.ok(i > -1);
    const body = SRC.slice(i, SRC.indexOf("function _onTaskTimeout", i));
    const calls = (body.match(/_maybeResolveDrain\(\)/g) || []).length;
    assert.ok(calls >= 2, `both exit branches must call _maybeResolveDrain (drain() must not hang); found ${calls}`);
    const respawn = body.slice(body.indexOf("_spawnWorker"));
    assert.match(respawn, /_maybeResolveDrain\(\)/, "the respawn branch must settle drain after _drainQueue");
  });
});
