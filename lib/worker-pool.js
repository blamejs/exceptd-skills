"use strict";
/**
 * lib/worker-pool.js
 *
 * Thin convenience wrapper over the vendored blamejs worker-pool primitive.
 * The vendored module (vendor/blamejs/worker-pool.js) provides:
 *
 *   - bounded concurrency, defaults to max(2, cpus)
 *   - bounded in-memory queue (default 1024 depth)
 *   - per-task timeout (default 5min)
 *   - worker recycle on uncaught error / timeout / exit
 *
 * What this wrapper adds:
 *
 *   - WorkerPool class around the function-style `create()` API for
 *     callers that prefer an instance
 *   - runAll(tasks, opts) helper that runs an array of tasks through a
 *     fresh pool and terminates it when done
 *   - DEFAULT_SIZE re-export for callers that want to size manually
 *
 * Honest framing: at v0.7.0 corpus size (38 skills, 10 catalogs, ~150ms
 * total build time) worker-thread spawn cost is comparable to the work
 * itself. The pool is here so the architecture scales as the corpus
 * grows and so users can experiment with `--parallel`. Sequential builds
 * remain the default.
 */

const os = require("os");
const vendored = require("../vendor/blamejs/worker-pool");

const DEFAULT_SIZE = Math.max(1, Math.min(8, os.cpus()?.length || 4));

class WorkerPool {
  /**
   * @param {object} opts
   *   - runnerPath: absolute path to the worker script (required)
   *   - size, maxQueueDepth, taskTimeoutMs, onExit — forwarded to vendored.create
   */
  constructor(opts = {}) {
    if (!opts.runnerPath) throw new Error("WorkerPool: runnerPath is required");
    const { runnerPath, ...rest } = opts;
    if (rest.size === undefined) rest.size = DEFAULT_SIZE;
    this._pool = vendored.create(runnerPath, rest);
  }
  run(message, transferList) {
    return this._pool.run(message, transferList);
  }
  drain() {
    return this._pool.drain();
  }
  terminate() {
    return this._pool.terminate();
  }
  stats() {
    return this._pool.stats();
  }
}

/**
 * Run a list of tasks against a fresh pool, await all results, terminate.
 */
async function runAll(tasks, opts = {}) {
  const pool = new WorkerPool(opts);
  try {
    return await Promise.all(tasks.map((t) => pool.run(t)));
  } finally {
    await pool.terminate();
  }
}

module.exports = {
  WorkerPool,
  runAll,
  DEFAULT_SIZE,
  // Re-export vendored primitives for callers that prefer the function-style API
  // or need the size constants.
  create:                  vendored.create,
  MIN_SIZE:                vendored.MIN_SIZE,
  MAX_SIZE:                vendored.MAX_SIZE,
  DEFAULT_MAX_QUEUE_DEPTH: vendored.DEFAULT_MAX_QUEUE_DEPTH,
  MAX_QUEUE_DEPTH_CAP:     vendored.MAX_QUEUE_DEPTH_CAP,
  DEFAULT_TASK_TIMEOUT_MS: vendored.DEFAULT_TASK_TIMEOUT_MS,
  MAX_TASK_TIMEOUT_MS:     vendored.MAX_TASK_TIMEOUT_MS,
};
