"use strict";
/**
 * Thin wrapper over vendor/blamejs/worker-pool.js, which supplies the bounded
 * concurrency, bounded queue, per-task timeout and worker recycling. Added
 * here: a class around the function-style `create()`, a `runAll()` that owns
 * and terminates its pool, and DEFAULT_SIZE for callers that size manually.
 *
 * At current corpus size a worker spawn costs about as much as the work, so
 * sequential builds stay the default; the pool is here for `--parallel` and
 * for the corpus growing.
 */

const os = require("os");
const vendored = require("../vendor/blamejs/worker-pool");

const DEFAULT_SIZE = Math.max(1, Math.min(8, os.cpus()?.length || 4));

class WorkerPool {
  /**
   * `opts.runnerPath` — absolute path to the worker script — is required; size,
   * maxQueueDepth, taskTimeoutMs and onExit forward to vendored.create.
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

/** Runs the tasks on a fresh pool, awaits every result, then terminates it. */
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
  // For callers that prefer the function-style API or need the size constants.
  create:                  vendored.create,
  MIN_SIZE:                vendored.MIN_SIZE,
  MAX_SIZE:                vendored.MAX_SIZE,
  DEFAULT_MAX_QUEUE_DEPTH: vendored.DEFAULT_MAX_QUEUE_DEPTH,
  MAX_QUEUE_DEPTH_CAP:     vendored.MAX_QUEUE_DEPTH_CAP,
  DEFAULT_TASK_TIMEOUT_MS: vendored.DEFAULT_TASK_TIMEOUT_MS,
  MAX_TASK_TIMEOUT_MS:     vendored.MAX_TASK_TIMEOUT_MS,
};
