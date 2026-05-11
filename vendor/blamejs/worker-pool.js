"use strict";
/**
 * vendor/blamejs/worker-pool.js
 *
 * VENDORED — flattened and stripped from blamejs@1442f17 / lib/worker-pool.js.
 * Apache-2.0 (see vendor/blamejs/LICENSE). Provenance: vendor/blamejs/_PROVENANCE.json.
 *
 * Surface preserved:
 *   - create(scriptPath, opts) → { run, drain, terminate, stats }
 *   - bounded concurrency (`size`), default max(2, cpus)
 *   - bounded in-memory queue (`maxQueueDepth`, default 1024, cap 1_048_576)
 *   - per-task timeout (`taskTimeoutMs`, default 5min, cap 1h)
 *   - per-task message/transferList contract; worker reply envelope { ok, result } or { ok:false, message }
 *   - worker recycle on uncaught error / timeout / exit
 *   - drain() resolves when no in-flight + queue empty
 *
 * Stripped vs. upstream:
 *   - WorkerPoolError class — replaced with vanilla Error tagged with a `code` string
 *     (e.g. "workerpool/queue-full")
 *   - validate-opts dependency — replaced with inline option-whitelist + type checks
 *   - numeric-bounds dependency — replaced with two inline predicates
 *   - audit event sink — `_emitAudit` is a no-op stub (audit chain isn't part of exceptd)
 *   - constants C.BYTES.kib / C.TIME.minutes — replaced with literal int values
 *
 * Worker contract (operator-supplied script at scriptPath, unchanged):
 *
 *   var { parentPort } = require("node:worker_threads");
 *   parentPort.on("message", function (msg) {
 *     try {
 *       var result = doWork(msg);
 *       parentPort.postMessage({ ok: true, result: result });
 *     } catch (e) {
 *       parentPort.postMessage({ ok: false, message: e.message });
 *     }
 *   });
 *
 * Do NOT hand-edit. To re-vendor, copy the upstream file, re-apply the
 * strip rules above, refresh sha256 in _PROVENANCE.json, then re-run
 * `npm run validate-vendor`.
 */

var os = require("node:os");
var path = require("node:path");

var MIN_SIZE = 1;
var MAX_SIZE = 256;
var DEFAULT_MAX_QUEUE_DEPTH = 1024;
var MAX_QUEUE_DEPTH_CAP = 1048576;
var DEFAULT_TASK_TIMEOUT_MS = 5 * 60 * 1000;        // 5 min
var MAX_TASK_TIMEOUT_MS = 60 * 60 * 1000;           // 1 hour

function _err(code, message) {
  var e = new Error(message);
  e.code = code;
  return e;
}

function _isPositiveInt(v) {
  return typeof v === "number" && Number.isFinite(v) && Number.isInteger(v) && v > 0;
}

function _requireNonEmptyString(v, label, code) {
  if (typeof v !== "string" || v.length === 0) {
    throw _err(code, label + ": must be a non-empty string");
  }
}

function _validateOptsWhitelist(opts, allowed, label) {
  if (opts === null || opts === undefined) return;
  if (typeof opts !== "object") {
    throw _err("workerpool/bad-opts", label + ": opts must be a plain object");
  }
  for (var k in opts) {
    if (Object.prototype.hasOwnProperty.call(opts, k) && allowed.indexOf(k) === -1) {
      throw _err("workerpool/bad-opts", label + ": unknown opt \"" + k + "\"; allowed: " + allowed.join(", "));
    }
  }
}

function _validateScriptPath(scriptPath) {
  _requireNonEmptyString(scriptPath, "workerPool.create: scriptPath", "workerpool/bad-script-path");
  if (!path.isAbsolute(scriptPath)) {
    throw _err("workerpool/bad-script-path",
      "workerPool.create: scriptPath must be an absolute path; got " + JSON.stringify(scriptPath));
  }
  if (/^data:/i.test(scriptPath) || /^eval:/i.test(scriptPath)) {
    throw _err("workerpool/bad-script-path",
      "workerPool.create: scriptPath must be a filesystem path, not an eval/data URL");
  }
}

function _emitAudit(_action, _outcome, _metadata) {
  // No-op stub — upstream uses an audit chain that exceptd does not have.
  // Preserved as a function so the rest of the file matches upstream shape.
}

function create(scriptPath, opts) {
  opts = opts || {};
  _validateOptsWhitelist(opts, ["size", "onExit", "maxQueueDepth", "taskTimeoutMs"], "workerPool.create");
  _validateScriptPath(scriptPath);

  var defaultSize = Math.max(2, (os.cpus() || []).length || 2);
  var size = (opts.size === undefined) ? defaultSize : opts.size;
  if (!_isPositiveInt(size) || size < MIN_SIZE || size > MAX_SIZE) {
    throw _err("workerpool/bad-size",
      "workerPool.create: opts.size must be a positive finite integer in [" +
      MIN_SIZE + ".." + MAX_SIZE + "]");
  }

  var maxQueueDepth = (opts.maxQueueDepth === undefined) ? DEFAULT_MAX_QUEUE_DEPTH : opts.maxQueueDepth;
  if (!_isPositiveInt(maxQueueDepth) || maxQueueDepth > MAX_QUEUE_DEPTH_CAP) {
    throw _err("workerpool/bad-max-queue-depth",
      "workerPool.create: opts.maxQueueDepth must be a positive finite integer <= " + MAX_QUEUE_DEPTH_CAP);
  }

  var taskTimeoutMs = (opts.taskTimeoutMs === undefined) ? DEFAULT_TASK_TIMEOUT_MS : opts.taskTimeoutMs;
  if (!_isPositiveInt(taskTimeoutMs) || taskTimeoutMs > MAX_TASK_TIMEOUT_MS) {
    throw _err("workerpool/bad-task-timeout",
      "workerPool.create: opts.taskTimeoutMs must be a positive finite integer <= " + MAX_TASK_TIMEOUT_MS);
  }

  var onExit = opts.onExit;
  if (onExit !== undefined && onExit !== null && typeof onExit !== "function") {
    throw _err("workerpool/bad-on-exit", "workerPool.create: opts.onExit must be a function");
  }

  var workerThreads;
  try { workerThreads = require("node:worker_threads"); }
  catch (_e) {
    throw _err("workerpool/no-worker-threads",
      "workerPool.create: node:worker_threads is unavailable in this runtime");
  }

  var workerSlots = [];
  var workerSeq = 0;
  var taskSeq = 0;
  var queue = [];
  var totalTasks = 0;
  var totalErrors = 0;
  var terminated = false;
  var drainResolvers = [];

  function _spawnWorker() {
    var id = ++workerSeq;
    var worker;
    try {
      worker = new workerThreads.Worker(scriptPath);
    } catch (eSpawn) {
      _emitAudit("workerpool.spawn.failed", "failure", {
        scriptPath: scriptPath,
        message:    (eSpawn && eSpawn.message) || String(eSpawn),
      });
      throw _err("workerpool/spawn-failed",
        "workerPool.create: failed to spawn worker: " + (eSpawn && eSpawn.message));
    }
    var slot = {
      id:             id,
      worker:         worker,
      busy:           false,
      currentTaskId:  null,
      currentTimer:   null,
      currentTask:    null,
    };
    worker.on("message", function (msg) { _onWorkerMessage(slot, msg); });
    worker.on("error",   function (err) { _onWorkerError(slot, err); });
    worker.on("exit",    function (code) { _onWorkerExit(slot, code); });
    workerSlots.push(slot);
    _emitAudit("workerpool.created", "success", { workerId: id, size: size });
    return slot;
  }

  function _findIdleSlot() {
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (!workerSlots[i].busy && !workerSlots[i].recycling) return workerSlots[i];
    }
    return null;
  }

  function _dispatch(slot, task) {
    slot.busy = true;
    slot.currentTaskId = task.id;
    slot.currentTask = task;
    slot.currentTimer = setTimeout(function () {
      _onTaskTimeout(slot);
    }, taskTimeoutMs);
    if (slot.currentTimer && typeof slot.currentTimer.unref === "function") {
      slot.currentTimer.unref();
    }
    try {
      slot.worker.postMessage(task.message, task.transferList || undefined);
    } catch (ePost) {
      _finishTask(slot, true,
        _err("workerpool/post-failed", "workerPool.run: postMessage failed: " + (ePost && ePost.message)));
    }
  }

  function _drainQueue() {
    while (!terminated && queue.length > 0) {
      var slot = _findIdleSlot();
      if (!slot) return;
      var task = queue.shift();
      _dispatch(slot, task);
    }
  }

  function _finishTask(slot, isError, payloadOrError) {
    var task = slot.currentTask;
    if (!task) return;
    if (slot.currentTimer) { clearTimeout(slot.currentTimer); slot.currentTimer = null; }
    slot.busy = false;
    slot.currentTaskId = null;
    slot.currentTask = null;
    totalTasks += 1;
    if (isError) {
      totalErrors += 1;
      task.reject(payloadOrError);
    } else {
      task.resolve(payloadOrError);
    }
    _maybeResolveDrain();
    _drainQueue();
  }

  function _onWorkerMessage(slot, msg) {
    if (!slot.currentTask) return;
    if (!msg || typeof msg !== "object" || typeof msg.ok !== "boolean") {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId, reason: "workerpool/worker-bad-message",
      });
      _finishTask(slot, true,
        _err("workerpool/worker-bad-message",
          "workerPool: worker reply was not { ok, ... } envelope-shaped"));
      return;
    }
    if (msg.ok) {
      _emitAudit("workerpool.task.completed", "success", {
        workerId: slot.id, taskId: slot.currentTaskId,
      });
      _finishTask(slot, false, msg.result);
    } else {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId,
        reason: "workerpool/task-failed",
        message: msg.message || "",
      });
      _finishTask(slot, true,
        _err("workerpool/task-failed",
          "workerPool: worker reported failure: " + (msg.message || "(no message)")));
    }
  }

  function _onWorkerError(slot, err) {
    var failingTask = slot.currentTask;
    _emitAudit("workerpool.task.failed", "failure", {
      workerId: slot.id, taskId: slot.currentTaskId,
      reason:   "workerpool/worker-error",
      message:  (err && err.message) || String(err),
    });
    if (failingTask) {
      _finishTask(slot, true,
        _err("workerpool/worker-error",
          "workerPool: worker errored: " + (err && err.message ? err.message : String(err))));
    }
    _recycleWorker(slot);
  }

  function _onWorkerExit(slot, code) {
    var failingTask = slot.currentTask;
    if (failingTask) {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId,
        reason:   "workerpool/worker-exit", code: code,
      });
      _finishTask(slot, true,
        _err("workerpool/worker-exit",
          "workerPool: worker exited (code " + code + ") mid-task"));
    }
    _emitAudit("workerpool.terminated", "success", { workerId: slot.id, code: code });
    if (typeof onExit === "function") {
      try { onExit(code, slot.id); } catch (_e) { /* operator hook best-effort */ }
    }
    var idx = workerSlots.indexOf(slot);
    if (idx !== -1) workerSlots.splice(idx, 1);
    if (!terminated && workerSlots.length < size) {
      try { _spawnWorker(); } catch (_e) { /* already audited */ }
      _drainQueue();
    } else {
      _maybeResolveDrain();
    }
  }

  function _onTaskTimeout(slot) {
    var taskId = slot.currentTaskId;
    _emitAudit("workerpool.task.timeout", "failure", {
      workerId: slot.id, taskId: taskId, taskTimeoutMs: taskTimeoutMs,
    });
    var failingTask = slot.currentTask;
    if (failingTask) {
      _finishTask(slot, true,
        _err("workerpool/timeout",
          "workerPool: task " + taskId + " exceeded taskTimeoutMs=" + taskTimeoutMs));
    }
    _recycleWorker(slot);
  }

  function _recycleWorker(slot) {
    slot.busy = true;
    slot.recycling = true;
    try { slot.worker.terminate(); } catch (_e) { /* best-effort */ }
  }

  function _maybeResolveDrain() {
    if (drainResolvers.length === 0) return;
    var anyBusy = false;
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (workerSlots[i].busy) { anyBusy = true; break; }
    }
    if (anyBusy || queue.length > 0) return;
    var pending = drainResolvers.splice(0, drainResolvers.length);
    for (var j = 0; j < pending.length; j += 1) {
      try { pending[j](); } catch (_e) { /* best-effort */ }
    }
  }

  function run(message, transferList) {
    if (terminated) {
      return Promise.reject(_err("workerpool/terminated", "workerPool.run: pool has been terminated"));
    }
    if (transferList !== undefined && transferList !== null && !Array.isArray(transferList)) {
      return Promise.reject(_err("workerpool/bad-transfer-list",
        "workerPool.run: transferList must be an array if supplied"));
    }
    if (queue.length >= maxQueueDepth) {
      return Promise.reject(_err("workerpool/queue-full",
        "workerPool.run: queue is full (depth=" + queue.length + " >= maxQueueDepth=" + maxQueueDepth + ")"));
    }
    var taskId = ++taskSeq;
    return new Promise(function (resolve, reject) {
      var task = {
        id:           taskId,
        message:      message,
        transferList: transferList || null,
        resolve:      resolve,
        reject:       reject,
      };
      var slot = _findIdleSlot();
      if (slot) {
        _dispatch(slot, task);
      } else {
        queue.push(task);
      }
    });
  }

  function drain() {
    return new Promise(function (resolve) {
      var anyBusy = false;
      for (var i = 0; i < workerSlots.length; i += 1) {
        if (workerSlots[i].busy) { anyBusy = true; break; }
      }
      if (!anyBusy && queue.length === 0) { resolve(); return; }
      drainResolvers.push(resolve);
    });
  }

  function terminate() {
    terminated = true;
    var pending = queue.splice(0, queue.length);
    for (var i = 0; i < pending.length; i += 1) {
      try {
        pending[i].reject(_err("workerpool/terminated",
          "workerPool.terminate: task aborted before dispatch"));
      } catch (_e) { /* best-effort */ }
    }
    var promises = [];
    for (var j = 0; j < workerSlots.length; j += 1) {
      var slot = workerSlots[j];
      if (slot.currentTimer) { clearTimeout(slot.currentTimer); slot.currentTimer = null; }
      try { promises.push(slot.worker.terminate()); }
      catch (_e) { /* best-effort */ }
    }
    return Promise.all(promises).then(function () { /* swallow */ });
  }

  function stats() {
    var busy = 0;
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (workerSlots[i].busy) busy += 1;
    }
    return {
      size:        workerSlots.length,
      busy:        busy,
      idle:        workerSlots.length - busy,
      queued:      queue.length,
      totalTasks:  totalTasks,
      totalErrors: totalErrors,
    };
  }

  for (var k = 0; k < size; k += 1) _spawnWorker();

  return {
    run:       run,
    drain:     drain,
    terminate: terminate,
    stats:     stats,
  };
}

module.exports = {
  create:                  create,
  MIN_SIZE:                MIN_SIZE,
  MAX_SIZE:                MAX_SIZE,
  DEFAULT_MAX_QUEUE_DEPTH: DEFAULT_MAX_QUEUE_DEPTH,
  MAX_QUEUE_DEPTH_CAP:     MAX_QUEUE_DEPTH_CAP,
  DEFAULT_TASK_TIMEOUT_MS: DEFAULT_TASK_TIMEOUT_MS,
  MAX_TASK_TIMEOUT_MS:     MAX_TASK_TIMEOUT_MS,
};
