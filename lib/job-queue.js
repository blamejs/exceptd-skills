"use strict";
/**
 * lib/job-queue.js
 *
 * Async job queue specialized for exceptd's upstream-fetch workloads. The
 * generic retry semantics (HTTP + Node net classifier, exponential
 * backoff with crypto jitter, AbortSignal-aware sleep) live in the
 * vendored blamejs retry primitive — this module wraps it with the
 * per-source concurrency caps + token-bucket rate limits + priority
 * ordering specific to the KEV / EPSS / NVD / IETF / GitHub workloads.
 *
 *   - per-source concurrency caps (max in-flight)
 *   - token-bucket rate limiting (max requests per window)
 *   - priority ordering (higher number = sooner)
 *   - retry classification + backoff delegated to vendor/blamejs/retry.js
 *   - per-source stats (queued / in_flight / completed / failed / retried)
 *
 * No npm deps. Node 24 stdlib + vendored retry.js.
 */

const retry = require("../vendor/blamejs/retry");

class TokenBucket {
  constructor({ tokens, windowMs }) {
    this.capacity = tokens;
    this.tokens = tokens;
    this.windowMs = windowMs;
    this.refillIntervalMs = windowMs / tokens;
    this.lastRefill = Date.now();
  }
  refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed <= 0) return;
    const add = elapsed / this.refillIntervalMs;
    if (add >= 1) {
      this.tokens = Math.min(this.capacity, this.tokens + Math.floor(add));
      this.lastRefill = now;
    }
  }
  tryTake() {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil(this.refillIntervalMs - (Date.now() - this.lastRefill)));
  }
}

class JobQueue {
  constructor(options = {}) {
    const defaults = { concurrency: 4 };
    this.sources = options.sources || { default: defaults };
    // Retry options forwarded to vendored withRetry. Defaults are tighter
    // than withRetry's own DEFAULT_RETRY so a network blip on KEV/EPSS
    // doesn't stall the whole refresh by 80s.
    this.retry = {
      maxAttempts: 3,
      baseDelayMs: 200,
      maxDelayMs: 5000,
      jitterFactor: 0.5,
      ...options.retry,
    };
    // Caller may override the retry classifier. Default is the vendored
    // blamejs classifier (HTTP 408/425/429/5xx + Node net codes), which
    // matches everything the upstream sources emit.
    this.isRetryable = options.isRetryable || retry.isRetryable;
    this._perSource = {};
    for (const [name, cfg] of Object.entries(this.sources)) {
      this._perSource[name] = {
        cfg: { concurrency: defaults.concurrency, ...cfg },
        pending: [],
        inFlight: 0,
        bucket: cfg.rate ? new TokenBucket(cfg.rate) : null,
        stats: { queued: 0, in_flight: 0, completed: 0, failed: 0, retried: 0 },
      };
    }
    this._drainResolvers = [];
    this._closed = false;
  }

  /**
   * Enqueue a job.
   * @param {object} job
   *   - source:   source key from the sources map (default: "default")
   *   - priority: integer; higher runs sooner within a source
   *   - run:      async () => result
   *   - signal:   optional AbortSignal forwarded to retry.withRetry sleep
   *   - retry:    per-job retry override (merged onto queue defaults)
   *   - meta:     freeform metadata attached to stats / errors
   */
  add(job) {
    if (this._closed) return Promise.reject(new Error("JobQueue is closed"));
    const source = job.source || "default";
    const bucket = this._perSource[source] || this._perSource.default;
    if (!bucket) {
      return Promise.reject(new Error(`JobQueue: unknown source "${source}" and no default configured`));
    }
    return new Promise((resolve, reject) => {
      const entry = {
        source,
        priority: typeof job.priority === "number" ? job.priority : 0,
        run: job.run,
        retry: { ...this.retry, ...(job.retry || {}) },
        signal: job.signal,
        meta: job.meta || {},
        resolve,
        reject,
      };
      bucket.pending.push(entry);
      bucket.pending.sort((a, b) => b.priority - a.priority);
      bucket.stats.queued++;
      this._tick(source);
    });
  }

  _tick(source) {
    const bucket = this._perSource[source];
    if (!bucket) return;
    while (bucket.inFlight < bucket.cfg.concurrency && bucket.pending.length > 0) {
      if (bucket.bucket) {
        const waitMs = bucket.bucket.tryTake();
        if (waitMs > 0) {
          setTimeout(() => this._tick(source), waitMs);
          break;
        }
      }
      const entry = bucket.pending.shift();
      bucket.stats.queued--;
      bucket.inFlight++;
      bucket.stats.in_flight = bucket.inFlight;
      this._run(entry).finally(() => {
        bucket.inFlight--;
        bucket.stats.in_flight = bucket.inFlight;
        this._tick(source);
        if (this._allIdle()) this._notifyDrain();
      });
    }
  }

  async _run(entry) {
    const bucket = this._perSource[entry.source];
    const onRetry = () => { bucket.stats.retried++; };
    try {
      const result = await retry.withRetry(
        () => entry.run(),
        {
          maxAttempts: entry.retry.maxAttempts,
          baseDelayMs: entry.retry.baseDelayMs,
          maxDelayMs: entry.retry.maxDelayMs,
          jitterFactor: entry.retry.jitterFactor,
          isRetryable: this.isRetryable,
          onRetry,
          signal: entry.signal,
        }
      );
      bucket.stats.completed++;
      entry.resolve(result);
    } catch (err) {
      bucket.stats.failed++;
      try { err.queue_meta = { source: entry.source, ...entry.meta }; } catch { /* readonly */ }
      entry.reject(err);
    }
  }

  _allIdle() {
    for (const b of Object.values(this._perSource)) {
      if (b.inFlight > 0 || b.pending.length > 0) return false;
    }
    return true;
  }

  _notifyDrain() {
    for (const r of this._drainResolvers) r();
    this._drainResolvers = [];
  }

  drain() {
    if (this._allIdle()) return Promise.resolve();
    return new Promise((resolve) => this._drainResolvers.push(resolve));
  }

  stats() {
    const out = {};
    for (const [name, b] of Object.entries(this._perSource)) out[name] = { ...b.stats };
    return out;
  }

  close() {
    this._closed = true;
  }
}

module.exports = { JobQueue, TokenBucket, isRetryable: retry.isRetryable };
