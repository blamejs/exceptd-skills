"use strict";
/**
 * Async job queue for exceptd's upstream fetches: per-source concurrency caps,
 * token-bucket rate limits and priority ordering (higher number runs sooner).
 * Retry classification and backoff come from vendor/blamejs/retry.js.
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
      const whole = Math.floor(add);
      this.tokens = Math.min(this.capacity, this.tokens + whole);
      // Credit only the time the granted tokens consumed; snapping lastRefill
      // to `now` drops the sub-interval remainder, so the bucket refills
      // slower than the configured tokens/windowMs.
      this.lastRefill += whole * this.refillIntervalMs;
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
    // Forwarded to the vendored withRetry, tighter than its own defaults so a
    // network blip on one source does not stall the whole refresh.
    this.retry = {
      maxAttempts: 3,
      baseDelayMs: 200,
      maxDelayMs: 5000,
      jitterFactor: 0.5,
      ...options.retry,
    };
    // Defaults to the vendored classifier: HTTP 408/425/429/5xx + Node net codes.
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
   * Enqueues { source, priority, run, signal, retry, meta }. `priority` orders
   * within a source, higher first; `retry` merges onto the queue defaults;
   * `signal` reaches the retry sleep. Resolves with run()'s result, or rejects
   * with the last error, carrying source + meta on its `queue_meta`.
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
