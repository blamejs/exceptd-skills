"use strict";
/**
 * vendor/blamejs/retry.js
 *
 * VENDORED — flattened and stripped from blamejs@1442f17 / lib/retry.js.
 * Apache-2.0 (see vendor/blamejs/LICENSE). Provenance: vendor/blamejs/_PROVENANCE.json.
 *
 * Surface preserved:
 *   - withRetry(fn, opts)        — exponential backoff + crypto jitter + AbortSignal honor
 *   - isRetryable(err)           — default classifier (HTTP + Node net codes)
 *   - backoffDelay(attempt, opts) — pure helper
 *   - CircuitBreaker             — failure-threshold / cooldown / half-open probe
 *   - DEFAULT_RETRY, DEFAULT_BREAKER
 *
 * Stripped vs. upstream:
 *   - observability event sink (every _emitEvent call → no-op)
 *   - audit hooks
 *   - lazy-require for safeAsync.sleep — replaced with a stdlib AbortSignal-aware sleep
 *   - numeric-checks dependency — replaced with two inline predicates
 *   - constants C.TIME.seconds(...) — replaced with literal ms values
 *
 * Behavior preserved verbatim:
 *   - backoff math: capped exponential * (1 - jitterFactor * U(0,1)) using crypto.randomInt
 *   - classifier semantics (HTTP 408/425/429/5xx, ECONNRESET et al)
 *   - permanent error short-circuit
 *   - signal-aware cancellation during the backoff sleep
 *
 * Do NOT hand-edit. To re-vendor, copy the upstream file, re-apply the
 * strip rules above, refresh sha256 in _PROVENANCE.json, then re-run
 * `npm run validate-vendor`.
 */

var nodeCrypto = require("crypto");

// ---- Defaults ----

var DEFAULT_RETRY = Object.freeze({
  maxAttempts:    5,
  baseDelayMs:    100,
  maxDelayMs:     10 * 1000,    // 10s
  jitterFactor:   0.5,
});

var HTTP = Object.freeze({
  BAD_REQUEST:                      0x190,
  UNAUTHORIZED:                     0x191,
  FORBIDDEN:                        0x193,
  NOT_FOUND:                        0x194,
  METHOD_NOT_ALLOWED:               0x195,
  REQUEST_TIMEOUT:                  0x198,
  CONFLICT:                         0x199,
  GONE:                             0x19a,
  LENGTH_REQUIRED:                  0x19b,
  PRECONDITION_FAILED:              0x19c,
  PAYLOAD_TOO_LARGE:                0x19d,
  URI_TOO_LONG:                     0x19e,
  UNSUPPORTED_MEDIA_TYPE:           0x19f,
  RANGE_NOT_SATISFIABLE:            0x1a0,
  EXPECTATION_FAILED:               0x1a1,
  UNPROCESSABLE_ENTITY:             0x1a6,
  TOO_EARLY:                        0x1a9,
  TOO_MANY_REQUESTS:                0x1ad,
  UNAVAILABLE_FOR_LEGAL_REASONS:    0x1c3,
  INTERNAL_SERVER_ERROR:            0x1f4,
  NOT_IMPLEMENTED:                  0x1f5,
  BAD_GATEWAY:                      0x1f6,
  SERVICE_UNAVAILABLE:              0x1f7,
  GATEWAY_TIMEOUT:                  0x1f8,
  HTTP_VERSION_NOT_SUPPORTED:       0x1f9,
});

var NON_RETRYABLE_HTTP_STATUS = new Set([
  HTTP.BAD_REQUEST, HTTP.UNAUTHORIZED, HTTP.FORBIDDEN, HTTP.NOT_FOUND,
  HTTP.METHOD_NOT_ALLOWED, HTTP.CONFLICT, HTTP.GONE, HTTP.LENGTH_REQUIRED,
  HTTP.PRECONDITION_FAILED, HTTP.PAYLOAD_TOO_LARGE, HTTP.URI_TOO_LONG,
  HTTP.UNSUPPORTED_MEDIA_TYPE, HTTP.RANGE_NOT_SATISFIABLE, HTTP.EXPECTATION_FAILED,
  HTTP.UNPROCESSABLE_ENTITY, HTTP.UNAVAILABLE_FOR_LEGAL_REASONS,
  HTTP.NOT_IMPLEMENTED, HTTP.HTTP_VERSION_NOT_SUPPORTED,
]);

var RETRYABLE_HTTP_STATUS = new Set([
  HTTP.REQUEST_TIMEOUT, HTTP.TOO_EARLY, HTTP.TOO_MANY_REQUESTS,
  HTTP.INTERNAL_SERVER_ERROR, HTTP.BAD_GATEWAY, HTTP.SERVICE_UNAVAILABLE,
  HTTP.GATEWAY_TIMEOUT,
]);

var RETRYABLE_NET_ERRORS = new Set([
  "ECONNRESET", "ECONNREFUSED", "ECONNABORTED", "ETIMEDOUT",
  "EPIPE", "EAGAIN", "ENOTFOUND", "ENETUNREACH",
]);

var STATE_CLOSED = "closed";
var STATE_OPEN   = "open";
var STATE_HALF   = "half-open";

var DEFAULT_BREAKER = Object.freeze({
  failureThreshold:  10,
  cooldownMs:        30 * 1000,
  successThreshold:  2,
});

// ---- Inlined predicates (replaces numeric-checks dep) ----

function _isPositiveInt(v) {
  return typeof v === "number" && Number.isFinite(v) && Number.isInteger(v) && v > 0;
}
function _isNonNegFinite(v) {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}
function _isAbortSignal(s) {
  return s != null && typeof s === "object" &&
         typeof s.aborted === "boolean" &&
         typeof s.addEventListener === "function";
}

// ---- Signal-aware sleep (replaces safeAsync.sleep dep) ----

function _sleep(ms, opts) {
  return new Promise(function (resolve, reject) {
    var signal = opts && opts.signal;
    if (signal && signal.aborted) {
      var abErr = new Error("aborted");
      abErr.name = "AbortError";
      reject(abErr);
      return;
    }
    var t = setTimeout(function () {
      if (signal) signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    // NOTE: deliberately do NOT unref the timer here. CLI callers
    // (refresh-external, prefetch, build-indexes --parallel) rely on the
    // retry sleep to keep the event loop alive; unref-ing causes the
    // process to exit before the backoff completes when there are no
    // other open handles.
    function onAbort() {
      clearTimeout(t);
      var err = new Error("aborted");
      err.name = "AbortError";
      reject(err);
    }
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
  });
}

// ---- Validation ----

function _validateRetryOpts(opts) {
  if (!_isPositiveInt(opts.maxAttempts)) {
    throw new TypeError("retry.withRetry: maxAttempts must be a positive integer");
  }
  if (!_isNonNegFinite(opts.baseDelayMs)) {
    throw new TypeError("retry.withRetry: baseDelayMs must be a non-negative finite number");
  }
  if (!_isNonNegFinite(opts.maxDelayMs)) {
    throw new TypeError("retry.withRetry: maxDelayMs must be a non-negative finite number");
  }
  if (typeof opts.jitterFactor !== "number" || !isFinite(opts.jitterFactor) ||
      opts.jitterFactor < 0 || opts.jitterFactor > 1) {
    throw new TypeError("retry.withRetry: jitterFactor must be a finite number in [0, 1]");
  }
  if (opts.isRetryable !== undefined && typeof opts.isRetryable !== "function") {
    throw new TypeError("retry.withRetry: isRetryable must be a function or undefined");
  }
  if (opts.onRetry !== undefined && typeof opts.onRetry !== "function") {
    throw new TypeError("retry.withRetry: onRetry must be a function or undefined");
  }
  if (opts.signal !== undefined && opts.signal !== null && !_isAbortSignal(opts.signal)) {
    throw new TypeError("retry.withRetry: signal must be an AbortSignal or undefined");
  }
}

function _validateBreakerOpts(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("retry.CircuitBreaker: name must be a non-empty string");
  }
  if (!_isPositiveInt(opts.failureThreshold)) {
    throw new TypeError("retry.CircuitBreaker: failureThreshold must be a positive integer");
  }
  if (!_isNonNegFinite(opts.cooldownMs)) {
    throw new TypeError("retry.CircuitBreaker: cooldownMs must be a non-negative finite number");
  }
  if (!_isPositiveInt(opts.successThreshold)) {
    throw new TypeError("retry.CircuitBreaker: successThreshold must be a positive integer");
  }
}

// ---- Public surface ----

function isRetryable(err) {
  if (!err) return false;
  if (err.isObjectStoreError && err.permanent) return false;
  if (err.permanent) return false;
  if (typeof err.statusCode === "number") {
    if (RETRYABLE_HTTP_STATUS.has(err.statusCode)) return true;
    if (NON_RETRYABLE_HTTP_STATUS.has(err.statusCode)) return false;
    if (err.statusCode >= 500) return true;
    return false;
  }
  if (err.code && RETRYABLE_NET_ERRORS.has(err.code)) return true;
  return false;
}

function backoffDelay(attempt, opts) {
  if (!_isPositiveInt(attempt)) {
    throw new TypeError("retry.backoffDelay: attempt must be a positive integer");
  }
  opts = opts || DEFAULT_RETRY;
  var base = opts.baseDelayMs * Math.pow(2, attempt - 1);
  var capped = Math.min(base, opts.maxDelayMs);
  var jitterDenom = 1000000;
  var jitter = capped * opts.jitterFactor * (nodeCrypto.randomInt(0, jitterDenom) / jitterDenom);
  return Math.floor(capped - jitter);
}

async function withRetry(fn, opts) {
  if (typeof fn !== "function") {
    throw new TypeError("retry.withRetry: fn must be a function, got " + typeof fn);
  }
  opts = Object.assign({}, DEFAULT_RETRY, opts || {});
  _validateRetryOpts(opts);
  var classify = (typeof opts.isRetryable === "function") ? opts.isRetryable : isRetryable;
  var lastErr = null;
  for (var attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      var retryable = classify(err);
      if (!retryable || attempt === opts.maxAttempts) {
        throw err;
      }
      var delay = backoffDelay(attempt, opts);
      if (typeof opts.onRetry === "function") {
        try { opts.onRetry({ attempt: attempt, delay: delay, error: err }); }
        catch (_cbErr) { /* observer error never crashes the retry loop */ }
      }
      await _sleep(delay, { signal: opts.signal });
    }
  }
  throw lastErr;
}

// ---- Circuit breaker ----

class CircuitBreaker {
  constructor(name, opts) {
    var merged = Object.assign({}, DEFAULT_BREAKER, opts || {});
    _validateBreakerOpts(name || "", merged);
    this.name = name;
    this.opts = merged;
    this.state = STATE_CLOSED;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
  }

  async wrap(fn) {
    if (typeof fn !== "function") {
      throw new TypeError("retry.CircuitBreaker.wrap: fn must be a function, got " + typeof fn);
    }
    if (this.state === STATE_OPEN) {
      if (Date.now() - this.openedAt >= this.opts.cooldownMs) {
        this._transition(STATE_OPEN, STATE_HALF);
      } else {
        var err = new Error("circuit breaker '" + this.name + "' is OPEN");
        err.code = "CIRCUIT_OPEN";
        err.permanent = false;
        err.isObjectStoreError = true;
        throw err;
      }
    }
    try {
      var result = await fn();
      this._onSuccess();
      return result;
    } catch (e) {
      this._onFailure(e);
      throw e;
    }
  }

  _transition(_from, to) {
    this.state = to;
  }

  _onSuccess() {
    if (this.state === STATE_HALF) {
      this.consecutiveSuccesses += 1;
      if (this.consecutiveSuccesses >= this.opts.successThreshold) {
        this._transition(STATE_HALF, STATE_CLOSED);
        this.consecutiveFailures = 0;
        this.consecutiveSuccesses = 0;
      }
    } else {
      this.consecutiveFailures = 0;
    }
  }

  _onFailure(err) {
    if (err && err.permanent) return;
    if (err && err.isObjectStoreError && err.code === "CIRCUIT_OPEN") return;
    this.consecutiveFailures += 1;
    this.consecutiveSuccesses = 0;
    if (this.state === STATE_HALF) {
      this._transition(STATE_HALF, STATE_OPEN);
      this.openedAt = Date.now();
    } else if (this.state === STATE_CLOSED && this.consecutiveFailures >= this.opts.failureThreshold) {
      this._transition(STATE_CLOSED, STATE_OPEN);
      this.openedAt = Date.now();
    }
  }

  getState() { return this.state; }

  reset() {
    this.state = STATE_CLOSED;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
  }
}

module.exports = {
  withRetry:                 withRetry,
  isRetryable:               isRetryable,
  backoffDelay:              backoffDelay,
  CircuitBreaker:            CircuitBreaker,
  DEFAULT_RETRY:             DEFAULT_RETRY,
  DEFAULT_BREAKER:           DEFAULT_BREAKER,
  RETRYABLE_HTTP_STATUS:     Array.from(RETRYABLE_HTTP_STATUS),
  NON_RETRYABLE_HTTP_STATUS: Array.from(NON_RETRYABLE_HTTP_STATUS),
  RETRYABLE_NET_ERRORS:      Array.from(RETRYABLE_NET_ERRORS),
  STATES:                    { CLOSED: STATE_CLOSED, OPEN: STATE_OPEN, HALF_OPEN: STATE_HALF },
};
