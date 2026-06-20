'use strict';

// Regression: prefetch's timedFetch must tag HTTP failures with the field the
// vendored retry classifier actually reads (err.statusCode), so a transient
// 429/5xx from a KEV/NVD/EPSS/OSV source routes through the job-queue backoff
// instead of being dropped on the first hiccup. Earlier it set only err.status,
// which vendor/blamejs/retry.js isRetryable never inspects — every retryable
// HTTP status was misclassified non-retryable and the fetch failed after one
// attempt with no backoff.

const test = require('node:test');
const assert = require('node:assert/strict');

const prefetch = require('../lib/prefetch');
const { timedFetch } = prefetch._internal;
const { JobQueue } = require('../lib/job-queue');
const { isRetryable } = require('../vendor/blamejs/retry');

function withStubbedFetch(impl, fn) {
  const orig = global.fetch;
  global.fetch = impl;
  return Promise.resolve()
    .then(fn)
    .finally(() => { global.fetch = orig; });
}

test('timedFetch tags HTTP failures with statusCode the vendored classifier reads', async () => {
  let thrown;
  await withStubbedFetch(
    async () => ({ ok: false, status: 503, headers: { get: () => null }, json: async () => ({}) }),
    async () => {
      try {
        await timedFetch('https://example.test/kev.json');
        assert.fail('expected timedFetch to throw on a 503');
      } catch (err) {
        thrown = err;
      }
    }
  );
  // Exact field + value the classifier keys off, and the classifier verdict.
  assert.equal(thrown.statusCode, 503);
  assert.equal(typeof thrown.statusCode, 'number');
  assert.equal(isRetryable(thrown), true, 'a 503 from timedFetch must classify retryable');
});

test('a transient 503 from timedFetch is retried through the job-queue backoff', async () => {
  const q = new JobQueue({
    sources: { kev: { concurrency: 1 } },
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2, jitterFactor: 0 },
  });
  let calls = 0;
  await withStubbedFetch(
    async () => {
      calls++;
      if (calls <= 2) {
        return { ok: false, status: 503, headers: { get: () => null }, json: async () => ({}) };
      }
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ ok: true }) };
    },
    async () => {
      const res = await q.add({
        source: 'kev',
        run: () => timedFetch('https://example.test/kev.json'),
        meta: { id: 'x' },
      });
      assert.deepEqual(res.json, { ok: true });
    }
  );
  await q.drain();
  const s = q.stats().kev;
  assert.equal(calls, 3, 'timedFetch must be called maxAttempts times for two 503s then a 200');
  assert.equal(s.retried, 2, 'job-queue must record two retries');
  assert.equal(s.completed, 1);
  assert.equal(s.failed, 0);
});

test('a permanent 404 from timedFetch is NOT retried', async () => {
  const q = new JobQueue({
    sources: { kev: { concurrency: 1 } },
    retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2, jitterFactor: 0 },
  });
  let calls = 0;
  await withStubbedFetch(
    async () => {
      calls++;
      return { ok: false, status: 404, headers: { get: () => null }, json: async () => ({}) };
    },
    async () => {
      await assert.rejects(
        q.add({ source: 'kev', run: () => timedFetch('https://example.test/missing.json'), meta: { id: 'y' } }),
        /HTTP 404/
      );
    }
  );
  await q.drain();
  assert.equal(calls, 1, 'a 404 must fail on the first attempt with no retry');
  assert.equal(q.stats().kev.retried, 0);
});
