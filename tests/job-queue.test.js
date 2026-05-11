'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { JobQueue, TokenBucket } = require('../lib/job-queue');

test('JobQueue: respects per-source concurrency cap', async () => {
  const q = new JobQueue({ sources: { x: { concurrency: 2 } }, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 } });
  let inFlight = 0;
  let peak = 0;
  const tasks = Array.from({ length: 6 }, () =>
    q.add({
      source: 'x',
      run: async () => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 15));
        inFlight--;
        return 'ok';
      },
    })
  );
  await Promise.all(tasks);
  assert.equal(peak, 2, `peak in-flight was ${peak}, expected 2`);
});

test('JobQueue: priority orders higher-number first within a source', async () => {
  const q = new JobQueue({ sources: { p: { concurrency: 1 } }, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 } });
  const seen = [];
  // Add lowest priority first; it should still run first because no other
  // tasks are queued yet at that moment. Subsequent inserts are sorted.
  const p1 = q.add({ source: 'p', priority: 1, run: async () => { seen.push('p1'); await new Promise(r => setTimeout(r, 5)); } });
  // While p1 runs, queue three with mixed priorities.
  await new Promise((r) => setTimeout(r, 1));
  const p10 = q.add({ source: 'p', priority: 10, run: async () => { seen.push('p10'); } });
  const p5 = q.add({ source: 'p', priority: 5, run: async () => { seen.push('p5'); } });
  const p2 = q.add({ source: 'p', priority: 2, run: async () => { seen.push('p2'); } });
  await Promise.all([p1, p10, p5, p2]);
  // p1 ran first (only thing in queue); after that, priority order is p10, p5, p2.
  assert.deepEqual(seen, ['p1', 'p10', 'p5', 'p2']);
});

test('JobQueue: retries transient errors via vendored classifier', async () => {
  const q = new JobQueue({ sources: { x: { concurrency: 1 } }, retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 } });
  let attempts = 0;
  const result = await q.add({
    source: 'x',
    run: async () => {
      attempts++;
      if (attempts < 3) {
        const e = new Error('reset');
        e.code = 'ECONNRESET';
        throw e;
      }
      return 'won';
    },
  });
  assert.equal(result, 'won');
  assert.equal(attempts, 3);
  const s = q.stats().x;
  assert.equal(s.completed, 1);
  assert.equal(s.retried, 2);
});

test('JobQueue: does NOT retry permanent / non-retryable errors', async () => {
  const q = new JobQueue({ sources: { x: { concurrency: 1 } }, retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0 } });
  let attempts = 0;
  await assert.rejects(async () => {
    await q.add({
      source: 'x',
      run: async () => {
        attempts++;
        const e = new Error('bad input');
        e.statusCode = 400;
        throw e;
      },
    });
  });
  assert.equal(attempts, 1);
});

test('JobQueue: drain resolves after all sources are idle', async () => {
  const q = new JobQueue({ sources: { x: { concurrency: 2 } }, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 } });
  const p1 = q.add({ source: 'x', run: async () => { await new Promise(r => setTimeout(r, 10)); return 'a'; } });
  const p2 = q.add({ source: 'x', run: async () => { await new Promise(r => setTimeout(r, 20)); return 'b'; } });
  let drained = false;
  q.drain().then(() => { drained = true; });
  await Promise.all([p1, p2]);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(drained, true);
});

test('TokenBucket: tryTake returns 0 while tokens available, > 0 when starved', () => {
  const b = new TokenBucket({ tokens: 2, windowMs: 1000 });
  assert.equal(b.tryTake(), 0);
  assert.equal(b.tryTake(), 0);
  const w = b.tryTake();
  assert.ok(w > 0, `expected positive wait, got ${w}`);
});

test('JobQueue: surfaces queue_meta on failed jobs', async () => {
  const q = new JobQueue({ sources: { x: { concurrency: 1 } }, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 } });
  try {
    await q.add({
      source: 'x',
      meta: { cve: 'CVE-2026-31431' },
      run: async () => { const e = new Error('nope'); e.statusCode = 400; throw e; },
    });
    assert.fail('expected throw');
  } catch (err) {
    assert.ok(err.queue_meta, 'queue_meta missing on error');
    assert.equal(err.queue_meta.source, 'x');
    assert.equal(err.queue_meta.cve, 'CVE-2026-31431');
  }
});
