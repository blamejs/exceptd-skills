'use strict';

/**
 * Scheduler INT32 overflow guard.
 *
 * Node coerces setTimeout / setInterval delays to a signed 32-bit integer.
 * Any delay above 2^31 - 1 ms (~24.8 days) is silently clamped to 1 ms,
 * which causes the handler to fire ~1000×/sec — a stdout flood that
 * exhausts the event loop. `scheduleEvery` wraps the underlying timer
 * with a bounded tick interval and compares wall-clock elapsed time
 * against the requested interval, so over-INT32 delays behave correctly.
 *
 * These tests verify:
 *   1. A delay above SAFE_MAX_MS does NOT emit Node's TimeoutOverflowWarning.
 *   2. The handler does NOT fire more than once within real wall time
 *      shorter than the requested interval.
 *   3. The unschedule callback stops further firings.
 *   4. A short interval still fires repeatedly as expected (sanity).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { scheduleEvery, SAFE_MAX_MS } = require('../orchestrator/scheduler');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

test('scheduleEvery: SAFE_MAX_MS + 1 emits no TimeoutOverflowWarning and does not fire spuriously', async () => {
  const warnings = [];
  const onWarning = (w) => {
    if (w && w.name === 'TimeoutOverflowWarning') warnings.push(w);
  };
  process.on('warning', onWarning);

  let fired = 0;
  const off = scheduleEvery(SAFE_MAX_MS + 1, () => { fired += 1; });

  try {
    // Real wall time is ~300 ms; the requested interval is ~24.8 days +
    // 1 ms. The handler must not fire even once in that window.
    await sleep(300);
    assert.equal(fired, 0, 'handler must not fire within 300 ms when interval is > SAFE_MAX_MS');
    assert.equal(warnings.length, 0, 'no TimeoutOverflowWarning must be emitted for over-INT32 intervals');
  } finally {
    off();
    process.off('warning', onWarning);
  }
});

test('scheduleEvery: short interval fires repeatedly', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => { fired += 1; });
  try {
    await sleep(150);
    assert.ok(fired >= 3, `expected handler to fire at least 3 times in 150 ms with 20 ms interval, got ${fired}`);
  } finally {
    off();
  }
});

test('scheduleEvery: returned unschedule callback stops further firings', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => { fired += 1; });
  await sleep(80);
  const firedAtStop = fired;
  off();
  await sleep(120);
  // Allow at most one extra fire that may have been in-flight at the
  // moment off() ran; any larger growth means the timer kept ticking.
  assert.ok(
    fired - firedAtStop <= 1,
    `handler kept firing after unschedule: ${firedAtStop} -> ${fired}`
  );
});

test('scheduleEvery: handler errors are caught and do not break the timer', async () => {
  let fired = 0;
  const off = scheduleEvery(20, () => {
    fired += 1;
    throw new Error('boom');
  });
  // Silence the console.error noise from the catch block; the test
  // listener is enough.
  const origErr = console.error;
  console.error = () => {};
  try {
    await sleep(120);
    assert.ok(fired >= 2, `timer must keep ticking after handler throws (fired=${fired})`);
  } finally {
    console.error = origErr;
    off();
  }
});
