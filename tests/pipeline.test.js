'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// --- #41 malformed last_threat_review → maximally stale, observable --------

test('#41 _currencyScore(NaN) === 0 (safe value, not the safe-LOOKING 100)', () => {
  const pipeline = require('../orchestrator/pipeline.js');
  assert.equal(pipeline._currencyScore(NaN), 0);
  assert.equal(typeof pipeline._currencyScore(NaN), 'number');
});

test('#41 _skillCurrencyRow over a malformed date yields stale + observable flag', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-13-99', forward_watch: [] },
    now,
  );
  assert.equal(row.currency_score, 0, 'a malformed date must score maximally stale (0)');
  assert.equal(typeof row.currency_score, 'number');
  assert.equal(row.action_required, true, 'a malformed date must trip action_required');
  assert.equal(row.unparseable_review_date, true, 'the misformat must be surfaced (observable)');
  assert.equal(typeof row.unparseable_review_date, 'boolean');
});

test('#41 _skillCurrencyRow over a fresh valid date stays current and not flagged', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-06-19', forward_watch: [] },
    now,
  );
  assert.equal(row.unparseable_review_date, false, 'a valid date must not be flagged unparseable');
  assert.equal(row.currency_score, 100, 'a 1-day-old review is fully current');
  assert.equal(row.action_required, false);
});

// --- #42 buildHandoff named guard on non-object stageOutput ----------------

test('#42 buildHandoff throws a NAMED TypeError on null/number/string stageOutput', () => {
  const { initPipeline, buildHandoff } = require('../orchestrator/pipeline.js');
  const run = initPipeline('manual', {});
  const re = /stageOutput .* must be a non-null object/;
  assert.throws(() => buildHandoff(run, 0, null), re, 'null payload → named error');
  assert.throws(() => buildHandoff(run, 0, 42), re, 'number payload → named error');
  assert.throws(() => buildHandoff(run, 0, 'str'), re, 'string payload → named error');
  assert.throws(() => buildHandoff(run, 0, []), re, 'array payload → named error');
  // Specifically NOT the opaque deref message.
  assert.throws(
    () => buildHandoff(run, 0, null),
    (err) => err instanceof TypeError && !/in.*operator/.test(err.message),
    'must be the named TypeError, not the opaque "in operator" deref',
  );
});
