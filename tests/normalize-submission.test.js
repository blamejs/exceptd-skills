'use strict';

/**
 * Subject: `normalizeSubmission` exported from lib/playbook-runner.js — the
 * submission → {artifacts, signal_overrides} normalizer.
 *
 * Consolidated from per-finding test files; each source file's contribution is
 * wrapped in a describe() block carrying its original basename so file-local
 * helper/const names cannot collide across merged sources.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const runner = require('../lib/playbook-runner.js');

test('normalize-submission subject file loaded', () => {
  assert.ok(true);
});

// ===========================================================================
describe('attest-diff-nonvalue-evidence', () => {
  test('reserved control keys (indicator/result) are not leaked into the artifact', () => {
    const norm = runner.normalizeSubmission(
      { observations: { w: { captured: true, indicator: 'aws-access-key-id', result: 'hit' } } },
      runner.loadPlaybook('secrets'));
    assert.deepEqual(norm.artifacts.w, { captured: true }, 'control-only observation yields a bare {captured} artifact');
    assert.equal(norm.signal_overrides['aws-access-key-id'], 'hit', 'the indicator still drives signal_overrides');
  });
});
