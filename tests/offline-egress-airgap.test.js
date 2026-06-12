'use strict';

/**
 * Regression: runs the operator believes are offline must make no network call.
 *
 *  [16] An intrinsically air-gapped playbook (_meta.air_gap_mode — secrets /
 *       cred-stores / containers) + `--upstream-check` must refuse the npm
 *       registry probe even without the explicit --air-gap flag.
 *  [2]  discoverNewRfcs queries IETF Datatracker live; under --air-gap it must
 *       make no call (the help no longer claims --from-cache alone is "entirely
 *       offline" — RFC discovery is live unless --air-gap is also passed).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { discoverNewRfcs } = require('../lib/auto-discovery');

const cli = makeCli(makeSuiteHome('exceptd-offline-egress-'));

test('intrinsic air-gap playbook + --upstream-check refuses the registry probe (no flag)', () => {
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r = cli(['run', 'secrets', '--upstream-check', '--evidence', '-', '--json'], { input: sub });
  assert.equal(r.status, 0, `run must succeed; stderr=${r.stderr.slice(0, 300)}`);
  const body = tryJson((r.stdout || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  assert.ok(body.upstream_check && typeof body.upstream_check === 'object', 'upstream_check must be present');
  assert.equal(body.upstream_check.air_gap_blocked, true, 'intrinsic air-gap must block the registry probe');
  assert.equal(body.upstream_check.source, 'air-gap');
});

test('discoverNewRfcs makes no network call under air-gap', async () => {
  const orig = global.fetch;
  let called = false;
  global.fetch = async () => { called = true; throw new Error('network call attempted under air-gap'); };
  try {
    const r = await discoverNewRfcs({ airGap: true, rfcCatalog: {} });
    assert.equal(called, false, 'discoverNewRfcs must not call fetch under air-gap');
    assert.equal(r.diffs.length, 0);
    assert.match(r.summary, /air-gap/i);
  } finally {
    global.fetch = orig;
  }
});
