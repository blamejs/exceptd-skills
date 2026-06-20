'use strict';

/**
 * Regression: `attest diff` must not fabricate added/removed/changed entries
 * when one side carried a real submission and the other was empty.
 *
 * normalizedArtifacts()/normalizedSignalOverrides() resolve each diff side
 * independently: a side with real artifacts/signal_overrides passes through the
 * operator's keys, while an EMPTY side fell through to the playbook's full
 * catalog stub (every look.artifact id / every detect.indicator id). Diffing N
 * real keys against the full catalog stub manufactured phantom drift — every
 * catalog id the populated side did not submit read as `added` (artifacts) or
 * `changed`→inconclusive (signals). The fix gates the stub on a peer-symmetric
 * test: the catalog stub stands in for an empty side ONLY when BOTH sides are
 * empty (so the count means "N catalog ids, uniformly empty on both sides");
 * when exactly one side has real data, the empty side becomes {} so the
 * populated side's keys diff against nothing — yielding the genuine
 * added/removed, never the catalog noise.
 *
 * Exact value + count assertions per the anti-coincidence rule: assert the
 * specific differing key AND that no catalog id the operator never submitted
 * appears, plus the empty-vs-empty control that locks the all-unchanged shape.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-asym-');
const cli = makeCli(SUITE_HOME);
const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

function lastJson(s) {
  return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
}

// Produce a secrets-playbook attestation with the given submission body.
function makeSession(sid, submission) {
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', sid],
    { input: JSON.stringify(submission) });
  assert.equal(r.status, 0, `producer run failed for ${sid}: ${r.stderr.slice(0, 400)}`);
  return r;
}

test('real-submission-vs-empty diffs only the genuinely-differing keys (no catalog-stub phantoms)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const a = 'asym-a-' + Date.now();
    const b = 'asym-b-' + Date.now();
    // A: one real artifact captured + one real signal override.
    makeSession(a, {
      artifacts: { 'env-files': { captured: true, value: 'DB_PASSWORD=hunter2' } },
      signal_overrides: { 'aws-access-key-id': 'hit' },
      verdict: { classification: 'detected' },
    });
    // B: empty submission (posture-only baseline).
    makeSession(b, { observations: {}, verdict: { classification: 'not_detected' } });

    const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
    assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
    const body = lastJson(r.stdout);

    const ad = body.artifact_diff || {};
    // The only artifact difference is env-files (present on A, absent on B).
    // A captured it and B did not, so it is removed from B's perspective.
    const movedIds = [...(ad.added || []), ...(ad.removed || []), ...(ad.changed || [])].map((x) => x.id);
    assert.deepEqual(movedIds, ['env-files'],
      `only env-files may differ; got ${JSON.stringify(movedIds)} — catalog-stub phantoms regressed`);
    assert.equal(ad.total_compared, 1,
      `total_compared must be 1 (the single real key), not the catalog size; got ${ad.total_compared}`);
    // The 6 secrets-catalog artifact ids the operator never submitted must NOT
    // appear as added/changed.
    const PHANTOM_ARTIFACTS = ['repo-tree', 'auth-config-files', 'ssh-private-keys',
      'iac-credential-bearers', 'secret-regex-scan-text-files', 'world-writable-secret-files'];
    for (const id of PHANTOM_ARTIFACTS) {
      assert.ok(!movedIds.includes(id), `catalog id "${id}" must not be fabricated into the artifact diff`);
    }

    const sd = body.signal_override_diff || {};
    // The only signal difference is aws-access-key-id (A: hit; B: nothing).
    const sigIds = (sd.changed || []).map((x) => x.id);
    assert.deepEqual(sigIds, ['aws-access-key-id'],
      `only aws-access-key-id may differ; got ${JSON.stringify(sigIds)} — inconclusive-stub phantoms regressed`);
    assert.equal(sd.total_compared, 1,
      `signal total_compared must be 1, not the 13-indicator catalog; got ${sd.total_compared}`);
  });

test('empty-vs-empty still uses the catalog stub uniformly (all-unchanged baseline preserved)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const a = 'asym-e-a-' + Date.now();
    const b = 'asym-e-b-' + Date.now();
    const empty = { observations: {}, verdict: { classification: 'not_detected' } };
    makeSession(a, empty);
    makeSession(b, empty);

    const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
    assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
    const body = lastJson(r.stdout);

    const ad = body.artifact_diff || {};
    // Both sides get the identical catalog stub → every catalog artifact id is
    // compared and all are unchanged. total_compared reflects the catalog size
    // (the #128 "N catalog ids, uniformly empty on both sides" intent).
    assert.equal(ad.total_compared, 7, `empty-both artifact total_compared must equal the catalog size; got ${ad.total_compared}`);
    assert.equal((ad.added || []).length, 0, 'empty-both must report 0 added');
    assert.equal((ad.removed || []).length, 0, 'empty-both must report 0 removed');
    assert.equal((ad.changed || []).length, 0, 'empty-both must report 0 changed');
    assert.equal(ad.unchanged_count, 7, 'empty-both must report all catalog artifacts unchanged');

    const sd = body.signal_override_diff || {};
    assert.equal(sd.total_compared, 13, `empty-both signal total_compared must equal the indicator-catalog size; got ${sd.total_compared}`);
    assert.equal((sd.changed || []).length, 0, 'empty-both must report 0 signal changes');
    assert.equal(sd.unchanged_count, 13, 'empty-both must report all indicators unchanged');
  });

test('real-vs-real artifact diff is a clean passthrough (no catalog ids injected)',
  { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
  () => {
    const a = 'asym-r-a-' + Date.now();
    const b = 'asym-r-b-' + Date.now();
    makeSession(a, { artifacts: { 'env-files': { captured: true, value: 'x' } }, verdict: { classification: 'detected' } });
    makeSession(b, { artifacts: { 'env-files': { captured: true, value: 'y' } }, verdict: { classification: 'detected' } });

    const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
    assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
    const body = lastJson(r.stdout);
    const ad = body.artifact_diff || {};
    assert.equal(ad.total_compared, 1, `real-vs-real must compare only the submitted key; got ${ad.total_compared}`);
    assert.deepEqual((ad.changed || []).map((x) => x.id), ['env-files'], 'the one differing value must be the only change');
    assert.equal((ad.added || []).length, 0, 'real-vs-real must inject no catalog "added" entries');
  });
