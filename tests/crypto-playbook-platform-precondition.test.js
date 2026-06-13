'use strict';
/**
 * tests/crypto-playbook-platform-precondition.test.js
 *
 * The crypto collector self-vetoes on non-Linux hosts (it reads /etc/ssh and
 * invokes the system openssl/ssh binaries), emitting precondition_checks with
 * linux-platform:false and every artifact captured:false. Before crypto.json
 * declared a matching `linux-platform` precondition, that veto was silently
 * dropped: the run scanned nothing yet returned a false "evidence complete,
 * not_detected" verdict.
 *
 * crypto.json now carries a `linux-platform` precondition (on_fail:halt). A
 * submission that fails it must block at preflight rather than reporting a
 * clean not_detected. The precondition override is passed explicitly so the
 * test is deterministic on Linux CI (where process.platform is 'linux').
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const CRYPTO_DIRECTIVE = 'all-crypto-pqc-readiness';

// Exactly the shape the collector emits on a non-Linux host: linux-platform
// attested false, all artifacts captured:false, empty signal_overrides.
function nonLinuxSubmission() {
  return {
    precondition_checks: { 'linux-platform': false },
    observations: {},
    artifacts: {
      'openssl-version': { captured: false },
      'openssl-kem-algorithms': { captured: false },
    },
    signal_overrides: {},
  };
}

test('crypto playbook blocks at preflight when linux-platform is false', () => {
  const result = runner.run(CRYPTO_DIRECTIVE === null ? '' : 'crypto', CRYPTO_DIRECTIVE, nonLinuxSubmission());

  assert.equal(result.ok, false, 'a failed halt precondition must not produce an ok run');
  assert.equal(result.verdict, 'blocked', 'verdict must be "blocked", not a detection verdict');
  assert.equal(result.blocked_by, 'precondition', 'blocked_by must name the precondition gate');

  // Field-present AND populated: the blocked result must NOT advertise a
  // completed evidence pass. A halted run never reaches evidence evaluation.
  assert.notEqual(
    result.evidence_completeness,
    'complete',
    'a blocked run must not report evidence_completeness:"complete"',
  );
  assert.equal(
    result.evidence_completeness,
    'not-evaluated',
    'a preflight-blocked run reports evidence_completeness:"not-evaluated"',
  );

  // It must not carry a not_detected classification either — nothing was
  // scanned, so there is no "8/8 clean" result to report.
  assert.notEqual(result.verdict, 'not_detected');
  assert.equal(
    'detection_classification' in result && result.detection_classification === 'not_detected',
    false,
    'a blocked run must not classify anything as not_detected',
  );
});

test('crypto playbook proceeds past the linux-platform gate when attested true', () => {
  // Parity / control: with the platform gate satisfied, preflight no longer
  // blocks on linux-platform. (Other warn-level preconditions may still warn,
  // but the run must not be blocked_by:'precondition' for the platform gate.)
  const sub = nonLinuxSubmission();
  sub.precondition_checks['linux-platform'] = true;
  // filesystem-read is the other halt-level precondition; attest it so the
  // run clears preflight rather than blocking on a different gate.
  sub.precondition_checks['filesystem-read'] = true;
  const result = runner.run('crypto', CRYPTO_DIRECTIVE, sub);

  const blockedOnPlatform =
    result.ok === false &&
    result.blocked_by === 'precondition' &&
    /linux-platform/.test(JSON.stringify(result.issues || result.reason || ''));
  assert.equal(
    blockedOnPlatform,
    false,
    'with linux-platform attested true, the run must not block on the platform gate',
  );
});
