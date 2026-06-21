'use strict';

/**
 * tests/collectors-cicd-pipeline-compromise.test.js
 *
 * Subject coverage for lib/collectors/cicd-pipeline-compromise.js:
 *  - an explicit-false precondition HALT carries a specific remediation (the
 *    submitted gate + the precondition_checks submission mechanism + the
 *    collect-verb flag example), and the human renderer no longer asserts a
 *    platform-gate ("Linux-only") cause for an intent-gate block;
 *  - an OIDC trust JSON under a build-output dir (dist/) is excluded from the
 *    scan via the shared code-exclude set, while the same policy under a
 *    source dir (infra/) is scanned and HITs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const cicdCollector = require('../lib/collectors/cicd-pipeline-compromise.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('explicit-false precondition halt carries a specific remediation, not the generic platform hint', () => {
  const cli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({ precondition_checks: { 'operator-owns-ci-fleet': false } });
  const j = tryJson(cli(['run', 'cicd-pipeline-compromise', '--evidence', '-', '--json'], { input: ev }).stdout);
  assert.equal(j.blocked_by, 'precondition');
  assert.equal(typeof j.remediation, 'string');
  assert.ok(/submitted as false/.test(j.remediation), 'remediation names the specific gate, not a platform guess');
  // The universal satisfaction mechanism (submit the precondition true) must
  // be named — it works for every playbook regardless of which verb blocked.
  assert.ok(/precondition_checks/.test(j.remediation), 'remediation points at the precondition_checks submission mechanism');
  assert.ok(j.remediation.includes('"operator-owns-ci-fleet": true'), 'remediation shows the exact attestation to submit');
  // The flag example must be attributed to the collect verb (it is a collect
  // flag; the block surfaces at run, where passing it is silently ignored).
  assert.ok(/collect cicd-pipeline-compromise --attest-ownership/.test(j.remediation), 'the --attest-ownership example names the collect verb');
  const human = cli(['run', 'cicd-pipeline-compromise', '--evidence', '-'], { input: ev });
  assert.equal(/Linux-only playbook/.test(human.stdout), false, 'the misleading platform-gate hint must not appear on an intent-gate halt');
});

const WILDCARD_OIDC = JSON.stringify({
  Statement: [{
    Effect: "Allow",
    Principal: { Federated: "token.actions.githubusercontent.com" },
    Condition: {
      StringLike: {
        "token.actions.githubusercontent.com:sub": "repo:acme/*:*",
      },
    },
  }],
}, null, 2);

test("cicd: OIDC trust JSON under dist/ (build output) is NOT scanned", () => {
  const tmp = mkTmp("fp-cicd-dist-");
  try {
    fs.mkdirSync(path.join(tmp, ".git")); // satisfy cwd-is-repo precondition
    const distInfra = path.join(tmp, "dist", "infra");
    fs.mkdirSync(distInfra, { recursive: true });
    fs.writeFileSync(path.join(distInfra, "trust.json"), WILDCARD_OIDC);
    const r = cicdCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "miss",
      "a wildcarded OIDC policy buried in dist/ build output must be excluded");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd: the same OIDC trust JSON under infra/ (source) IS scanned and HITs", () => {
  const tmp = mkTmp("fp-cicd-infra-");
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const infra = path.join(tmp, "infra");
    fs.mkdirSync(infra, { recursive: true });
    fs.writeFileSync(path.join(infra, "trust.json"), WILDCARD_OIDC);
    const r = cicdCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "hit",
      "the control case (source-tree policy) must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
