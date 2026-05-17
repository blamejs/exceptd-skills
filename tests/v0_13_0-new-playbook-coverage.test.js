'use strict';

/**
 * tests/v0_13_0-new-playbook-coverage.test.js
 *
 * Surface-coverage tests for the 4 new v0.13.0 playbooks. Each indicator
 * and artifact id appears here so the diff-coverage gate
 * (scripts/check-test-coverage.js) recognises them as covered. The tests
 * also assert that each playbook ships its declared indicators + artifacts
 * (smoke-coverage against schema drift).
 *
 * The indicator/artifact ids are referenced as string literals so the
 * grep-based corpus walker in check-test-coverage.js picks them up.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function loadPb(id) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'playbooks', `${id}.json`), 'utf8'));
}

// ---------- webhook-callback-abuse ----------

test('webhook-callback-abuse: indicators present', () => {
  const pb = loadPb('webhook-callback-abuse');
  const ids = (pb.phases?.detect?.indicators || []).map((i) => i.id).sort();
  const expected = [
    'leaked-incoming-webhook-url',
    'long-lived-callback-token-in-ci-log',
    'missing-state-parameter',
    'missing-webhook-replay-window',
    'missing-webhook-signature-validation',
    'webhook-secret-shared-across-apps',
    'wildcard-redirect-uri',
  ];
  assert.deepEqual(ids, expected);
});

test('webhook-callback-abuse: artifacts present', () => {
  const pb = loadPb('webhook-callback-abuse');
  const ids = (pb.phases?.look?.artifacts || []).map((a) => a.id).sort();
  const expected = [
    'callback-state-enforcement',
    'ci-cd-pipeline-webhook-config',
    'github-apps-webhook-config',
    'oauth-client-inventory',
    'platform-incoming-webhook-urls',
    'webhook-receiver-inventory',
    'webhook-replay-window',
  ];
  assert.deepEqual(ids, expected);
});

// ---------- cicd-pipeline-compromise ----------

test('cicd-pipeline-compromise: indicators present', () => {
  const pb = loadPb('cicd-pipeline-compromise');
  const ids = (pb.phases?.detect?.indicators || []).map((i) => i.id).sort();
  const expected = [
    'actions-floating-tag-pin',
    'pull-request-target-with-pr-checkout',
    'runner-scoped-signing-key',
    'secret-exposed-to-fork-pr',
    'self-hosted-runner-non-ephemeral',
    'wildcarded-oidc-sub-claim',
    'workflow-injection-sink',
  ];
  assert.deepEqual(ids, expected);
});

test('cicd-pipeline-compromise: artifacts present', () => {
  const pb = loadPb('cicd-pipeline-compromise');
  const ids = (pb.phases?.look?.artifacts || []).map((a) => a.id).sort();
  const expected = [
    'actions-sha-pinning',
    'fork-pr-workflow-exposure',
    'oidc-trust-policy-inventory',
    'runner-secrets-inventory',
    'self-hosted-runner-registrations',
    'signing-key-locations',
    'workflow-yaml-inventory',
  ];
  assert.deepEqual(ids, expected);
});

// ---------- identity-sso-compromise ----------

test('identity-sso-compromise: indicators present', () => {
  const pb = loadPb('identity-sso-compromise');
  const ids = (pb.phases?.detect?.indicators || []).map((i) => i.id).sort();
  const expected = [
    'conditional-access-exclusion-membership-change',
    'federation-signing-cert-added',
    'high-impact-oauth-consent-grant',
    'okta-class-support-session',
    'out-of-window-global-admin-grant',
    'prt-claim-anomaly',
    'refresh-token-hoarding-by-sp',
  ];
  assert.deepEqual(ids, expected);
});

test('identity-sso-compromise: artifacts present', () => {
  const pb = loadPb('identity-sso-compromise');
  const ids = (pb.phases?.look?.artifacts || []).map((a) => a.id).sort();
  const expected = [
    'break-glass-and-sync-accounts',
    'conditional-access-policy-state',
    'directory-audit-window',
    'federation-trust-config',
    'oauth-app-consent-inventory',
    'privileged-role-assignments',
    'refresh-token-issuance-baseline',
  ];
  assert.deepEqual(ids, expected);
});

// ---------- llm-tool-use-exfil ----------

test('llm-tool-use-exfil: indicators present', () => {
  const pb = loadPb('llm-tool-use-exfil');
  const ids = (pb.phases?.detect?.indicators || []).map((i) => i.id).sort();
  const expected = [
    'agent-egress-to-non-allowlisted-destination',
    'auto-approve-on-high-impact-tool',
    'credential-shadow-in-tool-args',
    'instruction-coercion-in-tool-response',
    'rag-source-from-untrusted-origin',
    'rubber-stamp-approval-pattern',
    'unprompted-tool-chain',
  ];
  assert.deepEqual(ids, expected);
});

test('llm-tool-use-exfil: artifacts present', () => {
  const pb = loadPb('llm-tool-use-exfil');
  const ids = (pb.phases?.look?.artifacts || []).map((a) => a.id).sort();
  const expected = [
    'agent-tool-allowlist',
    'approval-latency-and-denial-rate',
    'egress-destination-inventory',
    'model-system-prompt-and-context-state',
    'rag-ingestion-sources',
    'tool-call-transcripts',
  ];
  assert.deepEqual(ids, expected);
});

// ---------- feed-in chains ----------

test('all 4 new playbooks declare feeds_into[] chains', () => {
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    const pb = loadPb(id);
    assert.ok(Array.isArray(pb._meta?.feeds_into), `${id}: _meta.feeds_into must be an array`);
    assert.ok(pb._meta.feeds_into.length >= 1, `${id}: must chain into at least one downstream playbook`);
    for (const edge of pb._meta.feeds_into) {
      assert.equal(typeof edge.playbook_id, 'string', `${id}: feeds_into entry must carry playbook_id`);
      assert.equal(typeof edge.condition, 'string', `${id}: feeds_into entry must carry condition`);
    }
  }
});

test('all 4 new playbooks meet the 90+ threat_currency_score threshold', () => {
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    const pb = loadPb(id);
    assert.equal(typeof pb._meta?.threat_currency_score, 'number', `${id}: threat_currency_score must be numeric`);
    assert.ok(pb._meta.threat_currency_score >= 90,
      `${id}: threat_currency_score=${pb._meta.threat_currency_score} below the 90-floor for new playbooks`);
  }
});
