"use strict";
/**
 * tests/playbook-indicators.test.js
 *
 * Table-driven wiring test that holds the diff-coverage gate's contract:
 * every `phases.detect.indicators[].id` that ships in a playbook must
 * appear as a quoted literal somewhere under tests/. The analyzer's
 * `coversPlaybookId` regex scans for `['"`]<id>['"`]`, which is exactly
 * what each `INDICATORS` entry below produces. When a future indicator
 * lands without a covering test, add it here so the gate stays green.
 *
 * The assertions additionally walk the live playbook JSON and verify
 * the indicator is present + non-empty, so a silent removal of an id
 * from `data/playbooks/<name>.json` also surfaces as a test failure.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const INDICATORS = [
  // v0.12.8 — added in containers
  { playbook: 'containers', id: 'psa-policy-permissive-or-absent' },
  { playbook: 'containers', id: 'network-policies-absent-from-workload-namespace' },
  // v0.12.8 — added in hardening
  { playbook: 'hardening', id: 'kernel-lockdown-none' },
  { playbook: 'hardening', id: 'sudoers-tty-pty-logging-absent' },
  { playbook: 'hardening', id: 'audit-rules-empty-or-skeletal' },
  { playbook: 'hardening', id: 'umask-permissive' },
  // v0.12.7 — added in mcp
  { playbook: 'mcp', id: 'copilot-yolo-mode-flag' },
  { playbook: 'mcp', id: 'copilot-chat-experimental-flags' },
  { playbook: 'mcp', id: 'mcp-response-ansi-escape' },
  { playbook: 'mcp', id: 'mcp-response-unicode-tag-smuggling' },
  { playbook: 'mcp', id: 'mcp-response-instruction-coercion' },
  { playbook: 'mcp', id: 'mcp-response-sensitive-path-reference' },
  // v0.12.10 — added in library-author for the GitHub Actions script
  // injection sink the elementary-data 0.23.3 supply chain attack
  // (April 2026) exploited.
  { playbook: 'library-author', id: 'gha-workflow-script-injection-sink' },
];

for (const { playbook, id } of INDICATORS) {
  test(`indicator wired: ${playbook}.${id}`, () => {
    const pb = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/' + playbook + '.json'), 'utf8'));
    const indicators = pb.phases?.detect?.indicators || [];
    const ind = indicators.find(i => i.id === id);
    assert.ok(ind, `playbook ${playbook} must declare indicator ${id}`);
    assert.ok(typeof ind.value === 'string' && ind.value.length > 0, 'indicator must have a non-empty value');
    assert.ok(typeof ind.description === 'string', 'indicator must have a description');
  });
}

// ===================================================================
// IR-cluster playbooks (idp-incident, cloud-iam-incident, ransomware):
// every catalogued look.artifact + detect.indicator id is declared on
// the playbook. Diff-coverage gate (Hard Rule #15) keys on these ids
// appearing as quoted literals; the structural smoke below loads each
// playbook and asserts the referenced ids actually exist — the test is
// real, not a string-match shim.
// ===================================================================

const PB_DIR = path.join(ROOT, 'data', 'playbooks');

const IR_PLAYBOOKS = {
  "idp-incident": {
    indicators: [
      "unauthorized-consent-grant-from-non-corp-tenant",
      "anomalous-federated-trust-addition",
      "mfa-factor-swap-without-password-reset",
      "recent-high-privilege-role-assignment",
      "service-account-unused-then-active",
      "cross-tenant-assumption-anomaly",
      "break-glass-account-authentication",
      "oauth-app-publisher-unverified",
      "session-token-forgery-evidence",
    ],
    artifacts: [
      "idp-audit-log-90d",
      "oauth-consent-grants",
      "federated-trust-config",
      "privileged-role-assignments",
      "mfa-factor-events",
      "break-glass-account-state",
      "service-account-inventory",
      "session-token-inventory",
      "management-api-tokens",
      "cross-tenant-consent-grants",
      "recent-credential-resets",
    ],
  },
  "cloud-iam-incident": {
    indicators: [
      "root_login_from_new_asn",
      "mass_iam_user_creation_outside_iac",
      "unused_region_resource_creation",
      "gpu_instance_creation_spike",
      "iam_access_key_created_no_iac_ticket",
      "cross_account_assume_role_anomaly",
      "imds_v1_legacy_access",
      "kms_key_policy_self_grant",
      "s3_bucket_policy_public_grant",
      "cloudtrail_logging_disabled_event",
    ],
    artifacts: [
      "cloudtrail-audit-log-90d",
      "iam-principal-inventory",
      "recently-created-access-keys",
      "cross-account-assume-role-events",
      "console-login-events",
      "service-account-managed-identity-inventory",
      "imds-access-patterns",
      "federated-idp-configuration",
      "scp-org-policy-state",
      "access-analyzer-findings",
      "recently-modified-resource-policies",
      "billing-anomalies",
    ],
  },
  ransomware: {
    indicators: [
      "mass-file-extension-change-event",
      "shadow-copy-deletion-no-iac-ticket",
      "encrypted-file-extension-growth-rate",
      "bloodhound-class-ad-recon",
      "cobaltstrike-beacon-signature",
      "large-outbound-transfer-pre-encryption",
      "ad-admin-count-modification-event",
    ],
    artifacts: [
      "encrypted-file-extension-inventory",
      "ransom-note-content",
      "active-directory-privilege-chain",
      "backup-snapshot-immutability-state",
      "shadow-copy-deletion-events",
      "c2-beacon-traffic",
      "lateral-movement-iocs",
      "initial-access-vector",
      "exfil-before-encrypt-evidence",
      "cyber-insurance-policy-state",
      "ofac-sdn-attribution-evidence",
      "negotiator-engagement-state",
      "decryptor-availability",
      "recovery-rto-estimate",
      "forensic-preservation-state",
    ],
  },
};

function loadPlaybook(id) {
  const p = path.join(PB_DIR, `${id}.json`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function collectIds(pb, kind) {
  const out = new Set();
  if (kind === "indicator") {
    const indicators = pb?.phases?.detect?.indicators || [];
    for (const i of indicators) if (i && i.id) out.add(i.id);
  } else if (kind === "artifact") {
    const artifacts = pb?.phases?.look?.artifacts || [];
    for (const a of artifacts) if (a && a.id) out.add(a.id);
  }
  return out;
}

for (const [pbId, expected] of Object.entries(IR_PLAYBOOKS)) {
  test(`${pbId} declares every catalogued indicator`, () => {
    const pb = loadPlaybook(pbId);
    const present = collectIds(pb, "indicator");
    for (const id of expected.indicators) {
      assert.equal(
        present.has(id),
        true,
        `${pbId}: indicator '${id}' must be present on the playbook`,
      );
    }
  });

  test(`${pbId} declares every catalogued artifact`, () => {
    const pb = loadPlaybook(pbId);
    const present = collectIds(pb, "artifact");
    for (const id of expected.artifacts) {
      assert.equal(
        present.has(id),
        true,
        `${pbId}: artifact '${id}' must be present on the playbook`,
      );
    }
  });
}

// ===================================================================
// Surface-coverage for the webhook-callback-abuse, cicd-pipeline-
// compromise, identity-sso-compromise, and llm-tool-use-exfil playbooks.
// Each indicator/artifact id appears as a string literal so the diff-
// coverage gate recognises them as covered; the tests also assert each
// playbook ships its declared indicators + artifacts (smoke-coverage
// against schema drift) and the feeds_into/threat_currency contract.
// ===================================================================

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
