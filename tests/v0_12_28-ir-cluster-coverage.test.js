"use strict";
/**
 * tests/v0_12_28-ir-cluster-coverage.test.js
 *
 * Diff-coverage gate (Hard Rule #15) — every new look.artifact + detect.indicator
 * id introduced by the v0.12.28 IR-cluster playbooks (idp-incident,
 * cloud-iam-incident, ransomware) is referenced here so the gate can match it
 * against tests/. The structural smoke at the bottom loads each playbook and
 * asserts that the referenced ids actually exist on the playbook — that is,
 * the test is real, not a string-match shim.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const PB_DIR = path.join(ROOT, "data", "playbooks");

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
  test(`v0.12.28: ${pbId} declares every catalogued indicator`, () => {
    const pb = loadPlaybook(pbId);
    const present = collectIds(pb, "indicator");
    for (const id of expected.indicators) {
      assert.equal(
        present.has(id),
        true,
        `${pbId}: indicator '${id}' must be present on the playbook (catalogued by the v0.12.28 IR-cluster pass)`,
      );
    }
  });

  test(`v0.12.28: ${pbId} declares every catalogued artifact`, () => {
    const pb = loadPlaybook(pbId);
    const present = collectIds(pb, "artifact");
    for (const id of expected.artifacts) {
      assert.equal(
        present.has(id),
        true,
        `${pbId}: artifact '${id}' must be present on the playbook (catalogued by the v0.12.28 IR-cluster pass)`,
      );
    }
  });
}
