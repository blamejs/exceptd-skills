"use strict";


// ---- routed from collectors-fp-fixes ----
require("node:test").describe("collectors-fp-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-fp-fixes.test.js
 *
 * Regression tests for a batch of collector false-positive / completeness
 * fixes:
 *   1. sbom: lockfile-no-integrity must NOT fire on a clean npm 7+ lockfile
 *      whose `""` root entry carries name+version but no integrity. It must
 *      still fire when a REMOTE-tarball entry (one with `resolved`) is missing
 *      integrity.
 *   2. secrets: a text file over the 1 MB scan limit is no longer silently
 *      dropped — the skip is recorded in collector_errors.
 *   3. secrets: the AWS-published example access-key id AKIAIOSFODNN7EXAMPLE
 *      does not flip aws-access-key-id.
 *   4. cicd-pipeline-compromise: an OIDC trust JSON under a build-output dir
 *      (dist/) is excluded from the scan via the shared code-exclude set.
 *   5. content-regex collectors (secrets / crypto-codebase / citation-hygiene)
 *      attach a 1-based startLine to their evidence_locations.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const cryptoCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));
const cicdCollector = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const { lineFromOffset } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Finding 1 — sbom lockfile-no-integrity
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 2 — secrets >1 MB skip is recorded
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding 3 — AWS doc example key demotion
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 4 — cicd OIDC scan honors code-exclude set (dist/)
// ---------------------------------------------------------------------------

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



// ---------------------------------------------------------------------------
// Finding 5 — evidence_locations carry startLine
// ---------------------------------------------------------------------------

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collectors-redos-whitespace-line ----
require("node:test").describe("collectors-redos-whitespace-line", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-redos-whitespace-line.test.js
 *
 * Regression coverage for a catastrophic-backtracking (ReDoS) hazard in
 * three line-scanning collector regexes that anchored leading indentation
 * with two adjacent `\s*` runs around an optional list-dash
 * (`^\s*-?\s*<literal>:`). A single long all-whitespace line — well under
 * the 512KB readSafe cap — drove O(n^2) backtracking and blocked the event
 * loop for ~2 minutes per file.
 *
 * Two guarantees per collector:
 *   (a) a fixture with a ~200KB whitespace line returns in well under 1s,
 *   (b) normal `uses:` / `image:` lines still produce the expected hit and
 *       capture, with and without the `- ` list marker, quoted and unquoted.
 *
 * Affected sites:
 *   lib/collectors/library-author.js        publish-workflow `uses:` scan
 *   lib/collectors/cicd-pipeline-compromise  workflow `uses:` scan
 *   lib/collectors/containers.js             k8s manifest `image:` scan
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const libraryAuthor = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
const cicd = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const containers = require(path.join(ROOT, "lib", "collectors", "containers.js"));

// A line long enough that the pre-fix O(n^2) backtracking takes tens of
// seconds, but comfortably under readSafe's 512KB cap.
const WHITESPACE_LINE = " ".repeat(200 * 1024);
// A hit must complete fast even with the hostile line present.
const FAST_MS = 2000;

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFileEnsuringDir(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

// ---------------------------------------------------------------------------
// library-author — publish-workflow `uses:` scan
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// cicd-pipeline-compromise — workflow `uses:` scan
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// containers — k8s manifest `image:` scan
// ---------------------------------------------------------------------------

test("cicd: long-whitespace workflow line returns fast and still flags floating tag pins", () => {
  const tmp = mkTmp("redos-cicd-");
  try {
    // The collector requires a .git directory at cwd.
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    const wf = [
      "name: ci",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // owner=actions: first-party, excluded
      "      - uses: third/party@v1",               // floating tag -> HIT
      "        uses: 'quoted/action@main'",         // quoted, no dash -> HIT
      WHITESPACE_LINE,                               // hostile line
      "      - uses: another/thing@1.2.3",          // floating tag -> HIT
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const start = Date.now();
    const r = cicd.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "hit",
      "normal floating-tag `uses:` refs must still flip the indicator");
    const locs = r.evidence_locations["actions-floating-tag-pin"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 floating-tag hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd: clean workflow (SHA-pinned third-party + first-party) is a MISS", () => {
  const tmp = mkTmp("redos-cicd-clean-");
  try {
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    const sha = "b".repeat(40);
    const wf = [
      "name: ci",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // first-party owner: excluded
      `        uses: "third/party@${sha}"`,        // SHA-pinned: excluded
      "      - uses: ./local-action",               // local: excluded
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const r = cicd.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "miss",
      "first-party + SHA-pinned + local refs must not flip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from playbook-indicators ----
require("node:test").describe("playbook-indicators", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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



// ---------- cicd-pipeline-compromise ----------



// ---------- identity-sso-compromise ----------



// ---------- llm-tool-use-exfil ----------



// ---------- feed-in chains ----------

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from v0_13_0-new-playbook-coverage ----
require("node:test").describe("v0_13_0-new-playbook-coverage", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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



// ---------- cicd-pipeline-compromise ----------



// ---------- identity-sso-compromise ----------



// ---------- llm-tool-use-exfil ----------



// ---------- feed-in chains ----------

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
