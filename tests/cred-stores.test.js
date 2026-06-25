"use strict";

/**
 * tests/cred-stores.test.js
 *
 * Behavioral coverage for the `cred-stores` collector
 * (lib/collectors/cred-stores.js): the companion collector for the
 * cred-stores playbook. It inspects local credential carriers under
 * $HOME + project-level .npmrc/.pypirc and flips signal_overrides for
 * deterministic indicators.
 *
 * The collector reads $HOME via env.HOME/env.USERPROFILE first, so every
 * positive/negative fixture builds a synthetic home in os.tmpdir() and
 * points the collector at it — no host credential dotfiles are touched
 * and no real files are mutated.
 *
 * Discipline (project anti-coincidence rules): assert the EXACT verdict
 * ("hit"/"miss"), pair field-presence with content, exercise at least one
 * negative/abstain path per indicator, confine all writes to os.tmpdir().
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const collector = require(path.join(ROOT, "lib", "collectors", "cred-stores.js"));

const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

function mkHome(prefix = "cred-stores-home-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
function mkCwd(prefix = "cred-stores-cwd-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
function writeFile(home, rel, content) {
  const full = path.join(home, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}
/** Run collect() against a synthetic home + empty cwd. */
function collectAt(home, cwd) {
  return collector.collect({ cwd: cwd || home, env: { HOME: home, USERPROFILE: home } });
}

// ---------------------------------------------------------------------------
// Module contract
// ---------------------------------------------------------------------------

test("exports playbook_id 'cred-stores' + a collect() function", () => {
  assert.equal(collector.playbook_id, "cred-stores");
  assert.equal(typeof collector.collect, "function");
});

test("collect() returns the full collector envelope shape", () => {
  const home = mkHome();
  try {
    const r = collectAt(home);
    for (const k of ENVELOPE_KEYS) {
      assert.ok(k in r, `envelope must carry top-level key ${k}`);
    }
    assert.equal(r.collector_meta.collector_id, "cred-stores");
    assert.equal(typeof r.collector_meta.captured_at, "string");
    assert.ok(Array.isArray(r.collector_errors));
    assert.equal(typeof r.signal_overrides, "object");
    assert.equal(typeof r.artifacts, "object");
    // home-dir-readable precondition is true for an existing tempdir home.
    assert.equal(r.precondition_checks["home-dir-readable"], true);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Empty home — every deterministic indicator abstains to "miss", nothing
// false-positives.
// ---------------------------------------------------------------------------

test("a home with no credential carriers misses every deterministic indicator", () => {
  const home = mkHome();
  const cwd = mkCwd();
  try {
    const r = collectAt(home, cwd);
    const so = r.signal_overrides;
    assert.equal(so["aws-static-key-present"], "miss");
    assert.equal(so["kube-static-token"], "miss");
    assert.equal(so["gcp-service-account-json-adc"], "miss");
    assert.equal(so["docker-cleartext-auth"], "miss");
    assert.equal(so["npm-pat-present"], "miss");
    assert.equal(so["pypi-token-present"], "miss");
    // No carriers present -> __fp_checks attestations are absent (only
    // attached on a hit).
    assert.ok(!("aws-static-key-present__fp_checks" in so));
    assert.ok(!("docker-cleartext-auth__fp_checks" in so));
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// aws-static-key-present — positive, doc-fixture demotion, break-glass demotion
// ---------------------------------------------------------------------------

test("aws-static-key-present hits on a static AKIA profile, with the FP-check attestation", () => {
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[prod]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = abcd\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "hit");
    // The collector attests the two deterministic FP checks it ran (doc-
    // fixture demotion [0] + break-glass pattern [2]).
    assert.deepEqual(r.signal_overrides["aws-static-key-present__fp_checks"], { "0": true, "2": true });
    // Artifact captures the static-profile count.
    assert.match(r.artifacts["aws-credentials"].value, /1 static profile/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present demotes the AWS-published doc-fixture key (FP[0])", () => {
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[doc]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss",
      "the published AWS doc-fixture key must not flip the indicator");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present is NOT demoted by an earlier duplicate-name block holding the doc-fixture key", () => {
  // Two [default] blocks: the first holds the AWS doc-fixture key, the second
  // a real AKIA key. The demotion must key off the EXACT live key value (the
  // last-occurrence/real key, matching SDK precedence), not the first
  // name-matching block — otherwise the example key in the first block
  // silently demotes the real credential under the same name.
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n" +
      "[default]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = y\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "hit",
      "the live (last-occurrence) real key must fire even though an earlier duplicate block holds the example key");
    // The FP attestation still rides along on the hit.
    assert.deepEqual(r.signal_overrides["aws-static-key-present__fp_checks"], { "0": true, "2": true });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present demotes a break-glass profile name (FP[2])", () => {
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[breakglass-prod]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = x\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss",
      "a breakglass-* profile is a deliberate break-glass path, demoted");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present misses on an SSO/federated profile (has sso_session)", () => {
  const home = mkHome();
  try {
    // A profile WITH federation but no static key is not a static-key hit.
    writeFile(home, ".aws/credentials",
      "[fed]\nsso_session = corp\nrole_arn = arn:aws:iam::123:role/r\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss");
    assert.match(r.artifacts["aws-credentials"].value, /1 federated/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present hits on a static AKIA key carried ALONGSIDE a role_arn (role_arn is NOT federation)", () => {
  // A source_profile/assume-role setup where the profile carries BOTH a static
  // aws_access_key_id (AKIA*) AND a role_arn: the static key IS the long-lived
  // IAM-user credential that bootstraps the assumed role — a genuine static-key
  // exposure. role_arn must NOT be treated as a federation marker (only
  // sso_session / credential_process are), or the present IAM-user key is
  // silently suppressed.
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[prod]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE2\naws_secret_access_key = abc\n" +
      "role_arn = arn:aws:iam::123:role/x\nsource_profile = base\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "hit",
      "a static AKIA key alongside a role_arn is still a static-key hit");
    // The hit rides with the deterministic FP-check attestation (doc-fixture
    // demotion [0] + break-glass pattern [2]); AKIAIOSFODNN7EXAMPLE2 is not the
    // published example key so it is not demoted.
    assert.deepEqual(r.signal_overrides["aws-static-key-present__fp_checks"], { "0": true, "2": true });
    // The profile is counted as a static profile, not a federated one.
    assert.match(r.artifacts["aws-credentials"].value, /1 static profile/);
    assert.match(r.artifacts["aws-credentials"].value, /0 federated/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("aws-static-key-present misses on a PURE assume-role profile (role_arn + source_profile, no aws_access_key_id)", () => {
  // The negative companion: a profile that delegates entirely to an assumed
  // role and carries no own access key has no long-lived static credential.
  // The hasKey gate (aws_access_key_id present) keeps it out of the static set.
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials",
      "[delegate]\nrole_arn = arn:aws:iam::123:role/x\nsource_profile = base\n");
    const r = collectAt(home);
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss",
      "a pure assume-role profile carries no static access key and must not flip the indicator");
    // No static profile recorded for a key-less assume-role block.
    assert.match(r.artifacts["aws-credentials"].value, /0 static profile/);
    // No FP attestation is attached when the indicator does not hit.
    assert.ok(!("aws-static-key-present__fp_checks" in r.signal_overrides));
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// kube-static-token — static token hits; exec-provider abstains
// ---------------------------------------------------------------------------

test("kube-static-token hits on a user-level static token with no exec sibling", () => {
  const home = mkHome();
  try {
    writeFile(home, ".kube/config",
      [
        "apiVersion: v1",
        "users:",
        "- name: admin",
        "  user:",
        "    token: abcdef.0123456789abcdef",
        "",
      ].join("\n"));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["kube-static-token"], "hit");
    assert.match(r.artifacts["kube-config"].value, /static_token=true/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("kube-static-token misses when the user uses an exec credential plugin", () => {
  const home = mkHome();
  try {
    writeFile(home, ".kube/config",
      [
        "apiVersion: v1",
        "users:",
        "- name: admin",
        "  user:",
        "    exec:",
        "      command: aws",
        "",
      ].join("\n"));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["kube-static-token"], "miss",
      "an exec-provider user is a dynamic credential, not a static token");
    assert.match(r.artifacts["kube-config"].value, /exec_provider=true/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// gcp-service-account-json-adc
// ---------------------------------------------------------------------------

test("gcp-service-account-json-adc hits on a service_account ADC json", () => {
  const home = mkHome();
  try {
    writeFile(home, ".config/gcloud/application_default_credentials.json",
      JSON.stringify({ type: "service_account", private_key: "x" }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["gcp-service-account-json-adc"], "hit");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("gcp-service-account-json-adc misses on an authorized_user ADC json", () => {
  const home = mkHome();
  try {
    writeFile(home, ".config/gcloud/application_default_credentials.json",
      JSON.stringify({ type: "authorized_user", refresh_token: "x" }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["gcp-service-account-json-adc"], "miss",
      "an authorized_user ADC is a user OAuth flow, not a long-lived SA key");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// docker-cleartext-auth — positive, vendor-token demotion, local-only demotion,
// credHelper suppression
// ---------------------------------------------------------------------------

function dockerAuthB64(user, pass) {
  return Buffer.from(`${user}:${pass}`, "utf8").toString("base64");
}

test("docker-cleartext-auth hits on a real cleartext auth with no cred helper", () => {
  const home = mkHome();
  try {
    writeFile(home, ".docker/config.json", JSON.stringify({
      auths: { "registry.example.com": { auth: dockerAuthB64("deploybot", "s3cret") } },
    }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "hit");
    assert.deepEqual(r.signal_overrides["docker-cleartext-auth__fp_checks"], { "0": true, "1": true, "2": true });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("docker-cleartext-auth demotes a vendor-token user pattern (FP[0])", () => {
  const home = mkHome();
  try {
    writeFile(home, ".docker/config.json", JSON.stringify({
      auths: { "public.ecr.aws": { auth: dockerAuthB64("AWS", "eyJ...") } },
    }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss",
      "the 'AWS' vendor-token user is a published convention, demoted");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("docker-cleartext-auth demotes a local-only registry (FP[1])", () => {
  const home = mkHome();
  try {
    writeFile(home, ".docker/config.json", JSON.stringify({
      auths: { "localhost:5000": { auth: dockerAuthB64("dev", "dev") } },
    }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss",
      "a loopback dev registry is demoted");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("docker-cleartext-auth misses when a global credsStore covers the registry (FP[2])", () => {
  const home = mkHome();
  try {
    writeFile(home, ".docker/config.json", JSON.stringify({
      credsStore: "desktop",
      auths: { "registry.example.com": { auth: dockerAuthB64("deploybot", "s3cret") } },
    }));
    const r = collectAt(home);
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss",
      "a global credsStore means the auth entry is not the live credential");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// npm-pat-present / pypi-token-present — project-level carriers under cwd
// ---------------------------------------------------------------------------

test("npm-pat-present hits on a project .npmrc carrying an npm_ PAT", () => {
  const home = mkHome();
  const cwd = mkCwd();
  try {
    fs.writeFileSync(path.join(cwd, ".npmrc"),
      "//registry.npmjs.org/:_authToken=npm_" + "A".repeat(36) + "\n");
    const r = collectAt(home, cwd);
    assert.equal(r.signal_overrides["npm-pat-present"], "hit");
    assert.match(r.artifacts["npmrc"].value, /_authToken_present=true/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test("npm-pat-present misses on a registry-only .npmrc (no auth token)", () => {
  const home = mkHome();
  const cwd = mkCwd();
  try {
    fs.writeFileSync(path.join(cwd, ".npmrc"), "registry=https://registry.npmjs.org/\n");
    const r = collectAt(home, cwd);
    assert.equal(r.signal_overrides["npm-pat-present"], "miss");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test("pypi-token-present hits on a project .pypirc carrying a pypi- token", () => {
  const home = mkHome();
  const cwd = mkCwd();
  try {
    fs.writeFileSync(path.join(cwd, ".pypirc"),
      "[pypi]\nusername = __token__\npassword = pypi-" + "B".repeat(50) + "\n");
    const r = collectAt(home, cwd);
    assert.equal(r.signal_overrides["pypi-token-present"], "hit");
    assert.match(r.artifacts["pypirc"].value, /token_present=true/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Deferred (non-deterministic) artifacts stay captured=false so the runner
// records partial-evidence coverage rather than a forged miss.
// ---------------------------------------------------------------------------

test("non-deterministic carriers are surfaced as captured=false with a reason", () => {
  const home = mkHome();
  try {
    const r = collectAt(home);
    for (const id of ["gpg-keys", "ssh-keys-inventory", "ssh-config", "keychain-inventory"]) {
      assert.ok(r.artifacts[id], `artifact ${id} must be present`);
      assert.equal(r.artifacts[id].captured, false, `${id} must be deferred (captured=false)`);
      assert.equal(typeof r.artifacts[id].reason, "string");
      assert.ok(r.artifacts[id].reason.length > 0);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Platform-conditional: POSIX mode-bit indicator. On win32 it is skipped;
// on POSIX a 0644 carrier flips credentials-file-bad-perms.
// ---------------------------------------------------------------------------

test("credentials-file-bad-perms is skipped on win32 (ACL out of scope)", { skip: process.platform !== "win32" }, () => {
  const home = mkHome();
  try {
    writeFile(home, ".aws/credentials", "[p]\naws_access_key_id=AKIA1234567890ABCDEF\n");
    const r = collectAt(home);
    assert.ok(!("credentials-file-bad-perms" in r.signal_overrides),
      "win32 must not emit the POSIX mode-bit verdict");
    assert.equal(r.artifacts["credentials-file-perms-check"].captured, false);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("credentials-file-bad-perms hits on a 0644 credentials file on POSIX", { skip: process.platform === "win32" }, () => {
  const home = mkHome();
  try {
    const f = writeFile(home, ".aws/credentials",
      "[p]\naws_access_key_id=AKIA1234567890ABCDEF\naws_secret_access_key=x\n");
    fs.chmodSync(f, 0o644);
    const r = collectAt(home);
    assert.equal(r.signal_overrides["credentials-file-bad-perms"], "hit",
      "a world-readable 0644 credentials file must flip the indicator");
    assert.deepEqual(r.signal_overrides["credentials-file-bad-perms__fp_checks"], { "0": true, "1": true });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("credentials-file-bad-perms misses on a correctly-0600 credentials file on POSIX", { skip: process.platform === "win32" }, () => {
  const home = mkHome();
  try {
    const f = writeFile(home, ".aws/credentials",
      "[p]\naws_access_key_id=AKIA1234567890ABCDEF\naws_secret_access_key=x\n");
    fs.chmodSync(f, 0o600);
    const r = collectAt(home);
    assert.equal(r.signal_overrides["credentials-file-bad-perms"], "miss",
      "a 0600 credentials file is at the expected mode");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
