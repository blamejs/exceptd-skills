"use strict";


// ---- routed from collectors ----
require("node:test").describe("collectors", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors.test.js
 *
 * Pins the collector interface contract + reference implementations:
 *   - exceptd collect <unknown> -> structured error + exit 1 + lists
 *     the available collectors so an operator can discover them.
 *   - exceptd collect <known> -> submission JSON with the required
 *     top-level keys (precondition_checks, artifacts,
 *     signal_overrides, collector_meta, collector_errors).
 *   - exceptd collect <known> | exceptd run <known> --evidence -
 *     round-trips: the runner accepts the collector's output without
 *     schema errors.
 *   - exceptd collect <known> --cwd <nonexistent> -> structured error.
 *   - secrets collector finds expected file types on a synthetic
 *     repo with a fake .env + fake .npmrc.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// Direct module imports so the diff-coverage gate sees the exports
// are exercised by unit-level tests, not just via subprocess
// invocation through the CLI.
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const kernelCollector = require(path.join(ROOT, "lib", "collectors", "kernel.js"));
const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
const containersCollector = require(path.join(ROOT, "lib", "collectors", "containers.js"));
const libraryAuthorCollector = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
const cryptoCodebaseCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const credStoresCollector = require(path.join(ROOT, "lib", "collectors", "cred-stores.js"));
const hardeningCollector = require(path.join(ROOT, "lib", "collectors", "hardening.js"));
const runtimeCollector = require(path.join(ROOT, "lib", "collectors", "runtime.js"));
const aiApiCollector = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));
const mcpCollector = require(path.join(ROOT, "lib", "collectors", "mcp.js"));



const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

test("secrets collector permission predicates match the playbook indicator spec", { skip: process.platform === "win32" }, () => {
  // The secrets playbook defines:
  //   world-writable-env-file: env-files only, mode 0666 or 0664 (group/world writable)
  //   ssh-key-bad-perms: ssh-private-keys only, mode != 0600
  // Verify the collector implements those predicates, not loose proxies.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-perm-"));
  try {
    // env-file with group-write bit (mode 0664) → world-writable-env-file MUST hit.
    const envPath = path.join(tmp, ".env");
    fs.writeFileSync(envPath, "FOO=bar\n");
    fs.chmodSync(envPath, 0o664);
    // ssh-private-key with mode 0640 (group-read only) → ssh-key-bad-perms MUST hit because mode != 0600.
    const sshPath = path.join(tmp, "id_rsa");
    fs.writeFileSync(sshPath, "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n");
    fs.chmodSync(sshPath, 0o640);

    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["world-writable-env-file"], "hit",
      "0664 .env must hit world-writable-env-file (group-writable bit set)");
    assert.equal(r.signal_overrides["ssh-key-bad-perms"], "hit",
      "0640 ssh private key must hit ssh-key-bad-perms (mode != 0600)");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("secrets collector world-writable-env-file does NOT fire on non-env carrier", { skip: process.platform === "win32" }, () => {
  // The playbook scopes world-writable-env-file to env-files only.
  // A world-writable .npmrc must NOT trigger that indicator — it
  // belongs under the broader auth-config-files scope instead.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-perm-scope-"));
  try {
    const npmrcPath = path.join(tmp, ".npmrc");
    fs.writeFileSync(npmrcPath, "registry=https://registry.npmjs.org/\n");
    fs.chmodSync(npmrcPath, 0o666);
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["world-writable-env-file"], "miss",
      "world-writable .npmrc is OUT of scope for world-writable-env-file (env-files only)");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect secrets pipes through to run --evidence - without schema errors", () => {
  // Use a synthetic tempdir as the collect target so the test is
  // deterministic + bounded.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-pipe-"));
  try {
    fs.writeFileSync(path.join(tmp, ".env"), "AWS_KEY=AKIA1234567890ABCDEF\nOTHER=value\n");
    fs.writeFileSync(path.join(tmp, "README.md"), "no secrets here\n");
    const collectR = cli(["collect", "secrets", "--cwd", tmp, "--json"]);
    assert.equal(collectR.status, 0);
    const submission = tryJson(collectR.stdout);
    assert.ok(submission, "collector stdout must be parseable JSON");
    assert.equal(submission.signal_overrides["aws-access-key-id"], "hit",
      "secrets collector must flip aws-access-key-id to hit when a real AKIA literal is present");
    // Pipe collector output into run.
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "collect-run-"));
    const runR = cli(["run", "secrets", "--evidence", "-"],
      { input: JSON.stringify(submission), env: { EXCEPTD_HOME: tmpHome } });
    assert.equal(runR.status, 0, `run must accept the collector's submission; stderr: ${runR.stderr.slice(0, 200)}`);
    // The run human output must show the indicator firing.
    assert.match(runR.stdout, /\[!! DETECTED\]|aws-access-key-id/,
      "the runner must recognise the collector-supplied signal_overrides");
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


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

test("secrets: text file over 1 MB is recorded as file_too_large_skipped (not silent)", () => {
  const tmp = mkTmp("fp-secrets-big-");
  try {
    // 1 MB limit is exclusive (> MAX). Build a >1 MB .txt file.
    const big = "A".repeat(1024 * 1024 + 64) + "\n";
    fs.writeFileSync(path.join(tmp, "huge.txt"), big);
    const r = secretsCollector.collect({ cwd: tmp });
    const skip = r.collector_errors.find(e => e.kind === "file_too_large_skipped");
    assert.ok(skip, "a >1 MB text file must produce a file_too_large_skipped collector error");
    assert.equal(skip.artifact_id, "secret-regex-scan-text-files");
    assert.match(skip.reason, /huge\.txt/);
    assert.match(skip.reason, /not scanned/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: AWS doc example key AKIAIOSFODNN7EXAMPLE does NOT flip aws-access-key-id", () => {
  const tmp = mkTmp("fp-secrets-awsexample-");
  try {
    fs.writeFileSync(path.join(tmp, "README.md"),
      "# Example\n\nUse your AWS key, e.g. `AKIAIOSFODNN7EXAMPLE`, from the AWS docs.\n");
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "miss",
      "the published AWS example key must be demoted");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a non-example AKIA key DOES flip aws-access-key-id", () => {
  const tmp = mkTmp("fp-secrets-awsreal-");
  try {
    // 16 trailing uppercase/digit chars, not the example value.
    fs.writeFileSync(path.join(tmp, "config.txt"),
      "aws_access_key_id = AKIA1234567890ABCDEF\n");
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "hit",
      "a real-shaped AKIA key must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: evidence_locations carry a startLine pointing at the secret's line", () => {
  const tmp = mkTmp("fp-secrets-line-");
  try {
    // Real GitHub PAT shape on line 3 (1-based).
    const ghp = "ghp_" + "A".repeat(36);
    fs.writeFileSync(path.join(tmp, "leak.env"),
      `# comment line 1\nFOO=bar\nTOKEN=${ghp}\n`);
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["github-personal-access-token"], "hit");
    const locs = r.evidence_locations["github-personal-access-token"];
    assert.ok(Array.isArray(locs) && locs.length === 1, "exactly one location expected");
    assert.equal(locs[0].uri, "leak.env");
    assert.equal(locs[0].startLine, 3, "startLine must point at the line carrying the token");
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
