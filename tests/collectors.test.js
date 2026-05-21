"use strict";

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

test("collector modules export the contract: playbook_id + collect()", () => {
  for (const mod of [secretsCollector, kernelCollector, sbomCollector, containersCollector]) {
    assert.equal(typeof mod.playbook_id, "string", "playbook_id must be a string");
    assert.ok(mod.playbook_id.length > 0);
    assert.equal(typeof mod.collect, "function", "collect must be a function");
  }
  assert.equal(secretsCollector.playbook_id, "secrets");
  assert.equal(kernelCollector.playbook_id, "kernel");
  assert.equal(sbomCollector.playbook_id, "sbom");
  assert.equal(containersCollector.playbook_id, "containers");
});

test("collector.collect() returns the contract envelope when called directly", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-direct-"));
  try {
    const result = sbomCollector.collect({ cwd: tmp });
    for (const k of ["precondition_checks", "artifacts", "signal_overrides", "collector_meta", "collector_errors"]) {
      assert.ok(k in result, `direct collect() return must carry "${k}"`);
    }
    assert.equal(result.collector_meta.collector_id, "sbom");
    // Empty tempdir has no lockfile + no SBOM → artifacts carry the
    // "none found" prose; the precondition reflects the absence.
    assert.equal(result.precondition_checks["sbom-tool-available"], false);
    assert.match(result.artifacts["lockfile-inventory"].value, /no lockfile found/);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

test("collect <unknown> exits 1 with structured error + lists available collectors", () => {
  const r = cli(["collect", "this-collector-does-not-exist"]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err, "stderr must be parseable JSON");
  assert.equal(err.type, "collector_not_found");
  assert.ok(Array.isArray(err.collectors_available));
  // The three reference collectors must be present.
  assert.ok(err.collectors_available.includes("secrets"));
  assert.ok(err.collectors_available.includes("kernel"));
  assert.ok(err.collectors_available.includes("sbom"));
  // The error must point the operator at the AI-evidence path.
  assert.match(err.error, /AI-evidence path remains/);
});

test("collect kernel emits the contract envelope shape", () => {
  const r = cli(["collect", "kernel", "--json"]);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body, `must emit parseable JSON; stdout: ${r.stdout.slice(0, 200)}`);
  for (const k of ENVELOPE_KEYS) {
    assert.ok(k in body, `envelope must carry "${k}" top-level key`);
  }
  assert.equal(body.collector_meta.collector_id, "kernel");
  assert.equal(typeof body.collector_meta.captured_at, "string");
  // linux-platform precondition is deterministic from process.platform.
  assert.equal(typeof body.precondition_checks["linux-platform"], "boolean");
});

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

test("secrets collector world-writable-env-file does NOT fire on non-env carrier (codex P1 false-positive guard)", { skip: process.platform === "win32" }, () => {
  // Pre-fix the collector flagged ANY world-writable carrier as
  // world-writable-env-file. A world-writable .npmrc must NOT trigger
  // that indicator — the playbook scopes the predicate to env files.
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

test("collect --cwd <nonexistent> exits with structured error", () => {
  const r = cli(["collect", "kernel", "--cwd", "/path/that/absolutely/does/not/exist-" + Date.now()]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err);
  assert.match(err.error, /does not exist/);
});

test("collect sbom emits only signal_overrides that exist in the playbook indicator set", () => {
  // The sbom playbook's indicator set is owned by data/playbooks/sbom.json.
  // The collector must NOT emit invented keys (those would be silently
  // ignored by the runner). It MAY flip `lockfile-no-integrity` when it
  // can decide deterministically from the lockfile contents.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-sbom-"));
  try {
    // Lockfile with one integrity entry and one resolved-but-no-integrity entry.
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/foo": { version: "1.0.0", resolved: "https://r/foo-1.0.0.tgz", integrity: "sha512-abc" },
        "node_modules/bar": { version: "2.0.0", resolved: "https://r/bar-2.0.0.tgz" },
      },
    }));
    const r = cli(["collect", "sbom", "--cwd", tmp, "--json"]);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body);
    // The artifact carrying the lockfile inventory must be visible.
    assert.match(body.artifacts["lockfile-inventory"].value, /npm:package-lock\.json/);
    // signal_overrides must NOT contain the previously-invented keys.
    assert.equal(body.signal_overrides["sbom-document-absent"], undefined,
      "collector must not emit invented indicator keys — they're silently ignored by the runner");
    assert.equal(body.signal_overrides["lockfile-absent"], undefined,
      "ditto for lockfile-absent");
    // lockfile-no-integrity IS in the playbook indicator set and the
    // collector can decide it deterministically.
    assert.equal(body.signal_overrides["lockfile-no-integrity"], "hit",
      "collector must flip lockfile-no-integrity when an entry resolves without integrity");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect sbom does not flip lockfile-no-integrity when every entry carries integrity", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-sbom-clean-"));
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/foo": { version: "1.0.0", resolved: "https://r/foo.tgz", integrity: "sha512-abc" },
      },
    }));
    const r = cli(["collect", "sbom", "--cwd", tmp, "--json"]);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.equal(body.signal_overrides["lockfile-no-integrity"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("containers collector flips every deterministic indicator on a synthetic bad-shape fixture", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-containers-"));
  try {
    fs.writeFileSync(path.join(tmp, "Dockerfile"), [
      "FROM ubuntu:latest",
      "RUN curl https://get.example.com | bash",
      "COPY app /",
      'CMD ["/app"]',
    ].join("\n") + "\n");
    fs.writeFileSync(path.join(tmp, "docker-compose.yml"), [
      "services:",
      "  web:",
      "    image: nginx",
      "    privileged: true",
      "    network_mode: host",
      "    volumes:",
      "      - /var/run/docker.sock:/var/run/docker.sock",
    ].join("\n") + "\n");
    fs.writeFileSync(path.join(tmp, "deployment.yaml"), [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "metadata:",
      "  name: app",
      "spec:",
      "  template:",
      "    spec:",
      "      hostNetwork: true",
      "      containers:",
      "        - image: nginx:latest",
      "          securityContext:",
      "            runAsUser: 0",
      "            privileged: true",
    ].join("\n") + "\n");

    const r = containersCollector.collect({ cwd: tmp });
    const expectedHits = [
      "dockerfile-from-latest", "dockerfile-no-digest-pin",
      "dockerfile-runs-as-root", "dockerfile-curl-pipe-bash",
      "compose-privileged", "compose-host-network", "compose-docker-sock-mount",
      "k8s-privileged", "k8s-host-namespaces", "k8s-run-as-root", "k8s-image-latest",
    ];
    for (const id of expectedHits) {
      assert.equal(r.signal_overrides[id], "hit",
        `containers collector must flip ${id} on the bad-shape fixture`);
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("containers collector misses every indicator on a clean Dockerfile (digest-pinned + non-root)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-containers-clean-"));
  try {
    fs.writeFileSync(path.join(tmp, "Dockerfile"), [
      "FROM node:20-alpine@sha256:" + "a".repeat(64),
      "USER nonroot",
      "RUN echo safe",
    ].join("\n") + "\n");
    const r = containersCollector.collect({ cwd: tmp });
    for (const id of ["dockerfile-from-latest", "dockerfile-no-digest-pin", "dockerfile-runs-as-root", "dockerfile-curl-pipe-bash"]) {
      assert.equal(r.signal_overrides[id], "miss",
        `clean Dockerfile must NOT flip ${id}`);
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect <pb> --pretty produces indented JSON envelope", () => {
  const r = cli(["collect", "kernel", "--pretty"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^\{\n /, "pretty mode must indent the JSON envelope");
  const body = tryJson(r.stdout);
  assert.ok(body);
  assert.equal(body.collector_meta.collector_id, "kernel");
});
