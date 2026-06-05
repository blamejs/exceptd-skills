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
const libraryAuthorCollector = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
const cryptoCodebaseCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const credStoresCollector = require(path.join(ROOT, "lib", "collectors", "cred-stores.js"));
const hardeningCollector = require(path.join(ROOT, "lib", "collectors", "hardening.js"));
const runtimeCollector = require(path.join(ROOT, "lib", "collectors", "runtime.js"));
const aiApiCollector = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));
const mcpCollector = require(path.join(ROOT, "lib", "collectors", "mcp.js"));

test("collector modules export the contract: playbook_id + collect()", () => {
  for (const mod of [secretsCollector, kernelCollector, sbomCollector, containersCollector, libraryAuthorCollector, cryptoCodebaseCollector, credStoresCollector, hardeningCollector, runtimeCollector, aiApiCollector, mcpCollector]) {
    assert.equal(typeof mod.playbook_id, "string", "playbook_id must be a string");
    assert.ok(mod.playbook_id.length > 0);
    assert.equal(typeof mod.collect, "function", "collect must be a function");
  }
  assert.equal(secretsCollector.playbook_id, "secrets");
  assert.equal(kernelCollector.playbook_id, "kernel");
  assert.equal(sbomCollector.playbook_id, "sbom");
  assert.equal(containersCollector.playbook_id, "containers");
  assert.equal(libraryAuthorCollector.playbook_id, "library-author");
  assert.equal(cryptoCodebaseCollector.playbook_id, "crypto-codebase");
  assert.equal(credStoresCollector.playbook_id, "cred-stores");
  assert.equal(hardeningCollector.playbook_id, "hardening");
  assert.equal(runtimeCollector.playbook_id, "runtime");
  assert.equal(aiApiCollector.playbook_id, "ai-api");
  assert.equal(mcpCollector.playbook_id, "mcp");
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
    // Realistic npm 7+ root entry: the `""` package legitimately carries
    // name + version and NO integrity (it's the project itself, not a remote
    // tarball). A clean lockfile like this must report "miss" — counting the
    // root entry as missing-integrity false-positived on every real repo.
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
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

test("sbom collector recognises pyproject.toml as a Python dependency manifest", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-pyproject-"));
  try {
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), [
      "[project]",
      'name = "x"',
      "dependencies = [",
      '  "requests>=2.0",',
      '  "urllib3>=1.26",',
      "]",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/sbom.js");
    const r = collect({ cwd: tmp });
    assert.ok(r.collector_meta.ecosystems_detected.includes("python"),
      `expected python in ecosystems; got: ${JSON.stringify(r.collector_meta.ecosystems_detected)}`);
    assert.match(r.artifacts["lockfile-inventory"].value, /pyproject\.toml/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom collector recognises requirements-VARIANT.txt glob (not just the canonical name)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-reqglob-"));
  try {
    fs.writeFileSync(path.join(tmp, "requirements-dev.txt"), "pytest\nblack\n");
    fs.writeFileSync(path.join(tmp, "dev-requirements.txt"), "ruff\n");
    const { collect } = require("../lib/collectors/sbom.js");
    const r = collect({ cwd: tmp });
    const inv = r.artifacts["lockfile-inventory"].value;
    assert.match(inv, /requirements-dev\.txt/);
    assert.match(inv, /dev-requirements\.txt/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom collector probes one level into docs/ + packages/ subdirs", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-subdir-"));
  try {
    // docs/requirements.txt (sphinx-style)
    fs.mkdirSync(path.join(tmp, "docs"));
    fs.writeFileSync(path.join(tmp, "docs", "requirements.txt"), "sphinx\nfuro\n");
    // packages/foo/package.json (monorepo workspace)
    fs.mkdirSync(path.join(tmp, "packages", "foo"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "packages", "foo", "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/bar": { version: "1.0.0", integrity: "sha512-x" } },
    }));
    const { collect } = require("../lib/collectors/sbom.js");
    const r = collect({ cwd: tmp });
    const inv = r.artifacts["lockfile-inventory"].value;
    assert.match(inv, /docs\/requirements\.txt/);
    assert.match(inv, /packages\/foo\/package-lock\.json/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom collector does not double-count requirements.txt when both root-LOCKFILES match and glob match are eligible", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-no-dup-"));
  try {
    // Only the canonical name at root — must be captured exactly once.
    fs.writeFileSync(path.join(tmp, "requirements.txt"), "requests\nurllib3\n");
    const { collect } = require("../lib/collectors/sbom.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.collector_meta.lockfiles_found, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
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

test("containers collector matches the playbook predicates exactly across edge-case forms", () => {
  // Four predicate-alignment regression cases that each surface a
  // distinct form the playbook contract specifies — pinning them so
  // future renames don't silently regress the contract.
  const cases = [
    {
      name: "USER 0:0 counts as root",
      dockerfile: "FROM alpine\nUSER 0:0\n",
      expect: { "dockerfile-runs-as-root": "hit" },
    },
    {
      name: "USER root:wheel counts as root",
      dockerfile: "FROM alpine\nUSER root:wheel\n",
      expect: { "dockerfile-runs-as-root": "hit" },
    },
    {
      name: "USER nonroot does NOT count as root",
      dockerfile: "FROM alpine\nUSER nonroot:wheel\n",
      expect: { "dockerfile-runs-as-root": "miss" },
    },
    {
      name: "compose pid: host fires compose-host-network",
      compose: "services:\n  web:\n    image: nginx\n    pid: host\n",
      expect: { "compose-host-network": "hit" },
    },
    {
      name: "compose ipc: host fires compose-host-network",
      compose: "services:\n  web:\n    image: nginx\n    ipc: host\n",
      expect: { "compose-host-network": "hit" },
    },
    {
      name: "compose SYS_PTRACE fires compose-cap-add-sys-admin",
      compose: "services:\n  web:\n    image: nginx\n    cap_add:\n      - SYS_PTRACE\n",
      expect: { "compose-cap-add-sys-admin": "hit" },
    },
    {
      name: "compose SYS_MODULE fires compose-cap-add-sys-admin",
      compose: "services:\n  web:\n    image: nginx\n    cap_add: [SYS_MODULE]\n",
      expect: { "compose-cap-add-sys-admin": "hit" },
    },
    {
      name: "k8s runAsNonRoot:false fires k8s-run-as-root",
      k8s: [
        "apiVersion: v1", "kind: Pod", "metadata: { name: x }",
        "spec:", "  containers:", "    - image: nginx@sha256:" + "a".repeat(64),
        "      securityContext:", "        runAsNonRoot: false",
      ].join("\n") + "\n",
      expect: { "k8s-run-as-root": "hit" },
    },
  ];
  for (const c of cases) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-c-case-"));
    try {
      if (c.dockerfile) fs.writeFileSync(path.join(tmp, "Dockerfile"), c.dockerfile);
      if (c.compose) fs.writeFileSync(path.join(tmp, "docker-compose.yml"), c.compose);
      if (c.k8s) fs.writeFileSync(path.join(tmp, "pod.yaml"), c.k8s);
      const r = containersCollector.collect({ cwd: tmp });
      for (const [id, expected] of Object.entries(c.expect)) {
        assert.equal(r.signal_overrides[id], expected,
          `case "${c.name}" expected ${id}=${expected}; got ${r.signal_overrides[id]}`);
      }
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
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

test("library-author collector flips the deterministic file-presence indicators", () => {
  // Synthetic tempdir with NO SECURITY.md, NO security.txt, NO sbom,
  // NO package.json (so publisher-context = false), NO workflows.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-lib-bare-"));
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.precondition_checks["publisher-context"], false,
      "bare tempdir has no manifest → publisher-context=false");
    assert.equal(r.signal_overrides["no-security-md"], "hit");
    assert.equal(r.signal_overrides["no-security-txt"], "hit");
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("library-author collector flips package-json-provenance-missing + lockfile-missing-integrity precisely", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-lib-pkg-"));
  try {
    // package.json WITHOUT publishConfig.provenance
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/foo": { version: "1.0.0", resolved: "https://r/foo.tgz" },  // no integrity
      },
    }));
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["package-json-provenance-missing"], "hit",
      "package.json without publishConfig.provenance must fire the indicator");
    assert.equal(r.signal_overrides["lockfile-missing-integrity"], "hit",
      "lockfile with resolved but no integrity must fire the indicator");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("library-author publish-workflow predicates align with playbook spec", () => {
  // Synthetic workflow that:
  //   - uses secrets.NPM_TOKEN (static token)
  //   - has no `id-token: write` permission
  //   - uses `actions/checkout@v4` (mutable ref, not 40-char sha)
  //   - uses `npm install` (not `npm ci`)
  //   - runs on self-hosted
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-lib-wf-"));
  try {
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.writeFileSync(path.join(tmp, ".github", "workflows", "release.yml"), [
      "name: release",
      "on: { push: { tags: ['v*'] } }",
      "jobs:",
      "  publish:",
      "    runs-on: self-hosted",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - run: npm install",
      "      - run: npm publish",
      "        env:",
      "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
    ].join("\n") + "\n");
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-uses-static-token"], "hit");
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "hit");
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "hit");
    assert.equal(r.signal_overrides["release-workflow-non-frozen-install"], "hit");
    assert.equal(r.signal_overrides["publish-workflow-runs-on-self-hosted"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("library-author static-token matcher covers every publish-credential secret in the playbook spec", () => {
  // Per data/playbooks/library-author.json: the predicate names
  // NPM_TOKEN / PYPI_TOKEN / CARGO_TOKEN / RUBYGEMS_API_KEY /
  // GEM_HOST_API_KEY. The collector must flip the indicator for
  // any of these (when id-token: write is absent).
  const tokenNames = ["NPM_TOKEN", "PYPI_TOKEN", "CARGO_TOKEN", "RUBYGEMS_API_KEY", "GEM_HOST_API_KEY"];
  for (const name of tokenNames) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `lib-token-${name}-`));
    try {
      fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
      fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
      fs.writeFileSync(path.join(tmp, ".github", "workflows", "release.yml"), [
        "name: release",
        "on: { push: { tags: ['v*'] } }",
        "jobs:",
        "  publish:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: echo publish",
        "        env:",
        `          TOKEN: \${{ secrets.${name} }}`,
      ].join("\n") + "\n");
      const r = libraryAuthorCollector.collect({ cwd: tmp });
      assert.equal(r.signal_overrides["publish-workflow-uses-static-token"], "hit",
        `secrets.${name} without id-token: write must fire publish-workflow-uses-static-token`);
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }
});

test("library-author lockfile-missing-integrity covers non-npm lockfiles + stays unflipped when no lockfile present", () => {
  // Pre-fix the collector forced miss when no package-lock.json
  // was present, hiding integrity gaps in yarn / pnpm / cargo / go
  // repos. The predicate covers ALL walked lockfiles.

  // Case A: no lockfile → indicator stays unflipped (undefined),
  // runner returns inconclusive.
  {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lib-lf-none-"));
    try {
      const r = libraryAuthorCollector.collect({ cwd: tmp });
      assert.equal(r.signal_overrides["lockfile-missing-integrity"], undefined,
        "no lockfile present → indicator must stay unflipped (inconclusive)");
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }
  // Case B: yarn.lock with one resolved-no-integrity block → hit.
  {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lib-lf-yarn-"));
    try {
      fs.writeFileSync(path.join(tmp, "yarn.lock"), [
        "# yarn lockfile v1",
        "",
        "foo@1.0.0:",
        "  version \"1.0.0\"",
        "  resolved \"https://r/foo-1.0.0.tgz\"",
        "  integrity sha512-abc",
        "",
        "bar@2.0.0:",
        "  version \"2.0.0\"",
        "  resolved \"https://r/bar-2.0.0.tgz\"",
        // no integrity line — should fire the indicator
      ].join("\n") + "\n");
      const r = libraryAuthorCollector.collect({ cwd: tmp });
      assert.equal(r.signal_overrides["lockfile-missing-integrity"], "hit",
        "yarn.lock entry with resolved + no integrity must fire the indicator");
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    }
  }
});

test("library-author package-json-provenance-missing checks workflow --provenance fallback", () => {
  // Per playbook spec: the indicator fires when BOTH manifest
  // opt-in AND workflow --provenance are absent. A repo that
  // publishes via `npm publish --provenance` without
  // publishConfig.provenance must NOT be flagged.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lib-prov-wf-"));
  try {
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.writeFileSync(path.join(tmp, ".github", "workflows", "release.yml"), [
      "name: release",
      "on: { push: { tags: ['v*'] } }",
      "jobs:",
      "  publish:",
      "    permissions: { id-token: write }",
      "    steps:",
      "      - run: npm publish --provenance",
    ].join("\n") + "\n");
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["package-json-provenance-missing"], "miss",
      "workflow --provenance path must satisfy the indicator even when publishConfig.provenance is unset");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("library-author publish-workflow heuristic demotes verify / test / e2e / kind / validate-named workflows", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "la-demote-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wf = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wf, { recursive: true });
    // Verification workflow with id-token: write + cosign-installer
    // — must NOT be classified as publish.
    fs.writeFileSync(
      path.join(wf, "kind-verify-attestation.yaml"),
      [
        "name: kind-verify-attestation",
        "on: pull_request",
        "jobs:",
        "  verify:",
        "    permissions:",
        "      id-token: write",
        "      contents: read",
        "    steps:",
        "      - uses: sigstore/cosign-installer@" + "a".repeat(40),
        "      - uses: ko-build/setup-ko@" + "b".repeat(40),
        "      - run: cosign verify-attestation example.com/img",
        "",
      ].join("\n"),
    );
    // validate-release.yml with no publish command — must NOT be
    // classified as publish.
    fs.writeFileSync(
      path.join(wf, "validate-release.yml"),
      [
        "name: validate-release",
        "on: push",
        "jobs:",
        "  validate:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@" + "c".repeat(40),
        "",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(tmp, "package.json"), '{"name":"x","version":"1.0.0"}');

    const { collect } = require("../lib/collectors/library-author.js");
    const r = collect({ cwd: tmp });
    assert.deepEqual(r.collector_meta.publish_workflows, [],
      `expected 0 publish workflows; got: ${JSON.stringify(r.collector_meta.publish_workflows)}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author recognises a real publish workflow via docker/login-action (cosign build.yaml pattern)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "la-docker-login-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wf = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wf, { recursive: true });
    // Opaque publish path: docker/login-action + Makefile invocation.
    fs.writeFileSync(
      path.join(wf, "build.yaml"),
      [
        "name: build",
        "on: push",
        "jobs:",
        "  build:",
        "    permissions:",
        "      id-token: write",
        "      contents: read",
        "    steps:",
        "      - uses: actions/checkout@" + "a".repeat(40),
        "      - uses: docker/login-action@" + "b".repeat(40),
        "      - run: make sign-ci-containers",
        "",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(tmp, "package.json"), '{"name":"x","version":"1.0.0"}');

    const { collect } = require("../lib/collectors/library-author.js");
    const r = collect({ cwd: tmp });
    assert.ok(r.collector_meta.publish_workflows.includes("build.yaml"),
      `expected build.yaml in publish_workflows; got: ${JSON.stringify(r.collector_meta.publish_workflows)}`);
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author publish-workflow predicates miss on the clean OIDC + sha-pinned shape", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-lib-wf-clean-"));
  try {
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({
      name: "x",
      version: "1.0.0",
      publishConfig: { provenance: true },
    }));
    const sha = "0".repeat(40);
    fs.writeFileSync(path.join(tmp, ".github", "workflows", "release.yml"), [
      "name: release",
      "on: { push: { tags: ['v*'] } }",
      "jobs:",
      "  publish:",
      "    runs-on: ubuntu-latest",
      "    permissions:",
      "      id-token: write",
      "      contents: read",
      "    steps:",
      `      - uses: actions/checkout@${sha}`,
      "      - run: npm ci",
      "      - run: npm publish --provenance",
    ].join("\n") + "\n");
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-uses-static-token"], "miss");
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "miss");
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "miss");
    assert.equal(r.signal_overrides["release-workflow-non-frozen-install"], "miss");
    assert.equal(r.signal_overrides["publish-workflow-runs-on-self-hosted"], "miss");
    assert.equal(r.signal_overrides["package-json-provenance-missing"], "miss");
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

test("crypto-codebase collector flips the deterministic predicates on bad fixtures", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-bad-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"));
    // Weak hash in security context: md5 + the variable name "token"
    // appears in the same file — flow heuristic flips.
    fs.writeFileSync(path.join(tmp, "src", "auth.js"), [
      "const crypto = require('crypto');",
      "function token(payload) {",
      "  return crypto.createHash('md5').update(payload).digest('hex');",
      "}",
    ].join("\n"));
    // Weak cipher mode (ECB) + RSA-1024 + TLS-old-protocol in one file.
    fs.writeFileSync(path.join(tmp, "src", "broken.js"), [
      "const c = require('crypto');",
      "c.createCipheriv('aes-128-ecb', key, null);",
      "c.generateKeyPairSync('rsa', { modulusLength: 1024 });",
      "tls.createServer({ secureProtocol: 'TLSv1_method' });",
    ].join("\n"));
    // Math.random with security variable in proximity.
    fs.writeFileSync(path.join(tmp, "src", "rng.js"), [
      "function makeToken() {",
      "  const session_token = Math.random().toString(36).slice(2);",
      "  return session_token;",
      "}",
    ].join("\n"));
    // Under-iterated PBKDF2 + low bcrypt cost.
    fs.writeFileSync(path.join(tmp, "src", "kdf.js"), [
      "const crypto = require('crypto');",
      "const bcrypt = require('bcrypt');",
      "crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256');",
      "bcrypt.hashSync(password, 8);",
    ].join("\n"));
    // Hardcoded PEM key material in source.
    fs.writeFileSync(path.join(tmp, "src", "key.js"), [
      "const KEY = `-----BEGIN PRIVATE KEY-----",
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc=",
      "-----END PRIVATE KEY-----`;",
    ].join("\n"));

    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-hash-import"], "hit");
    assert.equal(r.signal_overrides["weak-cipher-mode"], "hit");
    assert.equal(r.signal_overrides["rsa-1024-anywhere"], "hit");
    assert.equal(r.signal_overrides["math-random-in-security-path"], "hit");
    assert.equal(r.signal_overrides["pbkdf2-under-iterated"], "hit");
    assert.equal(r.signal_overrides["bcrypt-cost-low"], "hit");
    assert.equal(r.signal_overrides["hardcoded-key-material"], "hit");
    assert.equal(r.signal_overrides["tls-old-protocol"], "hit");
    assert.equal(r.signal_overrides["vendored-pqc-no-provenance"], "miss");
    assert.equal(r.collector_errors.length, 0);
    // ecdsa-without-pqc-roadmap should NOT be set — no classical sig
    // markers in the fixtures means the indicator stays unflipped
    // (inconclusive).
    assert.equal(r.signal_overrides["ecdsa-without-pqc-roadmap"], undefined);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase collector returns clean miss on a benign fixture", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-clean-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.writeFileSync(path.join(tmp, "src", "ok.js"), [
      "const crypto = require('crypto');",
      "function token() {",
      "  return crypto.randomBytes(32).toString('hex');",
      "}",
      "crypto.pbkdf2Sync(pw, salt, 600001, 32, 'sha256');",
      "bcrypt.hashSync(pw, 12);",
    ].join("\n"));
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-hash-import"], "miss");
    assert.equal(r.signal_overrides["weak-cipher-mode"], "miss");
    assert.equal(r.signal_overrides["rsa-1024-anywhere"], "miss");
    assert.equal(r.signal_overrides["math-random-in-security-path"], "miss");
    assert.equal(r.signal_overrides["pbkdf2-under-iterated"], "miss");
    assert.equal(r.signal_overrides["bcrypt-cost-low"], "miss");
    assert.equal(r.signal_overrides["hardcoded-key-material"], "miss");
    assert.equal(r.signal_overrides["tls-old-protocol"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase collector demotes test/spec/fixture paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-testdemote-"));
  try {
    fs.mkdirSync(path.join(tmp, "tests"), { recursive: true });
    // Same bad-cipher fixture as the hit test, but under tests/ — the
    // production-context indicators must NOT flip.
    fs.writeFileSync(path.join(tmp, "tests", "kat.js"), [
      "// Known-answer test against published RC4 vector.",
      "const c = require('crypto');",
      "c.createCipheriv('aes-128-ecb', key, null);",
      "c.generateKeyPairSync('rsa', { modulusLength: 1024 });",
    ].join("\n"));
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-cipher-mode"], "miss");
    assert.equal(r.signal_overrides["rsa-1024-anywhere"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase ecdsa-without-pqc-roadmap fires only when classical sig + no roadmap", () => {
  const baseline = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-ecdsa-"));
  try {
    fs.mkdirSync(path.join(baseline, "src"));
    // Classical ECDSA use, no PQC impl, no roadmap text → hit.
    fs.writeFileSync(path.join(baseline, "src", "sig.js"), [
      "const sig = crypto.sign('ECDSA', data, key);",
      "// curve secp256r1",
    ].join("\n"));
    const r1 = cryptoCodebaseCollector.collect({ cwd: baseline });
    assert.equal(r1.signal_overrides["ecdsa-without-pqc-roadmap"], "hit");

    // Add a roadmap mention in SECURITY.md → miss.
    fs.writeFileSync(path.join(baseline, "SECURITY.md"), [
      "## PQC migration",
      "This library publishes a hybrid-signature migration roadmap for downstream consumers.",
    ].join("\n"));
    const r2 = cryptoCodebaseCollector.collect({ cwd: baseline });
    assert.equal(r2.signal_overrides["ecdsa-without-pqc-roadmap"], "miss");
  } finally {
    try { fs.rmSync(baseline, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase no-ml-kem-implementation fires on PQC claim without ML-KEM", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-mlkem-"));
  try {
    // README claims PQC-ready; no ML-KEM/Kyber/liboqs anywhere in src.
    fs.writeFileSync(path.join(tmp, "README.md"), [
      "# my-lib",
      "Post-quantum ready library for next-gen cryptography.",
    ].join("\n"));
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(path.join(tmp, "src", "ok.js"), "module.exports = {};\n");
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["no-ml-kem-implementation"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase fips-claim-without-runtime-activation fires only when claim + no activation", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-fips-"));
  try {
    fs.writeFileSync(path.join(tmp, "SECURITY.md"), "This library is FIPS 140-3 validated.\n");
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(path.join(tmp, "src", "ok.js"), "module.exports = {};\n");
    const r1 = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r1.signal_overrides["fips-claim-without-runtime-activation"], "hit");

    // Add a setFips activation call site → flip to miss.
    fs.writeFileSync(path.join(tmp, "src", "boot.js"), [
      "const crypto = require('crypto');",
      "crypto.setFips(true);",
    ].join("\n"));
    const r2 = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r2.signal_overrides["fips-claim-without-runtime-activation"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase vendored-pqc-no-provenance fires on vendor PQC without provenance marker", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-vendor-"));
  try {
    fs.mkdirSync(path.join(tmp, "vendor", "kyber-impl"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "vendor", "kyber-impl", "kyber.c"), "/* kyber */\n");
    const r1 = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r1.signal_overrides["vendored-pqc-no-provenance"], "hit");

    fs.writeFileSync(path.join(tmp, "vendor", "kyber-impl", "_PROVENANCE.json"), JSON.stringify({ upstream: "x" }));
    const r2 = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r2.signal_overrides["vendored-pqc-no-provenance"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase pbkdf2 1024 iterations fires (codex P1 #77)", () => {
  // Regression test for codex P1: pbkdf2Sync(pw, salt, 1024, ...) is
  // an under-iterated call; the iter scanner must not pre-filter 1024
  // as a "common key-bit-size" value.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-pbkdf2-1024-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(path.join(tmp, "src", "kdf.js"), [
      "const crypto = require('crypto');",
      "crypto.pbkdf2Sync(pw, salt, 1024, 32, 'sha256');",
    ].join("\n"));
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["pbkdf2-under-iterated"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase test-fixture PQC/FIPS code does not contaminate behavioral signals (codex P1 #77)", () => {
  // Regression test for codex P1: ML-KEM / FIPS / Dilithium references
  // inside tests/ should NOT count as evidence the library ships the
  // capability. The library claims PQC-ready but its only ML-KEM
  // reference is in a test — should still flip no-ml-kem-implementation
  // to hit, because the production tree carries no impl.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-fixture-contam-"));
  try {
    fs.writeFileSync(path.join(tmp, "README.md"), "Post-quantum ready library.\n");
    fs.mkdirSync(path.join(tmp, "tests"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "tests", "kem-fixture.js"), [
      "// Test fixture references ML-KEM keys for round-trip checks",
      "const kyberKey = require('./fixtures/ml-kem-768.bin');",
    ].join("\n"));
    fs.writeFileSync(path.join(tmp, "src", "main.js"), "module.exports = {};\n");
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    // PQC claim + no production ML-KEM impl → hit (test fixture must
    // not flip sawMlKemImpl=true).
    assert.equal(r.signal_overrides["no-ml-kem-implementation"], "hit");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("crypto-codebase vendored-pqc walks all the way up to repo root (codex P2 #77)", () => {
  // Regression test for codex P2: provenance marker at vendor root
  // must be discovered even when the PQC source is deeply nested.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-deep-vendor-"));
  try {
    fs.mkdirSync(path.join(tmp, "vendor", "a", "b", "c", "d", "e", "kyber-impl"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "vendor", "a", "b", "c", "d", "e", "kyber-impl", "kyber.c"), "/* kyber */\n");
    // Marker at the vendor root — 6+ levels above the source file.
    fs.writeFileSync(path.join(tmp, "vendor", "_PROVENANCE.json"), JSON.stringify({ upstream: "x" }));
    const r = cryptoCodebaseCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["vendored-pqc-no-provenance"], "miss",
      "provenance marker at vendor root must be found regardless of nesting depth");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect crypto-codebase pipes into run --evidence -", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "collect-crypto-pipe-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(path.join(tmp, "src", "auth.js"), [
      "function token() {",
      "  return require('crypto').createHash('md5').update('x').digest('hex');",
      "}",
    ].join("\n"));
    const collected = cli(["collect", "crypto-codebase", "--json", "--cwd", tmp]);
    assert.equal(collected.status, 0, `collect stderr: ${collected.stderr}`);
    const ran = cli(["run", "crypto-codebase", "--evidence", "-", "--json"], { input: collected.stdout });
    // The runner may return any verdict; what matters is that it
    // accepts the collector's submission and returns a structured
    // envelope rather than a parse error.
    const body = tryJson(ran.stdout) || tryJson(ran.stderr);
    assert.ok(body, `run must emit parseable JSON; status=${ran.status}, stdout: ${ran.stdout.slice(0, 200)}; stderr: ${ran.stderr.slice(0, 200)}`);
    assert.equal(body.playbook_id, "crypto-codebase");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

// Fake-HOME helper for cred-stores fixture tests. Each test stages a
// synthetic ~/.aws / ~/.kube / etc. inside the tempdir and points
// the collector at it via env.HOME (env.USERPROFILE on Windows is
// honoured by the collector too).
function fakeHome(prefix) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return {
    home: tmp,
    write(rel, content) {
      const full = path.join(tmp, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
    cleanup() {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    },
  };
}

test("cred-stores collector flips zero on a clean fake-home", () => {
  const h = fakeHome("cred-clean-");
  try {
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss");
    assert.equal(r.signal_overrides["kube-static-token"], "miss");
    assert.equal(r.signal_overrides["gcp-service-account-json-adc"], "miss");
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss");
    assert.equal(r.signal_overrides["npm-pat-present"], "miss");
    assert.equal(r.signal_overrides["pypi-token-present"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores aws-static-key-present fires on AKIA* with no federation", () => {
  const h = fakeHome("cred-aws-static-");
  try {
    h.write(".aws/credentials", [
      "[default]",
      // Synthetic AKIA value — not the AWS-published doc-fixture
      // (AKIAIOSFODNN7EXAMPLE), which the collector demotes per
      // false_positive_checks_required[0].
      "aws_access_key_id = AKIASYNTHETICTESTKEY",
      "aws_secret_access_key = " + "a".repeat(40),
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["aws-static-key-present"], "hit");
    // Codex P1 #78: the collector must attest the FP checks it ran so
    // the runner doesn't downgrade hit → inconclusive.
    const att = r.signal_overrides["aws-static-key-present__fp_checks"];
    assert.equal(typeof att, "object", "fp-check attestation must be present on hit");
    assert.equal(att["0"], true);
    assert.equal(att["2"], true);
  } finally {
    h.cleanup();
  }
});

test("cred-stores aws-static-key-present demotes the AWS-published doc-fixture key (codex P1 #78 FP[0])", () => {
  const h = fakeHome("cred-aws-docfixture-");
  try {
    h.write(".aws/credentials", [
      "[default]",
      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss");
    assert.equal(r.signal_overrides["aws-static-key-present__fp_checks"], undefined);
  } finally {
    h.cleanup();
  }
});

test("cred-stores aws-static-key-present demotes break-glass profile names (codex P1 #78 FP[2])", () => {
  const h = fakeHome("cred-aws-breakglass-");
  try {
    h.write(".aws/credentials", [
      "[breakglass-emergency]",
      "aws_access_key_id = AKIASYNTHETICBREAKGLASS",
      "aws_secret_access_key = " + "z".repeat(40),
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores aws-static-key-present demotes when sso_session present", () => {
  const h = fakeHome("cred-aws-sso-");
  try {
    h.write(".aws/credentials", [
      "[profile work]",
      "sso_session = my-org",
      "sso_account_id = 111122223333",
      "sso_role_name = ReadOnly",
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["aws-static-key-present"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores kube-static-token fires on users[].user.token", () => {
  const h = fakeHome("cred-kube-static-");
  try {
    h.write(".kube/config", [
      "apiVersion: v1",
      "kind: Config",
      "users:",
      "- name: admin",
      "  user:",
      "    token: abcdef1234567890",
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["kube-static-token"], "hit");
  } finally {
    h.cleanup();
  }
});

test("cred-stores kube-static-token miss on auth-provider cached tokens (codex P2 #78)", () => {
  // Regression test for codex P2: tokens cached under
  // auth-provider.config.access-token (gcp-iap, oidc, etc.) are NOT
  // static credentials — they're dynamic provider tokens. The
  // collector must scope its token: match to user.token /
  // user.token-data, not any sub-key in the user block.
  const h = fakeHome("cred-kube-authprovider-");
  try {
    h.write(".kube/config", [
      "apiVersion: v1",
      "kind: Config",
      "users:",
      "- name: gcp-iap-user",
      "  user:",
      "    auth-provider:",
      "      name: gcp",
      "      config:",
      "        access-token: ya29.cached-dynamic-token-not-static",
      "        id-token: eyJhbGc.cached-id-token",
      "        refresh-token: refresh-cached",
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["kube-static-token"], "miss",
      "auth-provider.config.access-token must NOT count as user.token static credential");
  } finally {
    h.cleanup();
  }
});

test("cred-stores kube-static-token miss when only exec provider", () => {
  const h = fakeHome("cred-kube-exec-");
  try {
    h.write(".kube/config", [
      "apiVersion: v1",
      "kind: Config",
      "users:",
      "- name: admin",
      "  user:",
      "    exec:",
      "      apiVersion: client.authentication.k8s.io/v1beta1",
      "      command: aws",
      "      args:",
      "      - eks",
      "      - get-token",
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["kube-static-token"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores gcp-service-account-json-adc fires on type=service_account", () => {
  const h = fakeHome("cred-gcp-sa-");
  try {
    h.write(".config/gcloud/application_default_credentials.json", JSON.stringify({
      type: "service_account",
      private_key: "stub",
      client_email: "svc@project.iam.gserviceaccount.com",
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["gcp-service-account-json-adc"], "hit");
  } finally {
    h.cleanup();
  }
});

test("cred-stores gcp-service-account-json-adc miss on user adc shape", () => {
  const h = fakeHome("cred-gcp-user-");
  try {
    h.write(".config/gcloud/application_default_credentials.json", JSON.stringify({
      type: "authorized_user",
      client_id: "x",
      refresh_token: "y",
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["gcp-service-account-json-adc"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores docker-cleartext-auth fires when auths set with no cred helper", () => {
  const h = fakeHome("cred-docker-cleartext-");
  try {
    h.write(".docker/config.json", JSON.stringify({
      auths: { "https://index.docker.io/v1/": { auth: "dXNlcjpwYXNzd29yZA==" } },
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "hit");
  } finally {
    h.cleanup();
  }
});

test("cred-stores docker-cleartext-auth demotes vendor-token user patterns (codex P1 #78 FP[0])", () => {
  const h = fakeHome("cred-docker-vendortoken-");
  try {
    // base64("<token>:abcdef") — the user portion is `<token>`, a
    // documented ECR-helper convention; not a static cleartext cred.
    const authValue = Buffer.from("<token>:abcdef").toString("base64");
    h.write(".docker/config.json", JSON.stringify({
      auths: { "public.ecr.aws": { auth: authValue } },
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores docker-cleartext-auth demotes local-only registries (codex P1 #78 FP[1])", () => {
  const h = fakeHome("cred-docker-local-");
  try {
    const authValue = Buffer.from("user:password").toString("base64");
    h.write(".docker/config.json", JSON.stringify({
      auths: { "localhost:5000": { auth: authValue } },
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss",
      "loopback registry is local-only, blast radius is negligible");
  } finally {
    h.cleanup();
  }
});

test("cred-stores docker-cleartext-auth attests all three FP checks on hit (codex P1 #78)", () => {
  const h = fakeHome("cred-docker-fp-attest-");
  try {
    const authValue = Buffer.from("real-user:real-pass").toString("base64");
    h.write(".docker/config.json", JSON.stringify({
      auths: { "registry.example.com": { auth: authValue } },
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "hit");
    const att = r.signal_overrides["docker-cleartext-auth__fp_checks"];
    assert.equal(typeof att, "object");
    assert.equal(att["0"], true);
    assert.equal(att["1"], true);
    assert.equal(att["2"], true);
  } finally {
    h.cleanup();
  }
});

test("cred-stores docker-cleartext-auth miss when credsStore covers the registry", () => {
  const h = fakeHome("cred-docker-helper-");
  try {
    h.write(".docker/config.json", JSON.stringify({
      auths: { "https://index.docker.io/v1/": { auth: "dXNlcjpwYXNzd29yZA==" } },
      credsStore: "desktop",
    }));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["docker-cleartext-auth"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores npm-pat-present + pypi-token-present fire on the catalogued patterns", () => {
  const h = fakeHome("cred-npm-pypi-");
  try {
    h.write(".npmrc", "//registry.npmjs.org/:_authToken=npm_" + "A".repeat(36) + "\n");
    h.write(".pypirc", [
      "[pypi]",
      "username = __token__",
      "password = pypi-" + "A".repeat(50),
    ].join("\n"));
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["npm-pat-present"], "hit");
    assert.equal(r.signal_overrides["pypi-token-present"], "hit");
  } finally {
    h.cleanup();
  }
});

test("cred-stores project-level .npmrc / .pypirc are picked up via cwd", () => {
  const h = fakeHome("cred-proj-");
  const projTmp = fs.mkdtempSync(path.join(os.tmpdir(), "cred-proj-cwd-"));
  try {
    fs.writeFileSync(path.join(projTmp, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_" + "B".repeat(40) + "\n");
    const r = credStoresCollector.collect({ cwd: projTmp, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["npm-pat-present"], "hit",
      "project-level .npmrc token must flip the indicator");
  } finally {
    h.cleanup();
    try { fs.rmSync(projTmp, { recursive: true, force: true }); } catch {}
  }
});

test("cred-stores credentials-file-bad-perms: posix only; skipped on win32", { skip: process.platform === "win32" }, () => {
  const h = fakeHome("cred-perms-");
  try {
    const credPath = h.write(".aws/credentials", "[default]\naws_access_key_id = AKIASYNTHETICTESTKEY\n");
    // Make it world-readable — not 0600.
    fs.chmodSync(credPath, 0o644);
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["credentials-file-bad-perms"], "hit");
    // Codex P1 #78: FP checks the collector ran must be attested.
    const att = r.signal_overrides["credentials-file-bad-perms__fp_checks"];
    assert.equal(typeof att, "object");
    assert.equal(att["0"], true);
    assert.equal(att["1"], true);
    fs.chmodSync(credPath, 0o600);
    const r2 = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r2.signal_overrides["credentials-file-bad-perms"], "miss");
  } finally {
    h.cleanup();
  }
});

test("cred-stores credentials-file-bad-perms includes gcloud ADC (codex P2 #78)", { skip: process.platform === "win32" }, () => {
  const h = fakeHome("cred-perms-gcloud-");
  try {
    const adcPath = h.write(".config/gcloud/application_default_credentials.json", JSON.stringify({ type: "authorized_user" }));
    fs.chmodSync(adcPath, 0o644);
    const r = credStoresCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["credentials-file-bad-perms"], "hit",
      "world-readable application_default_credentials.json must flip the indicator");
  } finally {
    h.cleanup();
  }
});

// Builds a synthetic /proc + /sys + /etc/ssh layout under a tempdir
// and returns args.paths that point the hardening collector at it.
function fakeLinuxRoot(prefix, sysctls = {}, cmdline = "", lockdown = "", sshd = "", kallsyms = "") {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const write = (rel, content) => {
    const full = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
    return full;
  };
  const out = { tmp, cleanup: () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} } };
  const paths = {};
  if (sysctls.kptrRestrict != null) paths.kptrRestrict = write("proc/sys/kernel/kptr_restrict", String(sysctls.kptrRestrict));
  if (sysctls.unprivUserns != null) paths.unprivUserns = write("proc/sys/kernel/unprivileged_userns_clone", String(sysctls.unprivUserns));
  if (sysctls.unprivBpf != null) paths.unprivBpf = write("proc/sys/kernel/unprivileged_bpf_disabled", String(sysctls.unprivBpf));
  if (sysctls.yamaPtrace != null) paths.yamaPtrace = write("proc/sys/kernel/yama/ptrace_scope", String(sysctls.yamaPtrace));
  if (sysctls.suidDumpable != null) paths.suidDumpable = write("proc/sys/fs/suid_dumpable", String(sysctls.suidDumpable));
  if (cmdline != null) paths.cmdline = write("proc/cmdline", cmdline);
  if (lockdown != null) paths.lockdown = write("sys/kernel/security/lockdown", lockdown);
  if (sshd != null) paths.sshdConfig = write("etc/ssh/sshd_config", sshd);
  if (kallsyms != null) paths.kallsyms = write("proc/kallsyms", kallsyms);
  // sshd_config.d does not exist by default — point at a non-existent path.
  paths.sshdConfigD = path.join(tmp, "etc", "ssh", "sshd_config.d.nonexistent");
  out.paths = paths;
  return out;
}

test("hardening collector skips with linux-platform=false on non-Linux", () => {
  // Force-skip path: when forceLinux is NOT set and platform != linux,
  // collector emits a skipped envelope with linux-platform=false.
  const r = hardeningCollector.collect({ cwd: ROOT });
  if (process.platform !== "linux") {
    assert.equal(r.precondition_checks["linux-platform"], false);
    assert.deepEqual(r.signal_overrides, {});
    assert.match(r.artifacts["sysctl-kernel-hardening"].reason, /linux required/);
  } else {
    assert.equal(r.precondition_checks["linux-platform"], true);
  }
});

test("hardening collector flips all deterministic indicators against a synthetic bad layout", () => {
  const h = fakeLinuxRoot("harden-bad-", {
    kptrRestrict: 0,
    unprivUserns: 1,
    unprivBpf: 0,
    yamaPtrace: 0,
    suidDumpable: 1,
  }, "BOOT_IMAGE=/vmlinuz root=UUID=x mitigations=off nokaslr quiet",
     "[none] integrity confidentiality\n",
     "PermitRootLogin yes\nPasswordAuthentication yes\n",
     "ffffffff81000000 T _stext\n");
  try {
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    assert.equal(r.precondition_checks["linux-platform"], true);
    assert.equal(r.signal_overrides["kptr-restrict-disabled"], "hit");
    assert.equal(r.signal_overrides["unprivileged-userns-enabled"], "hit");
    assert.equal(r.signal_overrides["unprivileged-bpf-allowed"], "hit");
    assert.equal(r.signal_overrides["yama-ptrace-permissive"], "hit");
    assert.equal(r.signal_overrides["kaslr-disabled-at-boot"], "hit");
    assert.equal(r.signal_overrides["mitigations-off"], "hit");
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "hit");
    assert.equal(r.signal_overrides["kernel-lockdown-none"], "hit");
    // kptr FP-check attestation: collector saw kallsyms leak non-zero
    // addresses → attests FP[1].
    const att = r.signal_overrides["kptr-restrict-disabled__fp_checks"];
    assert.equal(typeof att, "object", "kptr fp-check attestation must be present");
    assert.equal(att["1"], true);
  } finally {
    h.cleanup();
  }
});

test("hardening collector returns clean miss on a hardened synthetic layout", () => {
  const h = fakeLinuxRoot("harden-good-", {
    kptrRestrict: 2,
    unprivUserns: 0,
    unprivBpf: 1,
    yamaPtrace: 1,
    suidDumpable: 0,
  }, "BOOT_IMAGE=/vmlinuz root=UUID=x quiet lockdown=confidentiality",
     "none integrity [confidentiality]\n",
     "PermitRootLogin prohibit-password\nPasswordAuthentication no\n",
     "0000000000000000 T _stext\n");
  try {
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    for (const id of [
      "kptr-restrict-disabled", "unprivileged-userns-enabled", "unprivileged-bpf-allowed",
      "yama-ptrace-permissive", "kaslr-disabled-at-boot", "mitigations-off",
      "sshd-permitrootlogin-yes", "kernel-lockdown-none",
    ]) {
      assert.equal(r.signal_overrides[id], "miss", `${id} must be miss on hardened layout`);
    }
  } finally {
    h.cleanup();
  }
});

test("hardening collector kptr fp-check NOT attested when kallsyms is zeroed (legitimate kptr=2)", () => {
  // kptr_restrict=0 but kallsyms shows zeroed addresses — the FP[1]
  // counter-evidence (kallsyms zeros despite kptr=0) means the
  // indicator should NOT carry the attestation (operator must check).
  const h = fakeLinuxRoot("harden-kptr-zeroed-", { kptrRestrict: 0 },
    "BOOT_IMAGE=/vmlinuz quiet", "[none]\n", "PermitRootLogin no\n",
    "0000000000000000 T _stext\n");
  try {
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    assert.equal(r.signal_overrides["kptr-restrict-disabled"], "hit");
    // Attestation must be absent — collector can't honestly confirm
    // the indicator is real when kallsyms shows zeros.
    assert.equal(r.signal_overrides["kptr-restrict-disabled__fp_checks"], undefined);
  } finally {
    h.cleanup();
  }
});

test("hardening collector PermitRootLogin without-password counts as hit (legacy form)", () => {
  const h = fakeLinuxRoot("harden-rootlogin-legacy-", { kptrRestrict: 2 },
    "BOOT_IMAGE=/vmlinuz quiet", "[confidentiality]\n",
    "PermitRootLogin without-password\n");
  try {
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "hit");
  } finally {
    h.cleanup();
  }
});

test("hardening collector honours sshd Include drop-in precedence (codex P1 #79)", () => {
  // Regression test for codex P1: when sshd_config starts with
  //   Include /etc/ssh/sshd_config.d/*.conf
  // OpenSSH parses the drop-in directives FIRST, so any
  // `PermitRootLogin yes` in a drop-in beats a later
  // `PermitRootLogin no` in the base file. The collector must
  // honour that ordering.
  const h = fakeLinuxRoot("harden-sshd-include-", { kptrRestrict: 2 },
    "BOOT_IMAGE=/vmlinuz quiet", "[confidentiality]\n", null);
  try {
    // sshd_config: Include first, then PermitRootLogin no.
    const sshdConfig = path.join(h.tmp, "etc", "ssh", "sshd_config");
    fs.mkdirSync(path.dirname(sshdConfig), { recursive: true });
    fs.writeFileSync(sshdConfig,
      "Include /etc/ssh/sshd_config.d/*.conf\n" +
      "PermitRootLogin no\n");
    // Drop-in: PermitRootLogin yes (should win).
    const dDir = path.join(h.tmp, "etc", "ssh", "sshd_config.d");
    fs.mkdirSync(dDir, { recursive: true });
    fs.writeFileSync(path.join(dDir, "10-cloud-init.conf"), "PermitRootLogin yes\n");
    h.paths.sshdConfig = sshdConfig;
    h.paths.sshdConfigD = dDir;
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "hit",
      "drop-in PermitRootLogin yes must beat base-file no when Include appears first");
  } finally {
    h.cleanup();
  }
});

test("hardening collector leaves unreadable sysctls unflipped (codex P1 #79)", () => {
  // Regression test for codex P1: when sysctl reads fail (permission
  // denied, masked /proc in a container, knob absent on the kernel
  // build), the indicator must NOT flip to "miss" — that asserts a
  // hardened posture without evidence. It must stay unflipped so the
  // runner returns inconclusive.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "harden-unreadable-"));
  try {
    // Point every sysctl path at a non-existent location; only
    // populate cmdline + lockdown + sshd so those indicators DO flip.
    const paths = {
      kptrRestrict: path.join(tmp, "missing-kptr"),
      unprivUserns: path.join(tmp, "missing-userns"),
      unprivBpf: path.join(tmp, "missing-bpf"),
      yamaPtrace: path.join(tmp, "missing-yama"),
      suidDumpable: path.join(tmp, "missing-suid"),
      cmdline: path.join(tmp, "cmdline"),
      lockdown: path.join(tmp, "lockdown"),
      sshdConfig: path.join(tmp, "sshd_config"),
      sshdConfigD: path.join(tmp, "sshd_config.d.nonexistent"),
      kallsyms: path.join(tmp, "missing-kallsyms"),
    };
    fs.writeFileSync(paths.cmdline, "BOOT_IMAGE=/vmlinuz quiet");
    fs.writeFileSync(paths.lockdown, "[confidentiality]\n");
    fs.writeFileSync(paths.sshdConfig, "PermitRootLogin no\n");

    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths, forceLinux: true } });
    // Sysctl-derived indicators must NOT be present in signal_overrides.
    assert.equal(r.signal_overrides["kptr-restrict-disabled"], undefined);
    assert.equal(r.signal_overrides["unprivileged-userns-enabled"], undefined);
    assert.equal(r.signal_overrides["unprivileged-bpf-allowed"], undefined);
    assert.equal(r.signal_overrides["yama-ptrace-permissive"], undefined);
    // cmdline-derived + sshd-derived indicators DO flip — they're
    // readable.
    assert.equal(r.signal_overrides["kaslr-disabled-at-boot"], "miss");
    assert.equal(r.signal_overrides["mitigations-off"], "miss");
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "miss");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("hardening collector lockdown=integrity in cmdline counts kernel-lockdown as miss", () => {
  const h = fakeLinuxRoot("harden-lockdown-int-", { kptrRestrict: 2 },
    "BOOT_IMAGE=/vmlinuz quiet lockdown=integrity",
    "", // no /sys/kernel/security/lockdown file
    "PermitRootLogin no\n");
  // Override the lockdown path with a deliberately non-existent
  // file so the collector treats it as absent. (Deleting the key
  // lets the default `/sys/kernel/security/lockdown` take over,
  // which DOES exist on CI Linux hosts and would contaminate the
  // test's intended absent-file scenario.)
  h.paths.lockdown = path.join(h.tmp, "lockdown.nonexistent");
  try {
    const r = hardeningCollector.collect({ cwd: ROOT, args: { paths: h.paths, forceLinux: true } });
    assert.equal(r.signal_overrides["kernel-lockdown-none"], "miss");
  } finally {
    h.cleanup();
  }
});

function fakeRuntimeRoot(prefix) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const write = (rel, content) => {
    const full = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
    return full;
  };
  const mkdir = (rel) => { const full = path.join(tmp, rel); fs.mkdirSync(full, { recursive: true }); return full; };
  return {
    tmp, write, mkdir,
    cleanup() { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} },
  };
}

test("runtime collector skips with linux-platform=false on non-Linux", () => {
  if (process.platform === "linux") return; // Linux host would actually flip
  const r = runtimeCollector.collect({ cwd: ROOT });
  assert.equal(r.precondition_checks["linux-platform"], false);
  assert.deepEqual(r.signal_overrides, {});
});

test("runtime collector flips sudoers-nopasswd-wildcard on a wildcard rule", () => {
  const h = fakeRuntimeRoot("runtime-sudo-wild-");
  try {
    const sudoers = h.write("etc/sudoers", "Defaults requiretty\nroot ALL=(ALL) ALL\n");
    const sudoersD = h.mkdir("etc/sudoers.d");
    h.write("etc/sudoers.d/10-bad", "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart *\n");
    h.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: { sudoers, sudoersD, passwd: path.join(h.tmp, "etc/passwd"), trustedPaths: [], procRoot: path.join(h.tmp, "nonexistent") },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "hit");
    assert.equal(r.signal_overrides["duplicate-uid-zero"], "miss");
  } finally {
    h.cleanup();
  }
});

test("runtime collector skips root NOPASSWD ALL (tautological — not a finding)", () => {
  const h = fakeRuntimeRoot("runtime-sudo-root-");
  try {
    const sudoers = h.write("etc/sudoers", "root ALL=(ALL) NOPASSWD: ALL\n");
    const passwd = h.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: { sudoers, sudoersD: path.join(h.tmp, "nodir"), passwd, trustedPaths: [], procRoot: path.join(h.tmp, "nodir") },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "miss");
  } finally {
    h.cleanup();
  }
});

test("runtime collector flips duplicate-uid-zero on >1 UID-0 entries", () => {
  const h = fakeRuntimeRoot("runtime-uid0-");
  try {
    const sudoers = h.write("etc/sudoers", "");
    const passwd = h.write("etc/passwd",
      "root:x:0:0:root:/root:/bin/bash\n" +
      "toor:x:0:0:backdoor:/root:/bin/bash\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: { sudoers, sudoersD: path.join(h.tmp, "nodir"), passwd, trustedPaths: [], procRoot: path.join(h.tmp, "nodir") },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["duplicate-uid-zero"], "hit");
  } finally {
    h.cleanup();
  }
});

test("runtime collector duplicate-uid-zero miss on single UID 0", () => {
  const h = fakeRuntimeRoot("runtime-uid0-single-");
  try {
    const passwd = h.write("etc/passwd",
      "root:x:0:0:root:/root:/bin/bash\n" +
      "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: { sudoers: path.join(h.tmp, "noexist"), sudoersD: path.join(h.tmp, "nodir"), passwd, trustedPaths: [], procRoot: path.join(h.tmp, "nodir") },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["duplicate-uid-zero"], "miss");
  } finally {
    h.cleanup();
  }
});

test("runtime collector world-writable-in-trusted-path: posix only", { skip: process.platform === "win32" }, () => {
  const h = fakeRuntimeRoot("runtime-ww-");
  try {
    const trustedDir = h.mkdir("opt");
    const bad = h.write("opt/payload.sh", "#!/bin/sh\necho pwn\n");
    fs.chmodSync(bad, 0o777);
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: {
          sudoers: path.join(h.tmp, "noexist"),
          sudoersD: path.join(h.tmp, "nodir"),
          passwd: path.join(h.tmp, "nopasswd"),
          trustedPaths: [trustedDir],
          procRoot: path.join(h.tmp, "nodir"),
        },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["world-writable-in-trusted-path"], "hit");
  } finally {
    h.cleanup();
  }
});

test("runtime collector mixed-user sudoers entry fires when non-root principal grants wildcard (codex P2 #80)", () => {
  const h = fakeRuntimeRoot("runtime-mixed-sudo-");
  try {
    const sudoers = h.write("etc/sudoers", "root,deploy ALL=(ALL) NOPASSWD: ALL\n");
    const passwd = h.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: { sudoers, sudoersD: path.join(h.tmp, "nodir"), passwd, trustedPaths: [], procRoot: path.join(h.tmp, "nodir") },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "hit",
      "root,deploy NOPASSWD: ALL grants wildcard to deploy — must fire");
  } finally {
    h.cleanup();
  }
});

test("runtime collector orphan-privileged stays unflipped when /proc/<pid>/exe unreadable (codex P1 #80)", () => {
  // Synthesise /proc layout where every PID's status file exists
  // but no exe symlink does — mirrors hidepid / ptrace-restrict on
  // non-root scope. The collector must NOT report "miss" — that
  // would mask real orphan-privileged implants.
  const h = fakeRuntimeRoot("runtime-orphan-noexe-");
  try {
    const procRoot = h.mkdir("proc");
    // PID 1 (no exe symlink readable)
    h.write("proc/1/status", "Name:\tsystemd\nPPid:\t0\nUid:\t0\t0\t0\t0\n");
    // PID 100, UID 0, PPID 1 — would look like an orphan, but exe
    // symlink missing.
    h.write("proc/100/status", "Name:\tsuspicious\nPPid:\t1\nUid:\t0\t0\t0\t0\n");
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: {
          sudoers: path.join(h.tmp, "nosudoers"),
          sudoersD: path.join(h.tmp, "nodir"),
          passwd: path.join(h.tmp, "nopasswd"),
          trustedPaths: [],
          procRoot,
        },
        forceLinux: true,
      },
    });
    // exe links unreadable → indicator unflipped (codex P1 #80)
    assert.equal(r.signal_overrides["orphan-privileged-process"], undefined,
      "missing exe links must leave indicator unflipped, not assert clean");
  } finally {
    h.cleanup();
  }
});

test("runtime collector leaves indicators unflipped when sources unreadable", () => {
  // All paths point at non-existent locations → no indicator should
  // be set; runner returns inconclusive.
  const h = fakeRuntimeRoot("runtime-empty-");
  try {
    const r = runtimeCollector.collect({
      cwd: ROOT,
      args: {
        paths: {
          sudoers: path.join(h.tmp, "noexist1"),
          sudoersD: path.join(h.tmp, "noexist2"),
          passwd: path.join(h.tmp, "noexist3"),
          trustedPaths: [path.join(h.tmp, "noexist4")],
          procRoot: path.join(h.tmp, "noexist5"),
        },
        forceLinux: true,
      },
    });
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], undefined);
    assert.equal(r.signal_overrides["duplicate-uid-zero"], undefined);
    assert.equal(r.signal_overrides["world-writable-in-trusted-path"], undefined);
    assert.equal(r.signal_overrides["orphan-privileged-process"], undefined);
  } finally {
    h.cleanup();
  }
});

test("ai-api collector flips zero on a clean fake-home", () => {
  const h = fakeHome("ai-api-clean-");
  try {
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["cleartext-api-key-in-dotfile"], "miss");
    assert.equal(r.signal_overrides["long-lived-aws-keys"], "miss");
    assert.equal(r.signal_overrides["gcp-service-account-json"], "miss");
    assert.equal(r.signal_overrides["kubeconfig-with-static-token"], "miss");
  } finally {
    h.cleanup();
  }
});

test("ai-api cleartext-api-key-in-dotfile fires on OPENAI_API_KEY export in .zshrc", () => {
  const h = fakeHome("ai-api-zshrc-");
  try {
    h.write(".zshrc", "export PATH=$PATH:/usr/local/bin\nexport OPENAI_API_KEY=sk-" + "A".repeat(30) + "\n");
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["cleartext-api-key-in-dotfile"], "hit");
  } finally {
    h.cleanup();
  }
});

test("ai-api cleartext-api-key-in-dotfile fires on ANTHROPIC + HF tokens", () => {
  const h = fakeHome("ai-api-anthropic-");
  try {
    h.write(".bashrc", "export ANTHROPIC_API_KEY=sk-ant-" + "A".repeat(30) + "\nexport HF_TOKEN=hf_" + "A".repeat(30) + "\n");
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["cleartext-api-key-in-dotfile"], "hit");
  } finally {
    h.cleanup();
  }
});

test("ai-api cleartext-api-key-in-dotfile fires on fish-style set -gx", () => {
  const h = fakeHome("ai-api-fish-");
  try {
    h.write(".config/fish/config.fish", "set -gx GOOGLE_API_KEY " + "A".repeat(40) + "\n");
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["cleartext-api-key-in-dotfile"], "hit");
  } finally {
    h.cleanup();
  }
});

test("ai-api long-lived-aws-keys: STS session_token sibling demotes to miss", () => {
  const h = fakeHome("ai-api-aws-sts-");
  try {
    h.write(".aws/credentials", [
      "[default]",
      "aws_access_key_id = ASIASYNTHETICTEMPKEY",
      "aws_secret_access_key = " + "a".repeat(40),
      "aws_session_token = " + "z".repeat(40),
    ].join("\n"));
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["long-lived-aws-keys"], "miss",
      "aws_session_token sibling marks the profile as STS-temporary, not long-lived");
  } finally {
    h.cleanup();
  }
});

test("ai-api long-lived-aws-keys: AKIA without session token fires", () => {
  const h = fakeHome("ai-api-aws-longlived-");
  try {
    h.write(".aws/credentials", [
      "[default]",
      "aws_access_key_id = AKIASYNTHETICTESTKEY",
      "aws_secret_access_key = " + "a".repeat(40),
    ].join("\n"));
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["long-lived-aws-keys"], "hit");
  } finally {
    h.cleanup();
  }
});

test("ai-api kubeconfig-with-static-token honours user.token / not auth-provider", () => {
  const h = fakeHome("ai-api-kube-token-");
  try {
    h.write(".kube/config", [
      "users:",
      "- name: admin",
      "  user:",
      "    token: abcdef1234567890",
    ].join("\n"));
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["kubeconfig-with-static-token"], "hit");
  } finally {
    h.cleanup();
  }
});

test("ai-api kubeconfig-with-static-token miss on auth-provider cached token", () => {
  const h = fakeHome("ai-api-kube-authprov-");
  try {
    h.write(".kube/config", [
      "users:",
      "- name: gcp-iap",
      "  user:",
      "    auth-provider:",
      "      name: gcp",
      "      config:",
      "        access-token: ya29.dynamic-cached",
    ].join("\n"));
    const r = aiApiCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["kubeconfig-with-static-token"], "miss");
  } finally {
    h.cleanup();
  }
});

test("mcp collector flips zero on a clean fake-home", () => {
  const h = fakeHome("mcp-clean-");
  try {
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["mcp-version-without-integrity"], "miss");
    assert.equal(r.signal_overrides["copilot-yolo-mode-flag"], "miss");
    // ANSI / unicode indicators should be unflipped when no logs exist.
    assert.equal(r.signal_overrides["mcp-response-ansi-escape"], undefined);
    assert.equal(r.signal_overrides["mcp-response-unicode-tag-smuggling"], undefined);
  } finally {
    h.cleanup();
  }
});

test("mcp version-without-integrity fires on npx @scope/pkg@x.y.z without integrity sibling", () => {
  const h = fakeHome("mcp-pinned-");
  try {
    h.write(".cursor/mcp.json", JSON.stringify({
      mcpServers: {
        "fs-server": { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"] },
      },
    }));
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["mcp-version-without-integrity"], "hit");
  } finally {
    h.cleanup();
  }
});

test("mcp version-without-integrity miss when integrity sibling present", () => {
  const h = fakeHome("mcp-integ-");
  try {
    h.write(".cursor/mcp.json", JSON.stringify({
      mcpServers: {
        "fs-server": {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"],
          integrity: "sha256-abc123",
        },
      },
    }));
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["mcp-version-without-integrity"], "miss");
  } finally {
    h.cleanup();
  }
});

test("mcp copilot-yolo-mode-flag fires on chat.tools.autoApprove=true", () => {
  const h = fakeHome("mcp-yolo-");
  try {
    h.write(".config/Code/User/settings.json", JSON.stringify({
      "chat.tools.autoApprove": true,
    }));
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["copilot-yolo-mode-flag"], "hit");
  } finally {
    h.cleanup();
  }
});

test("mcp copilot-yolo-mode-flag fires on per-server autoApprove=true", () => {
  const h = fakeHome("mcp-yolo-perserver-");
  try {
    h.write(".config/Code/User/settings.json", JSON.stringify({
      "chat.mcp.servers": {
        "dangerous-server": { autoApprove: true },
      },
    }));
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["copilot-yolo-mode-flag"], "hit");
  } finally {
    h.cleanup();
  }
});

test("mcp ansi-escape + unicode-tag-smuggling fire on tainted log content", () => {
  const h = fakeHome("mcp-tainted-log-");
  try {
    // ANSI escape: 0x1B in the JSONL content.
    h.write(".claude/logs/mcp/server1.jsonl",
      `{"method":"tools/call","result":{"content":[{"text":"hello \x1b[31mred\x1b[0m"}]}}\n`);
    // Unicode tag smuggling: codepoint U+E0040.
    const tagSmuggled = "innocent " + String.fromCodePoint(0xE0040) + " text";
    h.write(".cursor/logs/mcp-call.jsonl",
      JSON.stringify({ method: "tools/list", result: { tools: [{ description: tagSmuggled }] } }) + "\n");
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["mcp-response-ansi-escape"], "hit");
    assert.equal(r.signal_overrides["mcp-response-unicode-tag-smuggling"], "hit");
  } finally {
    h.cleanup();
  }
});

test("mcp ansi-escape miss when log content is clean", () => {
  const h = fakeHome("mcp-clean-log-");
  try {
    h.write(".claude/logs/mcp/server1.jsonl",
      JSON.stringify({ method: "tools/call", result: { content: [{ text: "plain text" }] } }) + "\n");
    const r = mcpCollector.collect({ cwd: ROOT, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["mcp-response-ansi-escape"], "miss");
    assert.equal(r.signal_overrides["mcp-response-unicode-tag-smuggling"], "miss");
  } finally {
    h.cleanup();
  }
});

test("mcp project-level .vscode/settings.json under cwd flips yolo flag", () => {
  const h = fakeHome("mcp-proj-vsc-");
  const projTmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-proj-cwd-"));
  try {
    fs.mkdirSync(path.join(projTmp, ".vscode"), { recursive: true });
    fs.writeFileSync(path.join(projTmp, ".vscode", "settings.json"), JSON.stringify({
      chat: { tools: { autoApprove: true } },
    }));
    const r = mcpCollector.collect({ cwd: projTmp, env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(r.signal_overrides["copilot-yolo-mode-flag"], "hit");
  } finally {
    h.cleanup();
    try { fs.rmSync(projTmp, { recursive: true, force: true }); } catch {}
  }
});

test("collect mcp pipes into run --evidence -", () => {
  const h = fakeHome("mcp-pipe-");
  try {
    h.write(".cursor/mcp.json", JSON.stringify({
      mcpServers: { fs: { command: "npx", args: ["@modelcontextprotocol/server-filesystem@1.0.0"] } },
    }));
    const collected = cli(["collect", "mcp", "--json"], { env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(collected.status, 0);
    const ran = cli(["run", "mcp", "--evidence", "-", "--json"], { input: collected.stdout, env: { HOME: h.home, USERPROFILE: h.home } });
    const body = tryJson(ran.stdout) || tryJson(ran.stderr);
    assert.ok(body);
    assert.equal(body.playbook_id, "mcp");
  } finally {
    h.cleanup();
  }
});

test("collect ai-api pipes into run --evidence -", () => {
  const h = fakeHome("ai-api-pipe-");
  try {
    h.write(".zshrc", "export OPENAI_API_KEY=sk-" + "P".repeat(40) + "\n");
    const collected = cli(["collect", "ai-api", "--json"], { env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(collected.status, 0);
    const ran = cli(["run", "ai-api", "--evidence", "-", "--json"], { input: collected.stdout, env: { HOME: h.home, USERPROFILE: h.home } });
    const body = tryJson(ran.stdout) || tryJson(ran.stderr);
    assert.ok(body, `run must emit parseable JSON; stdout: ${ran.stdout.slice(0,200)}`);
    assert.equal(body.playbook_id, "ai-api");
  } finally {
    h.cleanup();
  }
});

test("collect cred-stores pipes into run --evidence -", () => {
  const h = fakeHome("cred-pipe-");
  try {
    h.write(".npmrc", "//registry.npmjs.org/:_authToken=npm_" + "C".repeat(36) + "\n");
    const collected = cli(["collect", "cred-stores", "--json"], { env: { HOME: h.home, USERPROFILE: h.home } });
    assert.equal(collected.status, 0, `collect stderr: ${collected.stderr}`);
    const ran = cli(["run", "cred-stores", "--evidence", "-", "--json"], { input: collected.stdout, env: { HOME: h.home, USERPROFILE: h.home } });
    const body = tryJson(ran.stdout) || tryJson(ran.stderr);
    assert.ok(body, `run must emit parseable JSON; status=${ran.status}, stdout: ${ran.stdout.slice(0, 200)}`);
    assert.equal(body.playbook_id, "cred-stores");
  } finally {
    h.cleanup();
  }
});

test("crypto collector flips openssl-pre-3-5 + sshd-no-pqc-kex + ml-kem-absent + ml-dsa-slh-dsa-absent + weak-mac-or-cipher on a pre-3.5 host without PQC", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "crypto-collector-bad-"));
  try {
    const sshdPath = path.join(tmp, "sshd_config");
    fs.writeFileSync(sshdPath, [
      "Port 22",
      "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256",
      "MACs hmac-sha1,hmac-sha2-256",
      "Ciphers aes256-ctr,arcfour",
      "PermitRootLogin no",
      "",
    ].join("\n"));
    const sshdD = path.join(tmp, "sshd_config.d");
    fs.mkdirSync(sshdD);
    const opensslVerPath = path.join(tmp, "openssl-version.txt");
    fs.writeFileSync(opensslVerPath, "OpenSSL 3.0.13 30 Jan 2024\nbuilt on: ...\n");
    const opensslKemPath = path.join(tmp, "openssl-kem.txt");
    fs.writeFileSync(opensslKemPath, "Name: X25519\nName: X448\n");
    const opensslSigPath = path.join(tmp, "openssl-sig.txt");
    fs.writeFileSync(opensslSigPath, "Name: ECDSA\nName: RSA-PSS\n");
    const certStoreDir = path.join(tmp, "certs");
    fs.mkdirSync(certStoreDir);
    fs.writeFileSync(path.join(certStoreDir, "ca.pem"), "-----BEGIN CERTIFICATE-----\n");

    const { collect } = require("../lib/collectors/crypto.js");
    const r = collect({
      cwd: tmp,
      args: {
        forceLinux: true,
        paths: {
          sshdConfig: sshdPath,
          sshdConfigD: sshdD,
          opensslVersionOutput: opensslVerPath,
          opensslKemOutput: opensslKemPath,
          opensslSignatureOutput: opensslSigPath,
          certStore: certStoreDir,
        },
      },
    });

    assert.equal(r.signal_overrides["openssl-pre-3-5"], "hit");
    assert.equal(r.signal_overrides["sshd-no-pqc-kex"], "hit");
    assert.equal(r.signal_overrides["ml-kem-absent"], "hit");
    assert.equal(r.signal_overrides["ml-dsa-slh-dsa-absent"], "hit");
    assert.equal(r.signal_overrides["weak-mac-or-cipher"], "hit");
    assert.equal(r.precondition_checks["linux-platform"], true);
    assert.equal(r.collector_meta.collector_id, "crypto");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto collector returns clean miss on modern openssl + PQC sshd", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "crypto-collector-ok-"));
  try {
    const sshdPath = path.join(tmp, "sshd_config");
    fs.writeFileSync(sshdPath, [
      "Port 22",
      "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256",
      "MACs hmac-sha2-512-etm@openssh.com",
      "Ciphers chacha20-poly1305@openssh.com",
      "",
    ].join("\n"));
    const opensslVerPath = path.join(tmp, "openssl-version.txt");
    fs.writeFileSync(opensslVerPath, "OpenSSL 3.5.0 8 Apr 2025\n");
    const opensslKemPath = path.join(tmp, "openssl-kem.txt");
    fs.writeFileSync(opensslKemPath, "Name: mlkem768\nName: X25519\n");
    const opensslSigPath = path.join(tmp, "openssl-sig.txt");
    fs.writeFileSync(opensslSigPath, "Name: ML-DSA-65\nName: ECDSA\n");

    const { collect } = require("../lib/collectors/crypto.js");
    const r = collect({
      cwd: tmp,
      args: {
        forceLinux: true,
        paths: {
          sshdConfig: sshdPath,
          sshdConfigD: path.join(tmp, "sshd_config.d"),
          opensslVersionOutput: opensslVerPath,
          opensslKemOutput: opensslKemPath,
          opensslSignatureOutput: opensslSigPath,
          certStore: path.join(tmp, "no-certs"),
        },
      },
    });
    assert.equal(r.signal_overrides["openssl-pre-3-5"], "miss");
    assert.equal(r.signal_overrides["sshd-no-pqc-kex"], "miss");
    assert.equal(r.signal_overrides["ml-kem-absent"], "miss");
    assert.equal(r.signal_overrides["ml-dsa-slh-dsa-absent"], "miss");
    assert.equal(r.signal_overrides["weak-mac-or-cipher"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto collector emits empty submission on non-linux platforms", { skip: process.platform === "linux" }, () => {
  const { collect } = require("../lib/collectors/crypto.js");
  const r = collect({ args: { forceLinux: false } });
  assert.equal(r.precondition_checks["linux-platform"], false);
  assert.deepEqual(r.signal_overrides, {});
  assert.equal(r.artifacts["openssl-version"].captured, false);
});

test("crypto collector flips weak-mac-or-cipher on aes-cbc variants", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "crypto-aes-cbc-"));
  try {
    const sshdPath = path.join(tmp, "sshd_config");
    fs.writeFileSync(sshdPath, [
      "Port 22",
      "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256",
      "MACs hmac-sha2-512-etm@openssh.com",
      "Ciphers aes256-ctr,aes128-cbc",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/crypto.js");
    const r = collect({
      cwd: tmp,
      args: {
        forceLinux: true,
        paths: {
          sshdConfig: sshdPath,
          sshdConfigD: path.join(tmp, "sshd_config.d"),
          opensslVersionOutput: path.join(tmp, "noop"),
          opensslKemOutput: path.join(tmp, "noop"),
          opensslSignatureOutput: path.join(tmp, "noop"),
          certStore: path.join(tmp, "no-certs"),
        },
      },
    });
    assert.equal(r.signal_overrides["weak-mac-or-cipher"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector flips fork-PR-checkout + injection-sink + floating-tag + secret-exposed + OIDC-wildcard on a bad fixture", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-collector-bad-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });

    fs.writeFileSync(path.join(wfDir, "test.yml"), [
      "name: test",
      "on: pull_request_target",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - uses: third-party/action@v1",
      "      - name: build",
      "        run: echo ${{ github.event.pull_request.title }}",
      "      - name: secret",
      "        run: curl -H \"x: ${{ secrets.NPM_TOKEN }}\" https://example.com",
      "",
    ].join("\n"));

    const infraDir = path.join(tmp, "infra");
    fs.mkdirSync(infraDir);
    fs.writeFileSync(path.join(infraDir, "ci-trust-policy.json"), JSON.stringify({
      Version: "2012-10-17",
      Statement: [{
        Effect: "Allow",
        Principal: { Federated: "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" },
        Action: "sts:AssumeRoleWithWebIdentity",
        Condition: { StringLike: { "token.actions.githubusercontent.com:sub": "*" } },
      }],
    }));

    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });

    assert.equal(r.signal_overrides["pull-request-target-with-pr-checkout"], "hit");
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "hit");
    assert.equal(r.signal_overrides["workflow-injection-sink"], "hit");
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "hit");
    assert.equal(r.signal_overrides["secret-exposed-to-fork-pr"], "hit");
    assert.equal(r.collector_meta.collector_id, "cicd-pipeline-compromise");
    assert.equal(r.precondition_checks["cwd-is-repo"], true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector misses on a clean SHA-pinned + env-bound workflow", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-collector-ok-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });
    fs.writeFileSync(path.join(wfDir, "ci.yml"), [
      "name: ci",
      "on: [pull_request]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
      "      - uses: third-party/safe@" + "a".repeat(40),
      "      - name: build",
      "        env:",
      "          PR_TITLE: ${{ github.event.pull_request.title }}",
      "        run: echo \"$PR_TITLE\"",
      "",
    ].join("\n"));

    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });

    assert.equal(r.signal_overrides["pull-request-target-with-pr-checkout"], "miss");
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "miss");
    assert.equal(r.signal_overrides["workflow-injection-sink"], "miss");
    assert.equal(r.signal_overrides["secret-exposed-to-fork-pr"], "miss");
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector attests ci-config-readable on the success path (filesystem read genuinely performed)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-preconds-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.precondition_checks["cwd-is-repo"], true);
    assert.equal(r.precondition_checks["ci-config-readable"], true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets collector demotes hits that exist only in test / fixture paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-demote-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.mkdirSync(path.join(tmp, "test"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "test", "fulcio_test.go"),
      'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";\n',
    );
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".github", "workflows", "cosign-test.key"),
      "-----BEGIN PRIVATE KEY-----\nMIIBAA==\n-----END PRIVATE KEY-----\n",
    );

    const { collect } = require("../lib/collectors/secrets.js");
    const r = collect({ cwd: tmp });

    assert.equal(r.signal_overrides["jwt-token-with-secret-context"], "miss");
    assert.equal(r.signal_overrides["ssh-private-key-block"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets collector still fires when production code has a real secret (demotion is not blanket suppression)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-prod-hit-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "src", "auth.go"),
      'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";\n',
    );

    const { collect } = require("../lib/collectors/secrets.js");
    const r = collect({ cwd: tmp });

    assert.equal(r.signal_overrides["jwt-token-with-secret-context"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author recognises container-native publish workflows (cosign sign + ko publish + id-token: write)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "la-publish-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wf = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wf, { recursive: true });
    fs.writeFileSync(
      path.join(wf, "build.yaml"),
      [
        "name: build",
        "on: push",
        "jobs:",
        "  build:",
        "    permissions:",
        "      id-token: write",
        "      contents: read",
        "    steps:",
        "      - uses: sigstore/cosign-installer@" + "a".repeat(40),
        "      - uses: ko-build/setup-ko@" + "b".repeat(40),
        "      - run: ko publish ./cmd/foo",
        "      - run: cosign sign $IMAGE",
        "",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(tmp, "package.json"), '{"name":"x","version":"1.0.0"}');

    const { collect } = require("../lib/collectors/library-author.js");
    const r = collect({ cwd: tmp });

    assert.ok(r.collector_meta.publish_workflows.includes("build.yaml"),
      `expected build.yaml in publish_workflows; got: ${JSON.stringify(r.collector_meta.publish_workflows)}`);
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cred-stores surfaces credentials-file-perms-check skip on Windows", { skip: process.platform !== "win32" }, () => {
  const { collect } = require("../lib/collectors/cred-stores.js");
  const r = collect({ cwd: process.cwd() });
  const art = r.artifacts["credentials-file-perms-check"];
  assert.ok(art, "credentials-file-perms-check artifact missing");
  assert.equal(art.captured, false);
  assert.match(art.reason, /Windows|ACL|POSIX/i);
});

test("cred-stores credentials-file-perms-check is captured on POSIX", { skip: process.platform === "win32" }, () => {
  const { collect } = require("../lib/collectors/cred-stores.js");
  const r = collect({ cwd: process.cwd() });
  const art = r.artifacts["credentials-file-perms-check"];
  assert.ok(art, "credentials-file-perms-check artifact missing");
  assert.equal(art.captured, true);
});

test("crypto-codebase demotes weak-hash hits in content-integrity / fingerprinting files (non-security context)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cc-integrity-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.mkdirSync(path.join(tmp, "resources", "integrity"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "resources", "integrity", "integrity.go"),
      'package integrity\nimport "crypto/md5"\nfunc Hash(b []byte) string { h := md5.Sum(b); return string(h[:]) }\n',
    );
    const { collect } = require("../lib/collectors/crypto-codebase.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-hash-import"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto-codebase filename demotion does NOT bypass an explicit security-context token (integrity.go with password fires)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cc-int-pw-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.mkdirSync(path.join(tmp, "r"));
    fs.writeFileSync(
      path.join(tmp, "r", "integrity.go"),
      'package r\nimport "crypto/md5"\nfunc PasswordCheck(password string) string { h := md5.Sum([]byte(password)); return string(h[:]) }\n',
    );
    const { collect } = require("../lib/collectors/crypto-codebase.js");
    const r = collect({ cwd: tmp });
    // Filename signals content-addressable, but the code carries a
    // strong security token (password). The hit must fire.
    assert.equal(r.signal_overrides["weak-hash-import"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto-codebase still fires weak-hash on a real security context (auth.go with token)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cc-auth-token-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.mkdirSync(path.join(tmp, "src"));
    fs.writeFileSync(
      path.join(tmp, "src", "auth.go"),
      'package auth\nimport "crypto/md5"\nfunc TokenHash(t string) string { return string(md5.Sum([]byte(t)))[:] }\n',
    );
    const { collect } = require("../lib/collectors/crypto-codebase.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-hash-import"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto-codebase isTestPath demotes Go _test.go files", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cc-go-test-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    fs.writeFileSync(
      path.join(tmp, "auth_test.go"),
      'package auth\nimport "crypto/md5"\nfunc TestThing(t *testing.T) { token := md5.Sum([]byte("x")); _ = token }\n',
    );
    const { collect } = require("../lib/collectors/crypto-codebase.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["weak-hash-import"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector requires explicit --attest-ownership for the CI-fleet ownership precondition", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-attest-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");

    // Default: no flag → ownership NOT attested (playbook gate stays
    // enforced, run halts at preflight unless operator opts in).
    const noFlag = collect({ cwd: tmp });
    assert.equal(noFlag.precondition_checks["operator-owns-ci-fleet"], false);

    // Camel-case (programmatic): explicit attestOwnership: true
    const camel = collect({ cwd: tmp, args: { attestOwnership: true } });
    assert.equal(camel.precondition_checks["operator-owns-ci-fleet"], true);

    // Kebab-case (CLI): --attest-ownership lands as args["attest-ownership"]
    const kebab = collect({ cwd: tmp, args: { "attest-ownership": true } });
    assert.equal(kebab.precondition_checks["operator-owns-ci-fleet"], true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector precondition fails outside a git repo", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-no-git-"));
  try {
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.precondition_checks["cwd-is-repo"], false);
    assert.deepEqual(r.signal_overrides, {});
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector covers github.head_ref shape of PR-target-checkout", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-head-ref-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });
    fs.writeFileSync(path.join(wfDir, "test.yml"), [
      "name: test",
      "on:",
      "  pull_request_target:",
      "    types: [opened, synchronize]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@" + "b".repeat(40),
      "        with:",
      "          ref: ${{ github.head_ref }}",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["pull-request-target-with-pr-checkout"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector excludes actions/* first-party from floating-tag predicate", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-first-party-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });
    fs.writeFileSync(path.join(wfDir, "ci.yml"), [
      "name: ci",
      "on: push",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - uses: actions/setup-node@v3",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise collector recognises block-list on: trigger form", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-block-list-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });
    fs.writeFileSync(path.join(wfDir, "test.yml"), [
      "name: test",
      "on:",
      "  - pull_request_target",
      "  - push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["pull-request-target-with-pr-checkout"], "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd-pipeline-compromise PR-head ref must be bound to the actions/checkout step, not any step", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-binding-"));
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const wfDir = path.join(tmp, ".github", "workflows");
    fs.mkdirSync(wfDir, { recursive: true });
    // Checkout uses BASE ref (safe); a separate step echos PR head.
    // File-wide co-occurrence used to falsely flag this — must miss now.
    fs.writeFileSync(path.join(wfDir, "test.yml"), [
      "name: test",
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@" + "a".repeat(40),
      "        with:",
      "          ref: ${{ github.event.pull_request.base.sha }}",
      "      - name: log head",
      "        env:",
      "          PR_HEAD: ${{ github.event.pull_request.head.sha }}",
      "        run: echo \"$PR_HEAD\"",
      "",
    ].join("\n"));
    const { collect } = require("../lib/collectors/cicd-pipeline-compromise.js");
    const r = collect({ cwd: tmp });
    assert.equal(r.signal_overrides["pull-request-target-with-pr-checkout"], "miss");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto collector leaves indicators unflipped (inconclusive) when openssl + sshd_config are both unreadable", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "crypto-collector-empty-"));
  try {
    const { collect } = require("../lib/collectors/crypto.js");
    const r = collect({
      cwd: tmp,
      args: {
        forceLinux: true,
        paths: {
          sshdConfig: path.join(tmp, "nonexistent"),
          sshdConfigD: path.join(tmp, "nonexistent.d"),
          opensslVersionOutput: path.join(tmp, "no-version"),
          opensslKemOutput: path.join(tmp, "no-kem"),
          opensslSignatureOutput: path.join(tmp, "no-sig"),
          certStore: path.join(tmp, "no-certs"),
        },
      },
    });
    // Nothing was readable → no indicator emits a verdict.
    assert.equal(r.signal_overrides["openssl-pre-3-5"], undefined);
    assert.equal(r.signal_overrides["sshd-no-pqc-kex"], undefined);
    assert.equal(r.signal_overrides["ml-kem-absent"], undefined);
    assert.equal(r.signal_overrides["weak-mac-or-cipher"], undefined);
    assert.equal(r.artifacts["openssl-version"].captured, false);
    assert.equal(r.artifacts["sshd-config-effective"].captured, false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
