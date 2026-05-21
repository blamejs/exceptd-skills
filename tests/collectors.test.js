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

test("collector modules export the contract: playbook_id + collect()", () => {
  for (const mod of [secretsCollector, kernelCollector, sbomCollector, containersCollector, libraryAuthorCollector]) {
    assert.equal(typeof mod.playbook_id, "string", "playbook_id must be a string");
    assert.ok(mod.playbook_id.length > 0);
    assert.equal(typeof mod.collect, "function", "collect must be a function");
  }
  assert.equal(secretsCollector.playbook_id, "secrets");
  assert.equal(kernelCollector.playbook_id, "kernel");
  assert.equal(sbomCollector.playbook_id, "sbom");
  assert.equal(containersCollector.playbook_id, "containers");
  assert.equal(libraryAuthorCollector.playbook_id, "library-author");
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
