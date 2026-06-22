"use strict";


// ---- routed from blamejs-scan-fixes ----
require("node:test").describe("blamejs-scan-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/blamejs-scan-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const containersCollector = require('../lib/collectors/containers.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('containers.hasContainerArtifacts finds Dockerfiles/compose anywhere in the tree, by filename variant', () => {
  const fx = mkfx();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const found = containersCollector.hasContainerArtifacts(fx);
  assert.ok(found.some((r) => /Dockerfile$/i.test(r)), 'finds the subdir Dockerfile');
  assert.ok(found.some((r) => /docker-compose\.test\.yml$/.test(r)), 'finds the compose variant');
  // An empty tree yields no artifacts.
  assert.deepEqual(containersCollector.hasContainerArtifacts(mkfx()), [], 'no container files -> empty list');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


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

test("containers: long-whitespace k8s manifest line returns fast and still flags :latest images", () => {
  const tmp = mkTmp("redos-containers-");
  try {
    const manifest = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  containers:",
      "    - image: nginx:latest",                  // :latest -> HIT (with dash, unquoted)
      "      image: 'redis:latest'",                // :latest -> HIT (quoted, no dash)
      WHITESPACE_LINE,                               // hostile line
      "    - image: busybox",                        // no tag (defaults to latest) -> HIT
      "      image: pinned/app:v1.2.3",             // explicit non-latest tag -> not a latest hit
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, "pod.yaml"), manifest);

    const start = Date.now();
    const r = containers.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["k8s-image-latest"], "hit",
      "normal `image:` :latest / untagged lines must still flip the indicator");
    const locs = r.evidence_locations["k8s-image-latest"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 latest-image hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("containers: pinned-tag k8s manifest is a MISS for k8s-image-latest", () => {
  const tmp = mkTmp("redos-containers-clean-");
  try {
    const manifest = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  containers:",
      "    - image: nginx:1.27.0",
      "      image: 'redis:7.2'",
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, "pod.yaml"), manifest);

    const r = containers.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["k8s-image-latest"], "miss",
      "explicitly tagged images must not flip the latest-image indicator");
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


// ---- routed from hunt-fix-C-correlations ----
require("node:test").describe("hunt-fix-C-correlations", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the C-correlations cluster:
 *
 *   #9  byTtp() returned found:false / entry:null for every ATT&CK
 *       technique — only the ATLAS catalog was consulted for the entry,
 *       while skills + related_cves correctly unioned both id spaces.
 *   #10 byTtp() d3fend correlation read the always-empty `counters` field
 *       instead of the populated `counters_attack_techniques`.
 *   #11 framework-gap lagScore() reported framework_specific_gaps:0 for
 *       every framework whose global-frameworks short key is not a literal
 *       substring of its catalog display string.
 *   #12 containers collector tracked USER globally, so a multi-stage build
 *       with a non-root USER in an early stage masked a root final stage.
 *   #13 byCwe/byTtp/bySkill leaked _auto_imported draft CVEs into the
 *       related_cves/cve_refs correlations (byCve excluded them; these
 *       transitive paths did not).
 *   #14 gap-detectors REFERENCE_TOKEN_RE could not match D3A-* / D3F-*
 *       D3FEND ids, mis-flagging referenced entries as unused orphans.
 *
 * Real-catalog assertions read the shipped data/ tree (default DATA_DIR).
 * The draft-leak case (#13) needs a synthetic catalog, which cross-ref-api
 * binds at require-time from EXCEPTD_DATA_DIR — so it runs in a child
 * process with that env var pointed at an isolated tempdir.
 *
 * Run under --test-concurrency=1 (the cross-ref cache + shared data dir are
 * process-global).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const xref = require('../lib/cross-ref-api.js');
const fg = require('../lib/framework-gap.js');
const gd = require('../lib/gap-detectors.js');
const containers = require('../lib/collectors/containers.js');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// ---------------------------------------------------------------------------
// Finding #9 — byTtp resolves the ATT&CK technique record, not only ATLAS.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Finding #10 — byTtp d3fend correlation reads counters_attack_techniques.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding #11 — lagScore counts framework-specific gaps by normalized match.
// ---------------------------------------------------------------------------

const controlGaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const globalFrameworks = loadJson(path.join(DATA_DIR, 'global-frameworks.json'));





// ---------------------------------------------------------------------------
// Finding #12 — containers collector resets USER state per build stage.
// ---------------------------------------------------------------------------

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}







// ---------------------------------------------------------------------------
// Finding #13 — draft CVEs never leak into transitive correlations.
//
// cross-ref-api binds DATA_DIR at require-time from EXCEPTD_DATA_DIR, so the
// synthetic catalog must be exercised in a child process.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding #14 — REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

test('#12 multi-stage build with non-root builder USER but root final stage is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nRUN echo build\nFROM nginx:1.27\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'final stage has no USER directive — must fire runs-as-root');
});

test('#12 single-stage build with a trailing non-root USER is a MISS', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\nUSER node\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss');
});

test('#12 single-stage root build is a HIT', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 final stage built FROM a prior alias inherits the parent USER (MISS)', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nUSER node\nFROM base AS final\nRUN echo build\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss',
    'FROM <alias> inherits the parent stage USER — must not reset to root');
});

test('#12 final stage FROM an alias that never set USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nRUN echo build\nFROM base AS final\nRUN echo more\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 scratch final stage with no USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nFROM scratch\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'scratch starts a fresh stage (root) — must reset and fire');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
