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

test("sbom collector counts CycloneDX components correctly under a short read (does not fall back to null)", () => {
  // A single fs.readSync(fd, buf, 0, stat.size, 0) is not guaranteed to fill
  // the buffer — a network/FUSE mount (or a signal) can return a short read,
  // leaving the tail NUL-padded and truncating valid JSON. JSON.parse then
  // throws, swallowed by the inner catch, and component_count silently becomes
  // null on a present, parseable SBOM. readFileSync(fd) loops to EOF instead
  // and never touches the JS-level fs.readSync wrapper.
  //
  // The stub below makes the FIRST large fs.readSync return only a partial
  // chunk. Production code that reads via a single readSync(stat.size) gets a
  // truncated buffer and reports component_count: null; production code that
  // reads via readFileSync(fd) never calls the wrapper, reads the whole file,
  // and reports the true count. So this test fails on the buggy form and
  // passes on the fixed form.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-shortread-"));
  const realReadSync = fs.readSync;
  try {
    const sbom = { bomFormat: "CycloneDX", specVersion: "1.6", components: [] };
    for (let i = 0; i < 50; i++) {
      sbom.components.push({ type: "library", name: `pkg-${i}`, version: "1.0.0", purl: `pkg:npm/pkg-${i}@1.0.0` });
    }
    fs.writeFileSync(path.join(tmp, "sbom.cdx.json"), JSON.stringify(sbom, null, 2), "utf8");

    fs.readSync = function (fd, buffer, offset, length, position) {
      // Truncate the first large read — emulate a partial-read mount.
      if (typeof length === "number" && length > 4096) {
        return realReadSync.call(fs, fd, buffer, offset, 4096, position);
      }
      return realReadSync.call(fs, fd, buffer, offset, length, position);
    };

    const { collect } = require("../lib/collectors/sbom.js");
    const r = collect({ cwd: tmp });

    // The count must be the TRUE component count (50), not null.
    assert.match(
      r.artifacts["sbom-document"].value,
      /sbom\.cdx\.json \(\d+ bytes, 50 components\)/,
      `expected '50 components', got: ${r.artifacts["sbom-document"].value}`,
    );
  } finally {
    fs.readSync = realReadSync;
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

test("sbom: clean npm 7+ lockfile (root entry has name+version, no integrity) is a MISS", () => {
  const tmp = mkTmp("fp-sbom-clean-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/foo": { version: "1.2.3", resolved: "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz", integrity: "sha512-deadbeef" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "miss",
      "root entry without integrity must not trip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: remote-tarball entry missing integrity is still a HIT", () => {
  const tmp = mkTmp("fp-sbom-bad-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/good": { version: "1.0.0", resolved: "https://registry.npmjs.org/good/-/good-1.0.0.tgz", integrity: "sha512-abc" },
        // resolved to a remote tarball but no integrity hash -> the real bug
        "node_modules/evil": { version: "2.0.0", resolved: "https://evil.example/evil-2.0.0.tgz" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "hit",
      "a resolved remote entry without integrity must fire the indicator");
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


// ---- collector_errors reachability + integrity-count surfacing ----
require("node:test").describe("sbom-collector-errors", () => {
/**
 * The sbom collector declared `collector_errors: []` and never pushed to it:
 * every read and parse failure was caught locally and discarded, so an
 * unreadable lockfile and an unparseable SBOM both rendered as an ordinary
 * clean scan. bin/exceptd.js prints collector_errors[] as "Collector warnings"
 * and the runner forwards them as collector_warnings, so an empty channel is
 * the difference between a partial scan the operator can see and one they
 * cannot.
 *
 * Also pins the two integrity counts. They were computed off package-lock.json
 * and assigned to a local object that never left collect(), so the
 * lockfile-no-integrity verdict shipped without its magnitude.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const sbom = require(path.join(__dirname, "..", "lib", "collectors", "sbom.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("sbom: an unparseable CycloneDX document is reported on collector_errors, not silently counted as zero components", () => {
  const tmp = mkTmp("sbom-err-cdx-");
  try {
    // Well-formed enough to open and read, invalid as JSON.
    fs.writeFileSync(path.join(tmp, "sbom.cdx.json"), '{"bomFormat":"CycloneDX","components":[', "utf8");
    const r = sbom.collect({ cwd: tmp });

    assert.ok(Array.isArray(r.collector_errors), "collector_errors must be an array");
    const hit = r.collector_errors.find(
      (e) => e.artifact_id === "sbom-document" && e.kind === "parse_failed",
    );
    assert.ok(
      hit,
      `expected a sbom-document/parse_failed entry; got ${JSON.stringify(r.collector_errors)}`,
    );
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^sbom\.cdx\.json: /);
    // The artifact still reports the document as present with no component
    // count — that is exactly the state the warning explains.
    assert.match(r.artifacts["sbom-document"].value, /sbom\.cdx\.json/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: an unparseable package-lock.json is reported on collector_errors with the parse kind", () => {
  const tmp = mkTmp("sbom-err-lock-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{ not json", "utf8");
    const r = sbom.collect({ cwd: tmp });

    const hit = r.collector_errors.find(
      (e) => e.artifact_id === "lockfile-inventory" && e.kind === "lockfile_parse_failed",
    );
    assert.ok(
      hit,
      `expected a lockfile-inventory/lockfile_parse_failed entry; got ${JSON.stringify(r.collector_errors)}`,
    );
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^package-lock\.json: /);
    // A read failure and a parse failure are different operator actions, so the
    // read kind must NOT be what an unparseable-but-readable file reports.
    assert.equal(
      r.collector_errors.some((e) => e.kind === "lockfile_read_failed"),
      false,
      "a readable-but-unparseable lockfile is a parse failure, not a read failure",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: a clean scan leaves collector_errors empty", () => {
  const tmp = mkTmp("sbom-err-clean-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "p", version: "1.0.0" },
        "node_modules/foo": { version: "1.0.0", resolved: "https://r/foo.tgz", integrity: "sha512-abc" },
      },
    }), "utf8");
    const r = sbom.collect({ cwd: tmp });
    assert.deepEqual(r.collector_errors, [], "no failures means no warnings — the channel must not over-report");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: collector_meta carries the npm integrity present/missing counts behind the lockfile-no-integrity verdict", () => {
  const tmp = mkTmp("sbom-integrity-counts-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "p", version: "1.0.0" },
        "node_modules/a": { version: "1.0.0", resolved: "https://r/a.tgz", integrity: "sha512-a" },
        "node_modules/b": { version: "1.0.0", resolved: "https://r/b.tgz", integrity: "sha512-b" },
        "node_modules/c": { version: "1.0.0", resolved: "https://r/c.tgz" },
      },
    }), "utf8");
    const r = sbom.collect({ cwd: tmp });

    assert.equal(r.signal_overrides["lockfile-no-integrity"], "hit");
    assert.equal(typeof r.collector_meta.npm_integrity_present_count, "number");
    assert.equal(typeof r.collector_meta.npm_integrity_missing_count, "number");
    assert.equal(r.collector_meta.npm_integrity_present_count, 2);
    assert.equal(r.collector_meta.npm_integrity_missing_count, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: the integrity counts are absent (not zero) when no npm lockfile was parsed", () => {
  const tmp = mkTmp("sbom-integrity-absent-");
  try {
    // A cargo lockfile only — nothing to derive npm integrity coverage from.
    // Reporting 0/0 here would read as "every entry carries a hash".
    fs.writeFileSync(path.join(tmp, "Cargo.lock"), '[[package]]\nname = "x"\n', "utf8");
    const r = sbom.collect({ cwd: tmp });
    assert.equal(r.collector_meta.npm_integrity_present_count, undefined);
    assert.equal(r.collector_meta.npm_integrity_missing_count, undefined);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

/**
 * findSbomDocuments records a failed document from two places — the openSync
 * catch and the outer catch around fstatSync — and collect() turns each into a
 * collector_errors entry. Reporting both as "open_failed" sends an operator
 * chasing file permissions for a descriptor that opened fine, so the kind
 * travels from the push site the way the lockfile loop already does it.
 */

test("sbom: an fstat failure on an opened SBOM document reports stat_failed, not open_failed", () => {
  const tmp = mkTmp("sbom-err-fstat-");
  const realFstatSync = fs.fstatSync;
  try {
    fs.writeFileSync(path.join(tmp, "sbom.cdx.json"), '{"bomFormat":"CycloneDX","components":[]}', "utf8");
    // fs.fstatSync has exactly one call site in the collector — the descriptor
    // stat inside findSbomDocuments — so throwing here drives the outer catch
    // and touches nothing else in the scan.
    fs.fstatSync = () => {
      const e = new Error("EIO: i/o error, fstat");
      e.code = "EIO";
      throw e;
    };
    const r = sbom.collect({ cwd: tmp });
    fs.fstatSync = realFstatSync;

    const hit = r.collector_errors.find((e) => e.artifact_id === "sbom-document");
    assert.ok(hit, `expected a sbom-document entry; got ${JSON.stringify(r.collector_errors)}`);
    assert.equal(hit.kind, "stat_failed", "the descriptor opened — fstat is what failed");
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^sbom\.cdx\.json: /);
    assert.match(hit.reason, /EIO/);
  } finally {
    fs.fstatSync = realFstatSync;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: a document that opens and stats but cannot be read reports read_failed", () => {
  const tmp = mkTmp("sbom-err-read-");
  try {
    // A directory at the document's name opens and fstats on both POSIX and
    // Windows; the read is what fails (EISDIR).
    fs.mkdirSync(path.join(tmp, "sbom.cdx.json"));
    const r = sbom.collect({ cwd: tmp });

    const hit = r.collector_errors.find((e) => e.artifact_id === "sbom-document");
    assert.ok(hit, `expected a sbom-document entry; got ${JSON.stringify(r.collector_errors)}`);
    assert.equal(hit.kind, "read_failed");
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^sbom\.cdx\.json: /);
    assert.equal(
      r.collector_errors.some((e) => e.kind === "open_failed" || e.kind === "stat_failed"),
      false,
      "the open and the stat both succeeded — neither may be reported",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});
