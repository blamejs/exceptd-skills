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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from dispatch-collector-scoring-fixes ----
require("node:test").describe("dispatch-collector-scoring-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Routing / collector / scoring correctness from the adjacent-area hunt:
 *  - dispatcher must preserve distinct findings that route to the same skill
 *    (de-dupe by skill+finding, not skill alone) so per-CVE evidence survives;
 *  - scanner's mcp_config_parse_error finding carries a skill_hint so it routes
 *    directly, not only via the brittle domain table;
 *  - library-author's action-ref scan flags a floating ref even with a trailing
 *    YAML comment (the `$`-anchored pattern silently missed those);
 *  - scoring.validate() honors the reboot_required alias when recomputing the
 *    expected RWEP, so a top-level reboot_required does not create false drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

test('library-author flags a floating action ref that carries a trailing YAML comment', () => {
  const { collect } = require('../lib/collectors/library-author.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libauth-'));
  try {
    const wfDir = path.join(dir, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    // A publish-shaped workflow with a floating (non-SHA) ref AND a trailing
    // comment — the case the `$`-anchored regex used to miss entirely.
    fs.writeFileSync(path.join(wfDir, 'release.yml'), [
      'name: release',
      'on: { push: { tags: ["v*"] } }',
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4  # pin this eventually',
      '      - run: npm publish',
    ].join('\n'));
    const res = collect({ cwd: dir });
    assert.equal(
      res.signal_overrides['publish-workflow-action-refs-mutable'],
      'hit',
      `a floating ref with a trailing comment must register a hit; signal_overrides=${JSON.stringify(res.signal_overrides)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collector-comment-marker-fp ----
require("node:test").describe("collector-comment-marker-fp", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collector-comment-marker-fp.test.js
 *
 * Collectors must not read a `#`-commented MENTION of a publish-shape token,
 * command, or runner as the real thing, and a doc/detection-pattern snippet of
 * a private key must not register as an embedded secret.
 *
 *  - library-author: the classifier already strips YAML comments before its
 *    publish-shape probes; the INDICATOR scanner (static-token / non-frozen
 *    install / self-hosted runner) and the provenance / SBOM-capability probes
 *    must use the same comment-stripped view. Otherwise a comment produces a
 *    deterministic false HIT, and — in the provenance direction — a commented
 *    `--provenance` suppresses a real gap (a security-relevant false NEGATIVE).
 *  - secrets: gcp-service-account-json must require a full PEM block, not just
 *    the `-----BEGIN PRIVATE KEY-----` header, so a service-account JSON shown
 *    as a placeholder / redaction-pattern literal does not register as a key.
 *
 * Exact-value pins (miss/hit), fail-before / pass-after, per the
 * anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const libauthor = require('../lib/collectors/library-author.js');
const secrets = require('../lib/collectors/secrets.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-comment-fp-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx(files) {
  const d = path.join(TMP, 'fx-' + _n++);
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return d;
}
function overrides(d) { return libauthor.collect({ cwd: d }).signal_overrides || {}; }




// --- secrets: gcp-service-account-json full-block guard -----------------

// Assemble the PEM markers + body at runtime so no contiguous private-key
// literal exists in this source file (push-protection / gitleaks safe).
const BEGIN = '-----BEGIN' + ' PRIVATE KEY-----';
const END = '-----END' + ' PRIVATE KEY-----';
function fakePemBody(repeats) {
  // Non-secret fixed base64-shaped filler, JSON-encoded with \n line breaks.
  const chunk = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj';
  const lines = [];
  for (let i = 0; i < repeats; i++) lines.push(chunk);
  return BEGIN + '\\n' + lines.join('\\n') + '\\n' + END + '\\n';
}
function gcpHit(text) {
  const re = secrets.__INDICATOR_PATTERNS
    ? secrets.__INDICATOR_PATTERNS.find(p => p.id === 'gcp-service-account-json').re
    : null;
  if (re) { re.lastIndex = 0; return re.test(text); }
  // Fall back to the collector surface if the pattern table isn't exported.
  const d = mkfx({ 'creds.json': text });
  const ov = secrets.collect({ cwd: d }).signal_overrides || {};
  return ov['gcp-service-account-json'] === 'hit';
}

test('library-author: comment-only publish-shape mentions do not fire the indicators (FP)', () => {
  // Publishes cleanly via `npm publish --provenance` with OIDC. The ONLY
  // mentions of `npm install`, `runs-on: self-hosted`, and `secrets.NPM_TOKEN`
  // are inside `#` comments — none is a real command/token/runner. No `npm ci`
  // either, so the non-frozen probe is exercised on the comment alone.
  const d = mkfx({
    'package.json': '{"name":"x","version":"1.0.0","publishConfig":{"provenance":true}}',
    '.github/workflows/release.yml':
      'name: release\n' +
      "on: { push: { tags: ['v*'] } }\n" +
      'permissions:\n  id-token: write\n  contents: read\n' +
      'jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      # legacy note: do NOT npm install here; never runs-on: self-hosted;\n' +
      '      # never use secrets.NPM_TOKEN — OIDC + provenance only.\n' +
      '      - run: npm publish --provenance --access public\n',
  });
  const o = overrides(d);
  assert.equal(o['release-workflow-non-frozen-install'], 'miss');
  assert.equal(o['publish-workflow-runs-on-self-hosted'], 'miss');
  assert.equal(o['publish-workflow-uses-static-token'], 'miss');
});

test('library-author: a commented `--provenance` does not suppress provenance-missing (FN)', () => {
  // No publishConfig.provenance, a real `npm publish` WITHOUT --provenance, and
  // only a COMMENT mentions --provenance. The gap must still be reported.
  const d = mkfx({
    'package.json': '{"name":"y","version":"1.0.0"}',
    '.github/workflows/release.yml':
      'name: release\n' +
      'jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      # TODO: switch to `npm publish --provenance` once OIDC is configured\n' +
      '      - run: npm publish\n',
  });
  assert.equal(overrides(d)['package-json-provenance-missing'], 'hit');
});

test('library-author: real static token / npm install / self-hosted still fire (no over-correction)', () => {
  const d = mkfx({
    'package.json': '{"name":"z","version":"1.0.0"}',
    '.github/workflows/release.yml':
      'name: release\n' +
      'jobs:\n  publish:\n    runs-on: self-hosted\n    steps:\n' +
      '      - run: npm install\n' +
      '      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n',
  });
  const o = overrides(d);
  assert.equal(o['release-workflow-non-frozen-install'], 'hit');
  assert.equal(o['publish-workflow-runs-on-self-hosted'], 'hit');
  assert.equal(o['publish-workflow-uses-static-token'], 'hit');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collector-library-author-release-artifacts ----
require("node:test").describe("collector-library-author-release-artifacts", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collector-library-author-release-artifacts.test.js
 *
 * Pins the library-author collector's handling of capabilities that
 * exist at release time but are invisible in committed repo state:
 *
 *   - `id-token: write` declared at JOB scope (not workflow-level)
 *     still grants OIDC, so publish-workflow-no-id-token-write must
 *     NOT fire.
 *   - A publish workflow that generates an SBOM (cyclonedx / syft /
 *     anchore-sbom-action / `npm sbom`), emits npm provenance
 *     (`--provenance` / publishConfig.provenance), or signs artifacts
 *     with cosign/sigstore satisfies sbom-absent-or-unsigned even when
 *     no SBOM file is committed.
 *   - With neither a committed SBOM nor any release-time SBOM /
 *     provenance / signing capability, the indicator still fires.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const libraryAuthorCollector = require(path.join(ROOT, "lib", "collectors", "library-author.js"));

function mkRepo(prefix, files) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return tmp;
}

test("id-token: write at JOB scope satisfies publish-workflow-no-id-token-write", () => {
  // `permissions:` declared under a specific job (not workflow-level).
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions:",
    "      contents: read",
    "      id-token: write",   // JOB-scoped OIDC grant
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-jobscope-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "miss",
      "job-scoped id-token: write must count as OIDC present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("a sibling workflow's id-token: write does NOT mask a static-token publish job", () => {
  // Codex P2: OIDC is per-publish-workflow, not repo-wide. A docs/deploy
  // workflow declaring id-token: write must not make a release job that
  // publishes with a long-lived NPM_TOKEN (and no OIDC of its own) look
  // OIDC-capable — that would hide the static-token takeover case.
  const publishWf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
    "        env: { NODE_AUTH_TOKEN: '${{ secrets.NPM_TOKEN }}' }",
  ].join("\n") + "\n";
  const docsWf = [
    "name: docs",
    "on: { push: { branches: ['main'] } }",
    "jobs:",
    "  deploy-docs:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",   // sibling OIDC, unrelated to publish
    "    steps:",
    "      - run: echo deploy",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-sibling-oidc-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": publishWf,
    ".github/workflows/docs.yml": docsWf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "hit",
      "publish job without its own id-token: write must fire even when a sibling workflow has OIDC");
    assert.equal(r.signal_overrides["publish-workflow-uses-static-token"], "hit",
      "a publish job on NPM_TOKEN with no OIDC of its own must fire the static-token indicator");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("release-time SBOM generation step satisfies sbom-absent-or-unsigned (no committed SBOM)", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: npm ci",
    "      - uses: anchore/sbom-action@v0",   // generates CycloneDX SBOM at release
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-sbomstep-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "a release-time SBOM-generation step makes the SBOM capability present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("npm provenance satisfies sbom-absent-or-unsigned (signed provenance attestation)", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish --provenance",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-provenance-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "npm publish --provenance emits a signed build-provenance attestation");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("publishConfig.provenance: true satisfies sbom-absent-or-unsigned", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-pkgprov-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0", publishConfig: { provenance: true } }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "publishConfig.provenance: true signals a signed provenance attestation at publish");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("cosign signing step satisfies sbom-absent-or-unsigned", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - uses: sigstore/cosign-installer@v3",
    "      - run: cosign sign --yes $IMAGE",   // sigstore signing of release artifact
    "      - run: docker push $IMAGE",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-cosign-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "a cosign/sigstore signing step makes the signed-attestation capability present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("sbom-absent-or-unsigned still FIRES with no committed SBOM and no release-time capability", () => {
  // Publish workflow that does plain `npm publish` — no SBOM step, no
  // --provenance, no cosign, no publishConfig.provenance, no SBOM file.
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
    "        env: { NODE_AUTH_TOKEN: '${{ secrets.NPM_TOKEN }}' }",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-nosbom-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "hit",
      "no committed SBOM and no release-time SBOM/provenance/signing capability must still fire");
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

test("library-author: long-whitespace workflow line returns fast and still flags mutable refs", () => {
  const tmp = mkTmp("redos-libauthor-");
  try {
    // release.yml matches the publish-workflow filename prefix. The body
    // carries normal `uses:` lines (with/without dash, quoted/unquoted) plus
    // a hostile 200KB whitespace line that previously triggered backtracking.
    const wf = [
      "name: release",
      "jobs:",
      "  publish:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // first-party: excluded, but exercises the regex
      "      - uses: third/party@v1",               // mutable third-party ref -> HIT
      "        uses: 'quoted/action@main'",         // quoted, no dash -> HIT
      WHITESPACE_LINE,                               // hostile line
      "      - uses: another/thing@1.2.3",          // mutable -> HIT
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const start = Date.now();
    const r = libraryAuthor.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "hit",
      "normal mutable `uses:` refs must still flip the indicator");
    const locs = r.evidence_locations["publish-workflow-action-refs-mutable"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 mutable-ref hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author: clean workflow (all refs SHA-pinned) is a MISS with normal `uses:` shapes", () => {
  const tmp = mkTmp("redos-libauthor-clean-");
  try {
    const sha = "a".repeat(40);
    const wf = [
      "name: release",
      "jobs:",
      "  publish:",
      "    steps:",
      `      - uses: actions/checkout@${sha}`,
      `        uses: "third/party@${sha}"`,
      "      - uses: ./.github/actions/local",      // local: excluded
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const r = libraryAuthor.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "miss",
      "SHA-pinned refs and a local action must not flip the indicator");
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


// ---- routed from gha-workflow-script-injection-sink ----
require("node:test").describe("gha-workflow-script-injection-sink", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/gha-workflow-script-injection-sink.test.js
 *
 * End-to-end fixture test for the GitHub Actions script-injection sink
 * indicator in data/playbooks/library-author.json. The regex is pulled
 * out of the indicator's `value` field at test time so the test stays
 * coupled to what operators actually run.
 *
 * v0.12.10 shipped a regex anchored on `run:\s*\|` (block-scalar pipe)
 * that missed single-line `run: <command>` shapes. v0.12.11 widens the
 * regex to `run:[\s\S]*?...` to admit both forms. Fixture #8 is the
 * exact shape that escaped the v0.12.10 regex; it must fire here.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB_PATH = path.join(ROOT, 'data/playbooks/library-author.json');
const playbook = JSON.parse(fs.readFileSync(PB_PATH, 'utf8'));

const indicator = playbook.phases.detect.indicators.find(
  (i) => i.id === 'gha-workflow-script-injection-sink'
);

test('gha-workflow-script-injection-sink: indicator is present in playbook', () => {
  assert.ok(indicator, 'indicator must exist in library-author playbook');
  assert.equal(indicator.id, 'gha-workflow-script-injection-sink');
  assert.ok(typeof indicator.value === 'string' && indicator.value.length > 0);
});

// Pull the regex out of the indicator value. The value contains multiple
// backtick-fenced spans (`run: |`, `run: <command>`, and the actual regex);
// the regex is the one whose body starts with `run:[`.
const regexMatch = indicator.value.match(/`(run:\[[^`]+)`/);
assert.ok(regexMatch, 'indicator value must embed the literal regex inside backticks, starting with `run:[`');
const SINK_RE = new RegExp(regexMatch[1]);

test('gha-workflow-script-injection-sink: extracted regex is non-trivial', () => {
  assert.ok(SINK_RE instanceof RegExp);
  // Sanity: must mention github.event somewhere
  assert.match(regexMatch[1], /github\\\.\(event/);
});

const FIXTURES = [
  {
    name: '1. block-scalar elementary-data exact sink',
    yaml: [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.comment.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '2. env-capture safety pattern (block scalar)',
    yaml: [
      'on: { issue_comment: { types: [created] } }',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - env:',
      '          COMMENT_BODY: ${{ github.event.comment.body }}',
      '        run: |',
      '          echo "$COMMENT_BODY"',
      '',
    ].join('\n'),
    fires: false,
  },
  {
    name: '3. sandboxed pull_request with title interpolation (fires at regex; FP demoted downstream)',
    yaml: [
      'on:',
      '  pull_request:',
      '    branches: [main]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "PR title: ${{ github.event.pull_request.title }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '4. pull_request_target with github.head_ref interpolation',
    yaml: [
      'on:',
      '  pull_request_target:',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          git checkout ${{ github.head_ref }}',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '5. discussion trigger with discussion.body interpolation',
    yaml: [
      'on:',
      '  discussion:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.discussion.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '6. push trigger with head_commit.message interpolation',
    yaml: [
      'on: push',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "commit: ${{ github.event.head_commit.message }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '7. env-capture safety pattern (single-line)',
    yaml: [
      'on: { issue_comment: { types: [created] } }',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - env:',
      '          COMMENT_BODY: ${{ github.event.comment.body }}',
      '        run: echo "$COMMENT_BODY"',
      '',
    ].join('\n'),
    fires: false,
  },
  {
    name: '8. single-line run: with github.event interpolation (v0.12.11 gap)',
    yaml: [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ github.event.comment.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
];

for (const f of FIXTURES) {
  test(`gha-workflow-script-injection-sink: ${f.name}`, () => {
    const hit = SINK_RE.test(f.yaml);
    assert.equal(
      hit,
      f.fires,
      `expected ${f.fires ? 'FIRES' : 'no-fire'} for fixture "${f.name}"`
    );
  });
}
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- release-workflow-non-frozen-install, per ecosystem ----
require("node:test").describe("release-workflow-non-frozen-install", () => {
/**
 * The playbook indicator names four ecosystems — `npm install` / `pnpm install`
 * / `pip install -r` / `bundle install`, "not the --frozen / --locked /
 * --require-hashes variant". Only npm and cargo were probed, so a Python or
 * Ruby publisher resolving dependencies at release time read as a clean miss.
 *
 * The flag suppressions are also scoped to the command that carries them: a
 * workflow that pins one install and resolves another must still report the
 * unpinned one.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const libauthor = require('../lib/collectors/library-author.js');

const INDICATOR = 'release-workflow-non-frozen-install';

// Writes a minimal publisher repo: a package manifest plus one release
// workflow, plus any extra files the case needs (e.g. a requirements file).
function fixture(releaseSteps, extraFiles = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'libauthor-install-')));
  const wf = path.join(dir, '.github', 'workflows');
  fs.mkdirSync(wf, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x","version":"1.0.0"}');
  fs.writeFileSync(path.join(wf, 'release.yml'), [
    'name: release',
    'on: { push: { tags: ["v*"] } }',
    'jobs:',
    '  publish:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    ...releaseSteps,
    '',
  ].join('\n'));
  for (const [rel, body] of Object.entries(extraFiles)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  return dir;
}

function verdictFor(releaseSteps, extraFiles) {
  const dir = fixture(releaseSteps, extraFiles);
  try {
    const res = libauthor.collect({ cwd: dir });
    const v = res.signal_overrides[INDICATOR];
    assert.equal(typeof v, 'string', `${INDICATOR} must resolve to a string verdict`);
    return { verdict: v, overrides: res.signal_overrides, locations: res.evidence_locations[INDICATOR] };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const PUBLISH = '      - run: python -m build';

test('pip install -r without --require-hashes is a hit', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: pip install -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('pip install with the requirement file attached to -r is a hit', () => {
  // pip accepts `-rreq.txt` as readily as `-r req.txt`. A predicate demanding a
  // separator examines neither the command nor the file it names, so an
  // unpinned requirement set in this form reads as clean.
  const { verdict, overrides } = verdictFor([
    '      - run: pip install -rrequirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('an attached -r naming a hash-pinned requirements file is a miss', () => {
  // A guard against the detector over-firing, not proof of the repair: it reads
  // as a miss whether the attached form is recognised or not. Its pair with the
  // hit case above is what shows the attached filename reaches the hash lookup
  // rather than only the detector.
  const { verdict, overrides } = verdictFor([
    '      - run: pip install -rrequirements.txt',
    PUBLISH,
  ], { 'requirements.txt': 'flask==3.0.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n' });
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a hash-pinned requirements file under a working-directory is a miss', () => {
  // The command resolves its relative path against the job's working-directory,
  // not the repository root. Checking only the root finds nothing and reports a
  // correctly pinned release as unpinned.
  const { verdict, overrides } = verdictFor([
    '    defaults: { run: { working-directory: packages/api } }',
    '      - run: pip install -r requirements.txt',
    PUBLISH,
  ], { 'packages/api/requirements.txt': 'flask==3.0.0 --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n' });
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('an unpinned requirements file under a working-directory is still a hit', () => {
  // The working-directory lookup must not become a way to be excused: the file
  // resolves, and what it holds is what decides.
  const { verdict, overrides } = verdictFor([
    '    defaults: { run: { working-directory: packages/api } }',
    '      - run: pip install -r requirements.txt',
    PUBLISH,
  ], { 'packages/api/requirements.txt': 'flask==3.0.0\n' });
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a pinned copy in one working-directory does not vouch for an unpinned copy in another', () => {
  // Both candidates resolve, so both are read. Suppressing on the strength of
  // the hashed one would report an unpinned release as reproducible.
  const { verdict, overrides } = verdictFor([
    '      - run: pip install -r requirements.txt',
    '        working-directory: packages/api',
    '      - run: pip install -r requirements.txt',
    '        working-directory: packages/worker',
    PUBLISH,
  ], {
    'packages/api/requirements.txt': 'flask==3.0.0 --hash=sha256:2222222222222222222222222222222222222222222222222222222222222222\n',
    'packages/worker/requirements.txt': 'celery==5.4.0\n',
  });
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('pip install --require-hashes -r is a miss', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: pip install --require-hashes -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a hash-pinned pip install does not vouch for an unpinned one in the same workflow', () => {
  // The suppression is scoped to the command carrying the flag. Read across the
  // whole file instead, the second command reads as clean.
  const { verdict, overrides } = verdictFor([
    '      - run: pip install --require-hashes -r build-reqs.txt',
    '      - run: pip install -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('the evidence points at the unpinned command line, not the top of the file', () => {
  // Steps start on line 7, so the unpinned second install is line 8. A
  // whole-file probe has no command to point at and reports line 0.
  const { verdict, locations } = verdictFor([
    '      - run: pip install --require-hashes -r build-reqs.txt',
    '      - run: pip install -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit');
  assert.equal(Array.isArray(locations), true, 'evidence_locations entry must be an array');
  assert.equal(locations.length, 1);
  assert.equal(locations[0].uri, '.github/workflows/release.yml');
  assert.equal(locations[0].startLine, 8);
});

test('the same two installs chained on one line are still probed separately', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: pip install --require-hashes -r build-reqs.txt && pip install -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a backslash-continued pip install is read as one command', () => {
  // Split across lines, `pip install \` and `-r requirements.txt` each match
  // nothing on their own and the unpinned install reads as a clean miss.
  const { verdict, locations, overrides } = verdictFor([
    '      - run: |',
    '          pip install \\',
    '            -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
  // Reported where the command starts, not where its last fragment ends.
  assert.equal(locations[0].startLine, 8);
});

test('a backslash-continued pip install keeps its --require-hashes suppression', () => {
  // Companion pin, not proof of the join: this reads as a miss with or without
  // line joining. It locks the join against later losing the flag it carries.
  const { verdict, overrides } = verdictFor([
    '      - run: |',
    '          pip install --require-hashes \\',
    '            -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('pip install -r against a --generate-hashes requirements file is a miss', () => {
  // One hashed requirement puts pip in hash-checking mode for the whole file,
  // so this install is reproducible without the flag being spelled out.
  const { verdict, overrides } = verdictFor(
    ['      - run: pip install -r requirements.txt', PUBLISH],
    {
      'requirements.txt': [
        'requests==2.32.3 \\',
        '    --hash=sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eac5d0c0f0f14',
        '',
      ].join('\n'),
    }
  );
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('pip install -r against a requirements file with no hashes is a hit', () => {
  const { verdict, overrides } = verdictFor(
    ['      - run: pip install -r requirements.txt', PUBLISH],
    { 'requirements.txt': 'requests==2.32.3\n' }
  );
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a hashed requirements file outside the scanned tree cannot suppress the finding', () => {
  // The `..` target is REAL and hash-pinned. Resolving it would read a file the
  // scan was never pointed at and turn the finding into a miss, so the reach is
  // refused and the unresolvable requirement set stays a hit.
  const outer = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'libauthor-escape-')));
  try {
    fs.mkdirSync(path.join(outer, 'elsewhere'), { recursive: true });
    fs.writeFileSync(path.join(outer, 'elsewhere', 'requirements.txt'), [
      'requests==2.32.3 \\',
      '    --hash=sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eac5d0c0f0f14',
      '',
    ].join('\n'));

    const repo = path.join(outer, 'repo');
    const wf = path.join(repo, '.github', 'workflows');
    fs.mkdirSync(wf, { recursive: true });
    fs.writeFileSync(path.join(repo, 'package.json'), '{"name":"x","version":"1.0.0"}');
    fs.writeFileSync(path.join(wf, 'release.yml'), [
      'name: release',
      'on: { push: { tags: ["v*"] } }',
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: pip install -r ../elsewhere/requirements.txt',
      PUBLISH,
      '',
    ].join('\n'));

    // Same file reached from INSIDE the tree is a miss, which is what proves
    // the hit above comes from the containment check and not from the file
    // being unreadable.
    fs.copyFileSync(
      path.join(outer, 'elsewhere', 'requirements.txt'),
      path.join(repo, 'requirements.txt')
    );

    const escaped = libauthor.collect({ cwd: repo });
    assert.equal(typeof escaped.signal_overrides[INDICATOR], 'string');
    assert.equal(escaped.signal_overrides[INDICATOR], 'hit',
      `signal_overrides=${JSON.stringify(escaped.signal_overrides)}`);

    fs.writeFileSync(path.join(wf, 'release.yml'),
      fs.readFileSync(path.join(wf, 'release.yml'), 'utf8')
        .replace('-r ../elsewhere/requirements.txt', '-r requirements.txt'));
    const inTree = libauthor.collect({ cwd: repo });
    assert.equal(inTree.signal_overrides[INDICATOR], 'miss',
      `the same hashed file inside the tree must suppress; signal_overrides=${JSON.stringify(inTree.signal_overrides)}`);
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

test('cargo install --locked does not vouch for an unlocked cargo build', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: cargo install --locked cargo-audit',
    '      - run: cargo build --release',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('cargo build --locked alone is a miss', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: cargo build --release --locked',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('pnpm install opting out of the frozen lockfile is a hit', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: pnpm install --no-frozen-lockfile',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a bare pnpm install in a GitHub Actions workflow is a miss', () => {
  // A pin on a deliberate no-fire, not proof of a repair — pnpm defaults to
  // --frozen-lockfile whenever CI is set, and Actions always sets it, so only
  // the explicit opt-out above resolves dependencies at release time. This
  // reads as a miss with or without the pnpm probe; it locks the probe against
  // widening to bare `pnpm install` and reporting every Actions workflow.
  const { verdict, overrides } = verdictFor([
    '      - run: pnpm install',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('bundle install without --deployment / --frozen is a hit', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: bundle install',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('bundle install --deployment is a miss', () => {
  const { verdict, overrides } = verdictFor([
    '      - run: bundle install --deployment',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a bundle config frozen set earlier in the job suppresses a later bundle install', () => {
  // Bundler frozen mode is job-scoped state rather than a per-command flag, so
  // this one suppressor legitimately reads across the file.
  const { verdict, overrides } = verdictFor([
    '      - run: bundle config set --local frozen true',
    '      - run: bundle install',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('bundle config set frozen false does not suppress a later bundle install', () => {
  // The setting has to be turned ON. Matching the key alone reads an explicit
  // opt-out as the protection it opts out of — the strongest possible signal
  // that the install is not frozen, silencing the finding.
  const { verdict, overrides } = verdictFor([
    '      - run: bundle config set --local frozen false',
    '      - run: bundle install',
    PUBLISH,
  ]);
  assert.equal(verdict, 'hit', `signal_overrides=${JSON.stringify(overrides)}`);
});

test('a commented-out unpinned install does not flip the indicator', () => {
  // False-positive guard on the probes added above: they read the
  // comment-stripped view, so a `#` line naming an unpinned install is not a
  // command. Nothing here fires without those probes, so it pins the new
  // surface rather than proving a repair.
  const { verdict, overrides } = verdictFor([
    '      # - run: pip install -r requirements.txt',
    '      # - run: bundle install',
    '      - run: pip install --require-hashes -r requirements.txt',
    PUBLISH,
  ]);
  assert.equal(verdict, 'miss', `signal_overrides=${JSON.stringify(overrides)}`);
});
});
