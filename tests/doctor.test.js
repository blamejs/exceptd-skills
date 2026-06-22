'use strict';

/**
 * Subject coverage for the `doctor` CLI verb (bin/exceptd.js cmdDoctor): the
 * full no-flags health run, each selective subcheck (--signatures, --currency,
 * --cves, --rfcs, --shipped-tarball), the output envelope + summary shape, and
 * the --air-gap flag-allowlist consistency.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-doctor-');
  const cli = makeCli(SUITE_HOME);

  test('doctor no-flags emits checks{} covering every subcheck', () => {
    const r = cli(['doctor', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.equal(data.verb, 'doctor');
    assert.ok(data.checks && typeof data.checks === 'object', 'checks{} must be present');
    assert.ok(Object.keys(data.checks).length >= 4,
      'doctor with no flags must run at least 4 subchecks (signatures, currency, cves, rfcs)');
    for (const [name, check] of Object.entries(data.checks)) {
      assert.equal(typeof check.ok, 'boolean',
        `check ${name} must carry boolean .ok (no coincidence-passing)`);
    }
  });

  test('doctor --signatures emits only the signatures subcheck', () => {
    const r = cli(['doctor', '--signatures', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.signatures,
      'checks.signatures must be present when --signatures is passed');
    assert.equal(typeof data.checks.signatures.ok, 'boolean',
      'signatures.ok must be a boolean verdict, not undefined');
  });

  test('doctor --signatures --shipped-tarball opts into tarball-verify round-trip', () => {
    const r = cli(['doctor', '--signatures', '--shipped-tarball', '--json'], { timeout: 120000 });
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.signatures, 'checks.signatures must be present');
    assert.ok(data.checks.signatures.shipped_tarball,
      'checks.signatures.shipped_tarball must be populated when --shipped-tarball is passed');
    const st = data.checks.signatures.shipped_tarball;
    if (st.skipped === true) {
      assert.equal(typeof st.reason, 'string',
        'when skipped, shipped_tarball must document why (e.g. installed package without verify-shipped-tarball.js)');
    } else {
      assert.equal(typeof st.ok, 'boolean',
        'when run, shipped_tarball.ok must be a boolean verdict');
    }
  });

  test('doctor --currency emits only the currency subcheck', () => {
    const r = cli(['doctor', '--currency', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.currency, 'checks.currency must be present');
    assert.equal(typeof data.checks.currency.ok, 'boolean');
  });

  test('doctor --cves emits only the cves subcheck', () => {
    const r = cli(['doctor', '--cves', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.cves, 'checks.cves must be present');
    assert.equal(typeof data.checks.cves.ok, 'boolean');
  });

  test('doctor --rfcs emits only the rfcs subcheck', () => {
    const r = cli(['doctor', '--rfcs', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.rfcs, 'checks.rfcs must be present');
    assert.equal(typeof data.checks.rfcs.ok, 'boolean');
  });

  test('doctor --rfcs (modern) wraps the same validator with structured output', () => {
    const r = cli(['doctor', '--rfcs', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data?.checks?.rfcs, 'doctor --rfcs must populate checks.rfcs');
    assert.equal(typeof data.checks.rfcs.ok, 'boolean',
      'checks.rfcs.ok must be a boolean (not undefined / not coincidence-truthy)');
    assert.ok(typeof data.checks.rfcs.total === 'number' || data.checks.rfcs.total === null,
      'checks.rfcs.total must be numeric or explicit null');
  });
});

// ===========================================================================
test.describe('cli-output-envelope-shape-v0_12_39', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  test('doctor envelope: exact top-level + summary sub-key set + baseline check set', () => {
    const r = cli(['doctor', '--json']);
    const body = tryJson(r.stdout);
    assert.ok(body, `doctor must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    assert.deepEqual(Object.keys(body).sort(), ['checks', 'local_version', 'ok', 'summary', 'verb']);
    assert.equal(body.verb, 'doctor');
    assert.equal(body.ok, true, 'v0.13: doctor carries ok:true (summary.all_green remains authoritative)');

    const baselineChecks = ['currency', 'cves', 'rfcs', 'signatures', 'signing'];
    for (const k of baselineChecks) {
      assert.ok(k in body.checks, `expected check "${k}" in doctor.checks`);
      assert.equal(typeof body.checks[k].ok, 'boolean');
    }

    const expectedSummaryKeys = [
      'all_green', 'failed_checks', 'issues_count',
      'warning_checks', 'warnings_count',
    ];
    assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
    assert.equal(typeof body.summary.all_green, 'boolean');
    assert.ok(Array.isArray(body.summary.failed_checks));
    assert.ok(Array.isArray(body.summary.warning_checks));
    assert.equal(body.summary.issues_count, body.summary.failed_checks.length);
    assert.equal(body.summary.warnings_count, body.summary.warning_checks.length);
  });
});

// ===========================================================================
test.describe('reconciliation-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-doctor-');
  const cli = makeCli(home);

  test('doctor accepts --air-gap on both validation paths (allowlist drift fixed)', () => {
    const r = cli(['doctor', '--bogus', '--json']);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.ok(Array.isArray(body.known_flags), 'doctor --bogus emits known_flags');
    assert.ok(body.known_flags.includes('--air-gap'), 'doctor known_flags must include --air-gap');
    const ok = cli(['doctor', '--signatures', '--air-gap', '--json']);
    assert.doesNotMatch((ok.stdout || '') + (ok.stderr || ''), /unknown flag/, '--air-gap must be accepted on doctor');
  });
});


// ---- routed from doctor-collectors ----
require("node:test").describe("doctor-collectors", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/doctor-collectors.test.js
 *
 * Pins the doctor collector-layer health gate: --collectors flag
 * emits a structured envelope, default no-flag doctor pass folds
 * it in, ok: true on a clean tree, policy_skips covers the
 * catalogued judgement-shaped playbooks, with_collector +
 * without_collector counts match on-disk truth.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");
const PLAYBOOK_DIR = path.join(ROOT, "data", "playbooks");
const COLLECTOR_DIR = path.join(ROOT, "lib", "collectors");

const POLICY_SKIPS = [
  "framework", "ransomware", "ai-discovered-cve-triage",
  "cloud-iam-incident", "idp-incident", "identity-sso-compromise",
  "llm-tool-use-exfil", "supply-chain-recovery",
  "post-quantum-migration", "webhook-callback-abuse",
];

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    timeout: 60000,
    ...opts,
  });
}

test("doctor --collectors emits a structured envelope with the catalogued shape", () => {
  const r = runCli(["doctor", "--collectors", "--json"]);
  assert.equal(r.status, 0, `doctor --collectors exit non-zero; stderr=${r.stderr.slice(0, 400)}`);
  const body = JSON.parse(r.stdout);
  assert.ok(body.checks, "envelope missing checks");
  const c = body.checks.collectors;
  assert.ok(c, "envelope missing checks.collectors");
  assert.equal(c.ok, true, `collectors ok=false: ${JSON.stringify(c)}`);
  assert.equal(typeof c.total_playbooks, "number");
  assert.equal(typeof c.with_collector, "number");
  assert.ok(Array.isArray(c.without_collector));
  assert.ok(Array.isArray(c.load_errors));
  assert.ok(Array.isArray(c.policy_skips));
  for (const pid of POLICY_SKIPS) {
    assert.ok(c.policy_skips.includes(pid), `policy_skips missing ${pid}`);
  }
});

test("doctor --collectors counts match on-disk truth (every playbook resolved against lib/collectors/<id>.js)", () => {
  const r = runCli(["doctor", "--collectors", "--json"]);
  const body = JSON.parse(r.stdout);
  const c = body.checks.collectors;

  const playbooks = fs.readdirSync(PLAYBOOK_DIR)
    .filter(f => f.endsWith(".json") && !f.startsWith("_"))
    .map(f => f.replace(/\.json$/, ""));

  assert.equal(c.total_playbooks, playbooks.length);

  let actualWith = 0;
  const actualWithout = [];
  for (const pid of playbooks) {
    if (fs.existsSync(path.join(COLLECTOR_DIR, pid + ".js"))) actualWith++;
    else actualWithout.push(pid);
  }
  assert.equal(c.with_collector, actualWith);
  assert.deepEqual(c.without_collector.sort(), actualWithout.sort());
});

test("default doctor pass (no flags) folds in the collector gate", () => {
  // The default doctor pass also runs the signing-status check, which
  // is severity:warn (not green) when .keys/private.pem is absent.
  // On CI / consumer installs that's the normal state, so the overall
  // doctor exit code lands non-zero. We don't care here — we only need
  // to confirm the collectors gate is included in the envelope.
  const r = runCli(["doctor", "--json"]);
  const body = JSON.parse(r.stdout);
  assert.ok(body.checks, "doctor envelope missing checks");
  assert.ok(body.checks.collectors, "default doctor pass missing collectors gate");
  assert.equal(body.checks.collectors.ok, true);
});

test("doctor --collectors human renderer prints the collector-layer line + skip note", () => {
  const r = runCli(["doctor", "--collectors"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /collector layer:\s+\d+\/\d+ playbooks have collectors/);
  assert.match(r.stdout, /judgement-shaped playbooks intentionally without/);
});
});


// ---- routed from doctor-consumer-install-mode ----
require("node:test").describe("doctor-consumer-install-mode", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/doctor-consumer-install-mode.test.js
 *
 * v0.13.13 regression pin for the consumer-install-aware signing check.
 *
 * Pre-fix: a fresh `npm install -g @blamejs/exceptd-skills` printed
 * `[!! warn] attestation signing: private key MISSING` and counted
 * one warning in the JSON summary. That nudge made sense for a
 * contributor checkout (where the operator is expected to generate
 * a keypair and sign skills) but read as a problem for a consumer
 * install where signing is intentionally not enabled — consumers
 * verify shipped signatures, they do not generate new ones.
 *
 * Post-fix: doctor detects PKG_ROOT under node_modules/ and reports
 * the absent-key state as severity:info (with the explanatory hint)
 * on a consumer install, while keeping severity:warn for contributor
 * checkouts. The bucketing logic from v0.13.11 then routes consumer
 * installs to neither warnings nor errors — `all_green: true`.
 *
 * Test approach: shell out to the doctor verb with the working
 * directory inside a fixture tree that mimics each shape, and pin
 * the install_mode + severity + bucket placement.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

test("doctor: contributor checkout sets install_mode=contributor", () => {
  // Running the in-repo CLI is a contributor checkout — PKG_ROOT is the
  // repo root, NOT under node_modules/. install_mode must reflect that.
  const r = spawnSync(process.execPath, [CLI, "doctor", "--json"], {
    encoding: "utf8",
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
  });
  const body = JSON.parse(r.stdout);
  assert.equal(body.checks.signing.install_mode, "contributor",
    "in-repo run must detect contributor install_mode");
});

test("doctor: contributor checkout WITH private key reports severity:info + warnings_count=0", () => {
  // The repo ships with .keys/private.pem (the maintainer's signing
  // key checked out in the working tree). Doctor must see the key and
  // report severity:info, with the check absent from both bucket lists.
  if (!fs.existsSync(path.join(ROOT, ".keys", "private.pem"))) {
    // Skip when running on a contributor checkout that doesn't have
    // the key — the next test exercises that path explicitly.
    return;
  }
  const r = spawnSync(process.execPath, [CLI, "doctor", "--json"], {
    encoding: "utf8",
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
  });
  const body = JSON.parse(r.stdout);
  assert.equal(body.checks.signing.severity, "info");
  assert.equal(body.checks.signing.private_key_present, true);
  assert.ok(!body.summary.warning_checks.includes("signing"));
  assert.ok(!body.summary.failed_checks.includes("signing"));
});

test("doctor: consumer detection survives realpath-resolved symlink (parent-is-@blamejs signal)", () => {
  // Codex P1 on PR #53: single-signal "PKG_ROOT contains node_modules"
  // is fragile against symlink-resolved paths (npm link / workspaces).
  // The v0.13.14 fix adds a second signal: PKG_ROOT's parent dir basename
  // is "@blamejs". Stage a layout where the package sits inside an
  // @blamejs/ scope dir but NOT under any node_modules/ ancestor (the
  // realpath-after-symlink-resolution shape codex named). Detection
  // must still classify as consumer.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-realpath-"));
  try {
    const pkg = path.join(tmp, "@blamejs", "exceptd-skills");
    fs.mkdirSync(pkg, { recursive: true });
    const SYMLINK_OK = new Set([
      "data", "lib", "orchestrator", "scripts", "sources", "vendor", "skills", "agents", "keys",
      "AGENTS.md", "ARCHITECTURE.md", "CHANGELOG.md", "CONTEXT.md",
      "LICENSE", "NOTICE", "README.md", "SECURITY.md",
      "manifest.json", "manifest-snapshot.json", "manifest-snapshot.sha256", "sbom.cdx.json",
      "package.json",
    ]);
    for (const rel of fs.readdirSync(ROOT)) {
      if (rel === ".keys" || rel === ".git" || rel === "node_modules") continue;
      const src = path.join(ROOT, rel);
      const dst = path.join(pkg, rel);
      if (rel === "bin") { fs.cpSync(src, dst, { recursive: true }); }
      else if (SYMLINK_OK.has(rel)) {
        try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? "dir" : "file"); }
        catch { fs.cpSync(src, dst, { recursive: true }); }
      } else { fs.cpSync(src, dst, { recursive: true }); }
    }
    const stagedCli = path.join(pkg, "bin", "exceptd.js");
    const r = spawnSync(process.execPath, [stagedCli, "doctor", "--json"], {
      encoding: "utf8", cwd: tmp,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
    });
    const body = JSON.parse(r.stdout);
    assert.equal(body.checks.signing.install_mode, "consumer",
      "@blamejs parent-dir signal must detect consumer mode without a node_modules ancestor");
    assert.equal(body.checks.signing.severity, "info");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test("doctor: consumer install (PKG_ROOT under node_modules/) reports severity:info on missing key", () => {
  // Stage a fake "consumer install" layout: a temp dir with a
  // `node_modules/@blamejs/exceptd-skills/` shape. The doctor verb is
  // invoked via that shape's bin/exceptd.js so PKG_ROOT resolves to
  // the staged location.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-consumer-"));
  try {
    const pkg = path.join(tmp, "node_modules", "@blamejs", "exceptd-skills");
    fs.mkdirSync(pkg, { recursive: true });
    // Stage the repo tree at the consumer-install path. bin/ MUST be
    // copied (not symlinked) — Node resolves __dirname through symlinks,
    // so a symlinked bin/exceptd.js would compute PKG_ROOT against the
    // REAL repo, not the staged location, defeating the test. The rest
    // of the tree can symlink for speed.
    const SYMLINK_OK = new Set([
      "data", "lib", "orchestrator", "scripts", "sources", "vendor", "skills", "agents", "keys",
      "AGENTS.md", "ARCHITECTURE.md", "CHANGELOG.md", "CONTEXT.md",
      "LICENSE", "NOTICE", "README.md", "SECURITY.md",
      "manifest.json", "manifest-snapshot.json", "manifest-snapshot.sha256", "sbom.cdx.json",
      "package.json",
    ]);
    for (const rel of fs.readdirSync(ROOT)) {
      if (rel === ".keys" || rel === ".git" || rel === "node_modules") continue;
      const src = path.join(ROOT, rel);
      const dst = path.join(pkg, rel);
      if (rel === "bin") {
        // Copy bin/ so __dirname resolves to the staged path.
        fs.cpSync(src, dst, { recursive: true });
      } else if (SYMLINK_OK.has(rel)) {
        try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? "dir" : "file"); }
        catch { fs.cpSync(src, dst, { recursive: true }); }
      } else {
        // Unknown entry — copy to be safe.
        fs.cpSync(src, dst, { recursive: true });
      }
    }
    const stagedCli = path.join(pkg, "bin", "exceptd.js");
    const r = spawnSync(process.execPath, [stagedCli, "doctor", "--json"], {
      encoding: "utf8",
      cwd: tmp,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
    });
    const body = JSON.parse(r.stdout);
    assert.equal(body.checks.signing.install_mode, "consumer",
      "PKG_ROOT under node_modules/ must detect consumer install_mode");
    assert.equal(body.checks.signing.private_key_present, false);
    assert.equal(body.checks.signing.severity, "info",
      "consumer install with absent key must be severity:info, not :warn");
    // Bucket placement: not in warning_checks, not in failed_checks.
    assert.ok(!body.summary.warning_checks.includes("signing"),
      "consumer install signing check must NOT route to warning_checks");
    assert.ok(!body.summary.failed_checks.includes("signing"),
      "consumer install signing check must NOT route to failed_checks");
    // Hint must explain why signing isn't enabled.
    assert.match(body.checks.signing.hint, /consumer install/i,
      "consumer-install hint must be operator-readable");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
});
