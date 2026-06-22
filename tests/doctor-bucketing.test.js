"use strict";

/**
 * tests/doctor-bucketing.test.js
 *
 * v0.13.11 regression pin for the doctor checks-to-buckets rule.
 *
 * Pre-fix bug: a check with `{ ok: false, severity: "warn" }` (e.g. the
 * signing-status check on a non-contributor install, where `.keys/private.pem`
 * is absent and the operator is being nudged to enable signing rather than
 * blocked from a release) was bucketed into `failed_checks` because the
 * `ok === false` branch fired before the `severity === "warn"` branch.
 * A fresh global `npm install -g @blamejs/exceptd-skills` would then
 * print `all_green: false`, `issues_count: 1`, `failed_checks: ["signing"]`,
 * `warnings_count: 0` — directly contradicting the `[!! warn]` icon shown
 * in the human text-mode output.
 *
 * Post-fix: severity wins. `severity === "warn"` always routes to
 * `warning_checks`, regardless of `ok`.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { bucketChecks } = require(path.join(__dirname, "..", "lib", "doctor-bucketing.js"));

test("doctor-bucketing: severity warn + ok false routes to warnList (not errorList)", () => {
  const checks = {
    signing: { ok: false, severity: "warn", private_key_present: false },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["signing"],
    "ok:false + severity:warn must be a warning, not a failure");
  assert.deepEqual(errorList, [],
    "no errors expected when only severity-warn checks are present");
});

test("doctor-bucketing: ok false without severity warn routes to errorList", () => {
  const checks = {
    signatures: { ok: false, exit_code: 1 },
    cves: { ok: false, error: "catalog unreadable" },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, []);
  assert.deepEqual(errorList.sort(), ["cves", "signatures"]);
});

test("doctor-bucketing: ok true with no severity routes to neither bucket (green)", () => {
  const checks = {
    signatures: { ok: true, skills_passed: 42, skills_total: 42 },
    currency: { ok: true, total_skills: 42 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, []);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: severity warn + ok true also routes to warnList", () => {
  // Some checks are advisory: they may set severity:warn while still
  // returning ok:true (e.g. a soft "consider upgrading" hint). These
  // belong in the warning bucket.
  const checks = {
    catalog_freshness: { ok: true, severity: "warn", days_since_refresh: 75 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["catalog_freshness"]);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: mixed input partitions correctly into both buckets", () => {
  const checks = {
    signatures: { ok: true },
    cves: { ok: false, error: "catalog missing" },
    signing: { ok: false, severity: "warn", private_key_present: false },
    currency: { ok: true, severity: "warn", days_since_refresh: 95 },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList.sort(), ["currency", "signing"]);
  assert.deepEqual(errorList, ["cves"]);
});

test("doctor-bucketing: tolerates null / non-object check values without throwing", () => {
  // Defensive: a future check that fails to populate its slot must not
  // crash the bucketing. assert: ignored entries don't appear in either
  // bucket and no exception escapes.
  const checks = {
    legit: { ok: false, severity: "warn" },
    busted: null,
    also_busted: "not-an-object",
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, ["legit"]);
  assert.deepEqual(errorList, []);
});

test("doctor-bucketing: severity:info with ok:false routes to neither bucket (informational-only)", () => {
  // v0.13.13 pin. severity:info means "this check is informational, not
  // a problem here." A consumer install of @blamejs/exceptd-skills sets
  // signing.severity=info with ok:false (no private key) — that's not
  // a warning or a failure, just a fact about the install shape.
  const checks = {
    signing: { ok: false, severity: "info", private_key_present: false, install_mode: "consumer" },
  };
  const { warnList, errorList } = bucketChecks(checks);
  assert.deepEqual(warnList, [],
    "severity:info must NOT route to warnList even with ok:false");
  assert.deepEqual(errorList, [],
    "severity:info must NOT route to errorList even with ok:false");
});

test("doctor-bucketing: empty input returns empty buckets (no exception)", () => {
  assert.deepEqual(bucketChecks({}), { warnList: [], errorList: [] });
  assert.deepEqual(bucketChecks(null), { warnList: [], errorList: [] });
  assert.deepEqual(bucketChecks(undefined), { warnList: [], errorList: [] });
});


// ---- routed from hunt-fix-H-cli ----
;(() => {
// Regression tests for the H-cli bug cluster in bin/exceptd.js:
//   #35 doctor --json/--pretty exit-code symmetry with the human path
//       (warnings alone are exit 0; only errors force exit 1).
//   #36 ci --evidence-dir applies the SAME symlink/junction/non-regular-file/
//       playbook-id hardening as run --evidence-dir (shared readEvidenceDir).
//   #37 --json-stdout-only routes the emitError ok:false envelope to STDOUT
//       (so a `| jq` consumer never sees an empty document on an error path).
//   #38 help/welcome printers exit via safeExit (no process.exit-after-stdout
//       truncation), and `help`/`<verb> --help`/no-arg all exit 0 with output.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const BIN = path.resolve(__dirname, '..', 'bin', 'exceptd.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || process.cwd(),
    env: { ...process.env, ...(opts.env || {}) },
    // stderr is a pipe (not a TTY) here, which is exactly the CI/parser shape
    // the JSON-envelope contract targets.
  });
}

function tryJson(s) {
  if (typeof s !== 'string') return null;
  try { return JSON.parse(s); } catch { return null; }
}

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-hcli-'));
}

// ---------------------------------------------------------------------------
// #36 — shared readEvidenceDir helper (in-process, exact-value assertions).
// ---------------------------------------------------------------------------
const cli = require('../bin/exceptd.js');

test('#36 readEvidenceDir is exported and shared by run + ci', () => {
  assert.equal(typeof cli._readEvidenceDir, 'function');
});

test('#36 readEvidenceDir reads a normal <pb>.json regular file (positive path)', () => {
  const dir = mkTmp();
  try {
    fs.writeFileSync(path.join(dir, 'sbom.json'), JSON.stringify({ signals: { x: 1 } }), 'utf8');
    const r = cli._readEvidenceDir(dir, 'run');
    assert.equal(r.ok, true);
    assert.equal(typeof r.bundle, 'object');
    assert.notEqual(r.bundle, null);
    assert.deepEqual(r.bundle.sbom, { signals: { x: 1 } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses a non-regular-file entry (dir named <pb>.json)', () => {
  const dir = mkTmp();
  try {
    // A directory whose name ends in .json is a non-regular file; the fstat
    // isFile() gate must refuse it (this is the junction/symlink/dir bypass
    // class that the bare ci reader missed).
    fs.mkdirSync(path.join(dir, 'sbom.json'));
    const r = cli._readEvidenceDir(dir, 'ci');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    assert.match(r.error, /not a regular file|resolves outside|symbolic link/);
    // The verb prefix is threaded through so the caller's message is correct.
    assert.match(r.error, /^ci:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses an invalid playbook-id filename segment', () => {
  const dir = mkTmp();
  try {
    // Uppercase filename → validateIdComponent('playbook') rejects it.
    fs.writeFileSync(path.join(dir, 'Sbom.json'), '{}', 'utf8');
    const r = cli._readEvidenceDir(dir, 'run');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    assert.match(r.error, /invalid playbook-id segment/);
    assert.match(r.error, /^run:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses a symlinked entry (symlink/junction class)', (t) => {
  const dir = mkTmp();
  const outside = mkTmp();
  try {
    const target = path.join(outside, 'secret.json');
    fs.writeFileSync(target, JSON.stringify({ stolen: true }), 'utf8');
    const link = path.join(dir, 'sbom.json');
    try {
      // Windows: a file symlink needs the symlink type + (usually) privilege.
      fs.symlinkSync(target, link, 'file');
    } catch (e) {
      if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOSYS') {
        t.skip('symlink creation not permitted on this host');
        return;
      }
      throw e;
    }
    const r = cli._readEvidenceDir(dir, 'ci');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    // O_NOFOLLOW (POSIX) refuses at open with ELOOP; Windows follows the link
    // and the explicit lstat refusal fires. Either way the symlink target is
    // never absorbed into the bundle.
    assert.match(r.error, /symbolic link|symlink|resolves outside|not a regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir refuses a non-regular-file entry end-to-end (cross-platform parity)', () => {
  // No symlink privilege required: a directory named <pb>.json exercises the
  // exact fstat isFile() gate the bare ci reader lacked pre-fix. Pre-fix the
  // bare fs.readFileSync would EISDIR; the hardened reader refuses with a
  // structured ok:false body and exit 1, matching run.
  const dir = mkTmp();
  try {
    fs.mkdirSync(path.join(dir, 'sbom.json'));
    const r = run(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    assert.equal(r.status, 1);
    const e = tryJson(r.stderr);
    assert.notEqual(e, null);
    assert.equal(e.ok, false);
    assert.equal(typeof e.error, 'string');
    assert.match(e.error, /not a regular file/);
    assert.match(e.error, /^ci:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir reads a normal <pb>.json regular file end-to-end (positive)', () => {
  const dir = mkTmp();
  try {
    fs.writeFileSync(path.join(dir, 'sbom.json'), JSON.stringify({ signals: {} }), 'utf8');
    const r = run(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    // A clean no-detection run exits 0; the point is the gate ran and accepted
    // the regular file (no refusal error on stderr).
    assert.equal(r.status, 0);
    const e = tryJson(r.stderr);
    assert.equal(e, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir refuses a symlinked entry end-to-end (verb parity with run)', (t) => {
  const dir = mkTmp();
  const outside = mkTmp();
  try {
    const target = path.join(outside, 'secret.json');
    fs.writeFileSync(target, JSON.stringify({ stolen: true }), 'utf8');
    const link = path.join(dir, 'sbom.json');
    try {
      fs.symlinkSync(target, link, 'file');
    } catch (e) {
      if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOSYS') {
        t.skip('symlink creation not permitted on this host');
        return;
      }
      throw e;
    }
    const r = run(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    assert.equal(r.status, 1);
    const e = tryJson(r.stderr);
    assert.notEqual(e, null);
    assert.equal(e.ok, false);
    assert.equal(typeof e.error, 'string');
    assert.match(e.error, /symbolic link|resolves outside|not a regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// #35 — doctor exit-code symmetry across JSON / pretty / human modes.
// A warn-only state (no errors, >=1 warning) must exit 0 in EVERY output mode.
// Pre-fix the JSON/pretty path gated on `!allGreen` (which conflates warnings
// with errors) and exited 1, while human mode correctly exited 0.
//
// Deterministic warn-only state: a registry fixture reporting a much-newer
// published version drives the --registry-check probe to behind:true, which
// the doctor classifies as severity:"warn" — no error checks involved.
// ---------------------------------------------------------------------------
function writeBehindFixture(dir) {
  const fx = path.join(dir, 'registry-fixture.json');
  fs.writeFileSync(fx, JSON.stringify({
    'dist-tags': { latest: '99.0.0' },
    version: '99.0.0',
    time: { '99.0.0': '2099-01-01T00:00:00.000Z', modified: '2099-01-01T00:00:00.000Z' },
  }), 'utf8');
  return fx;
}

test('#35 doctor --registry-check (warn-only) exits 0 in JSON, pretty, AND human modes', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const env = { EXCEPTD_REGISTRY_FIXTURE: fx };

    const rJson = run(['doctor', '--registry-check', '--json'], { env });
    const b = tryJson(rJson.stdout);
    assert.notEqual(b, null);
    // Confirm we actually staged a warn-only state (field-presence paired with
    // content): a warning exists, no errors, registry is the warning check.
    assert.equal(b.summary.issues_count, 0);
    assert.equal(b.summary.warnings_count >= 1, true);
    assert.equal(Array.isArray(b.summary.warning_checks), true);
    assert.equal(b.summary.warning_checks.includes('registry'), true);
    assert.equal(b.summary.all_green, false);
    // The fix: JSON exit code tracks errors only, so warn-only => exit 0.
    assert.equal(rJson.status, 0);

    const rPretty = run(['doctor', '--registry-check', '--pretty'], { env });
    assert.equal(rPretty.status, 0);

    const rHuman = run(['doctor', '--registry-check'], { env });
    assert.equal(rHuman.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 doctor --json exit code equals the human exit code in the warn-only state', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const env = { EXCEPTD_REGISTRY_FIXTURE: fx };
    const rJson = run(['doctor', '--registry-check', '--json'], { env });
    const rHuman = run(['doctor', '--registry-check'], { env });
    assert.equal(rJson.status, rHuman.status);
    assert.equal(rJson.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 doctor --json body keeps all_green:false + warning_checks even though exit is 0', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const rJson = run(['doctor', '--registry-check', '--json'], { env: { EXCEPTD_REGISTRY_FIXTURE: fx } });
    const b = tryJson(rJson.stdout);
    assert.notEqual(b, null);
    // The body still surfaces the full picture for consumers that want it;
    // only the exit code stopped conflating warnings with errors.
    assert.equal(b.summary.all_green, false);
    assert.equal(typeof b.summary.warnings_count, 'number');
    assert.equal(b.summary.warnings_count >= 1, true);
    assert.equal(b.summary.issues_count, 0);
    assert.equal(rJson.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 inverse: a genuine error-severity check still forces exit 1 (errorList non-empty)', () => {
  // The fixed JSON predicate is `errorList.length > 0`. Pin the property that a
  // real signature failure (ok:false with NO severity:"warn") routes to
  // errorList — so it still forces exit 1 under the fix — using the same
  // bucketing the doctor uses. A warn-only check must NOT land in errorList.
  const { bucketChecks } = require('../lib/doctor-bucketing.js');
  const errState = bucketChecks({
    signatures: { ok: false, error: 'Ed25519 verification failed' }, // no severity => error
    registry: { ok: false, severity: 'warn', error: 'behind' },
  });
  assert.equal(errState.errorList.includes('signatures'), true);
  assert.equal(errState.errorList.length > 0, true); // => fixed predicate exits 1
  assert.equal(errState.warnList.includes('registry'), true);
  assert.equal(errState.errorList.includes('registry'), false);

  const warnOnly = bucketChecks({
    registry: { ok: false, severity: 'warn', error: 'behind' },
  });
  assert.equal(warnOnly.errorList.length, 0); // => fixed predicate exits 0
  assert.equal(warnOnly.warnList.length, 1);
});

// ---------------------------------------------------------------------------
// #37 — --json-stdout-only emits the ok:false envelope to STDOUT on error.
// Pre-fix: both stdout and stderr were empty on the error path (only an exit
// code), so a `| jq` consumer parsed nothing.
// ---------------------------------------------------------------------------
test('#37 unknown verb + --json-stdout-only writes the ok:false envelope to STDOUT (exit 10)', () => {
  const r = run(['definitelynotaverb', '--json-stdout-only']);
  assert.equal(r.status, 10);
  const body = tryJson(r.stdout);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /unknown command/);
});

test('#37 evidence-read failure + --json-stdout-only is reachable on STDOUT (exit 1)', () => {
  // A missing --evidence-dir is the simplest deterministic IO-failure path
  // that lands in emitError under the run verb.
  const missing = path.join(os.tmpdir(), 'exceptd-hcli-does-not-exist-' + process.pid);
  const r = run(['run', 'sbom', '--evidence-dir', missing, '--json-stdout-only']);
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  // Specifically: the diagnostic is on stdout (the flag's whole purpose),
  // not only stderr.
  assert.notEqual(tryJson(r.stdout), null);
  assert.equal(tryJson(r.stdout).ok, false);
});

test('#37 a typo flag under --json-stdout-only still surfaces a machine-readable error', () => {
  const r = run(['run', '--evidnce', 'x', '--json-stdout-only']);
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
});

// ---------------------------------------------------------------------------
// #38 — help/welcome printers exit 0 with output (no process.exit truncation).
// ---------------------------------------------------------------------------
test('#38 bare invocation (welcome) exits 0 and writes non-empty stdout', () => {
  const r = run([]);
  assert.equal(r.status, 0);
  assert.equal(typeof r.stdout, 'string');
  assert.equal(r.stdout.length > 0, true);
});

test('#38 `help` exits 0 and writes the full help text to stdout', () => {
  const r = run(['help']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
  assert.match(r.stdout, /exceptd/);
});

test('#38 `help <verb>` exits 0 with verb-specific help (no truncation)', () => {
  const r = run(['help', 'run']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
});

test('#38 `<verb> --help` exits 0 with verb help', () => {
  const r = run(['run', '--help']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
});

test('#38 no live process.exit() remains on the help/welcome dispatch paths', () => {
  // Structural guard: the source must not reintroduce a bare process.exit() on
  // the printWelcome / printHelp / printPlaybookVerbHelp paths. Strip comments,
  // then assert every remaining process.exit( occurrence is absent.
  const src = fs.readFileSync(BIN, 'utf8');
  const noLineComments = src.replace(/\/\/[^\n]*/g, '');
  const noComments = noLineComments.replace(/\/\*[\s\S]*?\*\//g, '');
  assert.equal(/process\.exit\s*\(/.test(noComments), false);
});
})();
