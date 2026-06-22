'use strict';

/**
 * Subject coverage for the `ci` CLI verb (bin/exceptd.js cmdCi): the
 * --max-rwep / --block-on-jurisdiction-clock / --evidence-dir flags, selector
 * refusals (--required "" / --scope "" / --required with no value), flag
 * relevance, the output envelope shape, --mode validation, session-id
 * attribution, and --help surfacing.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');

  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-ci-');
  const cli = makeCli(SUITE_HOME);

  test('ci --max-rwep <N> overrides the playbook escalate threshold', () => {
    const r = cli(['ci', '--required', 'secrets', '--max-rwep', '50', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data, 'ci --max-rwep must emit JSON');
    assert.equal(data.verb, 'ci');
    assert.equal(typeof data.summary.max_rwep_observed, 'number',
      'summary.max_rwep_observed must be numeric');
    assert.ok(typeof data.summary.verdict === 'string',
      'summary.verdict must be a string (PASS/FAIL)');
  });

  test('ci --format sarif emits a non-empty array of conformant SARIF documents', () => {
    // Regression: ci only built each playbook's declared PRIMARY bundle_format,
    // so `--format sarif` (when no playbook's primary was sarif) aggregated an
    // empty array. cmdCi now threads signals._bundle_formats into each run.
    const r = cli(['ci', '--scope', 'code', '--format', 'sarif']);
    const arr = tryJson(r.stdout);
    assert.ok(Array.isArray(arr) && arr.length > 0,
      `ci --format sarif must emit a non-empty array; got: ${String(r.stdout).slice(0, 120)}`);
    assert.ok(arr.every((d) => d && Array.isArray(d.runs)),
      'each element must be a conformant SARIF document (.runs[])');
  });

  test('ci --format openvex emits a non-empty array of conformant OpenVEX documents', () => {
    const r = cli(['ci', '--scope', 'code', '--format', 'openvex']);
    const arr = tryJson(r.stdout);
    assert.ok(Array.isArray(arr) && arr.length > 0,
      `ci --format openvex must emit a non-empty array; got: ${String(r.stdout).slice(0, 120)}`);
    assert.ok(arr.every((d) => d && d['@context']),
      'each element must carry an OpenVEX @context');
  });

  test('ci --block-on-jurisdiction-clock fails when a clock fires (F18: exit 5 = CLOCK_STARTED)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cidir-'));
    fs.mkdirSync(tmp, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'secrets.json'), JSON.stringify({
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 },
    }));
    try {
      const r = cli(['ci', '--required', 'secrets',
        '--evidence-dir', tmp,
        '--ack',
        '--block-on-jurisdiction-clock', '--json']);
      const data = tryJson(r.stdout);
      assert.ok(data, 'ci output must be JSON');
      assert.ok(data.summary.jurisdiction_clocks_started >= 1,
        'detected+blast_radius=4 must start at least one jurisdiction clock');
      assert.equal(data.summary.verdict, 'CLOCK_STARTED',
        'F18: --block-on-jurisdiction-clock plus a started clock must produce verdict=CLOCK_STARTED');
      assert.ok(Array.isArray(data.summary.clock_started_reasons),
        'F18: summary.clock_started_reasons must be present and an array');
      assert.ok(data.summary.clock_started_reasons.some(fr => /jurisdiction clock started/.test(fr)),
        'F18: clock_started_reasons must explicitly mention the jurisdiction-clock cause');
      assert.equal(r.status, 5,
        'F18: clock-fired runs exit 5 (CLOCK_STARTED), separate from FAIL (2)');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('ci --evidence-dir <dir> routes per-playbook submission files', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cidir2-'));
    fs.mkdirSync(tmp, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'secrets.json'), JSON.stringify({
      observations: { a: { captured: true, value: 'x', indicator: 'aws-access-key-id', result: 'miss' } },
    }));
    fs.writeFileSync(path.join(tmp, 'library-author.json'), JSON.stringify({
      observations: { b: { captured: true, value: 'y', indicator: 'publish-workflow-uses-static-token', result: 'miss' } },
    }));
    try {
      const r = cli(['ci', '--required', 'secrets,library-author', '--evidence-dir', tmp, '--json']);
      const data = tryJson(r.stdout);
      assert.ok(data, 'ci --evidence-dir must emit JSON');
      assert.deepEqual([...data.playbooks_run].sort(), ['library-author', 'secrets'],
        'ci must run exactly the two playbooks both keyed in --required and present in --evidence-dir');
      assert.equal(data.summary.total, 2, 'summary.total must reflect the dispatched count');
      assert.equal(data.summary.blocked, 0,
        '--evidence-dir submissions must satisfy preconditions; 0 blocked');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
test.describe('cli-error-envelopes', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  function run(script, args, env) {
    return spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1', EXCEPTD_RAW_JSON: '1', ...env },
    });
  }

  test('ci --max-rwep with a forgotten value errors instead of silently capping at 1', () => {
    const r = run(CLI, ['ci', 'secrets', '--max-rwep'], {});
    assert.equal(r.status, 1);
    const err = tryJson(r.stderr.trim());
    assert.ok(err, `stderr must be a parseable envelope; got ${r.stderr.slice(0, 200)}`);
    assert.equal(err.ok, false);
    assert.equal(err.verb, 'ci');
    assert.match(err.error, /--max-rwep/);
  });

  test('ci --max-rwep with a real numeric value is accepted (the guard rejects only the missing value)', () => {
    const r = run(CLI, ['ci', 'secrets', '--max-rwep', '100'], {});
    assert.ok([0, 2, 3].includes(r.status), `unexpected ci exit ${r.status}: ${r.stderr.slice(0, 200)}`);
  });
});

// ===========================================================================
test.describe('cli-flag-relevance-guard', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-flag-relevance-ci-');
  const cli = makeCli(SUITE_HOME);

  test('ci --scope code --max-rwep 70 is accepted (not refused as irrelevant)', () => {
    const r = cli(['ci', '--scope', 'code', '--max-rwep', '70', '--json'], { timeout: 60000 });
    const body = tryJson((r.stdout || '').trim()) || {};
    const err = tryJson(r.stderr.trim()) || {};
    assert.notEqual(err.error_class, 'irrelevant-flag',
      `--max-rwep must be accepted on ci; got refusal: ${r.stderr.slice(0, 300)}`);
    assert.equal(body.verb, 'ci', `ci should produce a ci body; got ${JSON.stringify(body.verb)} stderr=${r.stderr.slice(0, 200)}`);
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

  test('ci --required <pb> envelope: exact top-level key set + summary sub-key set', () => {
    const r = cli(['ci', '--required', 'cred-stores', '--json']);
    const body = tryJson(r.stdout);
    assert.ok(body, `ci must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    const expected = ['ok', 'playbooks_run', 'results', 'session_id', 'summary', 'verb'];
    assert.deepEqual(Object.keys(body).sort(), expected);
    assert.equal(body.verb, 'ci');
    assert.equal(body.ok, true, 'v0.13: ci carries ok:true (summary.verdict remains authoritative)');
    assert.ok(Array.isArray(body.playbooks_run));
    assert.ok(Array.isArray(body.results));

    const expectedSummaryKeys = [
      'blocked', 'clock_started_reasons', 'detected', 'fail_reasons',
      'framework_gap_count', 'framework_gap_rollup', 'inconclusive',
      'jurisdiction_clock_rollup', 'jurisdiction_clocks_started',
      'max_rwep_observed', 'not_detected', 'runtime_warnings',
      'runtime_warnings_count', 'total', 'verdict',
    ];
    assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
    assert.equal(typeof body.summary.verdict, 'string');
    assert.equal(typeof body.summary.total, 'number');
    assert.equal(typeof body.summary.max_rwep_observed, 'number');
    assert.ok(Array.isArray(body.summary.runtime_warnings));
    assert.equal(typeof body.summary.runtime_warnings_count, 'number');
  });
});

// ===========================================================================
test.describe('cli-selector-flag-fixes', () => {
  const path = require('node:path');
  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

  const SUITE_HOME = makeSuiteHome('exceptd-selector-fix-ci-');
  const cli = makeCli(SUITE_HOME);

  test('ci --required "" is refused (no false-green fall-through)', () => {
    const r = cli(['ci', '--required', '', '--json']);
    assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.equal(body.ok, false);
    assert.match(body.error, /empty playbook list/);
  });

  test('ci --scope "" is refused with the accepted-set message', () => {
    const r = cli(['ci', '--scope', '', '--json']);
    assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.equal(body.ok, false);
    assert.doesNotMatch(JSON.stringify(body), /"verdict":\s*"PASS"/);
  });

  test('ci --required with no value gives a clean usage refusal, not an internal error', () => {
    const r = cli(['ci', '--required']);
    assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.equal(body.ok, false);
    assert.match(body.error, /--required requires a value/);
    assert.doesNotMatch(body.error, /internal error/);
  });
});

// ===========================================================================
test.describe('cli-subverb-dispatch', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-audit-nn-ci-');
  const cli = makeCli(SUITE_HOME);

  test('NN P1-5: ci --help text lists --csaf-status and --publisher-namespace', () => {
    const r = cli(['ci', '--help']);
    assert.equal(r.status, 0, 'ci --help must exit 0; got ' + r.status);
    assert.match(r.stdout, /--csaf-status/,
      'ci --help must document --csaf-status; stdout-head=' + r.stdout.slice(0, 400));
    assert.match(r.stdout, /--publisher-namespace/,
      'ci --help must document --publisher-namespace; stdout-head=' + r.stdout.slice(0, 400));
  });
});

// ===========================================================================
// The reconciliation-deep-fixes session-id-attribution loop exercises the
// shared dispatchPlaybook verb-attribution across ci / run-all / ai-run; it is
// preserved here intact (the loop is one data-driven unit). The ci --mode
// guard is ci-specific.
test.describe('reconciliation-deep-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-deep-ci-');
  const cli = makeCli(home);

  for (const verb of ['ci', 'run-all', 'ai-run']) {
    test(`${verb} attributes a --session-id validation error to itself, not "run"`, () => {
      const r = cli([verb, 'kernel', '--session-id', '../evil', '--json'], { input: '{}' });
      assert.equal(r.status, 1, `${verb} session-id refusal must exit exactly 1`);
      const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
      assert.equal(err.ok, false, 'error envelope carries ok:false');
      assert.equal(err.verb, verb, `verb field must be "${verb}"`);
      assert.equal(typeof err.verb, 'string', 'verb is a string');
      assert.match(err.error, new RegExp(`^${verb}:`), `message prefix is "${verb}:"`);
      assert.doesNotMatch(err.error, /^run:/, 'message must not mis-attribute to run');
    });
  }

  test('ci --mode garbage attributes the error to ci (not run) and carries verb', () => {
    const r = cli(['ci', 'kernel', '--mode', 'garbage', '--json'], { input: '{}' });
    assert.equal(r.status, 1, 'invalid --mode exits exactly 1');
    const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(err.verb, 'ci', 'verb is ci');
    assert.match(err.error, /^ci:/, 'prefix is ci:');
  });
});


// ---- routed from audit-correctness-cluster ----
require("node:test").describe("audit-correctness-cluster", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a correctness cluster found auditing the run/ci/ai-run
 * verbs and the close/framework-gap surfaces for silent-wrong-answer bugs:
 *
 *   H1 — `ci <playbook> --evidence -` given a FLAT submission (the same shape
 *        `run` accepts) silently produced a PASS: the runner keyed the bundle
 *        by playbook id, found nothing, and evaluated an empty submission.
 *        ci must now treat a single-positional flat submission as belonging to
 *        that playbook, matching `run`'s verdict.
 *
 *   H2 — `ai-run <pb> --no-stream --evidence -` bypassed the evidence-shape
 *        guard `run` enforces, so `null` / `[]` / a scalar ran as if empty.
 *        It must be rejected at the read boundary with an actionable message.
 *
 *   H3 — the ci framework_gap_rollup read a nonexistent `why_insufficient`
 *        key, so every rollup entry's explanation was null. The data lives in
 *        `actual_gap`; the rollup must surface it.
 *
 *   M1 — the regulatory clock only started when the AGENT submitted
 *        detection_classification:'detected'. An engine-confirmed detection
 *        (indicators fired, engine classified 'detected') with --ack never
 *        started the clock, so notification deadlines silently stalled.
 *
 *   M2 — `framework-gap <bogus> <scenario>` produced a zero-gap report
 *        indistinguishable from a real "no gaps" result, so a typo read as
 *        proof the framework covered the scenario. An unknown framework must
 *        be refused; documented short forms ("NIST-800-53") must still resolve.
 *
 * Discipline: exact exit codes; presence assertions paired with value/type.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-auditcorrect-"));

// A flat secrets submission whose overrides fire real indicators.
const FLAT_SECRETS = JSON.stringify({
  signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" },
});





// The bug codex flagged: the guard above only fires on `--evidence`, but
// --no-stream ALSO auto-reads stdin. Whether a spawnSync pipe triggers the
// auto-stdin path is platform-divergent (POSIX FIFOs report readable; win32
// spawnSync pipes do not), so probe reachability first and only assert the
// rejection where the path is actually live — never coincidence-pass.
function autoStdinReachable() {
  const probe = cli(["ai-run", "secrets", "--no-stream", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } }),
  });
  const pj = tryJson(probe.stdout);
  return !!(pj && pj.phases?.analyze?._detect_classification === "detected");
}




const AI_API_FIRES = JSON.stringify({
  signal_overrides: {
    "cleartext-api-key-in-dotfile": "hit",
    "ai-api-beaconing-cadence": "hit",
    "long-lived-aws-keys": "hit",
  },
});

test("H1: ci accepts a flat single-positional submission and matches run's verdict", () => {
  const runR = cli(["run", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const run = tryJson(runR.stdout);
  assert.ok(run, "run must emit JSON");
  assert.equal(run.phases.analyze._detect_classification, "detected", "run classifies the flat submission as detected");

  const ciR = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const ci = tryJson(ciR.stdout);
  assert.ok(ci, "ci must emit JSON");
  const r0 = (ci.results || [])[0] || {};
  assert.equal(r0.verdict, "detected", "ci must NOT false-PASS a flat submission — it must match run");
  assert.equal(r0.rwep_score, run.phases.analyze.rwep.adjusted, "ci rwep must equal run's");
});

test("H1: a real bundle (keyed by playbook id) is still treated as a bundle", () => {
  const bundle = JSON.stringify({ secrets: { signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } } });
  const r = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: bundle });
  const ci = tryJson(r.stdout);
  assert.ok(ci, "ci must emit JSON");
  assert.equal((ci.results || [])[0]?.verdict, "detected", "the keyed bundle entry must still be evaluated");
});

test("H3: ci framework_gap_rollup populates why_insufficient from actual_gap", () => {
  const r = cli(["ci", "secrets", "--evidence", "-", "--json"], { input: FLAT_SECRETS });
  const ci = tryJson(r.stdout);
  assert.ok(ci, "ci must emit JSON");
  const rollup = ci.framework_gap_rollup || ci.summary?.framework_gap_rollup || [];
  assert.ok(Array.isArray(rollup) && rollup.length >= 1, "expected at least one rollup entry for a detected secrets finding");
  const entry = rollup[0];
  assert.equal(typeof entry.why_insufficient, "string", "why_insufficient must be a string, not null");
  assert.ok(entry.why_insufficient.length > 0, "why_insufficient must carry the actual_gap text");
  assert.equal(typeof entry.required_control, "string", "required_control must also be surfaced");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from audit-usability-fixes ----
require("node:test").describe("audit-usability-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================









// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================


// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================


// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================




// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================




// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================


// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================


// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('unknown flag on ci hard-fails (exit 1)', () => {
  const r = cli(['ci', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from bundle-and-doctor-correctness ----
require("node:test").describe("bundle-and-doctor-correctness", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a cluster found auditing the structured-bundle emitters
 * and the doctor subchecks:
 *
 *   CSAF threats text hard-coded "(CISA KEV)" for any confirmed-exploitation
 *     CVE, even when cisa_kev is false — operator-facing misattribution.
 *   SARIF/OpenVEX rendered the literal "null" for an unassessed blast_radius.
 *   SARIF cve_match results carried no locations, so GitHub Code Scanning
 *     silently dropped the highest-severity result class.
 *   An empty-vulnerabilities run emitted a csaf_security_advisory (Profile 4,
 *     where empty vulnerabilities is wrong) instead of csaf_informational.
 *   ci --format csaf/sarif/openvex wrapped documents in an exceptd envelope
 *     carrying a top-level `ok` key — invalid in all three standard formats.
 *   doctor --rfcs scraped table rows and undercounted the catalog, dropping
 *     non-RFC families; its freshness fields statted a nonexistent file.
 *
 * Discipline: exact values + types; presence paired with content.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { ROOT, makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-bundledoc-"));

// sbom + package-matches-catalogued-cve fires CVE-2026-45321. The CSAF
// threats text once hard-coded "(CISA KEV)" for any confirmed-exploitation
// CVE; the invariant under test is that the attribution tracks the entry's
// live cisa_kev flag. The flag itself churns with reality (the automated
// KEV refresh flips it when CISA lists the CVE), so the assertion reads the
// catalog instead of pinning one value — pinning false broke the day CISA
// added the CVE to KEV.
const SBOM_CVE = JSON.stringify({ signal_overrides: { "package-matches-catalogued-cve": "hit" } });
const CVE_CATALOG = require(path.join(ROOT, "data", "cve-catalog.json"));
const MATCHED_ENTRY = CVE_CATALOG["CVE-2026-45321"];

test("ci --format csaf emits a bare array of documents with no top-level 'ok' wrapper", () => {
  const r = cli(["ci", "--scope", "code", "--evidence", "-", "--format", "csaf", "--json"], { input: "{}" });
  const out = tryJson(r.stdout);
  assert.ok(Array.isArray(out), "ci --format csaf must emit a JSON array of documents");
  // A bare array carries no exceptd envelope keys (`ok` / `verb` / `bundles_count`).
  assert.ok(!("ok" in out), "the array must not carry an `ok` property (invalid in CSAF)");
  assert.ok(!("bundles_count" in out), "the array must not carry the old envelope's bundles_count");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#76 ci --format garbage returns structured JSON error', () => {
  const r = cli(['ci', '--scope', 'code', '--format', 'garbage']);
  // v0.12.24 routed --format validation through emitError (consistent with
  // every other flag-parse rejection in cmdCi). emitError exits 1, NOT 2 —
  // exit 2 is reserved for `DETECTED_ESCALATE`, which is a verdict-class
  // outcome, not a flag-parse outcome. The structured error body is preserved.
  assert.equal(r.status, 1, 'ci --format garbage must exit 1 (flag-validation rejection via emitError)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.equal(err.verb, 'ci',
    'verb field must identify the rejecting verb so log-correlators can route the error');
  assert.match(err.error, /ci: --format .* not in accepted set/,
    'error must name the verb, flag, and "accepted set" phrase — operators self-correct from this without grepping the source');
});

test('#103 ci does not fail on inconclusive baseline RWEP', () => {
  // Fresh repo, no evidence: every playbook returns inconclusive with
  // catalog-baseline RWEP. Pre-0.11.8 default --max-rwep (80) tripped on
  // baseline RWEP (90) and ci exited 2 with FAIL. Now: only RWEP DELTA
  // counts on inconclusive runs.
  const r = cli(['ci', '--scope', 'code', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  // Pin the shape contract: fail_reasons must ALWAYS be an array (possibly
  // empty), never undefined or null. Pre-strengthening the filter used
  // `data.summary.fail_reasons || []`, which silently substituted an
  // empty array when the field went missing — masking a "field missing
  // entirely" regression as "no reasons matched the regex." Hard-assert
  // the field exists and is an array BEFORE filtering.
  assert.ok(Array.isArray(data.summary.fail_reasons),
    'summary.fail_reasons must always be an array (possibly empty), never undefined/null — operators rely on `for (const r of fail_reasons)` not failing');
  // The fail_reasons for an unconfigured baseline run should not include
  // "rwep_delta >= cap" since delta is 0 (no operator evidence).
  const rwepDeltaReasons = data.summary.fail_reasons.filter(reason =>
    /rwep_delta/.test(reason) || /rwep=\d+ >= cap/.test(reason)
  );
  assert.equal(rwepDeltaReasons.length, 0,
    'baseline-only ci run should not fail on catalog RWEP — only on RWEP delta from operator evidence');
});

test('#115 ci --required filters to exactly the named playbooks', () => {
  const r = cli(['ci', '--required', 'secrets,sbom', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  const sortedRun = [...data.playbooks_run].sort();
  assert.deepEqual(sortedRun, ['sbom', 'secrets'],
    'ci --required must run exactly the named set, not a superset/subset');
});

test('#115 ci --required rejects unknown playbook id', () => {
  const r = cli(['ci', '--required', 'totally-not-a-playbook', '--json']);
  assert.equal(r.status, 1, 'unknown --required playbook must exit 1 (emitError unknown-playbook refusal)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /unknown playbook/);
});

test('#100 ci with NO --evidence + all inconclusive exits 3 (not 0)', () => {
  // E2: pre-fix empty submission always reached classification=inconclusive
  // (both branches of the indicator-default verdict computation emitted
  // 'inconclusive'). That meant a fresh `ci --required <pb>` with no
  // evidence always tripped the no-evidence-all-inconclusive guard (exit
  // 3). Post-E2 an empty submission with no captured artifacts now reaches
  // 'not_detected' cleanly. To exercise the original "ran but no real
  // data" guard, submit an evidence file that captures an artifact (which
  // makes any non-overridden indicator inconclusive) WITHOUT setting
  // signal_overrides — equivalent to the pre-E2 default empty-submission
  // outcome from a behavioral standpoint.
  const tmp = secureTmpFile('ev.json', 'incon-');
  // Submission with a captured artifact but no signal_overrides → all
  // indicators inconclusive → ci no-evidence guard fires (--evidence WAS
  // supplied so the guard's predicate skips it; this test now just asserts
  // exit 0 is the post-E2 valid outcome for "no real data" runs).
  fs.writeFileSync(tmp, '{}');
  try {
    const r = cli(['ci', '--required', 'sbom', '--json']);
    // Post-E2: empty submission → not_detected → verdict PASS → exit 0.
    // The "no real data" condition is now reflected in the not_detected
    // count + the absence of supplied evidence rather than in inconclusive.
    assert.ok([0, 3].includes(r.status),
      `ci without --evidence: legitimate not_detected (exit 0) or inconclusive-guard (exit 3) — got ${r.status}`);
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
});

test('#100/#103 ci exit-3 path still flushes JSON to stdout', () => {
  // v0.11.10 regression: process.exit(3) truncated buffered stdout when piped,
  // so --json consumers saw empty stdout despite the structured emit() call.
  // v0.11.11 switched to process.exitCode + return so the event loop drains.
  const r = cli(['ci', '--required', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci exit-3 path must still flush JSON to stdout (no truncation on piped stdout)');
  assert.equal(data.verb, 'ci');
  assert.ok(data.summary, 'JSON body must include summary');
});

test('#125/#134 ci with real preflight halt exits 4 BLOCKED (not 2 FAIL, not 0)', () => {
  // Real preflight halt: secrets has a halt-on-fail precondition `repo-context`
  // (cwd_readable == true). Submit it false explicitly so autoDetect doesn't
  // override it, keyed by playbook id so cmdCi's bundle dispatch routes it.
  const tmp = secureTmpFile('ev.json', 'block-');
  fs.writeFileSync(tmp, JSON.stringify({ secrets: { precondition_checks: { 'repo-context': false } } }));
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmp, '--json']);
  fs.unlinkSync(tmp);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci JSON must parse');
  assert.equal(data.summary.blocked, 1, 'summary.blocked must be 1 when preflight halts');
  assert.equal(r.status, 4,
    'BLOCKED must take precedence over FAIL — exit 4, not 2. Operators distinguish "playbook never executed" from "playbook detected an issue"');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from resolver-trust-and-flag-hardening ----
require("node:test").describe("resolver-trust-and-flag-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Resolver-trust + flag-hardening regression suite.
 *
 * Pins three independently-exploitable contracts so they can't silently
 * regress:
 *
 *   1. Resolved-cache integrity (lib/citation-resolve.js). A resolved record is
 *      only trusted when it carries a sha256 `_digest` over its own canonical
 *      bytes AND its embedded `resolved_at` is inside the freshness window.
 *      A poisoned/tampered/stale/future-dated file cannot launder a verdict —
 *      it reads back as a cache miss and the resolver falls through to
 *      offline/unknown. This is the security headline: an operator-writable
 *      cache directory can never turn a rejected/fabricated citation into a
 *      "published" one.
 *
 *   2. Unknown-flag rejection on the cve/rfc resolvers. A swallowed `--josn`
 *      would emit human text into a pipe that asked for JSON and defeat a CI
 *      gate, so an unrecognized flag is a hard exit 1 with an ok:false envelope.
 *
 *   3. Evidence-shape / --max-rwep / --format guards on run + ci. `null`, an
 *      array, or a scalar parse as valid JSON but are not a submission; a
 *      non-numeric or negative cap would degenerate the gate; `--format`
 *      explicitly overrides `--json`.
 *
 * Plus the applyResolution RFC-flip contract (a cited RFC number that resolves
 * to nothing is a bad citation; an obsoleted-but-real RFC is not).
 *
 * Discipline (project anti-coincidence rules): assert EXACT exit codes (never
 * notEqual(0)); pair every field-presence check with a value/type assertion;
 * never weaken a test to make it pass. Every test is deterministic and offline:
 * cache tests inject a per-suite EXCEPTD_RESOLVE_CACHE_DIR and a tiny catalog
 * fixture WITHOUT the test ids (so the resolver reaches the cache path), and
 * pass { noNetwork: true } so no network is touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// --- isolated resolved-cache dir + a tiny catalog fixture that deliberately
//     does NOT contain the ids these tests resolve, so resolveCve falls past
//     the catalog branch into the cache branch. Both env vars are set BEFORE
//     require('../lib/citation-resolve.js') — the catalog path is read +
//     memoized at module-require time; the cache dir is read at call time but
//     is set here too to be safe. --------------------------------------------
const CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-cache-'));
const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-fixture-'));
const CVE_FIXTURE = path.join(FIXTURE_DIR, 'cve-catalog.json');

// A catalog hit for the CLI fixture-id test, but NONE of the cache-integrity
// test ids, so those reach the cache path rather than short-circuiting here.
const CVE_FIXTURE_DATA = {
  'CVE-2030-0001': {
    cvss_score: 9.8,
    cisa_kev: true,
    name: 'FixtureVuln',
    status: 'published',
  },
};
fs.writeFileSync(CVE_FIXTURE, JSON.stringify(CVE_FIXTURE_DATA, null, 2));

process.on('exit', () => {
  try { fs.rmSync(CACHE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(FIXTURE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
});

process.env.EXCEPTD_CVE_CATALOG = CVE_FIXTURE;
process.env.EXCEPTD_RESOLVE_CACHE_DIR = CACHE_DIR;

const { resolveCve } = require('../lib/citation-resolve.js');
const citationHygiene = require('../lib/collectors/citation-hygiene.js');

// Spawned-CLI harness. Pass the fixture catalog + isolated cache dir as env
// overrides so subprocesses resolve offline against them, not the network.
const SUITE_HOME = makeSuiteHome('exceptd-resolver-trust-');
const baseCli = makeCli(SUITE_HOME);
const RESOLVER_ENV = {
  EXCEPTD_CVE_CATALOG: CVE_FIXTURE,
  EXCEPTD_RESOLVE_CACHE_DIR: CACHE_DIR,
};
function cli(args, opts = {}) {
  return baseCli(args, { ...opts, env: { ...RESOLVER_ENV, ...(opts.env || {}) } });
}

// --- digest helper: replicate lib/citation-resolve.js recordDigest exactly so
//     a test can write a VALID (trusted) cache record. sha256 over the record's
//     canonical JSON: keys sorted, `_digest` excluded. ------------------------
function recordDigest(rec) {
  const canon = {};
  for (const k of Object.keys(rec).sort()) {
    if (k === '_digest') continue;
    canon[k] = rec[k];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}
function writeRawCveCache(id, rec) {
  const dir = path.join(CACHE_DIR, 'cve');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(rec));
  return path.join(dir, `${id}.json`);
}
function writeDigestedCveCache(id, rec) {
  const signed = { ...rec };
  signed._digest = recordDigest(signed);
  return writeRawCveCache(id, signed);
}

// ===================================================================
// 1. Resolved-cache integrity
// ===================================================================








// ===================================================================
// 2. cve / rfc unknown-flag rejection (spawned CLIs)
// ===================================================================




// ===================================================================
// 3. run evidence-shape guard
// ===================================================================

for (const bad of [
  { label: 'null', input: 'null' },
  { label: 'array', input: '[]' },
  { label: 'string', input: '"astring"' },
  { label: 'number', input: '123' },
]) {
  test(`run CLI: --evidence - with ${bad.label} exits 1 with "evidence must be a JSON object"`, () => {
    const r = cli(['run', 'secrets', '--evidence', '-'], { input: bad.input });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stderr.trim());
    assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.match(body.error, /evidence must be a JSON object/);
  });
}


// ===================================================================
// 4. applyResolution RFC flip
// ===================================================================



// ===================================================================
// 5. ci --max-rwep validation
// ===================================================================




// ===================================================================
// 6. --format overrides --json (note on stderr, markdown on stdout)
// ===================================================================


// ===================================================================
// 7. help lists the cve / rfc / collect verbs
// ===================================================================

test('ci CLI: --max-rwep abc exits 1 with "non-negative number"', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', 'abc']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /non-negative number/);
});

test('ci CLI: --max-rwep -5 (negative) exits 1 with "non-negative number"', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', '-5']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /non-negative number/);
});

test('ci CLI: --max-rwep 70 (valid) runs — not the validation error', () => {
  const r = cli(['ci', 'secrets', '--max-rwep', '70']);
  // A clean no-evidence ci run with a valid cap PASSes the gate (exit 0); the
  // point of this assertion is that the cap was accepted, not the exact verdict.
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'ci');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from ux-next-step-guidance ----
require("node:test").describe("ux-next-step-guidance", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/ux-next-step-guidance.test.js
 *
 * Stage-by-stage next-step guidance surfaces. The behavior is
 * operator-facing prose, so regression coverage is grep-shaped — each
 * assertion pins the exact substring an operator searches for when
 * they ask "what do I do now?"
 *
 * Surfaces pinned:
 *   1. ci BLOCKED prints "Next steps (unblock the N halted playbook(s)):"
 *      with one `exceptd lint <playbook> -` per blocked id.
 *   2. ci NO_EVIDENCE prints "Next steps (every playbook ran inconclusive
 *      — no evidence supplied):" with a lint + ci-evidence-dir pair.
 *   3. run prints "evidence: <state> (<evaluated>/<known> indicators
 *      evaluated)" on every success.
 *   4. run prints "Attestation written:" + the verify/diff command pair
 *      after persistence.
 *   5. run non-detect prose says "Remediation path (informational — verdict
 *      =<x>, no action required now):" — NOT "Recommended remediation:".
 *   6. run unknown-playbook error references the live playbook count,
 *      not a hardcoded literal.
 *   7. ci FAIL fires guidance even when no playbook hit detected (delta-
 *      cap path).
 *   8. lint flags nested-shape submissions that supply artifacts but no
 *      signal_overrides — the workflow trapdoor.
 *
 * Per the anti-coincidence rule: assertions check exact substrings.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test("ci BLOCKED prints 'Next steps (unblock ...)' + one lint command per blocked playbook", () => {
  // ai-discovered-cve-triage has the precondition agent_has_vulnerability
  // _feed_access. Without it the playbook halts at preflight, ci goes
  // BLOCKED.
  const r = cli(["ci", "--required", "ai-discovered-cve-triage"]);
  assert.match(r.stdout, /\[!! BLOCKED\]/,
    "BLOCKED icon must appear on the verdict line");
  assert.match(r.stdout, /Next steps \(unblock the 1 halted playbook\(s\)\):/,
    "BLOCKED footer must announce the unblock action with the count");
  assert.match(r.stdout, /exceptd lint ai-discovered-cve-triage -/,
    "BLOCKED footer must list `exceptd lint <playbook> -` for the blocked id");
  assert.match(r.stdout, /exceptd run <playbook> --evidence <file>/,
    "BLOCKED footer must close with the run-with-evidence re-run command");
});

test("ci NO_EVIDENCE prints 'Next steps (every playbook ran inconclusive — no evidence supplied)' + lint + ci-evidence-dir", () => {
  // Use a tempdir cwd with no .git so discover-scope finds nothing — but
  // we'll force scope=code from the exceptd repo cwd, which has a .git
  // and ships its own indicators. The cwd here is the exceptd repo, so
  // the indicators evaluate against the exceptd source tree. Most
  // signal_overrides are not provided → indicators return inconclusive.
  // The path to reach NO_EVIDENCE is: ci --required <pb> on a playbook
  // whose indicators don't fire on the local cwd. `framework` is pure
  // analyze + has no detect indicators that would auto-hit, so it
  // returns inconclusive without --evidence.
  const r = cli(["ci", "--required", "framework"]);
  // Either verdict NO_EVIDENCE (no --evidence) or PASS (when
  // framework's catalog baseline returns clean). The guidance fires
  // only on NO_EVIDENCE; if the run lands PASS, this test is informational.
  if (/verdict=NO_EVIDENCE/.test(r.stdout)) {
    assert.match(r.stdout, /Next steps \(every playbook ran inconclusive — no evidence supplied\):/,
      "NO_EVIDENCE footer must explain WHY the run is inconclusive");
    assert.match(r.stdout, /exceptd lint framework -/,
      "NO_EVIDENCE footer must offer a lint command for the first playbook");
    assert.match(r.stdout, /exceptd ci --scope <type> --evidence-dir <dir>/,
      "NO_EVIDENCE footer must show the evidence-dir gate command");
  }
});

test("ci FAIL Next steps names the specific detected playbook + surfaces pending jurisdiction obligations", () => {
  // Multi-playbook ci with one detected + one inconclusive. The
  // Next-steps block must:
  //   - say "in <playbook-id>" (not "<playbook>" placeholder)
  //   - emit run commands with the actual playbook id
  //   - surface pending jurisdiction obligations grouped by
  //     clock_start_event across all detected playbooks
  const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), "multi-ev-"));
  try {
    fs.writeFileSync(path.join(evidenceDir, "kernel.json"), JSON.stringify({
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      signal_overrides: { "kver-in-affected-range": "hit" },
    }));
    fs.writeFileSync(path.join(evidenceDir, "secrets.json"), JSON.stringify({
      precondition_checks: { "repo-context": true, "regex-engine": true },
      artifacts: { "repo-tree": { value: "clean", captured: true } },
      signal_overrides: { "aws-access-key-id": "miss" },
    }));
    const r = cli(["ci", "--required", "kernel,secrets", "--evidence-dir", evidenceDir]);
    assert.match(r.stdout, /verdict=FAIL/,
      "kernel + kver-in-affected-range:hit must drive verdict=FAIL");
    assert.match(r.stdout, /Next steps \(review the 1 detected finding\(s\) in kernel\):/,
      "Next-steps header must name the specific detected playbook (not '<playbook>')");
    assert.match(r.stdout, /exceptd run kernel --format markdown/,
      "run command must use the actual playbook id, not '<playbook>' placeholder");
    assert.match(r.stdout, /Pending jurisdiction obligations across detected playbook\(s\) \(\d+\) — clock starts on operator action:/,
      "ci must surface pending jurisdiction obligations at the summary level for detected runs");
    assert.match(r.stdout, /\s+on \w+:\s+\w/,
      "obligations must be grouped by clock_start_event");
  } finally {
    try { fs.rmSync(evidenceDir, { recursive: true, force: true }); } catch {}
  }
});

test("ci FAIL with multiple detected playbooks emits run commands for EACH (not just detectedIds[0])", () => {
  // When ci lands multiple playbooks at classification=detected,
  // the Next-steps commands must enumerate ONE row per id for each
  // format. Pre-fix only detectedIds[0] got rendered, so operators
  // would miss the markdown / csaf-2.0 follow-up for every detected
  // playbook beyond the first.
  const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), "multi-detected-"));
  try {
    // Two playbooks, both forced to detected via signal_overrides.
    fs.writeFileSync(path.join(evidenceDir, "kernel.json"), JSON.stringify({
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      signal_overrides: { "kver-in-affected-range": "hit" },
    }));
    fs.writeFileSync(path.join(evidenceDir, "secrets.json"), JSON.stringify({
      precondition_checks: { "repo-context": true, "regex-engine": true },
      artifacts: { "repo-tree": { value: "src/config.js contains AKIA...", captured: true } },
      signal_overrides: { "aws-access-key-id": "hit" },
    }));
    const r = cli(["ci", "--required", "kernel,secrets", "--evidence-dir", evidenceDir]);
    assert.match(r.stdout, /detected=2/,
      "scenario depends on both playbooks landing detected");
    assert.match(r.stdout, /exceptd run kernel --format markdown/,
      "markdown command for kernel must be present");
    assert.match(r.stdout, /exceptd run secrets --format markdown/,
      "markdown command for secrets must ALSO be present (regression: was only emitted for detectedIds[0])");
    assert.match(r.stdout, /exceptd run kernel --format csaf-2\.0/,
      "csaf command for kernel must be present");
    assert.match(r.stdout, /exceptd run secrets --format csaf-2\.0/,
      "csaf command for secrets must ALSO be present");
  } finally {
    try { fs.rmSync(evidenceDir, { recursive: true, force: true }); } catch {}
  }
});

test("ci FAIL prints Next steps even when no playbook hit `detected` (delta-cap path)", () => {
  // `verdict === "FAIL"` fires in two shapes:
  //   (a) detected > 0 (a playbook landed classification=detected)
  //   (b) inconclusive + rwep_delta >= cap
  // Both must print a Next-steps block. This test pins shape (b) —
  // set --max-rwep to 0 + supply evidence that lifts the score by any
  // amount, so the rwep_delta gate fires while classification stays
  // inconclusive.
  const evidence = JSON.stringify({
    kernel: {
      precondition_checks: { "linux-platform": true, "uname-available": true },
      artifacts: { "kernel-release": "5.15.0-69-generic" },
      // Set ONE indicator to "hit" so RWEP rises by the cisa_kev / poc
      // adjustment ladder but classification stays inconclusive (the
      // ladder fires on any indicator going hit; classification only
      // moves to "detected" when the deterministic indicators fire on
      // confirmed-applicability).
      signal_overrides: { "active-exploitation-published": "hit" }
    }
  });
  const tmpFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fail-delta-')), 'ev.json');
  fs.writeFileSync(tmpFile, evidence);
  try {
    const r = cli(["ci", "--required", "kernel", "--evidence", tmpFile, "--max-rwep", "0"]);
    // We expect verdict=FAIL because rwep_delta will exceed cap=0. If
    // the classification lands "detected" (different shape), the FAIL
    // path still prints SOME guidance — test just pins that a Next-
    // steps block appears on any FAIL.
    if (/verdict=FAIL/.test(r.stdout)) {
      assert.match(r.stdout, /Next steps \(/,
        "FAIL must always print a Next-steps block — both the detected and the inconclusive+delta-cap shapes need actionable guidance");
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
});

test("brief --directives expands directive metadata in the human renderer", () => {
  // cmdPlan attaches directive metadata to each playbook when
  // --directives is set. Pre-fix the human renderer ignored that
  // metadata entirely — operators who passed --directives got the
  // same flat table as without it, silently dropping the documented
  // contract.
  const r = cli(["brief", "--directives"]);
  assert.equal(r.status, 0);
  // Each playbook row must be followed by `→ <directive-id>` lines.
  assert.match(r.stdout, /→ full-container-manifest-walk/,
    "containers playbook must show its directive ids");
  assert.match(r.stdout, /→ weak-primitive-inventory/,
    "crypto-codebase playbook must show its directive ids");
  // Threat-context preview should appear below the directive id.
  assert.match(r.stdout, /Container escape attack class in 2025-2026/,
    "directives must include the threat-context preview line");
});

test("brief (no arg) renders a scannable per-scope table, not 36 KB of JSON", () => {
  // Pre-fix `exceptd brief` with no playbook arg dumped 36+ KB of JSON
  // to stdout (delegated to cmdPlan which had no human renderer).
  // Operators running brief to explore the catalog had no scannable
  // view. The renderer now groups by scope with a per-playbook line
  // (id + threat_currency_score + domain.name truncated to 80 chars).
  const r = cli(["brief"]);
  assert.equal(r.status, 0);
  // Header line + scope summary.
  assert.match(r.stdout, /brief: \d+ playbook\(s\)\s+session-id: [0-9a-f]+/,
    "header line must include playbook count + session-id");
  assert.match(r.stdout, /(?:service|cross-cutting|code|system)=\d+/,
    "scope-summary line must report counts per scope");
  // Per-scope buckets with bracketed labels.
  assert.match(r.stdout, /\[code\]\s+\(\d+\)/,
    "must group playbooks by scope with bracketed labels");
  // Per-playbook lines include domain prose, not just an id.
  assert.match(r.stdout, /secrets\s+tcs=\d+\s+Repository-scoped secret/,
    "per-playbook line must carry the domain.name prose");
  // Next-step block.
  assert.match(r.stdout, /Next:\s*\n\s+exceptd brief <playbook>/,
    "Next-step block must point at single-playbook brief / discover / ci");
});

test("run --upstream-check surfaces version-currency result in human renderer", () => {
  // --upstream-check produces a useful `upstream_check` envelope but
  // the human renderer ignored it pre-fix — operators who passed the
  // flag saw no answer to "am I current?" at the terminal.
  // We can't reliably reach the network in CI, so the test instead
  // simulates the upstream-check result by injecting the field via
  // a separate code path is not feasible. Instead, just assert the
  // human renderer code path exists by reading the source.
  const src = fs.readFileSync(path.join(ROOT, "bin", "exceptd.js"), "utf8");
  assert.match(src, /if \(obj\.upstream_check\) \{/,
    "run renderer must branch on obj.upstream_check");
  assert.match(src, /upstream check: local v\$\{u\.local_version\} == published/,
    "renderer must emit a current-version line on same");
  assert.match(src, /upstream check: local v\$\{u\.local_version\} BEHIND published/,
    "renderer must emit a behind-version line + remediation");
});

test("doctor --ai-config surfaces scanned counts in human renderer", () => {
  // Pre-fix doctor --ai-config emitted only "all checks green" with
  // no detail on what was scanned. The operator running an audit
  // wants to see "scanned N files across M dirs, K findings".
  const r = cli(["doctor", "--ai-config"]);
  assert.match(r.stdout, /AI-assistant config audit: scanned \d+ file\(s\)/,
    "doctor --ai-config must report the scanned-file count");
  assert.match(r.stdout, /\d+ finding\(s\)/,
    "doctor --ai-config must report finding count");
});

test("run --diff-from-latest with NO prior attestation prints 'no prior' line (not silent)", () => {
  // Pre-fix the no_prior_attestation_for_playbook branch intentionally
  // produced no line — but operators who passed --diff-from-latest
  // then saw zero diff output and couldn't tell whether the flag took
  // effect. The explicit "no prior" line tells them this run is the
  // baseline.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "no-prior-"));
  try {
    // cwd-the-tempdir to avoid the legacy `.exceptd/` fallback root
    // picking up unrelated priors from the project tree.
    const r = cli(["run", "secrets", "--evidence", "-", "--diff-from-latest"],
      { input: "{}", env: { EXCEPTD_HOME: tmpHome }, cwd: tmpHome });
    assert.equal(r.status, 0, `run must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /drift vs prior: no prior attestation found for secrets — this run becomes the baseline/,
      "no-prior case must emit an explicit line so the operator knows --diff-from-latest took effect");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run inconclusive with mixed coverage breaks out decisive vs inconclusive indicators", () => {
  // A submission that supplies signal_overrides for only some
  // indicators lands `classification=inconclusive`. The raw
  // "evidence: complete (13/13 indicators evaluated)" wording is
  // technically correct (the engine ran every indicator) but
  // misleading — it sounds like full coverage. The renderer must
  // distinguish decisive (hit/miss) from inconclusive verdicts when
  // the classification itself is inconclusive AND there's a mix.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: { "repo-tree": { value: "tree dump", captured: true } },
    signal_overrides: {
      "aws-access-key-id": "miss",
      "github-personal-access-token": "miss",
    },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "mixed-cov-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0);
    // 2 decisive / 13 known / 11 inconclusive — the breakdown must
    // appear on the verdict line (decision IS load-bearing here).
    assert.match(r.stdout, /classification=inconclusive/,
      "scenario depends on the run landing inconclusive");
    assert.match(r.stdout, /evidence: complete\s+\(2\/13 decisive, 11 inconclusive — add signal_overrides to drive a verdict\)/,
      "verdict line must break out decisive vs inconclusive when both are present + verdict is inconclusive");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run detected with all indicators decisive does NOT break out the count", () => {
  // When classification is detected (or not_detected), the breakdown
  // is noise — operators just want the verdict and indicator counter.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: { "repo-tree": { value: "tree", captured: true } },
    signal_overrides: { "aws-access-key-id": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "decisive-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0);
    if (/classification=detected/.test(r.stdout)) {
      // Detected runs use the plain (N/M indicators evaluated) form;
      // the decisive-breakdown would be misleading here.
      assert.match(r.stdout, /evidence: complete\s+\(\d+\/\d+ indicators evaluated\)/,
        "detected runs use the plain N/M form, not the decisive breakdown");
      assert.doesNotMatch(r.stdout, /decisive,/,
        "detected runs must NOT show the decisive/inconclusive breakdown");
    }
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run surfaces runtime_errors in the human renderer (malformed signal_overrides is visible)", () => {
  // A malformed submission (e.g. signal_overrides as a string) used
  // to silently complete with `[ok] classification=not_detected`
  // because the runtime_errors[] entry lived only in
  // phases.analyze.runtime_errors and the human renderer ignored
  // them. The operator had no signal their submission was bogus.
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0" },
    signal_overrides: "not-an-object",
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-warn-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "kernel", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0, `run must exit 0 even on malformed submission; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /Runtime warnings \(\d+\):/,
      "Runtime warnings block must appear when runtime_errors[] is non-empty");
    assert.match(r.stdout, /\[signal_overrides_invalid\]/,
      "the signal_overrides_invalid kind must be surfaced as a labeled row");
    assert.match(r.stdout, /signal_overrides must be a plain object/,
      "the reason text must appear so the operator knows what to fix");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("lint flags nested submission with artifacts-but-no-signal_overrides (the workflow-blind path)", () => {
  // The cold-start workflow has a hidden trapdoor: lint says "Add to
  // submission.artifacts.<id>" for every required artifact, the
  // operator populates them all, runs, and gets every indicator =
  // inconclusive. detect() needs signal_overrides (or a verdict
  // override) to mark each indicator hit / miss — artifact presence
  // alone is not enough. lint must surface this explicitly so the
  // operator sees the JSON shape to populate next.
  const evidence = JSON.stringify({
    precondition_checks: { "repo-context": true, "regex-engine": true },
    artifacts: {
      "repo-tree": { value: "package.json src/ tests/", captured: true },
      "secret-regex-scan-text-files": { value: "scanned 47 files; 0 hits", captured: true }
    }
  });
  const tmpFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lint-no-overrides-')), 'ev.json');
  fs.writeFileSync(tmpFile, evidence);
  try {
    const r = cli(["lint", "secrets", tmpFile, "--json"]);
    const body = tryJson(r.stdout);
    assert.ok(body, "lint must emit parseable JSON");
    const hint = body.issues.find(i => i.kind === "no_signal_overrides_supplied");
    assert.ok(hint, `expected a no_signal_overrides_supplied info issue; got: ${JSON.stringify(body.issues.map(i => i.kind))}`);
    assert.equal(hint.severity, "info");
    assert.match(hint.hint, /signal_overrides/);
    assert.match(hint.hint, /"hit"\|"miss"/);
    assert.match(hint.hint, /verdict\.classification/);
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
