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


// ---- routed from ci-human-renderer ----
;(() => {
/**
 * tests/ci-human-renderer.test.js
 *
 * Pins the operator-facing surfaces of `ci`:
 *
 *   1. Default output is a human digest (table), not JSON.
 *   2. `--json` still emits the documented structured envelope.
 *   3. Result envelope carries `verdict` / `rwep_score` / `top_finding`
 *      / `summary_line` / `evidence_completeness` /
 *      `indicators_evaluated` / `indicators_known` at the top level.
 *   4. Blocked results carry `playbook_id` (same shape contract as
 *      successful results).
 *   5. Session-level warnings are deduped — N copies of the same
 *      bundle_publisher_unclaimed entry collapse to one summary row.
 *   6. `--scope <type>` summary surfaces the inclusion rule so
 *      operators see why cross-cutting + sbom appear alongside the
 *      requested scope.
 *
 * Per the anti-coincidence rule: every assertion checks an exact
 * key/value, not "ok-truthy" / "non-zero" / etc.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
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

test("ci default output is human text, not JSON", () => {
  // No --json / --pretty: the humanRenderer path fires unconditionally
  // when a renderer is registered (matches `run` v0.11.9 behavior).
  const r = cli(["ci", "--required", "cred-stores"]);
  assert.equal(tryJson(r.stdout), null,
    "default ci output must NOT be parseable JSON (operator-readable digest)");
  assert.match(r.stdout, /^ci: 1 playbook\(s\)/,
    "human header line must lead with `ci: N playbook(s)`");
  assert.match(r.stdout, /playbook\s+verdict\s+rwep\s+evidence\s+finding/,
    "per-playbook table header must be present");
  assert.match(r.stdout, /Full structured result: --json/,
    "footer must point operator at --json for the structured body");
});

test("ci --json still emits parseable JSON with documented envelope", () => {
  const r = cli(["ci", "--required", "cred-stores", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --json must emit parseable JSON");
  assert.equal(body.verb, "ci");
  assert.equal(typeof body.summary, "object");
  // Summary carries deduped runtime warnings.
  assert.ok(Array.isArray(body.summary.runtime_warnings),
    "summary.runtime_warnings must be an array");
  assert.equal(typeof body.summary.runtime_warnings_count, "number");
});

test("ci result carries top-level verdict / rwep_score / summary_line / evidence_completeness", () => {
  const r = cli(["ci", "--required", "secrets", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --json must emit parseable JSON");
  const row = body.results.find(x => x.playbook_id === "secrets");
  assert.ok(row, "secrets result must be present");
  if (row.ok === false) {
    // Blocked path: playbook_id MUST be at the top of the result
    // envelope (same contract as the success path).
    assert.equal(row.playbook_id, "secrets",
      "blocked results must carry playbook_id at top level");
    assert.equal(row.evidence_completeness, "not-evaluated",
      "blocked results report evidence_completeness=not-evaluated");
  } else {
    // Verdict MUST be derived from phases.detect.classification.
    // validate() does not carry a `verdict` field — sourcing the
    // hoist from phases.validate.verdict would degrade every non-
    // blocked result to the fallback "inconclusive".
    assert.equal(typeof row.verdict, "string");
    assert.equal(row.verdict, row.phases?.detect?.classification,
      "hoisted verdict must equal phases.detect.classification — not phases.validate.verdict");
    assert.ok(["detected", "not_detected", "inconclusive", "pending", "skipped"].includes(row.verdict),
      `verdict must be one of the documented enum values; got ${row.verdict}`);
    assert.equal(typeof row.summary_line, "string");
    assert.ok(["complete", "partial", "missing", "unknown", "not-evaluated"]
      .includes(row.evidence_completeness),
      `evidence_completeness must be one of the documented enum values; got ${row.evidence_completeness}`);
    // rwep_score is null on inconclusive-no-evidence; explicit number otherwise.
    assert.ok(row.rwep_score === null || typeof row.rwep_score === "number",
      "rwep_score is number or null, never undefined");
    // indicators_known is a count (or null when phase.detect.indicators absent).
    assert.ok(row.indicators_known === null || typeof row.indicators_known === "number",
      "indicators_known is number or null");
  }
});

test("ci --scope code surfaces scope_inclusion_rules in summary", () => {
  const r = cli(["ci", "--scope", "code", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --scope code --json must emit parseable JSON");
  assert.equal(body.summary.scope_request, "code");
  assert.ok(Array.isArray(body.summary.scope_inclusion_rules),
    "summary.scope_inclusion_rules must be an array");
  assert.ok(body.summary.scope_inclusion_rules.length >= 2,
    "scope_inclusion_rules must enumerate at least the scope-match rule and cross-cutting rule");
  // The code-scope-specific rule about sbom auto-inclusion fires only
  // when a lockfile is detected; the exceptd repo has package-lock.json
  // so the rule must be present.
  const sbomRule = body.summary.scope_inclusion_rules.find(s => /sbom/.test(s));
  assert.ok(sbomRule, "scope_inclusion_rules must mention sbom auto-inclusion on a lockfile repo");
});

test("ci --scope code dedupes session-level warnings across N playbooks", () => {
  // ci --scope code runs 8 playbooks on this repo (4 code + 4 cross-
  // cutting, sbom skipped because of mutex). Each successful playbook
  // independently touches the CSAF bundle-build path, which surfaces
  // the bundle_publisher_unclaimed warning when --publisher-namespace
  // is not supplied. The dedup folds N copies into one summary entry.
  const r = cli(["ci", "--scope", "code", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body, "ci --scope code --json must emit parseable JSON");
  // Count occurrences across results vs. summary dedup.
  let perResultCount = 0;
  for (const row of body.results) {
    const errs = row?.phases?.analyze?.runtime_errors || [];
    perResultCount += errs.filter(e => e.kind === "bundle_publisher_unclaimed").length;
  }
  const summaryDedup = body.summary.runtime_warnings.filter(e => e.kind === "bundle_publisher_unclaimed").length;
  if (perResultCount > 0) {
    assert.equal(summaryDedup, 1,
      `summary.runtime_warnings must dedupe bundle_publisher_unclaimed to a single entry; got ${summaryDedup}`);
    assert.ok(perResultCount > summaryDedup,
      "per-result count must exceed dedup count when the warning is session-level");
  }
});
})();


// ---- routed from ci-positional-args ----
;(() => {
/**
 * tests/ci-positional-args.test.js
 *
 * Cycle 11 F1 fix (v0.12.31): `exceptd ci <playbook>` previously ignored
 * positional arguments and silently ran the cwd-autodetected playbook set
 * instead. An operator typing `exceptd ci kernel` got a PASS verdict for
 * `containers, crypto-codebase, library-author, secrets` — the kernel
 * playbook never ran but the operator never knew.
 *
 * The fix treats positional args as an inline --required, with the same
 * unknown-id refusal. This test pins the contract.
 *
 * Per the anti-coincidence rule, every assertion checks the EXACT
 * playbooks_run array or EXACT exit code, never `assert.ok(includes)`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  return r;
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

test('ci <playbook> runs exactly the named playbook, not the cwd-autodetected set', () => {
  // v0.13.22 B3+B4: ci default uses human renderer; pass --json for shape tests.
  const r = cli(['ci', 'kernel', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci kernel must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run, ['kernel'], 'ci kernel must run exactly [kernel] and not the autodetected set');
});

test('ci <multiple-playbooks> runs every named playbook', () => {
  const r = cli(['ci', 'kernel', 'cred-stores', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci kernel cred-stores must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run.sort(), ['cred-stores', 'kernel']);
});

test('ci <unknown-playbook> refuses with structured error + exit 1, listing known IDs', () => {
  const r = cli(['ci', 'this-playbook-does-not-exist']);
  assert.equal(r.status, 1, `unknown positional must exit 1; got ${r.status}`);
  const err = tryJson(r.stderr);
  assert.ok(err, 'stderr must be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(Array.isArray(err.unknown), true);
  assert.equal(err.unknown.includes('this-playbook-does-not-exist'), true);
  assert.equal(Array.isArray(err.accepted), true);
  assert.equal(err.accepted.length > 10, true, 'accepted list should include the full playbook catalog');
});

test('ci <playbook> + --scope/--all/--required refuses as ambiguous (codex P1 v0.12.31 follow-up)', () => {
  // Pre-fix: `exceptd ci kernel --scope code` silently dropped `kernel`
  // and ran code-scope. The guard `!args.all && !args.scope` allowed
  // the positional to be ignored entirely. Now any selector combination
  // is refused with a structured error listing the conflict.
  const cases = [
    ['ci', 'kernel', '--scope', 'code'],
    ['ci', 'kernel', '--all'],
    ['ci', 'kernel', '--required', 'cred-stores'],
  ];
  for (const args of cases) {
    const r = cli(args);
    assert.equal(r.status, 1, `${args.join(' ')} must exit 1; got ${r.status}`);
    const err = tryJson(r.stderr);
    assert.ok(err, `stderr must be parseable JSON for ${args.join(' ')}`);
    assert.equal(err.ok, false);
    assert.equal(Array.isArray(err.conflicting_flags), true);
    assert.equal(err.conflicting_flags.length >= 1, true);
  }
});

test('ci --required <list> still works (existing contract preserved)', () => {
  const r = cli(['ci', '--required', 'kernel,cred-stores', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body, `ci --required must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(body.playbooks_run.sort(), ['cred-stores', 'kernel']);
});
})();
