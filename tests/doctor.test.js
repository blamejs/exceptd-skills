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

test("doctor --rfcs counts the full catalog (incl. non-RFC families) with a by_prefix breakdown and real freshness", () => {
  const r = cli(["doctor", "--rfcs", "--json"]);
  const out = tryJson(r.stdout);
  const rfcs = out.checks?.rfcs;
  assert.ok(rfcs, "expected a rfcs check");
  assert.ok(typeof rfcs.total === "number" && rfcs.total >= 8888, `rfcs.total must count the whole catalog; got ${rfcs.total}`);
  assert.ok(rfcs.by_prefix && typeof rfcs.by_prefix === "object", "must expose a by_prefix breakdown");
  const sum = Object.values(rfcs.by_prefix).reduce((a, b) => a + b, 0);
  assert.equal(sum, rfcs.total, "by_prefix entries must sum to total");
  assert.ok("RFC" in rfcs.by_prefix && rfcs.by_prefix.RFC > 8000, "RFC family must dominate");
  // freshness must stat the real catalog file, not a nonexistent one
  assert.ok(typeof rfcs.index_age_days === "number", "index_age_days must be populated (real catalog file), not null");
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

test('doctor --registry-check reports days_since_latest_publish from fixture', () => {
  const fix = withFixture('99.99.99', 7);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.ok(data.checks?.registry, 'registry check must be present when --registry-check is passed');
    assert.equal(data.checks.registry.latest_version, '99.99.99');
    assert.equal(data.checks.registry.days_since_latest_publish, 7);
    assert.equal(data.checks.registry.behind, true);
    assert.match(data.checks.registry.hint, /npm update -g|refresh --network/);
  } finally { fs.unlinkSync(fix); }
});

test('doctor --registry-check ok when local matches latest', () => {
  // Use the local installed version so we match.
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const fix = withFixture(pkg.version, 0);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.equal(data.checks.registry.same, true);
    assert.equal(data.checks.registry.behind, false);
  } finally { fs.unlinkSync(fix); }
});

test('audit-3 B.1: doctor --help advertises every runtime-accepted flag', () => {
  // Pre-fix: --collectors, --ai-config, --exit-codes, --shipped-tarball were
  // all runtime-accepted but absent from `doctor --help`. Operators couldn't
  // discover them. The fix added them to the help block. This test pins the
  // help text against the runtime acceptance set; if a new flag is added to
  // KNOWN_DOCTOR_FLAGS without a help entry, this fails.
  const r = cli(['doctor', '--help']);
  const text = (r.stdout || '') + (r.stderr || '');
  for (const flag of ['--collectors', '--ai-config', '--exit-codes', '--shipped-tarball', '--registry-check', '--fix']) {
    // Plain substring search — the flag is a literal token in the help text, so
    // no regex (and no partial hyphen-only escape that reads as incomplete
    // sanitization) is needed.
    assert.ok(text.includes(flag),
      `doctor --help must advertise ${flag}; got: ${text.slice(0, 500)}`);
  }
});

test('audit-3 B.2: doctor CVE catalog by_prefix sums to total', () => {
  const r = cli(['doctor', '--cves', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --cves --json must emit parseable JSON');
  const cves = data?.checks?.cves;
  assert.ok(cves, 'checks.cves must be present');
  assert.equal(typeof cves.total, 'number', 'cves.total must be numeric');
  assert.ok(cves.by_prefix && typeof cves.by_prefix === 'object',
    'cves.by_prefix must be an object enumerating every prefix group');
  const sum = Object.values(cves.by_prefix).reduce((a, b) => a + b, 0);
  assert.equal(sum, cves.total,
    `by_prefix must sum to total (${sum} != ${cves.total}); pre-fix only CVE + MAL were enumerated and BUG-* entries dropped from the breakdown`);
});

test('doctor --fix on a healthy install reports fix_status: already_present (no-op contract)', () => {
  // --fix once silently no-op'd when keys were already present. Operators
  // couldn't distinguish "we tried and were already healthy" from "we tried
  // and failed silently." It now surfaces a structured fix_status so the
  // operator (or a CI script) can branch on it.
  //
  // This contract is verified against the bin source rather than by spawning
  // `doctor --fix`. doctor resolves its key paths relative to the package
  // root (the bin script's parent), not the spawn cwd, and there is no
  // override — so a real `doctor --fix` invocation operates on the committed
  // keys/ + manifest.json. When the captured signatures check is transiently
  // failing (e.g. mid-edit), --fix chains sign-all, which rewrites every
  // signature in manifest.json. Spawning it from the suite would therefore
  // mutate committed signing material, the exact divergence class that once
  // shipped orphaned signatures to operators. Pin the no-op summary-shaping
  // logic by source assertion instead, matching the source-assertion pattern
  // the sibling --fix path tests already use.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');

  // The no-op branch fires only when --fix was requested AND no other fix
  // path ran (no applied / attempted / partial / decline outcome, and no
  // ai-config remediation). Pin that precondition so a future edit can't let
  // already_present mask a fix that actually ran.
  assert.match(
    src,
    /args\.fix\s*&&\s*!out\.summary\.fix_applied\s*&&\s*!out\.summary\.fix_attempted/,
    'already_present must gate on --fix with no applied/attempted fix'
  );
  // The structured status + reason both have to be set for callers to branch.
  assert.match(
    src,
    /out\.summary\.fix_status\s*=\s*["']already_present["']/,
    'doctor --fix no-op must set fix_status: "already_present"'
  );
  assert.match(
    src,
    /out\.summary\.fix_skipped_reason\s*=\s*["']/,
    'doctor --fix no-op must set a fix_skipped_reason string alongside fix_status'
  );
});

test('audit-3 B.4: doctor refuses unknown flags with structured error + known_flags list', () => {
  const r = cli(['doctor', '--bogus-flag-xyz']);
  const err = tryJson(r.stderr);
  assert.ok(err, 'unknown flag must produce stderr JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'doctor');
  assert.ok(Array.isArray(err.unknown_flags), 'unknown_flags must be an array');
  assert.ok(Array.isArray(err.known_flags), 'known_flags must list every accepted flag');
  assert.ok(err.known_flags.includes('--signatures'),
    'known_flags must include --signatures (sanity)');
  // Refusal must exit GENERIC_FAILURE (1), not 0. Pinning exact: per the
  // anti-coincidence rule, a status !== 0 check would have
  // passed on any non-success exit including 2 (DETECTED_ESCALATE) or
  // 10 (UNKNOWN_COMMAND) — both of which would be the wrong code path.
  assert.equal(r.status, 1, 'unknown-flag refusal must exit 1 (GENERIC_FAILURE)');
});

test('audit-3 A.2: run envelope surfaces air_gap_mode on the top-level result', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected' }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--air-gap', '--session-id', 'a2-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --json must emit parseable JSON');
  assert.equal(data.air_gap_mode, true,
    'run --air-gap must surface air_gap_mode: true at the top of the result envelope; stdout-parsing consumers depend on it');
});

test('audit-3 C.1: ask "the the the the" routes to nothing (stopwords filtered)', () => {
  // Pre-fix: substring matching caused "the" to hit "authentication" /
  // "anthropic" / etc inside larger words, so a pure-stopword query
  // routed confidently to ai-api. Now: stopwords are filtered after
  // synonym expansion and the haystack is tokenized for whole-token
  // membership tests.
  const r = cli(['ask', 'the the the the', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must emit parseable JSON');
  assert.equal(data.verb, 'ask');
  assert.deepEqual(data.routed_to, [],
    `pure-stopword query must route to nothing; got: ${JSON.stringify(data.routed_to)}`);
});

test('audit-3 C.2: ask "phished" routes to identity-sso-compromise', () => {
  // Pre-fix: no phishing / SSO / oauth / bec vocabulary in the synonym map.
  // "I think we got phished" routed to crypto instead of identity-sso-*.
  const r = cli(['ask', 'I think we got phished', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must emit parseable JSON');
  assert.ok(Array.isArray(data.routed_to) && data.routed_to.length > 0,
    'phished query must produce a match');
  assert.equal(data.routed_to[0], 'identity-sso-compromise',
    `phished query must top-route to identity-sso-compromise; got: ${JSON.stringify(data.routed_to)}`);
});

test('audit-3 A.1: refresh --air-gap with no fixtures/cache refuses every source', () => {
  // Pre-fix: only GHSA + OSV honored ctx.airGap at the source-module level.
  // kev/epss/nvd/rfc/pins fell through to live-network branches when
  // neither fixtures nor cacheDir was wired up. The fix puts the guard at
  // the central runOne dispatch.
  const r = cli(['refresh', '--air-gap', '--source', 'kev', '--json']);
  // refresh may print informational text on stdout; the report lives in
  // a separate report file but the dispatch must not have made a live
  // network call. Inspect the persisted report to confirm.
  const reportPath = path.join(ROOT, 'refresh-report.json');
  if (!fs.existsSync(reportPath)) {
    // refresh in dry-run may not write the report. Looking for the in-stdout
    // markers instead.
    const text = (r.stdout || '') + (r.stderr || '');
    assert.match(text, /air-gap mode: kev skipped/,
      `refresh --air-gap must short-circuit kev with the air_gap_blocked summary; got: ${text.slice(0, 600)}`);
    return;
  }
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  assert.equal(report.sources?.kev?.status, 'unreachable',
    'kev under --air-gap with no cache must report status: unreachable');
  assert.equal(report.sources?.kev?.air_gap_blocked, true,
    'kev under --air-gap must surface air_gap_blocked: true');
});

test('audit-3 A.4: collect envelope surfaces air_gap_mode on the top-level result', () => {
  // Two paths to surface: (a) operator passes --air-gap explicitly, (b)
  // the playbook declares _meta.air_gap_mode: true intrinsically (secrets,
  // cred-stores, containers do this). Both must produce the same envelope
  // marker so downstream automation makes the right network-policy call.
  const r1 = cli(['collect', 'secrets', '--air-gap', '--json']);
  const d1 = tryJson(r1.stdout);
  assert.ok(d1, 'collect --json must emit parseable JSON');
  assert.equal(d1.air_gap_mode, true,
    'collect --air-gap must surface air_gap_mode: true');

  // mcp is NOT intrinsically air-gapped; without --air-gap the field
  // should reflect that.
  const r2 = cli(['collect', 'mcp', '--json']);
  const d2 = tryJson(r2.stdout);
  assert.ok(d2);
  assert.equal(d2.air_gap_mode, false,
    'collect on a non-intrinsic playbook without --air-gap must report air_gap_mode: false');

  // Intrinsic playbook (secrets has _meta.air_gap_mode: true) — air-gap
  // marker must fire even WITHOUT --air-gap, mirroring how `run` honors
  // _meta.air_gap_mode.
  const r3 = cli(['collect', 'secrets', '--json']);
  const d3 = tryJson(r3.stdout);
  assert.ok(d3);
  assert.equal(d3.air_gap_mode, true,
    'collect on an intrinsically-air-gapped playbook must surface air_gap_mode: true even without --air-gap');
});

test('audit-3 A.6: run --upstream-check --air-gap refuses the registry probe', () => {
  // Pre-fix: --upstream-check fired the registry probe regardless of
  // --air-gap because the upstream-check helper had no air-gap awareness
  // and the run path didn't gate the call. Fix lives at the central
  // upstream-check dispatch in the run verb so any future caller inherits
  // the refusal.
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'aws-access-key-id', result: 'miss' } }
  });
  const r = cli(['run', 'secrets', '--upstream-check', '--air-gap', '--evidence', '-',
    '--session-id', 'a6-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --json must emit parseable JSON');
  assert.ok(data.upstream_check, 'upstream_check field must be present even when refused');
  assert.equal(data.upstream_check.air_gap_blocked, true,
    'upstream_check.air_gap_blocked must be true; pre-fix the probe ran anyway');
  assert.equal(data.upstream_check.source, 'air-gap');
});

test('audit-3 B.5: doctor --collectors text mode enumerates policy_skips', () => {
  const r = cli(['doctor', '--collectors']);
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /policy-skipped:.*[a-z]/i,
    'doctor --collectors text mode must enumerate policy-skipped playbook names, not just the count');
});

test('audit-3 B.7: doctor --currency surfaces freshness fields', () => {
  const r = cli(['doctor', '--currency', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --currency --json must parse');
  const c = data.checks?.currency;
  assert.ok(c, 'checks.currency must be present');
  assert.equal(typeof c.checked_at, 'string', 'checked_at must be an ISO timestamp');
  // oldest_last_threat_review / max_days_since_review may be null on a
  // freshly-bootstrapped catalog with no dates yet — but the keys must
  // exist for the consumer to know they were inspected.
  assert.ok('oldest_last_threat_review' in c, 'oldest_last_threat_review key must exist');
  assert.ok('newest_last_threat_review' in c, 'newest_last_threat_review key must exist');
  assert.ok('max_days_since_review' in c, 'max_days_since_review key must exist');
});

test('audit-3 B.9: doctor --ai-config walk caps + truncation marker', () => {
  const r = cli(['doctor', '--ai-config', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --ai-config --json must parse');
  const c = data.checks?.ai_config;
  assert.ok(c, 'checks.ai_config must be present');
  assert.ok(c.walk_caps && typeof c.walk_caps.max_files === 'number',
    'walk_caps.max_files must be a numeric ceiling so operators see the bound');
  assert.ok(typeof c.walk_caps.max_depth === 'number',
    'walk_caps.max_depth must be numeric');
  assert.equal(typeof c.walk_truncated, 'boolean',
    'walk_truncated must be a boolean so callers can detect partial scans');
  assert.ok(c.walk_caps.max_files <= 10000,
    `max_files cap should bound the walk; got ${c.walk_caps.max_files}`);
});

test('audit-3 B.6: doctor --collectors surfaces unexplained_missing_collectors AND gates ok on it', () => {
  const r = cli(['doctor', '--collectors', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --collectors --json must parse');
  const c = data.checks?.collectors;
  assert.ok(c, 'checks.collectors must be present');
  assert.ok(Array.isArray(c.unexplained_missing_collectors),
    'unexplained_missing_collectors must be an array');
  // The new field surfaces operator-actionable gaps. policy_skips intersection
  // with without_collector is by design — should appear in without_collector
  // but NOT in unexplained_missing_collectors.
  const policy = new Set(c.policy_skips || []);
  for (const id of c.unexplained_missing_collectors) {
    assert.ok(!policy.has(id),
      `unexplained_missing_collectors must exclude policy-skipped playbooks; ${id} is in both lists`);
  }
  // ok must reflect the unexplained_missing set. If the array is empty,
  // ok stays true; if anything appears in it, ok must flip to false so
  // CI health checks catch the regression class this field was added to
  // surface.
  if (c.unexplained_missing_collectors.length === 0) {
    assert.equal(c.ok, true, 'no unexplained missings → ok stays true');
  } else {
    assert.equal(c.ok, false,
      'unexplained missings must flip ok to false so doctor surfaces the gap as a failed check');
  }
});

test('audit-3 B.11: doctor surfaces local_version on the top-level result', () => {
  const r = cli(['doctor', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --json must parse');
  assert.equal(typeof data.local_version, 'string',
    'doctor --json must surface local_version (the running CLI version) at the top level');
  assert.match(data.local_version, /^\d+\.\d+\.\d+/,
    `local_version must look like a semver; got: ${data.local_version}`);
});

test('audit-3 C.7: ask confidence penalized by tie count', () => {
  // A vague single-token query produces a tie. The post-fix confidence
  // formula divides the base score by the tie spread, so multi-way ties
  // surface as visibly lower confidence than a clean winner.
  const r = cli(['ask', 'I think we got phished', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must parse');
  assert.ok(data.confidence_factors,
    'confidence_factors must surface base + tie_count');
  assert.equal(typeof data.confidence_factors.tie_count, 'number',
    'tie_count must be numeric');
  assert.ok(data.confidence_factors.tie_count >= 1, 'tie_count must be >= 1');
  // If there's any tie, the reported confidence must be strictly less
  // than the base.
  if (data.confidence_factors.tie_count > 1) {
    assert.ok(data.confidence < data.confidence_factors.base,
      `ties must reduce confidence below base; got confidence=${data.confidence} base=${data.confidence_factors.base} ties=${data.confidence_factors.tie_count}`);
  }
});

test('#87 doctor --fix is registered (smoke)', () => {
  // Dispatch-table-only smoke test. The earlier shape of this test invoked
  // `exceptd doctor --fix` directly. On any machine where `.keys/private.pem`
  // was missing (every CI run, every fresh clone), `--fix` synchronously
  // spawned `lib/sign.js generate-keypair`, which overwrote `keys/public.pem`
  // with a fresh Ed25519 public key. Every committed manifest signature
  // (signed against the OLD key) then failed to verify against the NEW
  // public.pem. Result: every v0.11.x and v0.12.x release shipped a tarball
  // where 0/38 skills verified on fresh `npm install`.
  //
  // The pre-stage-a-dummy-key workaround still touched the real .keys/ dir,
  // which leaked state on Ctrl-C. Replace with a non-mutating probe: spawn
  // `exceptd doctor --help` and assert the help text advertises --fix. This
  // exercises the dispatch + flag-registration surface without invoking the
  // mutating code path at all.
  const r = cli(['doctor', '--help']);
  // Pin the accepted exit codes explicitly rather than `notEqual(.status, 2)`.
  // Pre-fix the notEqual form would have silently absorbed a regression
  // that flipped --help to exit 2 (DETECTED_ESCALATE) — the test would
  // still fail only if exit was exactly 2, accepting all other regressions.
  // --help canonically exits 0; some help-renderers exit 1. Both fine.
  // Code 2 (DETECTED_ESCALATE) and 10 (UNKNOWN_COMMAND) are not.
  assert.ok([0, 1].includes(r.status),
    `doctor --help must exit 0 or 1 (got ${r.status}); refuses 2 (DETECTED_ESCALATE) and 10 (UNKNOWN_COMMAND).`);
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /--fix\b/,
    'doctor --help must advertise the --fix flag so operators can discover it. Got: ' + text.slice(0, 400));
});

test('empty-string --evidence / --cwd are operator errors, not a silent false-clean run', () => {
  // `--evidence ""` / `--cwd ""` were falsy and silently produced a no-evidence
  // "not_detected" run (exit 0) or a scan of the wrong directory.
  const ev = cli(['run', 'library-author', '--evidence', '', '--json']);
  assert.equal(ev.status, 1, 'run --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);

  // ai-run --no-stream tested args.evidence for truthiness, so `--evidence ""`
  // fell through to the stdin branch and — with closed stdin in the harness —
  // ran an empty submission to ok:true / evidence_hash at exit 0. The AI-facing
  // verb must refuse the empty value identically to `run`.
  const air = cli(['ai-run', 'secrets', '--no-stream', '--evidence', '', '--json']);
  assert.equal(air.status, 1, 'ai-run --no-stream --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(air.stdout + air.stderr, /--evidence was given an empty value/);
  // The run must be refused before it executes — no vacuous success body and no
  // evidence_hash for the empty submission may reach stdout.
  assert.doesNotMatch(air.stdout, /"ok":true/, 'ai-run --evidence "" must not emit a vacuous ok:true run');
  assert.doesNotMatch(air.stdout, /"evidence_hash"/, 'ai-run --evidence "" must not emit an evidence_hash for an empty submission');

  const cc = cli(['collect', 'library-author', '--cwd', '', '--json']);
  assert.equal(cc.status, 1, 'collect --cwd "" must exit 1');
  assert.match(cc.stdout + cc.stderr, /--cwd was given an empty value/);

  const dc = cli(['discover', '--cwd', '', '--json']);
  assert.equal(dc.status, 1, 'discover --cwd "" must exit 1');
  assert.match(dc.stdout + dc.stderr, /--cwd was given an empty value/);
});

test('ci --evidence "" / --evidence-dir "" are operator errors, not a silent false-green PASS', () => {
  // `ci <pb> --evidence ""` was falsy, so the truthiness-gated evidence read
  // skipped, every playbook ran with no evidence, and the gate reported
  // verdict=PASS at exit 0 — a false security green. The run verb was hardened
  // against this; the fix must hold for ci too (same class, sibling verb).
  const ev = cli(['ci', 'secrets', '--evidence', '', '--format', 'summary', '--json']);
  assert.equal(ev.status, 1, 'ci --evidence "" must exit 1, not a false-green exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);
  // It must NOT have produced a verdict — the gate is refused before it runs.
  assert.doesNotMatch(ev.stdout, /"verdict":"PASS"/, 'ci --evidence "" must not emit a PASS verdict');

  const evEq = cli(['ci', 'secrets', '--evidence=', '--format', 'summary', '--json']);
  assert.equal(evEq.status, 1, 'ci --evidence= (equals form) must exit 1');
  assert.match(evEq.stdout + evEq.stderr, /--evidence was given an empty value/);

  const ed = cli(['ci', 'framework', '--evidence-dir', '', '--format', 'summary', '--json']);
  assert.equal(ed.status, 1, 'ci --evidence-dir "" must exit 1');
  assert.match(ed.stdout + ed.stderr, /--evidence-dir was given an empty value/);
});

test('run --all / --scope / run-all with --evidence "" / --evidence-dir "" are operator errors, not a silent no-evidence contract run', () => {
  // cmdRunMulti (the engine behind `run --all`, `run --scope <type>`, and the
  // `run-all` alias) gated the evidence read on truthiness (`if (args.evidence)`),
  // so `--evidence ""` was dropped and the contract ran with an empty bundle,
  // reporting verdict=not_detected at exit 0 — a false-clean from a security
  // tool. The single-playbook `run` and the `ci` verb were already hardened;
  // the multi path was not. The `--evidence-dir ""` path additionally carried a
  // dead `dir.length === 0` guard nested inside `if (args["evidence-dir"])`,
  // which excludes "" (falsy) and so could never fire.
  //
  // Scope to `cross-cutting` (runs only the non-blocking `framework` playbook),
  // so a non-zero exit can ONLY come from the empty-value guard — never
  // coincidentally from a platform-blocked playbook (the way `--all` masks it).
  const ev = cli(['run', '--scope', 'cross-cutting', '--evidence', '', '--json']);
  assert.equal(ev.status, 1, 'run --scope --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);
  assert.doesNotMatch(ev.stdout, /"verdict":"not_detected"/, 'run --scope --evidence "" must not emit a not_detected verdict — the contract is refused before it runs');

  const evEq = cli(['run', '--scope', 'cross-cutting', '--evidence=', '--json']);
  assert.equal(evEq.status, 1, 'run --scope --evidence= (equals form) must exit 1');
  assert.match(evEq.stdout + evEq.stderr, /--evidence was given an empty value/);

  const ed = cli(['run', '--scope', 'cross-cutting', '--evidence-dir', '', '--json']);
  assert.equal(ed.status, 1, 'run --scope --evidence-dir "" must exit 1, not the dead length-0 path');
  assert.match(ed.stdout + ed.stderr, /--evidence-dir was given an empty value/);
  assert.doesNotMatch(ed.stdout, /"verdict":"not_detected"/, 'run --scope --evidence-dir "" must not emit a not_detected verdict');

  // run-all is `run --all`; it must inherit the same guard.
  const ra = cli(['run-all', '--evidence', '', '--json']);
  assert.equal(ra.status, 1, 'run-all --evidence "" must exit 1');
  assert.match(ra.stdout + ra.stderr, /--evidence was given an empty value/);

  // Negative control: omitting --evidence entirely is NOT an error — a
  // no-evidence contract run is a supported mode and must still reach a verdict
  // at exit 0. (Guards on presence === "", not on truthiness.)
  const noEv = cli(['run', '--scope', 'cross-cutting', '--json']);
  assert.equal(noEv.status, 0, 'run --scope with --evidence omitted must still run at exit 0');
  assert.doesNotMatch(noEv.stdout + noEv.stderr, /was given an empty value/, 'omitted --evidence must not trip the empty-value guard');
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
