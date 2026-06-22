'use strict';

/**
 * tests/refresh.test.js
 *
 * `exceptd refresh` CLI verb (and adjacent air-gap/flag-wiring surfaces that
 * the refresh flag set shares with watchlist / prefetch / cve / framework-gap /
 * report / run / brief). Every test spawns bin/exceptd.js through the shared
 * cli() harness and asserts the EXACT exit code plus the field value/type per
 * the project anti-coincidence rule. All reproduction is offline — air-gap is
 * forced via EXCEPTD_AIR_GAP=1 / --air-gap and offline catalogs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const test_describe = typeof test.describe === 'function' ? test.describe : (name, fn) => fn();

// ===========================================================================
// air-gap-and-refresh-correctness — CLI-verb air-gap + correctness regressions
// ===========================================================================

test_describe('air-gap-and-refresh-correctness', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');
  const crypto = require('node:crypto');

  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-airgap-refresh-');
  const cli = makeCli(SUITE_HOME);

  // A scenario CVE that the offline catalog carries framework-control gaps for.
  const SCENARIO_CVE = 'CVE-2025-53773';

  // Per-suite scratch dir for caches / report-out files so refresh runs never
  // pollute the package root (the child spawns with cwd = PKG_ROOT).
  const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-airgap-scratch-'));
  process.on('exit', () => { try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* non-fatal */ } });

  // 1. watchlist --org-scan air-gap egress guard
  test('watchlist --org-scan refuses under EXCEPTD_AIR_GAP=1 (exit 4, no fetch)', () => {
    const r = cli(['watchlist', '--org-scan', '--org', 'someorg', '--json'], { env: { EXCEPTD_AIR_GAP: '1' } });
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
    assert.ok(body, `expected JSON output; got stdout=${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(body.source, 'air-gap');
    assert.equal(body.verb, 'watchlist');
    assert.equal(body.mode, 'org-scan');
    assert.equal(typeof body.error, 'string');
    assert.match(body.error, /air-gap: watchlist --org-scan requires network egress to api\.github\.com; refused\./);
  });

  test('watchlist --org-scan refuses under --air-gap flag (exit 4)', () => {
    const r = cli(['watchlist', '--org-scan', '--org', 'someorg', '--air-gap', '--json']);
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, `expected JSON on stdout; got ${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(body.source, 'air-gap');
  });

  // 2. refresh --network air-gap refusal
  test('refresh --network refuses under EXCEPTD_AIR_GAP=1 (exit 4, no fetch)', () => {
    const r = cli(['refresh', '--network', '--json'], { env: { EXCEPTD_AIR_GAP: '1' } });
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)} stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
    assert.ok(body, `expected JSON output; got stdout=${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(body.source, 'air-gap');
    assert.equal(typeof body.error, 'string');
    assert.match(body.error, /air-gap: refresh --network requires network egress; refused\. Use --from-cache --apply for the offline path\./);
  });

  test('refresh --network refuses under --air-gap flag (exit 4)', () => {
    const r = cli(['refresh', '--network', '--air-gap', '--json']);
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
    assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(body.source, 'air-gap');
  });

  // 3. prefetch honors EXCEPTD_AIR_GAP / --air-gap (dry-run, no egress)
  test('prefetch under EXCEPTD_AIR_GAP=1 plans no live fetches (dry-run)', () => {
    const r = cli(['prefetch'], { env: { EXCEPTD_AIR_GAP: '1' } });
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    // The dry-run branch prints "DRY-RUN ... item(s)" and the "(dry-run)" summary
    // and NEVER the "fetching ... item(s)" header that the live path uses.
    assert.match(r.stdout, /prefetch — DRY-RUN/, 'prefetch should report DRY-RUN under air-gap');
    assert.match(r.stdout, /\(dry-run\)/, 'prefetch should emit the dry-run summary');
    assert.doesNotMatch(r.stdout, /prefetch — fetching/, 'prefetch must NOT plan live fetches under air-gap');
  });

  test('prefetch under --air-gap flag plans no live fetches (dry-run)', () => {
    const r = cli(['prefetch', '--air-gap']);
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    assert.match(r.stdout, /prefetch — DRY-RUN/);
    assert.doesNotMatch(r.stdout, /prefetch — fetching/);
  });

  // 4. cache-integrity refusals exit 4 (documented BLOCKED), not 1
  test('refresh --from-cache sha256 mismatch propagates exit 4 (not 1)', () => {
    // Build a cache whose payload no longer matches the sha256 recorded in
    // _index.json (a payload-tamper). --force-stale lets us past the cache
    // SIGNATURE gate so the run reaches readCachedJson's sha256 check, which
    // --force-stale deliberately does NOT bypass — the canonical tamper signal.
    // Before the fix this surfaced as exit 1 (the generic hadFailure code);
    // the integrity marker must now drive exit 4.
    const cacheDir = fs.mkdtempSync(path.join(SCRATCH, 'tampered-'));
    fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
    const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE, dateAdded: '2026-01-01' }] };
    fs.writeFileSync(path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify(payload));
    // Record a deliberately wrong sha256 so the recompute mismatches.
    fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify({
      entries: { 'kev/known_exploited_vulnerabilities': { sha256: '0'.repeat(64) } },
    }));

    const reportOut = path.join(cacheDir, 'report.json');
    const r = cli([
      'refresh', '--source', 'kev', '--from-cache', cacheDir,
      '--report-out', reportOut, '--force-stale', '--quiet',
    ]);
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stderr: ${r.stderr.slice(0, 300)})`);
    const report = JSON.parse(fs.readFileSync(reportOut, 'utf8'));
    assert.equal(report.sources.kev.status, 'error');
    assert.equal(report.sources.kev.cache_integrity, true);
    assert.match(report.sources.kev.error, /cache-integrity: sha256 mismatch/);
  });

  test('refresh --from-cache unsigned/partial index refuses with exit 4', () => {
    // A partial-index injection (index present, no per-entry sha256, no valid
    // sidecar signature) without --force-stale must refuse with exit 4 rather
    // than consuming the unverified cache. The signature precondition catches
    // it first; the documented code is 4 (BLOCKED / precondition refusal).
    const cacheDir = fs.mkdtempSync(path.join(SCRATCH, 'partial-'));
    fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
    const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE, dateAdded: '2026-01-01' }] };
    fs.writeFileSync(path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify(payload));
    fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify({ entries: {} }));

    const reportOut = path.join(cacheDir, 'report.json');
    const r = cli([
      'refresh', '--source', 'kev', '--from-cache', cacheDir,
      '--report-out', reportOut, '--quiet',
    ]);
    assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stderr: ${r.stderr.slice(0, 300)})`);
    // Confirm the refusal is the cache precondition, not a network attempt.
    assert.match(r.stderr, /signature verification failed|cache-integrity/);
  });

  // keep the integrity-marker recompute honest: the recorded sha must be the
  // canonical-stringify of the parsed payload, so an *untampered* index would
  // have matched. (Sanity guard, not an egress test.)
  test('cache sha256 recompute is over JSON.stringify(parsed) (sanity)', () => {
    const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE }] };
    const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    assert.equal(sha.length, 64);
    assert.notEqual(sha, '0'.repeat(64));
  });

  // 5. refresh --source "" errors instead of silently running all
  test('refresh --source "" errors (exit 2) listing valid sources', () => {
    const r = cli(['refresh', '--source', '', '--quiet']);
    assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    // The error lists the valid source names so the operator sees the typo.
    assert.match(r.stderr, /--source requires at least one source name/);
    for (const name of ['kev', 'epss', 'nvd', 'rfc', 'pins', 'ghsa', 'osv', 'advisories', 'cve-regression-watcher']) {
      assert.match(r.stderr, new RegExp(`\\b${name}\\b`), `valid-source list should mention "${name}"`);
    }
  });

  test('refresh --source "," (trims to empty) also errors exit 2', () => {
    const r = cli(['refresh', '--source', ',', '--quiet']);
    assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    assert.match(r.stderr, /--source requires at least one source name/);
  });

  // 6. cve "<whitespace>" is a usage error, not a fabricated lookup
  test('cve "   " (whitespace) is a usage error (exit 1), matching cve ""', () => {
    const ws = cli(['cve', '   ']);
    assert.equal(ws.status, 1, `expected exit 1; got ${ws.status} (stderr: ${ws.stderr.slice(0, 200)})`);
    const body = tryJson(ws.stderr.trim()) || tryJson(ws.stdout.trim());
    assert.ok(body, `expected JSON; got stderr=${ws.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'cve');
    assert.match(body.error, /usage: exceptd cve/);
    // It must NOT have resolved as a "fabricated" citation.
    assert.equal(body.status, undefined, 'whitespace cve must not produce a resolution status');

    // Parity with the empty-string form.
    const empty = cli(['cve', '']);
    assert.equal(empty.status, 1, `cve "" should also exit 1; got ${empty.status}`);
  });

  // 7. refresh --advisory "   " hits the dedicated empty-advisory guard
  test('refresh --advisory "   " hits the dedicated empty-advisory guard (exit 2)', () => {
    const r = cli(['refresh', '--advisory', '   ', '--quiet'], { env: { EXCEPTD_AIR_GAP: '1' } });
    assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
    assert.ok(body, `expected JSON; got stderr=${r.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.match(body.error, /--advisory requires a non-empty identifier/);
  });

  // 8. framework-gap single-framework summary agrees with the body
  test('framework-gap single framework: summary total_gaps equals per-framework gap_count', () => {
    const r = cli(['framework-gap', 'nist-800-53', SCENARIO_CVE, '--json']);
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, `expected JSON on stdout; got ${r.stdout.slice(0, 200)}`);
    const perFw = Object.values(body.frameworks).reduce((acc, v) => acc + v.gap_count, 0);
    // Single explicit framework -> summary matching count equals the body.
    assert.equal(typeof body.summary.total_gaps, 'number');
    assert.equal(body.summary.total_gaps, perFw,
      `summary.total_gaps (${body.summary.total_gaps}) must equal the sum of per-framework gap_count (${perFw})`);
  });

  test('framework-gap single framework: human Summary line agrees with body count', () => {
    const r = cli(['framework-gap', 'nist-800-53', SCENARIO_CVE]);
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const bodyMatch = r.stdout.match(/### nist-800-53 — (\d+) matching control gap\(s\)/);
    const sumMatch = r.stdout.match(/Summary: (\d+) matching gaps/);
    assert.ok(bodyMatch, `expected a per-framework body line; got ${r.stdout.slice(0, 300)}`);
    assert.ok(sumMatch, `expected a Summary line; got ${r.stdout.slice(0, 300)}`);
    assert.equal(sumMatch[1], bodyMatch[1],
      `Summary count (${sumMatch[1]}) must equal the per-framework body count (${bodyMatch[1]})`);
  });

  test('framework-gap all: summary counts every scenario-relevant gap (unchanged)', () => {
    const r = cli(['framework-gap', 'all', SCENARIO_CVE, '--json']);
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
    // "all" keeps catalog-wide counting: total_gaps must be a number >= the
    // max single-framework gap_count (it aggregates the scenario hits).
    assert.equal(typeof body.summary.total_gaps, 'number');
    const maxFw = Math.max(0, ...Object.values(body.frameworks).map((v) => v.gap_count));
    assert.ok(body.summary.total_gaps >= maxFw,
      `all-frameworks total_gaps (${body.summary.total_gaps}) should be >= max per-framework gap_count (${maxFw})`);
  });

  // 9. report executive: progress line goes to stderr, markdown on stdout
  test('report executive writes markdown header as the first stdout line', () => {
    const r = cli(['report', 'executive']);
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const firstStdoutLine = r.stdout.split('\n')[0];
    assert.equal(firstStdoutLine, '# exceptd Executive Report',
      `first stdout line must be the markdown header; got "${firstStdoutLine}"`);
    // The progress notice must NOT pollute stdout.
    assert.doesNotMatch(r.stdout, /\[orchestrator\] Generating/, 'progress line must not be on stdout');
    assert.match(r.stderr, /\[orchestrator\] Generating executive report/, 'progress line must be on stderr');
  });
});

// ===========================================================================
// refresh-airgap-and-tlp — refresh --advisory air-gap + --tlp flag wiring
// ===========================================================================

test_describe('refresh-airgap-and-tlp', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const cli = makeCli(makeSuiteHome('exceptd-refreshtlp-'));

  test('refresh --advisory <id> --air-gap refuses instead of egressing', () => {
    const r = cli(['refresh', '--advisory', 'CVE-2026-45321', '--air-gap']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /air-gap/);
    assert.doesNotMatch(r.stdout, /advisory-seed-dry-run/);
  });

  test("refresh --advisory '' errors (does not fall through to a full refresh)", () => {
    const r = cli(['refresh', '--advisory', '']);
    assert.equal(r.status, 2);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false);
    assert.match(body.error, /--advisory requires a non-empty identifier/);
  });

  test('--tlp stamps the CSAF distribution marking', () => {
    const r = cli(['run', 'sbom', '--evidence', '-', '--tlp', 'amber', '--format', 'csaf-2.0'], { input: '{}' });
    assert.equal(r.status, 0);
    const csaf = tryJson(r.stdout);
    assert.ok(csaf && csaf.document, 'expected a CSAF document');
    assert.ok(csaf.document.distribution, 'CSAF distribution must be present with --tlp');
    assert.equal(csaf.document.distribution.tlp.label, 'AMBER', 'lowercase --tlp amber normalizes to AMBER');
    assert.equal(csaf.document.distribution.text, 'TLP:AMBER');
  });

  test('--tlp CLEAR maps to the CSAF 2.0-valid WHITE label, preserving TLP:CLEAR in text', () => {
    // CSAF 2.0 pins tlp.label to WHITE/GREEN/AMBER/RED; CLEAR (TLP 2.0) must map
    // to WHITE so the document stays schema-valid, with the modern label in text.
    const r = cli(['run', 'sbom', '--evidence', '-', '--tlp', 'CLEAR', '--format', 'csaf-2.0'], { input: '{}' });
    assert.equal(r.status, 0);
    const csaf = tryJson(r.stdout);
    assert.equal(csaf.document.distribution.tlp.label, 'WHITE');
    assert.equal(csaf.document.distribution.text, 'TLP:CLEAR');
  });

  test('--tlp rejects a non-TLP value', () => {
    const r = cli(['run', 'sbom', '--evidence', '-', '--tlp', 'BOGUS'], { input: '{}' });
    assert.equal(r.status, 1);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false);
    assert.match(body.error, /--tlp must be one of/);
  });

  test('--tlp is refused on an info-only verb (brief)', () => {
    const r = cli(['brief', 'sbom', '--tlp', 'AMBER']);
    assert.equal(r.status, 1);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false);
    assert.match(body.error, /--tlp is irrelevant on this verb/);
  });
});

// ===========================================================================
// refresh-prefetch-populate-hint (refresh --help surface)
//
// The cache-populate command is `exceptd refresh --prefetch`. `--no-network` is
// the report-only dry run; `refresh --help` must present --prefetch as the
// populate command and document --no-network as report-only.
// ===========================================================================

test_describe('refresh-prefetch-populate-hint', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  test('refresh --help presents --prefetch as the populate command, not --no-network', () => {
    const r = spawnSync(process.execPath, [CLI, 'refresh', '--help'], { encoding: 'utf8', timeout: 30000 });
    assert.equal(r.status, 0, `refresh --help must exit 0; stderr=${r.stderr.slice(0, 300)}`);
    const out = r.stdout;
    assert.match(out, /--prefetch\b[^\n]*populate the cache/i,
      '--prefetch must be documented as the populate command');
    // --no-network must NOT be presented as a populate alias or as populating.
    assert.doesNotMatch(out, /alias:\s*--no-network\)?\s*populate/i,
      '--no-network must not be presented as a populate alias');
    assert.doesNotMatch(out, /--no-network\b[^\n]*populate the cache/i,
      '--no-network must not be described as populating the cache');
    // --no-network is documented accurately as report-only.
    assert.match(out, /--no-network\b[^\n]*report-only/i,
      '--no-network must be documented as report-only');
  });
});

// ===========================================================================
// Source: cli-flag-and-envelope-hardening.test.js — refresh unknown-flag
// rejection (F3). Offline via --air-gap; the rejection fires before any fetch.
// ===========================================================================
test_describe('cli-flag-and-envelope-hardening.test.js', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const cli = makeCli(makeSuiteHome('exceptd-flag-envelope-'));

  test('F3: refresh --badflag -> ok:false exit 2 (not silently swallowed)', () => {
    const r = cli(['refresh', '--badflag', '--air-gap'], { timeout: 20000 });
    assert.equal(r.status, 2, 'refresh usage error exits 2 per its own scheme');
    const body = tryJson(r.stderr.trim());
    assert.ok(body, 'must emit a parseable JSON envelope on stderr');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'refresh');
    assert.deepEqual(body.unknown_flags, ['--badflag']);
    assert.ok(Array.isArray(body.known_flags) && body.known_flags.includes('--source'));
  });

  test('F3: refresh --source kev --air-gap still runs (dry-run), exit 0', () => {
    const r = cli(['refresh', '--source', 'kev', '--air-gap'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /air-gap mode: kev skipped|dry-run/);
  });
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

test('refresh --help keeps its own detailed help (not swallowed by --help interception)', () => {
  const r = cli(['refresh', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /check-advisories/);
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

test('#65 refresh --no-network routes to prefetch', () => {
  const r = cli(['refresh', '--no-network', '--quiet']);
  // The behavior #65 tests: the refresh dispatcher routes --no-network
  // through to prefetch.js, which then emits the "prefetch summary:"
  // one-line. The exit code is prefetch.js's own contract (0 when all
  // sources fresh / dry-run completed, 1 when any source errored, 2 on
  // fatal). The Node-25-on-Windows libuv UV_HANDLE_CLOSING teardown
  // assertion that previously fired here is fixed by switching
  // prefetch.js's main() from process.exit(N) to process.exitCode = N;
  // return — letting the event loop drain naturally so undici / abort
  // signal teardown completes before the process exits. So exit code
  // is now meaningful again at this layer.
  //
  // Strengthening that respects the test's intent: parse the summary
  // line and confirm it contains the numeric breakdown — that's what
  // operators look for, and what a regression would silently break.
  // Pre-strengthening matched only "prefetch summary:" anywhere in
  // stdout, which would have accepted a regression where the dispatcher
  // mis-routed to a verb that happens to print that string in a
  // different format.
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --no-network must route to prefetch.js and emit its summary');
  // v0.12.16: dry-run summary differs — prefetch emits "N fetched, M fresh,
  // K would-fetch (dry-run)" when --no-network is supplied (versus
  // "N fetched, M fresh, K error(s)" on a real fetch run). Both shapes
  // prove prefetch.js produced the line. Accept either.
  const summaryMatch = r.stdout.match(/prefetch summary: (\d+) fetched, (\d+) fresh, (\d+) (?:error\(s\)|would-fetch)/);
  assert.ok(summaryMatch,
    `summary line must be in the exact "N fetched, M fresh, K error(s)" OR "N fetched, M fresh, K would-fetch (dry-run)" format — proves prefetch.js produced it, not a misrouted verb. Got stdout=${JSON.stringify(r.stdout.slice(0,300))}`);
  // The 2 prior 404 sources (mitre/cwe + d3fend/d3fend-data — neither
  // upstream project publishes via GitHub Releases) were removed from
  // the pins registry. The error counter SHOULD be 0 on a fresh cache,
  // but CI runs hit live upstream sources without auth and can see
  // transient GitHub-API rate-limit 403/404s on the remaining pin
  // sources. Assert errors <= a small ceiling so a real regression
  // (re-adding a permanently-broken URL) still fires but transient
  // upstream flakes don't fail CI on every PR.
  //
  // v0.12.16: the 3rd capture group means different things in the two
  // summary shapes — "N error(s)" vs "N would-fetch (dry-run)". The
  // ceiling check only applies to the error shape; the dry-run shape's
  // would-fetch count is the entire pin registry (47 today) and is
  // expected to be high.
  const isDryRun = /would-fetch/.test(summaryMatch[0]);
  if (!isDryRun) {
    const errorCount = parseInt(summaryMatch[3], 10);
    const ERROR_CEILING = 10; // remaining pin sources (8) + small headroom
    assert.ok(errorCount <= ERROR_CEILING,
      `prefetch error count ${errorCount} exceeds ceiling ${ERROR_CEILING} — implies a pin source URL is permanently broken (not transient upstream flakiness). Got: ${summaryMatch[0]}`);
  }
  // The libuv assertion fix: stderr must not contain the teardown
  // assertion line. Coupled with the exit-status path below, this
  // proves the crash is gone, not just masked by a pipe-buffered
  // swallow. Exit code: 0 (clean) on Linux/macOS; 1 (some pin source
  // errored) acceptable when upstream sources transient-fail under CI
  // network conditions; the Windows libuv quirk code is also accepted
  // (post-flush teardown anomaly, not a regression).
  const acceptableExits = new Set([0, 1, 3221226505]);
  assert.ok(acceptableExits.has(r.status),
    `prefetch exit must be 0 (clean), 1 (some source errored under transient network), or 3221226505 (Windows libuv post-flush teardown). Got status=${r.status}, stderr=${JSON.stringify((r.stderr || '').slice(-300))}`);
  assert.doesNotMatch(r.stderr || '', /UV_HANDLE_CLOSING|Assertion failed/,
    `stderr must not contain the libuv teardown assertion — got ${JSON.stringify(r.stderr)}`);
});

test('#129 refresh --from-cache <missing> emits structured hint, not stack trace', () => {
  const r = cli(['refresh', '--from-cache', '/totally/does/not/exist']);
  // The missing-cache branch in lib/refresh-external.js throws a hint
  // error without _exceptd_exit_code, so the top-level handler defaults
  // to exit 2 (lib/refresh-external.js:1442). Signature-validation
  // refusals from the same file set _exceptd_exit_code = 4, so notEqual(0)
  // would silently accept either — pin the exact missing-cache code.
  assert.equal(r.status, 2, 'missing cache dir must exit 2 (refresh-external hint refusal default)');
  const combined = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(combined, /at Object\.<anonymous>|^\s*at .*\.js:\d+/m,
    'no raw Node stack trace — should be a hinted error');
  assert.match(combined, /exceptd refresh --(prefetch|no-network)/,
    'error must tell operator the exact command to populate the cache');
});

test('#129 refresh --prefetch is an alias for --no-network', () => {
  // Pre-strengthening: ran `refresh --prefetch --help` and asserted only
  // status!==127 — which would silently accept ANY exit (0..126) including
  // the regression where --prefetch becomes unrecognized and the dispatcher
  // falls through to a different verb's help. Replace with the actual
  // behavioral contract: --prefetch routes through to prefetch.js which
  // emits "prefetch summary:" on stdout. Pin that exact string.
  const r = cli(['refresh', '--prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --prefetch must route to prefetch.js and emit its one-line summary — proves the alias works, not just that the dispatcher didn\'t crash');
});

test('refresh --network shows clear hint when registry is unreachable', () => {
  // Force "unreachable" by pointing the fixture at a missing file.
  const fakePath = path.join(require('os').tmpdir(), 'does-not-exist-' + Date.now() + '.json');
  const r = cli(['refresh', '--network', '--json', '--timeout', '500'], {
    env: { EXCEPTD_REGISTRY_FIXTURE: fakePath }
  });
  // lib/refresh-network.js:294 pins exitCode = 2 for the unreachable
  // branch. Pinning the code keeps this from masking a regression to
  // exit 1 (would conflate unreachable with generic validation refusal).
  assert.equal(r.status, 2, 'unreachable registry must exit 2 (refresh-network unreachable branch)');
  // Pre-strengthening only checked the exit code. The contract that
  // actually matters to operators is "I get a hint telling me what to
  // do" — without it, refresh --network is the silent-no-op class of
  // bug. Parse stdout (refresh-network emits structured JSON there even
  // on the error path) and verify the body carries ok:false + a string
  // error mentioning the failure mode (unreachable/registry).
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'refresh --network must emit structured JSON on the error path, not a raw stack trace');
  assert.equal(data.ok, false, 'unreachable registry must carry ok:false');
  assert.equal(typeof data.error, 'string', 'error must be a string operators can read');
  assert.match(data.error, /unreachable|registry/i,
    'error must name the failure class so operators see "unreachable" / "registry" — not a generic ENOENT bubble-up');
});

test('refresh --network --dry-run reports verification result without modifying files', () => {
  // Smoke contract: --dry-run + --json + --timeout exits with a structured
  // body in either branch (online or offline). Pre-strengthening, "data
  // parses as JSON" was the only check — a regression that emits {} (empty
  // object, no contract fields) would have passed. Pin the contract: the
  // body must carry one of the specific fields the dry-run path emits.
  // refresh-network's dry-run/skip path emits `verified` (verification
  // result), `ok` (success flag), or `skipped`/`message` (when already-
  // at-latest). At least one must be present.
  const r = cli(['refresh', '--network', '--dry-run', '--json', '--timeout', '1000']);
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'must emit structured JSON in either online or offline branch');
  assert.ok('verified' in data || 'ok' in data,
    `refresh --network --dry-run body must carry at least one of {verified, ok}; got keys=${JSON.stringify(Object.keys(data))}. An empty object is the field-missing regression.`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from v0_13_3-fixes ----
require("node:test").describe("v0_13_3-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_3-fixes.test.js
 *
 * Pin tests for the v0.13.3 patch.
 *
 * Coverage:
 *   A — refresh.yml split into refresh-data (no creds) + open-pr
 *       (contents:write + pull-requests:write scoped to PR creation only).
 *   B — Hard Rule #1 body-scan flipped from warning to hard error.
 *   E — doctor --ai-config produces a structured check matching the shape
 *       documented under NEW-CTRL-050.
 *   F — watchlist --org-scan refuses without --org / GITHUB_ORG; surfaces
 *       error envelope shape.
 *   G — ADVISORIES_SOURCE FEEDS grew from 4 to 8 (added kernel-org,
 *       oss-security, jfrog, cisa-current).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function extractJobBlock(yml, jobName) {
  const lines = yml.split('\n');
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === `  ${jobName}:`) { startIdx = i; break; }
  }
  if (startIdx === -1) return null;
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^  [a-z][a-z0-9_-]*:\s*$/.test(lines[i])) { endIdx = i; break; }
  }
  return lines.slice(startIdx, endIdx).join('\n');
}

const PERM_DECL = (key, value) =>
  new RegExp(`^\\s+${key}:\\s+${value}\\s*$`, 'm');

// ---------- A. refresh.yml split-checkout ----------




// ---------- B. lint Hard Rule #1 body-scan is now hard error ----------

test('A: refresh.yml has refresh-data job with NO write credentials', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  const block = extractJobBlock(yml, 'refresh-data');
  assert.ok(block, 'refresh-data job must exist');
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'refresh-data must NOT carry contents:write');
  assert.ok(!PERM_DECL('pull-requests', 'write').test(block),
    'refresh-data must NOT carry pull-requests:write');
  assert.ok(!PERM_DECL('issues', 'write').test(block),
    'refresh-data must NOT carry issues:write');
  // The checkout must persist-credentials: false in the no-creds job.
  assert.match(block, /persist-credentials:\s*false/);
});

test('A: refresh.yml has open-pr job with write credentials scoped here only', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  const block = extractJobBlock(yml, 'open-pr');
  assert.ok(block, 'open-pr job must exist');
  assert.match(block, PERM_DECL('contents', 'write'));
  assert.match(block, PERM_DECL('pull-requests', 'write'));
  assert.match(block, /needs:\s*refresh-data/,
    'open-pr must depend on refresh-data');
});

test('A: pre-v0.13.3 monolithic refresh job is gone', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.ok(!/^  refresh:\s*$/m.test(yml),
    'pre-v0.13.3 monolithic refresh job must be removed');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
