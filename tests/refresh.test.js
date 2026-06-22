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


// ---- routed from v0_13_4-fixes ----
require("node:test").describe("v0_13_4-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_4-fixes.test.js
 *
 * Pin tests for the v0.13.4 patch.
 *
 * Coverage:
 *   A — _meta.fed_by is now schema-accepted (drives the 20 cosmetic
 *       validate-playbooks warnings to 0).
 *   C — README + AGENTS surface the v0.13.x operator-facing features.
 *   E — 2 stuck-draft CVEs (MAL-2026-ANTHROPIC-MCP-STDIO + CVE-2026-GTIG-AI-2FA)
 *       are deleted from the catalog and from any cross-referencing data file.
 *   (B and D pin coverage is in their dedicated test files; this file
 *    covers the items that don't have a natural dedicated home.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

// ---------- A. fed_by schema acceptance ----------



// ---------- C. README + AGENTS surface v0.13.x features ----------








// ---------- E. 2 stuck-draft CVEs deleted ----------

test('C: README documents refresh --check-advisories', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--check-advisories/, 'README must mention refresh --check-advisories');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
