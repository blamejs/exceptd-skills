'use strict';

/**
 * tests/refresh-external.test.js
 *
 * Verifies the lib/refresh-external.js orchestrator using the frozen
 * fixture payloads under tests/fixtures/refresh/. Network never touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'refresh');
const os = require('os');

let REPORT;            // per-test tempfile so parallel test files don't race
function mkReport() {
  REPORT = path.join(os.tmpdir(), `refresh-report-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  return REPORT;
}

function runDryRun(args = []) {
  const reportPath = mkReport();
  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-fixture', FIX, '--quiet', '--report-out', reportPath, ...args],
    { cwd: ROOT, encoding: 'utf8', env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
  );
  return { exitCode: res.status, stdout: res.stdout, stderr: res.stderr };
}

test('refresh-external --from-fixture exits 0 and writes refresh-report.json', () => {
  const r = runDryRun();
  assert.equal(r.exitCode, 0, `stderr: ${r.stderr}`);
  assert.ok(fs.existsSync(REPORT));
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.mode, 'dry-run');
  assert.equal(report.fixture_mode, true);
  for (const src of ['kev', 'epss', 'nvd', 'rfc', 'pins']) {
    assert.ok(report.sources[src], `missing source ${src} in report`);
  }
});

test('refresh-external honors --source filter', () => {
  const r = runDryRun(['--source', 'kev,pins']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.deepEqual(Object.keys(report.sources).sort(), ['kev', 'pins']);
});

test('refresh-external surfaces KEV diff from fixture (CVE-2026-43284)', () => {
  const r = runDryRun(['--source', 'kev']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const diffs = report.sources.kev.diffs;
  assert.ok(diffs.find((d) => d.id === 'CVE-2026-43284' && d.field === 'cisa_kev'));
});

test('refresh-external marks pins as report-only', () => {
  const r = runDryRun(['--source', 'pins']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.sources.pins.report_only, true);
});

// The advisory feeds surface every CVE seen across USN / RHSA / ZDI / CISA
// that the catalog does not carry — thousands of them, and never zero, since
// the catalog deliberately does not track every Ubuntu kernel CVE. The refresh
// workflow counts only non-report_only sources toward `upsert_diffs` and gates
// its apply step AND its whole open-pr job on that being non-zero, so an
// unflagged advisories source pins the gate permanently open. The source's own
// applyDiff is a no-op, but the flag is what the callers read.
test('refresh-external marks advisories as report-only so it cannot pin the upsert gate open', () => {
  const r = runDryRun(['--source', 'advisories']);
  assert.equal(r.exitCode, 0);
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.sources.advisories.report_only, true);
});

test('only sources that can write the catalog count toward the upsert-diff gate', () => {
  const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const counted = Object.entries(ALL_SOURCES)
    .filter(([, s]) => s.report_only !== true)
    .map(([n]) => n)
    .sort();
  assert.deepEqual(counted, ['cve-regression-watcher', 'epss', 'ghsa', 'kev', 'nvd', 'osv', 'rfc'],
    'a source whose applyDiff cannot write the catalog must declare report_only, or it inflates ' +
    'upsert_diffs and makes the refresh workflow open a PR on every run regardless of real drift');
});

test('refresh-external rejects unknown --source values', () => {
  const r = runDryRun(['--source', 'made-up-thing']);
  assert.equal(r.exitCode, 2);
  assert.match(r.stderr || '', /unknown source/);
});

test('refresh-external --help exits 0 and prints usage', () => {
  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--help'],
    { cwd: ROOT, encoding: 'utf8' }
  );
  assert.equal(res.status, 0);
  assert.match(res.stdout, /refresh — pull latest upstream/);
  assert.match(res.stdout, /--apply/);
  assert.match(res.stdout, /--prefetch/);
  assert.match(res.stdout, /Air-gap workflow/);
  assert.match(res.stdout, /Hard Rule #12/);
});

test('version-pin-validator exports the expected pin list', () => {
  const { PINS } = require('../sources/validators/version-pin-validator');
  const names = PINS.map((p) => p.pin_name).sort();
  assert.deepEqual(names, ['atlas_version', 'attack_version', 'cwe_version', 'd3fend_version']);
});

test('refresh fixtures stay in sync with source modules', () => {
  const { ALL_SOURCES } = require('../lib/refresh-external');
  for (const src of Object.values(ALL_SOURCES)) {
    const fp = path.join(FIX, `${src.name}.json`);
    assert.ok(fs.existsSync(fp), `missing fixture for source ${src.name}`);
  }
});

// v0.12.12 C1 — concurrent `refresh --advisory --apply` regression test.
//
// Pre-fix: `seedSingleAdvisory` did `readFileSync → mutate → writeFileSync`
// against the shared catalog with no lock. Two concurrent
// `refresh --advisory CVE-A --apply` and `refresh --advisory CVE-B --apply`
// runs racing on the same catalog dropped one CVE roughly 1/20 trials —
// classic read-old / mutate / write-overwrites-sibling-mutation.
//
// Post-fix: every RMW on the catalog routes through `withCatalogLock` (an
// O_EXCL lockfile + atomic tmp+rename write). The mutator re-reads the
// catalog INSIDE the lock, so a sibling write that just landed is visible
// before this run's mutation is applied.
//
// The test runs the parallel-apply scenario 5 times in a loop to flush out
// any timing dependency in the lock implementation. Both CVEs must survive
// in the final catalog on every iteration.
test('refresh --advisory --apply: concurrent applies preserve both CVEs (5x)', async () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  for (let trial = 0; trial < 5; trial++) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `concurrent-apply-${trial}-`));
    const catalogPath = path.join(tmpDir, 'cve-catalog.json');
    fs.writeFileSync(catalogPath, JSON.stringify({ _meta: { last_updated: '2026-01-01' } }, null, 2));
    try {
      const env = {
        ...process.env,
        EXCEPTD_GHSA_FIXTURE: fix,
        EXCEPTD_CVE_CATALOG: catalogPath,
        EXCEPTD_DEPRECATION_SHOWN: '1',
        EXCEPTD_UNSIGNED_WARNED: '1',
      };
      const spawn = (cve) => new Promise((resolve) => {
        const cp = require('child_process').spawn(
          process.execPath,
          [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', cve, '--apply', '--json'],
          { env, stdio: ['ignore', 'pipe', 'pipe'] }
        );
        let stdout = '', stderr = '';
        cp.stdout.on('data', (b) => { stdout += b; });
        cp.stderr.on('data', (b) => { stderr += b; });
        cp.on('close', (code) => resolve({ code, stdout, stderr }));
      });
      const [a, b] = await Promise.all([
        spawn('CVE-2026-45321'),
        spawn('CVE-9999-99999'),
      ]);
      // Each should signal "draft applied, editorial pending" (exit 3).
      assert.equal(a.code, 3, `trial ${trial}: CVE-A apply exit code unexpected. stderr=${a.stderr}`);
      assert.equal(b.code, 3, `trial ${trial}: CVE-B apply exit code unexpected. stderr=${b.stderr}`);
      const final = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
      assert.ok(final['CVE-2026-45321'],
        `trial ${trial}: CVE-2026-45321 missing from catalog after concurrent apply — RACE LOST. keys=${Object.keys(final).join(',')}`);
      assert.ok(final['CVE-9999-99999'],
        `trial ${trial}: CVE-9999-99999 missing from catalog after concurrent apply — RACE LOST. keys=${Object.keys(final).join(',')}`);
      // Field-present + field-populated: every entry must have the
      // _auto_imported flag and a non-null name, confirming the write
      // landed in full rather than a partial / truncated buffer.
      assert.equal(final['CVE-2026-45321']._auto_imported, true,
        `trial ${trial}: CVE-A entry lacks _auto_imported flag — possible partial write`);
      assert.equal(final['CVE-9999-99999']._auto_imported, true,
        `trial ${trial}: CVE-B entry lacks _auto_imported flag — possible partial write`);
      // _meta.last_updated should remain present (no field stripped by the
      // concurrent writes).
      assert.ok(final._meta, `trial ${trial}: _meta stripped from catalog`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
});

// v0.12.12 C3 — `process.exit()` after stdout writes can truncate output.
// chosenSources() used to call `process.exit(2)` directly when an unknown
// --source name was passed; the swarm post-pool path and the help path used
// the same anti-pattern. Post-fix: thrown error / exitCode + return.
// Operator visibility: stderr must still carry the "unknown source" line.
test('refresh --source <unknown>: stderr surfaces error, exits 2 via exitCode', () => {
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--source', 'definitely-not-a-source', '--from-fixture', FIX, '--quiet'],
    { cwd: ROOT, encoding: 'utf8', env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
  );
  assert.equal(r.status, 2, `unknown --source must exit 2 via exitCode; got ${r.status}`);
  assert.match(r.stderr || '', /unknown source/);
  // Stack traces must not leak — _exceptd_unknown_source path strips them.
  assert.doesNotMatch(r.stderr || '', /at chosenSources/,
    `unknown-source error must not leak an internal stack trace; got ${r.stderr}`);
});

// ===========================================================================
// #15 — the advisories→cve-regression-watcher chaining is wired end-to-end
//       through the real CLI source loop. These spawn the orchestrator so they
//       exercise the EXACT broken wiring (the prior unit tests passed through
//       fetchDiff(ctx) directly and bypassed it).
// ===========================================================================

const REFRESH_EXTERNAL = path.join(ROOT, 'lib', 'refresh-external.js');
const ADV_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'refresh', 'advisories.json');
const WATCHER = require(path.join(ROOT, 'lib', 'cve-regression-watcher.js'));

// Helper: build an isolated fixture dir with the advisories feed bodies (which
// reference the historical CVE-2020-17103 inline) and a custom CVE catalog
// where CVE-2020-17103 is a DIRECT key with no *-REREGRESSION-<year> entry, so
// the watcher's verdict is the unambiguous `annotate`.
function buildChainFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-F-chain-'));
  fs.copyFileSync(ADV_FIXTURE, path.join(dir, 'advisories.json'));
  const catalogPath = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(catalogPath, JSON.stringify({
    _meta: { schema_version: '1.0.0' },
    'CVE-2020-17103': { aliases: [] },
  }));
  return { dir, catalogPath };
}

function runChain(extraArgs) {
  const { dir, catalogPath } = buildChainFixture();
  const reportPath = path.join(dir, 'report.json');
  const args = [
    REFRESH_EXTERNAL,
    '--from-fixture', dir,
    '--catalog', catalogPath,
    '--source', 'advisories,cve-regression-watcher',
    '--report-out', reportPath,
    '--quiet',
    ...(extraArgs || []),
  ];
  const r = spawnSync(process.execPath, args, {
    env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' },
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  return { r, report };
}

test('#15 sequential: advisories observations are threaded into the watcher', () => {
  const { r, report } = runChain([]);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 400)})`);

  const watcher = report.sources['cve-regression-watcher'];
  assert.equal(typeof watcher, 'object', 'watcher source must be present in the report');

  // Pre-fix: input was empty -> evaluated 0, diff_count 0. Assert the EXACT
  // non-zero evaluated count (>= 1) that distinguishes fixed from broken.
  assert.equal(watcher.diff_count, 1, 'exactly one candidate must surface from the threaded observations');
  assert.match(watcher.summary, /evaluated [1-9]\d* poller observations/,
    'summary must report a NON-ZERO evaluated-observations count');
  assert.doesNotMatch(watcher.summary, /evaluated 0 /,
    'a fixed pipeline must never report "evaluated 0" here');

  // The chaining selected the preferred observations field, not the fallback.
  assert.equal(watcher._meta.input_field_used, 'advisoriesObservations',
    'watcher must consume the threaded advisoriesObservations, not the diffs fallback');

  // Content-shape, not just field-presence: the candidate is the in-catalog
  // historical CVE routed to annotate, surfaced by both press feeds.
  const cand = watcher.diffs.find((d) => d.historical_cve === 'CVE-2020-17103');
  assert.equal(typeof cand, 'object', 'the historical CVE candidate must be present');
  assert.equal(cand.action, 'annotate',
    'the in-catalog historical CVE (no REREGRESSION entry) must route to annotate');
  assert.deepEqual(cand.surfaced_by.slice().sort(),
    ['bleepingcomputer-security', 'thehackernews'],
    'surfaced_by must list both press feeds that referenced CVE-2020-17103');

  // The orchestrator persists the advisories observations into the report so
  // the chaining is observable.
  const adv = report.sources['advisories'];
  assert.ok(Array.isArray(adv.observations), 'advisories source must persist observations[]');
  assert.equal(adv.observations.length, 1, 'one deduplicated CVE observation');
  assert.equal(adv.observations[0].id, 'CVE-2020-17103');
});

test('#15 --swarm: the watcher runs in a second pass and still sees the observations', () => {
  const { r, report } = runChain(['--swarm']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 400)})`);

  const watcher = report.sources['cve-regression-watcher'];
  assert.equal(watcher.diff_count, 1, 'swarm second-pass must still surface the candidate');
  assert.equal(watcher._meta.input_field_used, 'advisoriesObservations',
    'swarm second-pass must read the resolved advisories observations');
  assert.match(watcher.summary, /evaluated [1-9]/, 'swarm: non-zero evaluated count');

  // Declared --source order (advisories, cve-regression-watcher) must be
  // preserved in the report even though the watcher ran in a later pass.
  const keys = Object.keys(report.sources);
  assert.deepEqual(
    keys.filter((k) => k === 'advisories' || k === 'cve-regression-watcher'),
    ['advisories', 'cve-regression-watcher'],
    'report must preserve the operator-declared source order',
  );
});

test('#15 --swarm: watcher selected WITHOUT advisories does not crash (empty-input contract)', () => {
  const { dir, catalogPath } = buildChainFixture();
  const reportPath = path.join(dir, 'report.json');
  const r = spawnSync(process.execPath, [
    REFRESH_EXTERNAL,
    '--from-fixture', dir,
    '--catalog', catalogPath,
    '--source', 'cve-regression-watcher',
    '--report-out', reportPath,
    '--quiet', '--swarm',
  ], { env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' }, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  assert.equal(r.status, 0, `watcher-alone swarm must not crash; got ${r.status} (${r.stderr.slice(0, 300)})`);
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  assert.equal(report.sources['cve-regression-watcher'].diff_count, 0,
    'no advisories selected -> watcher legitimately evaluates an empty input');
});

// ===========================================================================
// parseArgs — --check-advisories is report-only and source-scoped (no network).
// ===========================================================================

test('refresh parseArgs: --check-advisories is report-only and source-scoped', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const a = parseArgs(['node', 'x', '--check-advisories']);
  assert.equal(a.source, 'advisories');
  assert.equal(a.apply, false);
  assert.equal(a.checkAdvisories, true);
  // --apply must NOT flip a check-advisories run to write mode, regardless of order.
  const b = parseArgs(['node', 'x', '--check-advisories', '--apply']);
  assert.equal(b.apply, false);
});

test('refresh parseArgs: --drift-only is recognised and defaults off', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  assert.equal(parseArgs(['node', 'x', '--from-cache']).driftOnly, undefined,
    'discovery stays on unless the operator asks for drift alone');
  assert.equal(parseArgs(['node', 'x', '--from-cache', '--drift-only']).driftOnly, true);
  // An unrecognised flag is refused rather than silently dropped, so a typo
  // cannot quietly run a full refresh. Confirm --drift-only is not landing in
  // that bucket.
  assert.equal((parseArgs(['node', 'x', '--drift-only'])._unknownFlags || []).length, 0);
});

const test_describe = typeof test.describe === 'function' ? test.describe : (name, fn) => fn();

// ===========================================================================
// refresh-curated-cvss-preservation — nvdDiffFromCache curator-ownership
//
// The version-downgrade guard already suppresses a v3.x->v2 regression. This
// additionally keeps a SAME-version NVD re-score (e.g. a maintainer-pinned 10.0
// dropping to NVD's 9.8) from silently overwriting a curated value. A catalog
// entry is curator-owned unless it carries `_auto_imported: true`. Offline only.
// ===========================================================================

test_describe('refresh-curated-cvss-preservation', () => {
  const crypto = require('crypto');
  const { nvdDiffFromCache, ALL_SOURCES } = require('../lib/refresh-external');

  const CURATED_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'; // score 10.0
  const NVD_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';      // score 9.8 (same version)

  function writeNvdCache(cacheDir, id, baseScore, vectorString) {
    fs.mkdirSync(path.join(cacheDir, 'nvd'), { recursive: true });
    // nvdDiffFromCache resolves the record by cve.id, not position — the cached
    // payload must carry the requested id or the metrics won't bind.
    const payload = {
      vulnerabilities: [{ cve: { id, metrics: {
        cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore, vectorString } }],
      } } }],
    };
    fs.writeFileSync(path.join(cacheDir, 'nvd', `${id}.json`), JSON.stringify(payload, null, 2) + '\n');
    const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const idxPath = path.join(cacheDir, '_index.json');
    let idx;
    try { idx = JSON.parse(fs.readFileSync(idxPath, 'utf8')); } catch { idx = { entries: {} }; }
    idx.entries[`nvd/${id}`] = { sha256: sha, fetched_at: new Date().toISOString(), url: 'test' };
    fs.writeFileSync(idxPath, JSON.stringify(idx, null, 2) + '\n');
  }

  function makeCtx(dir, cveCatalog) {
    const cvePath = path.join(dir, 'cve-catalog.json');
    fs.writeFileSync(cvePath, JSON.stringify(cveCatalog, null, 2) + '\n');
    return { cacheDir: dir, cveCatalog, cvePath, forceStale: false };
  }

  test('a curator-owned CVSS re-score is surfaced for review and NOT applied', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cvss-prot-'));
    try {
      const id = 'CVE-2025-31324';
      writeNvdCache(tmp, id, 9.8, NVD_VECTOR);
      // Curator-owned: no _auto_imported flag (the live-catalog norm).
      const catalog = { [id]: { cvss_score: 10, cvss_vector: CURATED_VECTOR, _auto_imported: false }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = nvdDiffFromCache(ctx);
      const score = diffs.find((d) => d.id === id && d.field === 'cvss_score');
      const vector = diffs.find((d) => d.id === id && d.field === 'cvss_vector');
      assert.ok(score, 'the NVD score delta must be surfaced in the report');
      assert.equal(score.after, 9.8);
      assert.equal(score.review_only, true, 'a curator-owned score re-score must be review_only');
      assert.equal(score.cvss_review, true);
      assert.ok(vector, 'the NVD vector delta must be surfaced too');
      assert.equal(vector.review_only, true, 'the vector re-score is review_only as well');

      await ALL_SOURCES.nvd.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[id];
      assert.equal(after.cvss_score, 10, 'curated cvss_score must SURVIVE (not lowered to 9.8)');
      assert.equal(after.cvss_vector, CURATED_VECTOR, 'curated cvss_vector must be preserved');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a raw _auto_imported draft applies the NVD CVSS re-score directly', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cvss-prot-'));
    try {
      const id = 'CVE-2026-99999';
      writeNvdCache(tmp, id, 9.8, NVD_VECTOR);
      const catalog = { [id]: { cvss_score: 10, cvss_vector: CURATED_VECTOR, _auto_imported: true }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = nvdDiffFromCache(ctx);
      const score = diffs.find((d) => d.id === id && d.field === 'cvss_score');
      assert.ok(score, 'a raw entry still surfaces the delta');
      assert.notEqual(score.review_only, true, 'a raw auto-imported draft is not review_only');

      await ALL_SOURCES.nvd.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[id];
      assert.equal(after.cvss_score, 9.8, 'a raw draft applies the NVD re-score');
      assert.equal(after.cvss_vector, NVD_VECTOR, 'a raw draft applies the NVD vector');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
// refresh-curated-kev-protection — kevDiffFromCache de-listing guard
//
// When a cached CISA KEV feed no longer lists a CVE the catalog has curated as
// cisa_kev:true, the de-listing must NOT be auto-applied if the curated entry
// carries strong human-curated exploitation signal. A transient or incomplete
// feed would otherwise silently strip confirmed-exploitation intel and drop the
// RWEP score. Offline only.
// ===========================================================================

test_describe('refresh-curated-kev-protection', () => {
  const crypto = require('crypto');
  const { kevDiffFromCache, ALL_SOURCES } = require('../lib/refresh-external');

  // Build a valid prefetch-style cache holding a KEV feed, padded to feedSize.
  function writeKevCache(dir, { feedSize = 800, includeCves = [] } = {}) {
    const vulnerabilities = [];
    for (const c of includeCves) {
      // Spread the caller's record so a test can carry dueDate,
      // knownRansomwareCampaignUse or any other KEV field; a record that omits
      // one is a record the feed genuinely does not carry it on, which is the
      // input several of these tests are built around.
      vulnerabilities.push({ dateAdded: '2025-01-01', ...c, cveID: c.cveID });
    }
    let n = vulnerabilities.length;
    while (vulnerabilities.length < feedSize) {
      n += 1;
      vulnerabilities.push({ cveID: `CVE-1999-${String(n).padStart(4, '0')}`, dateAdded: '2022-01-01' });
    }
    const feed = { catalogVersion: 'test', vulnerabilities };
    fs.mkdirSync(path.join(dir, 'kev'), { recursive: true });
    const feedPath = path.join(dir, 'kev', 'known_exploited_vulnerabilities.json');
    fs.writeFileSync(feedPath, JSON.stringify(feed, null, 2) + '\n');
    // readCachedJson recomputes sha256 over JSON.stringify(JSON.parse(fileBytes)).
    const reparsed = JSON.parse(fs.readFileSync(feedPath, 'utf8'));
    const sha256 = crypto.createHash('sha256').update(JSON.stringify(reparsed)).digest('hex');
    fs.writeFileSync(path.join(dir, '_index.json'), JSON.stringify({
      generated_at: new Date().toISOString(),
      entries: {
        'kev/known_exploited_vulnerabilities': {
          fetched_at: new Date().toISOString(), etag: null, url: 'x', sha256,
        },
      },
    }, null, 2) + '\n');
  }

  // A curated, strongly-signalled KEV entry shaped like the catalog norm.
  function curatedStrongEntry() {
    return {
      cisa_kev: true,
      cisa_kev_date: '2025-02-13',
      cisa_kev_due_date: '2025-03-06',
      active_exploitation: 'confirmed',
      verification_sources: ['vendor-advisory'],
      rwep_factors: { cisa_kev: 25 },
      rwep_score: 77,
    };
  }

  function makeCtx(dir, cveCatalog) {
    const cvePath = path.join(dir, 'cve-catalog.json');
    fs.writeFileSync(cvePath, JSON.stringify(cveCatalog, null, 2) + '\n');
    return { cacheDir: dir, cveCatalog, cvePath, forceStale: false };
  }

  test('curated strongly-signalled entry missing from a plausible feed is held for review, not de-listed', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2025-1094';
      writeKevCache(tmp, { feedSize: 800, includeCves: [] });
      const catalog = { [cve]: curatedStrongEntry(), _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
      assert.ok(delist, 'a cisa_kev diff for the missing curated CVE must be produced');
      assert.equal(delist.after, false, 'the diff direction is a de-listing (true->false)');
      assert.equal(delist.review_only, true, 'a curated de-listing must be marked review_only');
      assert.equal(delist.kev_delist_review, true);

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev, true, 'curated cisa_kev must SURVIVE the de-listing');
      assert.equal(after.rwep_factors.cisa_kev, 25, 'the KEV RWEP factor must be intact');
      assert.equal(after.rwep_score, 77, 'rwep_score must be unchanged (no 25-pt drop)');
      assert.equal(after.cisa_kev_date, '2025-02-13', 'the listing date must not be cleared');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a genuinely weak entry (no exploitation signal) still de-lists normally against a plausible feed', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2025-9999';
      writeKevCache(tmp, { feedSize: 800, includeCves: [] });
      const weak = {
        cisa_kev: true,
        cisa_kev_date: '2024-06-01',
        active_exploitation: null,
        rwep_factors: { cisa_kev: 25 },
        rwep_score: 60,
      };
      const catalog = { [cve]: weak, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
      assert.ok(delist, 'a de-listing diff must be produced for the weak entry');
      assert.notEqual(delist.review_only, true, 'a weak de-listing must NOT be review_only');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev, false, 'a weak entry must de-list normally');
      assert.equal(after.rwep_factors.cisa_kev, 0, 'the KEV factor zeroes on a real de-listing');
      assert.equal(after.cisa_kev_date, null, 'the orphaned listing date is cleared on de-listing');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('an implausibly small feed refuses ALL de-listings wholesale, even for a weak entry', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2025-7777';
      // A truncated feed (50 entries) — far below a plausible CISA KEV snapshot.
      writeKevCache(tmp, { feedSize: 50, includeCves: [] });
      const weak = {
        cisa_kev: true,
        cisa_kev_date: '2024-06-01',
        active_exploitation: null,
        rwep_factors: { cisa_kev: 25 },
        rwep_score: 60,
      };
      const catalog = { [cve]: weak, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const delist = diffs.find((d) => d.id === cve && d.field === 'cisa_kev' && d.after === false);
      assert.ok(delist, 'a de-listing diff is still produced');
      assert.equal(delist.review_only, true,
        'a truncated feed must hold even a weak de-listing for review');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev, true, 'no de-listing may apply against a truncated feed');
      assert.equal(after.rwep_score, 60, 'rwep_score unchanged under the feed-shrink guard');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a first-listing (false->true) is unaffected by the de-listing guard', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2026-0001';
      // Plausible feed that DOES list the CVE; catalog has it as not-yet-listed.
      writeKevCache(tmp, { feedSize: 800, includeCves: [{ cveID: cve, dateAdded: '2026-05-01' }] });
      const entry = {
        cisa_kev: false,
        cisa_kev_date: null,
        active_exploitation: 'confirmed',
        rwep_factors: { cisa_kev: 0 },
        rwep_score: 40,
      };
      const catalog = { [cve]: entry, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const listing = diffs.find((d) => d.id === cve && d.field === 'cisa_kev');
      assert.ok(listing, 'a first-listing diff must be produced');
      assert.equal(listing.after, true, 'direction is a listing (false->true)');
      assert.notEqual(listing.review_only, true, 'a first-listing must apply directly, not held for review');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev, true, 'the first-listing applies');
      assert.equal(after.rwep_factors.cisa_kev, 25, 'the KEV factor is credited on listing');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a due date CISA has moved is diffed and applied', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2026-0300';
      writeKevCache(tmp, { feedSize: 800, includeCves: [
        { cveID: cve, dateAdded: '2026-05-06', dueDate: '2026-05-09', knownRansomwareCampaignUse: 'Unknown' },
      ] });
      // Curated on the day of listing with a 21-day deadline assumed; CISA's
      // own record says three days.
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2026-05-06', cisa_kev_due_date: '2026-05-27',
        known_ransomware_use: false, rwep_factors: { cisa_kev: 25 }, rwep_score: 70,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const due = diffs.find((d) => d.id === cve && d.field === 'cisa_kev_due_date');
      assert.ok(due, 'a stale remediation deadline must produce a diff');
      assert.equal(due.before, '2026-05-27');
      assert.equal(due.after, '2026-05-09');
      assert.notEqual(due.review_only, true, 'an upstream deadline correction applies directly');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev_due_date, '2026-05-09', 'the catalog carries CISA’s deadline, not an assumed one');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a ransomware designation CISA has added is diffed and applied', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2021-4034';
      writeKevCache(tmp, { feedSize: 800, includeCves: [
        { cveID: cve, dateAdded: '2022-06-27', dueDate: '2022-07-18', knownRansomwareCampaignUse: 'Known' },
      ] });
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2022-06-27', cisa_kev_due_date: '2022-07-18',
        known_ransomware_use: false, rwep_factors: { cisa_kev: 25 }, rwep_score: 70,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const r = diffs.find((d) => d.id === cve && d.field === 'known_ransomware_use');
      assert.ok(r, 'a designation added after listing must produce a diff');
      assert.equal(r.before, false);
      assert.equal(r.after, true);
      assert.notEqual(r.review_only, true, 'an added designation applies directly');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.known_ransomware_use, true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('an entry omitting the ransomware field has it filled from the feed, in both directions', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const designated = 'CVE-2023-3519';
      const plain = 'CVE-2019-11510';
      writeKevCache(tmp, { feedSize: 800, includeCves: [
        { cveID: designated, dateAdded: '2023-07-19', dueDate: '2023-07-21', knownRansomwareCampaignUse: 'Known' },
        { cveID: plain, dateAdded: '2019-11-03', dueDate: '2022-01-24', knownRansomwareCampaignUse: 'Unknown' },
      ] });
      // Neither entry carries known_ransomware_use at all — the shape older
      // hand-curated entries were written in.
      const catalog = {
        [designated]: { cisa_kev: true, cisa_kev_date: '2023-07-19', cisa_kev_due_date: '2023-07-21', rwep_factors: { cisa_kev: 25 }, rwep_score: 70 },
        [plain]: { cisa_kev: true, cisa_kev_date: '2019-11-03', cisa_kev_due_date: '2022-01-24', rwep_factors: { cisa_kev: 25 }, rwep_score: 70 },
        _meta: {},
      };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const dD = diffs.find((d) => d.id === designated && d.field === 'known_ransomware_use');
      const dP = diffs.find((d) => d.id === plain && d.field === 'known_ransomware_use');
      assert.ok(dD, 'an omitted field on a designated CVE must be filled');
      assert.equal(dD.before, null, 'the diff records the omission as null, not as false');
      assert.equal(dD.after, true);
      assert.ok(dP, 'an omitted field is filled even when the answer is false');
      assert.equal(dP.after, false);
      assert.notEqual(dD.review_only, true, 'filling an omission is not a removal and is not held for review');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'));
      assert.equal(after[designated].known_ransomware_use, true);
      assert.equal(after[plain].known_ransomware_use, false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a feed record carrying no ransomware field produces no diff — absence is not a negative', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2023-4863';
      // No knownRansomwareCampaignUse key at all, and no dueDate. Reading the
      // missing field as "Unknown" would propose erasing a curated designation
      // on the strength of data the feed never carried.
      writeKevCache(tmp, { feedSize: 800, includeCves: [{ cveID: cve, dateAdded: '2023-09-13' }] });
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2023-09-13', cisa_kev_due_date: '2023-10-04',
        known_ransomware_use: true, rwep_factors: { cisa_kev: 25 }, rwep_score: 70,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      assert.equal(diffs.filter((d) => d.field === 'known_ransomware_use').length, 0,
        'an absent ransomware field must produce no diff in either direction');
      assert.equal(diffs.filter((d) => d.field === 'cisa_kev_due_date').length, 0,
        'an absent dueDate must not clear a stored deadline');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.known_ransomware_use, true, 'the curated designation survives');
      assert.equal(after.cisa_kev_due_date, '2023-10-04', 'the stored deadline survives');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a ransomware designation REMOVAL is held for review against a truncated feed', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2024-1709';
      writeKevCache(tmp, { feedSize: 50, includeCves: [
        { cveID: cve, dateAdded: '2024-02-22', dueDate: '2024-02-29', knownRansomwareCampaignUse: 'Unknown' },
      ] });
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2024-02-22', cisa_kev_due_date: '2024-02-29',
        known_ransomware_use: true, rwep_factors: { cisa_kev: 25 }, rwep_score: 70,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      const r = diffs.find((d) => d.id === cve && d.field === 'known_ransomware_use');
      assert.ok(r, 'the removal is still surfaced');
      assert.equal(r.after, false);
      assert.equal(r.review_only, true, 'a removal against a truncated feed is held for review');

      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.known_ransomware_use, true, 'the curated designation is not erased');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('--drift-only keeps the reconciliation and drops the discovery adds', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const held = 'CVE-2022-1234';      // in the catalog, with a stale deadline
      const unknown = 'CVE-2026-5555';   // upstream only — discovery would import it
      writeKevCache(tmp, { feedSize: 800, includeCves: [
        { cveID: held, dateAdded: '2022-04-01', dueDate: '2022-04-15', knownRansomwareCampaignUse: 'Unknown' },
        { cveID: unknown, dateAdded: '2026-08-01', dueDate: '2026-08-22', knownRansomwareCampaignUse: 'Known',
          vulnerabilityName: 'Example RCE', shortDescription: 'x', vendorProject: 'Example', product: 'Thing' },
      ] });
      const catalog = { [held]: {
        cisa_kev: true, cisa_kev_date: '2022-04-01', cisa_kev_due_date: '2022-05-01',
        known_ransomware_use: false, rwep_factors: { cisa_kev: 25 }, rwep_score: 70,
      }, _meta: {} };

      const withDiscovery = await ALL_SOURCES.kev.fetchDiff(makeCtx(tmp, JSON.parse(JSON.stringify(catalog))));
      assert.ok(withDiscovery.diffs.some((d) => d.op === 'add'),
        'the default cache path still discovers entries the catalog lacks');

      const ctx = makeCtx(tmp, JSON.parse(JSON.stringify(catalog)));
      ctx.driftOnly = true;
      const driftOnly = await ALL_SOURCES.kev.fetchDiff(ctx);
      assert.equal(driftOnly.diffs.filter((d) => d.op === 'add').length, 0,
        '--drift-only imports nothing new');
      assert.ok(driftOnly.diffs.some((d) => d.id === held && d.field === 'cisa_kev_due_date'),
        'the reconciliation of entries already held is unaffected');
      assert.equal(driftOnly.spilled, 0, 'nothing spills when nothing is discovered');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('a de-listing clears the ransomware designation along with the dates', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2025-9997';
      writeKevCache(tmp, { feedSize: 800, includeCves: [] });
      // Weak entry, so the de-listing applies rather than being held.
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2024-06-01', cisa_kev_due_date: '2024-06-22',
        known_ransomware_use: true, active_exploitation: null,
        rwep_factors: { cisa_kev: 25 }, rwep_score: 60,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      await ALL_SOURCES.kev.applyDiff(ctx, diffs);
      const after = JSON.parse(fs.readFileSync(ctx.cvePath, 'utf8'))[cve];
      assert.equal(after.cisa_kev, false);
      assert.equal(after.known_ransomware_use, null,
        'a designation restating a KEV record that no longer exists cannot survive it');
      assert.equal(after.cisa_kev_date, null);
      assert.equal(after.cisa_kev_due_date, null);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('an entry upstream no longer lists gets no due-date or ransomware diff', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kev-prot-'));
    try {
      const cve = 'CVE-2025-9998';
      writeKevCache(tmp, { feedSize: 800, includeCves: [] });
      const catalog = { [cve]: {
        cisa_kev: true, cisa_kev_date: '2024-06-01', cisa_kev_due_date: '2024-06-22',
        known_ransomware_use: false, active_exploitation: null,
        rwep_factors: { cisa_kev: 25 }, rwep_score: 60,
      }, _meta: {} };
      const ctx = makeCtx(tmp, catalog);

      const { diffs } = kevDiffFromCache(ctx);
      assert.equal(diffs.filter((d) => d.field === 'cisa_kev_due_date' || d.field === 'known_ransomware_use').length, 0,
        'a de-listing is the only thing to say about an entry the feed dropped');
      assert.ok(diffs.some((d) => d.field === 'cisa_kev' && d.after === false), 'the de-listing itself still fires');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('RC-1: the LIVE KEV path holds a curated-exploitation de-listing for review (not just --from-cache)', async () => {
    // fetchDiff lazily requires ../sources/validators; swap it in require.cache so
    // we can drive a de-listing discrepancy without any network call.
    const validatorsPath = require.resolve('../sources/validators');
    const orig = require.cache[validatorsPath];
    require.cache[validatorsPath] = {
      id: validatorsPath, filename: validatorsPath, loaded: true, exports: {
        validateAllCves: async () => ({
          total: 1,
          results: [{
            cve_id: 'CVE-2099-0001', status: 'ok',
            discrepancies: [{ field: 'cisa_kev', local: true, fetched: false, severity: 'high' }],
          }],
        }),
      },
    };
    try {
      const kev = ALL_SOURCES['kev'];
      // Confirmed-exploitation entry → de-listing must be review_only.
      const strong = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { active_exploitation: 'confirmed', cisa_kev: true } } });
      const ds = strong.diffs.find((x) => x.field === 'cisa_kev');
      assert.ok(ds, 'a cisa_kev de-listing diff is produced');
      assert.equal(ds.review_only, true, 'a curated-exploitation de-listing must be held for review on the live path');
      // Weak entry (no exploitation signal) → de-lists normally.
      const weak = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
      const dw = weak.diffs.find((x) => x.field === 'cisa_kev');
      assert.ok(!dw.review_only, 'a weak-signal de-listing is not held for review');
    } finally {
      if (orig) require.cache[validatorsPath] = orig; else delete require.cache[validatorsPath];
    }
  });

  test('the LIVE KEV path reconciles the deadline and the ransomware designation, not just the flag', async () => {
    // The cache path and the live path must cover the same field set. Filtering
    // the live discrepancies to cisa_kev/cisa_kev_date left the other two
    // reconciling only under --from-cache, which is not the default.
    const validatorsPath = require.resolve('../sources/validators');
    const orig = require.cache[validatorsPath];
    require.cache[validatorsPath] = {
      id: validatorsPath, filename: validatorsPath, loaded: true, exports: {
        validateAllCves: async () => ({
          total: 1,
          results: [{
            cve_id: 'CVE-2099-0002', status: 'drift',
            fetched: { sources: { kev: { reachable: true, total_entries: 1600 } } },
            discrepancies: [
              { field: 'cisa_kev_due_date', local: '2026-05-27', fetched: '2026-05-09', severity: 'medium' },
              { field: 'known_ransomware_use', local: false, fetched: true, severity: 'medium' },
            ],
          }],
        }),
      },
    };
    try {
      const kev = ALL_SOURCES['kev'];
      const r = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0002': { cisa_kev: true } } });
      const due = r.diffs.find((d) => d.field === 'cisa_kev_due_date');
      const ransom = r.diffs.find((d) => d.field === 'known_ransomware_use');
      assert.ok(due, 'the live path must emit a due-date diff');
      assert.equal(due.after, '2026-05-09');
      assert.ok(ransom, 'the live path must emit a ransomware diff');
      assert.equal(ransom.after, true);
      assert.notEqual(ransom.review_only, true, 'an added designation applies against a plausible feed');
    } finally {
      if (orig) require.cache[validatorsPath] = orig; else delete require.cache[validatorsPath];
    }
  });

  test('the LIVE path holds a ransomware designation REMOVAL against an implausibly small feed', async () => {
    const validatorsPath = require.resolve('../sources/validators');
    const orig = require.cache[validatorsPath];
    require.cache[validatorsPath] = {
      id: validatorsPath, filename: validatorsPath, loaded: true, exports: {
        validateAllCves: async () => ({
          total: 1,
          results: [{
            cve_id: 'CVE-2099-0003', status: 'drift',
            fetched: { sources: { kev: { reachable: true, total_entries: 12 } } },
            discrepancies: [{ field: 'known_ransomware_use', local: true, fetched: false, severity: 'medium' }],
          }],
        }),
      },
    };
    try {
      const kev = ALL_SOURCES['kev'];
      const r = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0003': { cisa_kev: true } } });
      const ransom = r.diffs.find((d) => d.field === 'known_ransomware_use');
      assert.ok(ransom, 'the removal is still surfaced');
      assert.equal(ransom.review_only, true, 'a truncated live feed must not erase a curated designation');
    } finally {
      if (orig) require.cache[validatorsPath] = orig; else delete require.cache[validatorsPath];
    }
  });

  test('RC-4b: the LIVE KEV path holds ALL de-listings when the live feed is implausibly small (parity with kevDiffFromCache)', async () => {
    const validatorsPath = require.resolve('../sources/validators');
    const orig = require.cache[validatorsPath];
    function mockFeed(totalEntries, { local = true, fetched = false } = {}) {
      require.cache[validatorsPath] = {
        id: validatorsPath, filename: validatorsPath, loaded: true, exports: {
          validateAllCves: async () => ({
            total: 1,
            results: [{
              cve_id: 'CVE-2099-0001', status: 'drift',
              fetched: totalEntries === undefined
                ? {}
                : { sources: { kev: { reachable: true, total_entries: totalEntries } } },
              discrepancies: [{ field: 'cisa_kev', local, fetched, severity: 'high' }],
            }],
          }),
        },
      };
    }
    try {
      const kev = ALL_SOURCES['kev'];
      // 12-entry feed + a weak (non-curated) entry → must be held for review.
      mockFeed(12);
      const tiny = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
      const dTiny = tiny.diffs.find((x) => x.field === 'cisa_kev' && x.after === false);
      assert.ok(dTiny, 'a cisa_kev de-listing diff is produced');
      assert.equal(dTiny.review_only, true, 'an implausibly small live feed must hold even a non-curated de-listing for review');
      assert.equal(dTiny.kev_delist_review, true, 'the live de-listing review carries the kev_delist_review marker (cache parity)');

      // An empty-but-valid feed (total_entries 0) is the maximal blast-radius case.
      mockFeed(0);
      const empty = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
      const dEmpty = empty.diffs.find((x) => x.field === 'cisa_kev' && x.after === false);
      assert.equal(dEmpty.review_only, true, 'an empty live feed (0 entries) must hold de-listings for review');

      // A plausible feed (800) + non-curated entry → de-lists normally (no regression).
      mockFeed(800);
      const plausible = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
      const dPlaus = plausible.diffs.find((x) => x.field === 'cisa_kev' && x.after === false);
      assert.notEqual(dPlaus.review_only, true, 'a plausible feed de-lists a non-curated entry normally');

      // Feed size unknown (no total_entries on any result) → fall back to the
      // per-entry curated-signal guard.
      mockFeed(undefined);
      const unknown = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: true } } });
      const dUnknown = unknown.diffs.find((x) => x.field === 'cisa_kev' && x.after === false);
      assert.notEqual(dUnknown.review_only, true, 'unknown live feed size falls back to the curated-only guard');

      // A first-listing (false→true) against a tiny feed is never held.
      mockFeed(12, { local: false, fetched: true });
      const listing = await kev.fetchDiff({ cveCatalog: { 'CVE-2099-0001': { cisa_kev: false } } });
      const dListing = listing.diffs.find((x) => x.field === 'cisa_kev' && x.after === true);
      assert.notEqual(dListing.review_only, true, 'a first-listing is never held by the feed-size guard');
    } finally {
      if (orig) require.cache[validatorsPath] = orig; else delete require.cache[validatorsPath];
    }
  });
});

// ===========================================================================
// refresh-from-cache-no-egress — GHSA/OSV cache-skip (no live fetch)
//
// --from-cache is the offline ingest path: every source reads only local cache
// files and never the network. GHSA and OSV have no cache layer, so they
// previously fell through to a live api.github.com / osv.dev fetch when a
// cacheDir was set but --air-gap was not. Both must now return a structured skip
// whenever ctx.cacheDir is present.
// ===========================================================================

test_describe('refresh-from-cache-no-egress', () => {
  const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));

  test('GHSA fetchDiff returns a structured cache skip (no live fetch) when cacheDir is set', async () => {
    const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false };
    const r = await ALL_SOURCES.ghsa.fetchDiff(ctx);
    assert.equal(r.status, 'unreachable');
    assert.equal(r.errors, 0);
    assert.deepEqual(r.diffs, []);
    assert.equal(typeof r.summary, 'string');
    assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
  });

  test('OSV fetchDiff returns a structured cache skip (no live fetch) when cacheDir is set', async () => {
    const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false };
    const r = await ALL_SOURCES.osv.fetchDiff(ctx);
    assert.equal(r.status, 'unreachable');
    assert.equal(r.errors, 0);
    assert.deepEqual(r.diffs, []);
    assert.equal(typeof r.summary, 'string');
    assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
  });

  test('cache skip holds even when osv_ids would otherwise drive a live lookup', async () => {
    // ctx.osv_ids populated is the only thing that makes OSV reach the network;
    // the cache-skip branch must win so a seeded id never egresses offline.
    const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: false, osv_ids: ['MAL-2026-0001'] };
    const r = await ALL_SOURCES.osv.fetchDiff(ctx);
    assert.equal(r.status, 'unreachable');
    assert.deepEqual(r.diffs, []);
    assert.match(r.summary, /no cache layer; skipped in --from-cache mode/);
  });

  test('air-gap fixture path is unaffected by the cache-skip branch (fixtures win)', async () => {
    // A configured GHSA fixture must still be honored; the cache skip only fires
    // when there is no fixture for the source.
    const ctx = { cacheDir: '/nonexistent/cache', cveCatalog: {}, airGap: true, fixtures: {} };
    // No ghsa fixture configured -> cache skip applies.
    const r = await ALL_SOURCES.ghsa.fetchDiff(ctx);
    assert.equal(r.status, 'unreachable');
    assert.match(r.summary, /no cache layer/);
  });
});

// ===========================================================================
// refresh-nvd-cvss-downgrade — nvdDiffFromCache cross-version guard
//
// The NVD apply must not downgrade a curated higher-version CVSS to NVD's legacy
// v2 metric. nvdDiffFromCache selects the newest CVSS version (Primary within
// it), normalizes a bare v2 vector, and suppresses BOTH the score and vector
// diff whenever the upstream metric is an older CVSS version than the curated
// one. Offline only.
// ===========================================================================

test_describe('refresh-nvd-cvss-downgrade', () => {
  const crypto = require('crypto');
  const { nvdDiffFromCache } = require('../lib/refresh-external');

  // Strict prefix the validation gate enforces.
  const STRICT = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

  function writeNvdCache(cacheDir, id, payload) {
    fs.mkdirSync(path.join(cacheDir, 'nvd'), { recursive: true });
    // nvdDiffFromCache resolves the record by cve.id — stamp the requested id
    // onto the record so the id-match path binds (the hash is computed below,
    // after the id is set, so on-disk bytes and recorded sha stay in sync).
    if (payload?.vulnerabilities?.[0]?.cve && payload.vulnerabilities[0].cve.id == null) {
      payload.vulnerabilities[0].cve.id = id;
    }
    fs.writeFileSync(path.join(cacheDir, 'nvd', `${id}.json`), JSON.stringify(payload, null, 2) + '\n');
    const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const idxPath = path.join(cacheDir, '_index.json');
    let idx;
    try { idx = JSON.parse(fs.readFileSync(idxPath, 'utf8')); } catch { idx = { entries: {} }; }
    idx.entries[`nvd/${id}`] = { sha256: sha, fetched_at: new Date().toISOString(), url: 'test' };
    fs.writeFileSync(idxPath, JSON.stringify(idx, null, 2) + '\n');
  }

  function nvdPayload(buckets) {
    return { vulnerabilities: [{ cve: { metrics: buckets } }] };
  }

  function run(localEntry, buckets) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nvd-downgrade-'));
    try {
      const id = 'CVE-2008-4250';
      writeNvdCache(tmp, id, nvdPayload(buckets));
      const ctx = { cacheDir: tmp, cveCatalog: { [id]: localEntry }, forceStale: false };
      return { id, ...nvdDiffFromCache(ctx) };
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  test('nvdDiffFromCache is exported for direct testing', () => {
    assert.equal(typeof nvdDiffFromCache, 'function');
  });

  test('v2-Primary + v3.1-Secondary against a curated v3.1 entry emits NO diff (the shipped-bug repro)', () => {
    const r = run(
      { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8 },
      {
        cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
        cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }],
      },
    );
    assert.equal(r.errors, 0);
    assert.equal(r.diffs.filter((d) => d.field === 'cvss_vector').length, 0, 'must not rewrite the curated v3.1 vector to bare v2');
    assert.equal(r.diffs.filter((d) => d.field === 'cvss_score').length, 0, 'must not downgrade the curated v3.1 score to the v2 score');
    assert.deepEqual(r.diffs, []);
  });

  test('downgrade-guard: v2-only upstream against a curated v3.1 entry emits NOTHING (vector AND score)', () => {
    // NVD never re-scored this CVE to v3.x; the catalog was curated to v3.1.
    const r = run(
      { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8 },
      { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 5.0, vectorString: 'AV:N/AC:L/Au:N/C:P/I:N/A:N' } }] },
    );
    assert.deepEqual(r.diffs, [], 'a strictly-older upstream version must suppress both the score and vector diff');
  });

  test('legitimate upgrade: local v3.0, upstream v3.1 still emits a diff (guard blocks only downgrades)', () => {
    const r = run(
      { cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.0 },
      { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
    );
    const vec = r.diffs.find((d) => d.field === 'cvss_vector');
    const score = r.diffs.find((d) => d.field === 'cvss_score');
    assert.ok(vec, 'a genuine newer-version upstream must still produce a vector diff');
    assert.equal(vec.after, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    assert.ok(score, 'and the accompanying score move');
    assert.equal(score.after, 9.8);
  });

  test('same-version score drift on a curated entry is surfaced but held for review (not a downgrade)', () => {
    // Catalog score hand-adjusted to 9.3 vs NVD v3.1 9.8 — a legitimate same-
    // version drift the refresh surfaces. The default catalog entry is
    // curator-owned (no _auto_imported flag), so the drift is held for review.
    const r = run(
      { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.3 },
      { cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
    );
    assert.equal(r.diffs.filter((d) => d.field === 'cvss_vector').length, 0, 'vectors match -> no vector diff');
    const score = r.diffs.find((d) => d.field === 'cvss_score');
    assert.ok(score && score.after === 9.8, 'same-version score drift is surfaced');
    assert.equal(score.review_only, true, 'a curator-owned entry holds the drift for review, not auto-applied');
  });

  test('same-version score drift on a raw auto-imported entry applies (not curator-owned)', () => {
    // An _auto_imported draft is not yet curated — NVD is its source of truth.
    const r = run(
      { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.3, _auto_imported: true },
      { cvssMetricV31: [{ type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
    );
    const score = r.diffs.find((d) => d.field === 'cvss_score');
    assert.ok(score && score.after === 9.8, 'a raw entry surfaces the same-version drift');
    assert.notEqual(score.review_only, true, 'a raw auto-imported entry applies the NVD re-score directly');
  });

  test('bare v2 upstream against a curated v2.0 entry: normalized, no spurious diff, validator-legal', () => {
    const r = run(
      { cvss_vector: 'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C', cvss_score: 10 },
      { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }] },
    );
    assert.deepEqual(r.diffs, [], 'normalizing the bare upstream vector to CVSS:2.0/ avoids a prefix-only churn diff');
  });

  test('any vector this apply would write is strict-validator-legal', () => {
    // A v2-only CVE whose catalog entry is (legitimately) still v2.
    const r = run(
      { cvss_vector: 'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:P', cvss_score: 5.0 },
      { cvssMetricV2: [{ type: 'Primary', cvssData: { version: '2.0', baseScore: 7.5, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' } }] },
    );
    for (const d of r.diffs.filter((x) => x.field === 'cvss_vector')) {
      assert.ok(STRICT.test(d.after), `apply must never write a vector that fails --strict: ${d.after}`);
    }
  });
});

// ===========================================================================
// refresh-swarm — lib/refresh-external.js --swarm + --from-cache + --from-fixture
// ===========================================================================

test_describe('refresh-swarm', () => {
  const FIX_SWARM = path.join(ROOT, 'tests', 'fixtures', 'refresh');

  let SWARM_REPORT;
  function mkSwarmReport() {
    SWARM_REPORT = path.join(os.tmpdir(), `refresh-report-swarm-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    return SWARM_REPORT;
  }

  function runSwarm(args) {
    const reportPath = mkSwarmReport();
    return spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-fixture', FIX_SWARM, '--quiet', '--report-out', reportPath, ...args],
      { encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
    );
  }

  test('refresh-external --swarm + --from-fixture: report is shape-identical to sequential', () => {
    const seq = runSwarm([]);
    assert.equal(seq.status, 0);
    const seqReport = JSON.parse(fs.readFileSync(SWARM_REPORT, 'utf8'));
    delete seqReport.generated_at;
    delete seqReport.swarm;
    const swarm = runSwarm(['--swarm']);
    assert.equal(swarm.status, 0);
    const swarmReport = JSON.parse(fs.readFileSync(SWARM_REPORT, 'utf8'));
    assert.equal(swarmReport.swarm, true);
    delete swarmReport.generated_at;
    delete swarmReport.swarm;
    assert.deepEqual(swarmReport, seqReport, 'swarm and sequential reports diverge');
  });

  test('refresh-external --from-cache reads kev/epss/nvd/rfc/pins from a cache dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'refresh-cache-'));
    try {
      // Seed minimal cache entries matching the prefetch layout.
      fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'),
        JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-43284', dateAdded: '2026-04-01' }] }));
      fs.mkdirSync(path.join(tmp, 'nvd'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'epss'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'rfc'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'pins'), { recursive: true });
      // Empty index file is fine; the source modules tolerate cache misses.
      fs.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({ generated_at: new Date().toISOString(), entries: {} }));

      const reportPath = mkSwarmReport();
      const r = spawnSync(
        process.execPath,
        // --force-stale bypasses the `_index.json.sig` requirement + max-age
        // check; this test seeds a minimal cache with empty entries + no
        // signature, which the production gate (correctly) refuses.
        [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-cache', tmp, '--source', 'kev', '--force-stale', '--quiet', '--report-out', reportPath],
        { encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
      );
      assert.equal(r.status, 0, `stderr: ${r.stderr}`);
      const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      assert.equal(report.cache_mode, true);
      // KEV catalog has CVE-2026-43284 NOT in KEV locally; cache says it IS in KEV.
      const diffs = report.sources.kev.diffs;
      assert.ok(diffs.some((d) => d.id === 'CVE-2026-43284' && d.field === 'cisa_kev' && d.after === true));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('refresh-external --from-fixture populates ctx.fixtures.advisories (no live-RSS fall-through)', () => {
    // Before this fix, --from-fixture loaded payloads for kev / epss / nvd / rfc
    // / pins / ghsa / osv but left the advisories poller unfixturized — it fell
    // through to live RSS feeds. Two back-to-back fixture-mode runs hit moving
    // upstream data and diverged, surfacing as a CI flake. This pins that the
    // advisories diffs come from the frozen fixture, not from the network.
    const reportPath = mkSwarmReport();
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-fixture', FIX_SWARM, '--source', 'advisories', '--quiet', '--report-out', reportPath],
      { encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
    );
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    const advisories = report.sources && report.sources.advisories;
    assert.ok(advisories, 'advisories source must appear in report');
    assert.equal(advisories.status, 'ok',
      `advisories status must be ok in fixture mode; got ${advisories.status}`);
    // The fixture covers N feeds; the summary line states reachable count. Assert
    // by-N-equals-feed-count rather than a literal so future intake expansions
    // don't require a test edit.
    const SOURCE = require(path.join(ROOT, 'lib', 'source-advisories.js'));
    const expectedFeedCount = SOURCE.FEEDS.length;
    assert.match(
      advisories.summary || '',
      new RegExp(expectedFeedCount + '/' + expectedFeedCount + ' feeds reachable'),
      `fixture-mode must report ${expectedFeedCount}/${expectedFeedCount} feeds reachable (proves frozen content was used, not live fetch); got: ${advisories.summary}`,
    );
    assert.equal(advisories.errors, 0,
      'fixture-mode advisories must produce zero feed errors');
  });

  test('refresh-external --from-cache <nonexistent> exits 2 (generic hint refusal)', () => {
    // The missing-cache branch throws a hint error without setting
    // _exceptd_exit_code, so the top-level handler defaults to exit 2 (generic
    // refusal). Signature-validation refusals set _exceptd_exit_code = 4. Pin
    // the exact value so a future change that moves missing-cache to a different
    // code surfaces here.
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-cache', '/does/not/exist/cache', '--quiet'],
      { encoding: 'utf8', cwd: ROOT }
    );
    assert.equal(r.status, 2, `expected exit 2 (missing-cache refusal); got ${r.status}; stderr: ${r.stderr}`);
  });
});

// ===========================================================================
// refresh-prefetch-source-validation — refresh --prefetch source-subset gate
//
// refresh --prefetch / --no-network validates --source against the prefetchable
// (cache-backed) subset before delegating to the prefetch cache warmer. Scoping
// a cache-warm to a live-only source (ghsa/osv/advisories/cve-regression-watcher)
// must refuse with a refresh-prefixed, actionable message, never the internal
// `prefetch: fatal` string. Offline only (every case runs --no-network).
// ===========================================================================

test_describe('refresh-prefetch-source-validation', () => {
  const REFRESH = path.join(ROOT, 'lib', 'refresh-external.js');

  function run(args) {
    return spawnSync(process.execPath, [REFRESH, ...args], { encoding: 'utf8' });
  }

  function lastJson(stream) {
    const line = (stream || '').trim().split('\n').pop();
    try { return JSON.parse(line); } catch { return null; }
  }

  for (const src of ['osv', 'ghsa', 'advisories', 'cve-regression-watcher']) {
    test(`refresh --prefetch --source ${src} refuses with a refresh-prefixed message, not "prefetch: fatal"`, () => {
      const r = run(['--prefetch', '--source', src, '--no-network']);
      assert.equal(r.status, 2, `${src} must exit exactly 2; stderr=${r.stderr}`);
      assert.doesNotMatch(r.stderr || '', /prefetch: fatal/,
        'must not leak the internal cache-warmer verb name');
      const body = lastJson(r.stderr);
      assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
      assert.equal(body.ok, false);
      assert.equal(body.verb, 'refresh');
      assert.match(body.error, new RegExp(src.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')),
        'the error must name the unsupported source');
      assert.match(body.error, /prefetchable sources: kev,nvd,epss,rfc,pins/,
        'the error must list the prefetchable subset');
    });
  }

  test('refresh --prefetch --source kev,osv reports only osv as unsupported (the valid one is not the complaint)', () => {
    const r = run(['--prefetch', '--source', 'kev,osv', '--no-network']);
    assert.equal(r.status, 2, `mixed scope must exit 2; stderr=${r.stderr}`);
    const body = lastJson(r.stderr);
    assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
    assert.match(body.error, /osv/, 'osv (the unsupported one) must be named');
    assert.doesNotMatch(body.error, /"kev"/, 'kev (the valid one) must not be flagged');
  });

  test('refresh --prefetch --source bogus reports a genuinely-unknown source distinctly', () => {
    const r = run(['--prefetch', '--source', 'bogus', '--no-network']);
    assert.equal(r.status, 2, `unknown source must exit 2; stderr=${r.stderr}`);
    const body = lastJson(r.stderr);
    assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
    assert.equal(body.verb, 'refresh');
    assert.match(body.error, /unknown source "bogus"/);
    assert.doesNotMatch(r.stderr || '', /prefetch: fatal/);
  });

  test('refresh --prefetch --source kev (a prefetchable source) delegates normally and exits 0', () => {
    const r = run(['--prefetch', '--source', 'kev', '--no-network']);
    assert.equal(r.status, 0, `kev is cacheable; --no-network dry-run must exit 0; stderr=${r.stderr}`);
    // The cache warmer ran (its dry-run summary surfaces) — proof the valid
    // scope was forwarded rather than rejected.
    assert.match(r.stdout, /\[kev\]/, 'the kev source must have been planned by the cache warmer');
  });
});

// ===========================================================================
// refresh-prefetch-populate-hint (direct refresh-external.js entrypoint)
//
// The cache-populate command is `exceptd refresh --prefetch`. `--no-network` is
// the report-only dry run. These pin the missing-path hint + the direct
// entrypoint's report-only behavior (the help surface lives in refresh.test.js).
// ===========================================================================

test_describe('refresh-prefetch-populate-hint', () => {
  const refresh = require(path.join(ROOT, 'lib', 'refresh-external.js'));

  test('the --from-cache missing-path hint points at --prefetch to populate, never --no-network', () => {
    const missing = path.join(os.tmpdir(), 'exceptd-no-such-cache-' + process.pid + '-' + (process.hrtime.bigint?.() ?? ''));
    try { fs.rmSync(missing, { recursive: true, force: true }); } catch { /* absent already */ }

    let threw = null;
    try { refresh.loadCtx({ fromCache: missing }); }
    catch (e) { threw = e; }

    assert.ok(threw, 'loadCtx({fromCache: <missing>}) must throw the missing-path error');
    const msg = String(threw.message);
    assert.match(msg, /--from-cache path does not exist/, 'the missing-path error fires');
    assert.match(msg, /exceptd refresh --prefetch/, 'the populate hint names --prefetch');
    assert.doesNotMatch(msg, /exceptd refresh --no-network/,
      'the hint must not tell operators to populate with --no-network (a dry run that writes nothing)');
  });

  test('the direct refresh-external entrypoint honors --no-network as report-only (no live refresh loop, no refresh-report.json)', () => {
    // Operators/tests invoking the script directly (not via bin/exceptd.js) must
    // get the report-only behavior the help promises — the direct path used to
    // treat --no-network as a no-op and fall through to the live refresh loop,
    // which egresses and writes refresh-report.json. The fix delegates to
    // prefetch (report-only), exactly as the operator path does.
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-refresh-direct-'));
    try {
      const r = spawnSync(process.execPath,
        [path.join(ROOT, 'lib', 'refresh-external.js'), '--no-network', '--source', 'kev', '--quiet'],
        { cwd: work, encoding: 'utf8', timeout: 30000, env: { ...process.env, EXCEPTD_AIR_GAP: '1' } });
      assert.equal(r.status, 0, `direct refresh --no-network must exit 0 (report-only); stderr=${r.stderr.slice(0, 300)}`);
      // The live refresh loop writes refresh-report.json; the report-only
      // prefetch delegate does not. Its absence proves the delegation fired.
      assert.equal(fs.existsSync(path.join(work, 'refresh-report.json')), false,
        'a report-only --no-network run must NOT write refresh-report.json (that would mean the live refresh loop ran)');
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
    }
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

test('refresh parseArgs: --check-advisories is report-only and source-scoped', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const a = parseArgs(['node', 'x', '--check-advisories']);
  assert.equal(a.source, 'advisories');
  assert.equal(a.apply, false);
  assert.equal(a.checkAdvisories, true);
  // --apply must NOT flip a check-advisories run to write mode, regardless of order.
  const b = parseArgs(['node', 'x', '--check-advisories', '--apply']);
  assert.equal(b.apply, false);
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

test('v0.12 refresh --advisory <CVE> dry-run emits draft + exits 3', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1' },
  });
  assert.equal(r.status, 3, '--advisory dry-run must exit 3 ("draft prepared, not applied")');
  const data = tryJson(r.stdout);
  assert.ok(data, 'JSON output must parse');
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'CVE-9999-99999');
  assert.equal(data.draft._auto_imported, true);
});

test('v0.12 refresh --advisory --apply writes draft to a copy of the catalog', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  // Never write to ROOT/data/cve-catalog.json from a test. A mutate-and-
  // restore-in-`finally{}` pattern would leak a synthetic CVE-9999-*
  // draft into the live catalog if a Ctrl-C / OOM / power-loss landed
  // between mutation and restore. refresh-external supports
  // `--catalog <path>`; point it at the tempdir copy.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cve-cat-'));
  const tmpCatalog = path.join(tmpDir, 'cve-catalog.json');
  fs.copyFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), tmpCatalog);
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--apply', '--catalog', tmpCatalog, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, '--advisory --apply exits 3 (applied, editorial-review pending)');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'advisory-seed-applied');
    const catAfter = JSON.parse(fs.readFileSync(tmpCatalog, 'utf8'));
    assert.ok(catAfter['CVE-9999-99999'], 'draft entry must be written');
    assert.equal(catAfter['CVE-9999-99999']._auto_imported, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-F-refresh-net ----
require("node:test").describe("hunt-fix-F-refresh-net", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hunt-fix-F-refresh-net.test.js
 *
 * Regression pins for the F-refresh-net cluster:
 *   #15 — cve-regression-watcher (NEW-CTRL-074) was dead in production: the
 *         refresh orchestrator never threaded the advisories source's
 *         observations onto ctx, so the watcher always saw empty input and
 *         evaluated zero observations. Now main()'s source loop threads
 *         ctx.advisoriesObservations (preferred) + ctx.advisoriesDiffs
 *         between advisories and the watcher (sequential AND --swarm).
 *   #16 — `refresh --network --air-gap` was silently bypassed when
 *         EXCEPTD_REGISTRY_FIXTURE was set; the air-gap refusal is now
 *         unconditional w.r.t. the fixture env var.
 *   #48 — content-only regression candidates were not deduplicated across
 *         feeds (unlike CVE-id-bearing candidates); now grouped by a stable
 *         key with merged surfaced_by.
 *   #51 — isAllowedTarballHost validated u.hostname but the connect reused
 *         u.host (port-inclusive); the guard now rejects a non-default port.
 *
 * Each case fails on the pre-fix behavior and passes after.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const REFRESH_EXTERNAL = path.join(ROOT, 'lib', 'refresh-external.js');
const REFRESH_NETWORK = path.join(ROOT, 'lib', 'refresh-network.js');
const ADV_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'refresh', 'advisories.json');

const WATCHER = require(path.join(ROOT, 'lib', 'cve-regression-watcher.js'));
const { isAllowedTarballHost } = require(REFRESH_NETWORK);

// ---------------------------------------------------------------------------
// Helper: build an isolated fixture dir with the advisories feed bodies (which
// reference the historical CVE-2020-17103 inline) and a custom CVE catalog
// where CVE-2020-17103 is a DIRECT key with no *-REREGRESSION-<year> entry, so
// the watcher's verdict is the unambiguous `annotate`.
// ---------------------------------------------------------------------------
function buildChainFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-F-chain-'));
  fs.copyFileSync(ADV_FIXTURE, path.join(dir, 'advisories.json'));
  const catalogPath = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(catalogPath, JSON.stringify({
    _meta: { schema_version: '1.0.0' },
    'CVE-2020-17103': { aliases: [] },
  }));
  return { dir, catalogPath };
}

function runChain(extraArgs) {
  const { dir, catalogPath } = buildChainFixture();
  const reportPath = path.join(dir, 'report.json');
  const args = [
    REFRESH_EXTERNAL,
    '--from-fixture', dir,
    '--catalog', catalogPath,
    '--source', 'advisories,cve-regression-watcher',
    '--report-out', reportPath,
    '--quiet',
    ...(extraArgs || []),
  ];
  const r = spawnSync(process.execPath, args, {
    env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' },
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  return { r, report };
}

// ===========================================================================
// #15 — the chaining is wired end-to-end through the real CLI source loop.
//       These spawn the orchestrator so they exercise the EXACT broken wiring
//       (the prior unit tests passed through fetchDiff(ctx) directly and
//       bypassed it).
// ===========================================================================




// ===========================================================================
// #16 — air-gap refusal is unconditional w.r.t. EXCEPTD_REGISTRY_FIXTURE.
// ===========================================================================


// ===========================================================================
// #48 — content-only candidate dedup / source-merge across feeds.
// ===========================================================================




// ===========================================================================
// #51 — host-allowlist port hole.
// ===========================================================================

test('#15 sequential: advisories observations are threaded into the watcher', () => {
  const { r, report } = runChain([]);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 400)})`);

  const watcher = report.sources['cve-regression-watcher'];
  assert.equal(typeof watcher, 'object', 'watcher source must be present in the report');

  // Pre-fix: input was empty -> evaluated 0, diff_count 0. Assert the EXACT
  // non-zero evaluated count (>= 1) that distinguishes fixed from broken.
  assert.equal(watcher.diff_count, 1, 'exactly one candidate must surface from the threaded observations');
  assert.match(watcher.summary, /evaluated [1-9]\d* poller observations/,
    'summary must report a NON-ZERO evaluated-observations count');
  assert.doesNotMatch(watcher.summary, /evaluated 0 /,
    'a fixed pipeline must never report "evaluated 0" here');

  // The chaining selected the preferred observations field, not the fallback.
  assert.equal(watcher._meta.input_field_used, 'advisoriesObservations',
    'watcher must consume the threaded advisoriesObservations, not the diffs fallback');

  // Content-shape, not just field-presence: the candidate is the in-catalog
  // historical CVE routed to annotate, surfaced by both press feeds.
  const cand = watcher.diffs.find((d) => d.historical_cve === 'CVE-2020-17103');
  assert.equal(typeof cand, 'object', 'the historical CVE candidate must be present');
  assert.equal(cand.action, 'annotate',
    'the in-catalog historical CVE (no REREGRESSION entry) must route to annotate');
  assert.deepEqual(cand.surfaced_by.slice().sort(),
    ['bleepingcomputer-security', 'thehackernews'],
    'surfaced_by must list both press feeds that referenced CVE-2020-17103');

  // The orchestrator persists the advisories observations into the report so
  // the chaining is observable.
  const adv = report.sources['advisories'];
  assert.ok(Array.isArray(adv.observations), 'advisories source must persist observations[]');
  assert.equal(adv.observations.length, 1, 'one deduplicated CVE observation');
  assert.equal(adv.observations[0].id, 'CVE-2020-17103');
});

test('#15 --swarm: the watcher runs in a second pass and still sees the observations', () => {
  const { r, report } = runChain(['--swarm']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 400)})`);

  const watcher = report.sources['cve-regression-watcher'];
  assert.equal(watcher.diff_count, 1, 'swarm second-pass must still surface the candidate');
  assert.equal(watcher._meta.input_field_used, 'advisoriesObservations',
    'swarm second-pass must read the resolved advisories observations');
  assert.match(watcher.summary, /evaluated [1-9]/, 'swarm: non-zero evaluated count');

  // Declared --source order (advisories, cve-regression-watcher) must be
  // preserved in the report even though the watcher ran in a later pass.
  const keys = Object.keys(report.sources);
  assert.deepEqual(
    keys.filter((k) => k === 'advisories' || k === 'cve-regression-watcher'),
    ['advisories', 'cve-regression-watcher'],
    'report must preserve the operator-declared source order',
  );
});

test('#15 --swarm: watcher selected WITHOUT advisories does not crash (empty-input contract)', () => {
  const { dir, catalogPath } = buildChainFixture();
  const reportPath = path.join(dir, 'report.json');
  const r = spawnSync(process.execPath, [
    REFRESH_EXTERNAL,
    '--from-fixture', dir,
    '--catalog', catalogPath,
    '--source', 'cve-regression-watcher',
    '--report-out', reportPath,
    '--quiet', '--swarm',
  ], { env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' }, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  assert.equal(r.status, 0, `watcher-alone swarm must not crash; got ${r.status} (${r.stderr.slice(0, 300)})`);
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  assert.equal(report.sources['cve-regression-watcher'].diff_count, 0,
    'no advisories selected -> watcher legitimately evaluates an empty input');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from kev-applydiff-rwep ----
require("node:test").describe("kev-applydiff-rwep", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * KEV applyDiff must keep RWEP coherent with the cisa_kev flag.
 *
 * The first scheduled refresh to apply a real KEV listing wrote
 * cisa_kev: true onto an entry without touching rwep_factors or
 * rwep_score, leaving the catalog failing scoring.validate()'s sum
 * invariant (stored 45 vs computed 70 — the delta is exactly the
 * RWEP_WEIGHTS.cisa_kev contribution). The fix recomputes the factor and
 * the stored score inside the same apply, honouring whichever factor
 * shape the entry stores (Shape A boolean / Shape B post-weight).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));

function makeCatalog(entry) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-rwep-'));
  const p = path.join(dir, 'cve-catalog.json');
  fs.writeFileSync(p, JSON.stringify({ 'CVE-2099-0001': entry }, null, 2));
  return p;
}

function readCatalog(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('cisa_kev false→true adds the KEV factor and recomputes rwep_score (Shape B)', async () => {
  const p = makeCatalog({
    cisa_kev: false,
    rwep_factors: { cisa_kev: 0, poc_available: 20, active_exploitation: 20, blast_radius: 5 },
    rwep_score: 45,
  });
  const r = await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  assert.equal(r.updated, 1, 'one entry updated');
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev,
    'Shape-B factor must store the post-weight KEV contribution');
  assert.equal(e.rwep_score, 45 + scoring.RWEP_WEIGHTS.cisa_kev,
    'rwep_score must gain exactly the KEV weight — the sum invariant scoring.validate() enforces');
});

test('cisa_kev true→false removes the KEV factor and recomputes rwep_score (Shape B)', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, poc_available: 20, active_exploitation: 20, blast_radius: 5 },
    rwep_score: 45 + scoring.RWEP_WEIGHTS.cisa_kev,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped back');
  assert.equal(e.rwep_factors.cisa_kev, 0, 'Shape-B factor must zero out');
  assert.equal(e.rwep_score, 45, 'rwep_score must drop by exactly the KEV weight');
});

test('Shape-A boolean factors keep their shape and re-derive through the canonical formula', async () => {
  const factorsAfter = { cisa_kev: true, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 };
  const p = makeCatalog({
    cisa_kev: false,
    rwep_factors: { cisa_kev: false, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 },
    rwep_score: scoring.deriveRwepFromFactors({ cisa_kev: false, poc_available: true, active_exploitation: 'confirmed', blast_radius: 2 }),
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(typeof e.rwep_factors.cisa_kev, 'boolean', 'Shape-A factor must stay boolean');
  assert.equal(e.rwep_factors.cisa_kev, true, 'Shape-A factor follows the flag');
  assert.equal(e.rwep_score, scoring.deriveRwepFromFactors(factorsAfter),
    'rwep_score must match the canonical derivation of the post-flip factors');
});

test('a cisa_kev_date diff does not touch rwep_factors or rwep_score', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    cisa_kev_date: '2026-01-01',
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 10 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev_date', before: '2026-01-01', after: '2026-06-01' },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev_date, '2026-06-01', 'date applied');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev, 'factor untouched');
  assert.equal(e.rwep_score, scoring.RWEP_WEIGHTS.cisa_kev + 10, 'score untouched');
});

test('a first KEV listing emits the flag AND the listing date for a null-date entry', async () => {
  // The diff producer once required a truthy local cisa_kev_date before it
  // would emit a date diff — so a first listing (local date null) flipped the
  // flag alone, and the applied tree failed strict validation (KEV-listed
  // entries must carry their listing date).
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-cache-'));
  fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
  fs.writeFileSync(
    path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'),
    JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2099-0001', dateAdded: '2026-06-01' }] })
  );
  const ctx = {
    cacheDir,
    forceStale: true,
    cveCatalog: { 'CVE-2099-0001': { cisa_kev: false, cisa_kev_date: null } },
  };
  const r = await ALL_SOURCES.kev.fetchDiff(ctx);
  const flag = r.diffs.find((d) => d.id === 'CVE-2099-0001' && d.field === 'cisa_kev');
  const date = r.diffs.find((d) => d.id === 'CVE-2099-0001' && d.field === 'cisa_kev_date');
  assert.ok(flag, 'flag diff emitted');
  assert.equal(flag.after, true, 'flag diff lists the CVE');
  assert.ok(date, 'date diff emitted despite null local date — first-listing case');
  assert.equal(date.before, null, 'before is the null local date');
  assert.equal(date.after, '2026-06-01', 'after is the upstream listing date');
});

test('an entry without rwep_factors gets the flag but no synthesized factors', async () => {
  const p = makeCatalog({ cisa_kev: false });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped');
  assert.equal('rwep_factors' in e, false, 'must not fabricate a factors object the curator never wrote');
  assert.equal('rwep_score' in e, false, 'must not fabricate a score');
});

test('a KEV de-listing (true→false) clears the now-orphaned cisa_kev_date', async () => {
  // After a CVE leaves KEV, its listing date is stale intel. The upstream
  // diff producer only emits a date diff when upstream HAS a date — a
  // de-listed CVE no longer does — so the applyDiff branch must clear the
  // date itself, or the entry ships cisa_kev:false alongside a stale date.
  const p = makeCatalog({
    cisa_kev: true,
    cisa_kev_date: '2026-01-01',
    cisa_kev_due_date: '2026-01-22',
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 10 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped to de-listed');
  assert.equal(e.cisa_kev_date, null, 'orphaned listing date cleared');
  assert.equal(e.cisa_kev_due_date, null, 'orphaned due date cleared');
  assert.equal(e.rwep_factors.cisa_kev, 0, 'KEV factor zeroed');
  assert.equal(e.rwep_score, 10, 'rwep_score drops by exactly the KEV weight');
});

test('a KEV listing (false→true) does not null a date the diff will set separately', async () => {
  // The date-clear must only fire on de-listing. A fresh listing keeps any
  // existing date untouched here; the paired cisa_kev_date diff sets it.
  const p = makeCatalog({
    cisa_kev: false,
    cisa_kev_date: null,
    rwep_factors: { cisa_kev: 0, blast_radius: 10 },
    rwep_score: 10,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: false, after: true },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, true, 'flag flipped to listed');
  assert.equal(e.cisa_kev_date, null, 'listing-direction flip leaves the date for its own diff');
  assert.equal(e.rwep_factors.cisa_kev, scoring.RWEP_WEIGHTS.cisa_kev, 'KEV factor added');
});

test('de-listing an entry that never carried a date leaves no spurious key', async () => {
  const p = makeCatalog({
    cisa_kev: true,
    rwep_factors: { cisa_kev: scoring.RWEP_WEIGHTS.cisa_kev, blast_radius: 5 },
    rwep_score: scoring.RWEP_WEIGHTS.cisa_kev + 5,
  });
  await ALL_SOURCES.kev.applyDiff({ cvePath: p }, [
    { id: 'CVE-2099-0001', field: 'cisa_kev', before: true, after: false },
  ]);
  const e = readCatalog(p)['CVE-2099-0001'];
  assert.equal(e.cisa_kev, false, 'flag flipped');
  assert.equal('cisa_kev_date' in e, false, 'must not introduce a date key that was never present');
  assert.equal('cisa_kev_due_date' in e, false, 'must not introduce a due-date key that was never present');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});

require('node:test').describe('epss-triple-coherence', () => {
  const { epssTripleDiffs, EPSS_DRIFT, ALL_SOURCES, epssDiffFromCache } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const { renderEpssNote } = require(path.join(ROOT, 'lib', 'cve-enrich.js'));
  const gate = require(path.join(ROOT, 'scripts', 'check-epss-consistency.js'));

  // The shape observed on the nightly refresh branch: a score that moved far
  // past the drift threshold while its percentile moved a small fraction of it.
  const local = () => ({
    epss_score: 0.84793,
    epss_percentile: 0.99688,
    epss_date: '2026-08-07',
    epss_note: 'FIRST EPSS 0.84793 (100th percentile) as of 2026-08-07.',
  });
  const row = { score: 0.99311, percentile: 0.9995, date: '2026-08-13' };
  // A neighbour already on the new publication, scoring BELOW the refreshed
  // entry. If the refreshed entry keeps yesterday's percentile, the cohort
  // stops ranking monotonically — which is exactly what the gate reports.
  const neighbour = { epss_score: 0.99085, epss_percentile: 0.99929, epss_date: '2026-08-13' };

  // The logic this replaced: the drift threshold applied to each field on its
  // own, so a field whose delta was small was left at the previous publication.
  // Kept here so the assertions below fail if the fix is ever reverted — a test
  // that only exercised the new path would pass against the bug too.
  function independentThresholdDiffs(id, loc, fetched, drift) {
    const out = [];
    if (fetched.score != null && loc.epss_score != null && Math.abs(fetched.score - loc.epss_score) > drift)
      out.push({ id, field: 'epss_score', after: fetched.score });
    if (fetched.percentile != null && loc.epss_percentile != null && Math.abs(fetched.percentile - loc.epss_percentile) > drift)
      out.push({ id, field: 'epss_percentile', after: fetched.percentile });
    if (fetched.date && loc.epss_date && fetched.date !== loc.epss_date) {
      const moved = out.some((d) => d.field === 'epss_score' || d.field === 'epss_percentile');
      if (moved) out.push({ id, field: 'epss_date', after: fetched.date });
    }
    return out;
  }

  const applyTo = (entry, diffs) => {
    const out = { ...entry };
    for (const d of diffs) out[d.field] = d.after;
    return out;
  };
  // mkdtempSync, not a composed path in the shared temp directory. It creates
  // the directory atomically with owner-only permissions, so nothing can
  // pre-create or swap the file between the name being chosen and the write —
  // which a pid-plus-timestamp name does not prevent, however unlikely the
  // collision. Each caller gets its own directory and removes it afterwards.
  const tmpDirs = [];
  const tmpJson = (obj) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epss-coh-'));
    tmpDirs.push(dir);
    const p = path.join(dir, 'catalog.json');
    fs.writeFileSync(p, JSON.stringify(obj));
    return p;
  };
  const cleanupTmp = () => {
    while (tmpDirs.length) {
      try { fs.rmSync(tmpDirs.pop(), { recursive: true, force: true }); } catch { /* best effort */ }
    }
  };
  const runGate = (catalog) => {
    const p = tmpJson(catalog);
    try { return gate.check(p); } finally { cleanupTmp(); }
  };

  test('the drift threshold decides whether an entry refreshes, not which of its fields does', () => {
    const old = independentThresholdDiffs('CVE-2099-0001', local(), row, EPSS_DRIFT);
    const now = epssTripleDiffs('CVE-2099-0001', local(), row, EPSS_DRIFT);

    assert.equal(old.some((d) => d.field === 'epss_percentile'), false,
      'precondition: the replaced logic omitted the percentile because its own delta was under the threshold');
    assert.equal(old.some((d) => d.field === 'epss_score'), true,
      'precondition: the replaced logic did write the score');

    assert.deepEqual(now.map((d) => d.field).sort(), ['epss_date', 'epss_percentile', 'epss_score'],
      'all three fields travel together once either number has moved');
    for (const d of now) {
      const expected = { epss_score: row.score, epss_percentile: row.percentile, epss_date: row.date }[d.field];
      assert.equal(d.after, expected, `${d.field} must come from the fetched row`);
    }
  });

  test('the replaced logic produces a cohort the consistency gate rejects; this one does not', () => {
    const before = runGate({ A: local(), B: neighbour });
    assert.deepEqual(before.failures, [], 'precondition: the starting catalog is consistent');

    const broken = runGate({
      A: applyTo(local(), independentThresholdDiffs('A', local(), row, EPSS_DRIFT)),
      B: neighbour,
    });
    assert.ok(broken.failures.some((f) => /different publications/.test(f)),
      'the replaced logic must leave a score and percentile drawn from different publications');

    const fixed = runGate({
      A: applyTo(local(), epssTripleDiffs('A', local(), row, EPSS_DRIFT)),
      B: neighbour,
    });
    assert.deepEqual(fixed.failures.filter((f) => /different publications/.test(f)), [],
      'writing the row as a unit keeps the cohort ranking monotonically');
  });

  test('neither number past the threshold refreshes nothing — noise control is preserved', () => {
    const nudged = { score: 0.85, percentile: 0.997, date: '2026-08-13' };
    assert.deepEqual(epssTripleDiffs('CVE-2099-0001', local(), nudged, EPSS_DRIFT), [],
      'a sub-threshold day must not churn the catalog');
  });

  test('an entry carrying only half the pair gets the missing half from the same row', () => {
    const halved = { epss_score: 0.84793, epss_date: '2026-08-07' };
    const diffs = epssTripleDiffs('CVE-2099-0001', halved, row, EPSS_DRIFT);
    const pct = diffs.find((d) => d.field === 'epss_percentile');
    assert.ok(pct, 'the absent percentile is supplied rather than left absent');
    assert.equal(pct.after, row.percentile);
    assert.equal(pct.before, null, 'a missing field reports null, not undefined');
  });

  test('a half-populated entry is repaired even when the field it does have has barely moved', () => {
    // The test above passes for the wrong reason on its own: its score also
    // crosses the drift threshold, so the entry would refresh anyway. The
    // failing shape is a half-populated entry whose present field is STABLE —
    // the absent side can never register as moved, so a drift-only rule leaves
    // the entry incomplete forever while the consistency gate keeps failing it.
    const halved = { epss_score: 0.84793, epss_date: '2026-08-07' };
    const barelyMoved = { score: 0.85, percentile: 0.9971, date: '2026-08-13' };
    assert.ok(Math.abs(barelyMoved.score - halved.epss_score) < EPSS_DRIFT,
      'precondition: the present field is inside the drift threshold, so drift alone would not refresh');

    const diffs = epssTripleDiffs('CVE-2099-0001', halved, barelyMoved, EPSS_DRIFT);
    const pct = diffs.find((d) => d.field === 'epss_percentile');
    assert.ok(pct, 'the missing percentile must be supplied even though nothing crossed the threshold');
    assert.equal(pct.after, barelyMoved.percentile);

    // And a COMPLETE entry with the same sub-threshold movement must still be
    // left alone, so the repair path cannot become a daily-churn path.
    const complete = { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' };
    assert.deepEqual(epssTripleDiffs('CVE-2099-0002', complete, barelyMoved, EPSS_DRIFT), [],
      'a complete, stable entry must not churn');
  });

  test('a partial fetched row never refreshes a COMPLETE entry either', () => {
    // The partial-row guard first sat inside the repair branch, so it only
    // applied to half-populated entries. A complete entry meeting a row that
    // carries one number could still refresh on that number crossing the
    // threshold, writing it beside the previous publication's other half.
    const complete = { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' };
    const scoreOnlyRow = { score: 0.99311, percentile: null, date: '2026-08-13' };
    assert.ok(Math.abs(scoreOnlyRow.score - complete.epss_score) > EPSS_DRIFT,
      'precondition: the one number present HAS crossed the threshold, so only the row guard can stop this');
    assert.deepEqual(epssTripleDiffs('CVE-2099-0001', complete, scoreOnlyRow, EPSS_DRIFT), [],
      'a partial row must not refresh a complete entry, however far its one number moved');
  });

  test('a row with both numbers but no date is refused', () => {
    // The date is the third member of the triple. Writing the numbers without
    // it leaves the entry carrying the previous publication's date, and the
    // regenerated note then states the new numbers "as of" a publication they
    // did not come from.
    const complete = { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' };
    const undatedRow = { score: 0.99311, percentile: 0.9995, date: null };
    assert.ok(Math.abs(undatedRow.score - complete.epss_score) > EPSS_DRIFT,
      'precondition: the score HAS crossed the threshold, so only the date guard can stop this');
    assert.deepEqual(epssTripleDiffs('CVE-2099-0001', complete, undatedRow, EPSS_DRIFT), [],
      'an undated row is not a publication');
  });

  test('epssDiffFromCache applies the same coherence rule to a real cache payload', () => {
    // The cache path is what the nightly refresh actually runs, and it is where
    // the original defect shipped from — so drive it end to end rather than
    // only unit-testing the rule it delegates to. `forceStale` skips the signed
    // _index.json requirement, which is about cache integrity rather than the
    // coherence behaviour under test here.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epss-cache-'));
    try {
      fs.mkdirSync(path.join(dir, 'epss'));
      const write = (id, epss, percentile, date) => fs.writeFileSync(
        path.join(dir, 'epss', `${id}.json`),
        JSON.stringify({ status: 'OK', data: [{ cve: id, epss, percentile, date }] }),
      );
      // Moves far past the threshold; its percentile moves barely at all.
      write('CVE-2099-0001', '0.99311', '0.9995', '2026-08-13');
      // A row missing its percentile entirely — must not refresh anything.
      fs.writeFileSync(path.join(dir, 'epss', 'CVE-2099-0002.json'),
        JSON.stringify({ status: 'OK', data: [{ cve: 'CVE-2099-0002', epss: '0.99311', date: '2026-08-13' }] }));

      const ctx = {
        cacheDir: dir,
        forceStale: true,
        cveCatalog: {
          'CVE-2099-0001': { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' },
          'CVE-2099-0002': { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' },
        },
      };
      const r = epssDiffFromCache(ctx);
      const fields = (id) => r.diffs.filter((d) => d.id === id).map((d) => d.field).sort();

      assert.deepEqual(fields('CVE-2099-0001'), ['epss_date', 'epss_percentile', 'epss_score'],
        'a complete cached row refreshes the whole triple, including the percentile that barely moved');
      assert.deepEqual(fields('CVE-2099-0002'), [],
        'a cached row missing the percentile refreshes nothing, however far the score moved');
      assert.equal(r.status, 'ok');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('applyDiff does not regenerate the note from a partial diff set', async () => {
    // applyDiff is exported and is also driven by fixtures that carry a score
    // and a date without a percentile, so a diff set can move one half of the
    // pair alone. Rewriting the note there would state the new score beside the
    // previous publication's percentile and read as current — masking the only
    // signal the consistency gate has, since a single-entry date cohort has no
    // neighbour to rank against.
    const entry = {
      epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07',
      epss_note: renderEpssNote({ epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' }),
    };
    const p = tmpJson({ _meta: {}, 'CVE-2099-0001': entry });
    try {
      await ALL_SOURCES.epss.applyDiff({ cvePath: p }, [
        { id: 'CVE-2099-0001', field: 'epss_score', before: 0.84793, after: 0.99311 },
        { id: 'CVE-2099-0001', field: 'epss_date', before: '2026-08-07', after: '2026-08-13' },
      ]);
      const after = JSON.parse(fs.readFileSync(p, 'utf8'))['CVE-2099-0001'];
      assert.equal(after.epss_score, 0.99311, 'the diff still applies');
      assert.equal(after.epss_percentile, 0.99688, 'precondition: the percentile was not in the diff set');
      assert.equal(after.epss_note, entry.epss_note,
        'the note must be left describing the old publication so the gate still reports the mismatch');
      assert.notEqual(after.epss_note, renderEpssNote(after),
        'and it must NOT match the current fields, which is what the gate keys on');
    } finally {
      cleanupTmp();
    }
  });

  test('a complete row that moves only the score still refreshes the note', async () => {
    // The regression this guards: deciding coherence from WHICH fields changed
    // rather than from where the diff came. A complete upstream row whose
    // percentile rounds to the same value emits the score alone — legitimately
    // — and treating that as partial strands the note describing the old
    // publication for good, because the next refresh finds nothing left to
    // diff and the consistency gate fails on it forever.
    const entry = {
      epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07',
      epss_note: renderEpssNote({ epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' }),
    };
    const sameDayRow = { score: 0.99311, percentile: 0.99688, date: '2026-08-07' };
    const diffs = epssTripleDiffs('CVE-2099-0001', entry, sameDayRow, EPSS_DRIFT);
    assert.deepEqual(diffs.map((d) => d.field), ['epss_score'],
      'precondition: only the score differs, so a fields-based rule would call this partial');
    assert.ok(diffs.every((d) => d.coherent === true), 'the emitter vouches for the row');

    const p = tmpJson({ _meta: {}, 'CVE-2099-0001': entry });
    try {
      await ALL_SOURCES.epss.applyDiff({ cvePath: p }, diffs);
      const after = JSON.parse(fs.readFileSync(p, 'utf8'))['CVE-2099-0001'];
      assert.equal(after.epss_note, renderEpssNote(after),
        'the note must restate the current fields, not the publication before them');
      assert.notEqual(after.epss_note, entry.epss_note, 'precondition: it actually changed');
    } finally {
      cleanupTmp();
    }
  });

  test('a malformed numeric value is refused rather than written as NaN', () => {
    // Both call sites build these with Number(), so a malformed cached value
    // arrives as NaN, not null. NaN passes a nullish check, would ride the
    // repair path, and serialises into the catalog as null — recreating the
    // half-populated entry the repair exists to fix.
    const halved = { epss_score: 0.84793, epss_date: '2026-08-07' };
    const nanRow = { score: Number('not-a-number'), percentile: 0.9995, date: '2026-08-13' };
    assert.ok(Number.isNaN(nanRow.score), 'precondition: the row really does carry NaN, not null');
    assert.deepEqual(epssTripleDiffs('CVE-2099-0001', halved, nanRow, EPSS_DRIFT), [],
      'a NaN must not reach the catalog by way of the repair path');
  });

  test('an entry with no EPSS at all is left alone', () => {
    // Absent is not incoherent. Only entries that already carry EPSS are
    // refreshed, which is the behaviour that predates this change.
    assert.deepEqual(epssTripleDiffs('CVE-2099-0004', { last_verified: '2026-08-07' }, row, EPSS_DRIFT), [],
      'a complete row must not introduce EPSS onto an entry that never had it');
  });

  test('a partial fetched row cannot be used to repair a partial entry', () => {
    // Filling one side from a row that is missing the other leaves the entry
    // just as incomplete, and advances the date so the value that survived now
    // claims a publication it did not come from — the inconsistency is moved,
    // not repaired.
    const halved = { epss_score: 0.84793, epss_date: '2026-08-07' };
    const partialRow = { score: null, percentile: 0.9971, date: '2026-08-13' };
    assert.deepEqual(epssTripleDiffs('CVE-2099-0001', halved, partialRow, EPSS_DRIFT), [],
      'a row without both numbers is not a repair source');

    // The mirror case: local has only the percentile, the row has only a score.
    const halvedPct = { epss_percentile: 0.99688, epss_date: '2026-08-07' };
    const scoreOnlyRow = { score: 0.85, percentile: null, date: '2026-08-13' };
    assert.deepEqual(epssTripleDiffs('CVE-2099-0003', halvedPct, scoreOnlyRow, EPSS_DRIFT), [],
      'the mirror case is refused too');

    // A complete row still repairs the same entry, so the guard narrows the
    // repair path rather than removing it.
    const completeRow = { score: 0.85, percentile: 0.9971, date: '2026-08-13' };
    const fixed = epssTripleDiffs('CVE-2099-0001', halved, completeRow, EPSS_DRIFT);
    assert.ok(fixed.find((d) => d.field === 'epss_percentile'), 'a complete row still repairs');
  });

  test('applyDiff regenerates the derived epss_note, and only where one already exists', async () => {
    const withNote = local();
    const withoutNote = { epss_score: 0.84793, epss_percentile: 0.99688, epss_date: '2026-08-07' };
    const p = tmpJson({ _meta: {}, 'CVE-2099-0001': withNote, 'CVE-2099-0002': withoutNote });
    try {
      const diffs = [
        ...epssTripleDiffs('CVE-2099-0001', withNote, row, EPSS_DRIFT),
        ...epssTripleDiffs('CVE-2099-0002', withoutNote, row, EPSS_DRIFT),
      ];
      await ALL_SOURCES.epss.applyDiff({ cvePath: p }, diffs);
      const after = JSON.parse(fs.readFileSync(p, 'utf8'));

      assert.equal(after['CVE-2099-0001'].epss_note, renderEpssNote(after['CVE-2099-0001']),
        'the note must restate the fields it now sits beside');
      assert.notEqual(after['CVE-2099-0001'].epss_note, withNote.epss_note,
        'precondition: the note actually changed, so the assertion above is not vacuous');
      assert.equal('epss_note' in after['CVE-2099-0002'], false,
        'a refresh must not add a note to an entry that never carried one');
    } finally {
      cleanupTmp();
    }
  });
});
