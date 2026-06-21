'use strict';

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
// #16 — air-gap refusal is unconditional w.r.t. EXCEPTD_REGISTRY_FIXTURE.
// ===========================================================================

test('#16 refresh --network --air-gap refuses even with EXCEPTD_REGISTRY_FIXTURE set (exit 4)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-F-ag-'));
  const fixturePath = path.join(dir, 'meta.json');
  // A complete metadata fixture (version + dist.tarball + shasum). Pre-fix
  // the air-gap predicate `&& !process.env.EXCEPTD_REGISTRY_FIXTURE` would
  // short-circuit FALSE here and proceed to a live tarball fetch.
  fs.writeFileSync(fixturePath, JSON.stringify({
    version: '999.0.0',
    dist: { tarball: 'https://registry.npmjs.org/x.tgz', shasum: 'deadbeef' },
  }));
  const r = spawnSync(process.execPath, [REFRESH_NETWORK, 'refresh', '--network', '--air-gap', '--json'], {
    env: { ...process.env, EXCEPTD_REGISTRY_FIXTURE: fixturePath },
    encoding: 'utf8',
  });
  assert.equal(r.status, 4, `air-gap must refuse with exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 300)})`);
  const body = JSON.parse((r.stdout || r.stderr).trim().split('\n').pop());
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /requires network egress; refused/,
    'the refusal message must name the air-gap egress block');
});

// ===========================================================================
// #48 — content-only candidate dedup / source-merge across feeds.
// ===========================================================================

test('#48 duplicate content-only rows across feeds collapse to ONE candidate with merged surfaced_by', () => {
  const now = new Date('2026-05-19T00:00:00Z');
  // Same current-year CVE id from two feeds; both titles carry the same
  // regression-language signal. Pre-fix: two separate candidates.
  const report = WATCHER.findRegressionCandidates([
    { id: 'CVE-2026-99999', source: 'feedA', title: 'the 2020 fix is silently reverted' },
    { id: 'CVE-2026-99999', source: 'feedB', title: 'the 2020 fix is silently reverted' },
  ], { _meta: {} }, { now });

  const contentOnly = report.candidates.filter((c) => c.action === 'content-only-investigate');
  assert.equal(contentOnly.length, 1, 'duplicate rows must collapse to exactly one content-only candidate');
  assert.deepEqual(contentOnly[0].surfaced_by.slice().sort(), ['feedA', 'feedB'],
    'surfaced_by must be the sorted union of every contributing feed');
  assert.equal(contentOnly[0].historical_cve, null);
  assert.equal(typeof contentOnly[0].signals.regression_language, 'string',
    'the merged candidate must carry the regression-language signal');
});

test('#48 genuinely-distinct signals stay separate (no over-merge)', () => {
  const now = new Date('2026-05-19T00:00:00Z');
  const report = WATCHER.findRegressionCandidates([
    { id: 'CVE-2026-11111', source: 'feedA', title: 'James Forshaw: cldflt.sys silently reverted' },
    { id: 'CVE-2026-22222', source: 'feedB', title: 'Tavis Ormandy: ssh-keysign re-exploitable, the patch was reverted' },
  ], { _meta: {} }, { now });

  const contentOnly = report.candidates.filter((c) => c.action === 'content-only-investigate');
  assert.equal(contentOnly.length, 2, 'distinct keys must remain two separate candidates');
  assert.deepEqual(
    contentOnly.map((c) => c.signals.researcher).sort(),
    ['James Forshaw', 'Tavis Ormandy'],
    'each distinct candidate must keep its own researcher signal',
  );
});

test('#48 first_seen_titles is capped at 5 on content-only candidates', () => {
  const now = new Date('2026-05-19T00:00:00Z');
  // Seven feeds, same id, seven distinct titles -> one candidate, <=5 titles.
  const diffs = [];
  for (let i = 0; i < 7; i++) {
    diffs.push({
      id: 'CVE-2026-77777',
      source: `feed${i}`,
      title: `report ${i}: the 2020 fix is silently reverted`,
    });
  }
  const report = WATCHER.findRegressionCandidates(diffs, { _meta: {} }, { now });
  const contentOnly = report.candidates.filter((c) => c.action === 'content-only-investigate');
  assert.equal(contentOnly.length, 1);
  assert.equal(contentOnly[0].first_seen_titles.length, 5,
    'first_seen_titles must be capped at 5, matching the historical branch');
  assert.equal(contentOnly[0].surfaced_by.length, 7,
    'all seven surfacing feeds must still be recorded in surfaced_by');
});

// ===========================================================================
// #51 — host-allowlist port hole.
// ===========================================================================

test('#51 isAllowedTarballHost rejects a non-default port', () => {
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org:9999/x.tgz'), false,
    'a port-bearing allowlisted host must be rejected (validate/connect must agree)');
});

test('#51 isAllowedTarballHost accepts the default and explicit-443 ports', () => {
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org/x.tgz'), true);
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org:443/x.tgz'), true);
});

test('#51 isAllowedTarballHost still rejects look-alike and internal hosts', () => {
  // The anchored regex must stay intact — the port fix must not relax it.
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org.attacker.test/x.tgz'), false);
  assert.equal(isAllowedTarballHost('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(isAllowedTarballHost('not a url'), false);
});
