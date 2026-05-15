'use strict';

/**
 * tests/audit-ff-dd-hh-fixes.test.js
 *
 * Regression coverage for the FF / DD / HH audit batch landing in v0.12.21:
 *
 *   FF P1-1  scoring.validate() skips _auto_imported:true entries.
 *   FF P1-3  lib/refresh-external.js --air-gap flag reaches ctx.airGap.
 *   FF P1-4  cross-ref-api.byCve() excludes auto-imported drafts by default
 *            and re-includes them on { include_drafts: true }.
 *   DD P1-1  cross-ref-api cache invalidates when the source file mtime
 *            changes (long-running watcher visibility).
 *   DD P1-2  persistAttestation lock spin is bounded — exercised indirectly
 *            via the MAX_RETRIES = 10 invariant declared in source. The
 *            persistAttestation function is sync and used inside the CLI
 *            dispatcher; a runtime-contention test would require child
 *            processes racing on the same attestation slot, which is
 *            covered by the existing concurrent-attestation-writer helper.
 *            Here we assert the bound declared in source has not crept back
 *            up to 50 (the regression we fixed).
 *   DD P1-3  acquireLock reclaims a lockfile whose recorded PID is dead and
 *            returns null when the holder PID is alive.
 *   HH P1-1  release.yml declares a top-level permissions: block.
 *   HH P1-2  refresh.yml declares a top-level permissions: block.
 *
 * Per CLAUDE.md: each assertion checks the EXACT condition the fix produces.
 * No assert.notEqual(0) / assert.ok(field) coincidence-passers.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');

// ============================================================================
// FF P1-1 — scoring.validate() skip _auto_imported drafts
// ============================================================================

test('FF P1-1: scoring.validate() skips entries flagged _auto_imported: true', () => {
  const { validate } = require(path.join(ROOT, 'lib', 'scoring.js'));
  // Shape that previously triggered the divergence error: poc_available:null
  // on the entry but rwep_factors stored as if poc=true. The stored rwep_score
  // (computed from defaults) would diverge from validate()'s recompute by ~20.
  const draftCatalog = {
    'CVE-9999-00001': {
      type: 'TBD',
      cvss_score: null,
      cvss_vector: null,
      cisa_kev: true,
      poc_available: null,            // <-- the divergence trigger
      ai_discovered: null,
      active_exploitation: 'suspected',
      affected: 'whatever',
      patch_available: null,
      patch_required_reboot: null,
      live_patch_available: null,
      live_patch_tools: [],
      rwep_score: 70,                  // computed as if poc=true, reboot=true
      rwep_factors: {
        cisa_kev: 25, poc_available: 20, ai_factor: 0, active_exploitation: 10,
        blast_radius: 15, patch_available: 0, live_patch_available: 0,
        reboot_required: 5,
      },
      atlas_refs: [], attack_refs: [],
      source_verified: '2026-05-14', last_updated: '2026-05-14',
      verification_sources: ['https://example/'],
      _auto_imported: true,
    },
  };
  const errors = validate(draftCatalog);
  // The exact bug was a divergence-error string mentioning the CVE id.
  for (const e of errors) {
    assert.equal(
      e.includes('CVE-9999-00001') && e.includes('rwep_score'),
      false,
      `auto-imported draft should not trigger rwep divergence error, got: ${e}`,
    );
  }
});

test('FF P1-1: scoring.validate() flags divergence on a NON-_auto_imported entry (regression)', () => {
  const { validate } = require(path.join(ROOT, 'lib', 'scoring.js'));
  const curatedCatalog = {
    'CVE-9999-00002': {
      type: 'RCE',
      cvss_score: 9.8, cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cisa_kev: true,
      poc_available: true, poc_description: 'public exploit on github',
      ai_discovered: false,
      active_exploitation: 'confirmed',
      affected: 'vendor product 1.2.3', affected_versions: ['1.2.3'],
      patch_available: true, patch_required_reboot: false,
      live_patch_available: false, live_patch_tools: [],
      // Stored rwep_score wildly diverges from recomputed value (>5).
      // Real computed = 25+20+0+20+15+(-15)+0+0 = 65. Stored = 10.
      rwep_score: 10,
      rwep_factors: {
        cisa_kev: 25, poc_available: 20, ai_factor: 0, active_exploitation: 20,
        blast_radius: 15, patch_available: -15, live_patch_available: 0,
        reboot_required: 0,
      },
      atlas_refs: [], attack_refs: [],
      source_verified: '2026-05-14', last_updated: '2026-05-14',
      verification_sources: ['https://nvd.nist.gov/'],
      // NOT _auto_imported — full validation must fire.
    },
  };
  const errors = validate(curatedCatalog);
  const divergence = errors.find((e) => e.includes('CVE-9999-00002') && e.includes('rwep_score'));
  assert.equal(typeof divergence, 'string', 'curated entry must still trigger divergence error');
  assert.equal(divergence.includes('diverges from calculated'), true);
});

// ============================================================================
// FF P1-3 — refresh-external --air-gap flag wiring
// ============================================================================

test('FF P1-3: refresh-external parseArgs recognises --air-gap', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const args = parseArgs(['node', 'refresh-external.js', '--air-gap']);
  assert.equal(args.airGap, true);
});

test('FF P1-3: refresh-external parseArgs default has airGap unset (falsy)', () => {
  const { parseArgs } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const args = parseArgs(['node', 'refresh-external.js']);
  assert.equal(!!args.airGap, false);
});

test('FF P1-3: loadCtx threads --air-gap into ctx.airGap (true case)', () => {
  const { loadCtx } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  // Save & restore env so test ordering doesn't leak.
  const priorEnv = process.env.EXCEPTD_AIR_GAP;
  delete process.env.EXCEPTD_AIR_GAP;
  try {
    const ctx = loadCtx({ airGap: true });
    assert.equal(ctx.airGap, true);
  } finally {
    if (priorEnv !== undefined) process.env.EXCEPTD_AIR_GAP = priorEnv;
  }
});

test('FF P1-3: loadCtx threads EXCEPTD_AIR_GAP=1 into ctx.airGap (env fallback)', () => {
  const { loadCtx } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const priorEnv = process.env.EXCEPTD_AIR_GAP;
  process.env.EXCEPTD_AIR_GAP = '1';
  try {
    const ctx = loadCtx({});
    assert.equal(ctx.airGap, true);
  } finally {
    if (priorEnv === undefined) delete process.env.EXCEPTD_AIR_GAP;
    else process.env.EXCEPTD_AIR_GAP = priorEnv;
  }
});

test('FF P1-3: loadCtx ctx.airGap defaults to false when neither flag nor env set', () => {
  const { loadCtx } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  const priorEnv = process.env.EXCEPTD_AIR_GAP;
  delete process.env.EXCEPTD_AIR_GAP;
  try {
    const ctx = loadCtx({});
    assert.equal(ctx.airGap, false);
  } finally {
    if (priorEnv !== undefined) process.env.EXCEPTD_AIR_GAP = priorEnv;
  }
});

// ============================================================================
// FF P1-4 — cross-ref-api.byCve() excludes drafts by default
// ============================================================================

// Each test allocates a fresh DATA_DIR + clears the cross-ref-api module cache
// so the cache+mtime tests can mutate disk freely.
function makeDataDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xref-api-'));
  fs.mkdirSync(path.join(dir, '_indexes'));
  // Minimal index files so loadIndex() doesn't error out.
  for (const f of ['xref.json', 'recipes.json', 'theater-fingerprints.json', 'summary-cards.json']) {
    fs.writeFileSync(path.join(dir, '_indexes', f), '{}', 'utf8');
  }
  for (const f of ['cwe-catalog.json', 'atlas-ttps.json', 'd3fend-catalog.json',
                   'framework-control-gaps.json', 'global-frameworks.json',
                   'zeroday-lessons.json', 'rfc-references.json']) {
    fs.writeFileSync(path.join(dir, f), '{}', 'utf8');
  }
  return dir;
}

function loadFreshXrefApi(dataDir) {
  // Reset the module cache so EXCEPTD_DATA_DIR is honoured by a fresh require().
  delete require.cache[require.resolve(path.join(ROOT, 'lib', 'cross-ref-api.js'))];
  process.env.EXCEPTD_DATA_DIR = dataDir;
  return require(path.join(ROOT, 'lib', 'cross-ref-api.js'));
}

test('FF P1-4: byCve(id) excludes _auto_imported:true drafts by default', () => {
  const dataDir = makeDataDir();
  fs.writeFileSync(path.join(dataDir, 'cve-catalog.json'), JSON.stringify({
    'CVE-2030-00001': { type: 'TBD', rwep_score: 70, _auto_imported: true },
  }), 'utf8');
  const xref = loadFreshXrefApi(dataDir);
  const res = xref.byCve('CVE-2030-00001');
  assert.equal(res.found, false);
  assert.equal(res._draft_excluded, true);
  assert.equal(res.cve_id, 'CVE-2030-00001');
});

test('FF P1-4: byCve(id, { include_drafts: true }) returns the draft', () => {
  const dataDir = makeDataDir();
  fs.writeFileSync(path.join(dataDir, 'cve-catalog.json'), JSON.stringify({
    'CVE-2030-00002': { type: 'TBD', rwep_score: 70, _auto_imported: true,
                        atlas_refs: [], attack_refs: [] },
  }), 'utf8');
  const xref = loadFreshXrefApi(dataDir);
  const res = xref.byCve('CVE-2030-00002', { include_drafts: true });
  assert.equal(res.found, true);
  assert.equal(res.cve_id, 'CVE-2030-00002');
  assert.equal(res.rwep_score, 70);
});

test('FF P1-4: byCve(id) on a curated (non-draft) entry returns it normally', () => {
  const dataDir = makeDataDir();
  fs.writeFileSync(path.join(dataDir, 'cve-catalog.json'), JSON.stringify({
    'CVE-2030-00003': {
      type: 'RCE', rwep_score: 85, cisa_kev: true,
      atlas_refs: ['AML.T0051'], attack_refs: ['T1190'],
      active_exploitation: 'confirmed', ai_discovered: false,
    },
  }), 'utf8');
  const xref = loadFreshXrefApi(dataDir);
  const res = xref.byCve('CVE-2030-00003');
  assert.equal(res.found, true);
  assert.equal(res.rwep_score, 85);
  assert.equal(res.cisa_kev, true);
});

// ============================================================================
// DD P1-1 — cross-ref-api cache invalidates on mtime change
// ============================================================================

test('DD P1-1: cross-ref-api cache invalidates when source file mtime changes', async () => {
  const dataDir = makeDataDir();
  const cvePath = path.join(dataDir, 'cve-catalog.json');
  fs.writeFileSync(cvePath, JSON.stringify({
    'CVE-2030-10001': { type: 'RCE', rwep_score: 50,
                        atlas_refs: [], attack_refs: [],
                        active_exploitation: 'suspected', ai_discovered: false },
  }), 'utf8');
  // Backdate mtime so the subsequent mutation produces a measurably-different
  // mtimeMs on filesystems with coarse timestamp granularity (HFS+, FAT, some
  // network mounts).
  const past = Date.now() - 10_000;
  fs.utimesSync(cvePath, past / 1000, past / 1000);

  const xref = loadFreshXrefApi(dataDir);
  const first = xref.byCve('CVE-2030-10001');
  assert.equal(first.found, true);
  assert.equal(first.rwep_score, 50);

  // Mutate the catalog file directly without going through the API.
  fs.writeFileSync(cvePath, JSON.stringify({
    'CVE-2030-10001': { type: 'RCE', rwep_score: 95,
                        atlas_refs: [], attack_refs: [],
                        active_exploitation: 'confirmed', ai_discovered: false },
  }), 'utf8');
  // Force a future mtime to defeat coarse-granularity filesystems.
  const future = Date.now() + 5_000;
  fs.utimesSync(cvePath, future / 1000, future / 1000);

  const second = xref.byCve('CVE-2030-10001');
  assert.equal(second.found, true);
  assert.equal(second.rwep_score, 95,
    'cache must re-read after mtime change (was process-lifetime cached)');
});

// ============================================================================
// DD P1-2 — persistAttestation lock spin bounded to MAX_RETRIES = 10
// ============================================================================

test('DD P1-2: persistAttestation lock MAX_RETRIES is bounded to 10 (was 50)', () => {
  // The lock body uses `const MAX_RETRIES = 10;` inside the persistAttestation
  // function (post-DD-P1-2). Read the source and assert the bound has not
  // crept back up. A purely-numeric assertion is brittle to formatting; we
  // look for the labeled comment + the assignment together.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // The numeric bound lives in the persistAttestation function; capture
  // exactly that block (everything between persistAttestation's open and
  // its closing brace pattern is too tight, so we anchor on the comment
  // that documents the bound).
  const match = src.match(/DD P1-2[\s\S]{0,800}const MAX_RETRIES = (\d+);/);
  assert.notEqual(match, null, 'DD P1-2 documented MAX_RETRIES bound must exist in bin/exceptd.js');
  assert.equal(Number(match[1]), 10);
});

test('DD P1-2: persistAttestation surfaces lock_contention:true sentinel', () => {
  // Sanity check that the source still returns lock_contention:true on
  // exhausted retries. We assert on the shape of the literal return object.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.equal(
    /lock_contention:\s*true/.test(src),
    true,
    'persistAttestation must signal lock_contention sentinel for callers',
  );
  assert.equal(
    /LOCK_CONTENTION:/.test(src),
    true,
    'persistAttestation must prefix the error string with LOCK_CONTENTION: for grep-ability',
  );
});

// ============================================================================
// DD P1-3 — acquireLock PID-liveness reclaim
// ============================================================================

const playbookRunner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

function makeLockDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pb-locks-'));
  process.env.EXCEPTD_LOCK_DIR = dir;
  return dir;
}

test('DD P1-3: acquireLock reclaims a lockfile whose recorded PID is dead', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-stale-pid-' + process.pid;
  // Pick a PID that almost certainly does not exist. PIDs above the usual
  // pid_max are a safe choice on Linux/macOS; on Windows process.kill(pid, 0)
  // returns ESRCH for non-existent PIDs as well.
  const deadPid = 999999;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  fs.writeFileSync(lockFile, JSON.stringify({ pid: deadPid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2));

  const result = playbookRunner._acquireLock(playbookId);
  assert.equal(result, lockFile,
    'acquireLock must reclaim the lockfile when the recorded PID is not alive');

  // Lockfile should now be ours.
  const reread = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  assert.equal(reread.pid, process.pid);
  playbookRunner._releaseLock(result);
});

test('DD P1-3: acquireLock returns null when lockfile is held by a live PID', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-live-pid-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  // Record OUR pid as the holder — guaranteed to be alive.
  fs.writeFileSync(lockFile, JSON.stringify({ pid: process.pid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2));
  // pidAlive checks pid !== process.pid, so use a sibling helper to fake a
  // different live pid. process.ppid is alive (the test runner's parent) and
  // is !== process.pid.
  const livePid = process.ppid && process.ppid !== process.pid ? process.ppid : process.pid + 1;
  fs.writeFileSync(lockFile, JSON.stringify({ pid: livePid, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2));

  let isAlive = false;
  try { process.kill(livePid, 0); isAlive = true; } catch {}
  if (!isAlive) {
    // Skip: couldn't find a reliably-live distinct PID in this environment.
    return;
  }
  const result = playbookRunner._acquireLock(playbookId);
  assert.equal(result, null,
    'acquireLock must return null when the recorded PID is alive and not the caller');
  // Lockfile contents unchanged (still the live holder).
  const reread = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  assert.equal(reread.pid, livePid);
});

test('DD P1-3: acquireLockDiagnostic distinguishes held vs reclaimed', () => {
  const dir = makeLockDir();
  const playbookId = 'pb-diag-' + process.pid;
  const lockFile = path.join(dir, `${playbookId}.lock`);
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 999998, started_at: '2026-01-01T00:00:00Z', playbook: playbookId }, null, 2));

  const diag = playbookRunner._acquireLockDiagnostic(playbookId);
  assert.equal(diag.ok, true);
  assert.equal(diag.path, lockFile);
  assert.equal(diag.reclaimed_from_pid, 999998);
  playbookRunner._releaseLock(diag.path);
});

// ============================================================================
// HH P1-1 / HH P1-2 — workflow top-level permissions blocks
// ============================================================================

// Minimal YAML key probe — workflows are well-formed by construction; we just
// need to assert the top-level `permissions:` key exists. We do not require a
// full YAML parser; the workflow files are line-oriented enough that an
// anchored regex is reliable. The workflows-security.test.js suite already
// asserts every action ref is SHA-pinned, etc., so this is a focused check.
function topLevelPermissionsDeclared(yamlText) {
  // A top-level key is anchored at column 0. The block can be either a
  // mapping (multiline) or an inline mapping. Both forms satisfy
  // Scorecard's TokenPermissionsID.
  return /^permissions:\s*(?:#.*)?(?:\n[ \t]+\S|\s*\{[^}]*\}\s*$)/m.test(yamlText);
}

test('HH P1-1: release.yml declares a top-level permissions: block', () => {
  const yamlText = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  assert.equal(topLevelPermissionsDeclared(yamlText), true,
    'release.yml must declare workflow-level permissions:');
  // Specifically the minimum-scope default we shipped (contents: read).
  assert.equal(/^permissions:\s*\n\s*contents:\s*read/m.test(yamlText), true,
    'release.yml top-level permissions: must default to contents: read');
});

test('HH P1-2: refresh.yml declares a top-level permissions: block', () => {
  const yamlText = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.equal(topLevelPermissionsDeclared(yamlText), true,
    'refresh.yml must declare workflow-level permissions:');
  assert.equal(/^permissions:\s*\n\s*contents:\s*read/m.test(yamlText), true,
    'refresh.yml top-level permissions: must default to contents: read');
});
