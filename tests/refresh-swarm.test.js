'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'refresh');
const os = require('os');

let REPORT;
function mkReport() {
  REPORT = path.join(os.tmpdir(), `refresh-report-swarm-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  return REPORT;
}

function run(args) {
  const reportPath = mkReport();
  return spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-fixture', FIX, '--quiet', '--report-out', reportPath, ...args],
    { encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
  );
}

test('refresh-external --swarm + --from-fixture: report is shape-identical to sequential', () => {
  const seq = run([]);
  assert.equal(seq.status, 0);
  const seqReport = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  delete seqReport.generated_at;
  delete seqReport.swarm;
  const swarm = run(['--swarm']);
  assert.equal(swarm.status, 0);
  const swarmReport = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(swarmReport.swarm, true);
  delete swarmReport.generated_at;
  delete swarmReport.swarm;
  assert.deepEqual(swarmReport, seqReport, 'swarm and sequential reports diverge');
});

test('refresh-external --from-cache reads kev/epss/nvd/rfc/pins from a cache dir', () => {
  const fs2 = require('fs');
  const os = require('os');
  const tmp = fs2.mkdtempSync(path.join(os.tmpdir(), 'refresh-cache-'));
  try {
    // Seed minimal cache entries matching the prefetch layout.
    fs2.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs2.writeFileSync(path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'),
      JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-43284', dateAdded: '2026-04-01' }] }));
    fs2.mkdirSync(path.join(tmp, 'nvd'), { recursive: true });
    fs2.mkdirSync(path.join(tmp, 'epss'), { recursive: true });
    fs2.mkdirSync(path.join(tmp, 'rfc'), { recursive: true });
    fs2.mkdirSync(path.join(tmp, 'pins'), { recursive: true });
    // Empty index file is fine; the source modules tolerate cache misses.
    fs2.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({ generated_at: new Date().toISOString(), entries: {} }));

    const reportPath = mkReport();
    const r = spawnSync(
      process.execPath,
      // --force-stale bypasses v0.12.24's `_index.json.sig` requirement +
      // max-age check; this test seeds a minimal cache with empty entries +
      // no signature, which the production gate (correctly) refuses.
      [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-cache', tmp, '--source', 'kev', '--force-stale', '--quiet', '--report-out', reportPath],
      { encoding: 'utf8', cwd: ROOT, env: { ...process.env, EXCEPTD_TEST_HARNESS: '1' } }
    );
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const report = JSON.parse(fs2.readFileSync(reportPath, 'utf8'));
    assert.equal(report.cache_mode, true);
    // KEV catalog has CVE-2026-43284 NOT in KEV locally; cache says it IS in KEV.
    const diffs = report.sources.kev.diffs;
    assert.ok(diffs.some((d) => d.id === 'CVE-2026-43284' && d.field === 'cisa_kev' && d.after === true));
  } finally {
    fs2.rmSync(tmp, { recursive: true, force: true });
  }
});

test('refresh-external --from-cache <nonexistent> exits 2 (generic hint refusal)', () => {
  // The missing-cache branch in lib/refresh-external.js throws a hint
  // error without setting _exceptd_exit_code, so the top-level handler
  // defaults to exit 2 (generic refusal). Signature-validation refusals
  // set _exceptd_exit_code = 4. Pin the exact value so a future change
  // that moves missing-cache to a different code surfaces here, not as
  // a silent passing test.
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'lib', 'refresh-external.js'), '--from-cache', '/does/not/exist/cache', '--quiet'],
    { encoding: 'utf8', cwd: ROOT }
  );
  assert.equal(r.status, 2, `expected exit 2 (missing-cache refusal); got ${r.status}; stderr: ${r.stderr}`);
});
