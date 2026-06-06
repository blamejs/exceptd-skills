'use strict';

/**
 * The cache-populate command is `exceptd refresh --prefetch`. `--no-network`
 * is the report-only dry run that writes nothing (lib/prefetch.js treats it as
 * --dry-run), so it must never be presented as a populate alias in `refresh
 * --help` nor as the air-gap populate step in the `--from-cache` missing-path
 * hint. Both surfaces previously told operators to populate with
 * `--no-network`, which silently produces an empty cache.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');
const refresh = require(path.join(ROOT, 'lib', 'refresh-external.js'));

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
