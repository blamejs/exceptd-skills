'use strict';

/**
 * prefetch CLI argument validation + cache-freshness guards.
 *
 * Behaviors pinned here:
 *
 *   - `--source ""` (empty) must REFUSE (exit 2), not silently warm every
 *     source. The empty string is falsy, so an unguarded ternary would resolve
 *     to "all sources" and warm ~9738 entries the operator never asked for.
 *   - `--source ,` (comma-only) must REFUSE (exit 2), not silently warm
 *     nothing-and-report-success. A comma-only value trims to an empty source
 *     list, which would plan zero work yet exit 0 — a looks-clean false
 *     negative for a scoped cache-warm.
 *   - A trailing `--cache-dir` / `--source` / `--max-age` with no following
 *     value must REFUSE cleanly (exit 2, ok:false envelope), not crash with a
 *     raw path.resolve(undefined) TypeError, not silently widen --source to all
 *     sources, and not silently flip --max-age to 0 (refetch-everything).
 *   - The omitted-`--source` default is unchanged: no `--source` flag still
 *     plans across all five sources.
 *   - isFresh() treats a future-dated cache entry as STALE (re-fetched), so a
 *     clock-skewed or index-poisoned entry is never trusted as fresh.
 *
 * Offline only: every case runs `--no-network` (dry-run) or exercises pure
 * parse/freshness logic. No real fetch occurs. Cache writes go to a tmpdir.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PREFETCH = path.join(ROOT, 'lib', 'prefetch.js');

function run(args) {
  return spawnSync(process.execPath, [PREFETCH, ...args], { encoding: 'utf8' });
}

// --- empty / comma-only --source ------------------------------------------

test('prefetch --source "" refuses (exit 2) instead of silently warming all sources', () => {
  const r = run(['--no-network', '--source', '']);
  assert.equal(r.status, 2, `empty --source must exit 2; stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(r.stderr || '', /source/, 'error must name --source');
  // Must NOT have planned a full all-source warm.
  assert.doesNotMatch(r.stdout || '', /across 5 source\(s\)/,
    'empty --source must not fall through to the all-sources default');
});

test('prefetch --source , (comma-only) refuses (exit 2) instead of a silent zero-work success', () => {
  const r = run(['--no-network', '--source', ',']);
  assert.equal(r.status, 2, `comma-only --source must exit 2; stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(r.stderr || '', /source/, 'error must name --source');
  assert.doesNotMatch(r.stdout || '', /0 source\(s\)/,
    'comma-only --source must not report a 0-source dry-run as success');
});

test('prefetch --source= (empty assignment form) refuses (exit 2)', () => {
  const r = run(['--no-network', '--source=']);
  assert.equal(r.status, 2, `--source= must exit 2; stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(r.stderr || '', /source/);
});

// Positive control: the omitted-flag default is preserved — no --source still
// plans across all five sources. Proves the guard only fires when --source was
// actually supplied (and supplied empty), not on the default path.
test('prefetch with no --source still plans across all five sources', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-argval-'));
  try {
    const r = run(['--no-network', '--cache-dir', tmp]);
    assert.equal(r.status, 0, `default no-source dry-run must exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /across 5 source\(s\)/,
      'omitted --source must resolve to all five sources');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// --- trailing value-flags with no value -----------------------------------

test('prefetch --cache-dir with no value refuses cleanly (exit 2, ok:false) — no raw path.resolve crash', () => {
  const r = run(['--cache-dir']);
  assert.equal(r.status, 2, `trailing --cache-dir must exit 2, not crash (exit 1); stderr=${r.stderr}`);
  // Clean envelope, not a raw stack trace.
  let body = null;
  try { body = JSON.parse((r.stderr || '').trim().split('\n').pop()); } catch { /* fallthrough */ }
  assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'prefetch');
  assert.match(body.error, /cache-dir/);
  assert.doesNotMatch(r.stderr || '', /TypeError|ERR_INVALID_ARG_TYPE/,
    'must not surface a raw path.resolve(undefined) TypeError');
});

test('prefetch --source with no value refuses cleanly (exit 2) instead of silently widening to all sources', () => {
  const r = run(['--no-network', '--source']);
  assert.equal(r.status, 2, `trailing --source must exit 2; stderr=${r.stderr}`);
  let body = null;
  try { body = JSON.parse((r.stderr || '').trim().split('\n').pop()); } catch { /* fallthrough */ }
  assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'prefetch');
  assert.match(body.error, /source/);
});

test('prefetch --max-age with no value refuses cleanly (exit 2) instead of silently flipping to refetch-all', () => {
  const r = run(['--no-network', '--max-age']);
  assert.equal(r.status, 2, `trailing --max-age must exit 2; stderr=${r.stderr}`);
  let body = null;
  try { body = JSON.parse((r.stderr || '').trim().split('\n').pop()); } catch { /* fallthrough */ }
  assert.ok(body, `must emit a parseable JSON envelope; got stderr=${r.stderr}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'prefetch');
  assert.match(body.error, /max-age/);
});

// --- parseArgs unit assertions (no subprocess) ----------------------------

test('parseArgs records _argError for trailing value-flags and does not throw', () => {
  const { parseArgs } = require('../lib/prefetch');
  for (const flag of ['--cache-dir', '--source', '--max-age']) {
    let out;
    assert.doesNotThrow(() => { out = parseArgs(['node', 'prefetch.js', flag]); },
      `parseArgs must not throw on trailing ${flag}`);
    assert.ok(out._argError, `trailing ${flag} must record _argError`);
    assert.match(out._argError, new RegExp(flag.slice(2)));
  }
});

test('parseArgs no longer silently produces maxAgeMs=0 on a valueless --max-age', () => {
  const { parseArgs } = require('../lib/prefetch');
  const out = parseArgs(['node', 'prefetch.js', '--max-age']);
  // The flip to 0 is the bug; the guard records _argError instead. maxAgeMs
  // must stay at its safe default rather than the refetch-everything 0.
  assert.ok(out._argError, 'valueless --max-age must record _argError');
  assert.notEqual(out.maxAgeMs, 0, 'valueless --max-age must not silently flip maxAgeMs to 0');
});

test('parseArgs flags empty / comma-only --source as a usage error', () => {
  const { parseArgs } = require('../lib/prefetch');
  for (const val of ['', ' ', ',', ', ,']) {
    const out = parseArgs(['node', 'prefetch.js', '--source', val]);
    assert.ok(out._argError, `--source "${val}" must record _argError`);
    assert.match(out._argError, /source/);
  }
  // A real source name does NOT trip the guard.
  const ok = parseArgs(['node', 'prefetch.js', '--source', 'kev']);
  assert.equal(ok._argError, undefined);
  assert.equal(ok.source, 'kev');
});

// --- isFresh future-dated guard -------------------------------------------

test('prefetch isFresh treats a future-dated cache entry as STALE (re-fetch), not fresh', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-fresh-'));
  try {
    // A KEV feed payload + an _index.json whose fetched_at is one year in the
    // FUTURE for that entry. A clock-skewed or poisoned index would otherwise
    // pass the freshness gate and skip the re-fetch.
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'),
      JSON.stringify({ vulnerabilities: [] })
    );
    const futureIso = new Date(Date.now() + 365 * 86_400_000).toISOString();
    fs.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({
      generated_at: futureIso,
      entries: {
        'kev/known_exploited_vulnerabilities': { fetched_at: futureIso, etag: null, url: 'x', sha256: 'x' },
      },
    }));

    // Dry-run plan: the one KEV entry must be counted as would-fetch (stale),
    // NOT skipped_fresh. We run the subprocess in --no-network mode scoped to
    // kev and parse the summary line.
    const r = run(['--no-network', '--source', 'kev', '--cache-dir', tmp]);
    assert.equal(r.status, 0, `dry-run must exit 0; stderr=${r.stderr}`);
    // The KEV source plans exactly one entry. With the future-dated guard it
    // must be would-fetch, so: 0 fresh, 1 would-fetch.
    assert.match(r.stdout, /0 fetched, 0 fresh, 1 would-fetch \(dry-run\)/,
      `future-dated entry must be STALE (would-fetch), not skipped_fresh; got: ${r.stdout}`);
    assert.match(r.stdout, /STALE \(would fetch\)/,
      'the future-dated KEV entry must be tagged STALE');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Contrast control: a normally-aged (recent past) entry IS fresh, proving the
// guard only rejects the negative-age direction, not all freshness.
test('prefetch isFresh still treats a recent past entry as FRESH (skipped)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-fresh-'));
  try {
    fs.mkdirSync(path.join(tmp, 'kev'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'kev', 'known_exploited_vulnerabilities.json'),
      JSON.stringify({ vulnerabilities: [] })
    );
    const recentIso = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(path.join(tmp, '_index.json'), JSON.stringify({
      generated_at: recentIso,
      entries: {
        'kev/known_exploited_vulnerabilities': { fetched_at: recentIso, etag: null, url: 'x', sha256: 'x' },
      },
    }));
    const r = run(['--no-network', '--source', 'kev', '--cache-dir', tmp]);
    assert.equal(r.status, 0, `dry-run must exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /0 fetched, 1 fresh, 0 would-fetch \(dry-run\)/,
      `recent past entry must be FRESH (skipped); got: ${r.stdout}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
