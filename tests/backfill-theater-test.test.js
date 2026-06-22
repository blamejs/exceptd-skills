'use strict';

/**
 * tests/backfill-theater-test.test.js
 *
 * Subject coverage for scripts/backfill-theater-test.js — the one-shot that
 * stamps a `theater_test` block onto every data/framework-control-gaps.json
 * entry (Hard Rule #6: every compliance finding ships a paper-vs-real test).
 *
 * The script mutates a hard-coded CATALOG_PATH (data/framework-control-gaps.json
 * relative to its own __dirname) at module load, so it MUST NOT be required
 * against the real tree. Instead it is copied into an isolated tempdir whose
 * scripts/../data holds a fixture catalog; behaviour is exercised via a
 * subprocess.
 *
 * Pass contract: every entry that has a hand-authored test gets a theater_test
 *   with claim/test/evidence_required/verdict_when_failed, the entry's other
 *   fields are preserved, _meta is untouched, the output round-trips as JSON
 *   with a trailing newline, and the run exits 0.
 * Fail contract: an entry with no hand-authored test makes the run exit 2 and
 *   name the missing key on stderr — and it must NOT have written partial data.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT_SRC = path.join(__dirname, '..', 'scripts', 'backfill-theater-test.js');
const SCRIPT_BODY = fs.readFileSync(SCRIPT_SRC, 'utf8');

// Three real TESTS keys the shipped script hand-authors. (If any are renamed,
// this test fails loudly rather than silently testing nothing.)
const KNOWN_KEYS = ['ALL-AI-PIPELINE-INTEGRITY', 'ALL-MCP-TOOL-TRUST', 'CIS-Controls-v8-Control7'];

function entryStub(framework) {
  // A minimal but representative framework-control-gaps entry WITHOUT a
  // theater_test (the backfill is what adds it).
  return {
    framework,
    control_id: 'X-1',
    control_name: 'sample control',
    designed_for: 'paper',
    misses: 'the real threat',
    real_requirement: 'do the real thing',
    status: 'open',
    opened_date: '2026-01-01',
    evidence_cves: [],
    atlas_refs: [],
    attack_refs: [],
  };
}

let _n = 0;
function makeSandbox(catalog) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-backfill-${_n++}-`));
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  // Copy the REAL script byte-for-byte; its CATALOG_PATH resolves to
  // <root>/data/framework-control-gaps.json via __dirname/../data.
  fs.writeFileSync(path.join(root, 'scripts', 'backfill-theater-test.js'), SCRIPT_BODY);
  const catalogPath = path.join(root, 'data', 'framework-control-gaps.json');
  fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2) + '\n');
  return { root, catalogPath };
}
function runBackfill(root) {
  return spawnSync(process.execPath, [path.join(root, 'scripts', 'backfill-theater-test.js')], { encoding: 'utf8' });
}
function cleanup(root) {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

test('backfill stamps a complete theater_test onto every known entry and exits 0', () => {
  const catalog = {
    _meta: { schema_version: '2.0.0', note: 'fixture' },
    [KNOWN_KEYS[0]]: entryStub('ALL'),
    [KNOWN_KEYS[1]]: entryStub('ALL'),
    [KNOWN_KEYS[2]]: entryStub('CIS Controls v8'),
  };
  const { root, catalogPath } = makeSandbox(catalog);
  try {
    const r = runBackfill(root);
    assert.equal(r.status, 0, `expected exit 0; stderr=${r.stderr}`);
    assert.match(r.stdout, /Updated 3\/3 entries with theater_test\./);

    const out = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    // _meta preserved untouched.
    assert.deepEqual(out._meta, catalog._meta);
    for (const key of KNOWN_KEYS) {
      const tt = out[key].theater_test;
      assert.ok(tt, `${key} must have a theater_test`);
      assert.equal(typeof tt.claim, 'string');
      assert.ok(tt.claim.length > 0, `${key} claim non-empty`);
      assert.equal(typeof tt.test, 'string');
      assert.ok(tt.test.length > 0, `${key} test non-empty`);
      assert.ok(Array.isArray(tt.evidence_required) && tt.evidence_required.length >= 1,
        `${key} evidence_required must be a non-empty array`);
      // verdict_when_failed is the PAPER constant.
      assert.equal(tt.verdict_when_failed, 'compliance-theater');
      // Pre-existing fields are preserved, not clobbered.
      assert.equal(out[key].control_id, 'X-1');
      assert.equal(out[key].real_requirement, 'do the real thing');
    }
  } finally { cleanup(root); }
});

test('output round-trips as 2-space JSON with a trailing newline', () => {
  const catalog = {
    _meta: { schema_version: '2.0.0' },
    [KNOWN_KEYS[0]]: entryStub('ALL'),
  };
  const { root, catalogPath } = makeSandbox(catalog);
  try {
    const r = runBackfill(root);
    assert.equal(r.status, 0, `stderr=${r.stderr}`);
    const raw = fs.readFileSync(catalogPath, 'utf8');
    assert.ok(raw.endsWith('\n'), 'file must end with a trailing newline');
    // 2-space indentation: the second line of a pretty-printed object starts
    // with exactly two spaces.
    const secondLine = raw.split('\n')[1];
    assert.match(secondLine, /^ {2}"/, 'expected 2-space indentation');
    // re-parse confirms valid JSON.
    assert.doesNotThrow(() => JSON.parse(raw));
  } finally { cleanup(root); }
});

test('an entry with no hand-authored test exits 2, names the key, and writes nothing', () => {
  const UNKNOWN = 'NONEXISTENT-FRAMEWORK-GAP-9999';
  const catalog = {
    _meta: { schema_version: '2.0.0' },
    [KNOWN_KEYS[0]]: entryStub('ALL'),
    [UNKNOWN]: entryStub('UNKNOWN'),
  };
  const { root, catalogPath } = makeSandbox(catalog);
  const before = fs.readFileSync(catalogPath, 'utf8');
  try {
    const r = runBackfill(root);
    assert.equal(r.status, 2, `expected exit 2 on a missing test; stdout=${r.stdout}`);
    assert.match(r.stderr, /Missing theater_test for:/);
    assert.match(r.stderr, new RegExp(UNKNOWN));
    // The fail path exits BEFORE writeFileSync, so the catalog is unchanged.
    const after = fs.readFileSync(catalogPath, 'utf8');
    assert.equal(after, before, 'catalog must be untouched when a test is missing');
    assert.equal(JSON.parse(after)[KNOWN_KEYS[0]].theater_test, undefined,
      'no entry should have been stamped on the failing run');
  } finally { cleanup(root); }
});

test('script reads + writes only its own data/framework-control-gaps.json (no other tree mutation)', () => {
  // Structural guard: the script resolves CATALOG_PATH from __dirname/../data
  // and writes back to that same path — so a copied script in a sandbox can
  // never touch the real repo catalog.
  assert.match(SCRIPT_BODY, /path\.resolve\(__dirname,\s*'\.\.',\s*'data',\s*'framework-control-gaps\.json'\)/);
  assert.match(SCRIPT_BODY, /fs\.writeFileSync\(CATALOG_PATH,/);
  // The only writeFileSync target is CATALOG_PATH.
  const writes = [...SCRIPT_BODY.matchAll(/fs\.writeFileSync\(\s*([A-Za-z_][\w.]*)/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(writes)], ['CATALOG_PATH'],
    'the backfill must write ONLY to CATALOG_PATH');
});
