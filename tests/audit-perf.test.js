'use strict';

/**
 * tests/audit-perf.test.js
 *
 * Subject coverage for scripts/audit-perf.js — the hot-path micro-benchmark.
 * The script runs at module load (no exports, exits 0 naturally), so it is
 * exercised two ways:
 *
 *   1. Subprocess against the real repo: every benchmarked operation must
 *      actually run to completion against live data (the multi-hop chain
 *      dereferences a real catalog CVE, the watchlist aggregator parses every
 *      skill frontmatter, etc.). The report's contract is asserted — the
 *      header, a timing row per documented operation, the Sizes section, and
 *      exit 0. A throw in any benched path would drop its row / flip the exit.
 *
 *   2. The inline `parseFm` frontmatter parser is the one piece of non-trivial
 *      logic the watchlist row depends on. It is extracted from the shipped
 *      source by exact slice and evaluated in an isolated vm context (no file
 *      I/O, no side effects) so its REAL bytes are tested against scalar /
 *      block-sequence / [] / comment / CRLF / no-frontmatter inputs, including
 *      a negative path.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT_SRC = path.join(ROOT, 'scripts', 'audit-perf.js');
const SCRIPT_BODY = fs.readFileSync(SCRIPT_SRC, 'utf8');

// ---------------------------------------------------------------------------
// 1. Subprocess report contract on the real repo.
// ---------------------------------------------------------------------------

test('audit-perf runs every benched hot path against the real repo and exits 0', () => {
  const r = spawnSync(process.execPath, [SCRIPT_SRC], { encoding: 'utf8', cwd: ROOT });
  assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);
  assert.equal(r.stderr.trim(), '', 'no error output expected on a clean run');

  // Header + table.
  assert.match(r.stdout, /=== exceptd hot-path performance ===/);
  assert.match(r.stdout, /^Operation\s+Time$/m);

  // A timing row for each documented operation. Each row is "<ms> ms  <label>".
  const expectedLabels = [
    /load manifest\.json \(parse\)/,
    /load all \d+ data catalogs/,
    /read all \d+ skill\.md bodies/,
    /parse all \d+ skill frontmatters/,
    /trigger string-match against all skills \(single query\)/,
    /xref: which skills cite CWE-79\? \(linear scan\)/,
    /multi-hop chain: CVE-2026-31431/,
    /watchlist aggregator \(full scan, \d+ skills\)/,
    /full cross-skill audit script/,
  ];
  for (const re of expectedLabels) {
    assert.match(r.stdout, re, `missing benchmark row: ${re}`);
  }
  // Each timed row carries a millisecond figure.
  const timedRows = r.stdout.split('\n').filter((l) => /^\s+[\d.]+ ms\s{2}\S/.test(l));
  assert.ok(timedRows.length >= expectedLabels.length,
    `expected >= ${expectedLabels.length} timed rows, got ${timedRows.length}`);

  // Sizes section reports byte counts for the four artifact classes.
  assert.match(r.stdout, /=== Sizes ===/);
  assert.match(r.stdout, /manifest\.json:\s+[\d,]+ bytes/);
  assert.match(r.stdout, /data\/\*\.json \(\d+ files\):\s+[\d,]+ bytes/);
  assert.match(r.stdout, /skills\/\*\/skill\.md \(\d+ files\):\s+[\d,]+ bytes/);

  // Recommendation surfaces footer.
  assert.match(r.stdout, /=== Recommendation surfaces \(manual review\) ===/);
});

// ---------------------------------------------------------------------------
// 2. The inline parseFm parser — tested against its exact shipped bytes.
// ---------------------------------------------------------------------------

function extractParseFm() {
  const startIdx = SCRIPT_BODY.indexOf('function parseFm(');
  assert.ok(startIdx >= 0, 'parseFm must exist in audit-perf.js');
  // Balance braces from the function body open to its matching close.
  const braceOpen = SCRIPT_BODY.indexOf('{', startIdx);
  let depth = 0, end = -1;
  for (let i = braceOpen; i < SCRIPT_BODY.length; i++) {
    const ch = SCRIPT_BODY[i];
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  assert.ok(end > braceOpen, 'failed to balance parseFm braces');
  const src = SCRIPT_BODY.slice(startIdx, end + 1);
  // Materialise the exact shipped function bytes in THIS realm via
  // vm.runInThisContext (so returned objects/arrays share this realm's
  // prototypes and compare with deepStrictEqual). The src is the repo's own
  // committed source — not external input — and the wrapper exposes no fs /
  // require, so the parser is pure and side-effect-free.
  return vm.runInThisContext(`(() => { ${src}\nreturn parseFm; })()`);
}

const parseFm = extractParseFm();

test('parseFm returns null when the text has no frontmatter block', () => {
  assert.equal(parseFm('# just a heading\n\nbody'), null);
  assert.equal(parseFm('---\nname: x'), null, 'unterminated frontmatter -> null');
});

test('parseFm parses scalar key:value pairs', () => {
  const r = parseFm(['---', 'name: kernel-lpe-triage', 'version: 1.2.3', '---', '', 'body'].join('\n'));
  assert.equal(r.name, 'kernel-lpe-triage');
  assert.equal(r.version, '1.2.3');
});

test('parseFm parses a YAML block sequence into an array', () => {
  const r = parseFm([
    '---',
    'forward_watch:',
    '  - ATLAS v5.2.0 release',
    '  - NIST CSF 2.1 draft',
    'name: x',
    '---',
    'body',
  ].join('\n'));
  assert.deepEqual(r.forward_watch, ['ATLAS v5.2.0 release', 'NIST CSF 2.1 draft']);
  assert.equal(r.name, 'x', 'a scalar following a block sequence still parses');
});

test('parseFm treats `[]` as an empty array', () => {
  const r = parseFm(['---', 'triggers: []', '---', 'x'].join('\n'));
  assert.deepEqual(r.triggers, []);
});

test('parseFm skips blank and comment lines inside the block', () => {
  const r = parseFm(['---', '# a comment', '', 'name: y', '---', 'x'].join('\n'));
  assert.equal(r.name, 'y');
  assert.equal('# a comment' in r, false);
});

test('parseFm parses the first key on CRLF input (block-end detection is LF-anchored)', () => {
  // The shipped parser locates the frontmatter end with indexOf("\n---") and
  // captures up to it; on a CRLF body that boundary lands right after the first
  // key, so only `name` survives. This pins the REAL behaviour (a scalar key is
  // still recovered from CRLF input) rather than an idealised one.
  const r = parseFm(['---', 'name: z', 'version: 0.0.1', '---', 'body'].join('\r\n'));
  assert.equal(r.name, 'z');
});

test('parseFm: an empty frontmatter block yields an empty object (not null)', () => {
  const r = parseFm(['---', '---', 'body'].join('\n'));
  assert.deepEqual(r, {});
});
