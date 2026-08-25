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
 *   2. The two pieces of non-trivial logic behind the timed rows — `parseFm`,
 *      which the watchlist row depends on, and `multiHopChain`, which the CVE
 *      cross-reference row is named for — are extracted from the shipped source
 *      by exact slice and evaluated in an isolated vm context (no file I/O, no
 *      side effects), so their REAL bytes are what gets asserted. parseFm is
 *      driven through scalar / block-sequence / [] / comment / CRLF /
 *      no-frontmatter inputs; multiHopChain is asserted to union the citing
 *      skills' refs onto the seed rather than terminating at it, which is the
 *      half of the chain a badly-chosen benchmark CVE leaves unmeasured.
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
    // Built from the id the script declares, so reseeding the row cannot leave
    // this expectation matching a CVE that is no longer benched.
    new RegExp(`multi-hop chain: ${CHAIN_CVE}`),
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

// Materialises a named function's exact shipped bytes in THIS realm via
// vm.runInThisContext (so returned objects/arrays share this realm's prototypes
// and compare with deepStrictEqual). Braces are balanced from the body open to
// its matching close. The src is the repo's own committed source — not external
// input — and the wrapper exposes no fs / require, so what runs is pure.
function extractFn(name) {
  const startIdx = SCRIPT_BODY.indexOf(`function ${name}(`);
  assert.ok(startIdx >= 0, `${name} must exist in audit-perf.js`);
  const braceOpen = SCRIPT_BODY.indexOf('{', startIdx);
  let depth = 0, end = -1;
  for (let i = braceOpen; i < SCRIPT_BODY.length; i++) {
    const ch = SCRIPT_BODY[i];
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  assert.ok(end > braceOpen, `failed to balance ${name} braces`);
  const src = SCRIPT_BODY.slice(startIdx, end + 1);
  return vm.runInThisContext(`(() => { ${src}\nreturn ${name}; })()`);
}

const parseFm = extractFn('parseFm');

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

// ---------------------------------------------------------------------------
// 3. The multi-hop chain — the row is named for a CVE lookup, so the lookup has
//    to be what it measures. Extracted from the shipped bytes like parseFm.
// ---------------------------------------------------------------------------

const multiHopChain = extractFn('multiHopChain');
// The benched id is read out of the shipped source, so the fixture below can
// never drift from the CVE the row actually times.
const CHAIN_CVE = (SCRIPT_BODY.match(/const CHAIN_CVE_ID = "(CVE-[\d-]+)"/) || [])[1];
const CATALOG = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const SKILLS = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8')).skills;

test('the benched multi-hop row names a CVE whose weaknesses skills actually cite', () => {
  // Guards the fixture itself: seeded from a CVE no skill cites, the join below
  // degrades to the seed and every assertion in the next test passes vacuously.
  assert.equal(typeof CHAIN_CVE, 'string', 'audit-perf.js must declare CHAIN_CVE_ID');
  const entry = CATALOG[CHAIN_CVE];
  assert.ok(entry, `${CHAIN_CVE} must be in the catalog for the benched row to mean anything`);
  const seed = entry.cwe_refs || [];
  assert.equal(Array.isArray(seed), true);
  assert.ok(seed.length >= 1, 'fixture CVE must carry cwe_refs');
  const citing = SKILLS.filter((s) => (s.cwe_refs || []).some((c) => seed.includes(c)));
  assert.ok(citing.length >= 1,
    `no skill cites any of ${JSON.stringify(seed)} — reseed the benched row from a CVE that joins`);
});

test('multiHopChain unions the citing skills refs onto the catalog entry seed', () => {
  const entry = CATALOG[CHAIN_CVE];
  const cweRefs = entry.cwe_refs || [];
  const entryAtlas = entry.atlas_refs || [];

  const r = multiHopChain(CATALOG, SKILLS, CHAIN_CVE);
  assert.equal(Array.isArray(r.cwes), true, 'cwes must be an array');
  // The seed comes first, in catalog order.
  assert.deepEqual(r.cwes.slice(0, cweRefs.length), cweRefs);
  assert.deepEqual(r.atlases.slice(0, entryAtlas.length), entryAtlas);
  for (const gap of Object.keys(entry.framework_control_gaps || {})) {
    assert.equal(r.fws.includes(gap), true, `framework gap ${gap} must reach the chain`);
  }

  // The citing set is exactly the skills that reference one of the CVE's own
  // weaknesses — computed here from the catalog + manifest, not from the result.
  const citingSkills = SKILLS.filter((s) => (s.cwe_refs || []).some((c) => cweRefs.includes(c)));
  assert.deepEqual(r.citing, citingSkills.map((s) => s.name));
  assert.ok(r.citing.length >= 1, 'the join must be non-empty or nothing below is proven');

  // Every ref carried ONLY by a citing skill has to have crossed the join. A
  // skill loop that never runs leaves these out.
  const dragCwes = [...new Set(citingSkills.flatMap((s) => s.cwe_refs || []))]
    .filter((c) => !cweRefs.includes(c));
  const dragAtlas = [...new Set(citingSkills.flatMap((s) => s.atlas_refs || []))]
    .filter((a) => !entryAtlas.includes(a));
  const dragFws = [...new Set(citingSkills.flatMap((s) => s.framework_gaps || []))]
    .filter((f) => !(f in (entry.framework_control_gaps || {})));
  assert.ok(dragCwes.length >= 1 && dragAtlas.length >= 1,
    'fixture must carry refs the entry itself lacks, or the union is untested');
  for (const c of dragCwes) assert.equal(r.cwes.includes(c), true, `citing-skill CWE ${c} must reach the chain`);
  for (const a of dragAtlas) assert.equal(r.atlases.includes(a), true, `citing-skill ATLAS ${a} must reach the chain`);
  for (const f of dragFws) assert.equal(r.fws.includes(f), true, `citing-skill framework gap ${f} must reach the chain`);

  // …and the seed stays fixed while the scan runs: a skill that cites only a
  // CWE some OTHER skill dragged in is not itself a citing skill.
  const secondHop = SKILLS.filter((s) =>
    !(s.cwe_refs || []).some((c) => cweRefs.includes(c)) &&
    (s.cwe_refs || []).some((c) => dragCwes.includes(c)));
  assert.ok(secondHop.length >= 1, 'fixture must expose a second-hop skill for the seed-fixity check');
  for (const s of secondHop) {
    assert.equal(r.citing.includes(s.name), false,
      `${s.name} cites no weakness of ${CHAIN_CVE} — it must not be counted as citing`);
  }
});

test('multiHopChain returns empty sets for a CVE id the catalog does not hold', () => {
  assert.equal(CATALOG['CVE-0000-00000'], undefined, 'control id must be absent from the catalog');
  const r = multiHopChain(CATALOG, SKILLS, 'CVE-0000-00000');
  // The chain is a function of the CVE, so an id with no entry yields nothing.
  // A filter that ignores its input would return the whole corpus here.
  assert.deepEqual(r, { cwes: [], atlases: [], fws: [], citing: [] });
});
