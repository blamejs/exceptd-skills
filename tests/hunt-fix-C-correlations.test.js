'use strict';

/**
 * Regression coverage for the C-correlations cluster:
 *
 *   #9  byTtp() returned found:false / entry:null for every ATT&CK
 *       technique — only the ATLAS catalog was consulted for the entry,
 *       while skills + related_cves correctly unioned both id spaces.
 *   #10 byTtp() d3fend correlation read the always-empty `counters` field
 *       instead of the populated `counters_attack_techniques`.
 *   #11 framework-gap lagScore() reported framework_specific_gaps:0 for
 *       every framework whose global-frameworks short key is not a literal
 *       substring of its catalog display string.
 *   #12 containers collector tracked USER globally, so a multi-stage build
 *       with a non-root USER in an early stage masked a root final stage.
 *   #13 byCwe/byTtp/bySkill leaked _auto_imported draft CVEs into the
 *       related_cves/cve_refs correlations (byCve excluded them; these
 *       transitive paths did not).
 *   #14 gap-detectors REFERENCE_TOKEN_RE could not match D3A-* / D3F-*
 *       D3FEND ids, mis-flagging referenced entries as unused orphans.
 *
 * Real-catalog assertions read the shipped data/ tree (default DATA_DIR).
 * The draft-leak case (#13) needs a synthetic catalog, which cross-ref-api
 * binds at require-time from EXCEPTD_DATA_DIR — so it runs in a child
 * process with that env var pointed at an isolated tempdir.
 *
 * Run under --test-concurrency=1 (the cross-ref cache + shared data dir are
 * process-global).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const xref = require('../lib/cross-ref-api.js');
const fg = require('../lib/framework-gap.js');
const gd = require('../lib/gap-detectors.js');
const containers = require('../lib/collectors/containers.js');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// ---------------------------------------------------------------------------
// Finding #9 — byTtp resolves the ATT&CK technique record, not only ATLAS.
// ---------------------------------------------------------------------------

test('#9 byTtp resolves an ATT&CK technique entry (not only ATLAS)', () => {
  const r = xref.byTtp('T1190'); // Exploit Public-Facing Application
  assert.equal(r.found, true, 'ATT&CK technique must resolve found:true');
  assert.ok(r.entry, 'ATT&CK technique entry must be populated, not null');
  assert.equal(typeof r.entry.name, 'string');
  assert.ok(r.entry.name.length > 0, 'entry.name must be non-empty');
  assert.equal(r.entry.name, 'Exploit Public-Facing Application');
  // ATT&CK tactic is stored as an array of tactic names; the record is
  // passed through verbatim, so assert the shape the catalog actually uses.
  assert.ok(Array.isArray(r.entry.tactic) && r.entry.tactic.length > 0,
    'ATT&CK entry.tactic must be a non-empty array');
});

test('#9 byTtp still resolves an ATLAS technique entry', () => {
  const r = xref.byTtp('AML.T0010'); // ML Supply Chain Compromise
  assert.equal(r.found, true);
  assert.ok(r.entry, 'ATLAS entry must be populated');
  assert.equal(typeof r.entry.name, 'string');
  assert.equal(r.entry.name, 'ML Supply Chain Compromise');
  assert.equal(typeof r.entry.tactic, 'string'); // ATLAS stores tactic as a string
});

test('#9 byTtp reports found:false with a null entry for an unknown id', () => {
  const r = xref.byTtp('T9999.999');
  assert.equal(r.found, false);
  assert.equal(r.entry, null);
});

// ---------------------------------------------------------------------------
// Finding #10 — byTtp d3fend correlation reads counters_attack_techniques.
// ---------------------------------------------------------------------------

test('#10 byTtp surfaces D3FEND countermeasures for a covered ATT&CK technique', () => {
  const r = xref.byTtp('T1059'); // Command and Scripting Interpreter
  assert.ok(Array.isArray(r.d3fend_countermeasures),
    'd3fend_countermeasures must be an array');
  assert.ok(r.d3fend_countermeasures.length >= 5,
    'T1059 must surface its full D3FEND coverage (>=5), not an empty list');
  assert.ok(r.d3fend_countermeasures.includes('D3-EAL'),
    'T1059 must include the D3-EAL countermeasure');
});

test('#10 byTtp surfaces D3FEND countermeasures for a covered ATLAS technique', () => {
  const r = xref.byTtp('AML.T0010');
  assert.ok(Array.isArray(r.d3fend_countermeasures));
  assert.ok(r.d3fend_countermeasures.length >= 1,
    'AML.T0010 must surface >=1 D3FEND countermeasure');
  assert.ok(r.d3fend_countermeasures.includes('D3-EAL'),
    'AML.T0010 must include the D3-EAL countermeasure');
});

// ---------------------------------------------------------------------------
// Finding #11 — lagScore counts framework-specific gaps by normalized match.
// ---------------------------------------------------------------------------

const controlGaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const globalFrameworks = loadJson(path.join(DATA_DIR, 'global-frameworks.json'));

test('#11 lagScore counts framework-specific gaps for a key that is NOT a substring of its catalog string', () => {
  // EU_AI_ACT's catalog strings read "EU Artificial Intelligence Act ..."
  // and "EU AI Act ..."; the short key "EU_AI_ACT" is not a literal
  // substring of either, so the pre-fix `.includes(frameworkId)` returned 0.
  const r = fg.lagScore('EU_AI_ACT', controlGaps, globalFrameworks);
  assert.equal(typeof r.breakdown.framework_specific_gaps, 'number');
  assert.equal(r.breakdown.framework_specific_gaps, 7,
    'EU_AI_ACT must surface all 7 open AI-Act gaps');
});

test('#11 lagScore resolves another display-name-only framework (NCSC_CAF)', () => {
  const r = fg.lagScore('NCSC_CAF', controlGaps, globalFrameworks);
  assert.equal(r.breakdown.framework_specific_gaps, 7);
});

test('#11 lagScore leaves substring-matching frameworks unchanged', () => {
  // DORA / GDPR / NIS2 keys ARE substrings of their catalog strings, so the
  // fix must not change their counts (guards against over-matching).
  assert.equal(fg.lagScore('DORA', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 9);
  assert.equal(fg.lagScore('GDPR', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 2);
  assert.equal(fg.lagScore('NIS2', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 11);
});

test('#11 lagScore does not over-match a short key against another framework', () => {
  // EU_CRA resolves to exactly its own catalog string (1 open gap), not to
  // the broader EU_AI_ACT set — a regression that broadened matching too far
  // would inflate this.
  assert.equal(fg.lagScore('EU_CRA', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 1);
});

// ---------------------------------------------------------------------------
// Finding #12 — containers collector resets USER state per build stage.
// ---------------------------------------------------------------------------

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}

test('#12 multi-stage build with non-root builder USER but root final stage is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nRUN echo build\nFROM nginx:1.27\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'final stage has no USER directive — must fire runs-as-root');
});

test('#12 single-stage build with a trailing non-root USER is a MISS', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\nUSER node\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss');
});

test('#12 single-stage root build is a HIT', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 final stage built FROM a prior alias inherits the parent USER (MISS)', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nUSER node\nFROM base AS final\nRUN echo build\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss',
    'FROM <alias> inherits the parent stage USER — must not reset to root');
});

test('#12 final stage FROM an alias that never set USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nRUN echo build\nFROM base AS final\nRUN echo more\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 scratch final stage with no USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nFROM scratch\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'scratch starts a fresh stage (root) — must reset and fire');
});

// ---------------------------------------------------------------------------
// Finding #13 — draft CVEs never leak into transitive correlations.
//
// cross-ref-api binds DATA_DIR at require-time from EXCEPTD_DATA_DIR, so the
// synthetic catalog must be exercised in a child process.
// ---------------------------------------------------------------------------

test('#13 byCwe/byTtp/bySkill exclude _auto_imported drafts but keep curated CVEs', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c13-'));
  fs.mkdirSync(path.join(d, '_indexes'));
  const cve = {
    _meta: {},
    'CVE-2099-CURATED': { cwe_refs: ['CWE-79'], atlas_refs: ['AML.T0010'] },
    'CVE-2099-DRAFT': { _auto_imported: true, cwe_refs: ['CWE-79'], atlas_refs: ['AML.T0010'] },
  };
  fs.writeFileSync(path.join(d, 'cve-catalog.json'), JSON.stringify(cve), 'utf8');
  fs.writeFileSync(path.join(d, 'cwe-catalog.json'),
    JSON.stringify({ _meta: {}, 'CWE-79': { name: 'XSS' } }), 'utf8');
  fs.writeFileSync(path.join(d, 'atlas-ttps.json'),
    JSON.stringify({ _meta: {}, 'AML.T0010': { id: 'AML.T0010', name: 'Supply Chain', tactic: 'initial' } }), 'utf8');
  fs.writeFileSync(path.join(d, 'attack-techniques.json'), JSON.stringify({ _meta: {} }), 'utf8');
  fs.writeFileSync(path.join(d, 'd3fend-catalog.json'), JSON.stringify({ _meta: {} }), 'utf8');
  fs.writeFileSync(path.join(d, '_indexes', 'xref.json'),
    JSON.stringify({ cwe_refs: { 'CWE-79': ['skill-a'] }, atlas_refs: {}, attack_refs: {} }), 'utf8');
  fs.writeFileSync(path.join(d, '_indexes', 'summary-cards.json'), JSON.stringify({}), 'utf8');

  const apiPath = path.resolve(ROOT, 'lib', 'cross-ref-api.js');
  const script = [
    `const x = require(${JSON.stringify(apiPath)});`,
    'const out = {',
    '  cwe: x.byCwe("CWE-79").related_cves,',
    '  ttp: x.byTtp("AML.T0010").related_cves,',
    '  skill: x.bySkill("skill-a").cve_refs,',
    '};',
    'process.stdout.write(JSON.stringify(out));',
  ].join('\n');
  const raw = cp.execFileSync(process.execPath, ['-e', script], {
    env: { ...process.env, EXCEPTD_DATA_DIR: d },
  });
  const out = JSON.parse(raw.toString('utf8'));

  for (const [key, list] of Object.entries(out)) {
    assert.ok(Array.isArray(list), `${key} correlation must be an array`);
    assert.ok(list.includes('CVE-2099-CURATED'),
      `${key}: curated CVE must still surface (guard against over-exclusion)`);
    assert.ok(!list.includes('CVE-2099-DRAFT'),
      `${key}: _auto_imported draft must NOT leak into the correlation`);
  }
});

// ---------------------------------------------------------------------------
// Finding #14 — REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

test('#14 REFERENCE_TOKEN_RE matches D3A-* and D3F-* D3FEND artifact ids', () => {
  assert.equal(fullTokenMatch('D3A-AAD'), true, 'D3A-AAD must be recognized as a reference token');
  assert.equal(fullTokenMatch('D3F-UGPH'), true, 'D3F-UGPH must be recognized as a reference token');
});

test('#14 REFERENCE_TOKEN_RE still matches every prior token class', () => {
  assert.equal(fullTokenMatch('D3-EAL'), true);
  assert.equal(fullTokenMatch('CWE-79'), true);
  assert.equal(fullTokenMatch('T1059.003'), true);
  assert.equal(fullTokenMatch('AML.T0051'), true);
  assert.equal(fullTokenMatch('RFC-8446'), true);
});

test('#14 a skill body citing a D3A-* id removes that entry from the unused-orphan set', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c14-'));
  // Synthetic skills tree citing the D3A-* id in prose.
  const skillDir = path.join(tmp, 'skills', 'example-skill');
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'skill.md'),
    '# Example\n\nThis primitive maps to the D3A-AAD digital artifact.\n', 'utf8');

  const refs = gd.buildExternalRefs(tmp);
  assert.ok(refs.skillRefs.has('D3A-AAD'),
    'the D3A-AAD citation must be collected into skillRefs');

  // An _auto_imported D3FEND entry that IS referenced must not be flagged.
  const loaded = {
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': {
      _meta: {},
      'D3A-AAD': { _auto_imported: true, name: 'Account Access Removal' },
    },
  };
  const referenced = gd.unusedOrphanFindings(loaded, {
    skillRefs: refs.skillRefs,
    playbookRefs: refs.playbookRefs,
  });
  assert.ok(!referenced.some(f => f.id === 'D3A-AAD'),
    'a referenced D3A-* entry must NOT be flagged as an unused orphan');

  // Control: an UN-referenced _auto_imported D3A-* entry is still flagged,
  // proving the test would fail if the guard mis-fired.
  const unreferenced = gd.unusedOrphanFindings({
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': { _meta: {}, 'D3A-ZZZ': { _auto_imported: true, name: 'Orphan' } },
  }, { skillRefs: new Set(), playbookRefs: new Set() });
  assert.ok(unreferenced.some(f => f.id === 'D3A-ZZZ'),
    'an unreferenced auto-imported D3A-* entry must be flagged as orphan');
});
