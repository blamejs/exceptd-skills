'use strict';

/**
 * Behavioral coverage for the ANALYZE-phase cross-reference API.
 *
 * These tests guard the correlation arrays the host AI reads during the
 * ANALYZE phase: the skill / framework-gap / theater-test / zero-day-lesson
 * links a CVE, CWE, TTP, or skill resolves to. The read keys in
 * lib/cross-ref-api.js must match the field names the shipped indexes and
 * catalogs actually use; when they drift, the correlations silently return
 * empty arrays while every "field present" check still passes. Each
 * assertion below therefore pairs presence with content — a non-empty array
 * containing a specific, real entry — so a key-name regression fails the
 * suite instead of zeroing the feature invisibly.
 *
 * Run under --test-concurrency=1 (the cross-ref cache + shared data dir are
 * process-global).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const xref = require('../lib/cross-ref-api.js');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const INDEX_DIR = path.join(DATA_DIR, '_indexes');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

const xrefIndex = loadJson(path.join(INDEX_DIR, 'xref.json'));
const theaterIndex = loadJson(path.join(INDEX_DIR, 'theater-fingerprints.json'));
const gaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const lessons = loadJson(path.join(DATA_DIR, 'zeroday-lessons.json'));

// --- CWE -> skills ---

test('byCwe resolves the skills the xref index records for the CWE', () => {
  // CWE-125 (out-of-bounds read) is referenced by two skills in the shipped
  // index; the correlation must surface both, not an empty list.
  const expected = xrefIndex.cwe_refs['CWE-125'];
  assert.ok(Array.isArray(expected) && expected.length >= 2, 'fixture: CWE-125 must map to >=2 skills');

  const r = xref.byCwe('CWE-125');
  assert.equal(r.found, true);
  assert.ok(Array.isArray(r.skills) && r.skills.length > 0, 'skills must be populated, not empty');
  assert.deepEqual(r.skills.slice().sort(), expected.slice().sort());
  assert.ok(r.skills.includes('kernel-lpe-triage'));
  assert.ok(r.skills.includes('fuzz-testing-strategy'));
});

// --- TTP -> skills ---

test('byTtp resolves ATLAS-id skills from the atlas_refs map', () => {
  const expected = xrefIndex.atlas_refs['AML.T0043'];
  assert.ok(Array.isArray(expected) && expected.length >= 5, 'fixture: AML.T0043 must map to >=5 skills');

  const r = xref.byTtp('AML.T0043');
  assert.ok(Array.isArray(r.skills) && r.skills.length >= 5, 'ATLAS TTP skills must be populated');
  assert.deepEqual(r.skills.slice().sort(), expected.slice().sort());
  assert.ok(r.skills.includes('fuzz-testing-strategy'));
});

test('byTtp resolves ATT&CK-id skills from the attack_refs map', () => {
  // Pick any ATT&CK technique the index actually records skills for.
  const attackId = Object.keys(xrefIndex.attack_refs).find(
    (k) => Array.isArray(xrefIndex.attack_refs[k]) && xrefIndex.attack_refs[k].length > 0
  );
  assert.ok(attackId, 'fixture: at least one attack_refs entry must carry skills');
  const expected = xrefIndex.attack_refs[attackId];

  const r = xref.byTtp(attackId);
  assert.ok(r.skills.length > 0, `ATT&CK TTP ${attackId} skills must be populated`);
  assert.deepEqual(r.skills.slice().sort(), expected.slice().sort());
});

// --- skill -> TTPs / CVEs ---

test('bySkill inverts the TTP maps so ttp_refs lists the skill\'s techniques', () => {
  const r = xref.bySkill('fuzz-testing-strategy');
  assert.ok(Array.isArray(r.ttp_refs) && r.ttp_refs.length > 0, 'ttp_refs must be populated');
  // AML.T0043 lists fuzz-testing-strategy, so the inverse must include it.
  assert.ok(r.ttp_refs.includes('AML.T0043'), 'inverted ttp_refs must contain AML.T0043');
});

test('bySkill resolves cve_refs transitively through the skill\'s CWEs', () => {
  // kernel-lpe-triage is one of the two skills CWE-125 maps to, and many
  // CVEs reference CWE-125, so the transitive CVE set must be non-empty.
  const r = xref.bySkill('kernel-lpe-triage');
  assert.ok(Array.isArray(r.cve_refs) && r.cve_refs.length > 0, 'cve_refs must be populated, not empty');
  assert.ok(r.cve_refs.every((c) => typeof c === 'string' && c.length > 0));
});

// --- CVE -> skills (transitive) ---

test('byCve resolves skills transitively through the CVE\'s CWEs', () => {
  // CVE-2025-53773 declares CWE-77; that CWE maps to a known skill set.
  const cveCatalog = xref._loadCatalog('cve-catalog.json');
  const entry = cveCatalog['CVE-2025-53773'];
  assert.ok(entry && Array.isArray(entry.cwe_refs) && entry.cwe_refs.includes('CWE-77'),
    'fixture: CVE-2025-53773 must declare CWE-77');

  const expected = new Set();
  for (const cwe of entry.cwe_refs) {
    for (const skill of xrefIndex.cwe_refs[cwe] || []) expected.add(skill);
  }
  assert.ok(expected.size > 0, 'fixture: CVE-2025-53773 CWEs must map to >=1 skill');

  const r = xref.byCve('CVE-2025-53773');
  assert.equal(r.found, true);
  assert.ok(Array.isArray(r.skills) && r.skills.length > 0, 'skills must be populated');
  assert.deepEqual(r.skills.slice().sort(), [...expected].sort());
});

// --- CVE -> framework gaps + zero-day lesson ---

test('byCve correlates framework gaps via evidence_cves with a real control id', () => {
  // CVE-2022-1471 (SnakeYAML deserialization) appears in many gaps'
  // evidence_cves; the join must surface them with a populated control.
  const cve = 'CVE-2022-1471';
  const expectedIds = Object.keys(gaps)
    .filter((k) => !k.startsWith('_'))
    .filter((k) => Array.isArray(gaps[k].evidence_cves) && gaps[k].evidence_cves.includes(cve));
  assert.ok(expectedIds.length >= 1, 'fixture: CVE-2022-1471 must appear in >=1 gap evidence_cves');

  const r = xref.byCve(cve);
  assert.equal(r.framework_gaps.length, expectedIds.length);
  assert.deepEqual(r.framework_gaps.map((g) => g.id).sort(), expectedIds.slice().sort());
  // control comes from control_id; framework + status are real fields too.
  for (const g of r.framework_gaps) {
    assert.equal(typeof g.control, 'string');
    assert.ok(g.control.length > 0, 'control (control_id) must be populated');
    assert.equal(typeof g.framework, 'string');
    assert.ok(g.framework.length > 0);
    assert.equal(typeof g.status, 'string');
  }
});

test('byCve surfaces a CVE-keyed zero-day lesson as a direct hit', () => {
  // CVE-2025-53773 is itself a lesson key.
  assert.ok(Object.prototype.hasOwnProperty.call(lessons, 'CVE-2025-53773'),
    'fixture: CVE-2025-53773 must be a zeroday-lessons key');

  const r = xref.byCve('CVE-2025-53773');
  assert.deepEqual(r.zeroday_lessons, ['CVE-2025-53773']);
});

test('byCve returns no zero-day lesson for a CVE absent from the lessons catalog', () => {
  const cveCatalog = xref._loadCatalog('cve-catalog.json');
  const noLesson = Object.keys(cveCatalog)
    .filter((k) => !k.startsWith('_'))
    .find((k) => !Object.prototype.hasOwnProperty.call(lessons, k) && cveCatalog[k]._auto_imported !== true);
  if (!noLesson) return; // every catalog CVE has a lesson — nothing to assert.
  const r = xref.byCve(noLesson);
  assert.deepEqual(r.zeroday_lessons, []);
});

// --- CVE -> theater fingerprints ---

test('byCve correlates theater fingerprints via the pattern evidence CVE', () => {
  // pattern-1's evidence.cve is the patch-management-theater exemplar.
  const cve = theaterIndex.patterns['pattern-1'].evidence.cve;
  assert.ok(typeof cve === 'string' && cve.startsWith('CVE-'), 'fixture: pattern-1 must carry an evidence CVE');

  const r = xref.byCve(cve);
  assert.ok(r.theater_tests.length >= 1, 'theater_tests must be populated for a pattern CVE');
  const hit = r.theater_tests.find((t) => t.id === 'pattern-1');
  assert.ok(hit, 'pattern-1 must be among the matched theater tests');
  assert.equal(typeof hit.distinguisher, 'string');
  assert.ok(hit.distinguisher.length > 0, 'distinguisher (fast_test) must be a non-empty string');
  assert.equal(hit.pattern_name, theaterIndex.patterns['pattern-1'].pattern_name);
});

test('byCve returns no theater tests for a CVE no fingerprint references', () => {
  const r = xref.byCve('CVE-0000-00000');
  // An unknown CVE is not found at all; a found CVE with no pattern match
  // must still yield an empty array (never undefined).
  assert.deepEqual(r.theater_tests || [], []);
});

// --- theaterTestsFor multi-key lookup ---

test('theaterTestsFor matches on the pattern evidence CVE', () => {
  const cve = theaterIndex.patterns['pattern-1'].evidence.cve;
  const matches = xref.theaterTestsFor({ cveIds: [cve] });
  assert.ok(matches.length >= 1, 'a known pattern CVE must match >=1 fingerprint');
  assert.ok(matches.some((m) => m.id === 'pattern-1'));
  assert.ok(matches.every((m) => typeof m.distinguisher === 'string' && m.distinguisher.length > 0));
});

test('theaterTestsFor accepts both bare and framework-qualified control ids', () => {
  const bare = xref.theaterTestsFor({ frameworkIds: ['SI-2'] });
  const qualified = xref.theaterTestsFor({ frameworkIds: ['NIST 800-53::SI-2'] });
  assert.ok(bare.length >= 1, 'bare control id SI-2 must match a fingerprint');
  assert.ok(qualified.length >= 1, 'qualified NIST 800-53::SI-2 must match a fingerprint');
  assert.ok(bare.some((m) => m.id === 'pattern-1'));
  assert.ok(qualified.some((m) => m.id === 'pattern-1'));
});

test('theaterTestsFor matches every fingerprint sourced from a given skill', () => {
  // All shipped fingerprints are sourced from compliance-theater.
  const expected = Object.keys(theaterIndex.patterns)
    .filter((k) => theaterIndex.patterns[k].source_skill === 'compliance-theater');
  assert.ok(expected.length >= 1, 'fixture: compliance-theater must source >=1 pattern');

  const matches = xref.theaterTestsFor({ skillIds: ['compliance-theater'] });
  assert.deepEqual(matches.map((m) => m.id).sort(), expected.slice().sort());
});

test('theaterTestsFor returns nothing for unmatched ids', () => {
  const matches = xref.theaterTestsFor({
    cveIds: ['CVE-0000-00000'],
    frameworkIds: ['NO-SUCH-CONTROL'],
    skillIds: ['no-such-skill'],
  });
  assert.deepEqual(matches, []);
});

// --- globalFrameworkContext ---

test('globalFrameworkContext groups gaps by framework for a referenced CVE', () => {
  const cve = 'CVE-2022-1471';
  const grouped = xref.globalFrameworkContext({ cveIds: [cve] });
  const frameworks = Object.keys(grouped);
  assert.ok(frameworks.length >= 1, 'a referenced CVE must group under >=1 framework');
  for (const fw of frameworks) {
    assert.ok(Array.isArray(grouped[fw]) && grouped[fw].length >= 1);
    for (const g of grouped[fw]) {
      assert.equal(typeof g.control, 'string');
      assert.ok(g.control.length > 0, 'control (control_id) must be populated');
    }
  }
});

test('globalFrameworkContext groups gaps by framework for a referenced TTP', () => {
  // Use an ATLAS ref that some gap actually records.
  const gapKeys = Object.keys(gaps).filter((k) => !k.startsWith('_'));
  let atlasRef = null;
  for (const k of gapKeys) {
    if (Array.isArray(gaps[k].atlas_refs) && gaps[k].atlas_refs.length) {
      atlasRef = gaps[k].atlas_refs[0];
      break;
    }
  }
  assert.ok(atlasRef, 'fixture: at least one gap must carry an atlas_ref');

  const grouped = xref.globalFrameworkContext({ ttpIds: [atlasRef] });
  assert.ok(Object.keys(grouped).length >= 1, 'a referenced TTP must group under >=1 framework');
});

// --- contract guard: read keys must exist in the shipped index/catalog ---

test('the xref sub-maps the API reads are exactly what the index emits', () => {
  // Skill correlations read cwe_refs / atlas_refs / attack_refs. If a future
  // index rename drops any of these, the correlations silently empty out —
  // this guard fails first.
  for (const key of ['cwe_refs', 'atlas_refs', 'attack_refs']) {
    assert.ok(Object.prototype.hasOwnProperty.call(xrefIndex, key),
      `xref.json must carry the ${key} map the API reads`);
  }
  // The API must NOT depend on the buckets that never existed.
  for (const absent of ['cves', 'cwes', 'ttps']) {
    assert.equal(Object.prototype.hasOwnProperty.call(xrefIndex, absent), false,
      `xref.json must not carry a ${absent} map (the API no longer reads it)`);
  }
});

test('framework-gap entries carry the join + display fields the API reads', () => {
  const gapKeys = Object.keys(gaps).filter((k) => !k.startsWith('_'));
  // Every entry must use evidence_cves (not cve_refs) and control_id.
  for (const k of gapKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(gaps[k], 'cve_refs'), false,
      `${k} must not reintroduce a cve_refs key (the API joins on evidence_cves)`);
    assert.equal(Object.prototype.hasOwnProperty.call(gaps[k], 'ttp_refs'), false,
      `${k} must not reintroduce a ttp_refs key (the API joins on atlas_refs/attack_refs)`);
  }
  // At least one entry must actually carry each field the API reads.
  assert.ok(gapKeys.some((k) => Array.isArray(gaps[k].evidence_cves)));
  assert.ok(gapKeys.some((k) => typeof gaps[k].control_id === 'string'));
});

test('theater fingerprints are nested under patterns with the fields the API reads', () => {
  assert.ok(theaterIndex.patterns && typeof theaterIndex.patterns === 'object',
    'theater index must expose a patterns container');
  const patternKeys = Object.keys(theaterIndex.patterns);
  assert.ok(patternKeys.length >= 1);
  for (const k of patternKeys) {
    const p = theaterIndex.patterns[k];
    assert.equal(typeof p.fast_test, 'string', `${k}.fast_test (distinguisher) must be a string`);
    assert.ok('evidence' in p, `${k} must carry an evidence object`);
    assert.equal(typeof p.source_skill, 'string', `${k}.source_skill must be a string`);
    assert.ok(Array.isArray(p.controls), `${k}.controls must be a list`);
  }
});
