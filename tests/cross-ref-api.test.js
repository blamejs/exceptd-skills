'use strict';

/**
 * Tests for lib/cross-ref-api.js — ATT&CK/ATLAS/CWE/D3FEND/skill cross-reference
 * resolution and the draft-exclusion contract on transitive correlations.
 *
 * Real-catalog assertions read the shipped data/ tree (default DATA_DIR).
 * The draft-leak case needs a synthetic catalog, which cross-ref-api binds at
 * require-time from EXCEPTD_DATA_DIR — so it runs in a child process with that
 * env var pointed at an isolated tempdir.
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

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// byTtp resolves the ATT&CK technique record, not only ATLAS.
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
// byTtp d3fend correlation reads counters_attack_techniques.
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
// Draft CVEs never leak into transitive correlations.
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
// #7 byFramework resolves framework_meta from the region-nested
// global-frameworks.json — a flat global[frameworkId] lookup always returned
// null, so framework_meta was universally null. The resolver now walks
// regions[*].frameworks[*] and matches by short key, full_name, or
// catalog_aliases.
// ---------------------------------------------------------------------------

test('#7 byFramework resolves framework_meta via a catalog alias (au-ism)', () => {
  const r = xref.byFramework('au-ism');
  assert.ok(r.gap_count > 0, 'au-ism must surface its framework-control gaps');
  assert.equal(r.gap_count, r.gaps.length, 'gap_count must match the gaps array length');
  assert.notEqual(r.framework_meta, null, 'framework_meta must no longer be null for a known framework');
  assert.equal(typeof r.framework_meta, 'object');
  assert.equal(r.framework_meta._framework_key, 'ASD_ISM',
    'alias au-ism must resolve to the ASD_ISM short key');
  assert.equal(r.framework_meta._region, 'AU',
    'ASD_ISM must be annotated with its AU region');
});

test('#7 byFramework resolves framework_meta via the short key (ASD_ISM)', () => {
  const r = xref.byFramework('ASD_ISM');
  assert.ok(r.gap_count > 0, 'ASD_ISM must surface its framework-control gaps');
  assert.equal(r.gap_count, r.gaps.length, 'gap_count must match the gaps array length');
  assert.notEqual(r.framework_meta, null, 'framework_meta must resolve non-null for the short key');
  assert.equal(typeof r.framework_meta, 'object');
  assert.equal(r.framework_meta._framework_key, 'ASD_ISM');
  assert.equal(r.framework_meta._region, 'AU');
});

test('#7 byFramework gap set is consistent across a framework\'s aliases (gaps resolve like framework_meta)', () => {
  // The gap filter must resolve the framework's full label set, not a literal
  // id match — otherwise a call by short key returns framework_meta but a gap
  // list inconsistent with it. au-ism and ASD_ISM are the same framework, so
  // both must surface the same gap_count.
  const viaAlias = xref.byFramework('au-ism');
  const viaKey = xref.byFramework('ASD_ISM');
  assert.ok(viaKey.gap_count > 0 && viaAlias.gap_count > 0, 'both must surface gaps');
  assert.equal(viaKey.gap_count, viaAlias.gap_count,
    'the short key and a catalog alias for the same framework must yield the same gap set');
  // And resolution must not over-match a different framework: GDPR resolves to
  // GDPR, not the AU framework's gaps.
  const gdpr = xref.byFramework('GDPR');
  assert.equal(gdpr.framework_meta && gdpr.framework_meta._framework_key, 'GDPR');
  assert.notEqual(gdpr.gap_count, viaKey.gap_count, 'GDPR must not collapse into the AU-ISM gap set');
});

test.describe("ask-routing-and-recipe-cleanup", () => {
  const xrefMod = require("../lib/cross-ref-api.js");

  test("byCve() no longer emits the dead (always-empty) recipes field", () => {
    const r = xrefMod.byCve("CVE-2025-53773");
    assert.ok(r, "byCve must return a result");
    assert.ok(!("recipes" in r), "the always-empty recipes field must be removed");
    // Other cross-reference fields remain intact (the removal was scoped to recipes).
    assert.ok("skills" in r && "framework_gaps" in r && "theater_tests" in r, "other xref fields must remain");
  });
});


// ---- routed from crossref-api-correlation ----
require("node:test").describe("crossref-api-correlation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-C-correlations ----
require("node:test").describe("hunt-fix-C-correlations", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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




// ---------------------------------------------------------------------------
// Finding #10 — byTtp d3fend correlation reads counters_attack_techniques.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding #11 — lagScore counts framework-specific gaps by normalized match.
// ---------------------------------------------------------------------------

const controlGaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const globalFrameworks = loadJson(path.join(DATA_DIR, 'global-frameworks.json'));





// ---------------------------------------------------------------------------
// Finding #12 — containers collector resets USER state per build stage.
// ---------------------------------------------------------------------------

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}







// ---------------------------------------------------------------------------
// Finding #13 — draft CVEs never leak into transitive correlations.
//
// cross-ref-api binds DATA_DIR at require-time from EXCEPTD_DATA_DIR, so the
// synthetic catalog must be exercised in a child process.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding #14 — REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
