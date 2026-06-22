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
