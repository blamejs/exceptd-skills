'use strict';

/**
 * Cross-reference API — pure read-only knowledge queries over data/ + data/_indexes/.
 *
 * This is the knowledge layer the host AI calls into during the ANALYZE phase
 * of every directive. No probes, no shellouts, no network. Every function takes
 * an identifier and returns correlated catalog entries from CVE / CWE / ATLAS /
 * ATT&CK / D3FEND / framework-gaps / global-frameworks / RFC / zero-day-lessons,
 * plus pre-computed indexes (xref, chains, recipes, theater-fingerprints).
 *
 * Catalogs are loaded lazily and cached for the lifetime of the process.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = process.env.EXCEPTD_DATA_DIR || path.join(ROOT, 'data');
const INDEX_DIR = path.join(DATA_DIR, '_indexes');

const _cache = new Map();

function loadCatalog(filename) {
  if (_cache.has(filename)) return _cache.get(filename);
  const full = path.join(DATA_DIR, filename);
  if (!fs.existsSync(full)) {
    _cache.set(filename, {});
    return {};
  }
  const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
  _cache.set(filename, parsed);
  return parsed;
}

function loadIndex(filename) {
  if (_cache.has('idx:' + filename)) return _cache.get('idx:' + filename);
  const full = path.join(INDEX_DIR, filename);
  if (!fs.existsSync(full)) {
    _cache.set('idx:' + filename, {});
    return {};
  }
  const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
  _cache.set('idx:' + filename, parsed);
  return parsed;
}

function entries(catalog) {
  return Object.entries(catalog).filter(([k]) => !k.startsWith('_'));
}

// --- public API ---

/**
 * Full correlation for a CVE ID. Returns the catalog entry plus everything
 * that references it across skills, framework gaps, theater fingerprints,
 * recipes, and zero-day lessons.
 */
function byCve(cveId) {
  const catalog = loadCatalog('cve-catalog.json');
  const entry = catalog[cveId];
  if (!entry) return { found: false, cve_id: cveId };

  const xref = loadIndex('xref.json');
  const recipes = loadIndex('recipes.json');
  const theaterFp = loadIndex('theater-fingerprints.json');
  const gaps = loadCatalog('framework-control-gaps.json');
  const lessons = loadCatalog('zeroday-lessons.json');

  const skills = (xref[cveId] || xref.cves?.[cveId] || []).slice();
  const matchingRecipes = entries(recipes).filter(([, r]) =>
    Array.isArray(r.triggered_by) && r.triggered_by.includes(cveId)
  ).map(([id]) => id);
  const theater = entries(theaterFp).filter(([, t]) =>
    Array.isArray(t.cve_refs) && t.cve_refs.includes(cveId)
  ).map(([id, t]) => ({ id, distinguisher: t.distinguisher || t.test }));
  const framework_gaps = entries(gaps).filter(([, g]) =>
    Array.isArray(g.cve_refs) && g.cve_refs.includes(cveId)
  ).map(([id, g]) => ({ id, framework: g.framework, control: g.control, status: g.status }));
  const lessons_learned = entries(lessons).filter(([, l]) =>
    Array.isArray(l.cve_refs) && l.cve_refs.includes(cveId)
  ).map(([id]) => id);

  return {
    found: true,
    cve_id: cveId,
    entry,
    rwep_score: entry.rwep_score,
    cisa_kev: !!entry.cisa_kev,
    active_exploitation: entry.active_exploitation,
    ai_discovered: !!entry.ai_discovered,
    atlas_refs: entry.atlas_refs || [],
    attack_refs: entry.attack_refs || [],
    skills,
    framework_gaps,
    theater_tests: theater,
    recipes: matchingRecipes,
    zeroday_lessons: lessons_learned
  };
}

function byCwe(cweId) {
  const catalog = loadCatalog('cwe-catalog.json');
  const entry = catalog[cweId];
  if (!entry) return { found: false, cwe_id: cweId };
  const xref = loadIndex('xref.json');
  const skills = (xref.cwes?.[cweId] || []).slice();
  const relatedCves = entries(loadCatalog('cve-catalog.json'))
    .filter(([, c]) => Array.isArray(c.cwe_refs) && c.cwe_refs.includes(cweId))
    .map(([id]) => id);
  return { found: true, cwe_id: cweId, entry, skills, related_cves: relatedCves };
}

function byTtp(ttpId) {
  const atlas = loadCatalog('atlas-ttps.json');
  const xref = loadIndex('xref.json');
  const entry = atlas[ttpId] || null;
  const skills = (xref.ttps?.[ttpId] || []).slice();
  const relatedCves = entries(loadCatalog('cve-catalog.json'))
    .filter(([, c]) =>
      (Array.isArray(c.atlas_refs) && c.atlas_refs.includes(ttpId)) ||
      (Array.isArray(c.attack_refs) && c.attack_refs.includes(ttpId))
    )
    .map(([id]) => id);
  const d3fend = entries(loadCatalog('d3fend-catalog.json'))
    .filter(([, d]) => Array.isArray(d.counters) && d.counters.includes(ttpId))
    .map(([id]) => id);
  return { found: !!entry, ttp_id: ttpId, entry, skills, related_cves: relatedCves, d3fend_countermeasures: d3fend };
}

function bySkill(skillName) {
  const xref = loadIndex('xref.json');
  const summary = loadIndex('summary-cards.json');
  const card = summary[skillName] || summary.skills?.[skillName] || null;
  const cveRefs = Object.entries(xref.cves || {})
    .filter(([, skills]) => Array.isArray(skills) && skills.includes(skillName))
    .map(([cve]) => cve);
  const ttpRefs = Object.entries(xref.ttps || {})
    .filter(([, skills]) => Array.isArray(skills) && skills.includes(skillName))
    .map(([ttp]) => ttp);
  return { skill: skillName, summary_card: card, cve_refs: cveRefs, ttp_refs: ttpRefs };
}

function byFramework(frameworkId, scenario) {
  const gaps = loadCatalog('framework-control-gaps.json');
  const global = loadCatalog('global-frameworks.json');
  const matching = entries(gaps).filter(([, g]) => {
    if (g.framework !== frameworkId && g.framework !== 'ALL') return false;
    if (scenario && Array.isArray(g.scenarios) && !g.scenarios.includes(scenario)) return false;
    return true;
  }).map(([id, g]) => ({ id, ...g }));
  const fwMeta = global[frameworkId] || null;
  return { framework: frameworkId, scenario: scenario || null, framework_meta: fwMeta, gaps: matching, gap_count: matching.length };
}

/**
 * Given a detected signal shape, return recipes whose triggered_by matches
 * any of the signals. Used by the analyze phase to chain into multi-step
 * workflows the agent should walk through next.
 */
function recipesFor(signals) {
  const recipes = loadIndex('recipes.json');
  const sigSet = new Set(signals);
  return entries(recipes)
    .filter(([, r]) => Array.isArray(r.triggered_by) && r.triggered_by.some(t => sigSet.has(t)))
    .map(([id, r]) => ({ id, name: r.name, skills: r.skills, steps: r.steps }));
}

/**
 * Theater-fingerprint lookup — given a finding shape, return the specific test
 * that distinguishes paper compliance from actual security (AGENTS.md Hard
 * Rule #6). Drives the validate phase when emit.theater_check = true.
 */
function theaterTestsFor({ cveIds = [], frameworkIds = [], skillIds = [] }) {
  const fp = loadIndex('theater-fingerprints.json');
  const matches = [];
  for (const [id, t] of entries(fp)) {
    const cveMatch  = cveIds.some(c => (t.cve_refs || []).includes(c));
    const fwMatch   = frameworkIds.some(f => (t.framework_refs || []).includes(f));
    const skillMatch = skillIds.some(s => (t.skill_refs || []).includes(s));
    if (cveMatch || fwMatch || skillMatch) {
      matches.push({ id, distinguisher: t.distinguisher || t.test, applies_when: t.applies_when });
    }
  }
  return matches;
}

/**
 * Global-first framework correlation — given a finding's CVE/TTP set, return
 * the relevant gaps across EU (NIS2/DORA/EU AI Act) + UK (CAF) + AU (ISM /
 * Essential 8) + ISO 27001:2022 + NIST. Satisfies AGENTS.md Hard Rule #5.
 */
function globalFrameworkContext({ cveIds = [], ttpIds = [] }) {
  const gaps = loadCatalog('framework-control-gaps.json');
  const cveSet = new Set(cveIds);
  const ttpSet = new Set(ttpIds);
  const grouped = {};
  for (const [id, g] of entries(gaps)) {
    const cveHit = (g.cve_refs || []).some(c => cveSet.has(c));
    const ttpHit = (g.ttp_refs || []).some(t => ttpSet.has(t));
    if (!cveHit && !ttpHit) continue;
    const fw = g.framework || 'unspecified';
    grouped[fw] = grouped[fw] || [];
    grouped[fw].push({ id, control: g.control, status: g.status, scenarios: g.scenarios });
  }
  return grouped;
}

function clearCache() { _cache.clear(); }

module.exports = {
  byCve,
  byCwe,
  byTtp,
  bySkill,
  byFramework,
  recipesFor,
  theaterTestsFor,
  globalFrameworkContext,
  clearCache,
  // Lower-level access (engine uses these directly)
  _loadCatalog: loadCatalog,
  _loadIndex: loadIndex,
};
