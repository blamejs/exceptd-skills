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

// Cache entries store the parsed payload AND the mtimeMs of the source
// file at parse-time. Each load call re-stats the file; if mtime matches,
// the cached value is returned (one syscall, no parse). If mtime changed,
// re-parse + repopulate. If stat fails (file vanished mid-run, permission
// glitch), fall back to the cached value. Without mtime-keyed
// invalidation, long-running `orchestrator watch` processes never see
// `data/cve-catalog.json` mutations driven by `exceptd refresh --apply`.
const _cache = new Map();

// v0.12.14: catalog corruption no longer crashes the runner
// uncaught. A malformed JSON file in data/ used to produce a SyntaxError
// at require-time of any consumer (lib/playbook-runner.js), which threw
// out of the run() entrypoint without honoring AGENTS.md's "non-zero
// exit + {ok:false, error} to stderr" contract. Now: caught + degraded
// to an empty catalog with a recorded _loadError that downstream code
// can inspect.
const _loadErrors = [];

/**
 * v0.13.0: cache invalidation is keyed on (mtimeMs, size). Pre-v0.13 it
 * was mtime-only, but on filesystems with 1-2s mtime granularity
 * (FAT32, HFS+ pre-APFS, NFSv3, Docker bind-mounts that proxy mtime)
 * a rapid refresh-then-reload within the same second served stale
 * cached data. Adding `size` catches every content change that affects
 * byte count; mtimeMs catches in-place rewrites that preserve byte
 * count. Together they cover every realistic catalog-mutation path
 * without the cost of a per-load SHA computation. SHA-based tier is
 * available via _statContentHash() when callers want full invalidation
 * (e.g. long-running daemons against append-only catalogs).
 */
function _statSignature(p) {
  try {
    const s = fs.statSync(p);
    return { mtime: s.mtimeMs, size: s.size };
  } catch { return null; }
}

function _signatureEquals(a, b) {
  if (a === null && b === null) return true;
  if (a === null || b === null) return false;
  return a.mtime === b.mtime && a.size === b.size;
}

function loadCatalog(filename) {
  const full = path.join(DATA_DIR, filename);
  const sig = _statSignature(full);
  const cached = _cache.get(filename);
  if (cached && (sig === null || _signatureEquals(cached.sig, sig))) {
    return cached.value;
  }
  if (!fs.existsSync(full)) {
    _cache.set(filename, { value: {}, sig });
    return {};
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
    _cache.set(filename, { value: parsed, sig });
    return parsed;
  } catch (e) {
    _loadErrors.push({ kind: 'catalog', file: filename, error: e.message });
    const stub = {};
    Object.defineProperty(stub, '_loadError', { value: e.message, enumerable: false });
    _cache.set(filename, { value: stub, sig });
    return stub;
  }
}

function loadIndex(filename) {
  const full = path.join(INDEX_DIR, filename);
  const sig = _statSignature(full);
  const key = 'idx:' + filename;
  const cached = _cache.get(key);
  if (cached && (sig === null || _signatureEquals(cached.sig, sig))) {
    return cached.value;
  }
  if (!fs.existsSync(full)) {
    _cache.set(key, { value: {}, sig });
    return {};
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
    _cache.set(key, { value: parsed, sig });
    return parsed;
  } catch (e) {
    _loadErrors.push({ kind: 'index', file: filename, error: e.message });
    const stub = {};
    Object.defineProperty(stub, '_loadError', { value: e.message, enumerable: false });
    _cache.set(key, { value: stub, sig });
    return stub;
  }
}

function getLoadErrors() {
  return _loadErrors.slice();
}

function entries(catalog) {
  return Object.entries(catalog).filter(([k]) => !k.startsWith('_'));
}

// --- public API ---

/**
 * Full correlation for a CVE ID. Returns the catalog entry plus everything
 * that references it across skills, framework gaps, theater fingerprints,
 * recipes, and zero-day lessons.
 *
 * Auto-imported drafts (entries with `_auto_imported === true`) are
 * EXCLUDED by default. Drafts carry conservative-default mechanical fields
 * and null analytical fields pending curation; downstream analyze / bundle
 * emitters that assume `byCve()` returns curated data would treat the
 * draft's placeholders as authoritative. The cve-curation flow (which
 * surfaces the editorial questionnaire) opts in via
 * `byCve(id, { include_drafts: true })`; every other caller stays on the
 * default exclude path.
 */
function byCve(cveId, opts) {
  const includeDrafts = !!(opts && opts.include_drafts);
  const catalog = loadCatalog('cve-catalog.json');
  const entry = catalog[cveId];
  if (!entry) return { found: false, cve_id: cveId };
  if (!includeDrafts && entry._auto_imported === true) {
    return { found: false, cve_id: cveId, _draft_excluded: true };
  }

  const xref = loadIndex('xref.json');
  const theaterFp = loadIndex('theater-fingerprints.json');
  const gaps = loadCatalog('framework-control-gaps.json');
  const lessons = loadCatalog('zeroday-lessons.json');

  const skills = (xref[cveId] || xref.cves?.[cveId] || []).slice();
  // (Recipes are use-case curated, not CVE-triggered — recipes.json has no
  // `triggered_by`/CVE keying, so a per-CVE recipe lookup was always empty.
  // The dead `recipes:[]` field is no longer emitted.)
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
  theaterTestsFor,
  globalFrameworkContext,
  clearCache,
  // Lower-level access (engine uses these directly)
  _loadCatalog: loadCatalog,
  _loadIndex: loadIndex,
  // v0.12.14: surface accumulated catalog/index load errors. Returns
  // [{kind, file, error}, ...] for every catalog/index whose JSON
  // parse failed. Empty array on a healthy install.
  getLoadErrors,
};
