'use strict';

/**
 * Cross-reference API — read-only queries over data/ and data/_indexes/. Every
 * function takes an identifier and returns the correlated catalog entries.
 * Catalogs load lazily and are cached for the lifetime of the process.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = process.env.EXCEPTD_DATA_DIR || path.join(ROOT, 'data');
const INDEX_DIR = path.join(DATA_DIR, '_indexes');

// Each entry stores the parsed payload beside the source file's stat signature,
// so a long-running process sees a catalog that `refresh --apply` rewrote.
const _cache = new Map();

// A malformed JSON file degrades to an empty catalog carrying a recorded load
// error, rather than throwing out of the run() entrypoint.
const _loadErrors = [];

/**
 * Keyed on (mtimeMs, size): on a filesystem with 1-2s mtime granularity a
 * refresh-then-reload inside the same second serves stale data on mtime alone.
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

// Auto-imported drafts carry null analytical fields. byCve, byCwe, byTtp and
// bySkill all exclude on this one predicate, so a draft never reads as curated.
function _isDraftEntry(c) {
  return !!c && c._auto_imported === true;
}

// These names must match the keys the index builder emits into
// data/_indexes/xref.json — a name it never writes yields empty correlations with
// no error. ATLAS ids (AML.*) live in atlas_refs, ATT&CK ids in attack_refs.
const XREF_KEYS = {
  cwe: 'cwe_refs',
  atlas: 'atlas_refs',
  attack: 'attack_refs',
};

function skillsForCwe(xref, cweId) {
  return (xref[XREF_KEYS.cwe] && xref[XREF_KEYS.cwe][cweId]) || [];
}

// An id resolves through the map owning its prefix, falling back to the other.
function skillsForTtp(xref, ttpId) {
  const atlas = xref[XREF_KEYS.atlas] || {};
  const attack = xref[XREF_KEYS.attack] || {};
  return (ttpId.startsWith('AML.') ? atlas[ttpId] : attack[ttpId]) || atlas[ttpId] || attack[ttpId] || [];
}

// No CVE->skill map exists, so the linkage runs through the CVE's declared CWEs.
// The union is sorted so the result does not depend on CWE ordering.
function skillsForCve(xref, cveEntry) {
  const out = new Set();
  for (const cwe of (cveEntry && cveEntry.cwe_refs) || []) {
    for (const skill of skillsForCwe(xref, cwe)) out.add(skill);
  }
  return [...out].sort();
}

/**
 * Full correlation for a CVE id: the catalog entry plus everything referencing
 * it across skills, framework gaps, theater fingerprints and zero-day lessons.
 * Auto-imported drafts are excluded unless `opts.include_drafts` is set, since
 * callers read what this returns as curated.
 */
function byCve(cveId, opts) {
  const includeDrafts = !!(opts && opts.include_drafts);
  const catalog = loadCatalog('cve-catalog.json');
  const entry = catalog[cveId];
  if (!entry) return { found: false, cve_id: cveId };
  if (!includeDrafts && _isDraftEntry(entry)) {
    return { found: false, cve_id: cveId, _draft_excluded: true };
  }

  const xref = loadIndex('xref.json');
  const theaterFp = loadIndex('theater-fingerprints.json');
  const gaps = loadCatalog('framework-control-gaps.json');
  const lessons = loadCatalog('zeroday-lessons.json');

  const skills = skillsForCve(xref, entry);
  // Theater fingerprints live under the index's `patterns` container; each records
  // a single `evidence.cve`, and `fast_test` is the distinguishing check.
  const theater = Object.entries(theaterFp.patterns || {})
    .filter(([, t]) => t && t.evidence && t.evidence.cve === cveId)
    .map(([id, t]) => ({ id, pattern_name: t.pattern_name, distinguisher: t.fast_test }));
  const framework_gaps = entries(gaps).filter(([, g]) =>
    Array.isArray(g.evidence_cves) && g.evidence_cves.includes(cveId)
  ).map(([id, g]) => ({ id, framework: g.framework, control: g.control_id, status: g.status }));
  const lessons_learned = lessons[cveId] ? [cveId] : [];

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
  const skills = skillsForCwe(xref, cweId).slice();
  const relatedCves = entries(loadCatalog('cve-catalog.json'))
    .filter(([, c]) => !_isDraftEntry(c) && Array.isArray(c.cwe_refs) && c.cwe_refs.includes(cweId))
    .map(([id]) => id);
  return { found: true, cwe_id: cweId, entry, skills, related_cves: relatedCves };
}

function byTtp(ttpId) {
  // TTP ids span two disjoint catalogs (ATLAS AML.* vs ATT&CK T*); consulting
  // only one leaves every technique in the other reporting found:false.
  const atlas = loadCatalog('atlas-ttps.json');
  const attack = loadCatalog('attack-techniques.json');
  const xref = loadIndex('xref.json');
  const entry = atlas[ttpId] || attack[ttpId] || null;
  const skills = skillsForTtp(xref, ttpId).slice();
  const relatedCves = entries(loadCatalog('cve-catalog.json'))
    .filter(([, c]) =>
      !_isDraftEntry(c) && (
        (Array.isArray(c.atlas_refs) && c.atlas_refs.includes(ttpId)) ||
        (Array.isArray(c.attack_refs) && c.attack_refs.includes(ttpId))
      )
    )
    .map(([id]) => id);
  // D3FEND maps a countermeasure through `counters_attack_techniques`; the
  // `counters` field is empty catalog-wide, so filtering on it is dead.
  const d3fend = entries(loadCatalog('d3fend-catalog.json'))
    .filter(([, d]) => Array.isArray(d.counters_attack_techniques) && d.counters_attack_techniques.includes(ttpId))
    .map(([id]) => id);
  return { found: !!entry, ttp_id: ttpId, entry, skills, related_cves: relatedCves, d3fend_countermeasures: d3fend };
}

function bySkill(skillName) {
  const xref = loadIndex('xref.json');
  const summary = loadIndex('summary-cards.json');
  const card = summary[skillName] || summary.skills?.[skillName] || null;
  // Invert both TTP maps; both id spaces contribute.
  const ttpRefs = Object.entries({
    ...(xref[XREF_KEYS.atlas] || {}),
    ...(xref[XREF_KEYS.attack] || {}),
  })
    .filter(([, skills]) => Array.isArray(skills) && skills.includes(skillName))
    .map(([ttp]) => ttp)
    .sort();
  const cveCatalog = loadCatalog('cve-catalog.json');
  const cveRefs = entries(cveCatalog)
    .filter(([, c]) => !_isDraftEntry(c) && (c.cwe_refs || []).some(cwe => skillsForCwe(xref, cwe).includes(skillName)))
    .map(([cve]) => cve)
    .sort();
  return { skill: skillName, summary_card: card, cve_refs: cveRefs, ttp_refs: ttpRefs };
}

// global-frameworks.json is keyed by region, each region holding a nested
// `frameworks: { SHORTKEY: {...} }` map, so a flat `global[frameworkId]` lookup
// never matches. Match the short key, full_name or any catalog_alias, normalized.
function resolveFrameworkMeta(global, frameworkId) {
  if (!global || frameworkId == null) return null;
  const norm = (s) => String(s == null ? '' : s).toLowerCase().replace(/\([^)]*\)/g, '').replace(/[\s_-]/g, '');
  const want = norm(frameworkId);
  if (!want) return null;
  for (const [region, rv] of Object.entries(global)) {
    if (region === '_meta' || !rv || typeof rv !== 'object') continue;
    const fws = rv.frameworks || {};
    for (const [shortKey, fv] of Object.entries(fws)) {
      if (!fv || typeof fv !== 'object') continue;
      const aliases = Array.isArray(fv.catalog_aliases) ? fv.catalog_aliases.map(norm) : [];
      if (shortKey === frameworkId ||
          norm(shortKey) === want ||
          (fv.full_name && norm(fv.full_name) === want) ||
          aliases.some((a) => a && (a === want || a.includes(want) || want.includes(a)))) {
        return { ...fv, _framework_key: shortKey, _region: region, _jurisdiction: rv.jurisdiction || null };
      }
    }
  }
  return null;
}

function byFramework(frameworkId) {
  const gaps = loadCatalog('framework-control-gaps.json');
  const global = loadCatalog('global-frameworks.json');
  const fwMeta = resolveFrameworkMeta(global, frameworkId);
  // Match gap rows against the framework's whole label set: the catalog files
  // gaps under labels (au-ism / AU ISM / ACSC ISM) that diverge from the key.
  const norm = (s) => String(s == null ? '' : s).toLowerCase().replace(/\([^)]*\)/g, '').replace(/[\s_-]/g, '');
  const labels = new Set([norm(frameworkId)]);
  if (fwMeta) {
    if (fwMeta._framework_key) labels.add(norm(fwMeta._framework_key));
    if (fwMeta.full_name) labels.add(norm(fwMeta.full_name));
    for (const a of (Array.isArray(fwMeta.catalog_aliases) ? fwMeta.catalog_aliases : [])) labels.add(norm(a));
  }
  labels.delete('');
  const labelMatch = (fw) => {
    const n = norm(fw);
    if (!n) return false;
    for (const l of labels) if (n === l || n.includes(l) || l.includes(n)) return true;
    return false;
  };
  const matching = entries(gaps)
    .filter(([, g]) => {
      if (g.framework === 'ALL') return true;
      const fwList = Array.isArray(g.framework) ? g.framework : [g.framework];
      return fwList.some(labelMatch);
    })
    .map(([id, g]) => ({ id, ...g }));
  return { framework: frameworkId, framework_meta: fwMeta, gaps: matching, gap_count: matching.length };
}

/**
 * For a finding shape, the test that distinguishes paper compliance from actual
 * security. Drives the validate phase when emit.theater_check is true.
 */
function theaterTestsFor({ cveIds = [], frameworkIds = [], skillIds = [] }) {
  const fp = loadIndex('theater-fingerprints.json');
  const matches = [];
  // A framework match accepts either the bare control id ("SI-2") or the
  // qualified "framework::control_id" form the by_control index keys on.
  for (const [id, t] of Object.entries(fp.patterns || {})) {
    if (!t) continue;
    const cveMatch = t.evidence && cveIds.includes(t.evidence.cve);
    const fwMatch = (t.controls || []).some(c =>
      frameworkIds.includes(c.control_id) || frameworkIds.includes(`${c.framework}::${c.control_id}`)
    );
    const skillMatch = skillIds.includes(t.source_skill);
    if (cveMatch || fwMatch || skillMatch) {
      matches.push({ id, pattern_name: t.pattern_name, distinguisher: t.fast_test, controls: t.controls });
    }
  }
  return matches;
}

/**
 * Given a finding's CVE/TTP set, the relevant gaps across EU (NIS2/DORA/EU AI
 * Act), UK (CAF), AU (ISM / Essential 8), ISO 27001:2022 and NIST.
 */
function globalFrameworkContext({ cveIds = [], ttpIds = [] }) {
  const gaps = loadCatalog('framework-control-gaps.json');
  const cveSet = new Set(cveIds);
  const ttpSet = new Set(ttpIds);
  const grouped = {};
  for (const [id, g] of entries(gaps)) {
    const cveHit = (g.evidence_cves || []).some(c => cveSet.has(c));
    const ttpHit = [...(g.atlas_refs || []), ...(g.attack_refs || [])].some(t => ttpSet.has(t));
    if (!cveHit && !ttpHit) continue;
    const fw = g.framework || 'unspecified';
    grouped[fw] = grouped[fw] || [];
    grouped[fw].push({ id, control: g.control_id, control_name: g.control_name, status: g.status });
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
  // [{kind, file, error}] per catalog or index whose JSON parse failed.
  getLoadErrors,
};
