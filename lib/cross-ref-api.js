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

// Auto-imported drafts carry conservative-default mechanical fields and
// null analytical fields pending curation. byCve() excludes them by
// default; every transitive enumeration that walks the same catalog
// (byCwe / byTtp / bySkill) must apply the identical contract so a draft
// never surfaces as a curated cross-reference. Keyed on `_auto_imported`
// to match byCve's exact predicate, so all four entry points agree.
function _isDraftEntry(c) {
  return !!c && c._auto_imported === true;
}

// Single source of truth for the xref sub-maps the skill-correlation
// queries read. These names MUST stay identical to the keys the index
// builder emits into data/_indexes/xref.json; reading under a name the
// builder never writes silently yields empty correlations. The TTP maps
// are split by id space — ATLAS ids (AML.*) live in atlas_refs, ATT&CK
// ids (T*) in attack_refs — so a TTP lookup unions both.
const XREF_KEYS = {
  cwe: 'cwe_refs',
  atlas: 'atlas_refs',
  attack: 'attack_refs',
};

// CWE -> [skill, ...] from the xref index.
function skillsForCwe(xref, cweId) {
  return (xref[XREF_KEYS.cwe] && xref[XREF_KEYS.cwe][cweId]) || [];
}

// TTP -> [skill, ...]; ATLAS and ATT&CK ids occupy separate maps, so a
// single id resolves through whichever map owns its prefix (with a fall
// back to the other in case a caller passes an unprefixed id).
function skillsForTtp(xref, ttpId) {
  const atlas = xref[XREF_KEYS.atlas] || {};
  const attack = xref[XREF_KEYS.attack] || {};
  return (ttpId.startsWith('AML.') ? atlas[ttpId] : attack[ttpId]) || atlas[ttpId] || attack[ttpId] || [];
}

// No CVE->skill map exists in the index (no skill declares a CVE list, so
// the builder never emits one). The real linkage runs through the CVE's
// declared CWEs: each CWE maps to skills via the cwe_refs map. Union the
// skills across every CWE the CVE references, sorted + de-duplicated so
// the result is stable regardless of CWE ordering.
function skillsForCve(xref, cveEntry) {
  const out = new Set();
  for (const cwe of (cveEntry && cveEntry.cwe_refs) || []) {
    for (const skill of skillsForCwe(xref, cwe)) out.add(skill);
  }
  return [...out].sort();
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
  if (!includeDrafts && _isDraftEntry(entry)) {
    return { found: false, cve_id: cveId, _draft_excluded: true };
  }

  const xref = loadIndex('xref.json');
  const theaterFp = loadIndex('theater-fingerprints.json');
  const gaps = loadCatalog('framework-control-gaps.json');
  const lessons = loadCatalog('zeroday-lessons.json');

  // Skills correlate to a CVE transitively through its declared CWEs
  // (CVE -> cwe_refs -> xref.cwe_refs -> skills); there is no direct
  // CVE->skill index.
  const skills = skillsForCve(xref, entry);
  // (Recipes are use-case curated, not CVE-triggered — recipes.json has no
  // `triggered_by`/CVE keying, so a per-CVE recipe lookup was always empty.
  // The dead `recipes:[]` field is no longer emitted.)
  //
  // Theater fingerprints live under the index's `patterns` container; each
  // pattern records a single `evidence.cve` (or `evidence.campaign`, which
  // carries no CVE to match). The distinguishing check is `fast_test`.
  const theater = Object.entries(theaterFp.patterns || {})
    .filter(([, t]) => t && t.evidence && t.evidence.cve === cveId)
    .map(([id, t]) => ({ id, pattern_name: t.pattern_name, distinguisher: t.fast_test }));
  // Framework-control-gaps link CVEs through `evidence_cves`; the control
  // identifier field is `control_id`.
  const framework_gaps = entries(gaps).filter(([, g]) =>
    Array.isArray(g.evidence_cves) && g.evidence_cves.includes(cveId)
  ).map(([id, g]) => ({ id, framework: g.framework, control: g.control_id, status: g.status }));
  // Zero-day lessons are keyed by CVE id, so a referenced lesson is a
  // direct key hit rather than a back-reference scan.
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
  // TTP ids span two disjoint catalogs (ATLAS AML.* vs ATT&CK T*).
  // Resolve the record from whichever owns the id — namespaces never
  // collide, so order is irrelevant. Previously only atlas-ttps.json was
  // consulted, so every ATT&CK technique reported found:false / entry:null
  // even though skills + related_cves correctly unioned both spaces.
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
  // D3FEND maps countermeasures to the techniques they defeat through the
  // `counters_attack_techniques` field. The earlier `counters` field is
  // empty across every catalog entry, so this correlation was structurally
  // dead (a non-existent field .includes() is always false).
  const d3fend = entries(loadCatalog('d3fend-catalog.json'))
    .filter(([, d]) => Array.isArray(d.counters_attack_techniques) && d.counters_attack_techniques.includes(ttpId))
    .map(([id]) => id);
  return { found: !!entry, ttp_id: ttpId, entry, skills, related_cves: relatedCves, d3fend_countermeasures: d3fend };
}

function bySkill(skillName) {
  const xref = loadIndex('xref.json');
  const summary = loadIndex('summary-cards.json');
  const card = summary[skillName] || summary.skills?.[skillName] || null;
  // TTPs invert the atlas_refs + attack_refs maps: any TTP whose skill
  // list contains this skill is a reference. Both id spaces contribute.
  const ttpRefs = Object.entries({
    ...(xref[XREF_KEYS.atlas] || {}),
    ...(xref[XREF_KEYS.attack] || {}),
  })
    .filter(([, skills]) => Array.isArray(skills) && skills.includes(skillName))
    .map(([ttp]) => ttp)
    .sort();
  // CVEs link to a skill transitively: a CVE references CWEs, and each CWE
  // maps to skills via cwe_refs. Collect every CVE whose CWE set resolves
  // to this skill.
  const cveCatalog = loadCatalog('cve-catalog.json');
  const cveRefs = entries(cveCatalog)
    .filter(([, c]) => !_isDraftEntry(c) && (c.cwe_refs || []).some(cwe => skillsForCwe(xref, cwe).includes(skillName)))
    .map(([cve]) => cve)
    .sort();
  return { skill: skillName, summary_card: card, cve_refs: cveRefs, ttp_refs: ttpRefs };
}

// global-frameworks.json is keyed by REGION (EU/UK/AU/...), each with a nested
// `frameworks: { SHORTKEY: {full_name, catalog_aliases?, ...} }` map. A flat
// `global[frameworkId]` lookup therefore ALWAYS returned null — frameworkId is a
// short key or a catalog display name, never a region — so framework_meta was
// universally null. Walk the nested structure and match the requested id against
// the short key, the full_name, or any catalog_alias (normalized), returning the
// matched framework object annotated with its region + jurisdiction.
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
  const matching = entries(gaps)
    .filter(([, g]) => g.framework === frameworkId || g.framework === 'ALL')
    .map(([id, g]) => ({ id, ...g }));
  const fwMeta = resolveFrameworkMeta(global, frameworkId);
  return { framework: frameworkId, framework_meta: fwMeta, gaps: matching, gap_count: matching.length };
}

/**
 * Theater-fingerprint lookup — given a finding shape, return the specific test
 * that distinguishes paper compliance from actual security (AGENTS.md Hard
 * Rule #6). Drives the validate phase when emit.theater_check = true.
 */
function theaterTestsFor({ cveIds = [], frameworkIds = [], skillIds = [] }) {
  const fp = loadIndex('theater-fingerprints.json');
  const matches = [];
  // Fingerprints are nested under the index's `patterns` container, not at
  // the top level. Each pattern records a single `evidence.cve`, a list of
  // `controls` (each {framework, control_id}), and a `source_skill`. A
  // framework match accepts either the bare control id ("SI-2") or the
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
  // v0.12.14: surface accumulated catalog/index load errors. Returns
  // [{kind, file, error}, ...] for every catalog/index whose JSON
  // parse failed. Empty array on a healthy install.
  getLoadErrors,
};
