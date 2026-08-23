#!/usr/bin/env node
/*
 * Rebuilds the denormalised reverse-reference fields in the data catalogs from the
 * forward direction, which is the source of truth: a skill's atlas_refs / cwe_refs
 * / d3fend_refs / rfc_refs, and a CVE's forward refs. Every other field is
 * preserved and a second run changes nothing. `playbooks_referencing` is out of
 * scope — it carries playbook ids, not skill names.
 * Write-mode only, exit 0 always; the read-only drift detector is
 * tests/reverse-ref-drift.test.js.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const CVE_CATALOG_PATH = path.join(REPO_ROOT, 'data', 'cve-catalog.json');
const DATA_DIR = path.join(REPO_ROOT, 'data');

/* Per-catalog config:
 *   file          relative path under data/
 *   forwardField  array (or dict, with forwardFieldShape) on the source object
 *   reverseField  per-entry field this script overwrites in the catalog
 *   source        'manifest.skills' walks every skill; 'cve.entries' every
 *                 non-draft CVE
 *   entryKey      field used as the reverse-list value; null means the key itself
 */
const CATALOGS = [
  {
    file: 'atlas-ttps.json',
    forwardField: 'atlas_refs',
    reverseField: 'exceptd_skills',
    source: 'manifest.skills',
    entryKey: 'name',
  },
  {
    file: 'cwe-catalog.json',
    forwardField: 'cwe_refs',
    reverseField: 'skills_referencing',
    source: 'manifest.skills',
    entryKey: 'name',
  },
  {
    file: 'd3fend-catalog.json',
    forwardField: 'd3fend_refs',
    reverseField: 'skills_referencing',
    source: 'manifest.skills',
    entryKey: 'name',
  },
  {
    file: 'rfc-references.json',
    forwardField: 'rfc_refs',
    reverseField: 'skills_referencing',
    source: 'manifest.skills',
    entryKey: 'name',
  },
  // `evidence_cves` mirrors cve.cwe_refs: which CVEs land on this CWE.
  {
    file: 'cwe-catalog.json',
    forwardField: 'cwe_refs',
    reverseField: 'evidence_cves',
    source: 'cve.entries',
    entryKey: null, // value is the iterating CVE id
  },
  // The forward side here is an OBJECT, not an array: keys are gap ids, values
  // the per-CVE narrative, hence forwardFieldShape. The reverse is a set of ids.
  {
    file: 'framework-control-gaps.json',
    forwardField: 'framework_control_gaps',
    forwardFieldShape: 'object-keys', // dict; iterate keys
    reverseField: 'evidence_cves',
    source: 'cve.entries',
    entryKey: null, // value is the iterating CVE id
  },
  // `cve_refs` back-edges: an ATLAS or ATT&CK entry shows which CVEs cite it.
  {
    file: 'atlas-ttps.json',
    forwardField: 'atlas_refs',
    reverseField: 'cve_refs',
    source: 'cve.entries',
    entryKey: null,
  },
  {
    file: 'attack-techniques.json',
    forwardField: 'attack_refs',
    reverseField: 'cve_refs',
    source: 'cve.entries',
    entryKey: null,
  },
];

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function buildReverseIndex(skills, forwardField) {
  // entryId -> Set<skillName>
  const index = new Map();
  for (const skill of skills) {
    const refs = Array.isArray(skill[forwardField]) ? skill[forwardField] : [];
    for (const id of refs) {
      if (!index.has(id)) index.set(id, new Set());
      index.get(id).add(skill.name);
    }
  }
  return index;
}

// catalogEntryId -> Set<cveId>. Drafts are skipped: they are invisible to default
// consumers through cross-ref-api. Pass forwardFieldShape 'object-keys' when the
// forward field is a dict.
function buildCveReverseIndex(cveCatalog, forwardField, forwardFieldShape) {
  const index = new Map();
  for (const [cveId, entry] of Object.entries(cveCatalog)) {
    if (cveId === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    if (entry._draft === true) continue;
    let refs;
    if (forwardFieldShape === 'object-keys') {
      const fv = entry[forwardField];
      refs = (fv && typeof fv === 'object' && !Array.isArray(fv)) ? Object.keys(fv) : [];
    } else {
      refs = Array.isArray(entry[forwardField]) ? entry[forwardField] : [];
    }
    for (const targetId of refs) {
      if (!index.has(targetId)) index.set(targetId, new Set());
      index.get(targetId).add(cveId);
    }
  }
  return index;
}

function rebuildCatalog(cfg, manifest, cveCatalog) {
  const filePath = path.join(DATA_DIR, cfg.file);
  const catalog = readJson(filePath);
  const index = cfg.source === 'cve.entries'
    ? buildCveReverseIndex(cveCatalog, cfg.forwardField, cfg.forwardFieldShape)
    : buildReverseIndex(manifest.skills, cfg.forwardField);
  let changed = 0;
  let added = 0;
  let removed = 0;
  let unchanged = 0;
  const orphans = []; // forward refs that don't resolve to a catalog entry
  const seenIds = new Set();

  for (const [id, entry] of Object.entries(catalog)) {
    if (id === '_meta') continue;
    if (typeof entry !== 'object' || entry === null) continue;
    seenIds.add(id);
    const before = Array.isArray(entry[cfg.reverseField])
      ? [...entry[cfg.reverseField]]
      : [];
    const computed = index.has(id)
      ? Array.from(index.get(id)).sort()
      : [];
    const beforeSet = new Set(before);
    const computedSet = new Set(computed);
    const sameLen = before.length === computed.length;
    const sameContent =
      sameLen && before.every((s, i) => s === computed[i]);
    if (!sameContent) {
      entry[cfg.reverseField] = computed;
      changed += 1;
      for (const s of computed) if (!beforeSet.has(s)) added += 1;
      for (const s of before) if (!computedSet.has(s)) removed += 1;
    } else {
      unchanged += 1;
    }
  }

  // Orphans — forward refs naming a catalog entry that does not exist — are
  // reported, never fatal. Never wire this script up as a "reverse refs clean?"
  // check: the failing gates are lib/lint-skills.js and reverse-ref-drift.test.js.
  for (const id of index.keys()) {
    if (!seenIds.has(id)) orphans.push(id);
  }

  if (changed > 0) {
    fs.writeFileSync(filePath, JSON.stringify(catalog, null, 2) + '\n', 'utf8');
  }

  return {
    file: cfg.file,
    source: cfg.source,
    reverseField: cfg.reverseField,
    changed,
    added,
    removed,
    unchanged,
    orphans,
  };
}

// `_meta.fed_by` is the symmetric counterpart of `_meta.feeds_into`: which
// playbooks chain INTO this one. Writes each playbook file in place.
function rebuildPlaybookReverse() {
  const playbooksDir = path.join(DATA_DIR, 'playbooks');
  if (!fs.existsSync(playbooksDir)) return { file: 'playbooks/*.json', source: 'playbook.feeds_into', reverseField: 'fed_by', changed: 0, added: 0, removed: 0, unchanged: 0, orphans: [] };
  const files = fs.readdirSync(playbooksDir).filter((n) => n.endsWith('.json'));
  const playbookEntries = [];
  for (const f of files) {
    const filePath = path.join(playbooksDir, f);
    let data;
    try { data = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
    catch (e) { continue; }
    if (!data || !data._meta || !data._meta.id) continue;
    playbookEntries.push({ file: f, filePath, data });
  }
  // targetId -> Set<sourceId>. A feeds_into entry carries `playbook_id` +
  // `condition`; fed_by keeps only the ids, so the condition is not duplicated.
  const index = new Map();
  for (const { data } of playbookEntries) {
    const meta = data._meta;
    const targets = Array.isArray(meta.feeds_into) ? meta.feeds_into : [];
    for (const t of targets) {
      const targetId = (t && typeof t === 'object') ? t.playbook_id : t;
      if (!targetId || typeof targetId !== 'string') continue;
      if (!index.has(targetId)) index.set(targetId, new Set());
      index.get(targetId).add(meta.id);
    }
  }
  let changed = 0, added = 0, removed = 0, unchanged = 0;
  const orphans = [];
  const knownIds = new Set(playbookEntries.map((e) => e.data._meta.id));
  for (const { filePath, data } of playbookEntries) {
    const meta = data._meta;
    const before = Array.isArray(meta.fed_by) ? [...meta.fed_by] : [];
    const computed = index.has(meta.id) ? Array.from(index.get(meta.id)).sort() : [];
    const beforeSet = new Set(before);
    const computedSet = new Set(computed);
    const sameContent = before.length === computed.length && before.every((x, i) => x === computed[i]);
    if (!sameContent) {
      meta.fed_by = computed;
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
      changed += 1;
      for (const s of computed) if (!beforeSet.has(s)) added += 1;
      for (const s of before) if (!computedSet.has(s)) removed += 1;
    } else {
      unchanged += 1;
    }
  }
  for (const targetId of index.keys()) {
    if (!knownIds.has(targetId)) orphans.push(targetId);
  }
  return { file: 'playbooks/*.json', source: 'playbook.feeds_into', reverseField: 'fed_by', changed, added, removed, unchanged, orphans };
}

function main() {
  const manifest = readJson(MANIFEST_PATH);
  const cveCatalog = readJson(CVE_CATALOG_PATH);
  const results = [];
  for (const cfg of CATALOGS) {
    results.push(rebuildCatalog(cfg, manifest, cveCatalog));
  }
  results.push(rebuildPlaybookReverse());
  for (const r of results) {
    process.stdout.write(
      `${r.file} (${r.source || 'skills'} → ${r.reverseField}): ${r.changed} entries changed ` +
        `(+${r.added} / -${r.removed} refs), ` +
        `${r.unchanged} unchanged` +
        (r.orphans.length
          ? `, ${r.orphans.length} orphan forward ref(s) [${r.orphans.join(', ')}]`
          : '') +
        '\n',
    );
  }
}

module.exports = {
  CATALOGS,
  buildReverseIndex,
  buildCveReverseIndex,
  rebuildCatalog,
};

if (require.main === module) {
  main();
}
