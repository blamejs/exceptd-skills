#!/usr/bin/env node
/*
 * scripts/refresh-reverse-refs.js — rebuild reverse references in
 * data/{atlas-ttps,cwe-catalog,d3fend-catalog,rfc-references}.json from
 * the manifest.json forward direction.
 *
 * Background. Each skill in manifest.json declares forward references via
 * atlas_refs / cwe_refs / d3fend_refs / rfc_refs. The four catalogs above
 * carry a denormalised reverse field per entry (`exceptd_skills` for
 * atlas-ttps, `skills_referencing` for the other three) listing every
 * skill that points at that entry. The reverse field drifts whenever a
 * skill adds or removes a forward ref without the catalog being updated
 * in lockstep — Cycle 9 audit found this drift in production.
 *
 * Behaviour. For each catalog file:
 *   1. Walk every skill's relevant forward-ref array in manifest.json.
 *   2. For every catalog entry, list every skill that references it.
 *   3. Sort the resulting skill list and write it back into the per-entry
 *      reverse field. All other fields are preserved untouched.
 *
 * The script is idempotent: a second run produces no further changes.
 *
 * The script does NOT touch playbooks_referencing — that field carries
 * playbook ids (data/playbooks/*.json), not skill names; it has its own
 * source of truth and is out of scope for this audit fix.
 *
 * Run:   node scripts/refresh-reverse-refs.js
 *        npm run refresh-reverse-refs
 *
 * Exit code: 0 always (script is unconditionally write-mode). Use
 * tests/reverse-ref-drift.test.js as the read-only drift detector.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const CVE_CATALOG_PATH = path.join(REPO_ROOT, 'data', 'cve-catalog.json');
const DATA_DIR = path.join(REPO_ROOT, 'data');

/* Per-catalog config:
 *   file              relative path under data/
 *   forwardField      source-collection[].* array name
 *   reverseField      per-entry reverse field name in the catalog
 *   source            'manifest.skills' (default) — walk every skill's forward ref
 *                     'cve.entries'   — walk every CVE's forward ref (cycle 12 F3
 *                     extension); contributes CVE-IDs (skipping `_draft: true`
 *                     entries so the reverse direction tracks operator-queryable
 *                     truth, not in-progress curation state)
 *   entryKey          field on the source object used as the reverse-list value
 *                     ('name' for skills; '<self-id>' for CVE entries via the
 *                     map key, so the helper substitutes the iterating key)
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
  // Cycle 12 F3 (v0.12.32): CVE → CWE reverse direction. CWE entries
  // declare `evidence_cves` as the operator-facing "which CVEs land here"
  // index; pre-fix this was hand-maintained and drifted whenever a new
  // CVE landed without the matching CWE's evidence_cves being updated.
  // Now mirrors `cve.cwe_refs` → `cwe.evidence_cves` automatically.
  // Drafts excluded (they're invisible to default consumers anyway).
  {
    file: 'cwe-catalog.json',
    forwardField: 'cwe_refs',
    reverseField: 'evidence_cves',
    source: 'cve.entries',
    entryKey: null, // value is the iterating CVE id
  },
  // Cycle 20 B F4 (v0.12.40): CVE → framework-gap reverse direction.
  // Pre-fix 137 directional mismatches between cve.framework_control_gaps
  // (dict-keyed by gap-id) and gap.evidence_cves (array of CVE ids).
  // The forward shape on the CVE side is an OBJECT not an array — keys
  // are the gap ids, values are per-CVE narrative. The reverse direction
  // (which CVEs cite this gap) is a simple set of CVE ids on the gap
  // entry. The helper handles the dict-keyed forward field via the
  // `forwardFieldShape: 'object-keys'` flag.
  {
    file: 'framework-control-gaps.json',
    forwardField: 'framework_control_gaps',
    forwardFieldShape: 'object-keys', // dict; iterate keys
    reverseField: 'evidence_cves',
    source: 'cve.entries',
    entryKey: null, // value is the iterating CVE id
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

// Cycle 12 F3 (v0.12.32): build a reverse index keyed by catalog ID from the
// CVE catalog's forward refs. Each CVE entry has cwe_refs / attack_refs
// arrays; the reverse side is the CVE ID, indexed by the catalog entry.
// Draft entries are skipped — drafts are invisible to default consumers
// via cross-ref-api, so the reverse direction should track operator-
// queryable truth, not in-progress curation state.
//
// Cycle 20 B F4 (v0.12.40): forwardFieldShape parameter handles the
// CVE.framework_control_gaps case where the forward field is a dict
// (gap-id → narrative) rather than an array.
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

  // Surface forward refs that point at catalog entries that don't exist.
  // Not fatal here — that's a separate validation concern — but we report.
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

function main() {
  const manifest = readJson(MANIFEST_PATH);
  const cveCatalog = readJson(CVE_CATALOG_PATH);
  const results = [];
  for (const cfg of CATALOGS) {
    results.push(rebuildCatalog(cfg, manifest, cveCatalog));
  }
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
