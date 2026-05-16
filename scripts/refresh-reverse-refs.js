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
const DATA_DIR = path.join(REPO_ROOT, 'data');

/* Per-catalog config:
 *   file              relative path under data/
 *   forwardField      manifest.skills[].* array name
 *   reverseField      per-entry reverse field name in the catalog
 */
const CATALOGS = [
  {
    file: 'atlas-ttps.json',
    forwardField: 'atlas_refs',
    reverseField: 'exceptd_skills',
  },
  {
    file: 'cwe-catalog.json',
    forwardField: 'cwe_refs',
    reverseField: 'skills_referencing',
  },
  {
    file: 'd3fend-catalog.json',
    forwardField: 'd3fend_refs',
    reverseField: 'skills_referencing',
  },
  {
    file: 'rfc-references.json',
    forwardField: 'rfc_refs',
    reverseField: 'skills_referencing',
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

function rebuildCatalog(cfg, manifest) {
  const filePath = path.join(DATA_DIR, cfg.file);
  const catalog = readJson(filePath);
  const index = buildReverseIndex(manifest.skills, cfg.forwardField);
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
    changed,
    added,
    removed,
    unchanged,
    orphans,
  };
}

function main() {
  const manifest = readJson(MANIFEST_PATH);
  const results = [];
  for (const cfg of CATALOGS) {
    results.push(rebuildCatalog(cfg, manifest));
  }
  for (const r of results) {
    process.stdout.write(
      `${r.file}: ${r.changed} entries changed ` +
        `(+${r.added} / -${r.removed} skill refs), ` +
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
  rebuildCatalog,
};

if (require.main === module) {
  main();
}
