#!/usr/bin/env node
"use strict";
/**
 * Syncs the per-skill fields manifest.json caches from each skill's
 * frontmatter, the authoritative source the linter and staleness gate read.
 * Run it whenever frontmatter changes, then re-run sign-all — and, when a
 * cross-ref array changed, refresh-reverse-refs + build-indexes.
 *
 * `description`, `last_threat_review` and `forward_watch` MIRROR frontmatter
 * exactly and sync by replace. The cross-reference arrays are an enriched
 * superset — the manifest carries curated refs frontmatter does not — so they
 * sync by UNION; replacing them drops the curated refs build-indexes and
 * refresh-reverse-refs read.
 *
 * The package-level pins mirror the catalogs that carry them: `atlas_version`
 * and `atlas_version_date` from data/atlas-ttps.json `_meta` (`atlas_version`,
 * `atlas_release_date`), and `attack_version` and `attack_version_date` from
 * data/attack-techniques.json `_meta`. `threat_review_date` is the corpus-wide
 * review date and is not derived: every skill's review must fall within the
 * window before it, so it moves only when the whole corpus is reviewed.
 *
 * Exit codes: 0 = wrote (or already in sync), 1 = a skill file was missing, its
 * frontmatter failed to parse, or a pinned catalog lacked its version fields.
 */

const fs = require("fs");
const path = require("path");
const lint = require("../lib/lint-skills.js");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "manifest.json");

const MIRRORED_SCALAR = ["description", "last_threat_review"];
const MIRRORED_ARRAY = ["forward_watch"];
// Union, never replace — a replace drops the manifest's curated refs.
const MIRRORED_COVER = ["data_deps", "framework_gaps", "atlas_refs", "attack_refs", "rfc_refs", "cwe_refs", "d3fend_refs"];

function skillFrontmatter(id) {
  const p = path.join(ROOT, "skills", id, "skill.md");
  if (!fs.existsSync(p)) return null;
  const { frontmatter } = lint.extractFrontmatterBlock(fs.readFileSync(p, "utf8"));
  return lint.parseFrontmatter(frontmatter);
}

function sync() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  let changed = 0;
  const errors = [];
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    let fm;
    try {
      fm = skillFrontmatter(id);
    } catch (e) {
      errors.push(`${id}: frontmatter parse failed — ${e.message}`);
      continue;
    }
    if (!fm) {
      errors.push(`${id}: skill.md not found`);
      continue;
    }
    for (const key of MIRRORED_SCALAR) {
      if (key in fm && entry[key] !== fm[key]) {
        entry[key] = fm[key];
        changed++;
      }
    }
    for (const key of MIRRORED_ARRAY) {
      const want = Array.isArray(fm[key]) ? fm[key] : [];
      const have = Array.isArray(entry[key]) ? entry[key] : [];
      if (JSON.stringify(have) !== JSON.stringify(want)) {
        entry[key] = want;
        changed++;
      }
    }
    for (const key of MIRRORED_COVER) {
      const want = Array.isArray(fm[key]) ? fm[key] : [];
      if (!want.length) continue;
      const have = Array.isArray(entry[key]) ? entry[key] : [];
      const haveSet = new Set(have);
      const missing = want.filter((x) => !haveSet.has(x));
      if (missing.length) {
        entry[key] = [...have, ...missing];
        changed += missing.length;
      }
    }
  }
  // Package-level pins: [manifest key, catalog file, _meta key].
  const PINS = [
    ["atlas_version", "atlas-ttps.json", "atlas_version"],
    ["atlas_version_date", "atlas-ttps.json", "atlas_release_date"],
    ["attack_version", "attack-techniques.json", "attack_version"],
    ["attack_version_date", "attack-techniques.json", "attack_version_date"],
  ];
  const metas = {};
  for (const [key, file, metaKey] of PINS) {
    if (!(file in metas)) {
      try {
        metas[file] = JSON.parse(fs.readFileSync(path.join(ROOT, "data", file), "utf8"))._meta || {};
      } catch (e) {
        metas[file] = null;
        errors.push(`data/${file}: unreadable — ${e.message}`);
      }
    }
    const meta = metas[file];
    if (!meta) continue;
    const want = meta[metaKey];
    if (typeof want !== "string" || !want) {
      errors.push(`data/${file}: _meta.${metaKey} is missing`);
      continue;
    }
    if (manifest[key] !== want) {
      manifest[key] = want;
      changed++;
    }
  }
  if (errors.length) {
    for (const e of errors) process.stderr.write(`[sync-manifest-metadata] ${e}\n`);
    process.exitCode = 1;
    return;
  }
  if (changed > 0) {
    fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
  }
  process.stdout.write(`[sync-manifest-metadata] ${changed} field(s) synced from frontmatter and the pinned catalogs\n`);
}

sync();
