#!/usr/bin/env node
"use strict";
/**
 * scripts/sync-manifest-metadata.js
 *
 * Several per-skill fields in manifest.json are a cache of the authoritative
 * values in each skill's frontmatter (the linter and the staleness gate read
 * frontmatter, so frontmatter is the single source of truth). Nothing kept
 * the cache in sync, so editing frontmatter left the manifest copy stale.
 *
 * Two sync disciplines, because the fields differ in kind:
 *
 *   - MIRROR (exact): `last_threat_review` (scalar) and `forward_watch`
 *     (array) are an exact copy of frontmatter. Synced by replace.
 *
 *   - COVER (union): the cross-reference arrays (`data_deps`,
 *     `framework_gaps`, `atlas_refs`, `attack_refs`, `rfc_refs`, `cwe_refs`,
 *     `d3fend_refs`) are an ENRICHED SUPERSET — the manifest may carry extra
 *     curated refs that the derived indexes (build-indexes) and the
 *     reverse-ref refresh (refresh-reverse-refs) read. The invariant is that
 *     every frontmatter-declared ref MUST appear in the manifest, or it
 *     silently vanishes from those surfaces. Synced by UNION (append the
 *     missing frontmatter refs, preserve the manifest's order + enrichment) —
 *     never by replace, which would drop curated refs.
 *
 * Run it whenever skill frontmatter changes, then re-run sign-all (and, when
 * cross-ref arrays changed, refresh-reverse-refs + build-indexes) so the
 * refreshed manifest is signed and the derived surfaces pick up the refs.
 *
 * tests/manifest-frontmatter-sync.test.js fails the suite if the cache ever
 * drifts again, so a missed run is caught before release rather than shipping
 * a manifest that contradicts its own skill bodies.
 *
 * Exit codes: 0 = wrote (or already in sync), 1 = a skill file was missing or
 * its frontmatter failed to parse.
 */

const fs = require("fs");
const path = require("path");
const lint = require("../lib/lint-skills.js");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "manifest.json");

// The frontmatter fields the manifest caches and must mirror verbatim.
const MIRRORED_SCALAR = ["last_threat_review"];
const MIRRORED_ARRAY = ["forward_watch"];
// Cross-reference arrays: the manifest is an enriched superset, so sync by
// UNION (cover) — append frontmatter refs the manifest is missing, keep the
// manifest's own curated refs. See the header for why replace would regress.
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
  if (errors.length) {
    for (const e of errors) process.stderr.write(`[sync-manifest-metadata] ${e}\n`);
    process.exitCode = 1;
    return;
  }
  if (changed > 0) {
    fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
  }
  process.stdout.write(`[sync-manifest-metadata] ${changed} field(s) synced from frontmatter\n`);
}

sync();
