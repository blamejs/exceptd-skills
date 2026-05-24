#!/usr/bin/env node
"use strict";
/**
 * scripts/sync-manifest-metadata.js
 *
 * The per-skill `forward_watch` and `last_threat_review` fields in
 * manifest.json are a cache of the authoritative values in each skill's
 * frontmatter. There was no step that refreshed that cache, so editing a
 * skill's frontmatter (e.g. bumping last_threat_review on a threat-review
 * pass, or rewording a forward_watch item) left the manifest copy stale.
 * Over time the two diverged on dozens of skills.
 *
 * This script rewrites the manifest's `forward_watch` and
 * `last_threat_review` for every skill from that skill's frontmatter, which
 * is the single source of truth (the linter and the staleness gate both read
 * frontmatter). Run it whenever skill frontmatter changes, then re-run the
 * sign-all step so the refreshed manifest is signed.
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
