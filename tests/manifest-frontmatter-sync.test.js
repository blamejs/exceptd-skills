'use strict';

/**
 * tests/manifest-frontmatter-sync.test.js
 *
 * The per-skill `forward_watch` and `last_threat_review` fields in
 * manifest.json are a cache of the authoritative values in each skill's
 * frontmatter (the linter and the staleness gate both read frontmatter, so
 * frontmatter is the source of truth). Nothing kept the cache in sync, so
 * editing frontmatter left the manifest copy stale — at one point 17 skills
 * had drifted forward_watch and 23 had stale last_threat_review, including a
 * manifest forecast note that still dated an ATLAS release to the wrong month
 * after the skill body had been corrected.
 *
 * scripts/sync-manifest-metadata.js refreshes the cache from frontmatter.
 * This test fails the suite if the cache drifts again, so a missed sync is
 * caught before release instead of shipping a manifest that contradicts its
 * own skill bodies.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const lint = require('../lib/lint-skills.js');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

function frontmatterOf(id) {
  const p = path.join(ROOT, 'skills', id, 'skill.md');
  if (!fs.existsSync(p)) return null;
  const { frontmatter } = lint.extractFrontmatterBlock(fs.readFileSync(p, 'utf8'));
  return lint.parseFrontmatter(frontmatter);
}

test('manifest last_threat_review mirrors each skill frontmatter', () => {
  const drift = [];
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    const fm = frontmatterOf(id);
    if (!fm || !('last_threat_review' in fm)) continue;
    if (entry.last_threat_review !== fm.last_threat_review) {
      drift.push(`${id}: manifest ${entry.last_threat_review} vs frontmatter ${fm.last_threat_review}`);
    }
  }
  assert.equal(drift.length, 0,
    `manifest last_threat_review out of sync — run \`node scripts/sync-manifest-metadata.js\`:\n  ${drift.join('\n  ')}`);
});

// Cross-reference arrays the manifest caches as an enriched superset of
// frontmatter. build-indexes overlays these and refresh-reverse-refs reads
// them, so a frontmatter-declared ref MISSING from the manifest silently
// vanishes from every cross-reference surface (xref index, reverse-refs,
// summary cards). Manifest-only refs are intended enrichment and fine — the
// invariant is COVER, not exact mirror.
const COVER_FIELDS = ['data_deps', 'framework_gaps', 'atlas_refs', 'attack_refs', 'rfc_refs', 'cwe_refs', 'd3fend_refs'];

test('manifest cross-ref arrays cover every frontmatter-declared ref', () => {
  const drift = [];
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    const fm = frontmatterOf(id);
    if (!fm) continue;
    for (const field of COVER_FIELDS) {
      if (!Array.isArray(fm[field]) || fm[field].length === 0) continue;
      const have = new Set(Array.isArray(entry[field]) ? entry[field] : []);
      const missing = fm[field].filter((r) => !have.has(r));
      if (missing.length) {
        drift.push(`${id}.${field}: manifest omits ${missing.join(', ')}`);
      }
    }
  }
  assert.equal(drift.length, 0,
    `manifest cross-ref arrays omit frontmatter-declared refs (they would vanish from cross-references) — run \`node scripts/sync-manifest-metadata.js\` then refresh-reverse-refs:\n  ${drift.join('\n  ')}`);
});

test('manifest forward_watch mirrors each skill frontmatter', () => {
  const drift = [];
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    const fm = frontmatterOf(id);
    if (!fm) continue;
    const want = Array.isArray(fm.forward_watch) ? fm.forward_watch : [];
    const have = Array.isArray(entry.forward_watch) ? entry.forward_watch : [];
    if (JSON.stringify(have) !== JSON.stringify(want)) {
      drift.push(`${id}: manifest ${have.length} item(s) vs frontmatter ${want.length}`);
    }
  }
  assert.equal(drift.length, 0,
    `manifest forward_watch out of sync — run \`node scripts/sync-manifest-metadata.js\`:\n  ${drift.join('\n  ')}`);
});
