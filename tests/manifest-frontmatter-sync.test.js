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

test('manifest cwe_refs covers every frontmatter-declared CWE', () => {
  // cwe_refs is enrichment-richer on the manifest side (many entries carry
  // manifest-only refs, which is fine), but a CWE declared in a skill's
  // frontmatter MUST appear in its manifest entry — the derived indexes and
  // the reverse-ref refresh read the manifest, so a frontmatter-only ref
  // silently vanishes from every cross-reference surface.
  const drift = [];
  for (const entry of manifest.skills) {
    const id = entry.id || entry.name;
    const fm = frontmatterOf(id);
    if (!fm || !Array.isArray(fm.cwe_refs) || fm.cwe_refs.length === 0) continue;
    const have = new Set(Array.isArray(entry.cwe_refs) ? entry.cwe_refs : []);
    const missing = fm.cwe_refs.filter((c) => !have.has(c));
    if (missing.length) {
      drift.push(`${id}: frontmatter declares ${missing.join(', ')} but the manifest entry omits ${missing.length > 1 ? 'them' : 'it'}`);
    }
  }
  assert.equal(drift.length, 0,
    `manifest cwe_refs missing frontmatter-declared CWEs — add them to the manifest entry and re-run refresh-reverse-refs:\n  ${drift.join('\n  ')}`);
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
