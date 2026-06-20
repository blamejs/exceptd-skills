'use strict';

/**
 * tests/manifest-cover-ref-resolution.test.js
 *
 * The manifest cross-reference cover arrays (atlas_refs / attack_refs /
 * framework_gaps / rfc_refs / cwe_refs / d3fend_refs / dlp_refs) are an
 * enriched superset of skill frontmatter — the manifest may carry curated
 * refs absent from any skill body. Those manifest-only refs are what
 * scripts/refresh-reverse-refs.js writes into each catalog's reverse field
 * (atlas-ttps.exceptd_skills, cwe-catalog.skills_referencing, ...). The
 * per-skill frontmatter ref-resolution in lint-skills reads only skill
 * bodies, so it never sees the manifest-only delta: a typo'd or stale
 * manifest-only ref (a hand-edit, or one re-signed into manifest_signature)
 * would become an orphaned control reference in the signed manifest and the
 * reverse-ref surface, with no gate to catch it — the exact "no orphaned
 * controls" failure (AGENTS.md Hard Rule #4) the frontmatter resolution
 * prevents, applied to the delta the frontmatter pass is blind to.
 *
 * findUnresolvedManifestCoverRefs() closes that gap. These tests pin:
 *   1. the shipped manifest's cover arrays all resolve (clean baseline);
 *   2. a manifest-only ref absent from the catalog is REPORTED (the bug);
 *   3. a curated manifest-only ref that DOES resolve is ACCEPTED (no
 *      false-positive on legitimate enrichment).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const lint = require('../lib/lint-skills.js');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const ctx = lint.loadContext();

test('shipped manifest cover arrays all resolve to catalog entries (baseline clean)', () => {
  const errors = lint.findUnresolvedManifestCoverRefs(manifest.skills, ctx);
  assert.deepEqual(errors, [],
    `manifest cover arrays carry unresolved (orphaned) control refs:\n  ${errors.join('\n  ')}`);
});

test('a manifest-only ref absent from the catalog is reported (Hard Rule #4)', () => {
  // A skill entry whose cover arrays mix a real catalog ref with a bogus one
  // present in NEITHER frontmatter NOR the catalog. The bogus refs must be the
  // exact reported set; the real one must not be flagged.
  const realAtlas = [...ctx.atlasKeys][0];
  const realCwe = [...ctx.cweKeys][0];
  const synthetic = [{
    name: 'synthetic-skill',
    atlas_refs: [realAtlas, 'AML.T9999'],
    cwe_refs: [realCwe, 'CWE-99999'],
  }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, ctx);
  assert.deepEqual(errors, [
    'synthetic-skill.atlas_refs: "AML.T9999" not present in data/atlas-ttps.json',
    'synthetic-skill.cwe_refs: "CWE-99999" not present in data/cwe-catalog.json',
  ]);
});

test('a curated manifest-only ref that resolves to a catalog entry is accepted', () => {
  // Enrichment case: a real catalog key that no skill frontmatter declares is
  // legitimate manifest enrichment and must NOT be flagged.
  const realAtlas = [...ctx.atlasKeys][0];
  const synthetic = [{ name: 'synthetic-skill', atlas_refs: [realAtlas] }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, ctx);
  assert.deepEqual(errors, []);
});

test('an absent optional catalog (null key-set) skips that field rather than crashing', () => {
  // loadContext() leaves ctx.attackKeys null when data/attack-techniques.json
  // is absent in older trees. The resolver must degrade gracefully (skip),
  // matching the per-skill attack_refs check's contract — not throw or flag.
  const partialCtx = { ...ctx, attackKeys: null };
  const synthetic = [{ name: 'synthetic-skill', attack_refs: ['T9999'] }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, partialCtx);
  assert.deepEqual(errors, []);
});

test('MANIFEST_COVER_RESOLUTION enumerates the cover-ref fields the resolver walks', () => {
  // Direct reference to the exported config the resolver iterates — pins its
  // shape so a future edit that drops a field/ctxKey/catalog tuple is caught.
  assert.ok(Array.isArray(lint.MANIFEST_COVER_RESOLUTION) && lint.MANIFEST_COVER_RESOLUTION.length >= 1);
  for (const row of lint.MANIFEST_COVER_RESOLUTION) {
    assert.equal(typeof row.field, 'string');
    assert.equal(typeof row.ctxKey, 'string');
    assert.equal(typeof row.catalog, 'string');
  }
});
