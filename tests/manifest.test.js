"use strict";


// ---- routed from manifest-frontmatter-sync ----
require("node:test").describe("manifest-frontmatter-sync", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from threat-review-staleness ----
require("node:test").describe("threat-review-staleness", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/threat-review-staleness.test.js
 *
 * Cycle 10 P3 fix (v0.12.30): pin a staleness window between
 * manifest.threat_review_date and every skill.last_threat_review.
 * Hard Rule #8 makes per-entry threat review currency a release-blocker
 * after a stated window; pre-v0.12.30 the threat_review_date on the
 * manifest could drift arbitrarily from the per-skill record.
 *
 * Window: per-skill last_threat_review must be within 30 days of
 * manifest.threat_review_date. Catches the "manifest claims today,
 * skills last touched two months ago" lie without forcing maintainers
 * to fictionally bump every skill on every release.
 *
 * Also pins per-catalog _meta.last_threat_review presence — v0.12.30
 * added the field to cve-catalog, cwe-catalog, d3fend-catalog, and
 * dlp-controls; this test ensures it stays present.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * day-count threshold rather than `assert.ok(diff < N)`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

const STALENESS_DAYS = 30;

function daysBetween(a, b) {
  const ms = Math.abs(new Date(a).getTime() - new Date(b).getTime());
  return Math.floor(ms / 86400000);
}

test(`every skill.last_threat_review is within ${STALENESS_DAYS} days of manifest.threat_review_date`, () => {
  const anchor = manifest.threat_review_date;
  assert.equal(typeof anchor, 'string', 'manifest.threat_review_date must be a YYYY-MM-DD string');
  assert.match(anchor, /^\d{4}-\d{2}-\d{2}$/);
  const stale = [];
  for (const skill of manifest.skills) {
    const ltr = skill.last_threat_review;
    if (!ltr) {
      stale.push({ id: skill.id || skill.name, last_threat_review: null });
      continue;
    }
    const days = daysBetween(ltr, anchor);
    if (days > STALENESS_DAYS) {
      stale.push({ id: skill.id || skill.name, last_threat_review: ltr, days_stale: days });
    }
  }
  assert.deepEqual(
    stale,
    [],
    `${stale.length} skills exceed the ${STALENESS_DAYS}-day staleness window vs manifest.threat_review_date=${anchor}: ${JSON.stringify(stale.slice(0, 5), null, 2)}`,
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
