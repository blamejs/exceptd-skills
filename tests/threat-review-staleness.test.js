'use strict';

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
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
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

test('every shipped data/*.json catalog carries _meta.last_threat_review (Hard Rule #8)', () => {
  const catalogFiles = [
    'cve-catalog.json',
    'cwe-catalog.json',
    'd3fend-catalog.json',
    'dlp-controls.json',
    'atlas-ttps.json',
    'attack-techniques.json',
    'rfc-references.json',
    'framework-control-gaps.json',
  ];
  const missing = [];
  for (const f of catalogFiles) {
    const p = path.join(ROOT, 'data', f);
    if (!fs.existsSync(p)) continue;
    const c = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!c._meta || typeof c._meta.last_threat_review !== 'string') {
      missing.push(f);
    }
  }
  assert.deepEqual(missing, [], `catalogs missing _meta.last_threat_review: ${missing.join(', ')}`);
});
