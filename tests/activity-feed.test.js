'use strict';

/**
 * tests/activity-feed.test.js
 *
 * Subject coverage for scripts/builders/activity-feed.js (buildActivityFeed).
 * The builder fuses three event sources — per-skill last_threat_review,
 * per-catalog _meta.last_updated/last_verified, and the manifest
 * threat_review_date — into one descending-by-date feed.
 *
 * Assertions:
 *  - the returned envelope shape (_meta.schema_version/event_count + events[]);
 *  - skill events carry date/type/artifact/path/note from the skill record;
 *  - catalog events derive date from _meta.last_updated, fall back to
 *    last_verified, and count only non-`_`-prefixed entries;
 *  - a malformed / non-JSON catalog file is skipped (not thrown);
 *  - a catalog with no _meta date emits no event;
 *  - the manifest event appears only when threat_review_date is set;
 *  - events are sorted strictly descending by date and event_count matches;
 *  - determinism: two builds of the same inputs are deep-equal.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildActivityFeed } = require('../scripts/builders/activity-feed.js');

let _n = 0;
function mkFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `exceptd-actfeed-${_n++}-`));
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  return root;
}
function writeCatalog(root, name, obj) {
  fs.writeFileSync(path.join(root, name), JSON.stringify(obj));
}
function cleanup(root) {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

test('buildActivityFeed returns the documented envelope shape', () => {
  const root = mkFixture();
  try {
    const out = buildActivityFeed({
      root,
      manifest: { skills: [], threat_review_date: null },
      skills: [],
      catalogFiles: [],
    });
    assert.equal(out._meta.schema_version, '1.0.0');
    assert.equal(typeof out._meta.note, 'string');
    assert.equal(out._meta.event_count, 0);
    assert.ok(Array.isArray(out.events));
    assert.equal(out.events.length, 0);
  } finally { cleanup(root); }
});

test('skill events carry date/type/artifact/path/note from the skill record', () => {
  const root = mkFixture();
  try {
    const skills = [
      { name: 'kernel-lpe-triage', path: 'skills/kernel-lpe-triage/skill.md', last_threat_review: '2026-05-01', description: 'kernel LPE' },
      // a skill with no last_threat_review contributes no event
      { name: 'no-date', path: 'skills/no-date/skill.md', description: 'nope' },
    ];
    const out = buildActivityFeed({ root, manifest: { skills, threat_review_date: null }, skills, catalogFiles: [] });
    const ev = out.events.find((e) => e.artifact === 'kernel-lpe-triage');
    assert.ok(ev, 'expected an event for the dated skill');
    assert.equal(ev.type, 'skill_review');
    assert.equal(ev.date, '2026-05-01');
    assert.equal(ev.path, 'skills/kernel-lpe-triage/skill.md');
    assert.equal(ev.note, 'kernel LPE');
    // The undated skill must NOT appear.
    assert.equal(out.events.some((e) => e.artifact === 'no-date'), false);
    // note defaults to null when description is absent (proven via a 3rd skill).
    const out2 = buildActivityFeed({
      root,
      manifest: { skills: [], threat_review_date: null },
      skills: [{ name: 'x', path: 'skills/x/skill.md', last_threat_review: '2026-01-01' }],
      catalogFiles: [],
    });
    assert.equal(out2.events[0].note, null);
  } finally { cleanup(root); }
});

test('catalog events: date from last_updated, entry_count excludes _-prefixed keys', () => {
  const root = mkFixture();
  try {
    writeCatalog(root, 'data/cve-catalog.json', {
      _meta: { last_updated: '2026-04-15', schema_version: '2.1.0' },
      'CVE-2026-0001': {},
      'CVE-2026-0002': {},
    });
    const out = buildActivityFeed({
      root,
      manifest: { skills: [], threat_review_date: null },
      skills: [],
      catalogFiles: ['data/cve-catalog.json'],
    });
    assert.equal(out.events.length, 1);
    const ev = out.events[0];
    assert.equal(ev.type, 'catalog_update');
    assert.equal(ev.artifact, 'data/cve-catalog.json');
    assert.equal(ev.date, '2026-04-15');
    assert.equal(ev.schema_version, '2.1.0');
    assert.equal(ev.entry_count, 2, 'entry_count counts only non-_ keys');
  } finally { cleanup(root); }
});

test('catalog events fall back to last_verified when last_updated is absent', () => {
  const root = mkFixture();
  try {
    writeCatalog(root, 'data/atlas-ttps.json', {
      _meta: { last_verified: '2026-03-03' },
      'AML.T0001': {},
    });
    const out = buildActivityFeed({
      root,
      manifest: { skills: [], threat_review_date: null },
      skills: [],
      catalogFiles: ['data/atlas-ttps.json'],
    });
    assert.equal(out.events.length, 1);
    assert.equal(out.events[0].date, '2026-03-03');
    assert.equal(out.events[0].schema_version, null);
  } finally { cleanup(root); }
});

test('catalog with no _meta date emits no event; missing/malformed files are skipped', () => {
  const root = mkFixture();
  try {
    writeCatalog(root, 'data/no-date.json', { _meta: { schema_version: '1.0.0' }, k: {} });
    fs.writeFileSync(path.join(root, 'data', 'broken.json'), '{ this is : not json,,,');
    const out = buildActivityFeed({
      root,
      manifest: { skills: [], threat_review_date: null },
      skills: [],
      // 'data/absent.json' does not exist on disk
      catalogFiles: ['data/no-date.json', 'data/broken.json', 'data/absent.json'],
    });
    assert.equal(out.events.length, 0, 'no dated catalog, malformed + missing skipped silently');
  } finally { cleanup(root); }
});

test('manifest event appears only when threat_review_date is set', () => {
  const root = mkFixture();
  try {
    const skills = [{ name: 'a', path: 'skills/a/skill.md' }];
    const withDate = buildActivityFeed({
      root,
      manifest: { skills, threat_review_date: '2026-06-01' },
      skills,
      catalogFiles: [],
    });
    const me = withDate.events.find((e) => e.type === 'manifest_review');
    assert.ok(me, 'manifest event present when threat_review_date set');
    assert.equal(me.artifact, 'manifest.json');
    assert.match(me.note, /1 skills, 0 catalogs/);

    const noDate = buildActivityFeed({
      root,
      manifest: { skills, threat_review_date: null },
      skills,
      catalogFiles: [],
    });
    assert.equal(noDate.events.some((e) => e.type === 'manifest_review'), false);
  } finally { cleanup(root); }
});

test('events sorted strictly descending by date; event_count matches events length', () => {
  const root = mkFixture();
  try {
    writeCatalog(root, 'data/c1.json', { _meta: { last_updated: '2026-02-02' }, a: {} });
    writeCatalog(root, 'data/c2.json', { _meta: { last_updated: '2026-06-06' }, a: {} });
    const skills = [
      { name: 's-old', path: 'skills/s-old/skill.md', last_threat_review: '2026-01-01' },
      { name: 's-new', path: 'skills/s-new/skill.md', last_threat_review: '2026-05-05' },
    ];
    const out = buildActivityFeed({
      root,
      manifest: { skills, threat_review_date: '2026-04-04' },
      skills,
      catalogFiles: ['data/c1.json', 'data/c2.json'],
    });
    // 2 catalogs + 2 skills + 1 manifest = 5 events
    assert.equal(out.events.length, 5);
    assert.equal(out._meta.event_count, 5);
    const dates = out.events.map((e) => e.date);
    assert.deepEqual(dates, [...dates].sort((a, b) => b.localeCompare(a)),
      'events must be sorted descending by date');
    // newest event first
    assert.equal(out.events[0].date, '2026-06-06');
  } finally { cleanup(root); }
});

test('build is deterministic — two runs over identical inputs are deep-equal', () => {
  const root = mkFixture();
  try {
    writeCatalog(root, 'data/c.json', { _meta: { last_updated: '2026-03-03' }, a: {}, b: {} });
    const skills = [{ name: 's', path: 'skills/s/skill.md', last_threat_review: '2026-02-02', description: 'd' }];
    const args = { root, manifest: { skills, threat_review_date: '2026-01-01' }, skills, catalogFiles: ['data/c.json'] };
    const a = buildActivityFeed(args);
    const b = buildActivityFeed(args);
    assert.deepEqual(a, b);
  } finally { cleanup(root); }
});
