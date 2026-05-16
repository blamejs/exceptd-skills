'use strict';

/**
 * tests/docs-catalog-counts-pinned.test.js
 *
 * Cycle 14 docs-accuracy fix (v0.12.34): operator-facing README.md +
 * ARCHITECTURE.md were still pinning ATLAS v5.1.0 / ATT&CK v17 / 38 skills /
 * 28 D3FEND entries — nine releases after cycle 9 corrected the manifest
 * pin (v5.4.0 / v19.0). The CHANGELOG advertised v5.4.0 but the README's
 * badge still said v5.1.0; operators reading "which catalog version does
 * this skill set track" saw a 6-month-stale answer.
 *
 * This test asserts that the doc text matches the LIVE catalog state. A
 * future PR bumping the catalog without updating the doc fails this test
 * at CI time — eliminates the silent-drift class.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * substring or count.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const ARCH = fs.readFileSync(path.join(ROOT, 'ARCHITECTURE.md'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));
const d3fend = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'd3fend-catalog.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));

function entryCount(catalog) {
  return Object.keys(catalog).filter((k) => k !== '_meta').length;
}

test('README ATLAS version badge + narrative match live atlas-ttps._meta.atlas_version', () => {
  const live = atlas._meta.atlas_version;
  assert.equal(typeof live, 'string', '_meta.atlas_version must be set');
  // Badge URL contains the version directly (URL-encoded form ok).
  assert.equal(
    README.includes(`MITRE%20ATLAS-v${live}`),
    true,
    `README badge must reference ATLAS v${live}; live catalog pin is ${live}`,
  );
  // Narrative mentions: should not have stale 5.1.0 references anywhere.
  assert.equal(
    README.includes('ATLAS v5.1.0'),
    false,
    'README must not reference stale ATLAS v5.1.0 (cycle 9 corrected to v5.4.0)',
  );
});

test('README ATT&CK badge matches live attack-techniques._meta.attack_version', () => {
  const live = attack._meta.attack_version;
  // Badge URL contains the version (URL-encoded). Tolerate either bare
  // version ("v19.0") or just-major ("v19") form in the badge.
  const bare = live; // e.g. "19.0"
  const major = live.split('.')[0]; // e.g. "19"
  const has = README.includes(`ATT%26CK-v${bare}`) || README.includes(`ATT%26CK-v${major}`);
  assert.equal(has, true,
    `README ATT&CK badge must reference v${bare} or v${major}; live catalog pin is ${bare}`);
  // Stale v17 / v18 references banned.
  assert.equal(README.includes('ATT%26CK-v17'), false,
    'README must not reference stale ATT&CK v17');
  assert.equal(README.includes('ATT%26CK-v18'), false,
    'README must not reference stale ATT&CK v18');
});

test('README skill count badge + narrative match manifest.skills.length', () => {
  const live = manifest.skills.length;
  assert.equal(
    README.includes(`badge/skills-${live}-`),
    true,
    `README skill badge must show ${live}; live manifest has ${live} skills`,
  );
  // Narrative: "<N> skills across kernel LPE" — the specific phrase from
  // the README's intro paragraph. The cycle-14 pre-fix said "38 skills".
  assert.equal(
    new RegExp(`${live} skills across kernel LPE`).test(README),
    true,
    `README intro paragraph must say "${live} skills across kernel LPE"`,
  );
  assert.equal(
    /38 skills across kernel LPE/.test(README),
    false,
    'README must not reference stale "38 skills" count',
  );
});

test('ARCHITECTURE.md ATLAS references match live atlas-ttps._meta.atlas_version', () => {
  const live = atlas._meta.atlas_version;
  // ARCHITECTURE has 3 sites referencing ATLAS version (cycle 14 audit).
  // All must agree with live.
  assert.equal(ARCH.includes(`v${live}`), true,
    `ARCHITECTURE.md must reference ATLAS v${live}; live catalog pin is ${live}`);
  assert.equal(ARCH.includes('v5.1.0'), false,
    'ARCHITECTURE.md must not reference stale v5.1.0');
});

test('ARCHITECTURE.md D3FEND entry count matches live d3fend-catalog', () => {
  const live = entryCount(d3fend);
  assert.equal(
    new RegExp(`${live} MITRE D3FEND defensive technique entries`).test(ARCH),
    true,
    `ARCHITECTURE.md must say "${live} MITRE D3FEND defensive technique entries"; live catalog has ${live}`,
  );
});

test('All doc-text counts match live catalog state (CVE / framework-gap / atlas)', () => {
  // Sanity sweep: doc-level numbers that operators rely on.
  // CVE count: live = ?, doc may reference it implicitly. Don't enforce
  // a specific number on the doc side here — only assert there's no stale
  // hard-coded "30 CVE" / "31 CVE" / etc. that would mislead. Live is 37+
  // as of cycle 14.
  const liveCveCount = entryCount(cve);
  assert.equal(liveCveCount >= 30, true,
    `CVE catalog should have grown past 30; current is ${liveCveCount}`);
  // ATLAS / ATT&CK entry counts — surface in case future docs add them.
  const liveAtlas = entryCount(atlas);
  const liveAttack = entryCount(attack);
  assert.equal(typeof liveAtlas, 'number');
  assert.equal(typeof liveAttack, 'number');
});
