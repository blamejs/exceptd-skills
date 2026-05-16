'use strict';

/**
 * tests/docs-catalog-counts-pinned.test.js
 *
 * Cycle 14 docs-accuracy fix (v0.12.34): operator-facing README.md +
 * ARCHITECTURE.md were pinning ATLAS v5.1.0 / ATT&CK v17 / 38 skills /
 * 28 D3FEND entries — nine releases after cycle 9 corrected the manifest
 * pin (v5.4.0 / v19.0). The CHANGELOG advertised v5.4.0 but the README's
 * badge still said v5.1.0; operators reading "which catalog version does
 * this skill set track" saw a 6-month-stale answer.
 *
 * This test asserts that EVERY version mention in the docs aligns with the
 * CURRENT `_meta` pins — not just absence of a specific obsolete string.
 * codex P2 (v0.12.34 follow-up): a banned-string approach catches the
 * historical drift but lets future drift through silently. When ATLAS
 * advances beyond 5.4.0, a doc mention that remains on 5.4.0 must also
 * fail this gate.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * value or asserts the empty-set property "no mismatching pin found."
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

// Generic mismatch scan. Pull every version-shaped token next to the named
// context and assert it equals the live pin. If future ATLAS bumps to
// 5.5.0 and a doc still says 5.4.0, this fails — codex P2 review asked
// for this generalized behavior over the prior banned-string approach.
function findMismatches(doc, contextRe, livePin) {
  const mismatches = [];
  let m;
  const re = new RegExp(contextRe.source, contextRe.flags.includes('g') ? contextRe.flags : contextRe.flags + 'g');
  while ((m = re.exec(doc)) !== null) {
    const found = m[1];
    if (found !== livePin) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(doc.length, m.index + m[0].length + 30);
      mismatches.push({ found, expected: livePin, context: doc.slice(start, end).replace(/\s+/g, ' ').trim() });
    }
  }
  return mismatches;
}

test('README — every ATLAS version mention equals live atlas-ttps._meta.atlas_version', () => {
  const live = atlas._meta.atlas_version;
  const patterns = [
    /MITRE[%\s]*20?ATLAS[-\s]*v(\d+\.\d+\.\d+)/g,
    /MITRE ATLAS v(\d+\.\d+\.\d+)/g,
    /ATLAS v(\d+\.\d+\.\d+)/g,
  ];
  const allMismatches = [];
  for (const p of patterns) {
    allMismatches.push(...findMismatches(README, p, live));
  }
  const seen = new Set();
  const unique = allMismatches.filter((m) => {
    const k = `${m.found}|${m.context}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  assert.deepEqual(unique, [],
    `README ATLAS version mentions must all equal live pin ${live}; mismatches: ${JSON.stringify(unique, null, 2)}`);
});

test('README — every ATT&CK version mention equals live attack-techniques._meta.attack_version', () => {
  const live = attack._meta.attack_version;
  const liveMajor = live.split('.')[0];
  const patterns = [
    /ATT[%&]26?CK[-\s]*v(\d+(?:\.\d+)?)/g,
    /ATT&CK v(\d+(?:\.\d+)?)/g,
  ];
  const allMismatches = [];
  for (const p of patterns) {
    const re = new RegExp(p.source, p.flags);
    let m;
    while ((m = re.exec(README)) !== null) {
      const found = m[1];
      if (found !== live && found !== liveMajor) {
        const start = Math.max(0, m.index - 30);
        const end = Math.min(README.length, m.index + m[0].length + 30);
        allMismatches.push({ found, expected: `${live} or ${liveMajor}`, context: README.slice(start, end).replace(/\s+/g, ' ').trim() });
      }
    }
  }
  const seen = new Set();
  const unique = allMismatches.filter((m) => {
    const k = `${m.found}|${m.context}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  assert.deepEqual(unique, [],
    `README ATT&CK version mentions must all equal live ${live} (or major-only ${liveMajor}); mismatches: ${JSON.stringify(unique, null, 2)}`);
});

test('README — every skill-count mention equals live manifest.skills.length', () => {
  const live = manifest.skills.length;
  const badgeMatch = README.match(/badge\/skills-(\d+)-/);
  assert.ok(badgeMatch, 'README must declare a skill-count badge');
  assert.equal(Number(badgeMatch[1]), live,
    `README badge skill count = ${badgeMatch[1]}; live manifest has ${live} skills`);

  const proseMatch = README.match(/(\d+) skills across kernel LPE/);
  assert.ok(proseMatch, 'README intro must declare "<N> skills across kernel LPE"');
  assert.equal(Number(proseMatch[1]), live,
    `README intro skill count = ${proseMatch[1]}; live manifest has ${live} skills`);
});

test('ARCHITECTURE.md — every ATLAS version mention equals live atlas-ttps._meta.atlas_version', () => {
  const live = atlas._meta.atlas_version;
  const patterns = [
    /MITRE ATLAS v(\d+\.\d+\.\d+)/g,
    /ATLAS v(\d+\.\d+\.\d+)/g,
    /"atlas_version":\s*"(\d+\.\d+\.\d+)"/g,
  ];
  const allMismatches = [];
  for (const p of patterns) {
    allMismatches.push(...findMismatches(ARCH, p, live));
  }
  const seen = new Set();
  const unique = allMismatches.filter((m) => {
    const k = `${m.found}|${m.context}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  assert.deepEqual(unique, [],
    `ARCHITECTURE ATLAS version mentions must all equal live pin ${live}; mismatches: ${JSON.stringify(unique, null, 2)}`);
});

test('ARCHITECTURE.md — D3FEND entry count equals live d3fend-catalog count', () => {
  const live = entryCount(d3fend);
  const m = ARCH.match(/(\d+) MITRE D3FEND defensive technique entries/);
  assert.ok(m, 'ARCHITECTURE must declare D3FEND entry count in standard phrase');
  assert.equal(Number(m[1]), live,
    `ARCHITECTURE D3FEND count = ${m[1]}; live catalog has ${live} entries`);
});

test('Sanity sweep — live catalog counts within expected ranges (no silent collapse)', () => {
  assert.equal(entryCount(cve) >= 30, true,
    `CVE catalog should have grown past 30; current is ${entryCount(cve)}`);
  assert.equal(entryCount(atlas) >= 20, true,
    `ATLAS catalog should have grown past 20; current is ${entryCount(atlas)}`);
  assert.equal(entryCount(attack) >= 50, true,
    `ATT&CK catalog should have grown past 50; current is ${entryCount(attack)}`);
  assert.equal(entryCount(d3fend) >= 25, true,
    `D3FEND catalog should have grown past 25; current is ${entryCount(d3fend)}`);
});
