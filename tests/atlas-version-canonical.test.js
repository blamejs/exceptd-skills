'use strict';

/**
 * tests/atlas-version-canonical.test.js
 *
 * Single source of truth for the project's pinned ATLAS version is
 * data/atlas-ttps.json._meta.atlas_version. Every operator-facing
 * reference across docs, agents, GitHub templates, and skill bodies
 * must match it. Pre-fix the contributor/maintainer/context/agent
 * docs cited a stale v5.1.0 while the catalog had moved to v5.4.0 —
 * Hard Rule #8 was theater because half the codebase didn't obey it.
 *
 * This test scans operator-facing surfaces and refuses any version
 * string that doesn't match the catalog's atlas_version. A future
 * ATLAS bump becomes a one-line change in data/atlas-ttps.json + a
 * bulk replace elsewhere; the test surfaces every site that drifted.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const atlasMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const CANONICAL_ATLAS = atlasMeta._meta.atlas_version;

// Operator-facing surfaces that explicitly reference ATLAS versions.
// CHANGELOG.md is excluded because historical entries necessarily cite
// the version current at their release date.
const FILES_TO_CHECK = [
  'AGENTS.md',
  'CONTRIBUTING.md',
  'MAINTAINERS.md',
  'CONTEXT.md',
  'ARCHITECTURE.md',
  'README.md',
  'SECURITY.md',
  '.github/copilot-instructions.md',
  '.github/PULL_REQUEST_TEMPLATE.md',
  '.cursorrules',
];

function listSkillBodies() {
  const skillsDir = path.join(ROOT, 'skills');
  if (!fs.existsSync(skillsDir)) return [];
  const out = [];
  for (const name of fs.readdirSync(skillsDir)) {
    const p = path.join(skillsDir, name, 'skill.md');
    if (fs.existsSync(p)) out.push(path.relative(ROOT, p));
  }
  return out;
}

function listAgentBodies() {
  const agentsDir = path.join(ROOT, 'agents');
  if (!fs.existsSync(agentsDir)) return [];
  return fs.readdirSync(agentsDir)
    .filter(f => f.endsWith('.md'))
    .map(f => path.relative(ROOT, path.join(agentsDir, f)));
}

// Match "ATLAS v5.x.x" or "ATLAS v5.x" — captures any version string in
// the ATLAS namespace. Conservative: only fires on explicit
// "ATLAS v<digits>" so "ATT&CK v19.0" / "RFC 5280 v3" aren't captured.
const ATLAS_VERSION_RE = /ATLAS\s+v?(\d+\.\d+(?:\.\d+)?)/g;

function scanFile(rel) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return [];
  const text = fs.readFileSync(abs, 'utf8');
  const drift = [];
  let m;
  ATLAS_VERSION_RE.lastIndex = 0;
  while ((m = ATLAS_VERSION_RE.exec(text)) !== null) {
    const found = m[1];
    if (found !== CANONICAL_ATLAS) {
      const lineNo = text.slice(0, m.index).split('\n').length;
      drift.push(`${rel}:${lineNo} — found ATLAS v${found}, expected v${CANONICAL_ATLAS}`);
    }
  }
  return drift;
}

test('atlas-ttps.json._meta.atlas_version is the canonical pin', () => {
  assert.equal(typeof CANONICAL_ATLAS, 'string');
  assert.match(CANONICAL_ATLAS, /^\d+\.\d+\.\d+$/, `atlas_version must be semver; got ${CANONICAL_ATLAS}`);
});

test('every ATLAS version reference in operator-facing docs matches the canonical pin', () => {
  const drift = [];
  for (const rel of FILES_TO_CHECK) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `ATLAS version drift in operator-facing docs (canonical v${CANONICAL_ATLAS}):\n  ${drift.join('\n  ')}`);
});

test('manifest.json carries the same ATLAS version pin', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.equal(manifest.atlas_version, CANONICAL_ATLAS,
    `manifest.json.atlas_version (${manifest.atlas_version}) must match data/atlas-ttps.json._meta.atlas_version (${CANONICAL_ATLAS}).`);
});

test('every skill body referencing ATLAS uses the canonical version', () => {
  const drift = [];
  for (const rel of listSkillBodies()) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `ATLAS version drift in skill bodies (canonical v${CANONICAL_ATLAS}):\n  ${drift.join('\n  ')}`);
});

test('every agent body referencing ATLAS uses the canonical version', () => {
  const drift = [];
  for (const rel of listAgentBodies()) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `ATLAS version drift in agent bodies (canonical v${CANONICAL_ATLAS}):\n  ${drift.join('\n  ')}`);
});
