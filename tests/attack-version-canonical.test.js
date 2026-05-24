'use strict';

/**
 * tests/attack-version-canonical.test.js
 *
 * Single source of truth for the project's pinned MITRE ATT&CK version is
 * data/attack-techniques.json._meta.attack_version. Every operator-facing
 * reference across docs, agents, GitHub templates, and skill bodies must
 * track it. This is the ATT&CK analogue of atlas-version-canonical.test.js;
 * lib/version-pins.js documents it as the second canonical-drift guard, but
 * it had no implementation — so ATT&CK pin drift recurred silently (skills
 * citing v15/v16/v17 long after the catalog moved on) with no failing test
 * to surface it.
 *
 * Semantics differ from the ATLAS guard in one deliberate way: this scan is
 * STALE-ONLY. It flags a version reference OLDER than the canonical pin
 * (real drift — a skill still describing a superseded matrix) but permits a
 * reference EQUAL TO OR NEWER THAN canonical. Newer references are how the
 * forward-watch discipline records anticipated releases (e.g. a detection
 * strategy expected in the next ATT&CK cycle); flagging those would force
 * deleting correct anticipatory intel. An exact-match guard cannot tell
 * "anticipated next release" from "forgot to update," so it would punish the
 * right behavior. Stale-only does not.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const attackMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));
const CANONICAL_ATTACK = attackMeta._meta.attack_version;

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

// Parse "19.0" / "17" / "20" into a [major, minor] tuple for ordered
// comparison. Missing minor defaults to 0 so "v17" compares as [17, 0].
function parseVer(v) {
  const [maj, min] = v.split('.');
  return [parseInt(maj, 10), parseInt(min || '0', 10)];
}

// Returns true when `found` is strictly older than `canonical`.
function isStale(found, canonical) {
  const [fMaj, fMin] = parseVer(found);
  const [cMaj, cMin] = parseVer(canonical);
  if (fMaj !== cMaj) return fMaj < cMaj;
  return fMin < cMin;
}

// Match "ATT&CK v19.0" / "ATT&CK v17" — the version string must follow
// "ATT&CK" directly (optional whitespace). This deliberately does NOT match
// "ATT&CK Enterprise (v17)" or "ATT&CK Mappings v17 project", where another
// word sits between the framework name and the version: those phrasings name
// a sub-artifact (the Enterprise matrix label, the CTID crosswalk project)
// rather than the pinned catalog version, and are checked by reviewers, not
// this scan.
const ATTACK_VERSION_RE = /ATT&CK\s+v?(\d+(?:\.\d+)?)/g;

function scanFile(rel) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return [];
  const text = fs.readFileSync(abs, 'utf8');
  const drift = [];
  for (const m of text.matchAll(ATTACK_VERSION_RE)) {
    const found = m[1];
    if (isStale(found, CANONICAL_ATTACK)) {
      const lineNo = text.slice(0, m.index).split('\n').length;
      drift.push(`${rel}:${lineNo} — found stale ATT&CK v${found}, canonical is v${CANONICAL_ATTACK}`);
    }
  }
  return drift;
}

test('attack-techniques.json._meta.attack_version is the canonical pin', () => {
  assert.equal(typeof CANONICAL_ATTACK, 'string');
  assert.ok(CANONICAL_ATTACK.length > 0, `attack_version must be present; got ${CANONICAL_ATTACK}`);
});

test('isStale orders ATT&CK versions correctly (older flagged, equal/newer permitted)', () => {
  assert.equal(isStale('17', '19.0'), true, 'v17 is older than v19.0');
  assert.equal(isStale('18', '19.0'), true, 'v18 is older than v19.0');
  assert.equal(isStale('19.0', '19.0'), false, 'equal version is not stale');
  assert.equal(isStale('20', '19.0'), false, 'forward-watch v20 is not stale');
  assert.equal(isStale('19.1', '19.0'), false, 'newer minor is not stale');
});

test('no operator-facing doc references a stale ATT&CK version', () => {
  const drift = [];
  for (const rel of FILES_TO_CHECK) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `Stale ATT&CK version reference in operator-facing docs (canonical v${CANONICAL_ATTACK}):\n  ${drift.join('\n  ')}`);
});

test('no skill body references a stale ATT&CK version', () => {
  const drift = [];
  for (const rel of listSkillBodies()) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `Stale ATT&CK version reference in skill bodies (canonical v${CANONICAL_ATTACK}):\n  ${drift.join('\n  ')}`);
});

test('no agent body references a stale ATT&CK version', () => {
  const drift = [];
  for (const rel of listAgentBodies()) drift.push(...scanFile(rel));
  assert.equal(drift.length, 0,
    `Stale ATT&CK version reference in agent bodies (canonical v${CANONICAL_ATTACK}):\n  ${drift.join('\n  ')}`);
});

test('manifest.json carries the same ATT&CK version pin', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.equal(manifest.attack_version, CANONICAL_ATTACK,
    `manifest.json.attack_version (${manifest.attack_version}) must match data/attack-techniques.json._meta.attack_version (${CANONICAL_ATTACK}).`);
});

// The source registry's machine-readable version pointers are not regex-
// scanned above (they are not "ATT&CK vN" prose), but they are the
// authoritative "current version" fields consumers read. Guard them against
// the same drift that left them pinned to a superseded version for releases.
test('sources/index.json version pointers track the canonical catalog pins', () => {
  const sources = JSON.parse(fs.readFileSync(path.join(ROOT, 'sources', 'index.json'), 'utf8'));
  const atlasMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
  const canonicalAtlas = atlasMeta._meta.atlas_version;
  assert.equal(sources.sources.attack.current_version, CANONICAL_ATTACK,
    `sources/index.json attack.current_version must equal canonical ATT&CK v${CANONICAL_ATTACK}.`);
  assert.equal(sources.sources.atlas.current_version, canonicalAtlas,
    `sources/index.json atlas.current_version must equal canonical ATLAS v${canonicalAtlas}.`);
});
