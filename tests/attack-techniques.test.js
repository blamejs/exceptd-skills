"use strict";


// ---- routed from attack-version-canonical ----
require("node:test").describe("attack-version-canonical", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
  const cweMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cwe-catalog.json'), 'utf8'));
  const d3fendMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'd3fend-catalog.json'), 'utf8'));
  const canonicalAtlas = atlasMeta._meta.atlas_version;
  const canonicalCwe = cweMeta._meta.cwe_version;
  const canonicalD3fend = d3fendMeta._meta.d3fend_version;
  assert.equal(sources.sources.attack.current_version, CANONICAL_ATTACK,
    `sources/index.json attack.current_version must equal canonical ATT&CK v${CANONICAL_ATTACK}.`);
  assert.equal(sources.sources.atlas.current_version, canonicalAtlas,
    `sources/index.json atlas.current_version must equal canonical ATLAS v${canonicalAtlas}.`);
  assert.equal(sources.sources.cwe.current_version, canonicalCwe,
    `sources/index.json cwe.current_version must equal canonical CWE v${canonicalCwe} (data/cwe-catalog.json._meta.cwe_version).`);
  assert.equal(sources.sources.d3fend.current_version, canonicalD3fend,
    `sources/index.json d3fend.current_version must equal canonical D3FEND v${canonicalD3fend} (data/d3fend-catalog.json._meta.d3fend_version).`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hard-rule-forcing-functions ----
require("node:test").describe("hard-rule-forcing-functions", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hard-rule-forcing-functions.test.js
 *
 * Cycle 16 audit fix (v0.12.36): closes 3 gaps in AGENTS.md Hard Rule
 * forcing-function coverage. Without these tests the rules were
 * policy-only — a future PR could violate them and the CI gate would
 * stay green.
 *
 *   Rule #3 (no CVSS-only risk scoring): every non-draft CVE in
 *     data/cve-catalog.json must declare rwep_score + rwep_factors.
 *
 *   Rule #5 (global-first, not US-centric): the framework-control-gaps
 *     catalog must carry entries for EU + UK + AU + INTL alongside US.
 *
 *   Rule #8 (Pinned ATLAS version): manifest.json's atlas_version field
 *     must equal data/atlas-ttps.json._meta.atlas_version exactly, and
 *     same for attack_version. Pre-cycle-9 these drifted silently.
 *
 *   Cross-format CVE consistency: CSAF + OpenVEX + SARIF emitters must
 *     agree on the catalogued-CVE set per playbook run.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (deep-equality or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const gaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));


function frameworkRegion(frameworkText) {
  if (!frameworkText) return 'OTHER';
  if (/NIST|FedRAMP|CMMC|HIPAA|HITRUST|PCI|SOC|CIS Controls|OFAC|SEC|NYDFS|CIRCIA/i.test(frameworkText)) return 'US';
  if (/NIS2|DORA|GDPR|^EU |EU-|ENISA|CRA |AI Act|EU 2014\/833/i.test(frameworkText)) return 'EU';
  if (/\b(?:UK|CAF|Ofcom|NCSC|OFSI|UK-GDPR)\b/i.test(frameworkText)) return 'UK';
  if (/\b(?:AU|ACSC|ISM|Essential 8|APRA|eSafety|AU NDB)\b/i.test(frameworkText)) return 'AU';
  if (/\b(?:ISO|IEC \d|3GPP|GSMA|ITU|FCC|TSA|OWASP|SLSA|CycloneDX|SPDX)\b/i.test(frameworkText)) return 'INTL';
  return 'OTHER';
}

test('Hard Rule #8 — manifest.attack_version matches data/attack-techniques.json._meta.attack_version exactly', () => {
  const manifestPin = manifest.attack_version;
  const catalogPin = attack._meta.attack_version;
  assert.equal(typeof manifestPin, 'string', 'manifest.attack_version must be set');
  assert.equal(typeof catalogPin, 'string', 'attack-techniques._meta.attack_version must be set');
  const manifestCanonical = manifestPin.includes('.') ? manifestPin : `${manifestPin}.0`;
  const catalogCanonical = catalogPin.includes('.') ? catalogPin : `${catalogPin}.0`;
  assert.equal(manifestCanonical, catalogCanonical,
    `Rule #8 violation: manifest pins ATT&CK v${manifestPin} but catalog meta is v${catalogPin}. Pre-cycle-9 silent-drift class re-introduced.`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
