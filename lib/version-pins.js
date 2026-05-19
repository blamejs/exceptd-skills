"use strict";
/**
 * lib/version-pins.js
 *
 * Single source of truth for the canonical MITRE / ATT&CK / ATLAS /
 * D3FEND version pins that operator-facing docs reference.
 *
 * Pre-v0.13.20 history: ATLAS version was pinned to v5.4.0 in 33+
 * locations (READMEs, AGENTS.md, ARCHITECTURE.md, agent personas,
 * skill bodies, schema descriptions, manifest.json). Bumping required
 * a lockstep regex-replace across all 33 files. v0.13.18 bumped to
 * v5.6.0; the regex sweep accidentally touched dates in unrelated
 * paragraphs and only failed-loudly because the tests asserted
 * version drift. v0.13.20 makes the pin schema-driven:
 *
 *   - `data/atlas-ttps.json._meta.atlas_version` is the source of truth.
 *   - `data/attack-techniques.json._meta.attack_version` is too.
 *   - This module reads both, exposes them via getAtlasVersion() and
 *     getAttackVersion() helpers, and is the canonical resolver every
 *     consumer (test runner, doc-currency check, lint, skill-body
 *     scanner) reaches through.
 *
 * The drift-detection tests in tests/atlas-version-canonical.test.js
 * and tests/attack-version-canonical.test.js now compare every
 * operator-facing mention against the value this module returns.
 * A future bump is `node $(exceptd path)/lib/sign.js sign-all` + this
 * module reads the new value; no lockstep doc edit needed except where
 * the mention is
 * a literal-string semantic ("upgrade from v5.4.0 to v5.6.0") that an
 * operator must read.
 *
 * API:
 *   getAtlasVersion() → "5.6.0"
 *   getAttackVersion() → "19.0"
 *   getAtlasReleaseDate() → "2026-05-08"
 *   getAllPins() → { atlas_version, atlas_release_date, attack_version, ... }
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");

let _cached = null;

function loadPins() {
  if (_cached) return _cached;
  const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "atlas-ttps.json"), "utf8"));
  const attack = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "attack-techniques.json"), "utf8"));
  const meta = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  _cached = {
    atlas_version: (atlas._meta && atlas._meta.atlas_version) || null,
    atlas_release_date: (atlas._meta && atlas._meta.atlas_release_date) || null,
    attack_version: (attack._meta && attack._meta.attack_version) || null,
    attack_version_date: (attack._meta && attack._meta.attack_version_date) || null,
    manifest_atlas_version: meta.atlas_version || null,
    manifest_attack_version: meta.attack_version || null
  };
  return _cached;
}

function clearCache() { _cached = null; }
function getAtlasVersion() { return loadPins().atlas_version; }
function getAtlasReleaseDate() { return loadPins().atlas_release_date; }
function getAttackVersion() { return loadPins().attack_version; }
function getAttackVersionDate() { return loadPins().attack_version_date; }
function getAllPins() { return { ...loadPins() }; }

module.exports = {
  getAtlasVersion, getAtlasReleaseDate,
  getAttackVersion, getAttackVersionDate,
  getAllPins, clearCache
};
